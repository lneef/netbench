#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <format>
#include <rte_build_config.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_mbuf_core.h>
#include <rte_mempool.h>
#include <stdexcept>
#include <stdlib.h>
#include <string.h>
#include <string_view>
#include <unordered_map>

#include "port.h"

static uint8_t RSS_DEFAULT_KEY[] = {
    0xbe, 0xac, 0x01, 0xfa, 0x6a, 0x42, 0xb7, 0x3b, 0x80, 0x30,
    0xf2, 0x0c, 0x77, 0xcb, 0x2d, 0xa3, 0xae, 0x7b, 0x30, 0xb4,
    0xd0, 0xca, 0x2b, 0xcb, 0x43, 0xa3, 0x8f, 0xb0, 0x41, 0x67,
    0x25, 0x3d, 0x25, 0x5b, 0x0e, 0xc2, 0x6d, 0x5a, 0x56, 0xda};

static constexpr unsigned RSS_KEY_LEN = 40;

static std::unordered_map<std::string_view, opmode> opmodes{
    {"PING", opmode::PING},
    {"PONG", opmode::PONG},
    {"FORWARD", opmode::FORWARD},
    {"RECEIVE", opmode::RECEIVE}};

static bool is_sender(opmode role) {
  return role == opmode::FORWARD || role == opmode::PING ||
         role == opmode::PONG;
}

static bool is_receiver(opmode role) {
  return role == opmode::RECEIVE || role == opmode::PING ||
         role == opmode::PONG;
}

static rte_mempool *pool_create(std::string_view name, uint32_t pool_sz,
                                uint16_t lcore_id,
                                uint32_t buf_sz = RTE_MBUF_DEFAULT_BUF_SIZE) {
  return rte_pktmbuf_pool_create(name.data(), pool_sz, MEMPOOL_CACHE_SIZE, 0,
                                 buf_sz, rte_lcore_to_socket_id(lcore_id));
}

static rte_mempool *setup_send_pool(opmode role, uint32_t pool_sz,
                                    std::string_view name, uint16_t lcore_id,
                                    uint32_t msize) {
  switch (role) {
  case opmode::PING:
  case opmode::FORWARD:
  case opmode::PONG:
    return pool_create(name, pool_sz, lcore_id, msize);
  default:
    return nullptr;
  }
}

static rte_mempool *setup_receive_pool(opmode role, uint32_t pool_sz,
                                       std::string_view name, uint16_t lcore_id,
                                       uint32_t msize) {
  switch (role) {
  case opmode::RECEIVE:
  case opmode::PING:
    return pool_create(name, pool_sz, lcore_id, msize);
  case opmode::PONG:
    return pool_create(name, 2 * pool_sz, lcore_id, msize);
  default:
    return nullptr;
  }
}

static std::pair<rte_mempool *, rte_mempool *>
alloc_pools(opmode role, uint32_t recv_pool_sz, uint32_t send_pool_sz,
            std::string_view r_name, std::string_view s_name, uint16_t lcore_id,
            uint32_t msize) {
  return {setup_send_pool(role, send_pool_sz, s_name, lcore_id, msize),
          setup_receive_pool(role, recv_pool_sz, r_name, lcore_id, msize)};
}

int benchmark_config::port_init_cmdline(int argc, char **argv) {
  int opt, option_index;
  static const struct option long_options[] = {
      {"dip", required_argument, 0, 0},
      {"sip", required_argument, 0, 0},
      {"mtu", required_argument, 0, 0},
      {"rt", required_argument, 0, 0},
      {"bs", required_argument, 0, 0},
      {"dmac", required_argument, 0, 0},
      {"mode", required_argument, 0, 0},
      {"flows", required_argument, 0, 0},
      {"ntx", required_argument, 0, 0},
      {"nrx", required_argument, 0, 0},
      {0, 0, 0, 0}};
  while ((opt = getopt_long(argc, argv, "", long_options, &option_index)) !=
         -1) {
    if (opt == '?')
      continue;
    switch (option_index) {
    case 0:
      dip = inet_addr(optarg);
      break;
    case 1:
      sip = inet_addr(optarg);
      break;
    case 2:
      mtu = atol(optarg);
      break;
    case 3:
      rtime = atol(optarg);
      break;
    case 4:
      burst_size = atoi(optarg);
      break;
    case 5:
      rte_ether_unformat_addr(optarg, &dmac);
      break;
    case 6: {
      auto mode = std::string_view(optarg, strlen(optarg));
      auto it = opmodes.find(mode);
      if (it == opmodes.end())
        throw std::runtime_error(std::format("Unknown mode: {}", mode));
      role = it->second;
      break;
    }
    case 7:
      flows = atoi(optarg);
      break;
    case 8:
      nb_tx = atoi(optarg);
      break;
    case 9:
      nb_rx = atoi(optarg);
      break;
    default:
      break;
    }
  }
  mbuf_size = std::max<uint32_t>(
      mtu + sizeof(rte_ether_hdr) + RTE_PKTMBUF_HEADROOM, mbuf_size);
  return 0;
}

static inline void setup_reta(uint16_t port, uint32_t nrx, uint32_t reta_size){
    auto groups = reta_size / RTE_ETH_RETA_GROUP_SIZE;
    std::vector<rte_eth_rss_reta_entry64> reta(groups);

    for(auto i = 0u; i < reta_size; ++i)
        reta[i / RTE_ETH_RETA_GROUP_SIZE].mask = UINT64_MAX;

    for(auto i = 0u; i < reta_size; ++i){
        uint32_t reta_id = i / RTE_ETH_RETA_GROUP_SIZE;
        uint32_t reta_pos = i % RTE_ETH_RETA_GROUP_SIZE;
        uint32_t rss_qid = i % nrx;
        reta[reta_id].reta[reta_pos] = static_cast<uint16_t>(rss_qid);
    }

    if(rte_eth_dev_rss_reta_update(port, reta.data(), reta_size))
        throw std::runtime_error(std::format("Could not update reta on port {}\n", port));
}

int benchmark_config::port_init(port_info &info) {
  static constexpr uint16_t kDefaultDescNumTx = 1024;
  uint16_t nb_rxd, nb_txd;
  int retval;
  uint16_t port = info.port_id;
  nb_threads = rte_lcore_count();
  struct rte_eth_dev_info dev_info;
  struct rte_eth_rxconf rxconf{};
  struct rte_eth_txconf txconf{};
  rxconf.rx_free_thresh = burst_size;
  if (!rte_eth_dev_is_valid_port(port))
    throw std::runtime_error(std::format("Invalid port id: {}", port));
  rte_eth_conf port_conf{};
  retval = rte_eth_dev_info_get(port, &dev_info);
  if (retval != 0)
    throw std::runtime_error(
        std::format("Error during getting device info (port {})", port));
  nb_rxd = dev_info.rx_desc_lim.nb_max;
  nb_txd = std::min(dev_info.tx_desc_lim.nb_max, kDefaultDescNumTx);
  info.max_desc_rxq = nb_rxd;
  info.max_desv_txq = nb_txd;

  if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
    port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
  if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM)
    port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_IPV4_CKSUM;
  if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_UDP_CKSUM)
    port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_UDP_CKSUM;

  if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_UDP_CKSUM)
    port_conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_UDP_CKSUM;
  if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_IPV4_CKSUM)
    port_conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_IPV4_CKSUM;
  if(dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_RSS_HASH)
      dev_info.rx_offload_capa |= RTE_ETH_RX_OFFLOAD_RSS_HASH;

  info.caps.ip_cksum_tx =
      dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM;
  info.caps.l4_cksum_tx =
      dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_UDP_CKSUM;

  info.caps.ip_cksum_rx =
      dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_IPV4_CKSUM;
  info.caps.ip_cksum_tx =
      dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_UDP_CKSUM;
  nb_tx = is_sender(role) ? nb_tx : 0;
  nb_rx = is_receiver(role) ? nb_rx : 0;
  rxconf.rx_deferred_start = false;
  auto &rssconf = port_conf.rx_adv_conf.rss_conf;
  bool rss = false;
  if (nb_rx > 1 || nb_threads > 1) {
    port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
    rssconf.algorithm = RTE_ETH_HASH_FUNCTION_DEFAULT;
    rssconf.rss_key = RSS_DEFAULT_KEY;
    rssconf.rss_key_len = RSS_KEY_LEN;
    rssconf.rss_hf =
        RTE_ETH_RSS_NONFRAG_IPV4_UDP & dev_info.flow_type_rss_offloads;
    rss = true;
  } else {
    rssconf.rss_key = nullptr;
    rssconf.rss_hf = 0;
  }
  retval = rte_eth_dev_configure(port, nb_threads * nb_rx, nb_threads * nb_tx,
                                 &port_conf);
  if (retval != 0)
    throw std::runtime_error("Could not configure device");

  retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
  if (retval)
    throw std::runtime_error("Adjusting descriptors failed");
  info.thread_blocks.resize(nb_threads);
  txconf = dev_info.default_txconf;
  txconf.offloads = port_conf.txmode.offloads;
  rxconf = dev_info.default_rxconf;
  rxconf.offloads = port_conf.rxmode.offloads;
  uint16_t idx = 0;
  uint16_t lcore_id = 0;
  uint16_t setup_tx = 0;
  uint16_t setup_rx = 0;
  RTE_LCORE_FOREACH(lcore_id) {
    auto &tb = info.thread_blocks[idx];
    tb.s_name = std::format("SEND_POOL-{}", idx);
    tb.r_name = std::format("RECV_POOL-{}", idx++);
    auto [send_pool, recv_pool] = alloc_pools(
        role, static_cast<uint32_t>(nb_rx) * (nb_rxd + burst_size) + 4096,
        static_cast<uint32_t>(nb_tx) * (nb_txd + burst_size), tb.r_name,
        tb.s_name, lcore_id, mbuf_size);
    tb.setup_txqueues(port, nb_tx, nb_txd, txconf, send_pool, setup_tx);
    tb.setup_rxqueues(port, nb_rx, nb_rxd, rxconf, recv_pool, setup_rx);
    setup_tx += nb_tx;
    setup_rx += nb_rx;
  }

  uint16_t preconfigured_mtu;
  if (rte_eth_dev_get_mtu(port, &preconfigured_mtu))
    throw std::runtime_error("Could not retrieve mtu\n");

  if (preconfigured_mtu < mtu) {
    retval = rte_eth_dev_set_mtu(port, mtu);
    if (retval)
      throw std::runtime_error(std::format("Could not set mtu to {}\n", mtu));
  }

  retval = rte_eth_dev_start(port);
  if(rss)
      setup_reta(port, nb_rx * nb_threads, dev_info.reta_size);
  if (retval < 0)
    throw std::runtime_error(
        std::format("Could not start device: {}", strerror(-retval)));
  rte_eth_macaddr_get(port, &info.addr);
  return 0;
}

void thread_block::setup_rxqueues(uint16_t port, uint32_t nb_rx,
                                  uint16_t nb_desc, rte_eth_rxconf &rxconf,
                                  rte_mempool *pool, uint16_t rxoff) {
  recv_pool = {pool, deleter};
  for (uint16_t i = rxoff; i < rxoff + nb_rx; ++i) {
    if (rte_eth_rx_queue_setup(port, i, nb_desc, rte_eth_dev_socket_id(port),
                               &rxconf, pool))
      throw std::runtime_error("Failed to setup rxqueue\n");
    rx_queues.push_back(i);
  }
}

void thread_block::setup_txqueues(uint16_t port, uint32_t nb_tx,
                                  uint16_t nb_desc, rte_eth_txconf &txconf,
                                  rte_mempool *pool, uint16_t txoff) {
  send_pool = {pool, deleter};
  for (uint16_t i = txoff; i < txoff + nb_tx; ++i) {
    if (rte_eth_tx_queue_setup(port, i, nb_desc, rte_eth_dev_socket_id(port),
                               &txconf))
      throw std::runtime_error("Failed to setup txqueue\n");
    tx_queues.push_back(i);
  }
}

void port_info::collect_statistics(stat &statistics) {
  for (auto &tb : thread_blocks)
    statistics += tb.per_thread_stat;
}

void port_info::collect_submit_statistics(submit_stat &statistics) {
  for (auto &tb : thread_blocks) {
    statistics += tb.per_thread_submit_stat;
  }
}
