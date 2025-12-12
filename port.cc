#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <format>
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

static rte_mempool *pool_create(std::string_view name, uint32_t pool_sz, uint16_t lcore_id,
                                uint32_t buf_sz = RTE_MBUF_DEFAULT_BUF_SIZE) {
  return rte_pktmbuf_pool_create(name.data(), pool_sz, MEMPOOL_CACHE_SIZE, 0,
                                 buf_sz, rte_lcore_to_socket_id(lcore_id));
}

static rte_mempool *setup_send_pool(opmode role, uint32_t pool_sz,
                                 std::string_view name, uint16_t lcore_id) {
  switch (role) {
  case opmode::PING:
  case opmode::FORWARD:
    return pool_create(name, pool_sz, lcore_id, RTE_MBUF_DEFAULT_BUF_SIZE);
  default:
    return nullptr;
  }
}

static rte_mempool *setup_receive_pool(opmode role, uint32_t pool_sz,
                                   std::string_view name, uint16_t lcore_id) {
  switch (role) {
  case opmode::RECEIVE:
  case opmode::PING:
    return pool_create(name, pool_sz, lcore_id, RTE_MBUF_DEFAULT_BUF_SIZE);
  case opmode::PONG:
    return pool_create(name, 2 * pool_sz, lcore_id, RTE_MBUF_DEFAULT_BUF_SIZE);
  default:
    return nullptr;
  }
}

static std::pair<rte_mempool *, rte_mempool *>
alloc_pools(opmode role, uint32_t recv_pool_sz, uint32_t send_pool_sz,
            std::string_view r_name, std::string_view s_name, uint16_t lcore_id) {
  return {setup_send_pool(role, send_pool_sz, s_name, lcore_id),
          setup_receive_pool(role, recv_pool_sz, r_name, lcore_id)};
}

int benchmark_config::port_init_cmdline(int argc, char **argv) {
  int opt, option_index;
  static const struct option long_options[] = {
      {"dip", required_argument, 0, 0},
      {"sip", required_argument, 0, 0},
      {"framesize", required_argument, 0, 0},
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
      frame_size = atol(optarg);
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
  return 0;
}

int benchmark_config::port_init(port_info &info) {
  uint16_t nb_rxd, nb_txd;
  int retval;
  uint16_t port = info.port_id;
  nb_threads = rte_lcore_count();
  struct rte_eth_dev_info dev_info;
  struct rte_eth_rxconf rxconf;
  struct rte_eth_txconf txconf;
  if (!rte_eth_dev_is_valid_port(port))
    throw std::runtime_error(std::format("Invalid port id: {}", port));
  rte_eth_conf port_conf{};
  retval = rte_eth_dev_info_get(port, &dev_info);
  if (retval != 0)
    throw std::runtime_error(
        std::format("Error during getting device info (port {})", port));
  nb_rxd = dev_info.rx_desc_lim.nb_max;
  nb_txd = dev_info.tx_desc_lim.nb_max;
  info.max_desc_rxq = nb_rxd;
  info.max_desv_txq = nb_txd;

  if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
    port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
  if (dev_info.tx_offload_capa & RTE_ETH_RX_OFFLOAD_IPV4_CKSUM)
    port_conf.txmode.offloads |= RTE_ETH_RX_OFFLOAD_IPV4_CKSUM;
  if (dev_info.tx_offload_capa & RTE_ETH_RX_OFFLOAD_UDP_CKSUM)
    port_conf.txmode.offloads |= RTE_ETH_RX_OFFLOAD_UDP_CKSUM;

  if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_UDP_CKSUM)
    port_conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_UDP_CKSUM;
  if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_IPV4_CKSUM)
    port_conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_IPV4_CKSUM;

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
  retval = rte_eth_dev_configure(port, nb_rx, nb_tx, &port_conf);
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
  RTE_LCORE_FOREACH(lcore_id){
    auto& tb = info.thread_blocks[idx];  
    tb.s_name = std::format("SEND_POOL-{}", idx);
    tb.r_name = std::format("RECV_POOL-{}", idx++);
    auto [send_pool, recv_pool] =
        alloc_pools(role, static_cast<uint32_t>(nb_rx) * (nb_rxd + burst_size),
                    static_cast<uint32_t>(nb_tx) * (nb_txd + burst_size), tb.r_name, tb.s_name, lcore_id);
    tb.setup_txqueues(port, nb_tx / nb_threads, nb_txd, txconf, send_pool);
    tb.setup_rxqueues(port, nb_rx / nb_threads, nb_rxd, rxconf, recv_pool);
  }
  retval = rte_eth_dev_start(port);
  rte_eth_macaddr_get(port, &info.addr);
  if (retval < 0)
    throw std::runtime_error(
        std::format("Could not start device: {}", strerror(-retval)));
  return 0;
}

void thread_block::setup_rxqueues(uint16_t port, uint32_t nb_rx,
                                  uint16_t nb_desc, rte_eth_rxconf &rxconf,
                                  rte_mempool *pool) {
  recv_pool = {pool, deleter};
  for (uint16_t i = 0; i < nb_rx; ++i) {
    if (rte_eth_rx_queue_setup(port, i, nb_desc, rte_eth_dev_socket_id(port),
                               &rxconf, pool))
      throw std::runtime_error("Failed to setup rxqueue\n");
    rx_queues.push_back(i);
  }
}

void thread_block::setup_txqueues(uint16_t port, uint32_t nb_tx,
                                  uint16_t nb_desc, rte_eth_txconf &txconf,
                                  rte_mempool *pool) {
  send_pool = {pool, deleter};
  for (uint16_t i = 0; i < nb_tx; ++i) {
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
