#include <rte_branch_prediction.h>
#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mbuf_core.h>
#include <rte_mbuf_dyn.h>

#include <arpa/inet.h>
#include <fstream>
#include <rte_mempool.h>
#include <sched.h>
#include <signal.h>
#include <span>
#include <stdalign.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <vector>

#include "packet.h"
#include "port.h"
#include "util.h"

static int terminate = 0;

static void handler(int sig) {
  (void)sig;
  terminate = 1;
}

static bool handle_packet(packet_generator<> &pg, pkt_t *pkt) {
  struct rte_ether_hdr *eth = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
  switch (rte_be_to_cpu_16(eth->ether_type)) {
  case RTE_ETHER_TYPE_IPV4:
    return pg.packet_pong_ctor(pkt);
  default:
    return false;
  }
}

static int lcore_pong(void *port) {
  lcore_adapter *adapter = static_cast<lcore_adapter *>(port);
  auto &[pinfo, config] = *adapter;
  std::vector<pkt_t *> pkts(config.burst_size);
  std::vector<pkt_t *> pkts_out(config.burst_size);
  uint16_t nb_rx, nb_tx = 0, nb_rm = 0;
  auto &tb = pinfo.local();
  packet_generator pg(pinfo.caps, pinfo, config);
  for (; !terminate;) {
    nb_rx = rte_eth_rx_burst(pinfo.port_id, tb.rx_queues.front(), pkts.data(),
                             config.burst_size - nb_rm);
    for (uint16_t i = 0; i < nb_rx; ++i) {
      pkts_out[nb_rm] = pkts[i];
      if (likely(handle_packet(pg, pkts_out[nb_rm])))
        ++nb_rm;
      else
        rte_pktmbuf_free(pkts[i]);
    }

    nb_tx = rte_eth_tx_burst(pinfo.port_id, tb.tx_queues.front(),
                             pkts_out.data(), nb_rm);
    for (uint16_t i = nb_tx, j = 0; i < nb_rm; ++i, ++j)
      pkts_out[j] = pkts_out[i];
    nb_rm = nb_rm - nb_tx;
  }
  return 0;
}

static int lcore_recv(void *port) {
  auto &[info, config] = *static_cast<lcore_adapter *>(port);
  std::vector<pkt_t *> pkts(config.burst_size * config.nb_rx);
  auto &tb = info.local();
  uint16_t nb_rx;
  for (; !terminate;) {
    nb_rx = 0;
    for (auto qid : tb.rx_queues)
      nb_rx += rte_eth_rx_burst(info.port_id, qid, pkts.data() + nb_rx,
                                config.burst_size);
    rte_pktmbuf_free_bulk(pkts.data(), nb_rx);
  }
  return 0;
}

int lcore_count(void *port) {
  static constexpr uint64_t kDefaultCnt = 1e6;
  auto &[info, config] = *static_cast<lcore_adapter *>(port);
  auto &tb = info.local();
  std::vector<pkt_t *> pkts(config.burst_size);
  std::vector<uint64_t> seqs;
  packet_generator pg(info.caps, info, config);
  seqs.reserve(kDefaultCnt);
  auto fill = [&](std::span<pkt_t *> pkts) {
    for (auto *pkt : pkts) {
      auto *eth = rte_pktmbuf_mtod(pkt, rte_ether_hdr *);
      if (eth->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
        continue;
      auto *seq = rte_pktmbuf_mtod_offset(pkt, uint64_t *, kDataOffset);
      seqs.push_back(*seq);
    }
  };
  while (!terminate) {
    auto rxd = rte_eth_rx_burst(info.port_id, tb.rx_queues.front(), pkts.data(),
                                config.burst_size);
    fill(std::span(pkts).subspan(0, rxd));
    rte_pktmbuf_free_bulk(pkts.data(), rxd);
  }
  std::ofstream ofs("seqs_port_" + std::to_string(info.port_id) + ".csv");
  if (ofs) {
    ofs << "entry,seq\n";
    for (size_t i = 0; i < seqs.size(); ++i)
      ofs << i << "," << seqs[i] << "\n";
    ofs.close();

  }
  
  return 0;
}

int lcore_duplex(void *port) {
  auto &[info, config] = *static_cast<lcore_adapter *>(port);
  uint16_t tx_free = config.burst_size;
  auto &tb = info.local();
  packet_generator<udp_builder> pg(info.caps, info, config);
  std::vector<pkt_t *> pkts(tx_free);
  std::vector<pkt_t *> rpkts(tx_free);
  rte_mempool_obj_iter(tb.send_pool.get(),
                       packet_mempool_ctor_full<udp_builder>, &pg);
  rate_limiter rt(config.bps);
  uint64_t cycles = rte_get_timer_cycles();
  uint64_t end = config.rtime * rte_get_timer_hz() + cycles;
  for (; cycles < end; cycles = rte_get_timer_cycles()) {
    auto rx_nb = rte_eth_rx_burst(info.port_id, tb.rx_queues.front(),
                                  rpkts.data(), config.burst_size);
    rte_pktmbuf_free_bulk(rpkts.data(), rx_nb);
    tb.per_thread_stat.received += rx_nb;

    if (!rte_mempool_get_bulk(tb.send_pool.get(), (void **)pkts.data(),
                              tx_free))
      tx_free = 0;
    if (rt.sendable(cycles, ((config.burst_size - tx_free) * config.mtu))) {
      auto tx_nb =
          rte_eth_tx_burst(info.port_id, tb.tx_queues.front(),
                           pkts.data() + tx_free, config.burst_size - tx_free);
      tx_free += tx_nb;
      tb.per_thread_submit_stat.submitted += tx_nb;
      rt.notify(rte_get_timer_cycles(), tx_nb, config.mtu);
    }
  }
  sleep(3);
  return 0;
}

int main(int argc, char *argv[]) {
  struct sigaction sa = {};
  sa.sa_handler = handler;
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);
  int dpdk_argc = rte_eal_init(argc, argv);
  DPDK_LIFETIME_BEGIN
  port_info info;
  benchmark_config config;
  config.port_init_cmdline(argc - dpdk_argc, argv + dpdk_argc);
  config.port_init(info);
  lcore_adapter adapter{info, config};

  switch (config.role) {
  case opmode::RECEIVE:
    launch_lcores(lcore_recv, &adapter);
    break;
  case opmode::PONG:
    launch_lcores(lcore_pong, &adapter);
    break;
  case opmode::DUPLEX:
    launch_lcores(lcore_duplex, &adapter);
    break;
  case opmode::COUNT:
    launch_lcores(lcore_count, &adapter);
    break;
  default:
    break;
  }
  print_stats(info);
  info.stop_port();
  DPDK_LIFETIME_END
  rte_eal_cleanup();
  return 0;
}
