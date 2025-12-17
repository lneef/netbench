#include <cstdint>
#include <format>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_cycles.h>
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
#include <span>

#include <arpa/inet.h>
#include <iostream>
#include <rte_memcpy.h>
#include <rte_mempool.h>
#include <rte_udp.h>
#include <stdalign.h>
#include <stdbool.h>
#include <stdint.h>

#include "packet.h"
#include "port.h"
#include "rudp.h"
#include "statistics.h"
#include "util.h"

void send_rudp(void *port) {
  auto &[info, config] = *static_cast<lcore_adapter *>(port);
  auto &tb = info.local();

  packet_generator pg(info.caps, info, config);
  peer rudp_peer{info.port_id,
                 tb.tx_queues.front(),
                 tb.rx_queues.front(),
                 info.max_desv_txq,
                 2ull * config.burst_size,
                 tb.send_pool,
                 pg};

  uint16_t tx_free = config.burst_size, tx_nb;
  std::vector<pkt_t *> pkts(tx_free);
  std::vector<pkt_t *> rpkts(tx_free);
  rte_mempool_obj_iter(tb.send_pool.get(), packet_mempool_ctor_full, &pg);
  auto start_it = pkts.begin();
  auto end_it = pkts.end();
  uint64_t cycles = rte_get_timer_cycles();
  uint64_t end = config.rtime * rte_get_timer_hz() + cycles;
  for (; cycles < end; cycles = rte_get_timer_cycles()) {
    if (!rte_mempool_get_bulk(tb.send_pool.get(), (void **)pkts.data(),
                              tx_free))
      tx_free = 0;
    tx_nb = rudp_peer.submit_tx_burst(std::span(start_it + tx_free, end_it));
    tx_free += tx_nb;
    uint16_t nb_rx = 0;
    do {
      nb_rx += rudp_peer.submit_rx_burst(rpkts);
    } while (nb_rx < tx_nb);
    rte_pktmbuf_free_bulk(rpkts.data(), nb_rx);
    tb.per_thread_submit_stat.submitted += tx_nb;
  }
  rudp_peer.make_progress();
  auto stats = rudp_peer.get_stats();
  std::cout << std::format(
                   "acked: {}, retransmitted: {}, sent: {}, rtt: {:2}\n",
                   stats.acked, stats.retransmitted, stats.sent, stats.rtt)
            << std::endl;
}

void recv_rudp(void *port) {
  auto &[info, config] = *static_cast<lcore_adapter *>(port);
  auto &tb = info.local();

  packet_generator pg(info.caps, info, config);
  peer rudp_peer{info.port_id,
                 tb.tx_queues.front(),
                 tb.rx_queues.front(),
                 info.max_desv_txq,
                 2ull * config.burst_size,
                 tb.send_pool,
                 pg};

  uint16_t tx_free = config.burst_size, tx_nb;
  uint16_t queued = 0;
  std::vector<pkt_t *> pkts(tx_free);
  std::vector<pkt_t *> rpkts(tx_free);
  auto start_it = pkts.begin();
  uint64_t cycles = rte_get_timer_cycles();
  uint64_t end = config.rtime * rte_get_timer_hz() + cycles;
  for (; cycles < end; cycles = rte_get_timer_cycles()) {
    auto nb_rx = rudp_peer.submit_rx_burst(pkts);
    for (auto *pkt : std::span(start_it, start_it + nb_rx)) {
      pg.packet_pong_ctor(pkt);
      rpkts[queued++] = pkt;
    }

    tx_nb = 0;
    if (queued)
      tx_nb = rudp_peer.submit_tx_burst(
          std::span(rpkts.begin(), rpkts.begin() + queued));
    rudp_peer.make_progress();
    for (uint16_t i = tx_nb, j = 0; i < nb_rx; ++i)
      rpkts[j++] = rpkts[i];
    tb.per_thread_submit_stat.submitted += tx_nb;
    queued -= tx_nb;
  }
}

int main(int argc, char *argv[]) {
  int dpdk_argc = rte_eal_init(argc, argv);
  DPDK_LIFETIME_BEGIN
  port_info info;
  benchmark_config config;
  config.port_init_cmdline(argc - dpdk_argc, argv + dpdk_argc);
  config.port_init(info);
  lcore_adapter adapter{info, config};

  switch (config.role) {
  case opmode::PING: {
    send_rudp(&adapter);
    break;
  }
  case opmode::PONG: {
    recv_rudp(&adapter);
    break;
  }
  default:
    break;
  }
  info.stop_port();
  DPDK_LIFETIME_END
  rte_eal_cleanup();
  return 0;
}
