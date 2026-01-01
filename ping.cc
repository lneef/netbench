#include <cstdint>
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
#include <rte_memcpy.h>
#include <rte_mempool.h>
#include <rte_udp.h>
#include <stdalign.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "packet.h"
#include "port.h"
#include "statistics.h"
#include "util.h"

static uint16_t handle_pong_rdtsc(packet_generator &pg, stat &statistics,
                                  std::span<pkt_t *> pkts, uint16_t nb_rx) {
  struct pkt_content_rdtsc pc, rc;
  uint64_t elapsed = 0;
  uint16_t rx_count = 0;
  pc.time = rte_get_timer_cycles();
  for (auto *pkt : pkts.subspan(0, nb_rx)) {
    uint8_t *data = rte_pktmbuf_mtod_offset(pkt, uint8_t *, HDR_SIZE);
    if (!pg.packet_verify_ipv4(pkt) || !pg.packet_verify_rs(pkt))
      continue;
    ++rx_count;
    if (!pg.packet_verify_cksum(pkt)) {
      ++statistics.cksum_incorrect;
      continue;
    }
    PUN(&rc, data, typeof(rc));
    elapsed = pc.time - rc.time;
    statistics.time += elapsed;
    statistics.min = RTE_MIN(statistics.min, elapsed);
    ++statistics.received;
  }
  rte_pktmbuf_free_bulk(pkts.data(), nb_rx);
  return rx_count;
}

static void add_timestamp_rtdsc(packet_generator &pg, std::span<pkt_t *> pkts) {
  struct pkt_content_rdtsc pc = {.time = rte_get_timer_cycles()};
  for (auto *pkt : pkts) {
    uint8_t *data = rte_pktmbuf_mtod_offset(pkt, uint8_t *, HDR_SIZE);
    PUN(data, &pc, typeof(pc));
    pg.packet_ipv4_udp_cksum(pkt);
  }
}

static void print_submit_stat(submit_stat &submit_statistics,
                              [[maybe_unused]] benchmark_config &config) {
  printf("Submitted PPS: %.2f\n",(double)(submit_statistics.submitted));
}

static void print_stats(stat &statistics, submit_stat &submit_statistics,
                        benchmark_config &config) {
  double avg_latency_us = (double)statistics.time / (rte_get_timer_hz() / 1e6) /
                          statistics.received;
  double min_latency_us = (double)statistics.min / (rte_get_timer_hz() / 1e6);
  printf("-----Statistics-----\n");
  printf("Reached PPS: %.2f\n", (double)(statistics.received) / config.rtime);
  printf("Average latency: %.2f us -- Min latency: %.2f\n", avg_latency_us,
         min_latency_us);
  print_submit_stat(submit_statistics, config);
  printf("Packets with incorrect checksum: %lu \n", statistics.cksum_incorrect);
}

int lcore_ping(void *port) {
  auto &[info, config] = *static_cast<lcore_adapter *>(port);
  auto &tb = info.local();
  packet_generator pg(info.caps, info, config);
  std::vector<pkt_t *> pkts(config.burst_size);
  std::vector<pkt_t *> rpkts(config.burst_size);
  auto tx_queue = tb.tx_queues.front();
  auto rx_queue = tb.tx_queues.front();

  rte_mempool_obj_iter(tb.send_pool.get(), packet_mempool_ctor, &pg);
  uint16_t tx_nb = config.burst_size;
  uint64_t cycles = rte_get_timer_cycles();
  uint64_t end = config.rtime * rte_get_timer_hz() + cycles;

  for (; cycles < end; cycles = rte_get_timer_cycles()) {
    if (rte_mempool_get_bulk(tb.send_pool.get(), (void **)pkts.data(), tx_nb)) {
      rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1,
              "Failed to allocated burst of size %u\n", tx_nb);
      continue;
    }
    add_timestamp_rtdsc(pg, pkts);
    tx_nb = rte_eth_tx_burst(info.port_id, tx_queue, pkts.data(),
                             config.burst_size);
    tb.per_thread_submit_stat.submitted += tx_nb;
    uint16_t rx_nb = 0, rx_total = 0;
    do {
      rx_nb = rte_eth_rx_burst(info.port_id, rx_queue, rpkts.data(),
                               config.burst_size);
      if (rx_nb)
        rx_total += handle_pong_rdtsc(pg, tb.per_thread_stat, rpkts, rx_nb);

    } while (rx_total < tx_nb && rte_get_timer_cycles() < end);
  }
  return 0;
}

template <bool mq> int lcore_send(void *port) {
  auto &[info, config] = *static_cast<lcore_adapter *>(port);
  uint16_t tx_free = config.burst_size * config.nb_tx, tx_nb;
  auto &tb = info.local();
  packet_generator pg(info.caps, info, config);
  std::vector<pkt_t *> pkts(tx_free);
  rte_mempool_obj_iter(tb.send_pool.get(), packet_mempool_ctor_full, &pg);
  uint64_t cycles = rte_get_timer_cycles();
  uint64_t end = config.rtime * rte_get_timer_hz() + cycles;
  for (; cycles < end; cycles = rte_get_timer_cycles()) {
    if (!rte_mempool_get_bulk(tb.send_pool.get(), (void **)pkts.data(),
                              tx_free))
      tx_free = 0;
    tx_nb = 0;
    if constexpr (mq) {
      for (auto qid : tb.tx_queues) {
        auto burst_size = std::min<uint16_t>(config.burst_size,
                                             pkts.size() - tx_free - tx_nb);
        tx_nb += rte_eth_tx_burst(info.port_id, qid,
                                  pkts.data() + tx_free + tx_nb, burst_size);
      }
    } else {
      tx_nb = rte_eth_tx_burst(info.port_id, tb.tx_queues.front(),
                               pkts.data() + tx_free, config.burst_size - tx_free);
    }
    tx_free += tx_nb;
    tb.per_thread_submit_stat.submitted += tx_nb;
  }
  return 0;
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
  case opmode::FORWARD: {
    submit_stat submit_stats{};
    if (config.nb_tx > 1)
      launch_lcores(lcore_send<true>, &adapter);
    else
      launch_lcores(lcore_send<false>, &adapter);
    info.collect_submit_statistics(submit_stats);
    print_submit_stat(submit_stats, config);
    break;
  }
  case opmode::PING: {
    submit_stat submit_stats{};
    stat stats{};
    launch_lcores(lcore_ping, &adapter);
    lcore_ping(&adapter);
    info.collect_statistics(stats);
    info.collect_submit_statistics(submit_stats);
    print_stats(stats, submit_stats, config);
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
