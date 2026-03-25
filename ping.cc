#include <cstdint>
#include <cstring>
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

void dump_pkt(rte_mbuf *msg, uint16_t len) {
  static constexpr size_t bytes_per_line = 16;
  auto *data = rte_pktmbuf_mtod(msg, char *);
  for (size_t i = 0; i < len; i += bytes_per_line) {
    printf("%04zx  ", i);
    for (size_t j = 0; j < bytes_per_line; ++j) {
      if (i + j < len)
        printf("%02x ", data[i + j]);
      else
        printf("   ");
    }
    printf("\n");
  }
}

static uint16_t handle_pong_rdtsc(packet_generator<> &pg, stat &statistics,
                                  std::span<pkt_t *> pkts, uint16_t nb_rx) {
  struct pkt_content_rdtsc pc, rc;
  uint64_t elapsed = 0;
  uint16_t rx_count = 0;
  pc.time = rte_get_timer_cycles();
  for (auto *pkt : pkts.subspan(0, nb_rx)) {
    uint8_t *data = rte_pktmbuf_mtod_offset(pkt, uint8_t *, pg.data_offset());
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

static void add_timestamp_rtdsc(packet_generator<> &pg,
                                std::span<pkt_t *> pkts) {
  struct pkt_content_rdtsc pc = {.time = rte_get_timer_cycles()};
  for (auto *pkt : pkts) {
    uint8_t *data = rte_pktmbuf_mtod_offset(pkt, uint8_t *, pg.data_offset());
    PUN(data, &pc, typeof(pc));
    pg.packet_cksum(pkt);
  }
}

static void insert_seq(pkt_t * pkt, uint64_t &seq) {
    auto *seq_ptr = rte_pktmbuf_mtod_offset(pkt, uint8_t *, kDataOffset);
    std::memcpy(seq_ptr, &seq, sizeof(seq));
    ++seq;
  
}

static void print_submit_stat(submit_stat &submit_statistics,
                              [[maybe_unused]] benchmark_config &config) {
  printf("Submitted PPS: %.2f\n",
         (double)(submit_statistics.submitted) / config.rtime);
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
  packet_generator<> pg(info.caps, info, config);
  std::vector<pkt_t *> pkts(config.burst_size);
  std::vector<pkt_t *> rpkts(config.burst_size);
  auto tx_queue = tb.tx_queues.front();
  auto rx_queue = tb.rx_queues.front();

  rte_mempool_obj_iter(tb.send_pool.get(), packet_mempool_ctor<udp_builder>,
                       &pg);
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

template <bool mq, typename L4> int lcore_send(void *port) {
  auto &[info, config] = *static_cast<lcore_adapter *>(port);
  uint16_t tx_free = config.burst_size * config.nb_tx, tx_nb;
  auto &tb = info.local();
  packet_generator<L4> pg(info.caps, info, config);
  std::vector<pkt_t *> pkts(tx_free);
  rte_mempool_obj_iter(tb.send_pool.get(), packet_mempool_ctor_full<L4>, &pg);
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
      tx_nb =
          rte_eth_tx_burst(info.port_id, tb.tx_queues.front(),
                           pkts.data() + tx_free, config.burst_size - tx_free);
    }
    tx_free += tx_nb;
    tb.per_thread_submit_stat.submitted += tx_nb;
  }
  sleep(3);
  return 0;
}

template <typename L4> int lcore_count(void *port) {
  static constexpr uint64_t kDefaultCnt = 1e6;
  assert(rte_lcore_count() == 1);
  auto &[info, config] = *static_cast<lcore_adapter *>(port);
  uint16_t tx_free = config.burst_size, tx_nb;
  auto &tb = info.local();
  packet_generator<L4> pg(info.caps, info, config);
  std::vector<pkt_t *> pkts(tx_free);
  std::vector<uint16_t> flows(config.flows);
  for (auto &f : flows)
    f = rte_rand() % UINT16_MAX;
  uint16_t flow_idx = 0;
  uint64_t txd = 0;
  uint64_t seq = 0;
  for (; txd < kDefaultCnt;) {
    assert(tx_free <= config.burst_size);  
    auto pending = config.burst_size - tx_free;
    if (!rte_mempool_get_bulk(tb.send_pool.get(),
                              (void **)pkts.data() + pending, tx_free)) {
      for (auto *pkt : std::span(pkts).subspan(pending, tx_free)) {
        pg.packet_ctor_burst(pkt, flows[flow_idx]);
        insert_seq(pkt, seq);
        pg.packet_cksum(pkt);
          flow_idx = (flow_idx + 1) % config.flows;
      }
      tx_free = 0;
    }
    pending = config.burst_size - tx_free;
    tx_nb = rte_eth_tx_burst(info.port_id, tb.tx_queues.front(), pkts.data(),
                             pending);

    for (uint16_t i = tx_nb, j = 0; i < pending; ++i, ++j)
      pkts[j] = pkts[i];
    tx_free += tx_nb;
    txd += tx_nb;

    tb.per_thread_submit_stat.submitted += tx_nb;
  }
  sleep(3);
  return 0;
}

int lcore_duplex(void *port) {
  auto &[info, config] = *static_cast<lcore_adapter *>(port);
  uint16_t tx_free = config.burst_size;
  auto &tb = info.local();
  packet_generator<udp_builder> pg(info.caps, info, config);
  rate_limiter rt(config.bps);
  std::vector<pkt_t *> pkts(tx_free);
  std::vector<pkt_t *> rpkts(tx_free);
  rte_mempool_obj_iter(tb.send_pool.get(),
                       packet_mempool_ctor_full<udp_builder>, &pg);
  uint64_t cycles = rte_get_timer_cycles();
  uint64_t end = config.rtime * rte_get_timer_hz() + cycles;
  for (; cycles < end; cycles = rte_get_timer_cycles()) {
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
    auto rx_nb = rte_eth_rx_burst(info.port_id, tb.rx_queues.front(),
                                  rpkts.data(), config.burst_size);
    rte_pktmbuf_free_bulk(rpkts.data(), rx_nb);
    tb.per_thread_stat.received += rx_nb;
  }
  sleep(3);
  return 0;
}

void launch_forward(lcore_adapter &adapter) {
  auto &config = adapter.config;
  switch (config.transport) {
  case l4::UDP: {
    if (config.nb_tx > 1)
      launch_lcores(lcore_send<true, udp_builder>, &adapter);
    else
      launch_lcores(lcore_send<false, udp_builder>, &adapter);
    break;
  }
  case l4::TCP: {
    if (config.nb_tx > 1)
      launch_lcores(lcore_send<true, tcp_builder>, &adapter);
    else
      launch_lcores(lcore_send<false, tcp_builder>, &adapter);
    break;
  }
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
  case opmode::FORWARD: {
    submit_stat submit_stats{};
    launch_forward(adapter);
    info.collect_submit_statistics(submit_stats);
    print_submit_stat(submit_stats, config);
    break;
  }
  case opmode::PING: {
    submit_stat submit_stats{};
    stat stats{};
    launch_lcores(lcore_ping, &adapter);
    info.collect_statistics(stats);
    info.collect_submit_statistics(submit_stats);
    print_stats(stats, submit_stats, config);
    break;
  }
  case opmode::DUPLEX: {
    submit_stat submit_stats{};
    stat stats{};
    launch_lcores(lcore_duplex, &adapter);
    info.collect_statistics(stats);
    info.collect_submit_statistics(submit_stats);
    print_stats(stats, submit_stats, config);
    break;
  }
  case opmode::COUNT: {
    submit_stat submit_stats{};
    stat stats{};
    launch_lcores(lcore_count<udp_builder>, &adapter);
    break;
  }

  default:
    break;
  }
  print_stats(info);
  info.stop_port();
  DPDK_LIFETIME_END
  rte_eal_cleanup();
  return 0;
}
