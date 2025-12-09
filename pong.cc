#include <rte_branch_prediction.h>
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
#include <rte_mempool.h>
#include <sched.h>
#include <signal.h>
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

static bool handle_packet(packet_generator &pg, pkt_t *pkt) {
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
  auto tid = rte_lcore_id();
  std::vector<pkt_t *> pkts(config.burst_size);
  std::vector<pkt_t *> pkts_out(config.burst_size);
  uint16_t nb_rx, nb_tx = 0, nb_rm = 0;
  auto &tb = pinfo.thread_blocks[tid];
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
  uint64_t rcvd = 0;
  for (; !terminate;) {
    nb_rx = 0;
    for (auto qid : tb.rx_queues)
      nb_rx +=
          rte_eth_rx_burst(info.port_id, qid, pkts.data() + nb_rx, config.burst_size);
    rcvd += nb_rx;
    rte_pktmbuf_free_bulk(pkts.data(), nb_rx);
  }
  printf("Packets received: %lu\n", rcvd);
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
    lcore_recv(&adapter);
    break;
  case opmode::PONG:
    lcore_pong(&adapter);
    break;
  default:
    break;
  }
  info.stop_port();
  DPDK_LIFETIME_END
  rte_eal_cleanup();
  return 0;
}
