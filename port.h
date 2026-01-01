#pragma once
#include <cstdint>
#include <memory>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mbuf_core.h>
#include <rte_mempool.h>
#include <rte_ring.h>

#include <arpa/inet.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <string>
#include <unistd.h>

#include <memory.h>
#include <vector>

#include "statistics.h"
#include "util.h"

#define MEMPOOL_CACHE_SIZE 256

#define ETHER_SIZE (RTE_ETHER_MAX_LEN + RTE_PKTMBUF_HEADROOM)
#define JUMBO_SIZE (RTE_ETHER_MAX_JUMBO_FRAME_LEN + RTE_PKTMBUF_HEADROOM)

enum class opmode { PING, PONG, FORWARD, RECEIVE };

struct capabilities {
  bool ip_cksum_tx, ip_cksum_rx;
  bool l4_cksum_tx, l4_cksum_rx;
};

struct port_info;
struct benchmark_config {
  static constexpr uint16_t DEFAULT_BURST_SIZE = 32;
  static constexpr uint64_t DEFAULT_RTIME = 1;
  static constexpr uint16_t DEFAULT_FRAME_SIZE =
      RTE_ETHER_MIN_LEN - RTE_ETHER_CRC_LEN;
  uint32_t sip, dip;
  uint32_t frame_size;
  uint64_t rtime;
  uint16_t burst_size;
  uint16_t flows;
  uint16_t nb_threads;
  uint16_t nb_tx, nb_rx;
  uint32_t mbuf_size;
  rte_ether_addr dmac;
  opmode role;
  benchmark_config()
      : frame_size(DEFAULT_FRAME_SIZE), rtime(DEFAULT_RTIME),
        burst_size(DEFAULT_BURST_SIZE), flows(1), nb_threads(1), nb_tx(1),
        nb_rx(1), mbuf_size(RTE_MBUF_DEFAULT_BUF_SIZE) {}
  int port_init_cmdline(int argc, char **argv);
  int port_init(port_info &info);
};

static constexpr auto deleter = [](rte_mempool *pool) {
  if (pool)
    rte_mempool_free(pool);
};

struct thread_block {
  std::vector<uint16_t> rx_queues;
  std::vector<uint16_t> tx_queues;
  stat per_thread_stat;
  submit_stat per_thread_submit_stat;
  std::shared_ptr<rte_mempool> recv_pool;
  std::shared_ptr<rte_mempool> send_pool;
  std::string r_name, s_name;

  thread_block() : per_thread_stat(), per_thread_submit_stat() {}

  void setup_rxqueues(uint16_t port, uint32_t nb_rx, uint16_t nb_desc,
                      rte_eth_rxconf &rxconf, rte_mempool *pool);
  void setup_txqueues(uint16_t port, uint32_t nb_tx, uint16_t nb_desc,
                      rte_eth_txconf &txconf, rte_mempool *pool);
};

struct port_info {
  uint16_t port_id;
  aligned_vector<thread_block> thread_blocks;
  capabilities caps;
  uint32_t max_desc_rxq, max_desv_txq;
  rte_ether_addr addr;
  port_info() : port_id(0) {}

  thread_block &local() {
    return thread_blocks[rte_lcore_index(rte_lcore_id())];
  }
  void stop_port() { rte_eth_dev_stop(port_id); }
  void collect_statistics(stat &statistics);

  void collect_submit_statistics(submit_stat &statistics);
};
