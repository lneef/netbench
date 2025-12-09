#ifndef PACKET_H
#define PACKET_H

#include <cstdint>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf_core.h>
#include <rte_udp.h>

#include "port.h"

#define TTL 64
#define HDR_SIZE                                                               \
  (sizeof(rte_ether_hdr) + sizeof(rte_ipv4_hdr) + sizeof(rte_udp_hdr))

using pkt_t = rte_mbuf;

class packet_generator {
public:
  packet_generator(capabilities &caps, port_info &info,
                   const benchmark_config &config, uint16_t tid = 0)
      : caps(caps), flow(0), config(config), tid(tid) {
    rte_ether_addr_copy(&info.addr, &addr);
  }
  void packet_eth_ctor(pkt_t *mbuf, rte_ether_hdr *eth);
  void packet_udp_ctor(pkt_t *mbuf, rte_udp_hdr *udp, uint16_t dgram_len);
  void packet_ipv4_ctor(pkt_t *mbuf, rte_ipv4_hdr *ipv4, uint16_t total_length);

  void packet_pp_ctor_udp(pkt_t *mbuf);

  bool packet_pong_ctor(pkt_t* pkt); 

  void packet_ipv4_cksum(pkt_t *mbuf);

  void packet_ipv4_udp_cksum(pkt_t *mbuf);

  bool packet_verify_cksum(pkt_t *mbuf);

  bool packet_verify_rs(pkt_t *mbuf);

  bool packet_verify_ipv4(pkt_t *mbuf);

private:
  capabilities &caps;
  uint16_t flow;
  const benchmark_config &config;
  rte_ether_addr addr;
  uint16_t tid;
};

void packet_mempool_ctor(rte_mempool *mp, void *opaque, void *obj,
                         unsigned obj_idx __rte_unused);

void packet_mempool_ctor_full(rte_mempool *mp, void *opaque, void *obj,
                              unsigned int obj_idx __rte_unused);
#endif
