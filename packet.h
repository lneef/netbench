#ifndef PACKET_H
#define PACKET_H

#include <cstdint>
#include <limits>
#include <netinet/in.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_lcore.h>
#include <rte_mbuf_core.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <type_traits>

#include "port.h"

using pkt_t = rte_mbuf;

static constexpr uint16_t kDefaultTTL = 64;
struct l4_builder {
  static constexpr uint16_t kHeaderOffSet =
      sizeof(rte_ether_hdr) + sizeof(rte_ipv4_hdr);
  static constexpr uint16_t kDefaultRxPort = 12345;
  const benchmark_config &config;
  uint16_t flow;
  uint16_t tid;
  l4_builder(const benchmark_config &config)
      : config(config), flow(0), tid(rte_lcore_index(rte_lcore_id())) {}
};

struct udp_builder : l4_builder {
  uint16_t len;
  udp_builder(const benchmark_config &config)
      : l4_builder(config), len(config.mtu - sizeof(rte_ipv4_hdr)) {}

  void build_l4_header(pkt_t *pkt) {
    auto *udp = rte_pktmbuf_mtod_offset(pkt, rte_udp_hdr *, kHeaderOffSet);
    udp->src_port = rte_cpu_to_be_16(flow * rte_lcore_count() + tid);
    udp->dst_port = rte_cpu_to_be_16(kDefaultRxPort);
    udp->dgram_len = rte_cpu_to_be_16(config.mtu - sizeof(rte_ipv4_hdr));
    udp->dgram_cksum = 0;
    pkt->l4_len = sizeof(*udp);
    pkt->data_len += len;
    pkt->pkt_len += len;
    flow = (flow + 1) % config.flows;
  }

  void packet_cksum(pkt_t *pkt, capabilities &caps) {
    struct rte_ipv4_hdr *ipv4 = rte_pktmbuf_mtod_offset(
        pkt, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(ipv4 + 1);
    udp->dgram_cksum = 0;
    ipv4->hdr_checksum = 0;
    if (!caps.l4_cksum_tx) {
      udp->dgram_cksum = rte_ipv4_udptcp_cksum(ipv4, udp);
    } else {
      pkt->ol_flags |=
          RTE_MBUF_F_TX_UDP_CKSUM | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_IPV4;
      udp->dgram_cksum = rte_ipv4_phdr_cksum(ipv4, pkt->ol_flags);
    }
  }

  bool verify_cksum(pkt_t *pkt, capabilities &caps) {
    struct rte_ipv4_hdr *ipv4 = rte_pktmbuf_mtod_offset(
        pkt, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(ipv4 + 1);
    if (likely(caps.l4_cksum_rx))
      return (pkt->ol_flags & RTE_MBUF_F_RX_L4_CKSUM_BAD) == 0;
    else
      return rte_ipv4_udptcp_cksum_verify(ipv4, udp) == 0;
  }

  uint16_t ip_next_proto() const { return IPPROTO_UDP; }

  uint16_t data_offset() const{
      return kHeaderOffSet + sizeof(rte_udp_hdr);
  }
};

struct tcp_builder : l4_builder {
  uint16_t len;
  tcp_builder(const benchmark_config &config)
      : l4_builder(config), len(config.mtu - sizeof(rte_ipv4_hdr)) {}

  void build_l4_header(pkt_t *pkt) {
    auto *tcp_header =
        rte_pktmbuf_mtod_offset(pkt, rte_tcp_hdr *, kHeaderOffSet);
    tcp_header->data_off = (sizeof(rte_tcp_hdr) / 4) << 4;
    tcp_header->tcp_urp = 0;
    tcp_header->recv_ack = 0;
    tcp_header->sent_seq = 0;
    tcp_header->cksum = 0;
    tcp_header->rx_win = rte_cpu_to_be_16(std::numeric_limits<uint16_t>::max());
    tcp_header->src_port = rte_cpu_to_be_16(flow * rte_lcore_count() + tid);
    tcp_header->dst_port = rte_cpu_to_be_16(kDefaultRxPort);
    pkt->l4_len = sizeof(*tcp_header);
    pkt->data_len += len;
    pkt->pkt_len += len;
    pkt->tso_segsz = config.tcp_mss;
    pkt->ol_flags |= RTE_MBUF_F_TX_TCP_SEG;
    flow = (flow + 1) % config.flows;
  }

  void packet_cksum(pkt_t *pkt, capabilities &caps) {
    rte_ipv4_hdr *ipv4 = rte_pktmbuf_mtod_offset(
        pkt, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(ipv4 + 1);
    tcp->cksum = 0;
    ipv4->hdr_checksum = 0;
    if (!caps.l4_cksum_tx) {
       tcp->cksum = rte_ipv4_udptcp_cksum(ipv4, tcp);
    } else {
      pkt->ol_flags |=
          RTE_MBUF_F_TX_TCP_CKSUM | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_IPV4;
      tcp->cksum = rte_ipv4_phdr_cksum(ipv4, pkt->ol_flags);
    }
  }

  bool verify_cksum(pkt_t *pkt, capabilities &caps) {
    struct rte_ipv4_hdr *ipv4 = rte_pktmbuf_mtod_offset(
        pkt, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(ipv4 + 1);
    if (likely(caps.l4_cksum_rx))
      return (pkt->ol_flags & RTE_MBUF_F_RX_L4_CKSUM_BAD) == 0;
    else
      return rte_ipv4_udptcp_cksum_verify(ipv4, tcp) == 0;
  }

  uint16_t ip_next_proto() const { return IPPROTO_TCP; }

  uint16_t data_offset() const{
      return kHeaderOffSet + sizeof(rte_tcp_hdr);
  }
};

template <typename L4 = udp_builder> class packet_generator {
public:
  packet_generator(capabilities &caps, port_info &info,
                   const benchmark_config &config)
      : caps(caps), config(config),
        l4(config) {
    rte_ether_addr_copy(&info.addr, &addr);
  }

  uint16_t data_offset() const{
      return l4.data_offset();
  }

  void packet_eth_ctor(pkt_t *mbuf, rte_ether_hdr *eth) {
    rte_ether_addr_copy(&addr, &eth->src_addr);
    rte_ether_addr_copy(&config.dmac, &eth->dst_addr);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    mbuf->l2_len = sizeof(struct rte_ether_hdr);
    mbuf->data_len += sizeof(struct rte_ether_hdr);
    mbuf->pkt_len += sizeof(struct rte_ether_hdr);
  }

  void packet_ipv4_ctor(pkt_t *mbuf, struct rte_ipv4_hdr *ipv4,
                        uint16_t total_length) {
    ipv4->src_addr = config.sip;
    ipv4->dst_addr = config.dip;
    ipv4->version_ihl = RTE_IPV4_VHL_DEF;
    ipv4->time_to_live = kDefaultTTL;
    ipv4->next_proto_id = l4.ip_next_proto();
    ipv4->total_length = rte_cpu_to_be_16(total_length);
    ipv4->packet_id = 0;
    ipv4->fragment_offset = 0;
    ipv4->hdr_checksum = 0;
    ipv4->type_of_service = 0x02;
    mbuf->l3_len = sizeof(struct rte_ipv4_hdr);
    mbuf->data_len += sizeof(struct rte_ipv4_hdr);
    mbuf->pkt_len += sizeof(struct rte_ipv4_hdr);
  }

  void packet_ctor(pkt_t *mbuf) {
    rte_ether_hdr *eth = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    rte_ipv4_hdr *ipv4 = (struct rte_ipv4_hdr *)(eth + 1);
    mbuf->data_len = 0;
    mbuf->pkt_len = 0;
    l4.build_l4_header(mbuf);
    packet_ipv4_ctor(mbuf, ipv4, config.mtu);
    packet_eth_ctor(mbuf, eth);
    mbuf->nb_segs = 1;
  }

  bool packet_pong_ctor(pkt_t *pkt) {
    static_assert(std::is_same_v<L4, udp_builder>, "No Tcp Supported");  
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    struct rte_ipv4_hdr *ipv4 = (struct rte_ipv4_hdr *)(eth + 1);
    struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(ipv4 + 1);
    assert(pkt->packet_type & RTE_PTYPE_L3_IPV4);
    assert(pkt->packet_type & RTE_PTYPE_L4_UDP);
    if (!packet_verify_cksum(pkt)) {
      rte_log(RTE_LOG_INFO, RTE_LOGTYPE_USER1, "invalid checksum\n");
      return false;
    }
    pkt->l2_len = sizeof(rte_ether_hdr);
    pkt->l3_len = sizeof(rte_ipv4_hdr);
    pkt->l4_len = sizeof(rte_udp_hdr);
    pkt->ol_flags = 0;
    udp->dgram_cksum = 0;
    ipv4->hdr_checksum = 0;
    ipv4->time_to_live = kDefaultTTL;
    SWAP(udp->src_port, udp->dst_port, decltype(udp->dst_port));
    SWAP(ipv4->src_addr, ipv4->dst_addr, decltype(ipv4->src_addr));
    rte_ether_addr_copy(&eth->src_addr, &eth->dst_addr);
    rte_ether_addr_copy(&addr, &eth->src_addr);
    packet_cksum(pkt);
    return true;
  }

  void packet_ipv4_cksum(pkt_t *mbuf) {
    struct rte_ipv4_hdr *ipv4 = rte_pktmbuf_mtod_offset(
        mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    if (!caps.ip_cksum_tx)
      ipv4->hdr_checksum = rte_ipv4_cksum(ipv4);
    else
      mbuf->ol_flags |= RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_IPV4;
  }

  void packet_cksum(pkt_t *mbuf) {
    l4.packet_cksum(mbuf, caps);  
    packet_ipv4_cksum(mbuf);
  }

  bool packet_verify_cksum(pkt_t *mbuf) {
    struct rte_ipv4_hdr *ipv4 = rte_pktmbuf_mtod_offset(
        mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    if (likely(caps.ip_cksum_rx)) {
      if (mbuf->ol_flags & RTE_MBUF_F_RX_IP_CKSUM_BAD)
        return false;
    } else {
      if (rte_ipv4_cksum(ipv4))
        return false;
    }
    return l4.verify_cksum(mbuf, caps);
  }

  bool packet_verify_rs(pkt_t *mbuf) {
    struct rte_ipv4_hdr *ipv4 = rte_pktmbuf_mtod_offset(
        mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    return ipv4->dst_addr == config.sip && ipv4->src_addr == config.dip;
  }

  bool packet_verify_ipv4(pkt_t *mbuf) {
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    return rte_be_to_cpu_16(eth->ether_type) == RTE_ETHER_TYPE_IPV4;
  }

private:
  capabilities &caps;
  const benchmark_config &config;
  rte_ether_addr addr;
  L4 l4;
};

template <typename L4>
void packet_mempool_ctor(rte_mempool *mp, void *opaque, void *obj,
                         unsigned obj_idx __rte_unused) {
  struct rte_mbuf *mbuf = (struct rte_mbuf *)obj;
  auto *pg = static_cast<packet_generator<L4> *>(opaque);
  pg->packet_ctor(mbuf);

  mbuf->pool = mp;
  mbuf->next = NULL;
}

template <typename L4>
void packet_mempool_ctor_full(struct rte_mempool *mp, void *opaque, void *obj,
                              unsigned int obj_idx __rte_unused) {
  rte_mbuf *mbuf = (struct rte_mbuf *)obj;
  auto *pg = static_cast<packet_generator<L4> *>(opaque);
  pg->packet_ctor(mbuf);

  pg->packet_cksum(mbuf);
  mbuf->pool = mp;
  mbuf->next = NULL;
}

#endif
