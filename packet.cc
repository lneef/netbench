#include <assert.h>
#include <cstdint>
#include <rte_branch_prediction.h>
#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_mbuf_core.h>
#include <rte_udp.h>
#include <stdint.h>

#include "packet.h"
#include "port.h"
#include "util.h"

void packet_generator::packet_eth_ctor(pkt_t *mbuf, rte_ether_hdr* eth) {
  rte_ether_addr_copy(&addr, &eth->src_addr);
  rte_ether_addr_copy(&config.dmac, &eth->dst_addr);
  eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
  mbuf->l2_len = sizeof(struct rte_ether_hdr);
  mbuf->data_len += sizeof(struct rte_ether_hdr);
  mbuf->pkt_len += sizeof(struct rte_ether_hdr);
}

void packet_generator::packet_udp_ctor(pkt_t *mbuf, rte_udp_hdr* udp, uint16_t dgram_len) {
  udp->src_port = rte_cpu_to_be_16(flow * config.nb_threads + tid);
  udp->dst_port = rte_cpu_to_be_16(flow);
  udp->dgram_len = rte_cpu_to_be_16(dgram_len);
  udp->dgram_cksum = 0;
  mbuf->l4_len = sizeof(struct rte_udp_hdr);
  mbuf->data_len += dgram_len;
  mbuf->pkt_len += dgram_len;
  flow = (flow + 1) % config.flows;
}

void packet_generator::packet_ipv4_ctor(pkt_t *mbuf, struct rte_ipv4_hdr *ipv4, uint16_t total_length) {
  ipv4->src_addr = config.sip;
  ipv4->dst_addr = config.dip;
  ipv4->version_ihl = RTE_IPV4_VHL_DEF;
  ipv4->time_to_live = TTL;
  ipv4->next_proto_id = IPPROTO_UDP;
  ipv4->total_length = rte_cpu_to_be_16(total_length);
  ipv4->packet_id = 0;
  ipv4->fragment_offset = 0;
  ipv4->type_of_service = 0;
  ipv4->hdr_checksum = 0;
  ipv4->type_of_service = 0x02;
  mbuf->l3_len = sizeof(struct rte_ipv4_hdr);
  mbuf->data_len += sizeof(struct rte_ipv4_hdr);
  mbuf->pkt_len += sizeof(struct rte_ipv4_hdr);
}

void packet_generator::packet_pp_ctor_udp(pkt_t *mbuf) {
  packet_pp_ctor_udp(mbuf, config.frame_size - HDR_SIZE);  
}

void packet_generator::packet_pp_ctor_udp(pkt_t *mbuf, std::size_t msg_size) {
  rte_ether_hdr *eth = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
  rte_ipv4_hdr *ipv4 = (struct rte_ipv4_hdr *)(eth + 1);
  rte_udp_hdr *udp = (struct rte_udp_hdr *)(ipv4 + 1);
  mbuf->data_len = 0;
  mbuf->pkt_len = 0;
  uint32_t payload = msg_size;
  packet_udp_ctor(mbuf, udp, payload += sizeof(struct rte_udp_hdr));
  packet_ipv4_ctor(mbuf, ipv4, payload += sizeof(struct rte_ipv4_hdr));
  packet_eth_ctor(mbuf, eth);
  mbuf->nb_segs = 1;
}

bool packet_generator::packet_pong_ctor(pkt_t* pkt) {
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
  ipv4->time_to_live = TTL;
  SWAP(udp->src_port, udp->dst_port, decltype(udp->dst_port));
  SWAP(ipv4->src_addr, ipv4->dst_addr, decltype(ipv4->src_addr));
  packet_ipv4_udp_cksum(pkt);
  rte_ether_addr_copy(&eth->src_addr, &eth->dst_addr);
  rte_ether_addr_copy(&addr, &eth->src_addr);
  packet_ipv4_udp_cksum(pkt);
  return true;
}

void packet_generator::packet_ipv4_cksum(pkt_t *mbuf) {
  struct rte_ipv4_hdr *ipv4 = rte_pktmbuf_mtod_offset(
      mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
  if (!caps.ip_cksum_tx)
    ipv4->hdr_checksum = rte_ipv4_cksum(ipv4);
  else
    mbuf->ol_flags |= RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_IPV4;
}

void packet_generator::packet_ipv4_udp_cksum(pkt_t *mbuf) {
  struct rte_ipv4_hdr *ipv4 = rte_pktmbuf_mtod_offset(
      mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
  struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(ipv4 + 1);
  udp->dgram_cksum = 0;
  ipv4->hdr_checksum = 0;
  if (!caps.l4_cksum_tx) {
    udp->dgram_cksum = rte_ipv4_udptcp_cksum(ipv4, udp);
  } else {
    mbuf->ol_flags |=
        RTE_MBUF_F_TX_UDP_CKSUM | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_IPV4;
    udp->dgram_cksum = rte_ipv4_phdr_cksum(ipv4, mbuf->ol_flags);
  }
  packet_ipv4_cksum(mbuf);
}


bool packet_generator::packet_verify_cksum(pkt_t *mbuf) {
  struct rte_ipv4_hdr *ipv4 = rte_pktmbuf_mtod_offset(
      mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
  struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(ipv4 + 1);
  if(likely(caps.ip_cksum_rx)){
      if(mbuf->ol_flags & RTE_MBUF_F_RX_IP_CKSUM_BAD)
          return false;
  }else{
      if(rte_ipv4_cksum(ipv4))
          return false;
  }
  if(likely(caps.l4_cksum_rx))
      return (mbuf->ol_flags & RTE_MBUF_F_RX_L4_CKSUM_BAD) == 0;
  else
      return rte_ipv4_udptcp_cksum_verify(ipv4, udp) == 0;
}

bool packet_generator::packet_verify_rs(pkt_t *mbuf) {
  struct rte_ipv4_hdr *ipv4 = rte_pktmbuf_mtod_offset(
      mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
  return ipv4->dst_addr == config.sip && ipv4->src_addr == config.dip;
}

bool packet_generator::packet_verify_ipv4(pkt_t *mbuf) {
  struct rte_ether_hdr *eth = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
  return rte_be_to_cpu_16(eth->ether_type) == RTE_ETHER_TYPE_IPV4;
}

void packet_mempool_ctor(struct rte_mempool *mp, void *opaque, void *obj,
                         unsigned int obj_idx __rte_unused) {
  struct rte_mbuf *mbuf = (struct rte_mbuf *)obj;
  packet_generator *pg = static_cast<packet_generator*>(opaque);
  pg->packet_pp_ctor_udp(mbuf);


  mbuf->pool = mp;
  mbuf->next = NULL;
}
void packet_mempool_ctor_full(struct rte_mempool *mp, void *opaque, void *obj,
                         unsigned int obj_idx __rte_unused) {
  rte_mbuf *mbuf = (struct rte_mbuf *)obj;
  packet_generator* pg = static_cast<packet_generator*>(opaque);
  pg->packet_pp_ctor_udp(mbuf);

  pg->packet_ipv4_udp_cksum(mbuf);
  mbuf->pool = mp;
  mbuf->next = NULL;
}
