#ifndef RUDP_H
#define RUDP_H
#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <generic/rte_cycles.h>
#include <memory>
#include <ranges>
#include <rte_byteorder.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#include <rte_mbuf_core.h>
#include <rte_mempool.h>
#include <rte_ring.h>
#include <rte_ring_core.h>
#include <span>
#include <vector>

#include "packet.h"
#include "port.h"

static bool check_packet(pkt_t *pkt) {
  auto *eth = rte_pktmbuf_mtod(pkt, rte_ether_hdr *);
  return eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
}

static void pkt_inc_refcnt(pkt_t *pkt) { rte_mbuf_refcnt_update(pkt, 1); }

#if RTE_VERSION >= RTE_VERSION_NUM(25, 0, 0, 0)
struct __rte_packed_begin rudp_header {
  uint64_t ack;
  uint64_t seq;
} __rte_packed_end;
#else
struct rurudp_header {
  uint64_t ack;
  uint64_t seq;
} __rte_packed;
#endif

struct port_context {
  uint16_t port_id;
  uint16_t qid;

  port_context(uint16_t port_id, uint16_t qid) : port_id(port_id), qid(qid) {}
};

struct sender_entry {
  pkt_t *packet;
  uint64_t seq;

  sender_entry() : packet(nullptr), seq(0) {}
  sender_entry(pkt_t *pkt, uint64_t seq) : packet(pkt), seq(seq) {}

  bool requires_retry() { return packet != nullptr; }
  pkt_t *get() { return packet; }

  pkt_t *clear_if_valid(uint64_t ack) {
    if (ack == seq) {
      auto *pkt = packet;
      packet = nullptr;
      seq = 0;
      return pkt;
    }
    return nullptr;
  }
};

struct receiver_entry {
  uint64_t seq;
  receiver_entry() : seq(0) {}
};

template <typename D> struct pkt_buffer {
  std::vector<pkt_t *> buffer;
  std::size_t head;

  pkt_buffer(std::size_t size) : buffer(size), head(0) {}

  std::span<pkt_t *> span() {
    return std::span(buffer.begin() + head, buffer.end());
  }
  void push_back(pkt_t *pkt) { static_cast<D &>(*this).push_back_impl(pkt); }
  std::size_t capacity() { return buffer.size() - head; }
  pkt_t **data() { return buffer.data(); }
  void mark_as_used(std::size_t num) { head += num; }
  auto begin() { return buffer.begin(); }
  auto end() { return buffer.begin() + head; }

  void cleanup(std::size_t threshold) {
    static_cast<D &>(*this).cleanup_impl(threshold);
  }
};

struct tx_pkt_buffer : pkt_buffer<tx_pkt_buffer> {

  void cleanup_impl(std::size_t sent) {
    auto nhead = 0;
    auto begin = buffer.begin();
    for (auto *pkt : std::span(begin + sent, begin + head))
      buffer[nhead++] = pkt;
    head = nhead;
  }

  void push_back_impl(pkt_t *pkt) { buffer[head++] = pkt; }

  tx_pkt_buffer(std::size_t size) : pkt_buffer(size) {}
};

struct rx_free_buffer : pkt_buffer<rx_free_buffer> {

  void push_back_impl(pkt_t *pkt) {
    if (head == buffer.size())
      cleanup_impl(head);
    buffer[head++] = pkt;
  }

  void cleanup_impl(std::size_t size) {
    rte_pktmbuf_free_bulk(buffer.data() + head - size, size);
    head = size;
  }
  rx_free_buffer(std::size_t size) : pkt_buffer(size) {}
};

template <typename T> struct retry_buffer_base {
  std::vector<T> slots;
  std::size_t ptr;

  retry_buffer_base(std::size_t entries) : slots(std::bit_ceil(entries), T()), ptr(1) {}

  T &operator[](std::size_t idx) { return slots[idx & (slots.size() - 1)]; }

  T &at(std::size_t idx) { return operator[](idx); }
};

struct tx_retry_buffer : public retry_buffer_base<sender_entry> {

  tx_retry_buffer(std::size_t entries) : retry_buffer_base(entries) {}
  std::size_t prepare_next_n(std::size_t n, tx_pkt_buffer& tx_buffer) {
    auto free_to_use = 0u;
    n = n & (slots.size() - 1);
    for (auto i = 0u; i < n; ++i) {
      auto idx = ptr + i;
      auto& slot = at(idx);
      if (slot.requires_retry()) {
        auto *pkt = slot.get();
        tx_buffer.push_back(pkt);
        pkt_inc_refcnt(pkt);
      } else {
        ++free_to_use;
      }
    }
    return free_to_use;
  }

  uint64_t insert(pkt_t *pkt) {
    for (;; ++ptr)
      if (!at(ptr).requires_retry()){
        at(ptr) = {pkt, ptr};
        break;
      }
    pkt_inc_refcnt(pkt);
    return ptr;
  }
};

struct rx_retry_buffer : public retry_buffer_base<receiver_entry> {
  rx_retry_buffer(std::size_t size) : retry_buffer_base(size) {}
};

struct statistics {
  uint64_t acks;
  uint64_t piggybacked;
};

struct ack_buffer {
  rte_ring *ring;
  std::string name;
  ack_buffer(std::size_t size)
      : ring(rte_ring_create("ACK", size, rte_socket_id_by_idx(rte_lcore_id()),
                             RING_F_SP_ENQ | RING_F_SC_DEQ)) {}
  ~ack_buffer() { rte_ring_free(ring); }

  bool enqueue(uint64_t ack) {
    return rte_ring_enqueue(ring, std::bit_cast<void *>(ack)) == 0;
  }

  bool dequeue(uint64_t *ack) {
    return rte_ring_dequeue(ring, reinterpret_cast<void **>(&ack)) == 0;
  }

  bool empty() { return rte_ring_empty(ring) == 1; }

  std::size_t size() const { return rte_ring_count(ring); }

  std::size_t free() const { return rte_ring_free_count(ring); }
};

struct tx_context : public port_context {
  tx_retry_buffer retry_buffer;
  tx_pkt_buffer tx_buffer;

  tx_context(uint16_t port_id, uint16_t qid, std::size_t retry_size,
             std::size_t tx_size)
      : port_context(port_id, qid), retry_buffer(retry_size),
        tx_buffer(tx_size) {}
};

struct rx_context : public port_context {
  rx_free_buffer free_buf;
  rx_retry_buffer retry_buffer;
  packet_generator& pg;
  rx_context(uint16_t port_id, uint16_t qid, int64_t entries,
             std::size_t threshold, packet_generator& pg)
      : port_context(port_id, qid), free_buf(threshold), retry_buffer(entries), pg(pg) {
  }
};

struct ack_context {
  std::shared_ptr<rte_mempool> ack_pool;
  ack_buffer acks;
  uint64_t last_ack;
  ack_context(std::shared_ptr<rte_mempool> pool, uint64_t size)
      : ack_pool(std::move(pool)), acks(size),
        last_ack(rte_get_timer_cycles()) {}
};

struct peer {
  tx_context tx_ctx;
  rx_context rx_ctx;
  ack_context ack_ctx;
  statistics stats;

  peer(uint16_t port_id, uint16_t txq, uint16_t rxq, uint64_t entries, std::size_t tx_buffer_size,
       std::shared_ptr<rte_mempool> pool, packet_generator& pg)
      : tx_ctx(port_id, txq, entries, tx_buffer_size),
        rx_ctx(port_id, rxq, entries, MEMPOOL_CACHE_SIZE, pg),
        ack_ctx(pool, entries), stats() {}

  const statistics& get_stats() const { return stats; }

  uint16_t submit_tx_burst(std::span<pkt_t *> pkts) {
    uint64_t ack = 0;
    auto space = std::min(pkts.size(), tx_ctx.tx_buffer.capacity());
    auto free_to_use =
        tx_ctx.retry_buffer.prepare_next_n(space, tx_ctx.tx_buffer);
    auto occupied = tx_ctx.tx_buffer.head;
    for (auto *pkt : pkts.subspan(0, free_to_use)) {
      tx_ctx.tx_buffer.push_back(pkt);
      auto *hdr = rte_pktmbuf_mtod_offset(pkt, rudp_header *, HDR_SIZE);
      if (ack_ctx.acks.dequeue(&ack)){
        hdr->ack = ack;
        stats.piggybacked++;
      }else{
        hdr->ack = 0;
      }
      hdr->seq = tx_ctx.retry_buffer.insert(pkt);
    }
    auto nb_tx =
        rte_eth_tx_burst(tx_ctx.port_id, tx_ctx.qid, tx_ctx.tx_buffer.data(),
                         tx_ctx.tx_buffer.head);
    tx_ctx.tx_buffer.cleanup(nb_tx);
    if (nb_tx > occupied)
      nb_tx -= occupied;
    else
      nb_tx = 0;
    return nb_tx;
  }

  bool make_progress() {
    auto &ack_pool = ack_ctx.ack_pool;
    auto free_ack_buf = tx_ctx.tx_buffer.span();
    uint64_t ack;
    if (rte_pktmbuf_alloc_bulk(ack_pool.get(), free_ack_buf.data(),
                               free_ack_buf.size())) {
      rte_eth_tx_done_cleanup(tx_ctx.port_id, tx_ctx.qid, free_ack_buf.size());
      if (rte_pktmbuf_alloc_bulk(ack_pool.get(), free_ack_buf.data(),
                                 free_ack_buf.size()))
        return false;
    }

    for (auto *pkt : free_ack_buf) {
      rx_ctx.pg.packet_pp_ctor_udp(pkt);
      rx_ctx.pg.packet_ipv4_udp_cksum(pkt);
      auto *hdr = rte_pktmbuf_mtod_offset(pkt, rudp_header *, HDR_SIZE);
      hdr->seq = 0;
      ack_ctx.acks.dequeue(&ack);
      hdr->ack = ack;
    }

    auto tx_nb = submit_tx_burst_posted(free_ack_buf);
    tx_ctx.tx_buffer.cleanup(tx_nb);
    return true;
  }

  uint16_t submit_tx_burst_posted(std::span<rte_mbuf *> pkts) {
    return rte_eth_tx_burst(tx_ctx.port_id, tx_ctx.qid, pkts.data(),
                            pkts.size());
  }

  uint16_t submit_rx_burst(std::span<pkt_t *> pkts) {
    auto process_ack = [&](rudp_header *hdr) {
      auto &retry_buffer = tx_ctx.retry_buffer;
      auto &free_buf = rx_ctx.free_buf;
      auto ack = hdr->ack;
      auto &slot = retry_buffer[ack];
      auto *pkt = slot.clear_if_valid(ack);
      if (pkt){
        free_buf.push_back(pkt);
        stats.acks++;
      }
    };

    auto enqueue_ack = [&](rudp_header *hdr, auto &slot) -> bool {
      if (hdr->seq > 0) {
        if (hdr->seq <= slot.seq) {
          ack_ctx.acks.enqueue(hdr->seq);
          slot.seq = hdr->seq;
        }
        return slot.seq < hdr->seq;
      }
      return false;
    };
    uint16_t rcvd =
        rte_eth_rx_burst(rx_ctx.port_id, rx_ctx.qid, pkts.data(), pkts.size());
    uint16_t i, j;
    for (i = 0, j = 0; i < rcvd; ++i) {
      if (!check_packet(pkts[i])) {
        rx_ctx.free_buf.push_back(pkts[i]);
        continue;
      }
      auto *hdr = rte_pktmbuf_mtod_offset(pkts[i], rudp_header *, HDR_SIZE);
      if (hdr->ack > 0)
        process_ack(hdr);
      pkts[j] = pkts[i];
      auto &slot = rx_ctx.retry_buffer[hdr->seq];
      if (enqueue_ack(hdr, slot))
        ++j;
    }
    return j;
  }
};

#endif
