#ifndef RUDP_H
#define RUDP_H
#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <generic/rte_cycles.h>
#include <iterator>
#include <limits>
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

static __inline uint64_t estimate_latency(uint64_t latency, uint64_t measured) {
  static constexpr uint64_t w1 = 1, w2 = 7, shift = 3;
  return (w1 * measured + w2 * latency) >> shift;
}

enum class MessageType : uint16_t {
    NORMAL_PKT = 0, ACK_BURST = 1,
};

#if RTE_VERSION >= RTE_VERSION_NUM(25, 0, 0, 0)
struct __rte_packed_begin rudp_header_base {
#else
struct rudp_header_base {
#endif
    MessageType op;
#if RTE_VERSION >= RTE_VERSION_NUM(25, 0, 0, 0)
} __rte_packed_end;
#else
} __rte_packed;
#endif

#if RTE_VERSION >= RTE_VERSION_NUM(25, 0, 0, 0)
struct __rte_packed_begin rudp_header : public rudp_header_base{
#else
struct rudp_header : public rudp_header_base{
#endif
  uint64_t ack;
  uint64_t seq;
#if RTE_VERSION >= RTE_VERSION_NUM(25, 0, 0, 0)
} __rte_packed_end;
#else
} __rte_packed;
#endif

#if RTE_VERSION >= RTE_VERSION_NUM(25, 0, 0, 0)
struct __rte_packed_begin rudp_ack_header : public rudp_header_base{
#else
struct rudp_ack_header : public rrudp_header_base{
#endif
  uint64_t num;
  uint64_t acks[];
#if RTE_VERSION >= RTE_VERSION_NUM(25, 0, 0, 0)
} __rte_packed_end;
#else
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
  uint64_t ts;
  uint64_t deadline;
  bool passed_to_nic;
  sender_entry()
      : packet(nullptr), seq(0), ts(0),
        deadline(std::numeric_limits<uint64_t>::max()), passed_to_nic(false) {}
  sender_entry(pkt_t *pkt, uint64_t seq) = delete;

  bool requires_retry() {
    return passed_to_nic && rte_get_timer_cycles() > deadline;
  }
  bool is_free() { return packet == nullptr; }
  pkt_t *get() { return packet; }

  pkt_t *clear_if_valid(uint64_t ack, uint64_t &sts) {
    if (ack == seq) {
      auto *pkt = packet;
      sts = ts;
      seq = 0;
      packet = nullptr;
      deadline = std::numeric_limits<uint64_t>::max();
      passed_to_nic = false;
      return pkt;
    }
    return nullptr;
  }

  void update_ts(uint64_t latency) {
    ts = rte_get_timer_cycles();
    deadline = ts + latency;
  }

  void insert(uint64_t latency, auto &&...args) {
    std::tie(packet, seq) = {args...};
    update_ts(latency);
  }

  void set_passed_to_nic() { passed_to_nic = true; }
};

struct receiver_entry {
  uint64_t seq;
  receiver_entry() : seq(0) {}
};

template <typename D> struct pkt_buffer {
  std::vector<pkt_t *> buffer;
  std::size_t head;

  pkt_buffer(std::size_t size) : buffer(size), head(0) {}

  std::span<pkt_t *> free_span() {
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
    if(sent == 0)
        return;
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
    head -= size;
  }
  rx_free_buffer(std::size_t size) : pkt_buffer(size) {}
};

template <typename T> struct retry_buffer_base {
  std::vector<T> slots;
  std::size_t ptr;

  retry_buffer_base(std::size_t entries)
      : slots(std::bit_ceil(entries), T()), ptr(1) {}

  T &operator[](std::size_t idx) { return slots[idx & (slots.size() - 1)]; }

  T &at(std::size_t idx) { return operator[](idx); }
};

struct tx_retry_buffer : public retry_buffer_base<sender_entry> {
  uint64_t latency;
  tx_retry_buffer(std::size_t entries)
      : retry_buffer_base(entries), latency(rte_get_timer_hz() / 1e6 * 500) {}

  std::size_t insert_burst(std::span<pkt_t *> pkts, tx_pkt_buffer &tx_buffer,
                           std::invocable<pkt_t *, uint64_t> auto &&ctor) {
    auto cptr = ptr;
    auto pkt_it = pkts.begin();
    for (; pkt_it != pkts.end() && tx_buffer.capacity() > 0 && ptr < cptr + slots.size(); ++ptr) {
      auto &slot = at(ptr);
      pkt_t *pkt;
      if (slot.is_free()) {
        pkt = *(pkt_it++);
        ctor(pkt, ptr);
        pkt_inc_refcnt(pkt);
        slot.insert(latency, pkt, ptr);
      } else if (slot.requires_retry()) {
        pkt = slot.get();
        slot.update_ts(latency);
      } else {
        continue;
      }
      tx_buffer.push_back(pkt);
    }
    return std::distance(pkts.begin(), pkt_it);
  }

  std::size_t prepare_retry(tx_pkt_buffer &tx_buffer, std::size_t n) {
    auto dec = slots.size() - 1;
    std::size_t found = 0;
    n = std::min(n, slots.size());
    for (uint64_t i = 0; i < n * dec && tx_buffer.capacity() > 0; i += dec) {
      auto &slot = at(ptr + i);
      if (slot.requires_retry()) {
        tx_buffer.push_back(slot.get());
        slot.update_ts(latency);
        ++found;
      }
    }
    return found;
  }

  pkt_t *acknowledge(uint64_t ack) {
    uint64_t ts;
    auto &slot = at(ack);
    auto *pkt = slot.clear_if_valid(ack, ts);
    if (pkt)
      latency = estimate_latency(latency, rte_get_timer_cycles() - ts);
    return pkt;
  }

  void set_passed_to_nic(std::span<pkt_t *> pkts) {
    std::ranges::for_each(pkts, [&](pkt_t *pkt) {
      auto *hdr = rte_pktmbuf_mtod_offset(pkt, rudp_header *, HDR_SIZE);
      at(hdr->seq).set_passed_to_nic();
    });
  }
};

struct rx_retry_buffer : public retry_buffer_base<receiver_entry> {
  rx_retry_buffer(std::size_t size) : retry_buffer_base(size) {}
};

struct statistics {
  uint64_t acks;
  uint64_t piggybacked;
  statistics() : acks(0), piggybacked(0) {}
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
    return rte_ring_dequeue(ring, std::bit_cast<void **>(ack)) == 0;
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
  packet_generator &pg;
  rx_context(uint16_t port_id, uint16_t qid, int64_t entries,
             std::size_t threshold, packet_generator &pg)
      : port_context(port_id, qid), free_buf(threshold), retry_buffer(entries),
        pg(pg) {}
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

  peer(uint16_t port_id, uint16_t txq, uint16_t rxq, uint64_t entries,
       std::size_t tx_buffer_size, std::shared_ptr<rte_mempool> pool,
       packet_generator &pg)
      : tx_ctx(port_id, txq, entries, tx_buffer_size),
        rx_ctx(port_id, rxq, entries, MEMPOOL_CACHE_SIZE, pg),
        ack_ctx(pool, entries), stats() {}

  const statistics &get_stats() const { return stats; }

  uint16_t submit_tx_burst(std::span<pkt_t *> pkts) {
    uint64_t ack = 0;
    auto ctor = [&](pkt_t *pkt, uint64_t seq) {
      auto *hdr = rte_pktmbuf_mtod_offset(pkt, rudp_header *, HDR_SIZE);
      hdr->op = MessageType::NORMAL_PKT;
      hdr->seq = seq;
      if (ack_ctx.acks.dequeue(&ack)) {
        hdr->ack = ack;
        stats.piggybacked++;
      } else {
        hdr->ack = 0;
      }
    };
    auto inserted =
        tx_ctx.retry_buffer.insert_burst(pkts, tx_ctx.tx_buffer, ctor);
    auto nb_tx =
        rte_eth_tx_burst(tx_ctx.port_id, tx_ctx.qid, tx_ctx.tx_buffer.data(),
                         tx_ctx.tx_buffer.head);
    auto begin = tx_ctx.tx_buffer.begin();
    tx_ctx.retry_buffer.set_passed_to_nic(std::span(begin, begin + nb_tx));
    tx_ctx.tx_buffer.cleanup(nb_tx);
    return inserted;
  }

  void retry_last_n(std::size_t n) {
    tx_ctx.retry_buffer.prepare_retry(tx_ctx.tx_buffer, n);
    auto tx_nb = submit_tx_burst_posted(tx_ctx.tx_buffer);
    tx_ctx.tx_buffer.cleanup(tx_nb);
  }

  bool make_progress() {
    auto &ack_pool = ack_ctx.ack_pool;
    auto free_ack_buf = tx_ctx.tx_buffer.free_span();
    auto free_for_acks = free_ack_buf.size();
    free_for_acks = std::min(free_for_acks, ack_ctx.acks.size());
    uint64_t ack;
    if (rte_pktmbuf_alloc_bulk(ack_pool.get(), free_ack_buf.data(),
                               free_for_acks)) {
      rte_eth_tx_done_cleanup(tx_ctx.port_id, tx_ctx.qid, free_ack_buf.size());
      if (rte_pktmbuf_alloc_bulk(ack_pool.get(), free_ack_buf.data(),
                                 free_for_acks))
        return false;
    }

    for (auto *pkt : free_ack_buf.subspan(0, free_for_acks)) {
      rx_ctx.pg.packet_pp_ctor_udp(pkt);
      rx_ctx.pg.packet_ipv4_udp_cksum(pkt);
      auto *hdr = rte_pktmbuf_mtod_offset(pkt, rudp_header *, HDR_SIZE);
      hdr->seq = 0;
      ack_ctx.acks.dequeue(&ack);
      hdr->ack = ack;
    }

    tx_ctx.tx_buffer.mark_as_used(free_for_acks);
    auto tx_nb = submit_tx_burst_posted(tx_ctx.tx_buffer);
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
      auto *pkt = retry_buffer.acknowledge(ack);
      if (pkt) {
        free_buf.push_back(pkt);
        stats.acks++;
      }
    };

    auto enqueue_ack = [&](rudp_header *hdr) -> bool {
      if (hdr->seq > 0) {
        auto &slot = rx_ctx.retry_buffer[hdr->seq];
        bool inserted = false;
        if (slot.seq <= hdr->seq) {
          ack_ctx.acks.enqueue(hdr->seq);
          inserted = slot.seq < hdr->seq;
          slot.seq = hdr->seq;
        }
        return inserted;
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
      if (enqueue_ack(hdr))
        ++j;
      else
          rte_pktmbuf_free(pkts[i]);
    }
    return j;
  }
};

#endif
