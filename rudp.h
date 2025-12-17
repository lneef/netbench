#ifndef RUDP_H
#define RUDP_H
#include <algorithm>
#include <cassert>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <limits>
#include <memory>
#include <rte_byteorder.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#include <rte_mbuf_core.h>
#include <rte_mempool.h>
#include <rte_ring.h>
#include <rte_ring_core.h>
#include <span>
#include <tuple>
#include <utility>
#include <vector>

#include "packet.h"

static constexpr uint64_t min_seq = 1;

enum class MessageType : uint16_t {
  NORMAL_PKT = 0,
  ACK_BURST = 1,
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
struct __rte_packed_begin rudp_header : public rudp_header_base {
#else
struct rudp_header : public rudp_header_base {
#endif
  uint64_t ack;
  uint64_t seq;
#if RTE_VERSION >= RTE_VERSION_NUM(25, 0, 0, 0)
} __rte_packed_end;
#else
} __rte_packed;
#endif

#if RTE_VERSION >= RTE_VERSION_NUM(25, 0, 0, 0)
struct __rte_packed_begin rudp_ack_header : public rudp_header_base {
#else
struct rudp_ack_header : public rudp_header_base {
#endif
  uint64_t num;
  uint64_t acks[];
  std::size_t construct_bulk_ack(std::size_t nb, std::deque<uint64_t> &queue);
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

static bool check_packet(pkt_t *pkt) {
  auto *eth = rte_pktmbuf_mtod(pkt, rte_ether_hdr *);
  return eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
}

static void pkt_inc_refcnt(pkt_t *pkt) { rte_mbuf_refcnt_update(pkt, 1); }

static __inline std::pair<uint64_t, uint64_t>
estimate_timeout(uint64_t rtt, uint64_t rtt_dv, uint64_t measured) {
  static constexpr uint64_t w1 = 1, w2 = 7, shift = 3;
  auto nrtt = (w1 * measured + w2 * rtt) >> shift;
  auto diff = measured > rtt ? measured - rtt : rtt - measured;
  auto nrtt_dv = (w1 * diff + w2 * rtt_dv) >> shift;
  return {nrtt, nrtt_dv};
}

inline std::size_t
rudp_ack_header::construct_bulk_ack(std::size_t nb,
                                    std::deque<uint64_t> &queue) {
  op = MessageType::ACK_BURST;
  num = std::min(queue.size(), nb);
  for (auto i = 0u; i < num; ++i) {
    acks[i] = queue.back();
    queue.pop_back();
  }
  return nb;
}

struct sender_entry {
  pkt_t *packet;
  uint64_t seq;
  uint64_t ts;
  uint64_t deadline;
  bool retransmitted;
  sender_entry()
      : packet(nullptr), seq(0), ts(0),
        deadline(std::numeric_limits<uint64_t>::max()), retransmitted(false) {}
  sender_entry(pkt_t *packet, uint64_t seq, uint64_t ts, uint64_t deadline,
               bool retransmitted)
      : packet(packet), seq(seq), ts(ts), deadline(deadline),
        retransmitted(retransmitted) {}

  bool requires_retry() { return rte_get_timer_cycles() > deadline; }
  bool is_free() { return packet == nullptr; }
  pkt_t *get() { return packet; }

  sender_entry(const sender_entry &) = delete;
  sender_entry(sender_entry &&other) {
    packet = other.packet;
    seq = other.seq;
    ts = other.ts;
    deadline = other.deadline;
    retransmitted = other.retransmitted;
    other.packet = nullptr;
  }

  void update_ts(uint64_t latency) {
    ts = rte_get_timer_cycles();
    deadline = ts + latency;
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
    if (sent == 0)
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

class window {
public:
  using reference = std::vector<bool>::reference;
  window(std::size_t size, uint64_t min_seq)
      : wd(size), lb(0), ub(size - 1), mask(size - 1), least_in_window(min_seq),
        last_resize(rte_get_timer_cycles()) {}

  reference operator[](std::size_t idx) { return wd[index(idx)]; }

  bool add_and_set(uint64_t seq, uint64_t rto) {
    if (add(seq, rto)) {
      auto i = index(seq);
      bool retval = wd[i];
      wd[i] = true;
      return retval;
    }
    return false;
  }

  bool add(uint64_t seq, [[maybe_unused]] uint64_t rto) {
    assert(seq >= least_in_window);
    seq -= least_in_window;
    if (seq > mask)
#ifdef RESIZE
      resize(rto);
#else
      return false;
#endif
    return seq <= mask;
  }

  bool acked(uint64_t seq) {
    return seq < least_in_window ||
           (seq <= least_in_window + mask && wd[index(seq)]);
  }

  bool beyond_window(uint64_t seq) { return seq > least_in_window + mask; }

  void advance(std::invocable<uint64_t> auto &&...f) {
    assert(mask + 1 == wd.size());
    assert(lb == ((least_in_window - 1) & mask));
    while (wd[lb]) {
      lb = (lb + 1) & mask;
      ub = (ub + 1) & mask;
      wd[ub] = false;
      (f(least_in_window), ...);
      ++least_in_window;
    }
    assert(((lb + mask) & mask) == ub);
  }

  bool inside(uint64_t seq) {
    return seq >= least_in_window && seq <= least_in_window + mask;
  }

private:
  std::size_t __inline index(std::size_t i) {
    assert(i >= least_in_window);
    return (i - least_in_window + lb) & mask;
  }

  void resize(uint64_t rto) {
    uint64_t now = rte_get_timer_cycles();
    if (last_resize + 2 * rto > now)
      return;
    auto osize = wd.size();
    auto nsize = osize * 2;
    std::vector<bool> nwd(nsize);
    auto begin = wd.begin();
    auto nbegin = nwd.begin();
    std::copy(begin + lb, wd.end(), nbegin + lb);
    if (ub < lb)
      std::copy(begin, begin + ub + 1, nbegin + osize);
    mask = nsize - 1;
    wd = std::move(nwd);
    last_resize = rte_get_timer_cycles();
  }

  std::vector<bool> wd;
  std::size_t lb, ub;
  std::size_t mask;
  uint64_t least_in_window;
  uint64_t last_resize;
};

class retransmission_handler {
public:
  struct statistics {
    uint64_t acked, retransmitted, rtt;
    statistics() : acked(0), retransmitted(0) {}
  };
  retransmission_handler(std::size_t window_size)
      : ackstore(window_size, min_seq), seq(min_seq), rtt(rte_get_timer_hz()),
        rtt_dv(rte_get_timer_hz()), timeout(rtt + 4 * rtt_dv) {}

  void cleanup_acked_pkts(uint64_t seq) {
    auto now = rte_get_timer_cycles();
    while (!unacked_packets.empty() && unacked_packets.front().seq <= seq) {
      auto &desc = unacked_packets.front();
      if (!desc.retransmitted) {
        std::tie(rtt, rtt_dv) = estimate_timeout(rtt, rtt_dv, now - desc.ts);
        timeout = 2 * (rtt + 4 * rtt_dv); // always include one backoff
        stats.rtt = rtt;
      }
      assert(desc.packet);
      rte_pktmbuf_free(desc.packet);
      unacked_packets.pop_front();
    }
  }

  std::size_t insert_burst(std::span<pkt_t *> pkts, tx_pkt_buffer &tx_buffer,
                           std::invocable<pkt_t *, uint64_t> auto &&ctor) {
    probe_retransmit(tx_buffer, tx_buffer.capacity());
    auto space = std::min(tx_buffer.capacity(), pkts.size());
    auto nb = 0;
    for (auto *pkt : pkts.subspan(0, space)) {
      if (!ackstore.add(seq, timeout))
        break;
      ++nb;
      ctor(pkt, seq);
      tx_buffer.push_back(pkt);
      pkt_inc_refcnt(pkt);
      auto ts = rte_get_timer_cycles();
      unacked_packets.emplace_back(pkt, seq++, ts, ts + timeout, false);
    }
    return nb;
  }

  void probe_retransmit(tx_pkt_buffer &tx_buffer, std::size_t n) {
    auto i = 0u;
    for (; i < n && !unacked_packets.empty(); ++i) {
      auto &desc = unacked_packets.front();
      if (ackstore.acked(desc.seq) || !desc.requires_retry())
        break;
      ++stats.retransmitted;
      desc.update_ts(timeout);
      desc.retransmitted = true;
      tx_buffer.push_back(desc.packet);
      pkt_inc_refcnt(desc.packet);
      unacked_packets.push_back(std::move(desc));
      unacked_packets.pop_front();
    }
  }

  void acknowledge(uint64_t seq) {
    if (!ackstore.inside(seq) || ackstore[seq])
      return;
    ++stats.acked;
    ackstore[seq] = true;
    ackstore.advance([&](uint64_t seq) { cleanup_acked_pkts(seq); });
  }

  const statistics &get_stats() const { return stats; }

  bool is_acked(uint64_t seq) { return ackstore.acked(seq); }

private:
  statistics stats;
  std::deque<sender_entry> unacked_packets;
  window ackstore;
  uint64_t seq;
  uint64_t rtt;
  uint64_t rtt_dv;
  uint64_t timeout;
};

struct statistics {
  uint64_t retransmitted, acked, sent;
  double rtt;
  statistics(uint64_t retransmitted, uint64_t acked, uint64_t sent,
             uint64_t rtt_est)
      : retransmitted(retransmitted), acked(acked), sent(sent) {
    rtt = static_cast<double>(rtt_est) / (rte_get_timer_hz() / 1e6);
  }
};

struct tx_context : public port_context {
  retransmission_handler retry_buffer;
  tx_pkt_buffer tx_buffer;

  tx_context(uint16_t port_id, uint16_t qid, std::size_t retry_size,
             std::size_t tx_size)
      : port_context(port_id, qid), retry_buffer(retry_size),
        tx_buffer(tx_size) {}

  void process_ack(uint64_t ack) { retry_buffer.acknowledge(ack); }
};

struct rx_context : public port_context {
  packet_generator &pg;
  window recv_wd;
  rx_context(uint16_t port_id, uint16_t qid, int64_t entries,
             packet_generator &pg)
      : port_context(port_id, qid), pg(pg), recv_wd(entries, min_seq) {}

  bool process_seq(uint64_t seq) {
    if (recv_wd.acked(seq))
      return false;
    if (!recv_wd.add_and_set(seq, 0)) {
      recv_wd.advance();
      return true;
    } else {
      return false;
    }
  }
};

struct ack_context {
  std::shared_ptr<rte_mempool> ack_pool;
  std::deque<uint64_t> acks;
  ack_context(std::shared_ptr<rte_mempool> pool) : ack_pool(std::move(pool)) {}
};

struct peer {
  tx_context tx_ctx;
  rx_context rx_ctx;
  ack_context ack_ctx;
  struct {
    uint64_t sent = 0;
  } stats;

  peer(uint16_t port_id, uint16_t txq, uint16_t rxq, uint64_t entries,
       std::size_t tx_buffer_size, std::shared_ptr<rte_mempool> pool,
       packet_generator &pg)
      : tx_ctx(port_id, txq, entries, tx_buffer_size),
        rx_ctx(port_id, rxq, entries, pg), ack_ctx(pool) {}

  uint16_t submit_tx_burst(std::span<pkt_t *> pkts) {
    auto ctor = [&](pkt_t *pkt, uint64_t seq) {
      auto *hdr = rte_pktmbuf_mtod_offset(pkt, rudp_header *, HDR_SIZE);
      hdr->op = MessageType::NORMAL_PKT;
      hdr->seq = seq;
      if (!ack_ctx.acks.empty()) {
        hdr->ack = ack_ctx.acks.back();
        ack_ctx.acks.pop_back();
      } else {
        hdr->ack = 0;
      }
    };
    auto inserted =
        tx_ctx.retry_buffer.insert_burst(pkts, tx_ctx.tx_buffer, ctor);
    auto nb_tx =
        rte_eth_tx_burst(tx_ctx.port_id, tx_ctx.qid, tx_ctx.tx_buffer.data(),
                         tx_ctx.tx_buffer.head);
    stats.sent += inserted;
    tx_ctx.tx_buffer.cleanup(nb_tx);
    return inserted;
  }

  statistics get_stats() const {
    auto &rt_stats = tx_ctx.retry_buffer.get_stats();
    return {rt_stats.acked, rt_stats.retransmitted, stats.sent, rt_stats.rtt};
  }

  void retry_last_n(std::size_t n) {
    tx_ctx.retry_buffer.probe_retransmit(
        tx_ctx.tx_buffer, std::min(n, tx_ctx.tx_buffer.capacity()));
    auto tx_nb = submit_tx_burst_posted(tx_ctx.tx_buffer);
    tx_ctx.tx_buffer.cleanup(tx_nb);
  }

  bool make_progress() {
    static constexpr std::size_t hdr_space = HDR_SIZE + sizeof(rudp_ack_header);
    auto &ack_pool = ack_ctx.ack_pool;
    assert(ack_pool.get());
    auto free_ack_buf = tx_ctx.tx_buffer.free_span();
    auto free_for_acks = free_ack_buf.size();
    free_for_acks = std::min(free_for_acks, ack_ctx.acks.size());
    auto total_acks = ack_ctx.acks.size();
    if (total_acks == 0)
      return false;
    uint64_t processed = 0;
    uint16_t buffers_used = 0;
    for (auto &pkt : free_ack_buf.subspan(0, free_for_acks)) {
      pkt = rte_pktmbuf_alloc(ack_pool.get());
      auto *hdr = rte_pktmbuf_mtod_offset(pkt, rudp_ack_header *, HDR_SIZE);
      auto space = (pkt->buf_len - hdr_space) / sizeof(uint64_t);
      auto num = hdr->construct_bulk_ack(space, ack_ctx.acks);
      rx_ctx.pg.packet_pp_ctor_udp(pkt, num * sizeof(uint64_t) +
                                            sizeof(rudp_ack_header));
      rx_ctx.pg.packet_ipv4_udp_cksum(pkt);
      processed += num;
      ++buffers_used;
      if (processed == total_acks)
        break;
    }

    tx_ctx.tx_buffer.mark_as_used(buffers_used);
    auto tx_nb = submit_tx_burst_posted(tx_ctx.tx_buffer);
    tx_ctx.tx_buffer.cleanup(tx_nb);
    return true;
  }

  uint16_t submit_tx_burst_posted(std::span<rte_mbuf *> pkts) {
    return rte_eth_tx_burst(tx_ctx.port_id, tx_ctx.qid, pkts.data(),
                            pkts.size());
  }

  uint16_t submit_rx_burst(std::span<pkt_t *> pkts) {
    uint16_t rcvd =
        rte_eth_rx_burst(rx_ctx.port_id, rx_ctx.qid, pkts.data(), pkts.size());
    uint16_t i, j;
    for (i = 0, j = 0; i < rcvd; ++i) {
      if (!check_packet(pkts[i])) {
        rte_pktmbuf_free(pkts[i]);
        continue;
      }
      auto *hdr =
          rte_pktmbuf_mtod_offset(pkts[i], rudp_header_base *, HDR_SIZE);
      switch (hdr->op) {
      case MessageType::NORMAL_PKT: {
        auto *nhdr = static_cast<rudp_header *>(hdr);
        if (nhdr->ack)
          tx_ctx.process_ack(nhdr->ack);
        pkts[j] = pkts[i];
        ack_ctx.acks.push_front(nhdr->seq);
        if (rx_ctx.process_seq(nhdr->seq))
          ++j;
        else
          rte_pktmbuf_free(pkts[i]);
        break;
      }
      case MessageType::ACK_BURST: {
        auto *ahdr = static_cast<rudp_ack_header *>(hdr);
        for (auto i = 0u; i < ahdr->num; ++i)
          tx_ctx.process_ack(ahdr->acks[i]);
        break;
      }
      }
    }
    return j;
  }
};

#endif
