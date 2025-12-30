#ifndef RUDP_H
#define RUDP_H
#include <algorithm>
#include <cassert>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <generic/rte_cycles.h>
#include <memory>
#include <rte_byteorder.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip4.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#include <rte_mbuf_core.h>
#include <rte_mempool.h>
#include <rte_ring.h>
#include <rte_ring_core.h>
#include <span>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

#include "packet.h"

static constexpr uint64_t min_seq = 1;

static int timestamp_offset = -1;

enum class MessageType : uint16_t {
  DATA_PKT = 0,
  ACK_PKT = 1,
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
  uint64_t ack;
#if RTE_VERSION >= RTE_VERSION_NUM(25, 0, 0, 0)
} __rte_packed_end;
#else
} __rte_packed;
#endif

#if RTE_VERSION >= RTE_VERSION_NUM(25, 0, 0, 0)
struct __rte_packed_begin rudp_nack_header : public rudp_header_base {
#else
struct rudp_nack_header : public rudp_header_base {
#endif
  uint64_t ack;
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

static __inline uint64_t get_ts(pkt_t *mbuf) {
  return *RTE_MBUF_DYNFIELD(mbuf, timestamp_offset, uint64_t *);
}

struct sender_entry {
  pkt_t *packet;
  uint64_t seq;
  bool retransmitted;
  sender_entry() : packet(nullptr), seq(0), retransmitted(false) {}
  sender_entry(pkt_t *packet, uint64_t seq, bool retransmitted)
      : packet(packet), seq(seq), retransmitted(retransmitted) {}

  bool requires_retry(uint64_t now, uint64_t rto) {
    return now > get_ts(packet) + rto;
  }
  bool is_free() { return packet == nullptr; }
  pkt_t *get() { return packet; }

  sender_entry(const sender_entry &) = delete;
  sender_entry(sender_entry &&other) {
    packet = other.packet;
    seq = other.seq;

    retransmitted = other.retransmitted;
    other.packet = nullptr;
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

struct free_buffer : pkt_buffer<free_buffer> {
  free_buffer(std::size_t size) : pkt_buffer(size) {}

  void cleanup_impl(std::size_t threshold) {
    rte_pktmbuf_free_bulk(buffer.data(), threshold);
    head -= threshold;
  }

  void push_back_impl(pkt_t *pkt) {
    if (head == buffer.size())
      cleanup(head);
    buffer[head++] = pkt;
  }
};

struct packet_scheduler {
  uint64_t rate, interval, next_burst, rtt;
  double rate_update;
  double t_low, t_high, rtt_d;
  const double beta, alpha;
  packet_scheduler(uint64_t initial_rate, double t_low, double t_high)
      : rate(initial_rate), interval(), next_burst(), rtt(t_high),
        rate_update(rte_get_timer_hz() / t_low), t_low(t_low), t_high(t_high),
        beta(0.8), alpha(0.9) {}

  bool prepare_schedule_burst(uint16_t pkts,
                              uint64_t now = rte_get_timer_cycles()) {
    if (now > next_burst) {
      next_burst = now + pkts * interval;
      return true;
    }
    return false;
  }

  void update_rate(uint64_t new_rtt) {
    static constexpr auto lez = [](double v1) { return v1 < 0.1; };
    double new_rtt_diff = new_rtt - rtt;
    rtt_d = alpha * rtt_d + (1 - alpha) * new_rtt_diff;
    rtt = new_rtt;
    auto grad = rtt_d / rtt;
    if (rtt < t_low) {
      rate += rate_update;
    } else if (rtt > t_high) {
      rate *= (1 - beta * (1 - t_high / rtt));
    } else if (lez(grad)) {
      rate += rate_update;
    } else {
      rate += (1 - beta * grad);
    }
    interval = rte_get_timer_hz() / rate;
  }
};

template <typename D> struct ack_observer {
  void process_ack(uint64_t ack_seq, uint64_t now) {
    static_cast<D *>(this)->process_ack_impl(ack_seq, now);
  }
};

struct cnwd {
  uint64_t least_in_window, retransmit_cnt, last_decrease;
  std::size_t len, len_at_last_decrease;
  double target_delay, cwnd_size;
  const double ai, beta, max_md;
  const uint64_t min_wd_size, reset_threshold;

  cnwd(std::size_t initial_len, uint64_t target_delay, double ai, double beta,
       double max_md, uint64_t min_wd_size, uint64_t reset_threshold = 256)
      : least_in_window(min_seq), retransmit_cnt(0), last_decrease(0),
        len(initial_len), len_at_last_decrease(initial_len),
        target_delay(target_delay), cwnd_size(initial_len), ai(ai), beta(beta),
        max_md(max_md), min_wd_size(min_wd_size),
        reset_threshold(reset_threshold) {}

  void on_ack(uint64_t ack, uint64_t now, uint64_t rtt) {
    retransmit_cnt = 0;
    bool can_decrease = now - last_decrease > rtt;
    if (rtt < target_delay) {
      cwnd_size += ai / cwnd_size * (ack - least_in_window);
      len_at_last_decrease = cwnd_size;
    } else if (can_decrease) {
      cwnd_size *= 1 - beta * (rtt - target_delay) / rtt;
      last_decrease = now;
    }
    least_in_window = ack;
    len = std::max<std::size_t>(static_cast<std::size_t>(cwnd_size), 1);
  }

  void on_retransmission(std::size_t nb, uint64_t rtt, uint64_t now) {
    if (nb == 0)
      return;
    bool can_decrease = now - last_decrease > rtt;
    retransmit_cnt += nb;
    if (retransmit_cnt > reset_threshold) {
      cwnd_size = min_wd_size;
    } else if (can_decrease) {
      cwnd_size *= (1 - max_md);
      last_decrease = now;
    }
    len = std::max<std::size_t>(static_cast<std::size_t>(cwnd_size), 1);
  }

  bool fits_in_window(uint64_t seq, [[maybe_unused]] uint64_t rto) {
    assert(seq >= least_in_window);
    return seq < len + least_in_window;
  }

  bool is_acked(uint64_t seq) { return seq < least_in_window; }

  void advance_bulk(uint64_t ack_seq) {
    assert(ack_seq >= least_in_window && ack_seq < least_in_window + len);
    least_in_window = ack_seq;
  }
  bool beyond_window(uint64_t seq) {
    return seq >= least_in_window + len_at_last_decrease;
  }
};

class window {
public:
  using reference = std::vector<bool>::reference;
  window(std::size_t size, uint64_t min_seq)
      : wd(size), lb(0), ub(size - 1), mask(size - 1), least_in_window(min_seq),
        last_resize(rte_get_timer_cycles()) {}

  uint64_t get_last_acked_packet() const { return least_in_window - 1; }

  bool try_reserve_and_set(uint64_t seq, uint64_t rto = 0) {
    if (try_reserve(seq, rto)) {
      auto i = index(seq);
      bool prv = wd[i];
      wd[i] = true;
      return !prv;
    }
    return false;
  }

  bool is_set(uint64_t seq) {
    return seq < least_in_window ||
           (seq <= least_in_window + mask && wd[index(seq)]);
  }

  bool beyond_window(uint64_t seq) { return seq > least_in_window + mask; }

  void advance(std::invocable<uint64_t> auto &&...f) {
    assert(mask + 1 == wd.size());
    assert(lb == ((least_in_window - 1) & mask));
    auto i = index(least_in_window);
    while (wd[i]) {
      lb = (lb + 1) & mask;
      ub = (ub + 1) & mask;
      wd[ub] = false;
      ++least_in_window;
    }
    (f(least_in_window), ...);
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

  bool try_reserve(uint64_t seq, [[maybe_unused]] uint64_t rto) {
    assert(seq >= least_in_window);
    seq -= least_in_window;
    if (seq > mask)
#ifdef RESIZE
      maybe_resize(rto);
#else
      return false;
#endif
    return seq <= mask;
  }

  void maybe_resize(uint64_t rto) {
    uint64_t now = rte_get_timer_cycles();
    if (last_resize + 4 * rto > now)
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
  retransmission_handler(std::size_t window_size, std::size_t burst_size)
      :
        seq(min_seq), rtt(), rtt_dv(), rto(rte_get_timer_hz()) {}

  uint64_t cleanup_acked_pkts(uint64_t seq, uint64_t now) {
    uint64_t burst_rtt = 0;
    while (!unacked_packets.empty() && unacked_packets.front().seq < seq) {
      auto &desc = unacked_packets.front();
      if (!desc.retransmitted) {
        auto tsc_d = now - get_ts(desc.packet);
        if (rtt == 0)
          rtt = tsc_d;
        else
          std::tie(rtt, rtt_dv) = estimate_timeout(rtt, rtt_dv, tsc_d);
        if (burst_rtt == 0)
          burst_rtt = tsc_d;
        else
          burst_rtt = (burst_rtt * 7 + tsc_d) / 8;
        rto = 8 * (rtt + 4 * rtt_dv); // always include one backoff
        stats.rtt = rtt;
      }
      assert(desc.packet);
      rte_pktmbuf_free(desc.packet);
      unacked_packets.pop_front();
    }
    return burst_rtt;
  }

  std::size_t insert_burst(std::span<pkt_t *> pkts, tx_pkt_buffer &tx_buffer,
                           std::invocable<pkt_t *, uint64_t> auto &&ctor) {
    probe_retransmit(tx_buffer, tx_buffer.capacity());
    auto space = std::min(tx_buffer.capacity(), pkts.size());
    auto nb = 0;
    for (auto *pkt : pkts.subspan(0, space)) {
      ++nb;
      ctor(pkt, seq);
      tx_buffer.push_back(pkt);
      pkt_inc_refcnt(pkt);
      unacked_packets.emplace_back(pkt, seq++, false);
    }
    return nb;
  }

  void probe_retransmit(tx_pkt_buffer &tx_buffer, std::size_t n) {
    auto i = 0u;
    auto now = rte_get_timer_cycles();
    for (; i < n && !unacked_packets.empty(); ++i) {
      auto &desc = unacked_packets.front();
      if (desc.seq < stats.acked || !desc.requires_retry(now, rto))
        break;
      ++stats.retransmitted;
      desc.retransmitted = true;
      tx_buffer.push_back(desc.packet);
      pkt_inc_refcnt(desc.packet);
      unacked_packets.push_back(std::move(desc));
      unacked_packets.pop_front();
    }
    //ackstore.on_retransmission(i, rtt, rte_get_timer_cycles());
  }

  void acknowledge(uint64_t seq) {
    //if (ackstore.beyond_window(seq) || ackstore.is_acked(seq))
    //  return;
    if(seq < stats.acked)
        return;
    stats.acked = seq;
    auto now = rte_get_timer_cycles();
    cleanup_acked_pkts(seq, now);
    //ackstore.on_ack(seq, now, brtt);
  }

  const statistics &get_stats() const { return stats; }

private:
  statistics stats;
  std::deque<sender_entry> unacked_packets;
  //cnwd ackstore;
  uint64_t seq;
  uint64_t rtt;
  uint64_t rtt_dv;
  uint64_t rto;
};

struct statistics {
  uint64_t retransmitted, acked, sent, ecn;
  double rtt;
  statistics(uint64_t retransmitted, uint64_t acked, uint64_t sent, uint64_t ecn,
             uint64_t rtt_est)
      : retransmitted(retransmitted), acked(acked), sent(sent), ecn(ecn) {
    rtt = static_cast<double>(rtt_est) / (rte_get_timer_hz() / 1e6);
  }
};

struct tx_context : public port_context {
  retransmission_handler retry_buffer;
  tx_pkt_buffer tx_buffer;

  tx_context(uint16_t port_id, uint16_t qid, std::size_t retry_size,
             std::size_t tx_size)
      : port_context(port_id, qid), retry_buffer(retry_size, tx_size),
        tx_buffer(tx_size) {}

  void process_ack(uint64_t ack) { retry_buffer.acknowledge(ack); }
};

template <typename D> struct seq_observer {
  void process_seq(uint64_t seq) {
    static_cast<D &>(*this).process_seq_impl(seq);
  }
};

struct ack_scheduler : public seq_observer<ack_scheduler> {
  uint64_t last_acked;
  std::size_t threshold;
  bool pending_from_retry;
  void process_seq_impl(uint64_t seq) { pending_from_retry = seq < last_acked; }

  bool ack_pending(uint64_t seq) {
    return pending_from_retry || seq > last_acked;
  }

  void ack_callback(uint64_t seq) {
    last_acked = seq;
    pending_from_retry = false;
  }

  ack_scheduler(std::size_t window_size)
      : last_acked(0), threshold(window_size >> 2), pending_from_retry(false) {}
};

struct rx_context : public port_context {
  packet_generator &pg;
  window recv_wd;
  rx_context(uint16_t port_id, uint16_t qid, int64_t entries,
             packet_generator &pg)
      : port_context(port_id, qid), pg(pg), recv_wd(entries, min_seq) {}

  bool process_seq(uint64_t seq) {
    if (recv_wd.is_set(seq))
      return false;
    if (recv_wd.try_reserve_and_set(seq)) {
      recv_wd.advance();
      return true;
    } else {
      return false;
    }
  }
};

template <typename... O>
  requires(std::is_base_of_v<seq_observer<O>, O> && ...)
struct ack_context {
  std::shared_ptr<rte_mempool> ack_pool;
  std::tuple<O *...> observers;

  void process_seq(uint64_t seq) {
    std::apply([seq](auto &&...elems) { (elems->process_seq(seq), ...); },
               observers);
  }
  ack_context(std::shared_ptr<rte_mempool> pool, O *&&...observers)
      : ack_pool(std::move(pool)), observers((observers)...) {}
};

struct peer {
  tx_context tx_ctx;
  rx_context rx_ctx;
  std::unique_ptr<ack_scheduler> scheduler;
  ack_context<ack_scheduler> ack_ctx;
  struct {
    uint64_t sent = 0;
    uint64_t with_ecn = 0;
  } stats;

  peer(uint16_t port_id, uint16_t txq, uint16_t rxq, uint64_t entries,
       std::size_t tx_buffer_size, std::shared_ptr<rte_mempool> pool,
       packet_generator &pg)
      : tx_ctx(port_id, txq, entries, tx_buffer_size),
        rx_ctx(port_id, rxq, entries, pg),
        scheduler(std::make_unique<ack_scheduler>(tx_buffer_size)),
        ack_ctx(pool, scheduler.get()) {}

  uint16_t submit_tx_burst(std::span<pkt_t *> pkts) {
    auto ctor = [&](pkt_t *pkt, uint64_t seq) {
      auto *hdr = rte_pktmbuf_mtod_offset(pkt, rudp_header *, HDR_SIZE);
      hdr->op = MessageType::DATA_PKT;
      hdr->seq = seq;
      auto least_in_window = rx_ctx.recv_wd.get_last_acked_packet();
      if (scheduler->ack_pending(least_in_window)) [[unlikely]] {
        hdr->ack = least_in_window;
        scheduler->ack_callback(hdr->ack);
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
    std::ranges::for_each(
        tx_ctx.tx_buffer.begin(), tx_ctx.tx_buffer.begin() + nb_tx,
        [now = rte_get_timer_cycles()](auto &mbuf) {
          assert(timestamp_offset >= 0);
          auto *ts = RTE_MBUF_DYNFIELD(mbuf, timestamp_offset, uint64_t *);
          *ts = now;
        });
    tx_ctx.tx_buffer.cleanup(nb_tx);
    return inserted;
  }

  statistics get_stats() const {
    auto &rt_stats = tx_ctx.retry_buffer.get_stats();
    return {rt_stats.retransmitted, rt_stats.acked, stats.sent, stats.with_ecn, rt_stats.rtt};
  }

  void retry_last_n(std::size_t n) {
    tx_ctx.retry_buffer.probe_retransmit(
        tx_ctx.tx_buffer, std::min(n, tx_ctx.tx_buffer.capacity()));
    auto tx_nb = submit_tx_burst_posted(tx_ctx.tx_buffer);
    std::ranges::for_each(
        tx_ctx.tx_buffer.begin(), tx_ctx.tx_buffer.begin() + tx_nb,
        [now = rte_get_timer_cycles()](auto &mbuf) {
          assert(timestamp_offset >= 0);
          auto *ts = RTE_MBUF_DYNFIELD(mbuf, timestamp_offset, uint64_t *);
          *ts = now;
        });
    tx_ctx.tx_buffer.cleanup(tx_nb);
  }

  bool make_progress() {
    auto &ack_pool = ack_ctx.ack_pool;
    assert(ack_pool.get());
    auto capacity = tx_ctx.tx_buffer.capacity();
    auto acked = rx_ctx.recv_wd.get_last_acked_packet();

    if (capacity < 1 || !scheduler->ack_pending(acked))
      return false;

    auto *pkt = rte_pktmbuf_alloc(ack_pool.get());
    auto *hdr = rte_pktmbuf_mtod_offset(pkt, rudp_ack_header *, HDR_SIZE);
    hdr->op = MessageType::ACK_PKT;
    hdr->ack = acked;
    rx_ctx.pg.packet_pp_ctor_udp(pkt, sizeof(rudp_header));
    rx_ctx.pg.packet_ipv4_udp_cksum(pkt);
    tx_ctx.tx_buffer.push_back(pkt);

    auto tx_nb = submit_tx_burst_posted(tx_ctx.tx_buffer);
    tx_ctx.tx_buffer.cleanup(tx_nb);
    scheduler->ack_callback(acked);
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
      auto iphdr = rte_pktmbuf_mtod_offset(pkts[i], rte_ipv4_hdr*, sizeof(rte_ether_hdr));
      static constexpr uint8_t ecn_mask = 3;
      stats.with_ecn += ((iphdr->type_of_service >> 6) & ecn_mask) == ecn_mask ? 1 : 0;
      switch (hdr->op) {
      case MessageType::DATA_PKT: {
        auto *nhdr = static_cast<rudp_header *>(hdr);
        if (nhdr->ack)
          tx_ctx.process_ack(nhdr->ack);
        pkts[j] = pkts[i];
        ack_ctx.process_seq(nhdr->seq);
        if (rx_ctx.process_seq(nhdr->seq))
          ++j;
        else
          rte_pktmbuf_free(pkts[i]);
        break;
      }
      case MessageType::ACK_PKT: {
        auto *ahdr = static_cast<rudp_ack_header *>(hdr);
        tx_ctx.process_ack(ahdr->ack);
        rte_pktmbuf_free(pkts[i]);
        break;
      }
      }
    }
    return j;
  }
};

#endif
