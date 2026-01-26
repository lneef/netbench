#pragma once

#include "packet.h"
#include <algorithm>
#include <cstdint>
#include <generic/rte_cycles.h>
#include <rte_ether.h>

/*
 * inspired by
 * https://github.com/erpc-io/eRPC/blob/de83dab3eab4a0fb19bfc4881c11d4a6b89ff17d/src/cc/timely.h
 */
struct timely {
  uint64_t rtt, min_rtt;
  double rate, rate_update;
  double t_low, t_high, rtt_d;
  const double beta, alpha, nic_speed_per_byte;
  uint64_t neg_gradients = 0;
  uint64_t freq;
  timely(double nic_bw, double t_low, double t_high)
      : rtt(t_high), rate(nic_bw), rate_update(RTE_ETHER_MAX_LEN),
        t_low(t_low), t_high(t_high), beta(0.8), alpha(0.9),
        nic_speed_per_byte(1 / nic_bw), freq(rte_get_timer_hz()) {}

  double update_rate(uint64_t new_rtt) {
    static constexpr auto lez = [](double v1) { return v1 <= 0.0; };
    double new_rtt_diff = new_rtt - rtt;
    double new_rate;
    rtt_d = alpha * rtt_d + (1 - alpha) * new_rtt_diff;
    auto grad = rtt_d / min_rtt;
    neg_gradients = grad < 0. ? neg_gradients + 1 : 0;
    if (rtt < t_low) {
      new_rate = rate + rate_update;
    } else if (rtt > t_high) {
      new_rate = rate * (1 - beta * (1 - t_high / rtt));
    } else if (lez(grad)) {
      new_rate = rate + rate_update;
    } else {
      new_rate = rate * (1 - beta * grad);
    }

    rate = std::max(new_rate, rate * 0.5);
    rtt = new_rate;
    return rate / freq;
  }
};

template <typename R> struct packet_scheduler {
  R rate_controller;
  double budget = 0;
  uint64_t last_burst;
  double rate;

  packet_scheduler(double link_bw, R &&rate_controller)
      : rate_controller(std::move(rate_controller)),
        last_burst(rte_get_timer_cycles()), rate(link_bw) {}

  void adjust_rate(uint64_t new_rtt) { rate_controller.update_rate(new_rtt); }

  void prepare_schedule_burst(uint64_t now) {
    budget += rate * (now - last_burst);
  }

  bool schedule_packet(pkt_t *pkt) {
    if (pkt->pkt_len > budget)
      return false;
    budget -= pkt->pkt_len;
    return true;
  }

  void finish_schedule_burst(uint64_t now) { last_burst = now; }
};
