// bbr.hpp
// Simple header-only BBR-like congestion controller (lightweight, approximate)
// Purpose: provide a pluggable congestion-control policy for the client pacer.
#pragma once

#include <cstdint>
#include <unordered_map>
#include <algorithm>

// Windows headers sometimes define macros named `min` and `max` which
// conflict with `std::min`/`std::max` usage. Undefine them to avoid
// compilation errors when this header is included after Windows headers.
#ifdef max
#undef max
#endif
#ifdef min
#undef min
#endif

// Very small, self-contained BBR-like controller suitable for experiments.
// Not a full BBR implementation — provides the basic elements: track
// minimum RTT, estimate bottleneck bandwidth (packets/sec), and expose a
// target pacing rate. The goal is to find a high-throughput rate while
// reacting to RTT increases.
class bbr_congestion_controller {
public:
    bbr_congestion_controller() = default;

    void set_initial_rate(double pps) {
        if (pps <= 0.0) {
            unlimited_ = true;
        } else {
            unlimited_ = false;
            pacing_rate_pps_ = pps;
            max_bw_pps_ = pps;
            ewma_bw_pps_ = pps;
            pacing_gain_ = 1.0;
            state_ = state_t::STARTUP;
        }
    }

    // Called when a packet is sent. We record send timestamps by sequence.
    void on_send(uint64_t now_ns, uint64_t seq) {
        if (unlimited_) return;
        send_times_[seq] = now_ns;
    }

    // Called when an ack/echo is received. rtt_ns is the measured RTT for that packet.
    void on_ack(uint64_t now_ns, uint64_t seq, uint64_t rtt_ns) {
        if (unlimited_) return;

        // Update min RTT (simple minimum over window)
        if (rtt_ns > 0) {
            if (min_rtt_ns_ == 0 || rtt_ns < min_rtt_ns_) min_rtt_ns_ = rtt_ns;
        }

        // Estimate sample bandwidth (packets/sec) using send timestamp if available.
        auto it = send_times_.find(seq);
        if (it != send_times_.end()) {
            uint64_t send_ns = it->second;
            if (now_ns > send_ns) {
                uint64_t interval_ns = now_ns - send_ns;
                double sample_pps = 1e9 / static_cast<double>(interval_ns);
                // Update EWMA bandwidth estimate (smooth samples)
                if (ewma_bw_pps_ <= 0.0) ewma_bw_pps_ = sample_pps;
                const double bw_alpha = 0.85; // favor historical, not too noisy
                ewma_bw_pps_ = bw_alpha * ewma_bw_pps_ + (1.0 - bw_alpha) * sample_pps;

                // Keep a separate max estimate for occasional probes
                if (ewma_bw_pps_ > max_bw_pps_) max_bw_pps_ = ewma_bw_pps_;
            }
        }

        // Remove tracking to bound memory
        if (it != send_times_.end()) send_times_.erase(it);

        // State machine: STARTUP tries to ramp quickly, PROBE_BW probes conservatively
        if (state_ == state_t::STARTUP) {
            // If RTT inflates, exit startup into probe
            if (min_rtt_ns_ > 0 && rtt_ns > min_rtt_ns_ * rtt_inflation_threshold_) {
                state_ = state_t::PROBE_BW;
                pacing_gain_ = 1.0; // be conservative after inflation
            } else {
                // Ramp pacing gain multiplicatively (fast ramp). Limit to a cap.
                pacing_gain_ = std::min(max_startup_gain_, pacing_gain_ * startup_gain_mul_);
            }
        } else {
            // PROBE_BW: gentle increases when bandwidth appears to grow, back off on RTT spikes
            if (min_rtt_ns_ > 0 && rtt_ns > min_rtt_ns_ * rtt_inflation_threshold_) {
                // RTT inflated -> back off quickly
                pacing_gain_ = std::max(0.6, pacing_gain_ * 0.7);
            } else {
                // Gentle additive increase toward probe gain
                pacing_gain_ = std::min(max_probe_gain_, pacing_gain_ + probe_gain_add_);
            }
        }

        // Update pacing rate exposed to pacer using EWMA bandwidth estimate
        pacing_rate_pps_ = ewma_bw_pps_ * pacing_gain_;
        // Clamp to reasonable bounds
        if (pacing_rate_pps_ < 1.0) pacing_rate_pps_ = 1.0;
    }

    // Periodic poll (called from pacer.poll). Can be used for decay/timers.
    void on_poll(uint64_t now_ns) {
        if (unlimited_) return;
        // slowly decay max_bw_pps_ to forget very old samples
        const double decay = 0.9995;
        max_bw_pps_ = std::max(1.0, max_bw_pps_ * decay);
        // refresh pacing_rate
        pacing_rate_pps_ = max_bw_pps_ * pacing_gain_;
    }

    double target_rate_pps() const {
        if (unlimited_) return 0.0;
        return pacing_rate_pps_;
    }

private:
    enum class state_t { STARTUP, PROBE_BW };

    bool unlimited_{false};
    uint64_t min_rtt_ns_{0};
    double max_bw_pps_{1000.0};
    double ewma_bw_pps_{0.0};
    double pacing_gain_{1.0};
    double pacing_rate_pps_{1000.0};
    std::unordered_map<uint64_t, uint64_t> send_times_;
    state_t state_{state_t::PROBE_BW};

    // Tuning parameters
    const double rtt_inflation_threshold_{1.6};
    const double startup_gain_mul_{1.5};
    const double max_startup_gain_{8.0};
    const double probe_gain_add_{0.05};
    const double max_probe_gain_{3.0};
};
