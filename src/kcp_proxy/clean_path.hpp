#pragma once

#include <cstdint>

#include "kcp_proxy/config.hpp"
#include "kcp/snmp.h"

namespace kcp_proxy {

// One state machine, two policies.
//
// Both adaptive policies in this repo answer the same question -- "has this
// process's sending direction looked clean for long enough to stop paying for
// a protection that is not needed?" -- and both learn the answer from the same
// measurement. Adaptive FEC parity (fec_parity.hpp) stops emitting parity
// shards while the path is clean; the adaptive RTO floor (rto_floor.hpp) relaxes
// the retransmission timeout floor while the path is clean. Duplicating the
// hysteresis here would mean two copies drifting apart, so the state machine
// lives once and each policy is a thin adapter that reacts to a transition.
//
// The measurement, and why it is `fast_retrans` and nothing else:
//   * `snmp_lost` / `snmp_retrans` are dominated by timeout-driven
//     retransmissions of segments that are merely queued behind a large window.
//     On a clean 150 Mbit/s loopback that counter read 3-25% while 18296 sent
//     datagrams produced 18295 received and only ONE was actually missing.
//     Keying on it would misfire on every fast path.
//   * `snmp_fast_retrans` is the peer reporting an ACK gap, i.e. a datagram
//     that really was lost on the way towards the sender. Measured 0 on every
//     clean path (at every window size) and 3-5% under 8% loss.
//   * FEC repair hides a loss from the PROTECTED state, which is why leaving
//     the protected state needs NO evidence: the downgrade is itself the probe,
//     and detection only has to work from the cheap state, where nothing is
//     hidden.
struct CleanPathTuning {
    // Seconds of traffic-bearing clean samples before the cheap state is
    // entered.
    int clean_sec = 0;
    // Seconds to stay protected after evidence of loss, and the minimum gap
    // between two probes.
    int hold_sec = 0;
    // A sample only counts as traffic above this many KCP segments per second
    // (~0.55 Mbit/s at 1400B). Without it an idle tunnel would accumulate
    // cleanliness for free, and a transfer starting after a quiet minute would
    // begin unprotected.
    double min_seg_rate = 0.0;
};

// NOT thread-safe by design: exactly one timer drives it per process (the
// client's traffic reporter, the server's update tick), so its plain members
// need no lock. The gates it updates are atomic because N tunnel strands read
// them concurrently.
class CleanPathTracker {
public:
    enum class Transition {
        kNone,
        kToClean, // entered the cheap state: the caller may stop paying
        kToLossy, // evidence of loss: the caller must protect again
    };

    explicit CleanPathTracker(CleanPathTuning tuning) : tuning_(tuning) {}

    // One sample. `out_segs_total` / `fast_retrans_total` are the CUMULATIVE
    // process-wide counters (kcp::DefaultSnmp), not deltas: the tracker diffs
    // them itself, so a dropped sample cannot corrupt the state. The first call
    // only establishes the baseline and never transitions.
    Transition on_sample(uint64_t out_segs_total, uint64_t fast_retrans_total, int64_t now_us) {
        const bool first = !initialized_;
        const uint64_t d_out = out_segs_total - last_out_segs_;
        const uint64_t d_fast = fast_retrans_total - last_fast_retrans_;
        const int64_t dt_us = now_us - last_sample_us_;
        last_out_segs_ = out_segs_total;
        last_fast_retrans_ = fast_retrans_total;
        last_sample_us_ = now_us;
        initialized_ = true;
        if (first || dt_us <= 0) return Transition::kNone;

        if (d_fast > 0) {
            // The peer reported an ACK gap: a datagram of OURS was lost. This
            // is the only loss signal that is both direction-correct and immune
            // to the queueing noise described above.
            clean_us_ = 0;
            hold_until_us_ = now_us + static_cast<int64_t>(tuning_.hold_sec) * 1000000;
            if (clean_) {
                clean_ = false;
                return Transition::kToLossy;
            }
            return Transition::kNone;
        }

        if (now_us < hold_until_us_) {
            // Serving out a hold: do not accumulate cleanliness, so a single
            // probe window cannot start a new countdown early.
            clean_us_ = 0;
            return Transition::kNone;
        }

        const double seg_rate = static_cast<double>(d_out) * 1e6 / static_cast<double>(dt_us);
        if (seg_rate < tuning_.min_seg_rate) {
            // Too little traffic to judge (or an idle tunnel). Neither counts
            // as clean nor resets the count: silence says nothing either way.
            return Transition::kNone;
        }

        clean_us_ += dt_us;
        if (!clean_ && clean_us_ >= static_cast<int64_t>(tuning_.clean_sec) * 1000000) {
            clean_us_ = 0;
            clean_ = true;
            return Transition::kToClean;
        }
        return Transition::kNone;
    }

    // Convenience wrapper for the production sampling sites: reads the
    // process-wide counters for the caller.
    Transition sample(int64_t now_us) {
        const kcp::SnmpSnapshot snmp = kcp::DefaultSnmp().Snapshot();
        return on_sample(snmp.out_segs, snmp.fast_retrans_segs, now_us);
    }

    bool clean() const {
        return clean_;
    }
    // Micros of accumulated clean traffic (exposed for tests and log lines).
    int64_t clean_us() const {
        return clean_us_;
    }
    // The tuning in force, so callers can explain a transition without
    // duplicating the defaults.
    int clean_sec() const {
        return tuning_.clean_sec;
    }
    int hold_sec() const {
        return tuning_.hold_sec;
    }

private:
    const CleanPathTuning tuning_;

    bool initialized_ = false;
    bool clean_ = false;
    uint64_t last_out_segs_ = 0;
    uint64_t last_fast_retrans_ = 0;
    int64_t last_sample_us_ = 0;
    int64_t clean_us_ = 0;
    int64_t hold_until_us_ = 0;
};

} // namespace kcp_proxy
