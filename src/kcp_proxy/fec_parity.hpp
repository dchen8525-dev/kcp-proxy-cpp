#pragma once

#include <atomic>
#include <cstdint>

#include "kcp_proxy/clean_path.hpp"
#include "kcp_proxy/config.hpp"

namespace kcp_proxy {

// The one piece of state the send path reads: "may this tunnel emit parity?".
// A shared, immutable-from-the-reader's-side flag rather than a hook per
// tunnel: every session of a process shares one decision, so a plain atomic
// read inside on_kcp_datagram (strand-bound, once per emitted datagram) costs
// nothing and needs no lock. Default true = current behaviour for every caller
// that does not opt into adaptive parity.
class FecParityGate {
public:
    bool enabled() const {
        return enabled_.load(std::memory_order_relaxed);
    }
    void set(bool enabled) {
        enabled_.store(enabled, std::memory_order_relaxed);
    }

private:
    std::atomic<bool> enabled_{true};
};

// Tunables. The defaults come from config.hpp so the documented numbers live
// in exactly one place; the CLI may override the first two.
struct FecParityTuning {
    // Seconds of traffic-bearing clean samples before parity is dropped.
    int probe_sec = FEC_PARITY_PROBE_SEC;
    // Seconds to stay protected after evidence of loss (and the minimum gap
    // between two probes).
    int hold_sec = FEC_PARITY_HOLD_SEC;
    // Minimum KCP segments per second for a sample to count as traffic.
    double min_seg_rate = ADAPTIVE_MIN_SEG_RATE;
};

// Decides whether parity may be dropped: the CleanPathTracker state machine
// (clean_path.hpp) driving the gate every tunnel reads.
class FecParityController {
public:
    enum class Transition {
        kNone,
        kToEconomy,   // parity just stopped being emitted
        kToProtected, // parity just resumed after loss evidence
    };

    explicit FecParityController(FecParityGate& gate, FecParityTuning tuning = {})
        : gate_(gate),
          tracker_(CleanPathTuning{tuning.probe_sec, tuning.hold_sec, tuning.min_seg_rate}) {}

    // One sample over the CUMULATIVE process-wide counters (see
    // CleanPathTracker::on_sample).
    Transition on_sample(uint64_t out_segs_total, uint64_t fast_retrans_total, int64_t now_us) {
        switch (tracker_.on_sample(out_segs_total, fast_retrans_total, now_us)) {
            case CleanPathTracker::Transition::kToClean:
                gate_.set(false);
                return Transition::kToEconomy;
            case CleanPathTracker::Transition::kToLossy:
                gate_.set(true);
                return Transition::kToProtected;
            case CleanPathTracker::Transition::kNone:
                break;
        }
        return Transition::kNone;
    }

    Transition sample(int64_t now_us) {
        switch (tracker_.sample(now_us)) {
            case CleanPathTracker::Transition::kToClean:
                gate_.set(false);
                return Transition::kToEconomy;
            case CleanPathTracker::Transition::kToLossy:
                gate_.set(true);
                return Transition::kToProtected;
            case CleanPathTracker::Transition::kNone:
                break;
        }
        return Transition::kNone;
    }

    bool economy() const {
        return tracker_.clean();
    }
    int64_t clean_us() const {
        return tracker_.clean_us();
    }
    int probe_sec() const {
        return tracker_.clean_sec();
    }
    int hold_sec() const {
        return tracker_.hold_sec();
    }

    // "off"/"on" for logs; the wire effect, not the internal enum name.
    static const char* transition_name(Transition t) {
        switch (t) {
            case Transition::kToEconomy:
                return "off";
            case Transition::kToProtected:
                return "on";
            case Transition::kNone:
                break;
        }
        return "none";
    }

private:
    FecParityGate& gate_;
    CleanPathTracker tracker_;
};

} // namespace kcp_proxy
