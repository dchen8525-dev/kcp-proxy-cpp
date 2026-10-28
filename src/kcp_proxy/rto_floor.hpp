#pragma once

#include <atomic>
#include <cstdint>

#include "kcp_proxy/clean_path.hpp"
#include "kcp_proxy/config.hpp"

namespace kcp_proxy {

// "May this tunnel use the aggressive 30ms retransmission timeout floor?"
//
// KCP's nodelay mode sets rx_minrto to 30ms (kcp.cc: kRtoNdl) instead of the
// 100ms default. That floor is what makes a lost segment recover fast, and it
// is also what makes a CLEAN fast path retransmit datagrams that were never
// lost: a 1024-segment window is ~1.4 MB, which at 150 Mbit/s takes 75ms to
// drain through the socket, so every segment near the end of a burst passes its
// 30ms deadline while it is still queued. Measured on loopback: 1355
// retransmissions over 15001 segments (9%), of which the peer received 1172 as
// DUPLICATES -- pure self-inflicted waste -- and `snmp_repeat` proves it.
// Raising the floor to 100ms removed all of them (retrans=0 repeat=0 over two
// runs), at the cost of ~40% slower recovery at 2% loss and worse at 8%.
//
// So the floor is adaptive: keep the low-latency 30ms while the path is losing
// packets (where the floor earns its keep), and relax to 100ms only after a
// sustained clean window (where the floor only fires on our own queue). The
// relaxation is a *reaction to evidence*, never a default, so a lossy link
// behaves exactly as it does today.
class RtoFloorGate {
public:
    // true = nodelay mode (30ms floor, today's behaviour), false = 100ms floor.
    bool low_latency() const {
        return low_latency_.load(std::memory_order_relaxed);
    }
    void set_low_latency(bool on) {
        low_latency_.store(on, std::memory_order_relaxed);
    }

private:
    std::atomic<bool> low_latency_{true};
};

// Decides the floor: the CleanPathTracker state machine (clean_path.hpp) driving
// the gate every tunnel reads. Starts in the low-latency state, i.e. exactly the
// pre-adaptive behaviour, and only relaxes after the path has looked clean for
// `relax_sec` seconds of real traffic.
class RtoFloorController {
public:
    enum class Transition {
        kNone,
        kToRelaxed,    // floor raised to 100ms: stop timing out our own queue
        kToLowLatency, // loss seen: back to the 30ms floor
    };

    RtoFloorController(RtoFloorGate& gate, int relax_sec = KCP_RTO_RELAX_SEC,
                       int hold_sec = KCP_RTO_HOLD_SEC, double min_seg_rate = ADAPTIVE_MIN_SEG_RATE)
        : gate_(gate), tracker_(CleanPathTuning{relax_sec, hold_sec, min_seg_rate}) {}

    Transition on_sample(uint64_t out_segs_total, uint64_t fast_retrans_total, int64_t now_us) {
        switch (tracker_.on_sample(out_segs_total, fast_retrans_total, now_us)) {
            case CleanPathTracker::Transition::kToClean:
                gate_.set_low_latency(false);
                return Transition::kToRelaxed;
            case CleanPathTracker::Transition::kToLossy:
                gate_.set_low_latency(true);
                return Transition::kToLowLatency;
            case CleanPathTracker::Transition::kNone:
                break;
        }
        return Transition::kNone;
    }

    Transition sample(int64_t now_us) {
        switch (tracker_.sample(now_us)) {
            case CleanPathTracker::Transition::kToClean:
                gate_.set_low_latency(false);
                return Transition::kToRelaxed;
            case CleanPathTracker::Transition::kToLossy:
                gate_.set_low_latency(true);
                return Transition::kToLowLatency;
            case CleanPathTracker::Transition::kNone:
                break;
        }
        return Transition::kNone;
    }

    bool relaxed() const {
        return tracker_.clean();
    }
    int relax_sec() const {
        return tracker_.clean_sec();
    }
    int hold_sec() const {
        return tracker_.hold_sec();
    }

private:
    RtoFloorGate& gate_;
    CleanPathTracker tracker_;
};

} // namespace kcp_proxy
