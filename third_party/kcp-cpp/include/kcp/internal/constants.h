// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#ifndef KCP_INTERNAL_CONSTANTS_H_
#define KCP_INTERNAL_CONSTANTS_H_

#include <cstddef>
#include <cstdint>

namespace kcp {

// Wire and protocol constants from the reference implementation. Every value here carries the
// kcp-go source location in PORTING-PLAN.md §4.7; changing one without changing the plan is a bug.

// sess.go:77 - upper bound for a UDP packet, also the buffer pool granularity.
constexpr std::size_t kMtuLimit = 1500;

// sess.go:68,71,74 - CFB framing: random nonce + CRC32 + ciphertext.
constexpr std::size_t kNonceSize = 16;
constexpr std::size_t kCrcSize = 4;
constexpr std::size_t kCryptHeaderSize = kNonceSize + kCrcSize;

// sess.go:80 - conv field width; oob_max_size() = mtu - kConvSize.
constexpr std::size_t kConvSize = 4;

// sess.go:83 - pending connections a Listener may hold before it stops accepting new peers.
constexpr std::size_t kAcceptBacklog = 128;

// sess.go:86 - post-processing queue depth. Full means drop, never block (#38).
constexpr std::size_t kDevBacklog = 2048;

// sess.go:91,698 - the value sess.go passes to fecEncoder.encode(); it decides whether a shard set
// is continuous enough to emit parity.
constexpr int kMaxFecEncodeLatencyMs = 500;

// sess.go:94 - token bucket burst base.
constexpr std::size_t kMaxBatchSize = 64;

// fec.go:51-52 - FEC header: seqid(4) + type(2), plus a 2-byte payload size.
constexpr std::size_t kFecHeaderSize = 6;
constexpr std::size_t kFecHeaderSizePlus2 = kFecHeaderSize + 2;

// fec.go:53-55 - FEC packet types, carried in the low 16 bits of the header.
constexpr std::uint16_t kTypeData = 0xf1;
constexpr std::uint16_t kTypeParity = 0xf2;
constexpr std::uint16_t kTypeOob = 0xf3;

// fec.go:58 - how many incomplete shard sets may exist before the oldest is discarded.
constexpr int kMaxShardSets = 3;

// crypt.go:50 - CFB feedback seed. Encrypting this with the session key produces the first
// feedback block; it is not itself transmitted.
constexpr std::uint8_t kInitialVector[16] = {167, 115, 79,  156, 18,  172, 27,  1,
                                             164, 21,  242, 193, 252, 120, 230, 107};

// crypt.go:51 - PBKDF2 salt for NewSimpleXORBlockCrypt (32 iterations, kMtuLimit bytes out).
constexpr char kSaltXor[] = "sH3CIVoF#rWLtJo6";

// kcp.go:58 - segment header size, conv included.
constexpr std::size_t kOverhead = 24;

// kcp.go:53 - default MTU, also the value the construction path passes to SetMtu.
constexpr int kMtuDef = 1400;

// kcp.go:32-64 - protocol constants. The four command bytes and the probe flags are on the wire,
// so these are frozen; the timers are only defaults and are reachable through NoDelay/WndSize.
constexpr int kRtoNdl = 30;            // kcp.go:34 - minimum RTO with nodelay
constexpr int kRtoMin = 100;           // kcp.go:35
constexpr int kRtoDef = 200;           // kcp.go:36
constexpr int kRtoMax = 60000;         // kcp.go:37
constexpr std::uint8_t kCmdPush = 81;  // kcp.go:39
constexpr std::uint8_t kCmdAck = 82;   // kcp.go:40
constexpr std::uint8_t kCmdWask = 83;  // kcp.go:41
constexpr std::uint8_t kCmdWins = 84;  // kcp.go:42
constexpr std::uint32_t kAskSend = 1;  // kcp.go:45
constexpr std::uint32_t kAskTell = 2;  // kcp.go:46
constexpr int kWndSnd = 32;            // kcp.go:49
constexpr int kWndRcv = 32;            // kcp.go:50
constexpr int kAckFast = 3;            // kcp.go:56 - unused in the reference implementation
constexpr int kInterval = 100;         // kcp.go:57 - default flush interval
constexpr int kDeadLink = 20;          // kcp.go:59 - max xmit before the link is declared dead
constexpr int kThreshInit = 2;         // kcp.go:60
constexpr int kThreshMin = 2;          // kcp.go:61
constexpr int kProbeInit = 500;        // kcp.go:62
constexpr int kProbeLimit = 120000;    // kcp.go:63
constexpr std::size_t kSnOffset = 12;  // kcp.go:64 - sn byte offset in the segment header

// kcp.go:110 - the "link is dead" marker written into state when xmit reaches dead_link.
constexpr std::uint32_t kDeadState = 0xFFFFFFFFu;

// ringbuffer.go:31-32 - initial capacity floor and the point where growth switches from doubling
// to a flat 10%, for the segment queues.
constexpr std::size_t kRingBufferMin = 8;
constexpr std::size_t kRingBufferExp = 1024;

// crypt.go:273-277 - PBKDF2 parameters for the simple XOR cipher.
constexpr int kSimpleXorIterations = 32;

}  // namespace kcp

#endif  // KCP_INTERNAL_CONSTANTS_H_
