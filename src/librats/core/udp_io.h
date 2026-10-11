#pragma once

/**
 * @file udp_io.h
 * @brief Moving datagrams in bulk: batched syscalls and segmentation offload.
 *
 * A reliability layer built on datagrams moves one packet per call, so a bulk
 * transfer at a 1200-byte payload costs tens of thousands of trips through the
 * kernel per megabyte. Measured, that — not the framing, the congestion control
 * or the encryption — is where a user-space stream's CPU goes over TCP's: the
 * user time of the two is the same, the system time of the datagram side four to
 * six times higher. Two things take it back, and this file is both of them.
 *
 *   - Batching: one syscall for many datagrams (sendmmsg/recvmmsg). It saves the
 *     syscall, but every datagram still walks the whole UDP/IP stack.
 *   - Segmentation offload: hand the kernel one buffer of equal-size datagrams
 *     and let it cut them up after the stack — or on the NIC — instead of before
 *     it (Linux UDP_SEGMENT / Windows USO), and have it hand back runs of
 *     datagrams of one flow the same way (Linux UDP_GRO / Windows URO). This is
 *     what QUIC stacks run on, and what makes a datagram as cheap as a TCP
 *     segment.
 *
 * Whether the kernel can do the second is a fact about the running system, not
 * the build, so it is probed per socket (enable_udp_offload) and degrades on its
 * own: a send the kernel refuses to segment — a device that cannot checksum it,
 * an IPsec route — turns segmentation off for that socket and goes out unsegmented
 * at once rather than being lost. Where none of it exists (macOS, the BSDs) both
 * classes fall back to one call per datagram behind the same interface, so the
 * caller has no #ifdef and no second code path.
 */

#include "librats/core/address.h"
#include "librats/core/socket.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace librats {

/**
 * Buffers one receive call fills, and so the unit a receive loop works in. 32 is
 * enough to make the syscall a rounding error against the work of handling what
 * it returns, while keeping the per-call scratch (one message header, one iovec,
 * one address per buffer) small enough to live on the stack.
 */
constexpr size_t kUdpBatchMax = 32;

/// Datagrams one coalesced buffer may carry — Linux's UDP_MAX_SEGMENTS, the
/// smallest of the platform limits — in either direction.
constexpr size_t kUdpMaxSegments = 64;

/// Bytes one segmented send may carry. Under every IP length limit with room to
/// spare (an IPv6 header and the UDP one included), and a whole number of the
/// datagrams this transport sends nearly fills it (52 x 1220).
constexpr size_t kUdpMaxSendBytes = 63 * 1024;

/// Bytes one coalesced receive can return: a full IP datagram's worth, which is
/// what a kernel coalesces up to.
constexpr size_t kUdpMaxReceiveBytes = 65535;

/// What the kernel will do for one socket beyond moving single datagrams.
struct UdpOffload {
    /// Datagrams one send may carry as equal-size segments of a single buffer
    /// (Linux UDP_SEGMENT, Windows USO). 1 means no segmentation offload.
    size_t max_segments = 1;
    /// Whether one receive may return several datagrams of one flow coalesced
    /// into a single buffer (Linux UDP_GRO, Windows URO). When it is on, every
    /// receive buffer must hold kUdpMaxReceiveBytes — see UdpRecvBatch.
    bool coalesced_receive = false;
};

/**
 * Turn on whatever offload the running system offers on `socket`, and report
 * what took. Each half is independent: a kernel can have one without the other.
 * Never fails — a socket the probe gets nothing from is simply UdpOffload{}.
 */
UdpOffload enable_udp_offload(socket_t socket);

/**
 * Datagrams staged for the wire, leaving together.
 *
 * Datagrams are copied in as they are produced (one memcpy of at most a datagram
 * — the copy is what lets the producer reuse its buffer at once, which a
 * retransmission queue and a stack-built control packet both do) and coalesced
 * as they arrive: a datagram for the destination the previous one went to, no
 * longer than it, joins it as one more segment, and a shorter one ends the run,
 * as segmentation offload requires (equal sizes, the last allowed short). A
 * bulk sender's window therefore leaves as a handful of 52-datagram buffers.
 *
 * flush() puts it all on the wire. With segmentation each run is one send;
 * without it each datagram is its own message, still in one sendmmsg where the
 * platform has that — so turning offload off changes the syscall count and
 * nothing else.
 */
class UdpSendBatch {
public:
    /// Bytes the staging buffer holds; add() reports full past it. Four full
    /// segmented sends, which is more than any one flush of a paced sender
    /// produces (a millisecond at 1 Gbit/s is two of them).
    static constexpr size_t kCapacity = 4 * kUdpMaxSendBytes;

    /// Runs one batch can hold, whatever their size. A batch of bare
    /// acknowledgements to many peers is bounded by this rather than by bytes.
    static constexpr size_t kMaxRuns = 256;

    /// One run of datagrams to one destination, laid out back to back in the
    /// staging buffer: `count` of them, each `segment` bytes but the last, which
    /// may be shorter.
    struct Run {
        Address  to;
        size_t   offset  = 0;  ///< where the first datagram starts in the buffer
        size_t   bytes   = 0;  ///< all of them together
        size_t   segment = 0;  ///< size of each but the last
        size_t   count   = 0;
        bool     open    = true;  ///< false once a short datagram has ended it
    };

    /// @param max_segments datagrams one run may grow to; 1 stages each datagram
    ///        as a run of its own. Normally UdpOffload::max_segments.
    explicit UdpSendBatch(size_t max_segments = 1);

    UdpSendBatch(const UdpSendBatch&) = delete;
    UdpSendBatch& operator=(const UdpSendBatch&) = delete;

    /// Stage one datagram. Returns false, staging nothing, when it does not fit —
    /// flush() and add it again. A datagram longer than kUdpMaxSendBytes, or an
    /// empty one, is refused outright (false even on an empty batch).
    bool add(const Address& to, const uint8_t* data, size_t len);

    /**
     * Put every staged datagram on the wire and empty the batch.
     *
     * @return Datagrams the socket accepted. The caller must treat the whole batch
     *         as spent regardless: one the socket refused (a full send buffer) is
     *         indistinguishable from one the path dropped, and retransmission
     *         covers both — the count is for diagnostics, not for a retry.
     */
    size_t flush(socket_t socket, AddressFamily af);

    bool   empty() const noexcept { return runs_.empty(); }
    /// Datagrams staged, counting every segment of every run.
    size_t datagrams() const noexcept { return datagrams_; }
    const std::vector<Run>& runs() const noexcept { return runs_; }
    const uint8_t* data() const noexcept { return buffer_.get(); }

    /// Current segmentation limit. Drops to 1, for good, the first time the
    /// kernel refuses to segment a send on this socket.
    size_t max_segments() const noexcept { return max_segments_; }

private:
    void disable_segmentation(int error);

    std::unique_ptr<uint8_t[]> buffer_;  ///< kCapacity, never zeroed: only what is staged is touched
    size_t                     used_       = 0;
    size_t                     datagrams_  = 0;
    size_t                     max_segments_;
    std::vector<Run>           runs_;
};

/**
 * One receive batch: kUdpBatchMax buffers, refilled by each receive().
 *
 * Without coalescing each buffer is one datagram. With it a buffer may be a run
 * of datagrams of one flow — `segment` bytes each, the last possibly shorter —
 * and the reader walks them with for_each_datagram(). The buffers are allocated
 * once and never zeroed, so the 2 MiB a coalescing batch reserves costs memory
 * only as far as traffic actually fills it.
 */
class UdpRecvBatch {
public:
    struct Buffer {
        uint8_t* data    = nullptr;
        size_t   len     = 0;   ///< bytes received
        size_t   segment = 0;   ///< datagram size within it; == len for a single one
        Address  from;
    };

    /// @param max_datagram the largest datagram the caller accepts; anything
    ///        longer is truncated, and the caller's decoder refuses it.
    /// @param coalesced    whether the socket may coalesce (UdpOffload).
    UdpRecvBatch(size_t max_datagram, bool coalesced);

    UdpRecvBatch(const UdpRecvBatch&) = delete;
    UdpRecvBatch& operator=(const UdpRecvBatch&) = delete;

    /**
     * Receive into up to `count` buffers (at most kUdpBatchMax), in one syscall
     * where the platform has one.
     *
     * @return Buffers filled (> 0), kUdpRecvWouldBlock when nothing is pending, or
     *         kUdpRecvError. A result shorter than `count` does NOT prove the queue
     *         is empty — a per-datagram error truncates the batch too — so a caller
     *         that must drain (an edge-triggered poller) loops until would-block.
     */
    std::ptrdiff_t receive(socket_t socket, size_t count);

    const Buffer& operator[](size_t i) const noexcept { return buffers_[i]; }

    /// Datagrams one buffer can hold at most: what bounds a drain counted in
    /// datagrams when it can only ask for buffers.
    size_t max_datagrams_per_buffer() const noexcept { return coalesced_ ? kUdpMaxSegments : 1; }

    /// Call `fn(data, len)` for each datagram in buffer `i`, in order.
    template <typename Fn>
    void for_each_datagram(size_t i, Fn&& fn) const {
        const Buffer& b = buffers_[i];
        const size_t  step = b.segment ? b.segment : b.len;
        if (step == 0) { fn(b.data, size_t{0}); return; }  // an empty datagram is still one
        for (size_t off = 0; off < b.len; off += step)
            fn(b.data + off, (std::min)(step, b.len - off));
    }

private:
    std::unique_ptr<uint8_t[]> storage_;
    size_t                     capacity_;   ///< bytes per buffer
    bool                       coalesced_;
    Buffer                     buffers_[kUdpBatchMax];
};

} // namespace librats
