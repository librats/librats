#pragma once

/**
 * @file stream_transport.h
 * @brief A Transport over any ordered, reliable byte stream (a Link).
 *
 * The same code serves a kernel TCP socket and a relayed circuit: both are a Link,
 * and a Link is all this needs.
 *
 * On the wire it is a run of length-prefixed blocks (wire/frame.h). The first few
 * carry the handshake in the clear; every one after that is a single inner message
 * sealed by the Session. The stream delivers blocks in order, so both ends number
 * them alike — 0, 1, 2… in each direction — and the nonce never travels.
 *
 * ── Sending ──────────────────────────────────────────────────────────────────
 * Two queues stand between send() and the link:
 *
 *       send() ─→ [ SendQueue: in the clear, by lane ] ─seal─→ [ tx_: sealed ] ─→ link
 *
 * A message is sealed only when the link is about to take it: flush() seals just
 * enough to keep kSealAhead bytes ready in front of the link, and whatever the link
 * has not taken yet stays in the SendQueue, unsealed and still free to be overtaken
 * by a more urgent lane (see send_queue.h). Sealing earlier would fix the order for
 * good — the nonces are in lockstep — and a ping queued behind megabytes of file
 * would wait for all of them.
 *
 * It is also the last moment a live message can be dropped: once sealed it has a
 * nonce the peer is counting on, so one past its deadline is dropped by the queue
 * as its turn comes rather than sealed (send_queue.h). What the kernel has already
 * taken still arrives, late or not.
 *
 * For that to reach the network rather than end in a kernel queue, the kernel's
 * own backlog has to stay short too: a TCP socket is given TCP_NOTSENT_LOWAT (see
 * Reactor::adopt), so it accepts more only once what it has not sent yet runs low.
 *
 * Writes are aggregated: a reactor turn's messages go out in one flush() at the end
 * of it, and only a queue past kCoalesceLimit is written at once.
 *
 * ── Receiving ────────────────────────────────────────────────────────────────
 * The link is drained into a receive buffer and parsed as it fills, one block at a
 * time; each message is opened in place and handed to the sink, so receiving costs
 * no allocation per message.
 */

#include "librats/core/chained_send_buffer.h"
#include "librats/core/receive_buffer.h"
#include "librats/security/handshaker.h"
#include "librats/transport/link.h"
#include "librats/transport/send_queue.h"
#include "librats/transport/transport.h"

#include <memory>

namespace librats {

class StreamTransport final : public Transport {
public:
    /// Sealed bytes kept ready in front of the link. A write takes what the kernel
    /// will hold, and with TCP_NOTSENT_LOWAT that is little, so more than one write's
    /// worth sealed in advance is only order given up for nothing.
    static constexpr size_t kSealAhead = 64 * 1024;

    /// Queued bytes past which send() stops waiting for the end of the turn and
    /// writes at once. Below it, a turn's messages are one write instead of one each
    /// (measured at roughly ten times the throughput for small ones); above it there
    /// is already enough for a write, and waiting would only hold memory.
    static constexpr size_t kCoalesceLimit = 64 * 1024;

    StreamTransport(std::unique_ptr<Link> link, ConnRole role, SecurityProvider& security);
    ~StreamTransport() override;

    // — Transport —
    TransportKind          kind() const noexcept override { return link_->kind(); }
    socket_t               fd() const noexcept override { return link_->fd(); }
    std::optional<Address> remote_endpoint() const override { return link_->remote_endpoint(); }
    bool                   is_secure() const noexcept override { return session_ && session_->is_secure(); }
    void                   attach(ConnId id, TransportSink& sink) override;

    bool        start() override;
    bool        on_readable() override;
    bool        on_writable() override;
    bool        on_error() override { return fail(link_->error_reason()); }
    CloseReason error_reason() const override { return error_; }

    size_t max_payload() const noexcept override;
    bool   send(FrameHeader header, ByteView payload, Deadline deadline, uint64_t tag = 0) override;
    bool   flush() override;
    size_t backlog() const noexcept override { return queue_.allocated() + tx_.allocated(); }

    PathStats path_stats() const override;
    void      on_maintenance_tick() override { rx_.decay(); }
    void      close(CloseReason reason) override { link_->close(reason); }

private:
    enum class Phase { Connecting, Handshaking, Established, Broken };

    bool   begin_handshake();
    size_t read_size() const;          ///< bytes to offer the next read (see rx_need_)
    bool   process_blocks();           ///< parse every complete block in rx_
    bool   drive_handshake(ByteView body);
    bool   deliver(uint8_t* body, size_t size);  ///< open in place, parse, hand to the sink
    void   queue_handshake(const Bytes& message);
    void   arm_write(bool on);
    /// Seal and write what the link takes. flush() less telling the sink what
    /// became of tagged live messages, which send() must not.
    bool   write_out();
    bool   fail(CloseReason reason);   ///< record why, return false

    std::unique_ptr<Link> link_;
    ConnRole              role_;
    SecurityProvider&     security_;
    TransportSink*        sink_ = nullptr;
    Phase                 phase_ = Phase::Connecting;
    CloseReason           error_ = CloseReason::PeerClosed;

    std::unique_ptr<Handshaker> handshaker_;  ///< only while handshaking
    std::unique_ptr<Session>    session_;     ///< once established
    uint64_t                    send_nonce_ = 0;  ///< nonce of the next block sealed
    uint64_t                    recv_nonce_ = 0;  ///< nonce of the next block opened

    ReceiveBuffer rx_;
    /// Wire size of the block rx_ is part-way through once its length prefix is in,
    /// 0 otherwise — lets the next read size rx_ for all of it at once. The peer's
    /// word, so honoured only up to a cap (see read_size).
    size_t        rx_need_ = 0;

    SendQueue         queue_;  ///< messages not sealed yet
    ChainedSendBuffer tx_;     ///< sealed blocks (and handshake messages) the link has not taken
    bool              want_write_ = false;
};

} // namespace librats
