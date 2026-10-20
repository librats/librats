#pragma once

/**
 * @file udp_transport.h
 * @brief The Transport a Connection holds for a datagram connection.
 *
 * The UdpConnection itself belongs to the mux, not to the Connection: it has to
 * outlive the Connection briefly so the last bytes still get delivered, and it
 * has to be reachable by connection id from the datagram path. So this is a
 * handle — the translation between what a Connection asks of a Transport and what
 * the connection does, plus the one thing a handle owns: telling the sink about
 * the handshake's progress from inside an entry point, which is the only place
 * TransportSink may be called from.
 *
 * A connection whose packets a relay forwards (udp_mux.h) is the same datagram
 * connection with a third node's address as its remote. To everything above it is
 * a relayed peer: it reports TransportKind::Relay, and no endpoint — the address
 * it talks to is the relay's, which identify and NatStatus must never take for
 * the peer's own (see RelayLink::remote_endpoint).
 */

#include "librats/transport/transport.h"

namespace librats {

class UdpConnection;
class UdpMux;

class UdpTransport final : public Transport {
public:
    /// Messages queued past which send() stops waiting for the end of the reactor
    /// turn and sends at once (StreamTransport::kCoalesceLimit, for the same reason).
    static constexpr size_t kCoalesceLimit = 64 * 1024;

    UdpTransport(UdpMux& mux, UdpConnection& conn, bool relayed = false) noexcept
        : mux_(mux), conn_(conn), relayed_(relayed) {}
    ~UdpTransport() override;

    TransportKind kind() const noexcept override {
        return relayed_ ? TransportKind::Relay : TransportKind::Udp;
    }
    socket_t               fd() const noexcept override { return RATS_INVALID_SOCKET; }
    std::optional<Address> remote_endpoint() const override;
    bool                   is_secure() const noexcept override;
    void                   attach(ConnId id, TransportSink& sink) override;

    bool        start() override;
    bool        on_readable() override;
    bool        on_writable() override;
    bool        on_error() override;
    CloseReason error_reason() const override;

    size_t max_payload() const noexcept override;
    bool   send(FrameHeader header, ByteView payload, Deadline deadline, uint64_t tag = 0) override;
    bool   flush() override;
    size_t backlog() const noexcept override;

    PathStats path_stats() const override;
    void      on_maintenance_tick() override;
    void      close(CloseReason reason) override;

    UdpConnection& connection() noexcept { return conn_; }

private:
    /// Tell the sink what the handshake has done since it last heard. False once
    /// the connection is dead.
    bool report_progress();
    /// Tell the sink what became of the tagged live messages settled since.
    void report_outcomes();

    UdpMux&        mux_;
    UdpConnection& conn_;
    const bool     relayed_;
    TransportSink* sink_ = nullptr;
    bool           told_connected_   = false;
    bool           told_established_ = false;
};

} // namespace librats
