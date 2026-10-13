#include "librats/transport/udp_transport.h"
#include "librats/transport/udp_connection.h"
#include "librats/transport/udp_mux.h"

namespace librats {

namespace {
using Clock = UdpConnection::Clock;
} // namespace

UdpTransport::~UdpTransport() { mux_.release(conn_); }

std::optional<Address> UdpTransport::remote_endpoint() const {
    if (relayed_) return std::nullopt;
    return conn_.remote();
}

bool UdpTransport::is_secure() const noexcept { return conn_.is_secure(); }

void UdpTransport::attach(ConnId id, TransportSink& sink) {
    sink_ = &sink;
    conn_.set_conn_id(id);
}

bool UdpTransport::report_progress() {
    // A responder has heard its dialer by definition; a dialer once its Initial is
    // answered. The handshake is in the connection's hands either way, so the two
    // reports usually come together.
    if (!told_connected_ && (conn_.heard_from_peer() || conn_.established())) {
        told_connected_ = true;
        sink_->transport_connected();
    }
    if (!told_established_ && conn_.established()) {
        told_established_ = true;
        sink_->transport_established(conn_.remote_id());   // may send at once
    }
    return !conn_.dead();
}

bool UdpTransport::start() {
    // An accepted connection: the Initial is in, and with the plaintext handshake
    // so is everything else.
    return report_progress();
}

bool UdpTransport::on_readable() {
    report_progress();
    if (told_established_) {
        bool more = true;
        if (!conn_.deliver(Clock::now(), [&](const Frame& frame) {
                more = sink_->transport_frame(frame);
                return more;
            }))
            return false;
        // The sink is closing the connection, not reporting a broken transport.
        if (!more) return false;
    }
    // Dead after delivering what arrived before the end: an orderly close reads
    // everything the peer sent, then reports PeerClosed.
    if (conn_.dead()) return false;
    mux_.touch(conn_);
    return true;
}

bool UdpTransport::on_writable() {
    if (!report_progress()) return false;
    conn_.flush(Clock::now());
    conn_.want_write(conn_.queued_bytes() > 0);
    mux_.touch(conn_);
    return !conn_.dead();
}

bool UdpTransport::on_error() { return false; }

CloseReason UdpTransport::error_reason() const {
    return conn_.dead() ? conn_.close_reason() : CloseReason::PeerReset;
}

size_t UdpTransport::max_payload() const noexcept {
    // A message travels as stream bytes, so it is bounded by what the far end will
    // reassemble, not by a packet.
    return framer::kMaxBlockSize - framer::kHeaderSize;
}

bool UdpTransport::send(FrameHeader header, ByteView payload, Deadline deadline) {
    const bool queued = is_live(deadline) ? conn_.send_live(header, payload, deadline)
                                          : conn_.send_message(header, payload);
    if (!queued) return false;
    conn_.want_write(true);
    // Enough for a burst of packets already: send it now rather than at the end of
    // the turn, which would only hold memory.
    if (conn_.queued_bytes() >= kCoalesceLimit) {
        conn_.flush(Clock::now());
        mux_.touch(conn_);
    }
    return !conn_.dead();
}

bool UdpTransport::flush() {
    conn_.flush(Clock::now());
    mux_.touch(conn_);
    return !conn_.dead();
}

size_t UdpTransport::backlog() const noexcept { return conn_.queued_bytes(); }

PathStats UdpTransport::path_stats() const { return conn_.path_stats(); }

void UdpTransport::on_maintenance_tick() { conn_.release_memory(); }

void UdpTransport::close(CloseReason reason) {
    conn_.close(reason, Clock::now());
    mux_.touch(conn_);
}

} // namespace librats
