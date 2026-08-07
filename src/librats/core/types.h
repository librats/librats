#pragma once

/**
 * @file types.h
 * @brief Core transport identifiers and enums shared across the reactor layer.
 */

#include "librats/util/rats_export.h"

#include <cstdint>

namespace librats {

/// Stable-for-lifetime connection handle. Assigned by the owning Reactor and
/// unique within it; never reused while the connection is alive.
using ConnId = uint64_t;
constexpr ConnId kInvalidConnId = 0;

/// Opaque timer handle returned by Reactor::schedule(), usable to cancel().
using TimerId = uint64_t;
constexpr TimerId kInvalidTimerId = 0;

/// Who initiated the connection.
enum class ConnRole {
    Inbound,   ///< We accepted it from a listener.
    Outbound,  ///< We dialed out to a remote address.
};

/// Which wire a connection runs over. Both are first-class: they carry the exact
/// same block/frame protocol and the same secure handshake, and differ only in how
/// an ordered, reliable byte stream is obtained — the kernel's TCP stack, or the
/// library's own reliability layer on top of datagrams (see transport/udp_stream.h).
enum class TransportKind {
    Tcp,  ///< One kernel socket per peer.
    Udp,  ///< Reliable ordered stream over the shared UDP socket (NAT-friendly).
};

/// Connection lifecycle. A connection moves strictly forward through these.
enum class ConnState {
    Connecting,   ///< Outbound transport connect in flight (TCP connect / UDP SYN).
    Handshaking,  ///< Transport up; secure-channel handshake in progress.
    Established,  ///< Handshake done; application frames may flow.
    Closing,      ///< Marked for teardown; no further frames accepted.
    Closed,       ///< Removed from the reactor.
};

/// Why a connection was torn down. Surfaced to delegates/observers.
enum class CloseReason {
    LocalClose,        ///< Application asked to disconnect.
    PeerClosed,        ///< Remote sent FIN (clean close).
    PeerReset,         ///< Connection reset / socket error.
    ConnectFailed,     ///< Outbound transport connect never completed.
    HandshakeFailed,   ///< Secure-channel handshake failed or timed out.
    ProtocolError,     ///< Malformed frame / decryption failure on the wire.
    SlowConsumer,      ///< Send buffer exceeded its high-water mark.
    ReactorShutdown,   ///< Reactor is stopping.
    DuplicateConn,     ///< Redundant connection to a peer we already hold; superseded.
    PeerLimit,         ///< Inbound rejected: the configured peer limit is reached.
    IdleTimeout,       ///< Datagram link went silent past its idle deadline.
    DialSuperseded,    ///< A racing dial over the other transport won; this one is redundant.
};

const char* to_string(ConnState) noexcept;
const char* to_string(CloseReason) noexcept;
/// Exported, unlike its siblings above: TransportKind is part of the public
/// surface (NodeConfig::preferred_transport, PeerInfo::transport), so a consumer
/// of the shared build needs to be able to render one. ConnState/CloseReason only
/// ever appear on Connection, which does not cross the library boundary.
RATS_API const char* to_string(TransportKind) noexcept;

} // namespace librats
