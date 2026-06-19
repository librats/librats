#pragma once

/**
 * @file types.h
 * @brief Core transport identifiers and enums shared across the reactor layer.
 */

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

/// Connection lifecycle. A connection moves strictly forward through these.
enum class ConnState {
    Connecting,   ///< Outbound TCP connect in flight (waiting for writable).
    Handshaking,  ///< TCP up; secure-channel handshake in progress.
    Established,  ///< Handshake done; application frames may flow.
    Closing,      ///< Marked for teardown; no further frames accepted.
    Closed,       ///< Removed from the reactor.
};

/// Why a connection was torn down. Surfaced to delegates/observers.
enum class CloseReason {
    LocalClose,        ///< Application asked to disconnect.
    PeerClosed,        ///< Remote sent FIN (clean close).
    PeerReset,         ///< Connection reset / socket error.
    ConnectFailed,     ///< Outbound TCP connect never completed.
    HandshakeFailed,   ///< Secure-channel handshake failed or timed out.
    ProtocolError,     ///< Malformed frame / decryption failure on the wire.
    SlowConsumer,      ///< Send buffer exceeded its high-water mark.
    ReactorShutdown,   ///< Reactor is stopping.
};

const char* to_string(ConnState) noexcept;
const char* to_string(CloseReason) noexcept;

} // namespace librats
