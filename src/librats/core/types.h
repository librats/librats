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

/// Which wire a connection runs over. Tcp and Udp are first-class equals: they
/// carry the exact same block/frame protocol and the same secure handshake, and
/// differ only in how an ordered, reliable byte stream is obtained — the kernel's
/// TCP stack, or the library's own reliability layer on top of datagrams (see
/// transport/udp_stream.h). Relay is a third way of obtaining that same stream —
/// out of another peer's connection rather than out of a socket — and is a last
/// resort rather than an equal (see below).
enum class TransportKind {
    Tcp,    ///< One kernel socket per peer.
    Udp,    ///< Reliable ordered stream over the shared UDP socket (NAT-friendly).
    /// Carried inside another peer's connection: the byte stream is chopped into
    /// messages a third node forwards between the two ends (see subsystems/relay.h).
    /// Not a wire of its own — it is one of the two above, one hop further away —
    /// but it behaves differently enough to be worth naming: it costs the relay
    /// bandwidth, it cannot be dialed, and it must always lose to a direct link
    /// (see PeerTable::add). Never a value connect() or the Dialer chooses.
    Relay,
};

/// How hard an outbound datagram dial tries before it is called failed.
///
/// The default is the ordinary dial: three Syns at a doubling 500 ms timeout, so a
/// path that swallows UDP gives up in about three and a half seconds and the dialer
/// falls back to TCP promptly.
///
/// A hole punch wants the opposite shape. There the FIRST Syn is expected to die on
/// the peer's NAT — its job is to open our own mapping and filter — and what
/// actually connects is a later one, sent after the peer's Syn has crossed ours. So
/// a punch trades the long patient tail for a dense burst: more attempts, closer
/// together, no backoff. Everything else about the stream is unchanged; this only
/// governs the Syn, and once a stream is connected its timeout comes from measured
/// round trips as usual.
struct DialProfile {
    int      syn_attempts = 3;      ///< transmissions of the Syn before the dial fails
    uint32_t syn_rto_ms   = 500;    ///< interval before the first retransmission
    bool     syn_backoff  = true;   ///< double the interval after each attempt

    /// The punch shape: eight probes 200 ms apart, ~1.6 s of dense punching.
    static DialProfile punch() noexcept { return DialProfile{8, 200, false}; }
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
    SlowConsumer,      ///< Kept sending with the queue already past its high-water
                       ///< mark. Not "a message was too large": one message is
                       ///< always queued whatever its size (Connection::send).
    ReactorShutdown,   ///< Reactor is stopping.
    DuplicateConn,     ///< Redundant connection to a peer we already hold; superseded.
    PeerLimit,         ///< Inbound rejected: the configured peer limit is reached.
    IdleTimeout,       ///< Datagram link went silent past its idle deadline.
    DialSuperseded,    ///< A racing dial over the other transport won; this one is redundant.
};

const char* to_string(ConnState) noexcept;
/// Exported: a CloseReason is handed to every on_peer_disconnected handler, so a
/// consumer of the shared build has to be able to render one. (ConnState above is
/// not — it never leaves Connection.)
RATS_API const char* to_string(CloseReason) noexcept;
/// Exported for the same reason: TransportKind is part of the public surface
/// (NodeConfig::preferred_transport, PeerInfo::transport).
RATS_API const char* to_string(TransportKind) noexcept;

} // namespace librats
