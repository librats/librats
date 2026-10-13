#pragma once

/**
 * @file types.h
 * @brief Core transport identifiers and enums shared across the reactor layer.
 */

#include "librats/util/rats_export.h"

#include <chrono>
#include <cstddef>
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

/// Which wire a connection runs over. Tcp and Udp are first-class equals: the
/// same Noise handshake, the same messages, the same guarantees per lane. TCP
/// carries them as blocks over the kernel's byte stream; UDP as the library's own
/// QUIC-shaped packets on one shared socket (see transport/udp_connection.h).
/// Relay is a third way of reaching a peer — a byte stream out of another peer's
/// connection rather than out of a socket — and is a last resort rather than an
/// equal (see below).
enum class TransportKind {
    Tcp,    ///< One kernel socket per peer.
    Udp,    ///< The datagram transport, on the shared UDP socket (NAT-friendly).
    /// Carried inside another peer's connection: the byte stream is chopped into
    /// messages a third node forwards between the two ends (see subsystems/relay.h).
    /// Not a wire of its own — it is one of the two above, one hop further away —
    /// but it behaves differently enough to be worth naming: it costs the relay
    /// bandwidth, it cannot be dialed, and it must always lose to a direct link
    /// (see PeerTable::add). Never a value connect() or the Dialer chooses.
    Relay,
};

/// Which congestion controller a datagram stream runs (see
/// transport/congestion_control.h). TCP is governed by the kernel and ignores this.
///
/// BBR is the default because of what peer-to-peer paths look like: home Wi-Fi,
/// mobile links and long intercontinental hops all lose packets for reasons that
/// have nothing to do with congestion, and a loss-based controller reads every
/// one of those as "slow down". At 1% random loss Reno keeps about a tenth of a
/// 10 Mbit/s, 100 ms path; BBR, which steers by measured bandwidth and round-trip
/// time and only backs off once loss passes a threshold, keeps most of it.
enum class CongestionAlgorithm : uint8_t {
    Bbr,   ///< BBRv3 (draft-ietf-ccwg-bbr): model-based, paced, loss-tolerant.
    Reno,  ///< NewReno with HyStart++ (RFC 9406): the classic loss-based controller.
};

/// How hard an outbound datagram dial tries before it is called failed.
///
/// The default is the ordinary dial: three Initials at a doubling 500 ms interval,
/// so a path that swallows UDP gives up in about three and a half seconds and the
/// dialer falls back to TCP promptly.
///
/// A hole punch wants the opposite shape. There the FIRST Initial is expected to
/// die on the peer's NAT — its job is to open our own mapping and filter — and what
/// actually connects is a later one, sent after the peer's has crossed ours. So a
/// punch trades the long patient tail for a dense burst: more attempts, closer
/// together, no backoff. Everything else about the connection is unchanged; this
/// only governs the Initial, and once connected its timers come from measured
/// round trips as usual.
struct DialProfile {
    int      attempts    = 3;      ///< Initials sent before the dial fails
    uint32_t interval_ms = 500;    ///< wait before the first repeat
    bool     backoff     = true;   ///< double the wait after each attempt

    /// The punch shape: eight probes 200 ms apart, ~1.6 s of dense punching.
    static DialProfile punch() noexcept { return DialProfile{8, 200, false}; }
};

/// How one message is to be delivered.
///
/// The default is reliable: the message arrives whatever it takes, in order with
/// every other message of its lane (see Connection::send). That is right for
/// anything that must arrive, and wrong for anything that is only worth having
/// while it is fresh — a video frame a second late is no use to anyone, yet a
/// reliable transport would keep re-sending it and hold every fresher frame
/// behind it.
///
/// A message with a `lifetime` is *live* instead: worth delivering only within
/// that long of the send call. The transport still repairs what the path loses,
/// for as long as the repair can arrive in time, and drops the message — whole —
/// as soon as it cannot. So a live message arrives in time or not at all: never
/// in part, never twice, and never late by more than the transport's estimate of
/// the path is wrong. It is ordered with nothing, not even other live messages on
/// the same channel: it is handed over the moment it is complete, so a sender that
/// needs the order (a decoder does) numbers what it sends. Live messages go ahead
/// of ordinary traffic and are dropped before it is, which is what lets fresh
/// frames through a queue that a burst or an outage has filled.
///
/// The receiving side needs nothing: a live message arrives at the same handler
/// as any other on its channel.
struct SendOptions {
    /// Longest lifetime a live message may have; a longer one is shortened to it.
    /// Past this a message is not live, it is late.
    static constexpr std::chrono::milliseconds kMaxLifetime{30000};
    /// Largest payload a live message may carry — a 4K keyframe with room to
    /// spare. A message is only ever delivered whole, so the receiver holds all
    /// of one until its last piece is in, and this bounds that.
    static constexpr size_t kMaxLivePayload = 1024 * 1024;

    /// Zero (or less): reliable. Otherwise live, for this long from the call.
    std::chrono::milliseconds lifetime{0};

    bool live() const noexcept { return lifetime.count() > 0; }
};

/// When a queued message stops being worth sending: the moment a live message's
/// lifetime runs out (see SendOptions). The clock's epoch, the default, means
/// never — a reliable message.
using Deadline = std::chrono::steady_clock::time_point;

/// Whether a message with this deadline is live.
inline bool is_live(Deadline deadline) noexcept { return deadline != Deadline{}; }

/// What a connection's transport currently knows about the path to its peer —
/// for an application that sizes its own sending to the path rather than letting
/// the queue find the limit for it. A live encoder is the case it exists for: the
/// transport will carry whatever it is given, but anything past `bandwidth_bps`
/// waits in `queued_bytes`, and for a frame with a deadline waiting is losing.
///
/// Only the fields the transport can actually measure are filled; `valid` is false
/// when it measures nothing at all (a relayed link, TCP off Linux). Rates are bits
/// per second, the unit an encoder is configured in.
struct PathStats {
    bool     valid = false;
    /// What the congestion controller believes the path delivers — the figure to
    /// size a sender to. 0 until there is an estimate.
    uint64_t bandwidth_bps = 0;
    /// The sender was not filling the path when the estimate was last taken, so
    /// `bandwidth_bps` is a floor (what was used) rather than what the path holds.
    /// The normal state of a sender that keeps to the estimate; finding out how
    /// much more there is takes sending more.
    bool     app_limited = false;
    /// How fast the transport is releasing packets right now; 0 when unpaced.
    uint64_t pacing_bps = 0;
    uint32_t srtt_us    = 0;   ///< smoothed round trip
    uint32_t min_rtt_us = 0;   ///< lowest round trip seen: the path without queues
    /// Accepted for the peer and not yet sent: what a new message waits behind.
    /// Divided by `bandwidth_bps` it is that wait in seconds.
    uint64_t queued_bytes    = 0;
    uint64_t bytes_in_flight = 0;   ///< sent and not yet acknowledged
    /// Share of the bytes resolved over the last sampling interval that were
    /// declared lost, 0..1 (a spurious loss counts too: it is what the sender saw).
    double   loss = 0;
    uint64_t bytes_delivered = 0;   ///< acknowledged since the connection opened
    uint64_t bytes_lost      = 0;   ///< declared lost since the connection opened
    /// Live messages (SendOptions::lifetime) accepted since the connection opened,
    /// and how many of them were dropped because their lifetime ran out before
    /// they were known to be delivered — what a live encoder that is asking for
    /// more than the path carries sees first. Known by the sender: one given up on
    /// with a piece taken for lost that was only late may have arrived all the same.
    uint64_t live_sent    = 0;
    uint64_t live_expired = 0;
    /// Bytes of repair symbols sent with live messages since the connection opened
    /// (forward error correction, on a path that loses packets) — part of what the
    /// path carries that is not the source's: a source sizing itself to
    /// `bandwidth_bps` leaves room for it.
    uint64_t live_repair_bytes = 0;
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
/// Exported: NodeConfig::congestion_control is part of the public surface.
RATS_API const char* to_string(CongestionAlgorithm) noexcept;

} // namespace librats
