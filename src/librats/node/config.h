#pragma once

/**
 * @file config.h
 * @brief Node construction options.
 */

#include "librats/util/rats_export.h"
#include "librats/core/types.h"   // TransportKind

#include <cstdint>
#include <string>

namespace librats {

struct RATS_API NodeConfig {
    /// Listen port for inbound peers. 0 picks an ephemeral port. Ignored if
    /// enable_listen is false (client-only node). Both transports use this same
    /// port, so one advertised address is dialable over either.
    uint16_t listen_port = 0;
    bool     enable_listen = true;

    // ── Transports ──────────────────────────────────────────────────────────
    //
    // TCP and UDP are equal citizens here: identical framing, identical Noise
    // handshake, identical guarantees. They differ only in how the ordered,
    // reliable byte stream underneath is obtained — the kernel's TCP stack, or
    // the library's own reliability layer over datagrams (transport/udp_stream.h).
    // A node normally offers both and lets each dial pick.

    /// Accept and dial over TCP.
    bool enable_tcp = true;
    /// Accept and dial over the datagram transport. Also gives a dial-only node a
    /// single UDP socket to dial from, which is what keeps one NAT mapping open
    /// for every peer instead of one per peer.
    bool enable_udp = true;

    /// Which transport a dial tries first.
    ///
    /// UDP is the default because it is the better fit for peer-to-peer: every
    /// peer shares one socket and therefore one NAT mapping, the port a peer sees
    /// us send from is the port it can dial back, which is what makes hole
    /// punching possible at all, and no middlebox holds per-connection state that
    /// can be exhausted or timed out from under us. TCP remains a first-class
    /// equal, and is what the fallback below exists for — some networks block or
    /// throttle UDP outright.
    TransportKind preferred_transport = TransportKind::Udp;

    /// How long the preferred transport dials alone before the other one is
    /// raced alongside it. The first to complete its handshake wins and the loser
    /// is dropped, so a UDP-blocking network costs this delay rather than a failed
    /// connection. 0 disables the fallback: only the preferred transport is tried.
    uint32_t transport_fallback_ms = 1200;

    /// Bytes a peer's send queue may hold before an application that keeps
    /// sending anyway has the peer dropped as a slow consumer. 0 uses the library
    /// default (8 MiB).
    ///
    /// It is not a maximum message size. A single message is always queued
    /// whatever its size — a message cannot be sent by halves, and a healthy
    /// connection must not die over one large frame — so the queue's real ceiling
    /// is this plus one message. What gets a peer dropped is offering *another*
    /// message while the queue is still over the mark.
    ///
    /// A quarter of this is the mark at which send() starts answering "no room"
    /// and on_peer_writable is what says the room is back — so lowering it makes
    /// an application feel backpressure sooner, and raising it lets a bursty one
    /// buffer more before anything is said. The two move together on purpose:
    /// a warning that arrives at the same moment as the disconnection is no
    /// warning at all.
    size_t send_queue_limit = 0;

    /// Interface to bind the listener to. The address family is derived from it:
    ///   - ""  or "::"      → dual-stack wildcard: reachable over both IPv6 and IPv4
    ///                        (IPv4-mapped) on all interfaces. This is the default.
    ///   - "0.0.0.0"        → IPv4 on all interfaces.
    ///   - an IPv6 literal  → IPv6-only, that interface (e.g. "::1" for v6 loopback).
    ///   - an IPv4 literal  → IPv4, that interface (e.g. "127.0.0.1" for v4 loopback).
    /// Bare IPv6 literals are written without brackets here; peer endpoints rendered
    /// as text use bracketed "[ip]:port" form (see core/address.h).
    std::string bind_address = "";

    /// Number of reactor threads. 1 is plenty for thousands of peers; larger
    /// pools shard outbound connections across cores.
    size_t reactor_threads = 1;

    /// Maximum number of established peers. 0 means unlimited. The limit guards
    /// inbound connections (a flood is refused at accept, before any handshake);
    /// outbound dials we initiate are always honored. Runtime-adjustable via
    /// Node::set_max_peers().
    size_t max_peers = 0;

    /// Secure channel to use for peer connections.
    enum class Security { Noise, Plaintext };
    Security security = Security::Noise;

    /// Application protocol identity, bound into the Noise handshake prologue, so
    /// two nodes whose protocol differs cannot complete a handshake — a cheap,
    /// cryptographically-enforced way to keep separate apps (or app versions)
    /// from cross-connecting. An opaque string compared for exact equality; by
    /// convention "<name>/<version>". Both peers must match. (Under Plaintext it
    /// is still checked, but not cryptographically bound — see PlaintextSecurity.)
    std::string protocol = "librats/1.0";

    /// Directory for persistent state. Empty = ephemeral (a fresh random
    /// identity each run). When set, the node's Noise keypair is loaded from /
    /// saved to "<data_dir>/identity.key", giving a stable PeerId across restarts.
    std::string data_dir = "";

    /// Watch the host for network configuration changes (interface up/down, IP
    /// add/remove, route flip, wake-from-sleep) and publish NetworkChanged on the
    /// node's EventBus so subsystems can renew port mappings, re-run STUN and
    /// re-announce. Costs one mostly-idle monitor thread. See node/host_events.h.
    bool enable_network_monitor = true;
};

} // namespace librats
