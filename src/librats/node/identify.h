#pragma once

/**
 * @file identify.h
 * @brief The node's "identify" control message — how peers learn each other's
 *        dialable addresses (libp2p-identify in spirit).
 *
 * A TCP socket only reveals a peer's *source* endpoint: its IP plus an ephemeral
 * port the OS picked for the outbound socket — never the port it listens on. So
 * the dialable address of an INBOUND peer is unknowable from the connection
 * alone; the peer must tell us. Right after the secure handshake, each side sends
 * an Identify message over the authenticated channel carrying:
 *
 *   - listen_port : the TCP port this node accepts connections on. The receiver
 *                   pairs it with the IP it sees the sender at to form a dialable
 *                   address (the key that makes inbound peers reconnectable).
 *   - addresses   : additional self-advertised dialable addresses (e.g. each local
 *                   interface IP with the listen port) — the "multiaddr set".
 *   - observed    : the address the sender observed the RECIPIENT connecting from,
 *                   so a node can learn its own public IP as peers see it.
 *   - transports  : which wires the sender accepts on that port (TCP, the
 *                   datagram transport, or both). Both bind the SAME port, so
 *                   this is a property of the node rather than of an address —
 *                   it tells a peer which transports are worth dialing before it
 *                   spends a fallback delay finding out.
 *
 * The transports byte is appended after the older fields, and decode has always
 * ignored trailing bytes, so a node that predates it simply reads the message
 * without it and reports "unspecified" rather than failing.
 *
 * The wire form is a compact, versioned, fully bounds-checked binary blob — decode
 * never trusts a length without checking it against the buffer, and every count is
 * capped, so a malformed or hostile payload yields nullopt rather than misbehaving.
 */

#include "librats/util/rats_export.h"
#include "librats/core/address.h"
#include "librats/core/bytes.h"

#include <cstdint>
#include <optional>
#include <vector>

namespace librats {

struct RATS_API IdentifyMessage {
    static constexpr uint8_t kVersion      = 1;   ///< IPs on the wire are raw bytes (4/16), not text
    static constexpr size_t  kMaxAddresses = 32;  ///< cap advertised addresses
    static constexpr size_t  kMaxIpLength  = 16;  ///< a single IP is 4 (v4) or 16 (v6) bytes

    /// Transport bitmask values, matching PeerTransports in peer/peer_info.h.
    static constexpr uint8_t kTransportTcp = 1 << 0;
    static constexpr uint8_t kTransportUdp = 1 << 1;

    uint16_t               listen_port = 0;
    std::vector<Address>   addresses;   ///< sender's self-advertised dialable addrs
    std::optional<Address> observed;    ///< address sender saw the recipient at
    /// Transports the sender accepts on listen_port. 0 means the sender did not
    /// say (an older peer); treat that as "no better information", not as "none".
    uint8_t                transports = 0;

    /// Serialise to the wire form. Addresses with an empty IP, an over-long IP, or
    /// a zero port are skipped; at most kMaxAddresses are emitted.
    Bytes encode() const;

    /// Parse the wire form. Returns nullopt on an unknown version or any
    /// truncation/inconsistency — the caller treats that as "no identify".
    static std::optional<IdentifyMessage> decode(ByteView in);
};

} // namespace librats
