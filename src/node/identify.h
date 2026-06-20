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
 *
 * The wire form is a compact, versioned, fully bounds-checked binary blob — decode
 * never trusts a length without checking it against the buffer, and every count is
 * capped, so a malformed or hostile payload yields nullopt rather than misbehaving.
 */

#include "core/address.h"
#include "core/bytes.h"

#include <cstdint>
#include <optional>
#include <vector>

namespace librats {

struct IdentifyMessage {
    static constexpr uint8_t kVersion      = 1;
    static constexpr size_t  kMaxAddresses = 32;  ///< cap advertised addresses
    static constexpr size_t  kMaxIpLength  = 64;  ///< cap a single IP literal

    uint16_t               listen_port = 0;
    std::vector<Address>   addresses;   ///< sender's self-advertised dialable addrs
    std::optional<Address> observed;    ///< address sender saw the recipient at

    /// Serialise to the wire form. Addresses with an empty IP, an over-long IP, or
    /// a zero port are skipped; at most kMaxAddresses are emitted.
    Bytes encode() const;

    /// Parse the wire form. Returns nullopt on an unknown version or any
    /// truncation/inconsistency — the caller treats that as "no identify".
    static std::optional<IdentifyMessage> decode(ByteView in);
};

} // namespace librats
