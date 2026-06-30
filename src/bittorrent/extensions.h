#pragma once

/**
 * @file extensions.h
 * @brief BEP 10 extension protocol + BEP 9 metadata-exchange message codecs.
 *
 * BEP 10 layers named extensions on top of the wire's `extended` message
 * (id 20). After the BitTorrent handshake each side sends an *extended
 * handshake* (extended id 0) carrying a bencoded `m` dict that maps extension
 * names to the message ids it wants them sent under — so the id you use to send
 * a peer a `ut_metadata` message is the id *that peer* advertised, while the id
 * you receive it under is the one *you* advertised (our fixed kUtMetadataLocalId).
 *
 * BEP 9 (`ut_metadata`) fetches the info-dictionary from peers for magnet links:
 * the metadata is split into 16 KiB pieces requested/served via three message
 * types (request / data / reject).
 *
 * These functions are pure (de)serialisation — the stateful request/serve/verify
 * logic lives in the Torrent. That keeps the wire format unit-testable in
 * isolation.
 */

#include "bittorrent/types.h"
#include "core/bytes.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace librats::bittorrent::ext {

// Our local extended-message ids (what we tell peers to address us by).
constexpr std::uint8_t kUtMetadataLocalId = 1;
constexpr std::uint8_t kUtPexLocalId      = 2;

constexpr char kUtMetadataName[] = "ut_metadata";
constexpr char kUtPexName[]      = "ut_pex";

// ---- extended handshake (extended id 0) ----

/// Build our extended handshake. @p metadata_size is advertised only when > 0
/// (i.e. we actually hold the metadata); likewise @p listen_port when non-zero.
Bytes encode_handshake(std::uint32_t metadata_size, std::uint16_t listen_port);

struct PeerExtensions {
    std::uint8_t  ut_metadata_id = 0;  ///< id to send ut_metadata under (0 = unsupported)
    std::uint8_t  ut_pex_id      = 0;
    std::uint32_t metadata_size  = 0;  ///< peer's info-dict size, if advertised
    std::uint16_t listen_port    = 0;
};

/// Parse a peer's extended handshake. nullopt if it isn't a valid bencoded dict.
std::optional<PeerExtensions> decode_handshake(ByteView payload);

// ---- ut_metadata (BEP 9) ----

enum class MetadataType : std::uint8_t { Request = 0, Data = 1, Reject = 2 };

Bytes encode_metadata_request(std::uint32_t piece);
Bytes encode_metadata_reject(std::uint32_t piece);
/// A `data` message: the bencoded header followed by the raw metadata @p block.
Bytes encode_metadata_data(std::uint32_t piece, std::uint32_t total_size, ByteView block);

struct MetadataMessage {
    MetadataType  type        = MetadataType::Request;
    std::uint32_t piece       = 0;
    std::uint32_t total_size  = 0;  ///< only set on Data
    Bytes         block;            ///< only set on Data (the raw 16 KiB slice)
};

/// Parse a ut_metadata message (header dict + optional trailing block). nullopt
/// if malformed.
std::optional<MetadataMessage> decode_metadata(ByteView payload);

// ---- ut_pex (BEP 11) ----

struct PexPeer {
    std::string   ip;
    std::uint16_t port = 0;
};

/// Encode an IPv4 peer-exchange message (`added`/`dropped` compact lists).
Bytes encode_pex(const std::vector<PexPeer>& added, const std::vector<PexPeer>& dropped);

struct PexMessage {
    std::vector<PexPeer> added;
    std::vector<PexPeer> dropped;
};

/// Parse a ut_pex message. nullopt if malformed. (IPv4 `added`/`dropped` only.)
std::optional<PexMessage> decode_pex(ByteView payload);

} // namespace librats::bittorrent::ext
