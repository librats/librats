#pragma once

/**
 * @file bittorrent.h
 * @brief Main include file for BitTorrent functionality
 * 
 * This header aggregates all BitTorrent-related headers for convenience.
 * Include this single file to access the complete BitTorrent implementation.
 * 
 * Components:
 * - bt_types.h: Core types, constants, and utilities
 * - bt_bitfield.h: Efficient bit array for piece tracking
 * - bt_file_storage.h: File layout and piece-to-file mapping
 * - bt_torrent_info.h: .torrent file parsing and magnet URIs
 * - bt_piece_picker.h: Rarest-first piece selection
 * - bt_messages.h: Protocol message encoding/decoding
 * - bt_handshake.h: Handshake handling
 * - bt_peer_connection.h: Peer connection management
 * - bt_extension.h: Extension protocol (BEP 10, ut_metadata, ut_pex)
 * - bt_choker.h: Choking algorithm
 * - bt_torrent.h: Active torrent state machine
 * - bt_client.h: High-level BitTorrent client
 * 
 * Usage:
 * @code
 * #include "bittorrent.h"
 * 
 * using namespace librats;
 * 
 * // Create client
 * BtClient client;
 * client.start();
 * 
 * // Add torrent from file
 * auto torrent = client.add_torrent_file("example.torrent", "/downloads");
 * 
 * // Or from magnet link
 * auto torrent2 = client.add_magnet("magnet:?xt=urn:btih:...");
 * @endcode
 */

#ifdef RATS_SEARCH_FEATURES

#include "bt_types.h"
#include "bt_bitfield.h"
#include "bt_file_storage.h"
#include "bt_torrent_info.h"
#include "bt_piece_picker.h"
#include "bt_messages.h"
#include "bt_handshake.h"
#include "bt_peer_connection.h"
#include "bt_extension.h"
#include "bt_choker.h"
#include "bt_torrent.h"
#include "bt_client.h"

namespace librats {

//=============================================================================
// Type aliases for compatibility with existing librats API
//=============================================================================

/// Alias for TorrentDownload (used by RatsClient API)
using TorrentDownload = Torrent;

/// Alias for BitTorrentClient (used by RatsClient API)
using BitTorrentClient = BtClient;

/// Alias for InfoHash (used by RatsClient API) - 20-byte hash
using InfoHash = BtInfoHash;

} // namespace librats

#endif // RATS_SEARCH_FEATURES
