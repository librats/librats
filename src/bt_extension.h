#pragma once

/**
 * @file bt_extension.h
 * @brief BitTorrent extension protocol (BEP 10)
 * 
 * Base interface for protocol extensions like:
 * - ut_metadata (BEP 9): Metadata exchange for magnet links
 * - ut_pex: Peer exchange
 * - lt_donthave: Don't have notification
 */

#include "bt_types.h"
#include "bencode.h"

#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <functional>

namespace librats {

// Forward declarations
class BtPeerConnection;

/**
 * @brief Base class for BitTorrent extensions
 * 
 * Extensions handle specific extension messages and can add
 * data to the extension handshake.
 */
class BtExtension {
public:
    virtual ~BtExtension() = default;
    
    /**
     * @brief Get the extension name (e.g., "ut_metadata")
     */
    virtual std::string name() const = 0;
    
    /**
     * @brief Called when the peer's extension handshake is received
     * 
     * @param handshake The peer's handshake dictionary
     */
    virtual void on_handshake(const BencodeDict& handshake) = 0;
    
    /**
     * @brief Handle an extension message from the peer
     * 
     * @param msg_id The local message ID (from our extension handshake)
     * @param payload The message payload (after extension ID byte)
     * @return true if message was handled
     */
    virtual bool on_message(uint8_t msg_id, const std::vector<uint8_t>& payload) = 0;
    
    /**
     * @brief Add data to our extension handshake
     * 
     * @param handshake The handshake dictionary to add to
     */
    virtual void add_handshake_data(BencodeDict& handshake) = 0;
    
    /**
     * @brief Get the message ID the peer uses for this extension
     */
    uint8_t peer_msg_id() const { return peer_msg_id_; }
    
    /**
     * @brief Set the message ID the peer uses
     */
    void set_peer_msg_id(uint8_t id) { peer_msg_id_ = id; }
    
    /**
     * @brief Check if peer supports this extension
     */
    bool peer_supports() const { return peer_msg_id_ != 0; }
    
protected:
    uint8_t peer_msg_id_ = 0;  ///< Message ID in peer's namespace (0 = not supported)
};

/**
 * @brief Manages extension protocol for a connection
 */
class ExtensionManager {
public:
    /**
     * @brief Create extension manager
     * @param conn The peer connection
     */
    explicit ExtensionManager(BtPeerConnection* conn);
    
    /**
     * @brief Register an extension
     * 
     * @param extension The extension to register
     * @param local_id Our local message ID for this extension
     */
    void register_extension(std::shared_ptr<BtExtension> extension, uint8_t local_id);
    
    /**
     * @brief Get extension by name
     */
    std::shared_ptr<BtExtension> get_extension(const std::string& name);
    
    /**
     * @brief Create the extension handshake message
     * @return Bencoded handshake dictionary
     */
    std::vector<uint8_t> create_handshake();
    
    /**
     * @brief Process received extension handshake
     * @param payload The handshake payload (bencoded dictionary)
     */
    void process_handshake(const std::vector<uint8_t>& payload);
    
    /**
     * @brief Handle an extended message
     * 
     * @param extension_id The extension message ID
     * @param payload The message payload
     * @return true if message was handled
     */
    bool handle_message(uint8_t extension_id, const std::vector<uint8_t>& payload);
    
    /**
     * @brief Send an extension message
     * 
     * @param extension_name Name of the extension
     * @param payload Message payload
     */
    void send_message(const std::string& extension_name, const std::vector<uint8_t>& payload);
    
    /**
     * @brief Get metadata size from handshake (for ut_metadata)
     */
    size_t metadata_size() const { return metadata_size_; }
    
private:
    BtPeerConnection* conn_;
    std::unordered_map<std::string, std::shared_ptr<BtExtension>> extensions_;
    std::unordered_map<uint8_t, std::shared_ptr<BtExtension>> local_id_map_;
    std::unordered_map<uint8_t, std::shared_ptr<BtExtension>> peer_id_map_;
    size_t metadata_size_ = 0;
};

//=============================================================================
// ut_metadata Extension (BEP 9)
//=============================================================================

/**
 * @brief Message types for ut_metadata
 */
enum class UtMetadataMessageType : uint8_t {
    Request = 0,
    Data = 1,
    Reject = 2
};

/**
 * @brief ut_metadata extension for exchanging torrent metadata
 * 
 * This allows downloading torrent metadata from peers when using magnet links.
 */
class UtMetadataExtension : public BtExtension {
public:
    /// Callback when complete metadata is received
    using MetadataCallback = std::function<void(const std::vector<uint8_t>& metadata)>;
    
    /**
     * @brief Create ut_metadata extension
     * 
     * @param metadata_size Expected metadata size (from magnet or handshake)
     * @param our_metadata Our metadata (if we have it, for seeding)
     */
    UtMetadataExtension(size_t metadata_size = 0, 
                        const std::vector<uint8_t>* our_metadata = nullptr);
    
    std::string name() const override { return "ut_metadata"; }
    
    void on_handshake(const BencodeDict& handshake) override;
    bool on_message(uint8_t msg_id, const std::vector<uint8_t>& payload) override;
    void add_handshake_data(BencodeDict& handshake) override;
    
    /**
     * @brief Set callback for when metadata is complete
     */
    void set_metadata_callback(MetadataCallback cb) { on_metadata_complete_ = std::move(cb); }
    
    /**
     * @brief Request a metadata piece from peer
     * @param piece Piece index (0-based)
     * @return Encoded request message
     */
    std::vector<uint8_t> create_request(uint32_t piece);
    
    /**
     * @brief Create a data response
     * @param piece Piece index
     * @param data Piece data
     * @return Encoded data message
     */
    std::vector<uint8_t> create_data(uint32_t piece, const std::vector<uint8_t>& data);
    
    /**
     * @brief Create a reject response
     * @param piece Piece index
     * @return Encoded reject message
     */
    std::vector<uint8_t> create_reject(uint32_t piece);
    
    /**
     * @brief Get number of metadata pieces
     */
    uint32_t num_pieces() const;
    
    /**
     * @brief Check if we have complete metadata
     */
    bool have_metadata() const { return metadata_complete_; }
    
    /**
     * @brief Get the assembled metadata
     */
    const std::vector<uint8_t>& get_metadata() const { return received_metadata_; }
    
    /**
     * @brief Get next piece to request
     * @return Piece index, or num_pieces() if all requested
     */
    uint32_t next_piece_to_request() const;
    
private:
    void handle_request(const BencodeDict& msg);
    void handle_data(const BencodeDict& msg, const std::vector<uint8_t>& payload);
    void handle_reject(const BencodeDict& msg);
    void check_complete();
    
    size_t metadata_size_;
    const std::vector<uint8_t>* our_metadata_;
    
    std::vector<uint8_t> received_metadata_;
    std::vector<bool> pieces_received_;
    std::vector<bool> pieces_requested_;
    bool metadata_complete_;
    
    MetadataCallback on_metadata_complete_;
};

//=============================================================================
// ut_pex Extension (Peer Exchange)
//=============================================================================

/**
 * @brief Peer address for PEX
 */
struct PexPeer {
    std::string ip;
    uint16_t port;
    bool supports_encryption;
    bool supports_utp;
    
    PexPeer() : port(0), supports_encryption(false), supports_utp(false) {}
    PexPeer(const std::string& i, uint16_t p) 
        : ip(i), port(p), supports_encryption(false), supports_utp(false) {}
};

/**
 * @brief ut_pex extension for peer exchange
 */
class UtPexExtension : public BtExtension {
public:
    /// Callback for received peers
    using PeersCallback = std::function<void(const std::vector<PexPeer>& added,
                                             const std::vector<PexPeer>& dropped)>;
    
    UtPexExtension();
    
    std::string name() const override { return "ut_pex"; }
    
    void on_handshake(const BencodeDict& handshake) override;
    bool on_message(uint8_t msg_id, const std::vector<uint8_t>& payload) override;
    void add_handshake_data(BencodeDict& handshake) override;
    
    /**
     * @brief Set callback for received peers
     */
    void set_peers_callback(PeersCallback cb) { on_peers_ = std::move(cb); }
    
    /**
     * @brief Create a PEX message
     * 
     * @param added Newly added peers
     * @param dropped Recently dropped peers
     * @return Encoded PEX message
     */
    std::vector<uint8_t> create_message(const std::vector<PexPeer>& added,
                                         const std::vector<PexPeer>& dropped);
    
private:
    std::vector<PexPeer> parse_peers(const std::string& compact_peers);
    
    PeersCallback on_peers_;
};

} // namespace librats
