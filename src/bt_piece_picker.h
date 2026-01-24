#pragma once

/**
 * @file bt_piece_picker.h
 * @brief Intelligent piece selection for BitTorrent downloads
 * 
 * Implements various piece picking strategies:
 * - Rarest-first: Download pieces that are least available in the swarm
 * - Sequential: Download pieces in order (for streaming)
 * - Random: Random selection for initial bootstrapping
 * - Endgame: Request same blocks from multiple peers at end of download
 */

#include "bt_types.h"
#include "bt_bitfield.h"

#include <vector>
#include <set>
#include <unordered_set>
#include <mutex>
#include <optional>
#include <functional>

namespace librats {

/**
 * @brief Priority level for pieces (0-7)
 */
enum class PiecePriority : uint8_t {
    Skip = 0,       ///< Don't download this piece
    Lowest = 1,
    Low = 2,
    BelowNormal = 3,
    Normal = 4,     ///< Default priority
    AboveNormal = 5,
    High = 6,
    Highest = 7
};

/**
 * @brief State of a block within a piece
 */
enum class BlockState : uint8_t {
    None = 0,       ///< Not requested
    Requested = 1,  ///< Request sent to peer
    Writing = 2,    ///< Data received, being written to disk
    Finished = 3    ///< Written to disk
};

/**
 * @brief Information about a block request
 */
struct BlockRequest {
    BlockInfo block;
    void* peer;             ///< Opaque peer pointer (for tracking who requested)
    
    BlockRequest() : peer(nullptr) {}
    BlockRequest(const BlockInfo& b, void* p = nullptr) : block(b), peer(p) {}
    
    bool operator==(const BlockRequest& other) const {
        return block == other.block;
    }
};

/**
 * @brief Piece selection mode
 */
enum class PickerMode : uint8_t {
    RarestFirst,    ///< Pick rarest pieces first (default)
    Sequential,     ///< Pick pieces in order
    Random          ///< Pick random pieces
};

/**
 * @brief Statistics about a piece being downloaded
 */
struct DownloadingPiece {
    uint32_t piece_index;
    uint16_t blocks_total;
    uint16_t blocks_requested;
    uint16_t blocks_writing;
    uint16_t blocks_finished;
    
    DownloadingPiece() 
        : piece_index(0), blocks_total(0), blocks_requested(0)
        , blocks_writing(0), blocks_finished(0) {}
    
    explicit DownloadingPiece(uint32_t idx, uint16_t total)
        : piece_index(idx), blocks_total(total), blocks_requested(0)
        , blocks_writing(0), blocks_finished(0) {}
    
    bool is_complete() const { return blocks_finished == blocks_total; }
    bool is_empty() const { return blocks_requested == 0 && blocks_finished == 0; }
};

/**
 * @brief Intelligent piece picker for BitTorrent downloads
 * 
 * This class manages:
 * - Which pieces to request next based on availability and priority
 * - Tracking of in-progress pieces and their blocks
 * - Peer piece availability
 * - Endgame mode for finishing downloads
 * 
 * Thread-safe: All public methods are protected by a mutex.
 */
class PiecePicker {
public:
    /**
     * @brief Create a piece picker
     * @param num_pieces Total number of pieces in the torrent
     * @param piece_length Length of each piece in bytes
     * @param last_piece_length Length of the last piece (may be smaller)
     */
    PiecePicker(uint32_t num_pieces, uint32_t piece_length, uint32_t last_piece_length);
    
    /**
     * @brief Destructor
     */
    ~PiecePicker();
    
    // Non-copyable
    PiecePicker(const PiecePicker&) = delete;
    PiecePicker& operator=(const PiecePicker&) = delete;
    
    // Movable
    PiecePicker(PiecePicker&&) noexcept;
    PiecePicker& operator=(PiecePicker&&) noexcept;
    
    //=========================================================================
    // Configuration
    //=========================================================================
    
    /**
     * @brief Set the picking mode
     */
    void set_mode(PickerMode mode);
    
    /**
     * @brief Get the current picking mode
     */
    PickerMode mode() const;
    
    /**
     * @brief Set priority for a specific piece
     */
    void set_piece_priority(uint32_t piece, PiecePriority priority);
    
    /**
     * @brief Get priority for a specific piece
     */
    PiecePriority piece_priority(uint32_t piece) const;
    
    /**
     * @brief Set priority for a range of pieces
     */
    void set_piece_priority_range(uint32_t start, uint32_t end, PiecePriority priority);
    
    //=========================================================================
    // Piece State Management
    //=========================================================================
    
    /**
     * @brief Mark a piece as having been downloaded and verified
     * @param piece Piece index
     */
    void mark_have(uint32_t piece);
    
    /**
     * @brief Check if we have a piece
     * @param piece Piece index
     */
    bool have_piece(uint32_t piece) const;
    
    /**
     * @brief Get bitfield of pieces we have
     */
    Bitfield get_have_bitfield() const;
    
    /**
     * @brief Set the initial have bitfield (for resume)
     */
    void set_have_bitfield(const Bitfield& have);
    
    /**
     * @brief Get number of pieces we have
     */
    uint32_t num_have() const;
    
    /**
     * @brief Get number of pieces we still need
     */
    uint32_t num_want() const;
    
    /**
     * @brief Check if download is complete
     */
    bool is_complete() const;
    
    //=========================================================================
    // Peer Availability
    //=========================================================================
    
    /**
     * @brief Add a peer's piece availability
     * @param peer_id Unique identifier for the peer
     * @param bitfield Peer's have bitfield
     */
    void add_peer(void* peer_id, const Bitfield& bitfield);
    
    /**
     * @brief Remove a peer's contribution to availability
     * @param peer_id Peer to remove
     */
    void remove_peer(void* peer_id);
    
    /**
     * @brief Update a peer's availability (received HAVE message)
     * @param peer_id Peer identifier
     * @param piece Piece the peer now has
     */
    void peer_has_piece(void* peer_id, uint32_t piece);
    
    /**
     * @brief Get availability count for a piece
     * @param piece Piece index
     * @return Number of peers that have this piece
     */
    uint32_t availability(uint32_t piece) const;
    
    //=========================================================================
    // Piece Picking
    //=========================================================================
    
    /**
     * @brief Pick pieces to request from a peer
     * 
     * @param peer_bitfield Pieces the peer has
     * @param num_blocks Maximum number of blocks to return
     * @param peer_id Peer identifier (for tracking)
     * @return List of blocks to request
     */
    std::vector<BlockRequest> pick_pieces(
        const Bitfield& peer_bitfield,
        size_t num_blocks,
        void* peer_id);
    
    /**
     * @brief Pick a single piece to request
     * 
     * @param peer_bitfield Pieces the peer has
     * @return Piece index, or nullopt if no suitable piece
     */
    std::optional<uint32_t> pick_piece(const Bitfield& peer_bitfield);
    
    /**
     * @brief Check if a peer has pieces we're interested in
     */
    bool is_interesting(const Bitfield& peer_bitfield) const;
    
    //=========================================================================
    // Block Management
    //=========================================================================
    
    /**
     * @brief Mark a block as requested
     * @param block Block info
     * @param peer_id Peer the block was requested from
     */
    void mark_requested(const BlockInfo& block, void* peer_id);
    
    /**
     * @brief Mark a block as being written to disk
     * @param block Block info
     */
    void mark_writing(const BlockInfo& block);
    
    /**
     * @brief Mark a block as finished (written to disk)
     * @param block Block info
     * @return true if this completes the piece
     */
    bool mark_finished(const BlockInfo& block);
    
    /**
     * @brief Cancel a block request
     * @param block Block info
     * @param peer_id Peer the request was sent to
     */
    void cancel_request(const BlockInfo& block, void* peer_id);
    
    /**
     * @brief Cancel all requests to a peer
     * @param peer_id Peer identifier
     */
    void cancel_peer_requests(void* peer_id);
    
    /**
     * @brief Get state of a specific block
     */
    BlockState block_state(const BlockInfo& block) const;
    
    //=========================================================================
    // Endgame Mode
    //=========================================================================
    
    /**
     * @brief Check if we're in endgame mode
     * 
     * Endgame mode is activated when we have most pieces and only a few
     * blocks remaining. In this mode, we may request the same block from
     * multiple peers.
     */
    bool in_endgame_mode() const;
    
    /**
     * @brief Enable/disable endgame mode
     */
    void set_endgame_mode(bool enable);
    
    //=========================================================================
    // Statistics
    //=========================================================================
    
    /**
     * @brief Get number of pieces currently being downloaded
     */
    size_t num_downloading() const;
    
    /**
     * @brief Get list of pieces currently being downloaded
     */
    std::vector<DownloadingPiece> downloading_pieces() const;
    
    /**
     * @brief Get information about a specific downloading piece
     */
    std::optional<DownloadingPiece> get_downloading_piece(uint32_t piece) const;
    
    //=========================================================================
    // Utility
    //=========================================================================
    
    /**
     * @brief Get number of blocks in a piece
     */
    uint32_t blocks_in_piece(uint32_t piece) const;
    
    /**
     * @brief Get size of a specific block
     */
    uint32_t block_size(uint32_t piece, uint32_t block_index) const;
    
    /**
     * @brief Get total number of pieces
     */
    uint32_t num_pieces() const { return num_pieces_; }
    
    /**
     * @brief Get piece length
     */
    uint32_t piece_length() const { return piece_length_; }
    
private:
    //=========================================================================
    // Internal Types
    //=========================================================================
    
    struct PieceState {
        uint32_t availability;      // How many peers have this piece
        PiecePriority priority;
        bool have;                  // We have this piece
        bool downloading;           // Currently downloading
        
        PieceState() 
            : availability(0), priority(PiecePriority::Normal)
            , have(false), downloading(false) {}
    };
    
    struct BlockInfo_Internal {
        BlockState state;
        void* peer;                 // Who we requested from
        
        BlockInfo_Internal() : state(BlockState::None), peer(nullptr) {}
    };
    
    struct DownloadingPieceState {
        uint32_t piece_index;
        std::vector<BlockInfo_Internal> blocks;
        
        explicit DownloadingPieceState(uint32_t idx, size_t num_blocks)
            : piece_index(idx), blocks(num_blocks) {}
    };
    
    //=========================================================================
    // Internal Methods
    //=========================================================================
    
    uint32_t pick_rarest(const Bitfield& peer_bitfield) const;
    uint32_t pick_sequential(const Bitfield& peer_bitfield) const;
    uint32_t pick_random(const Bitfield& peer_bitfield) const;
    
    DownloadingPieceState* get_or_create_downloading(uint32_t piece);
    DownloadingPieceState* find_downloading(uint32_t piece);
    const DownloadingPieceState* find_downloading(uint32_t piece) const;
    void remove_downloading(uint32_t piece);
    
    void check_endgame();
    
    //=========================================================================
    // Data
    //=========================================================================
    
    mutable std::mutex mutex_;
    
    uint32_t num_pieces_;
    uint32_t piece_length_;
    uint32_t last_piece_length_;
    
    PickerMode mode_;
    bool endgame_enabled_;
    bool in_endgame_;
    
    std::vector<PieceState> pieces_;
    std::vector<DownloadingPieceState> downloading_;
    
    // Track which pieces each peer has (for accurate availability on disconnect)
    std::unordered_map<void*, Bitfield> peer_pieces_;
    
    // Cached counts
    uint32_t num_have_;
    uint32_t num_downloading_;
    
    // Sequential mode cursor
    uint32_t sequential_cursor_;
};

} // namespace librats
