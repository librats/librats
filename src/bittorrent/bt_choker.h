#pragma once

/**
 * @file bt_choker.h
 * @brief BitTorrent choking algorithm
 * 
 * Implements the tit-for-tat choking algorithm for fair bandwidth distribution.
 * Includes optimistic unchoking for discovering faster peers.
 */

#include <vector>
#include <chrono>
#include <cstdint>
#include <functional>

namespace librats {

// Forward declaration
class BtPeerConnection;

/**
 * @brief Configuration for the choking algorithm
 */
struct ChokerConfig {
    size_t max_uploads;                      ///< Maximum unchoked peers (default: 4)
    std::chrono::seconds rechoke_interval;   ///< How often to re-evaluate (default: 10s)
    std::chrono::seconds optimistic_interval;///< Optimistic unchoke rotation (default: 30s)
    bool seed_mode;                          ///< Use seed choking algorithm
    
    ChokerConfig()
        : max_uploads(4)
        , rechoke_interval(10)
        , optimistic_interval(30)
        , seed_mode(false) {}
};

/**
 * @brief Peer info for choking decisions
 */
struct ChokePeerInfo {
    BtPeerConnection* connection;
    double download_rate;       ///< Bytes/sec we're downloading from peer
    double upload_rate;         ///< Bytes/sec we're uploading to peer
    bool am_choking;           ///< Are we choking this peer?
    bool am_interested;        ///< Are we interested in this peer?
    bool peer_interested;      ///< Is peer interested in us?
    bool is_optimistic;        ///< Is this the optimistic unchoke slot?
    bool is_snubbed;           ///< Has peer not sent data recently?
    
    std::chrono::steady_clock::time_point last_unchoke;
    std::chrono::steady_clock::time_point connected_at;
    
    ChokePeerInfo() 
        : connection(nullptr)
        , download_rate(0), upload_rate(0)
        , am_choking(true), am_interested(false), peer_interested(false)
        , is_optimistic(false), is_snubbed(false) {}
};

/**
 * @brief Result of a choking decision
 */
struct ChokeResult {
    std::vector<BtPeerConnection*> to_choke;    ///< Peers to choke
    std::vector<BtPeerConnection*> to_unchoke;  ///< Peers to unchoke
};

/**
 * @brief Manages choking decisions for BitTorrent peers
 * 
 * The choking algorithm ensures fair bandwidth distribution:
 * - Unchoke top N peers based on download rate (reciprocation)
 * - One optimistic unchoke slot rotates to discover new fast peers
 * - Special handling for seed mode (upload-only)
 * 
 * Thread-safe: Call run_choker() from a single thread.
 */
class Choker {
public:
    /**
     * @brief Create a choker with default config
     */
    Choker();
    
    /**
     * @brief Create a choker with custom config
     */
    explicit Choker(const ChokerConfig& config);
    
    /**
     * @brief Set configuration
     */
    void set_config(const ChokerConfig& config);
    
    /**
     * @brief Get current configuration
     */
    const ChokerConfig& config() const { return config_; }
    
    /**
     * @brief Set whether we're in seed mode
     */
    void set_seed_mode(bool seed) { config_.seed_mode = seed; }
    
    /**
     * @brief Run the choking algorithm
     * 
     * @param peers Current peer information
     * @return Choking decisions
     */
    ChokeResult run(std::vector<ChokePeerInfo>& peers);
    
    /**
     * @brief Check if it's time to rechoke
     */
    bool should_rechoke() const;
    
    /**
     * @brief Get the optimistically unchoked peer
     */
    BtPeerConnection* optimistic_peer() const { return optimistic_peer_; }
    
private:
    /**
     * @brief Run download mode choking (we're leeching)
     */
    ChokeResult run_download_mode(std::vector<ChokePeerInfo>& peers);
    
    /**
     * @brief Run seed mode choking (we're seeding)
     */
    ChokeResult run_seed_mode(std::vector<ChokePeerInfo>& peers);
    
    /**
     * @brief Select new optimistic unchoke peer
     */
    void rotate_optimistic(std::vector<ChokePeerInfo>& peers);
    
    ChokerConfig config_;
    BtPeerConnection* optimistic_peer_;
    
    std::chrono::steady_clock::time_point last_rechoke_;
    std::chrono::steady_clock::time_point last_optimistic_rotation_;
    size_t optimistic_rotation_index_;
};

} // namespace librats
