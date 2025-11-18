    #pragma once

#include "bittorrent.h"
#include "socket.h"
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>

namespace librats {

// Forward declarations
class TrackerClient;
class HttpTrackerClient;
class UdpTrackerClient;

// Tracker announce event types (BEP 3)
enum class TrackerEvent {
    NONE = 0,
    COMPLETED = 1,
    STARTED = 2,
    STOPPED = 3
};

// Tracker response structure
struct TrackerResponse {
    std::string failure_reason;
    std::string warning_message;
    uint32_t interval;           // Seconds until next announce
    uint32_t min_interval;       // Minimum announce interval
    std::string tracker_id;      // Tracker ID for subsequent requests
    uint32_t complete;           // Number of seeders
    uint32_t incomplete;         // Number of leechers
    uint32_t downloaded;         // Number of times downloaded (scrape only)
    std::vector<Peer> peers;     // Peer list
    bool success;
    
    TrackerResponse() 
        : interval(1800), min_interval(900), complete(0), incomplete(0), 
          downloaded(0), success(false) {}
};

// Tracker announce request parameters
struct TrackerRequest {
    InfoHash info_hash;
    PeerID peer_id;
    uint16_t port;
    uint64_t uploaded;
    uint64_t downloaded;
    uint64_t left;
    TrackerEvent event;
    std::string ip;              // Optional IP address
    uint32_t numwant;            // Number of peers wanted (default 50)
    std::string tracker_id;      // Tracker ID from previous response
    
    TrackerRequest()
        : port(0), uploaded(0), downloaded(0), left(0), 
          event(TrackerEvent::NONE), numwant(50) {}
};

// Callback for tracker responses
using TrackerResponseCallback = std::function<void(const TrackerResponse& response, const std::string& tracker_url)>;

// Base tracker client interface
class TrackerClient {
public:
    virtual ~TrackerClient() = default;
    
    // Announce to tracker
    virtual bool announce(const TrackerRequest& request, TrackerResponseCallback callback) = 0;
    
    // Scrape tracker (optional, not all trackers support this)
    virtual bool scrape(const std::vector<InfoHash>& info_hashes, TrackerResponseCallback callback) = 0;
    
    // Get tracker URL
    virtual std::string get_url() const = 0;
    
    // Get last announce time
    virtual std::chrono::steady_clock::time_point get_last_announce_time() const = 0;
    
    // Get announce interval
    virtual uint32_t get_interval() const = 0;
    
    // Check if tracker is working
    virtual bool is_working() const = 0;
};

// HTTP/HTTPS Tracker Client (BEP 3)
class HttpTrackerClient : public TrackerClient {
public:
    explicit HttpTrackerClient(const std::string& tracker_url);
    ~HttpTrackerClient() override;
    
    bool announce(const TrackerRequest& request, TrackerResponseCallback callback) override;
    bool scrape(const std::vector<InfoHash>& info_hashes, TrackerResponseCallback callback) override;
    
    std::string get_url() const override { return tracker_url_; }
    std::chrono::steady_clock::time_point get_last_announce_time() const override { return last_announce_time_; }
    uint32_t get_interval() const override { return interval_; }
    bool is_working() const override { return is_working_; }
    
private:
    std::string tracker_url_;
    std::chrono::steady_clock::time_point last_announce_time_;
    uint32_t interval_;
    std::atomic<bool> is_working_;
    std::string tracker_id_;
    
    // Build announce URL with parameters
    std::string build_announce_url(const TrackerRequest& request);
    
    // Build scrape URL
    std::string build_scrape_url(const std::vector<InfoHash>& info_hashes);
    
    // Parse tracker response (bencode format)
    TrackerResponse parse_response(const std::vector<uint8_t>& data);
    
    // Parse compact peer list (BEP 23)
    std::vector<Peer> parse_compact_peers(const std::string& peer_data);
    
    // Parse dictionary peer list
    std::vector<Peer> parse_dict_peers(const BencodeValue& peers_list);
    
    // HTTP GET request
    std::vector<uint8_t> http_get(const std::string& url);
    
    // URL encode string
    std::string url_encode(const std::string& str);
    
    // URL encode binary data (for info_hash)
    std::string url_encode_binary(const uint8_t* data, size_t len);
};

// UDP Tracker Client (BEP 15)
class UdpTrackerClient : public TrackerClient {
public:
    explicit UdpTrackerClient(const std::string& tracker_url);
    ~UdpTrackerClient() override;
    
    bool announce(const TrackerRequest& request, TrackerResponseCallback callback) override;
    bool scrape(const std::vector<InfoHash>& info_hashes, TrackerResponseCallback callback) override;
    
    std::string get_url() const override { return tracker_url_; }
    std::chrono::steady_clock::time_point get_last_announce_time() const override { return last_announce_time_; }
    uint32_t get_interval() const override { return interval_; }
    bool is_working() const override { return is_working_; }
    
private:
    std::string tracker_url_;
    std::string hostname_;
    uint16_t port_;
    socket_t socket_;
    std::chrono::steady_clock::time_point last_announce_time_;
    std::chrono::steady_clock::time_point connection_expire_time_;
    uint32_t interval_;
    std::atomic<bool> is_working_;
    int64_t connection_id_;
    std::mutex socket_mutex_;
    
    // UDP tracker protocol constants
    static constexpr int64_t PROTOCOL_ID = 0x41727101980LL;
    static constexpr uint32_t ACTION_CONNECT = 0;
    static constexpr uint32_t ACTION_ANNOUNCE = 1;
    static constexpr uint32_t ACTION_SCRAPE = 2;
    static constexpr uint32_t ACTION_ERROR = 3;
    
    // Parse tracker URL
    bool parse_url();
    
    // Connect to UDP tracker (get connection ID)
    bool connect();
    
    // Check if connection is still valid
    bool is_connection_valid();
    
    // Send UDP request and receive response
    std::vector<uint8_t> send_request(const std::vector<uint8_t>& request, int timeout_ms = 15000);
    
    // Build connect request
    std::vector<uint8_t> build_connect_request(uint32_t transaction_id);
    
    // Build announce request
    std::vector<uint8_t> build_announce_request(const TrackerRequest& request, uint32_t transaction_id);
    
    // Build scrape request
    std::vector<uint8_t> build_scrape_request(const std::vector<InfoHash>& info_hashes, uint32_t transaction_id);
    
    // Parse connect response
    bool parse_connect_response(const std::vector<uint8_t>& data, uint32_t expected_transaction_id);
    
    // Parse announce response
    TrackerResponse parse_announce_response(const std::vector<uint8_t>& data, uint32_t expected_transaction_id);
    
    // Parse scrape response
    TrackerResponse parse_scrape_response(const std::vector<uint8_t>& data, uint32_t expected_transaction_id);
    
    // Parse error response
    std::string parse_error_response(const std::vector<uint8_t>& data);
    
    // Generate random transaction ID
    uint32_t generate_transaction_id();
    
    // Read 32-bit big-endian integer
    static uint32_t read_uint32_be(const uint8_t* data);
    
    // Write 32-bit big-endian integer
    static void write_uint32_be(uint8_t* data, uint32_t value);
    
    // Read 64-bit big-endian integer
    static int64_t read_int64_be(const uint8_t* data);
    
    // Write 64-bit big-endian integer
    static void write_int64_be(uint8_t* data, int64_t value);
};

// Tracker Manager - manages multiple trackers for a torrent
class TrackerManager {
public:
    explicit TrackerManager(const TorrentInfo& torrent_info);
    ~TrackerManager();
    
    // Add tracker from URL
    bool add_tracker(const std::string& tracker_url);
    
    // Announce to all trackers
    void announce(const TrackerRequest& request, TrackerResponseCallback callback);
    
    // Announce to best tracker only
    void announce_to_best(const TrackerRequest& request, TrackerResponseCallback callback);
    
    // Scrape all trackers
    void scrape(TrackerResponseCallback callback);
    
    // Get number of working trackers
    size_t get_working_tracker_count() const;
    
    // Get all tracker URLs
    std::vector<std::string> get_tracker_urls() const;
    
    // Check if it's time to announce
    bool should_announce() const;
    
    // Get next announce time
    std::chrono::steady_clock::time_point get_next_announce_time() const;
    
private:
    std::vector<std::shared_ptr<TrackerClient>> trackers_;
    mutable std::mutex trackers_mutex_;
    InfoHash info_hash_;
    std::chrono::steady_clock::time_point last_announce_time_;
    uint32_t announce_interval_;
    
    // Create tracker client based on URL scheme
    std::shared_ptr<TrackerClient> create_tracker_client(const std::string& tracker_url);
    
    // Sort trackers by priority (working trackers first)
    void sort_trackers_by_priority();
};

// Utility functions
std::string tracker_event_to_string(TrackerEvent event);
TrackerEvent string_to_tracker_event(const std::string& event_str);

} // namespace librats

