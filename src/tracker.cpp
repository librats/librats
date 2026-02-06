#include "tracker.h"
#include "bencode.h"
#include "logger.h"
#include <sstream>
#include <iomanip>
#include <random>
#include <algorithm>
#include <cstring>
#include <thread>
#include <atomic>

#define LOG_TRACKER_DEBUG(message) LOG_DEBUG("tracker", message)
#define LOG_TRACKER_INFO(message)  LOG_INFO("tracker", message)
#define LOG_TRACKER_WARN(message)  LOG_WARN("tracker", message)
#define LOG_TRACKER_ERROR(message) LOG_ERROR("tracker", message)

namespace librats {

//=============================================================================
// Utility Functions
//=============================================================================

std::string tracker_event_to_string(TrackerEvent event) {
    switch (event) {
        case TrackerEvent::STARTED: return "started";
        case TrackerEvent::STOPPED: return "stopped";
        case TrackerEvent::COMPLETED: return "completed";
        case TrackerEvent::NONE:
        default: return "";
    }
}

TrackerEvent string_to_tracker_event(const std::string& event_str) {
    if (event_str == "started") return TrackerEvent::STARTED;
    if (event_str == "stopped") return TrackerEvent::STOPPED;
    if (event_str == "completed") return TrackerEvent::COMPLETED;
    return TrackerEvent::NONE;
}

//=============================================================================
// HttpTrackerClient Implementation
//=============================================================================

HttpTrackerClient::HttpTrackerClient(const std::string& tracker_url)
    : tracker_url_(tracker_url), interval_(1800), is_working_(true) {
    LOG_TRACKER_INFO("Created HTTP tracker client for: " << tracker_url_);
}

HttpTrackerClient::~HttpTrackerClient() = default;

bool HttpTrackerClient::announce(const TrackerRequest& request, TrackerResponseCallback callback) {
    LOG_TRACKER_INFO("Announcing to HTTP tracker: " << tracker_url_);
    
    std::string announce_url = build_announce_url(request);
    
    try {
        std::vector<uint8_t> response_data = http_get(announce_url);
        
        if (response_data.empty()) {
            LOG_TRACKER_ERROR("Empty response from tracker: " << tracker_url_);
            is_working_ = false;
            
            TrackerResponse error_response;
            error_response.success = false;
            error_response.failure_reason = "Empty response from tracker";
            if (callback) callback(error_response, tracker_url_);
            return false;
        }
        
        TrackerResponse response = parse_response(response_data);
        
        if (response.success) {
            last_announce_time_ = std::chrono::steady_clock::now();
            interval_ = response.interval;
            if (!response.tracker_id.empty()) {
                tracker_id_ = response.tracker_id;
            }
            is_working_ = true;
            
            LOG_TRACKER_INFO("Announce successful. Peers: " << response.peers.size() 
                           << ", Seeders: " << response.complete 
                           << ", Leechers: " << response.incomplete);
        } else {
            LOG_TRACKER_ERROR("Tracker announce failed: " << response.failure_reason);
            is_working_ = false;
        }
        
        if (callback) {
            callback(response, tracker_url_);
        }
        
        return response.success;
        
    } catch (const std::exception& e) {
        LOG_TRACKER_ERROR("Exception during announce: " << e.what());
        is_working_ = false;
        
        TrackerResponse error_response;
        error_response.success = false;
        error_response.failure_reason = std::string("Exception: ") + e.what();
        if (callback) callback(error_response, tracker_url_);
        
        return false;
    }
}

bool HttpTrackerClient::scrape(const std::vector<InfoHash>& info_hashes, TrackerResponseCallback callback) {
    LOG_TRACKER_INFO("Scraping HTTP tracker: " << tracker_url_);
    
    std::string scrape_url = build_scrape_url(info_hashes);
    if (scrape_url.empty()) {
        LOG_TRACKER_WARN("Cannot build scrape URL for tracker: " << tracker_url_);
        return false;
    }
    
    try {
        std::vector<uint8_t> response_data = http_get(scrape_url);
        
        if (response_data.empty()) {
            LOG_TRACKER_ERROR("Empty scrape response from tracker: " << tracker_url_);
            return false;
        }
        
        TrackerResponse response = parse_response(response_data);
        
        if (callback) {
            callback(response, tracker_url_);
        }
        
        return response.success;
        
    } catch (const std::exception& e) {
        LOG_TRACKER_ERROR("Exception during scrape: " << e.what());
        return false;
    }
}

std::string HttpTrackerClient::build_announce_url(const TrackerRequest& request) {
    std::ostringstream url;
    url << tracker_url_;
    
    // Add query separator
    if (tracker_url_.find('?') == std::string::npos) {
        url << "?";
    } else {
        url << "&";
    }
    
    // Required parameters
    url << "info_hash=" << url_encode_binary(request.info_hash.data(), request.info_hash.size());
    url << "&peer_id=" << url_encode_binary(request.peer_id.data(), request.peer_id.size());
    url << "&port=" << request.port;
    url << "&uploaded=" << request.uploaded;
    url << "&downloaded=" << request.downloaded;
    url << "&left=" << request.left;
    url << "&compact=1";  // Request compact peer list (BEP 23)
    
    // Optional parameters
    if (request.event != TrackerEvent::NONE) {
        url << "&event=" << tracker_event_to_string(request.event);
    }
    
    if (!request.ip.empty()) {
        url << "&ip=" << url_encode(request.ip);
    }
    
    if (request.numwant > 0) {
        url << "&numwant=" << request.numwant;
    }
    
    if (!request.tracker_id.empty()) {
        url << "&trackerid=" << url_encode(request.tracker_id);
    } else if (!tracker_id_.empty()) {
        url << "&trackerid=" << url_encode(tracker_id_);
    }
    
    return url.str();
}

std::string HttpTrackerClient::build_scrape_url(const std::vector<InfoHash>& info_hashes) {
    // Convert announce URL to scrape URL by replacing "announce" with "scrape"
    std::string scrape_url = tracker_url_;
    
    size_t announce_pos = scrape_url.find("announce");
    if (announce_pos == std::string::npos) {
        return "";  // Cannot build scrape URL
    }
    
    scrape_url.replace(announce_pos, 8, "scrape");
    
    // Add info_hash parameters
    bool first = true;
    for (const auto& info_hash : info_hashes) {
        if (first) {
            scrape_url += "?";
            first = false;
        } else {
            scrape_url += "&";
        }
        scrape_url += "info_hash=" + url_encode_binary(info_hash.data(), info_hash.size());
    }
    
    return scrape_url;
}

TrackerResponse HttpTrackerClient::parse_response(const std::vector<uint8_t>& data) {
    TrackerResponse response;
    
    try {
        BencodeValue tracker_response = bencode::decode(data);
        
        if (!tracker_response.is_dict()) {
            response.failure_reason = "Invalid tracker response format";
            return response;
        }
        
        // Check for failure reason
        if (tracker_response.has_key("failure reason")) {
            response.failure_reason = tracker_response["failure reason"].as_string();
            response.success = false;
            return response;
        }
        
        // Parse warning message
        if (tracker_response.has_key("warning message")) {
            response.warning_message = tracker_response["warning message"].as_string();
            LOG_TRACKER_WARN("Tracker warning: " << response.warning_message);
        }
        
        // Parse interval
        if (tracker_response.has_key("interval")) {
            response.interval = static_cast<uint32_t>(tracker_response["interval"].as_integer());
        }
        
        // Parse min interval
        if (tracker_response.has_key("min interval")) {
            response.min_interval = static_cast<uint32_t>(tracker_response["min interval"].as_integer());
        }
        
        // Parse tracker ID
        if (tracker_response.has_key("tracker id")) {
            response.tracker_id = tracker_response["tracker id"].as_string();
        }
        
        // Parse complete (seeders)
        if (tracker_response.has_key("complete")) {
            response.complete = static_cast<uint32_t>(tracker_response["complete"].as_integer());
        }
        
        // Parse incomplete (leechers)
        if (tracker_response.has_key("incomplete")) {
            response.incomplete = static_cast<uint32_t>(tracker_response["incomplete"].as_integer());
        }
        
        // Parse peers
        if (tracker_response.has_key("peers")) {
            const auto& peers_value = tracker_response["peers"];
            
            if (peers_value.is_string()) {
                // Compact peer list (BEP 23)
                response.peers = parse_compact_peers(peers_value.as_string());
            } else if (peers_value.is_list()) {
                // Dictionary peer list
                response.peers = parse_dict_peers(peers_value);
            }
        }
        
        response.success = true;
        
    } catch (const std::exception& e) {
        LOG_TRACKER_ERROR("Failed to parse tracker response: " << e.what());
        response.failure_reason = std::string("Parse error: ") + e.what();
        response.success = false;
    }
    
    return response;
}

std::vector<Peer> HttpTrackerClient::parse_compact_peers(const std::string& peer_data) {
    std::vector<Peer> peers;
    
    // Each peer is 6 bytes: 4 bytes IP + 2 bytes port
    if (peer_data.length() % 6 != 0) {
        LOG_TRACKER_WARN("Invalid compact peer list length: " << peer_data.length());
        return peers;
    }
    
    for (size_t i = 0; i < peer_data.length(); i += 6) {
        const uint8_t* peer_bytes = reinterpret_cast<const uint8_t*>(peer_data.data() + i);
        
        // Extract IP address
        std::ostringstream ip_stream;
        ip_stream << static_cast<int>(peer_bytes[0]) << "."
                  << static_cast<int>(peer_bytes[1]) << "."
                  << static_cast<int>(peer_bytes[2]) << "."
                  << static_cast<int>(peer_bytes[3]);
        
        // Extract port (big-endian)
        uint16_t port = (peer_bytes[4] << 8) | peer_bytes[5];
        
        peers.emplace_back(ip_stream.str(), port);
    }
    
    LOG_TRACKER_DEBUG("Parsed " << peers.size() << " compact peers");
    return peers;
}

std::vector<Peer> HttpTrackerClient::parse_dict_peers(const BencodeValue& peers_list) {
    std::vector<Peer> peers;
    
    for (size_t i = 0; i < peers_list.size(); ++i) {
        const auto& peer_dict = peers_list[i];
        
        if (!peer_dict.is_dict()) {
            continue;
        }
        
        if (!peer_dict.has_key("ip") || !peer_dict.has_key("port")) {
            continue;
        }
        
        std::string ip = peer_dict["ip"].as_string();
        uint16_t port = static_cast<uint16_t>(peer_dict["port"].as_integer());
        
        peers.emplace_back(ip, port);
    }
    
    LOG_TRACKER_DEBUG("Parsed " << peers.size() << " dictionary peers");
    return peers;
}

std::vector<uint8_t> HttpTrackerClient::http_get(const std::string& url) {
    LOG_TRACKER_DEBUG("HTTP GET: " << url);
    
    // Parse URL to extract host, port, and path
    std::string protocol, host, path;
    uint16_t port = 80;
    
    size_t protocol_end = url.find("://");
    if (protocol_end != std::string::npos) {
        protocol = url.substr(0, protocol_end);
        size_t host_start = protocol_end + 3;
        size_t path_start = url.find('/', host_start);
        
        if (path_start != std::string::npos) {
            std::string host_port = url.substr(host_start, path_start - host_start);
            path = url.substr(path_start);
            
            size_t port_pos = host_port.find(':');
            if (port_pos != std::string::npos) {
                host = host_port.substr(0, port_pos);
                port = static_cast<uint16_t>(std::stoi(host_port.substr(port_pos + 1)));
            } else {
                host = host_port;
                port = (protocol == "https") ? 443 : 80;
            }
        } else {
            host = url.substr(host_start);
            path = "/";
        }
    } else {
        LOG_TRACKER_ERROR("Invalid URL format: " << url);
        return std::vector<uint8_t>();
    }
    
    // Create TCP connection
    socket_t socket = create_tcp_client(host, port, 15000);  // 15 second timeout
    if (!is_valid_socket(socket)) {
        LOG_TRACKER_ERROR("Failed to connect to tracker: " << host << ":" << port);
        return std::vector<uint8_t>();
    }
    
    // Build HTTP request
    std::ostringstream request;
    request << "GET " << path << " HTTP/1.0\r\n";
    request << "Host: " << host << "\r\n";
    request << "User-Agent: librats/1.0\r\n";
    request << "Accept: */*\r\n";
    request << "Connection: close\r\n";
    request << "\r\n";
    
    std::string request_str = request.str();
    
    // Send request
    if (send_tcp_string(socket, request_str) <= 0) {
        LOG_TRACKER_ERROR("Failed to send HTTP request");
        close_socket(socket);
        return std::vector<uint8_t>();
    }
    
    // Receive response
    std::vector<uint8_t> response_data;
    bool headers_complete = false;
    size_t content_start = 0;
    
    while (true) {
        std::vector<uint8_t> chunk = receive_tcp_data(socket, 4096);
        if (chunk.empty()) {
            break;  // Connection closed or error
        }
        
        response_data.insert(response_data.end(), chunk.begin(), chunk.end());
        
        // Find end of headers
        if (!headers_complete) {
            std::string response_str(response_data.begin(), response_data.end());
            size_t header_end = response_str.find("\r\n\r\n");
            if (header_end != std::string::npos) {
                headers_complete = true;
                content_start = header_end + 4;
            }
        }
    }
    
    close_socket(socket);
    
    if (!headers_complete || content_start >= response_data.size()) {
        LOG_TRACKER_ERROR("Invalid HTTP response");
        return std::vector<uint8_t>();
    }
    
    // Extract body
    std::vector<uint8_t> body(response_data.begin() + content_start, response_data.end());
    
    LOG_TRACKER_DEBUG("HTTP response body size: " << body.size() << " bytes");
    return body;
}

std::string HttpTrackerClient::url_encode(const std::string& str) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;
    
    for (char c : str) {
        // Keep alphanumeric and other safe characters
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
        } else {
            // Percent-encode
            escaped << '%' << std::setw(2) << int(static_cast<unsigned char>(c));
        }
    }
    
    return escaped.str();
}

std::string HttpTrackerClient::url_encode_binary(const uint8_t* data, size_t len) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex << std::uppercase;
    
    for (size_t i = 0; i < len; ++i) {
        uint8_t c = data[i];
        // Keep alphanumeric and other safe characters
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << static_cast<char>(c);
        } else {
            // Percent-encode
            escaped << '%' << std::setw(2) << static_cast<int>(c);
        }
    }
    
    return escaped.str();
}

//=============================================================================
// UdpTrackerClient Implementation
//=============================================================================

UdpTrackerClient::UdpTrackerClient(const std::string& tracker_url)
    : tracker_url_(tracker_url), port_(0), socket_(INVALID_SOCKET_VALUE),
      interval_(1800), is_working_(true), connection_id_(0) {
    
    if (parse_url()) {
        LOG_TRACKER_INFO("Created UDP tracker client for: " << hostname_ << ":" << port_);
    } else {
        LOG_TRACKER_ERROR("Failed to parse UDP tracker URL: " << tracker_url_);
        is_working_ = false;
    }
}

UdpTrackerClient::~UdpTrackerClient() {
    std::lock_guard<std::mutex> lock(socket_mutex_);
    if (is_valid_socket(socket_)) {
        close_socket(socket_);
        socket_ = INVALID_SOCKET_VALUE;
    }
}

bool UdpTrackerClient::parse_url() {
    // Parse udp://hostname:port
    if (tracker_url_.substr(0, 6) != "udp://") {
        return false;
    }
    
    std::string host_port = tracker_url_.substr(6);
    size_t colon_pos = host_port.find(':');
    
    if (colon_pos == std::string::npos) {
        return false;
    }
    
    hostname_ = host_port.substr(0, colon_pos);
    
    // Extract port and remove any path
    std::string port_str = host_port.substr(colon_pos + 1);
    size_t slash_pos = port_str.find('/');
    if (slash_pos != std::string::npos) {
        port_str = port_str.substr(0, slash_pos);
    }
    
    try {
        port_ = static_cast<uint16_t>(std::stoi(port_str));
    } catch (const std::exception&) {
        return false;
    }
    
    return true;
}

bool UdpTrackerClient::connect() {
    // Create UDP socket if needed (protected by mutex)
    {
        std::lock_guard<std::mutex> lock(socket_mutex_);
        if (!is_valid_socket(socket_)) {
            socket_ = create_udp_socket();
            if (!is_valid_socket(socket_)) {
                LOG_TRACKER_ERROR("Failed to create UDP socket for tracker");
                return false;
            }
        }
    }
    
    LOG_TRACKER_DEBUG("Connecting to UDP tracker: " << hostname_ << ":" << port_);
    
    uint32_t transaction_id = generate_transaction_id();
    std::vector<uint8_t> connect_request = build_connect_request(transaction_id);
    
    // Send connect request and receive response (send_request handles its own locking)
    std::vector<uint8_t> response = send_request(connect_request, 15000);
    
    if (response.empty()) {
        LOG_TRACKER_ERROR("No response from UDP tracker");
        return false;
    }
    
    if (!parse_connect_response(response, transaction_id)) {
        LOG_TRACKER_ERROR("Failed to parse connect response");
        return false;
    }
    
    // Connection is valid for 1 minute
    connection_expire_time_ = std::chrono::steady_clock::now() + std::chrono::seconds(60);
    
    LOG_TRACKER_INFO("Successfully connected to UDP tracker");
    return true;
}

bool UdpTrackerClient::is_connection_valid() {
    return connection_id_ != 0 && 
           std::chrono::steady_clock::now() < connection_expire_time_;
}

bool UdpTrackerClient::announce(const TrackerRequest& request, TrackerResponseCallback callback) {
    LOG_TRACKER_INFO("Announcing to UDP tracker: " << tracker_url_);
    
    // Connect if needed
    if (!is_connection_valid()) {
        if (!connect()) {
            is_working_ = false;
            
            TrackerResponse error_response;
            error_response.success = false;
            error_response.failure_reason = "Failed to connect to UDP tracker";
            if (callback) callback(error_response, tracker_url_);
            
            return false;
        }
    }
    
    uint32_t transaction_id = generate_transaction_id();
    std::vector<uint8_t> announce_request = build_announce_request(request, transaction_id);
    
    // Send announce request
    std::vector<uint8_t> response = send_request(announce_request, 15000);
    
    if (response.empty()) {
        LOG_TRACKER_ERROR("No response from UDP tracker announce");
        is_working_ = false;
        
        TrackerResponse error_response;
        error_response.success = false;
        error_response.failure_reason = "No response from tracker";
        if (callback) callback(error_response, tracker_url_);
        
        return false;
    }
    
    // Check for error response
    if (response.size() >= 8) {
        uint32_t action = read_uint32_be(response.data());
        if (action == ACTION_ERROR) {
            std::string error_msg = parse_error_response(response);
            LOG_TRACKER_ERROR("UDP tracker error: " << error_msg);
            is_working_ = false;
            
            TrackerResponse error_response;
            error_response.success = false;
            error_response.failure_reason = error_msg;
            if (callback) callback(error_response, tracker_url_);
            
            return false;
        }
    }
    
    TrackerResponse tracker_response = parse_announce_response(response, transaction_id);
    
    if (tracker_response.success) {
        last_announce_time_ = std::chrono::steady_clock::now();
        interval_ = tracker_response.interval;
        is_working_ = true;
        
        LOG_TRACKER_INFO("UDP announce successful. Peers: " << tracker_response.peers.size() 
                       << ", Seeders: " << tracker_response.complete 
                       << ", Leechers: " << tracker_response.incomplete);
    } else {
        LOG_TRACKER_ERROR("UDP tracker announce failed: " << tracker_response.failure_reason);
        is_working_ = false;
    }
    
    if (callback) {
        callback(tracker_response, tracker_url_);
    }
    
    return tracker_response.success;
}

bool UdpTrackerClient::scrape(const std::vector<InfoHash>& info_hashes, TrackerResponseCallback callback) {
    LOG_TRACKER_INFO("Scraping UDP tracker: " << tracker_url_);
    
    // Connect if needed
    if (!is_connection_valid()) {
        if (!connect()) {
            return false;
        }
    }
    
    uint32_t transaction_id = generate_transaction_id();
    std::vector<uint8_t> scrape_request = build_scrape_request(info_hashes, transaction_id);
    
    // Send scrape request
    std::vector<uint8_t> response = send_request(scrape_request, 15000);
    
    if (response.empty()) {
        LOG_TRACKER_ERROR("No response from UDP tracker scrape");
        return false;
    }
    
    TrackerResponse tracker_response = parse_scrape_response(response, transaction_id);
    
    if (callback) {
        callback(tracker_response, tracker_url_);
    }
    
    return tracker_response.success;
}

std::vector<uint8_t> UdpTrackerClient::send_request(const std::vector<uint8_t>& request, int timeout_ms) {
    std::lock_guard<std::mutex> lock(socket_mutex_);
    
    if (!is_valid_socket(socket_)) {
        return std::vector<uint8_t>();
    }
    
    // Send request
    if (send_udp_data(socket_, request, hostname_, port_) <= 0) {
        return std::vector<uint8_t>();
    }
    
    // Receive response with timeout
    Peer sender;
    std::vector<uint8_t> response = receive_udp_data(socket_, 2048, sender, timeout_ms);
    
    return response;
}

std::vector<uint8_t> UdpTrackerClient::build_connect_request(uint32_t transaction_id) {
    std::vector<uint8_t> request(16);
    
    // Protocol ID (64-bit)
    write_int64_be(request.data(), PROTOCOL_ID);
    
    // Action: connect (32-bit)
    write_uint32_be(request.data() + 8, ACTION_CONNECT);
    
    // Transaction ID (32-bit)
    write_uint32_be(request.data() + 12, transaction_id);
    
    return request;
}

std::vector<uint8_t> UdpTrackerClient::build_announce_request(const TrackerRequest& request, uint32_t transaction_id) {
    std::vector<uint8_t> announce_req(98);
    
    size_t offset = 0;
    
    // Connection ID (64-bit)
    write_int64_be(announce_req.data() + offset, connection_id_);
    offset += 8;
    
    // Action: announce (32-bit)
    write_uint32_be(announce_req.data() + offset, ACTION_ANNOUNCE);
    offset += 4;
    
    // Transaction ID (32-bit)
    write_uint32_be(announce_req.data() + offset, transaction_id);
    offset += 4;
    
    // Info hash (20 bytes)
    std::memcpy(announce_req.data() + offset, request.info_hash.data(), 20);
    offset += 20;
    
    // Peer ID (20 bytes)
    std::memcpy(announce_req.data() + offset, request.peer_id.data(), 20);
    offset += 20;
    
    // Downloaded (64-bit)
    write_int64_be(announce_req.data() + offset, request.downloaded);
    offset += 8;
    
    // Left (64-bit)
    write_int64_be(announce_req.data() + offset, request.left);
    offset += 8;
    
    // Uploaded (64-bit)
    write_int64_be(announce_req.data() + offset, request.uploaded);
    offset += 8;
    
    // Event (32-bit)
    write_uint32_be(announce_req.data() + offset, static_cast<uint32_t>(request.event));
    offset += 4;
    
    // IP address (32-bit, 0 for default)
    write_uint32_be(announce_req.data() + offset, 0);
    offset += 4;
    
    // Key (32-bit, random)
    write_uint32_be(announce_req.data() + offset, generate_transaction_id());
    offset += 4;
    
    // Num want (32-bit, -1 for default)
    write_uint32_be(announce_req.data() + offset, request.numwant > 0 ? request.numwant : 50);
    offset += 4;
    
    // Port (16-bit)
    announce_req[offset] = (request.port >> 8) & 0xFF;
    announce_req[offset + 1] = request.port & 0xFF;
    
    return announce_req;
}

std::vector<uint8_t> UdpTrackerClient::build_scrape_request(const std::vector<InfoHash>& info_hashes, uint32_t transaction_id) {
    std::vector<uint8_t> scrape_req(16 + info_hashes.size() * 20);
    
    size_t offset = 0;
    
    // Connection ID (64-bit)
    write_int64_be(scrape_req.data() + offset, connection_id_);
    offset += 8;
    
    // Action: scrape (32-bit)
    write_uint32_be(scrape_req.data() + offset, ACTION_SCRAPE);
    offset += 4;
    
    // Transaction ID (32-bit)
    write_uint32_be(scrape_req.data() + offset, transaction_id);
    offset += 4;
    
    // Info hashes (20 bytes each)
    for (const auto& info_hash : info_hashes) {
        std::memcpy(scrape_req.data() + offset, info_hash.data(), 20);
        offset += 20;
    }
    
    return scrape_req;
}

bool UdpTrackerClient::parse_connect_response(const std::vector<uint8_t>& data, uint32_t expected_transaction_id) {
    if (data.size() < 16) {
        LOG_TRACKER_ERROR("Invalid connect response size: " << data.size());
        return false;
    }
    
    uint32_t action = read_uint32_be(data.data());
    uint32_t transaction_id = read_uint32_be(data.data() + 4);
    
    if (action != ACTION_CONNECT) {
        LOG_TRACKER_ERROR("Invalid action in connect response: " << action);
        return false;
    }
    
    if (transaction_id != expected_transaction_id) {
        LOG_TRACKER_ERROR("Transaction ID mismatch in connect response");
        return false;
    }
    
    connection_id_ = read_int64_be(data.data() + 8);
    
    LOG_TRACKER_DEBUG("Received connection ID: " << connection_id_);
    return true;
}

TrackerResponse UdpTrackerClient::parse_announce_response(const std::vector<uint8_t>& data, uint32_t expected_transaction_id) {
    TrackerResponse response;
    
    if (data.size() < 20) {
        response.failure_reason = "Invalid announce response size";
        return response;
    }
    
    uint32_t action = read_uint32_be(data.data());
    uint32_t transaction_id = read_uint32_be(data.data() + 4);
    
    if (action != ACTION_ANNOUNCE) {
        response.failure_reason = "Invalid action in announce response";
        return response;
    }
    
    if (transaction_id != expected_transaction_id) {
        response.failure_reason = "Transaction ID mismatch";
        return response;
    }
    
    // Parse response fields
    response.interval = read_uint32_be(data.data() + 8);
    response.incomplete = read_uint32_be(data.data() + 12);
    response.complete = read_uint32_be(data.data() + 16);
    
    // Parse peer list (6 bytes per peer: 4 bytes IP + 2 bytes port)
    size_t peers_offset = 20;
    while (peers_offset + 6 <= data.size()) {
        const uint8_t* peer_data = data.data() + peers_offset;
        
        std::ostringstream ip_stream;
        ip_stream << static_cast<int>(peer_data[0]) << "."
                  << static_cast<int>(peer_data[1]) << "."
                  << static_cast<int>(peer_data[2]) << "."
                  << static_cast<int>(peer_data[3]);
        
        uint16_t port = (peer_data[4] << 8) | peer_data[5];
        
        response.peers.emplace_back(ip_stream.str(), port);
        peers_offset += 6;
    }
    
    response.success = true;
    return response;
}

TrackerResponse UdpTrackerClient::parse_scrape_response(const std::vector<uint8_t>& data, uint32_t expected_transaction_id) {
    TrackerResponse response;
    
    if (data.size() < 8) {
        response.failure_reason = "Invalid scrape response size";
        return response;
    }
    
    uint32_t action = read_uint32_be(data.data());
    uint32_t transaction_id = read_uint32_be(data.data() + 4);
    
    if (action != ACTION_SCRAPE) {
        response.failure_reason = "Invalid action in scrape response";
        return response;
    }
    
    if (transaction_id != expected_transaction_id) {
        response.failure_reason = "Transaction ID mismatch";
        return response;
    }
    
    // Parse scrape data (12 bytes per torrent)
    if (data.size() >= 20) {
        response.complete = read_uint32_be(data.data() + 8);
        response.downloaded = read_uint32_be(data.data() + 12);
        response.incomplete = read_uint32_be(data.data() + 16);
    }
    
    response.success = true;
    return response;
}

std::string UdpTrackerClient::parse_error_response(const std::vector<uint8_t>& data) {
    if (data.size() < 8) {
        return "Unknown error";
    }
    
    // Error message starts at offset 8
    std::string error_msg(data.begin() + 8, data.end());
    return error_msg;
}

uint32_t UdpTrackerClient::generate_transaction_id() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<uint32_t> dis;
    return dis(gen);
}

uint32_t UdpTrackerClient::read_uint32_be(const uint8_t* data) {
    return (static_cast<uint32_t>(data[0]) << 24) |
           (static_cast<uint32_t>(data[1]) << 16) |
           (static_cast<uint32_t>(data[2]) << 8) |
           static_cast<uint32_t>(data[3]);
}

void UdpTrackerClient::write_uint32_be(uint8_t* data, uint32_t value) {
    data[0] = (value >> 24) & 0xFF;
    data[1] = (value >> 16) & 0xFF;
    data[2] = (value >> 8) & 0xFF;
    data[3] = value & 0xFF;
}

int64_t UdpTrackerClient::read_int64_be(const uint8_t* data) {
    return (static_cast<int64_t>(data[0]) << 56) |
           (static_cast<int64_t>(data[1]) << 48) |
           (static_cast<int64_t>(data[2]) << 40) |
           (static_cast<int64_t>(data[3]) << 32) |
           (static_cast<int64_t>(data[4]) << 24) |
           (static_cast<int64_t>(data[5]) << 16) |
           (static_cast<int64_t>(data[6]) << 8) |
           static_cast<int64_t>(data[7]);
}

void UdpTrackerClient::write_int64_be(uint8_t* data, int64_t value) {
    data[0] = (value >> 56) & 0xFF;
    data[1] = (value >> 48) & 0xFF;
    data[2] = (value >> 40) & 0xFF;
    data[3] = (value >> 32) & 0xFF;
    data[4] = (value >> 24) & 0xFF;
    data[5] = (value >> 16) & 0xFF;
    data[6] = (value >> 8) & 0xFF;
    data[7] = value & 0xFF;
}

//=============================================================================
// TrackerManager Implementation
//=============================================================================

TrackerManager::TrackerManager(const TorrentInfo& torrent_info)
    : info_hash_(torrent_info.info_hash()), announce_interval_(1800) {
    
    LOG_TRACKER_INFO("Creating tracker manager for torrent: " << torrent_info.name());
    
    // Add primary announce URL
    if (!torrent_info.announce().empty()) {
        add_tracker(torrent_info.announce());
    }
    
    // Add announce list (each tier is a vector of tracker URLs)
    for (const auto& tier : torrent_info.announce_list()) {
        for (const auto& tracker_url : tier) {
            if (tracker_url != torrent_info.announce()) {
                add_tracker(tracker_url);
            }
        }
    }
    
    LOG_TRACKER_INFO("Tracker manager initialized with " << trackers_.size() << " trackers");
}

TrackerManager::~TrackerManager() = default;

bool TrackerManager::add_tracker(const std::string& tracker_url) {
    if (tracker_url.empty()) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(trackers_mutex_);
    
    // Check if tracker already exists
    for (const auto& tracker : trackers_) {
        if (tracker->get_url() == tracker_url) {
            return false;
        }
    }
    
    auto tracker_client = create_tracker_client(tracker_url);
    if (tracker_client) {
        trackers_.push_back(tracker_client);
        LOG_TRACKER_INFO("Added tracker: " << tracker_url);
        return true;
    }
    
    return false;
}

void TrackerManager::announce(const TrackerRequest& request, TrackerResponseCallback callback) {
    std::lock_guard<std::mutex> lock(trackers_mutex_);
    
    LOG_TRACKER_INFO("Announcing to all trackers (" << trackers_.size() << " trackers)");
    
    for (auto& tracker : trackers_) {
        // Skip non-working trackers
        if (!tracker->is_working()) {
            continue;
        }
        
        // Announce in separate thread to avoid blocking
        std::thread([tracker, request, callback]() {
            tracker->announce(request, callback);
        }).detach();
    }
    
    last_announce_time_ = std::chrono::steady_clock::now();
}

void TrackerManager::announce_to_best(const TrackerRequest& request, TrackerResponseCallback callback) {
    std::lock_guard<std::mutex> lock(trackers_mutex_);
    
    // Sort trackers by priority
    sort_trackers_by_priority();
    
    // Announce to first working tracker
    for (auto& tracker : trackers_) {
        if (tracker->is_working()) {
            LOG_TRACKER_INFO("Announcing to best tracker: " << tracker->get_url());
            
            std::thread([tracker, request, callback]() {
                tracker->announce(request, callback);
            }).detach();
            
            last_announce_time_ = std::chrono::steady_clock::now();
            return;
        }
    }
    
    LOG_TRACKER_WARN("No working trackers available for announce");
}

void TrackerManager::scrape(TrackerResponseCallback callback) {
    std::lock_guard<std::mutex> lock(trackers_mutex_);
    
    LOG_TRACKER_INFO("Scraping all trackers");
    
    for (auto& tracker : trackers_) {
        if (!tracker->is_working()) {
            continue;
        }
        
        std::thread([tracker, callback, this]() {
            tracker->scrape({info_hash_}, callback);
        }).detach();
    }
}

size_t TrackerManager::get_working_tracker_count() const {
    std::lock_guard<std::mutex> lock(trackers_mutex_);
    
    size_t count = 0;
    for (const auto& tracker : trackers_) {
        if (tracker->is_working()) {
            ++count;
        }
    }
    
    return count;
}

std::vector<std::string> TrackerManager::get_tracker_urls() const {
    std::lock_guard<std::mutex> lock(trackers_mutex_);
    
    std::vector<std::string> urls;
    for (const auto& tracker : trackers_) {
        urls.push_back(tracker->get_url());
    }
    
    return urls;
}

bool TrackerManager::should_announce() const {
    auto now = std::chrono::steady_clock::now();
    auto time_since_last = std::chrono::duration_cast<std::chrono::seconds>(now - last_announce_time_).count();
    return time_since_last >= announce_interval_;
}

std::chrono::steady_clock::time_point TrackerManager::get_next_announce_time() const {
    return last_announce_time_ + std::chrono::seconds(announce_interval_);
}

std::shared_ptr<TrackerClient> TrackerManager::create_tracker_client(const std::string& tracker_url) {
    if (tracker_url.substr(0, 4) == "http") {
        // HTTP or HTTPS tracker
        return std::make_shared<HttpTrackerClient>(tracker_url);
    } else if (tracker_url.substr(0, 6) == "udp://") {
        // UDP tracker
        return std::make_shared<UdpTrackerClient>(tracker_url);
    }
    
    LOG_TRACKER_WARN("Unsupported tracker protocol: " << tracker_url);
    return nullptr;
}

void TrackerManager::sort_trackers_by_priority() {
    // Sort: working trackers first, then by last announce time
    std::sort(trackers_.begin(), trackers_.end(), 
        [](const std::shared_ptr<TrackerClient>& a, const std::shared_ptr<TrackerClient>& b) {
            if (a->is_working() != b->is_working()) {
                return a->is_working();
            }
            return a->get_last_announce_time() < b->get_last_announce_time();
        });
}

//=============================================================================
// Simple Scrape API Implementation
//=============================================================================

std::vector<std::string> get_default_trackers() {
    // Common open trackers that support UDP scrape
    return {
        "udp://tracker.opentrackr.org:1337/announce",
        "udp://tracker.openbittorrent.com:6969/announce",
        "udp://open.stealth.si:80/announce",
        "udp://tracker.torrent.eu.org:451/announce",
        "udp://exodus.desync.com:6969/announce",
        "udp://tracker.tiny-vps.com:6969/announce",
        "udp://tracker.moeking.me:6969/announce",
        "udp://opentracker.i2p.rocks:6969/announce"
    };
}

void scrape_tracker(const std::string& tracker_url, 
                    const std::string& info_hash_hex,
                    ScrapeCallback callback,
                    int timeout_ms) {
    ScrapeResult result;
    result.tracker = tracker_url;
    
    // Validate hash
    if (info_hash_hex.length() != 40) {
        result.error = "Invalid hash length (expected 40 hex characters)";
        if (callback) callback(result);
        return;
    }
    
    // Convert hex to InfoHash
    InfoHash info_hash = hex_to_info_hash(info_hash_hex);
    
    // Check if hash conversion was successful
    bool all_zero = true;
    for (auto b : info_hash) {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    if (all_zero) {
        result.error = "Invalid hash format";
        if (callback) callback(result);
        return;
    }
    
    // Create appropriate tracker client
    std::shared_ptr<TrackerClient> client;
    
    if (tracker_url.substr(0, 6) == "udp://") {
        client = std::make_shared<UdpTrackerClient>(tracker_url);
    } else if (tracker_url.substr(0, 4) == "http") {
        client = std::make_shared<HttpTrackerClient>(tracker_url);
    } else {
        result.error = "Unsupported tracker protocol";
        if (callback) callback(result);
        return;
    }
    
    // Perform scrape
    std::vector<InfoHash> hashes = {info_hash};
    
    bool success = client->scrape(hashes, [&result, callback](const TrackerResponse& response, const std::string& url) {
        result.tracker = url;
        if (response.success) {
            result.seeders = response.complete;
            result.leechers = response.incomplete;
            result.completed = response.downloaded;
            result.success = true;
        } else {
            result.error = response.failure_reason.empty() ? "Scrape failed" : response.failure_reason;
        }
    });
    
    if (!success && !result.success) {
        if (result.error.empty()) {
            result.error = "Failed to scrape tracker";
        }
    }
    
    if (callback) callback(result);
}

void scrape_multiple_trackers(const std::string& info_hash_hex,
                              ScrapeCallback callback,
                              int timeout_ms) {
    // Validate hash first
    if (info_hash_hex.length() != 40) {
        ScrapeResult result;
        result.error = "Invalid hash length (expected 40 hex characters)";
        if (callback) callback(result);
        return;
    }
    
    std::vector<std::string> trackers = get_default_trackers();
    
    if (trackers.empty()) {
        ScrapeResult result;
        result.error = "No trackers available";
        if (callback) callback(result);
        return;
    }
    
    // Track best result
    ScrapeResult best_result;
    std::mutex result_mutex;
    std::atomic<int> pending{static_cast<int>(trackers.size())};
    std::atomic<bool> has_success{false};
    
    // Create threads to scrape each tracker concurrently
    std::vector<std::thread> threads;
    threads.reserve(trackers.size());
    
    for (const auto& tracker_url : trackers) {
        threads.emplace_back([&, tracker_url]() {
            scrape_tracker(tracker_url, info_hash_hex, [&](const ScrapeResult& result) {
                std::lock_guard<std::mutex> lock(result_mutex);
                
                // Update best result if this one is better
                if (result.success) {
                    if (!has_success.load() || result.seeders > best_result.seeders) {
                        best_result = result;
                        has_success.store(true);
                    }
                }
                
                pending--;
            }, timeout_ms);
        });
    }
    
    // Wait for all threads to complete
    for (auto& t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }
    
    // Return best result
    if (!has_success.load()) {
        best_result.error = "No tracker responded successfully";
    }
    
    if (callback) callback(best_result);
}

} // namespace librats

