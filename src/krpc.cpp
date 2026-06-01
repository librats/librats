#include "krpc.h"
#include "network_utils.h"
#include "logger.h"
#include <random>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <algorithm>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <arpa/inet.h>
    #include <netinet/in.h>
#endif

// KRPC module logging macros
#define LOG_KRPC_DEBUG(message) LOG_DEBUG("krpc", message)
#define LOG_KRPC_INFO(message)  LOG_INFO("krpc", message)
#define LOG_KRPC_WARN(message)  LOG_WARN("krpc", message)
#define LOG_KRPC_ERROR(message) LOG_ERROR("krpc", message)

namespace librats {

std::atomic<uint32_t> KrpcProtocol::transaction_counter_ = 0;

KrpcProtocol::KrpcProtocol() {}

KrpcProtocol::~KrpcProtocol() {}

// Create query messages
KrpcMessage KrpcProtocol::create_ping_query(const std::string& transaction_id, const NodeId& sender_id) {
    KrpcMessage message;
    message.type = KrpcMessageType::Query;
    message.transaction_id = transaction_id;
    message.query_type = KrpcQueryType::Ping;
    message.sender_id = sender_id;
    return message;
}

KrpcMessage KrpcProtocol::create_find_node_query(const std::string& transaction_id, const NodeId& sender_id, const NodeId& target_id) {
    KrpcMessage message;
    message.type = KrpcMessageType::Query;
    message.transaction_id = transaction_id;
    message.query_type = KrpcQueryType::FindNode;
    message.sender_id = sender_id;
    message.target_id = target_id;
    return message;
}

KrpcMessage KrpcProtocol::create_get_peers_query(const std::string& transaction_id, const NodeId& sender_id, const InfoHash& info_hash) {
    KrpcMessage message;
    message.type = KrpcMessageType::Query;
    message.transaction_id = transaction_id;
    message.query_type = KrpcQueryType::GetPeers;
    message.sender_id = sender_id;
    message.info_hash = info_hash;
    return message;
}

KrpcMessage KrpcProtocol::create_announce_peer_query(const std::string& transaction_id, const NodeId& sender_id, const InfoHash& info_hash, uint16_t port, const std::string& token, bool implied_port) {
    KrpcMessage message;
    message.type = KrpcMessageType::Query;
    message.transaction_id = transaction_id;
    message.query_type = KrpcQueryType::AnnouncePeer;
    message.sender_id = sender_id;
    message.info_hash = info_hash;
    message.port = port;
    message.implied_port = implied_port;
    message.token = token;
    return message;
}

// Create response messages
KrpcMessage KrpcProtocol::create_ping_response(const std::string& transaction_id, const NodeId& response_id) {
    KrpcMessage message;
    message.type = KrpcMessageType::Response;
    message.transaction_id = transaction_id;
    message.response_id = response_id;
    return message;
}

KrpcMessage KrpcProtocol::create_find_node_response(const std::string& transaction_id, const NodeId& response_id, const std::vector<KrpcNode>& nodes) {
    KrpcMessage message;
    message.type = KrpcMessageType::Response;
    message.transaction_id = transaction_id;
    message.response_id = response_id;
    message.nodes = nodes;
    return message;
}

KrpcMessage KrpcProtocol::create_get_peers_response(const std::string& transaction_id, const NodeId& response_id, const std::vector<Peer>& peers, const std::string& token) {
    KrpcMessage message;
    message.type = KrpcMessageType::Response;
    message.transaction_id = transaction_id;
    message.response_id = response_id;
    message.peers = peers;
    message.token = token;
    return message;
}

KrpcMessage KrpcProtocol::create_get_peers_response_with_nodes(const std::string& transaction_id, const NodeId& response_id, const std::vector<KrpcNode>& nodes, const std::string& token) {
    KrpcMessage message;
    message.type = KrpcMessageType::Response;
    message.transaction_id = transaction_id;
    message.response_id = response_id;
    message.nodes = nodes;
    message.token = token;
    return message;
}

KrpcMessage KrpcProtocol::create_announce_peer_response(const std::string& transaction_id, const NodeId& response_id) {
    KrpcMessage message;
    message.type = KrpcMessageType::Response;
    message.transaction_id = transaction_id;
    message.response_id = response_id;
    return message;
}

// Create error message
KrpcMessage KrpcProtocol::create_error(const std::string& transaction_id, KrpcErrorCode error_code, const std::string& error_message) {
    KrpcMessage message;
    message.type = KrpcMessageType::Error;
    message.transaction_id = transaction_id;
    message.error_code = error_code;
    message.error_message = error_message;
    return message;
}

// Encode messages
std::vector<uint8_t> KrpcProtocol::encode_message(const KrpcMessage& message) {
    BencodeValue root;
    
    switch (message.type) {
        case KrpcMessageType::Query:
            root = encode_query(message);
            break;
        case KrpcMessageType::Response:
            root = encode_response(message);
            break;
        case KrpcMessageType::Error:
            root = encode_error(message);
            break;
        default:
            LOG_KRPC_ERROR("Unknown message type: " << static_cast<int>(message.type));
            return {};
    }
    
    return root.encode();
}

BencodeValue KrpcProtocol::encode_query(const KrpcMessage& message) {
    BencodeValue root = BencodeValue::create_dict();
    
    // Common fields
    root["t"] = BencodeValue(message.transaction_id);
    root["y"] = BencodeValue("q");
    root["q"] = BencodeValue(query_type_to_string(message.query_type));
    
    // Arguments
    BencodeValue args = BencodeValue::create_dict();
    args["id"] = BencodeValue(node_id_to_string(message.sender_id));
    
    switch (message.query_type) {
        case KrpcQueryType::Ping:
            // No additional arguments for ping
            break;
        case KrpcQueryType::FindNode:
            args["target"] = BencodeValue(node_id_to_string(message.target_id));
            break;
        case KrpcQueryType::GetPeers:
            args["info_hash"] = BencodeValue(node_id_to_string(message.info_hash));
            break;
        case KrpcQueryType::AnnouncePeer:
            args["info_hash"] = BencodeValue(node_id_to_string(message.info_hash));
            args["port"] = BencodeValue(static_cast<int64_t>(message.port));
            args["token"] = BencodeValue(message.token);
            if (message.implied_port) {
                args["implied_port"] = BencodeValue(static_cast<int64_t>(1));
            }
            break;
    }
    
    // BEP 32: advertise which node families we want back
    if (!message.want.empty()) {
        BencodeValue want_list = BencodeValue::create_list();
        for (const auto& w : message.want) {
            want_list.push_back(BencodeValue(w));
        }
        args["want"] = want_list;
    }

    root["a"] = args;
    return root;
}

BencodeValue KrpcProtocol::encode_response(const KrpcMessage& message) {
    BencodeValue root = BencodeValue::create_dict();
    
    // Common fields
    root["t"] = BencodeValue(message.transaction_id);
    root["y"] = BencodeValue("r");
    
    // Response data
    BencodeValue response = BencodeValue::create_dict();
    response["id"] = BencodeValue(node_id_to_string(message.response_id));
    
    // Add nodes if present. BEP 32: IPv4 nodes go in "nodes" (26 bytes each),
    // IPv6 nodes go in "nodes6" (38 bytes each).
    if (!message.nodes.empty()) {
        std::string compact_nodes_v4;
        std::string compact_nodes_v6;
        for (const auto& node : message.nodes) {
            if (network_utils::is_valid_ipv6(node.ip)) {
                compact_nodes_v6 += compact_node_info(node);
            } else {
                compact_nodes_v4 += compact_node_info(node);
            }
        }
        if (!compact_nodes_v4.empty()) {
            response["nodes"] = BencodeValue(compact_nodes_v4);
        }
        if (!compact_nodes_v6.empty()) {
            response["nodes6"] = BencodeValue(compact_nodes_v6);
        }
    }
    
    // Add peers if present
    if (!message.peers.empty()) {
        BencodeValue values = BencodeValue::create_list();
        for (const auto& peer : message.peers) {
            values.push_back(BencodeValue(compact_peer_info(peer)));
        }
        response["values"] = values;
    }
    
    // Add token if present
    if (!message.token.empty()) {
        response["token"] = BencodeValue(message.token);
    }

    root["r"] = response;

    // BEP 42: echo the requester's external address as a top-level "ip" field
    // (compact 6-byte IPv4 / 18-byte IPv6 ip+port).
    if (!message.external_ip.empty()) {
        std::string compact = compact_peer_info(Peer(message.external_ip, message.external_port));
        if (!compact.empty()) {
            root["ip"] = BencodeValue(compact);
        }
    }

    return root;
}

BencodeValue KrpcProtocol::encode_error(const KrpcMessage& message) {
    BencodeValue root = BencodeValue::create_dict();
    
    // Common fields
    root["t"] = BencodeValue(message.transaction_id);
    root["y"] = BencodeValue("e");
    
    // Error data
    BencodeValue error = BencodeValue::create_list();
    error.push_back(BencodeValue(static_cast<int64_t>(message.error_code)));
    error.push_back(BencodeValue(message.error_message));
    
    root["e"] = error;
    return root;
}

// Decode messages
std::unique_ptr<KrpcMessage> KrpcProtocol::decode_message(const std::vector<uint8_t>& data) {
    try {
        BencodeValue root = bencode::decode(data);
        
        if (!root.is_dict()) {
            LOG_KRPC_ERROR("Root is not a dictionary");
            return nullptr;
        }
        
        if (!root.has_key("t") || !root.has_key("y")) {
            LOG_KRPC_ERROR("Missing required fields 't' or 'y'");
            return nullptr;
        }
        
        std::string transaction_id = root["t"].as_string();
        std::string message_type = root["y"].as_string();
        
        if (message_type == "q") {
            return decode_query(root);
        } else if (message_type == "r") {
            return decode_response(root);
        } else if (message_type == "e") {
            return decode_error(root);
        } else {
            LOG_KRPC_ERROR("Unknown message type: " << message_type);
            return nullptr;
        }
    } catch (const std::exception& e) {
        LOG_KRPC_DEBUG("Failed to decode KRPC message: " << e.what());
        return nullptr;
    }
}

std::unique_ptr<KrpcMessage> KrpcProtocol::decode_query(const BencodeValue& data) {
    if (!data.has_key("q") || !data.has_key("a")) {
        LOG_KRPC_ERROR("Missing required query fields 'q' or 'a'");
        return nullptr;
    }
    
    auto message = std::make_unique<KrpcMessage>();
    message->type = KrpcMessageType::Query;
    message->transaction_id = data["t"].as_string();
    
    std::string query_method = data["q"].as_string();
    message->query_type = string_to_query_type(query_method);
    
    const BencodeValue& args = data["a"];
    if (!args.is_dict() || !args.has_key("id")) {
        LOG_KRPC_ERROR("Invalid arguments in query");
        return nullptr;
    }
    
    message->sender_id = string_to_node_id(args["id"].as_string());

    // BEP 32: optional "want" list specifying desired node families
    if (args.has_key("want")) {
        const BencodeValue& want_list = args["want"];
        if (want_list.is_list()) {
            for (size_t i = 0; i < want_list.size(); ++i) {
                message->want.push_back(want_list[i].as_string());
            }
        }
    }

    switch (message->query_type) {
        case KrpcQueryType::Ping:
            // No additional arguments
            break;
        case KrpcQueryType::FindNode:
            if (args.has_key("target")) {
                message->target_id = string_to_node_id(args["target"].as_string());
            }
            break;
        case KrpcQueryType::GetPeers:
            if (args.has_key("info_hash")) {
                message->info_hash = string_to_node_id(args["info_hash"].as_string());
            }
            break;
        case KrpcQueryType::AnnouncePeer:
            if (args.has_key("info_hash")) {
                message->info_hash = string_to_node_id(args["info_hash"].as_string());
            }
            if (args.has_key("port")) {
                message->port = static_cast<uint16_t>(args["port"].as_integer());
            }
            if (args.has_key("token")) {
                message->token = args["token"].as_string();
            }
            if (args.has_key("implied_port")) {
                message->implied_port = (args["implied_port"].as_integer() != 0);
            }
            break;
    }
    
    return message;
}

std::unique_ptr<KrpcMessage> KrpcProtocol::decode_response(const BencodeValue& data) {
    if (!data.has_key("r")) {
        LOG_KRPC_ERROR("Missing required response field 'r'");
        return nullptr;
    }
    
    auto message = std::make_unique<KrpcMessage>();
    message->type = KrpcMessageType::Response;
    message->transaction_id = data["t"].as_string();
    
    const BencodeValue& response = data["r"];
    if (!response.is_dict() || !response.has_key("id")) {
        LOG_KRPC_ERROR("Invalid response data");
        return nullptr;
    }
    
    message->response_id = string_to_node_id(response["id"].as_string());
    
    // Parse nodes if present (BEP 32: "nodes" = IPv4, "nodes6" = IPv6)
    if (response.has_key("nodes")) {
        std::string compact_nodes = response["nodes"].as_string();
        message->nodes = parse_compact_node_info(compact_nodes, /*ipv6=*/false);
    }
    if (response.has_key("nodes6")) {
        std::string compact_nodes6 = response["nodes6"].as_string();
        auto nodes6 = parse_compact_node_info(compact_nodes6, /*ipv6=*/true);
        message->nodes.insert(message->nodes.end(), nodes6.begin(), nodes6.end());
    }
    
    // Parse peers if present
    if (response.has_key("values")) {
        const BencodeValue& values = response["values"];
        if (values.is_list()) {
            for (size_t i = 0; i < values.size(); ++i) {
                std::string compact_peers = values[i].as_string();
                auto peers = parse_compact_peer_info(compact_peers);
                message->peers.insert(message->peers.end(), peers.begin(), peers.end());
            }
        }
    }
    
    // Parse token if present
    if (response.has_key("token")) {
        message->token = response["token"].as_string();
    }

    // BEP 42: top-level "ip" field tells us our external address as the responder sees it.
    if (data.has_key("ip")) {
        auto endpoints = parse_compact_peer_info(data["ip"].as_string());
        if (!endpoints.empty()) {
            message->external_ip = endpoints[0].ip;
            message->external_port = endpoints[0].port;
        }
    }

    return message;
}

std::unique_ptr<KrpcMessage> KrpcProtocol::decode_error(const BencodeValue& data) {
    if (!data.has_key("e")) {
        LOG_KRPC_ERROR("Missing required error field 'e'");
        return nullptr;
    }
    
    auto message = std::make_unique<KrpcMessage>();
    message->type = KrpcMessageType::Error;
    message->transaction_id = data["t"].as_string();
    
    const BencodeValue& error = data["e"];
    if (!error.is_list() || error.size() < 2) {
        LOG_KRPC_ERROR("Invalid error data");
        return nullptr;
    }
    
    message->error_code = static_cast<KrpcErrorCode>(error[0].as_integer());
    message->error_message = error[1].as_string();
    
    return message;
}

// Utility functions
std::string KrpcProtocol::generate_transaction_id() {
    return std::to_string(++transaction_counter_);
}

std::string KrpcProtocol::node_id_to_string(const NodeId& id) {
    return std::string(id.begin(), id.end());
}

NodeId KrpcProtocol::string_to_node_id(const std::string& str) {
    NodeId id;
    if (str.size() >= 20) {
        std::copy_n(str.begin(), 20, id.begin());
    } else {
        std::fill(id.begin(), id.end(), 0);
        std::copy(str.begin(), str.end(), id.begin());
    }
    return id;
}

// Append a compact IP address (4 bytes for IPv4, 16 bytes for IPv6) to `out`.
// Returns the number of address bytes written, or 0 on failure.
static size_t append_compact_address(const std::string& ip, std::string& out) {
    if (network_utils::is_valid_ipv6(ip)) {
        struct in6_addr addr6;
        if (inet_pton(AF_INET6, ip.c_str(), &addr6) == 1) {
            out.append(reinterpret_cast<const char*>(addr6.s6_addr), 16);
            return 16;
        }
        return 0;
    }

    struct in_addr addr;
    if (inet_pton(AF_INET, ip.c_str(), &addr) == 1) {
        uint32_t v = ntohl(addr.s_addr);
        out += static_cast<char>((v >> 24) & 0xFF);
        out += static_cast<char>((v >> 16) & 0xFF);
        out += static_cast<char>((v >> 8) & 0xFF);
        out += static_cast<char>(v & 0xFF);
        return 4;
    }
    // Invalid IPv4, use 0.0.0.0
    out.append(4, '\x00');
    return 4;
}

// Read a compact IP address of `addr_len` bytes (4=IPv4, 16=IPv6) at compact_info[offset]
// into a printable string.
static std::string read_compact_address(const std::string& compact_info, size_t offset, size_t addr_len) {
    if (addr_len == 16) {
        struct in6_addr addr6;
        memcpy(addr6.s6_addr, compact_info.data() + offset, 16);
        char ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &addr6, ip_str, INET6_ADDRSTRLEN);
        return std::string(ip_str);
    }

    struct in_addr addr;
    uint32_t ip = 0;
    ip |= (static_cast<uint8_t>(compact_info[offset]) << 24);
    ip |= (static_cast<uint8_t>(compact_info[offset + 1]) << 16);
    ip |= (static_cast<uint8_t>(compact_info[offset + 2]) << 8);
    ip |= static_cast<uint8_t>(compact_info[offset + 3]);
    addr.s_addr = htonl(ip);
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
    return std::string(ip_str);
}

std::string KrpcProtocol::compact_peer_info(const Peer& peer) {
    std::string result;
    result.reserve(18);

    // IP address (4 bytes IPv4 / 16 bytes IPv6)
    append_compact_address(peer.ip, result);

    // Convert port to 2 bytes (network byte order)
    result += static_cast<char>((peer.port >> 8) & 0xFF);
    result += static_cast<char>(peer.port & 0xFF);

    return result;
}

std::string KrpcProtocol::compact_node_info(const KrpcNode& node) {
    std::string result;
    result.reserve(38);

    // Node ID (20 bytes)
    result += node_id_to_string(node.id);

    // IP address (4 bytes IPv4 / 16 bytes IPv6)
    append_compact_address(node.ip, result);

    // Port (2 bytes, network byte order)
    result += static_cast<char>((node.port >> 8) & 0xFF);
    result += static_cast<char>(node.port & 0xFF);

    return result;
}

std::vector<Peer> KrpcProtocol::parse_compact_peer_info(const std::string& compact_info) {
    std::vector<Peer> peers;

    // BEP 5/BEP 7: each "values" entry is a single compact peer: 6 bytes (IPv4) or 18 bytes (IPv6).
    // Detect the family from the entry length. An exact length of 18 is treated as one IPv6 peer;
    // otherwise we chunk by 6 (some implementations concatenate multiple IPv4 peers).
    size_t record_size = 6;
    size_t addr_len = 4;
    if (compact_info.size() == 18) {
        record_size = 18;
        addr_len = 16;
    } else if (compact_info.size() % 6 != 0) {
        LOG_KRPC_WARN("Invalid compact peer info size: " << compact_info.size());
        return peers;
    }

    for (size_t i = 0; i + record_size <= compact_info.size(); i += record_size) {
        std::string ip_str = read_compact_address(compact_info, i, addr_len);

        uint16_t port = 0;
        port |= (static_cast<uint8_t>(compact_info[i + addr_len]) << 8);
        port |= static_cast<uint8_t>(compact_info[i + addr_len + 1]);

        peers.emplace_back(ip_str, port);
    }

    return peers;
}

std::vector<KrpcNode> KrpcProtocol::parse_compact_node_info(const std::string& compact_info, bool ipv6) {
    std::vector<KrpcNode> nodes;

    const size_t addr_len = ipv6 ? 16 : 4;
    const size_t record_size = 20 + addr_len + 2;  // 26 (IPv4) or 38 (IPv6)

    if (compact_info.size() % record_size != 0) {
        LOG_KRPC_WARN("Invalid compact node info size: " << compact_info.size()
                      << " (expected multiple of " << record_size << ")");
        return nodes;
    }

    for (size_t i = 0; i < compact_info.size(); i += record_size) {
        // Extract node ID (20 bytes)
        NodeId node_id;
        std::copy_n(compact_info.begin() + i, 20, node_id.begin());

        // Extract IP address (4 or 16 bytes)
        std::string ip_str = read_compact_address(compact_info, i + 20, addr_len);

        // Extract port (2 bytes)
        uint16_t port = 0;
        port |= (static_cast<uint8_t>(compact_info[i + 20 + addr_len]) << 8);
        port |= static_cast<uint8_t>(compact_info[i + 20 + addr_len + 1]);

        nodes.emplace_back(node_id, ip_str, port);
    }

    return nodes;
}

KrpcQueryType KrpcProtocol::string_to_query_type(const std::string& str) {
    if (str == "ping") return KrpcQueryType::Ping;
    if (str == "find_node") return KrpcQueryType::FindNode;
    if (str == "get_peers") return KrpcQueryType::GetPeers;
    if (str == "announce_peer") return KrpcQueryType::AnnouncePeer;
    return KrpcQueryType::Ping; // Default
}

std::string KrpcProtocol::query_type_to_string(KrpcQueryType type) {
    switch (type) {
        case KrpcQueryType::Ping: return "ping";
        case KrpcQueryType::FindNode: return "find_node";
        case KrpcQueryType::GetPeers: return "get_peers";
        case KrpcQueryType::AnnouncePeer: return "announce_peer";
        default: return "ping";
    }
}

} // namespace librats 