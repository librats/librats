#include "bittorrent/tracker.h"

#include "bittorrent/bencode.h"
#include "bittorrent/byte_io.h"
#include "core/socket.h"

#include <cctype>
#include <cstring>
#include <iomanip>
#include <random>
#include <sstream>
#include <thread>

namespace librats::bittorrent {

namespace {

// UDP BEP 15 constants.
constexpr std::int64_t  kUdpMagic       = 0x41727101980LL;
constexpr std::uint32_t kActionConnect  = 0;
constexpr std::uint32_t kActionAnnounce = 1;
constexpr std::uint32_t kActionError    = 3;

std::uint32_t random_u32() {
    thread_local std::mt19937 gen(std::random_device{}());
    return std::uniform_int_distribution<std::uint32_t>{}(gen);
}

const char* http_event(TrackerEvent e) {
    switch (e) {
        case TrackerEvent::Started:   return "started";
        case TrackerEvent::Stopped:   return "stopped";
        case TrackerEvent::Completed: return "completed";
        default:                      return "";
    }
}

// UDP event codes differ from our enum order, so map explicitly.
std::uint32_t udp_event(TrackerEvent e) {
    switch (e) {
        case TrackerEvent::Completed: return 1;
        case TrackerEvent::Started:   return 2;
        case TrackerEvent::Stopped:   return 3;
        default:                      return 0;
    }
}

std::string url_encode_binary(const std::uint8_t* data, std::size_t len) {
    std::ostringstream o;
    o.fill('0');
    o << std::hex;
    for (std::size_t i = 0; i < len; ++i) {
        const std::uint8_t c = data[i];
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') o << char(c);
        else o << '%' << std::setw(2) << int(c);
    }
    return o.str();
}

std::vector<Address> parse_compact_peers(const std::string& data) {
    std::vector<Address> peers;
    for (std::size_t i = 0; i + 6 <= data.size(); i += 6) {
        const auto* b = reinterpret_cast<const std::uint8_t*>(data.data() + i);
        std::ostringstream ip;
        ip << int(b[0]) << '.' << int(b[1]) << '.' << int(b[2]) << '.' << int(b[3]);
        peers.emplace_back(ip.str(), read_u16_be(b + 4));
    }
    return peers;
}

std::vector<Address> parse_dict_peers(const librats::BencodeValue& list) {
    std::vector<Address> peers;
    for (std::size_t i = 0; i < list.size(); ++i) {
        const auto& d = list[i];
        if (!d.is_dict() || !d.has_key("ip") || !d.has_key("port")) continue;
        peers.emplace_back(d["ip"].as_string(), std::uint16_t(d["port"].as_integer()));
    }
    return peers;
}

/// Blocking HTTP/1.0 GET; returns the response body (headers stripped).
Bytes http_get(const std::string& url, int timeout_ms) {
    const std::size_t scheme = url.find("://");
    if (scheme == std::string::npos) return {};
    const std::string proto = url.substr(0, scheme);
    const std::size_t host_start = scheme + 3;
    const std::size_t path_start = url.find('/', host_start);

    std::string host_port = url.substr(host_start, path_start == std::string::npos ? std::string::npos
                                                                                   : path_start - host_start);
    std::string path = (path_start == std::string::npos) ? "/" : url.substr(path_start);

    std::uint16_t port = (proto == "https") ? 443 : 80;
    if (const std::size_t colon = host_port.find(':'); colon != std::string::npos) {
        port = std::uint16_t(std::stoi(host_port.substr(colon + 1)));
        host_port = host_port.substr(0, colon);
    }

    socket_t sock = create_tcp_client(host_port, port, timeout_ms);
    if (!is_valid_socket(sock)) return {};

    std::ostringstream req;
    req << "GET " << path << " HTTP/1.0\r\nHost: " << host_port
        << "\r\nUser-Agent: librats\r\nAccept: */*\r\nConnection: close\r\n\r\n";
    if (send_tcp_string(sock, req.str()) <= 0) { close_socket(sock); return {}; }

    Bytes data;
    for (;;) {
        Bytes chunk = receive_tcp_data(sock, 4096);
        if (chunk.empty()) break;
        data.insert(data.end(), chunk.begin(), chunk.end());
    }
    close_socket(sock);

    // Strip headers (everything up to and including the blank line).
    static const std::uint8_t sep[4] = {'\r', '\n', '\r', '\n'};
    for (std::size_t i = 0; i + 4 <= data.size(); ++i) {
        if (std::memcmp(data.data() + i, sep, 4) == 0)
            return Bytes(data.begin() + std::ptrdiff_t(i + 4), data.end());
    }
    return {};
}

TrackerResponse announce_http(const std::string& url, const TrackerRequest& req, int timeout_ms) {
    TrackerResponse out;
    const Bytes body = http_get(tracker_detail::build_http_announce_url(url, req), timeout_ms);
    if (body.empty()) { out.failure_reason = "no response"; return out; }
    return tracker_detail::parse_http_response(body);
}

TrackerResponse announce_udp(const std::string& url, const TrackerRequest& req, int timeout_ms) {
    TrackerResponse out;

    // Parse udp://host:port[/...]
    std::string rest = url.substr(6);
    if (const std::size_t slash = rest.find('/'); slash != std::string::npos) rest = rest.substr(0, slash);
    const std::size_t colon = rest.find(':');
    if (colon == std::string::npos) { out.failure_reason = "bad udp url"; return out; }
    const std::string host = rest.substr(0, colon);
    const int port = std::stoi(rest.substr(colon + 1));

    socket_t sock = create_udp_socket(0, "", AddressFamily::IPv4);
    if (!is_valid_socket(sock)) { out.failure_reason = "socket"; return out; }
    struct Closer { socket_t s; ~Closer() { if (is_valid_socket(s)) close_socket(s); } } closer{sock};

    // 1) connect
    const std::uint32_t tid1 = random_u32();
    Bytes creq(16);
    write_u64_be(creq.data(), std::uint64_t(kUdpMagic));
    write_u32_be(creq.data() + 8, kActionConnect);
    write_u32_be(creq.data() + 12, tid1);
    if (send_udp_data(sock, creq, host, port, AddressFamily::IPv4) <= 0) { out.failure_reason = "send"; return out; }

    Address sender;
    Bytes cresp = receive_udp_data(sock, 2048, sender, timeout_ms);
    if (cresp.size() < 16 || read_u32_be(cresp.data()) != kActionConnect ||
        read_u32_be(cresp.data() + 4) != tid1) {
        out.failure_reason = "connect failed";
        return out;
    }
    const std::uint64_t conn_id = read_u64_be(cresp.data() + 8);

    // 2) announce
    const std::uint32_t tid2 = random_u32();
    Bytes areq(98);
    write_u64_be(areq.data(), conn_id);
    write_u32_be(areq.data() + 8, kActionAnnounce);
    write_u32_be(areq.data() + 12, tid2);
    std::memcpy(areq.data() + 16, req.info_hash.data(), 20);
    std::memcpy(areq.data() + 36, req.peer_id.data(), 20);
    write_u64_be(areq.data() + 56, req.downloaded);
    write_u64_be(areq.data() + 64, req.left);
    write_u64_be(areq.data() + 72, req.uploaded);
    write_u32_be(areq.data() + 80, udp_event(req.event));
    write_u32_be(areq.data() + 84, 0);                       // our IP — let the tracker use the source
    write_u32_be(areq.data() + 88, random_u32());            // key
    write_u32_be(areq.data() + 92, std::uint32_t(req.numwant));
    write_u16_be(areq.data() + 96, req.port);
    if (send_udp_data(sock, areq, host, port, AddressFamily::IPv4) <= 0) { out.failure_reason = "send"; return out; }

    Bytes resp = receive_udp_data(sock, 2048, sender, timeout_ms);
    if (resp.size() < 8) { out.failure_reason = "no response"; return out; }
    const std::uint32_t action = read_u32_be(resp.data());
    if (action == kActionError) {
        out.failure_reason.assign(resp.begin() + 8, resp.end());
        return out;
    }
    if (action != kActionAnnounce || read_u32_be(resp.data() + 4) != tid2 || resp.size() < 20) {
        out.failure_reason = "bad announce response";
        return out;
    }

    out.interval   = read_u32_be(resp.data() + 8);
    out.incomplete = read_u32_be(resp.data() + 12);
    out.complete   = read_u32_be(resp.data() + 16);
    for (std::size_t off = 20; off + 6 <= resp.size(); off += 6) {
        const std::uint8_t* b = resp.data() + off;
        std::ostringstream ip;
        ip << int(b[0]) << '.' << int(b[1]) << '.' << int(b[2]) << '.' << int(b[3]);
        out.peers.emplace_back(ip.str(), read_u16_be(b + 4));
    }
    out.success = true;
    return out;
}

} // namespace

namespace tracker_detail {

std::string build_http_announce_url(const std::string& base, const TrackerRequest& req) {
    std::ostringstream u;
    u << base << (base.find('?') == std::string::npos ? '?' : '&');
    u << "info_hash=" << url_encode_binary(req.info_hash.data(), req.info_hash.size());
    u << "&peer_id="  << url_encode_binary(req.peer_id.data(), req.peer_id.size());
    u << "&port="       << req.port;
    u << "&uploaded="   << req.uploaded;
    u << "&downloaded=" << req.downloaded;
    u << "&left="       << req.left;
    u << "&numwant="    << req.numwant;
    u << "&compact=1";
    if (req.event != TrackerEvent::None) u << "&event=" << http_event(req.event);
    return u.str();
}

TrackerResponse parse_http_response(const Bytes& body) {
    TrackerResponse out;
    try {
        librats::BencodeValue d = librats::BencodeDecoder::decode(body.data(), body.size());
        if (!d.is_dict()) { out.failure_reason = "not a dict"; return out; }
        if (d.has_key("failure reason")) { out.failure_reason = d["failure reason"].as_string(); return out; }
        if (d.has_key("interval"))     out.interval     = std::uint32_t(d["interval"].as_integer());
        if (d.has_key("min interval")) out.min_interval = std::uint32_t(d["min interval"].as_integer());
        if (d.has_key("complete"))     out.complete     = std::uint32_t(d["complete"].as_integer());
        if (d.has_key("incomplete"))   out.incomplete   = std::uint32_t(d["incomplete"].as_integer());
        if (d.has_key("peers")) {
            const auto& p = d["peers"];
            if (p.is_string())    out.peers = parse_compact_peers(p.as_string());
            else if (p.is_list()) out.peers = parse_dict_peers(p);
        }
        out.success = true;
    } catch (const std::exception& e) {
        out.failure_reason = e.what();
    }
    return out;
}

} // namespace tracker_detail

TrackerResponse announce_to_tracker(const std::string& url, const TrackerRequest& req, int timeout_ms) {
    if (url.rfind("udp://", 0) == 0)  return announce_udp(url, req, timeout_ms);
    if (url.rfind("http", 0) == 0)    return announce_http(url, req, timeout_ms);
    TrackerResponse out;
    out.failure_reason = "unsupported tracker scheme";
    return out;
}

// ---- TrackerAnnouncer ----

TrackerAnnouncer::TrackerAnnouncer(std::vector<std::string> trackers, Poster poster, int timeout_ms)
    : trackers_(std::move(trackers)), poster_(std::move(poster)), timeout_ms_(timeout_ms) {}

TrackerAnnouncer::~TrackerAnnouncer() { stop(); }

void TrackerAnnouncer::announce(const TrackerRequest& req, PeerCallback on_peers) {
    for (const std::string& url : trackers_) {
        {
            std::lock_guard<std::mutex> lk(mutex_);
            if (stopping_) return;
            ++inflight_;
        }
        std::thread([this, url, req, on_peers] {
            TrackerResponse resp = announce_to_tracker(url, req, timeout_ms_);
            {
                std::lock_guard<std::mutex> lk(mutex_);
                if (!stopping_ && resp.success && !resp.peers.empty() && poster_) {
                    poster_([on_peers, peers = resp.peers] { on_peers(peers); });
                }
                --inflight_;
            }
            drain_cv_.notify_all();
        }).detach();
    }
}

void TrackerAnnouncer::stop() {
    std::unique_lock<std::mutex> lk(mutex_);
    stopping_ = true;
    drain_cv_.wait(lk, [this] { return inflight_ == 0; });
}

} // namespace librats::bittorrent
