#include "bittorrent/extensions.h"
#include "bittorrent/bencode.h"
#include "bittorrent/byte_io.h"

#include <cstdio>

namespace librats::bittorrent::ext {

namespace {

/// Parse "a.b.c.d" into 4 bytes. Returns false on anything that isn't dotted IPv4.
bool ipv4_to_bytes(const std::string& ip, std::uint8_t out[4]) {
    unsigned a, b, c, d;
    char extra;
    if (std::sscanf(ip.c_str(), "%u.%u.%u.%u%c", &a, &b, &c, &d, &extra) != 4) return false;
    if (a > 255 || b > 255 || c > 255 || d > 255) return false;
    out[0] = std::uint8_t(a); out[1] = std::uint8_t(b);
    out[2] = std::uint8_t(c); out[3] = std::uint8_t(d);
    return true;
}

std::string ipv4_to_string(const std::uint8_t* b) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
    return buf;
}

/// Pack peers into the 6-bytes-each compact form (4 IPv4 + 2 port BE).
std::string compact(const std::vector<PexPeer>& peers) {
    std::string out;
    for (const auto& p : peers) {
        std::uint8_t ip[4];
        if (!ipv4_to_bytes(p.ip, ip)) continue;
        out.append(reinterpret_cast<const char*>(ip), 4);
        std::uint8_t port[2];
        write_u16_be(port, p.port);
        out.append(reinterpret_cast<const char*>(port), 2);
    }
    return out;
}

std::vector<PexPeer> uncompact(const std::string& s) {
    std::vector<PexPeer> peers;
    for (std::size_t i = 0; i + 6 <= s.size(); i += 6) {
        const auto* b = reinterpret_cast<const std::uint8_t*>(s.data() + i);
        peers.push_back(PexPeer{ipv4_to_string(b), read_u16_be(b + 4)});
    }
    return peers;
}

// Length of the first bencoded value at the start of `d` (0 on malformed input).
// A small local scanner so we can split a ut_metadata header dict from the raw
// metadata block that follows it.
std::size_t bencode_value_length(const std::uint8_t* d, std::size_t n, std::size_t pos = 0) {
    if (pos >= n) return 0;
    const char c = char(d[pos]);
    if (c == 'i') {
        std::size_t e = pos + 1;
        while (e < n && d[e] != 'e') ++e;
        return e < n ? e + 1 - pos : 0;
    }
    if (c == 'l' || c == 'd') {
        std::size_t p = pos + 1;
        while (p < n && d[p] != 'e') {
            const std::size_t len = bencode_value_length(d, n, p);
            if (len == 0) return 0;
            p += len;
        }
        return p < n ? p + 1 - pos : 0;
    }
    if (c >= '0' && c <= '9') {
        std::size_t colon = pos;
        while (colon < n && d[colon] != ':') ++colon;
        if (colon >= n) return 0;
        std::uint64_t len = 0;
        for (std::size_t i = pos; i < colon; ++i) len = len * 10 + std::uint64_t(d[i] - '0');
        const std::size_t total = (colon + 1 - pos) + len;
        return (pos + total <= n) ? total : 0;
    }
    return 0;
}

const librats::BencodeValue* find(const librats::BencodeValue& dict, const char* key) {
    return dict.find(key);
}

std::optional<std::int64_t> find_int(const librats::BencodeValue& dict, const char* key) {
    const auto* v = find(dict, key);
    if (v && v->is_integer()) return v->as_integer();
    return std::nullopt;
}

} // namespace

Bytes encode_handshake(std::uint32_t metadata_size, std::uint16_t listen_port) {
    librats::BencodeValue d = librats::BencodeValue::create_dict();
    librats::BencodeValue m = librats::BencodeValue::create_dict();
    m["ut_metadata"] = librats::BencodeValue(std::int64_t(kUtMetadataLocalId));
    m["ut_pex"]      = librats::BencodeValue(std::int64_t(kUtPexLocalId));
    d["m"]           = m;
    if (metadata_size > 0) d["metadata_size"] = librats::BencodeValue(std::int64_t(metadata_size));
    if (listen_port > 0)   d["p"]             = librats::BencodeValue(std::int64_t(listen_port));
    d["v"] = librats::BencodeValue(std::string("librats"));
    return d.encode();
}

std::optional<PeerExtensions> decode_handshake(ByteView payload) {
    try {
        librats::BencodeValue d = librats::BencodeDecoder::decode(payload.data(), payload.size());
        if (!d.is_dict()) return std::nullopt;
        PeerExtensions ext;
        if (const auto* m = find(d, "m"); m && m->is_dict()) {
            if (auto v = find_int(*m, "ut_metadata")) ext.ut_metadata_id = std::uint8_t(*v);
            if (auto v = find_int(*m, "ut_pex"))      ext.ut_pex_id      = std::uint8_t(*v);
        }
        if (auto v = find_int(d, "metadata_size"); v && *v > 0) ext.metadata_size = std::uint32_t(*v);
        if (auto v = find_int(d, "p"); v && *v > 0)             ext.listen_port   = std::uint16_t(*v);
        return ext;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

Bytes encode_metadata_request(std::uint32_t piece) {
    librats::BencodeValue d = librats::BencodeValue::create_dict();
    d["msg_type"] = librats::BencodeValue(std::int64_t(MetadataType::Request));
    d["piece"]    = librats::BencodeValue(std::int64_t(piece));
    return d.encode();
}

Bytes encode_metadata_reject(std::uint32_t piece) {
    librats::BencodeValue d = librats::BencodeValue::create_dict();
    d["msg_type"] = librats::BencodeValue(std::int64_t(MetadataType::Reject));
    d["piece"]    = librats::BencodeValue(std::int64_t(piece));
    return d.encode();
}

Bytes encode_metadata_data(std::uint32_t piece, std::uint32_t total_size, ByteView block) {
    librats::BencodeValue d = librats::BencodeValue::create_dict();
    d["msg_type"]   = librats::BencodeValue(std::int64_t(MetadataType::Data));
    d["piece"]      = librats::BencodeValue(std::int64_t(piece));
    d["total_size"] = librats::BencodeValue(std::int64_t(total_size));
    Bytes out = d.encode();
    out.insert(out.end(), block.begin(), block.end());
    return out;
}

std::optional<MetadataMessage> decode_metadata(ByteView payload) {
    const std::size_t header_len = bencode_value_length(payload.data(), payload.size());
    if (header_len == 0) return std::nullopt;
    try {
        librats::BencodeValue d = librats::BencodeDecoder::decode(payload.data(), header_len);
        if (!d.is_dict()) return std::nullopt;
        const auto type  = find_int(d, "msg_type");
        const auto piece = find_int(d, "piece");
        if (!type || !piece) return std::nullopt;

        MetadataMessage msg;
        msg.type  = MetadataType(*type);
        msg.piece = std::uint32_t(*piece);
        if (msg.type == MetadataType::Data) {
            if (auto ts = find_int(d, "total_size")) msg.total_size = std::uint32_t(*ts);
            msg.block.assign(payload.begin() + std::ptrdiff_t(header_len), payload.end());
        }
        return msg;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

Bytes encode_pex(const std::vector<PexPeer>& added, const std::vector<PexPeer>& dropped) {
    librats::BencodeValue d = librats::BencodeValue::create_dict();
    d["added"]   = librats::BencodeValue(compact(added));
    d["dropped"] = librats::BencodeValue(compact(dropped));
    return d.encode();
}

std::optional<PexMessage> decode_pex(ByteView payload) {
    try {
        librats::BencodeValue d = librats::BencodeDecoder::decode(payload.data(), payload.size());
        if (!d.is_dict()) return std::nullopt;
        PexMessage msg;
        if (const auto* a = find(d, "added");   a && a->is_string()) msg.added   = uncompact(a->as_string());
        if (const auto* dr = find(d, "dropped"); dr && dr->is_string()) msg.dropped = uncompact(dr->as_string());
        return msg;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

} // namespace librats::bittorrent::ext
