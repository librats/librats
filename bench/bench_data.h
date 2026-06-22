#pragma once

// ─────────────────────────────────────────────────────────────────────────────
//  bench_data.h — deterministic JSON dataset generators shared by the timing
//  benchmark (bench_json.cpp) and the memory-footprint benchmark (bench_mem.cpp).
//
//  Every generator is seeded from a fixed constant so all runs — and both
//  executables — operate on byte-for-byte identical inputs. The datasets are
//  modelled on librats' real traffic plus a few general-purpose shapes (wide
//  objects, integer arrays, long strings, deep nesting).
// ─────────────────────────────────────────────────────────────────────────────

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace benchdata {

// Tiny deterministic PRNG so every run benches identical inputs.
struct Rng {
    uint64_t s;
    explicit Rng(uint64_t seed) : s(seed ? seed : 0x9E3779B97F4A7C15ull) {}
    uint64_t next() {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        return s;
    }
    uint32_t u32(uint32_t lo, uint32_t hi) {
        return lo + static_cast<uint32_t>(next() % (hi - lo + 1));
    }
    double unit() { return (next() >> 11) * (1.0 / 9007199254740992.0); }
};

struct Peer {
    std::string id;      // 40-hex node id
    std::string ip;
    int port;
    int64_t last_seen;
    double score;
    bool seed;
    std::string agent;
};

inline std::vector<Peer> make_peers(int n) {
    Rng rng(0xCAFEBABEull);
    std::vector<Peer> v;
    v.reserve(n);
    static const char* agents[] = {"librats/1.4", "rats-search/0.9", "libtorrent/2.0",
                                    "transmission/4.0"};
    for (int i = 0; i < n; ++i) {
        Peer p;
        char id[41];
        for (int k = 0; k < 40; ++k) id[k] = "0123456789abcdef"[rng.next() & 0xF];
        id[40] = '\0';
        p.id = id;
        char ip[24];
        std::snprintf(ip, sizeof ip, "%u.%u.%u.%u", rng.u32(1, 254), rng.u32(0, 255),
                      rng.u32(0, 255), rng.u32(1, 254));
        p.ip = ip;
        p.port = static_cast<int>(rng.u32(1024, 65535));
        p.last_seen = 1700000000ll + rng.next() % 30000000;
        p.score = rng.unit() * 100.0;
        p.seed = (rng.next() & 1) != 0;
        p.agent = agents[rng.next() % 4];
        v.push_back(std::move(p));
    }
    return v;
}

// Serialize the peer vector to a compact JSON array string (library-neutral).
inline std::string peers_to_json(const std::vector<Peer>& v) {
    std::string s = "[";
    char buf[96];
    for (std::size_t i = 0; i < v.size(); ++i) {
        const Peer& p = v[i];
        if (i) s += ',';
        s += "{\"id\":\"" + p.id + "\",\"ip\":\"" + p.ip + "\",\"port\":";
        std::snprintf(buf, sizeof buf, "%d", p.port);
        s += buf;
        s += ",\"last_seen\":";
        std::snprintf(buf, sizeof buf, "%lld", static_cast<long long>(p.last_seen));
        s += buf;
        s += ",\"score\":";
        std::snprintf(buf, sizeof buf, "%.6f", p.score);
        s += buf;
        s += ",\"seed\":";
        s += p.seed ? "true" : "false";
        s += ",\"agent\":\"" + p.agent + "\"}";
    }
    s += "]";
    return s;
}

// A small, deeply-typed config object — the shape librats serializes constantly.
inline std::string make_config_json() {
    return R"({"version":3,"node":{"id":"a1b2c3d4e5f6","listen_port":8443,
"max_peers":64,"encryption":true,"protocols":["noise_xx","plaintext"]},
"dht":{"enabled":true,"bootstrap":["router.bittorrent.com:6881",
"dht.transmissionbt.com:6881"],"k":8,"alpha":3},"nat":{"upnp":true,"natpmp":true,
"stun_servers":["stun.l.google.com:19302"]},"limits":{"send_hwm":8388608,
"establish_deadline_ms":15000,"reactor_threads":4}})";
}

// Float-heavy blob (canada.json style): an object holding a big coordinate array.
inline std::string make_numbers_json(int n) {
    Rng rng(0x1234567ull);
    std::string s = "{\"coordinates\":[";
    char buf[64];
    for (int i = 0; i < n; ++i) {
        if (i) s += ',';
        double lat = rng.unit() * 180.0 - 90.0;
        double lon = rng.unit() * 360.0 - 180.0;
        std::snprintf(buf, sizeof buf, "[%.10f,%.10f]", lat, lon);
        s += buf;
    }
    s += "]}";
    return s;
}

// String-heavy array with escapes and a Unicode escape on every element.
inline std::string make_strings_json(int n) {
    std::string s = "[";
    for (int i = 0; i < n; ++i) {
        if (i) s += ',';
        s += "\"line ";
        s += std::to_string(i);
        s += ":\\t\\\"quoted\\\"\\nand a \\u00e9 caf\\u00e9 \\\\ path\\\\to\\\\x\"";
    }
    s += "]";
    return s;
}

// Flat array of full-range signed 64-bit integers — isolates the integer
// conversion path (from_chars / to_chars) that the float blob never touches.
inline std::string make_integers_json(int n) {
    Rng rng(0xABCDEF01ull);
    std::string s = "[";
    char buf[32];
    for (int i = 0; i < n; ++i) {
        if (i) s += ',';
        int64_t v = static_cast<int64_t>(rng.next());  // spans negatives and >2^53
        std::snprintf(buf, sizeof buf, "%lld", static_cast<long long>(v));
        s += buf;
    }
    s += "]";
    return s;
}

// Array of long, escape-free strings (base64-like blobs — certs, payloads): the
// case the run-batching serializer/parser is built for, and the mirror image of
// the deliberately escape-heavy make_strings_json above.
inline std::string make_long_strings_json(int n, int len) {
    Rng rng(0x55AA55AAull);
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string s = "[";
    for (int i = 0; i < n; ++i) {
        if (i) s += ',';
        s += '"';
        for (int k = 0; k < len; ++k) s += alphabet[rng.next() & 63];
        s += '"';
    }
    s += "]";
    return s;
}

// One wide object whose key count is well past the lazy-index threshold, so the
// hash-backed lookup path (not just the small-object linear scan) is exercised.
inline std::string make_large_object_json(int n) {
    std::string s = "{";
    char buf[40];
    for (int i = 0; i < n; ++i) {
        if (i) s += ',';
        int klen = std::snprintf(buf, sizeof buf, "\"key_%d\":%d", i, i);
        s.append(buf, static_cast<std::size_t>(klen));
    }
    s += "}";
    return s;
}

// A chain of nested objects {"n":{"n":{ … 0 … }}} — stresses the recursive
// descent and the dump recursion (depth stays under the parser's 1000 guard).
inline std::string make_deep_json(int depth) {
    std::string s;
    for (int i = 0; i < depth; ++i) s += "{\"n\":";
    s += "0";
    for (int i = 0; i < depth; ++i) s += "}";
    return s;
}

}  // namespace benchdata
