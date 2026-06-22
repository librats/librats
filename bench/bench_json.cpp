// ─────────────────────────────────────────────────────────────────────────────
//  bench_json.cpp — benchmark librats::Json against the reference DOM libraries
//  (nlohmann::json, RapidJSON) across the key hot paths: parse, serialize
//  (compact + pretty), programmatic DOM construction, and field access.
//
//  All three are *mutable DOM* libraries, so the comparison is apples-to-apples
//  (unlike lazy/SAX parsers such as simdjson). The reference libraries are
//  optional — whichever ones the build found are included; the rest are skipped.
//
//  Datasets are modelled on librats' real traffic: peer records, a small config
//  object, a float-heavy coordinate blob, and an escape/Unicode-heavy string
//  array.
// ─────────────────────────────────────────────────────────────────────────────

#include "bench.h"
#include "util/json.h"

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#if defined(BENCH_HAVE_NLOHMANN) || __has_include(<nlohmann/json.hpp>)
#  include <nlohmann/json.hpp>
#  define HAVE_NLOHMANN 1
#endif

#if defined(BENCH_HAVE_RAPIDJSON) || __has_include(<rapidjson/document.h>)
#  include <rapidjson/document.h>
#  include <rapidjson/prettywriter.h>
#  include <rapidjson/stringbuffer.h>
#  include <rapidjson/writer.h>
#  define HAVE_RAPIDJSON 1
#endif

using bench::do_not_optimize;

// ── Deterministic data generation ────────────────────────────────────────────

namespace {

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

std::vector<Peer> make_peers(int n) {
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
std::string peers_to_json(const std::vector<Peer>& v) {
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
std::string make_config_json() {
    return R"({"version":3,"node":{"id":"a1b2c3d4e5f6","listen_port":8443,
"max_peers":64,"encryption":true,"protocols":["noise_xx","plaintext"]},
"dht":{"enabled":true,"bootstrap":["router.bittorrent.com:6881",
"dht.transmissionbt.com:6881"],"k":8,"alpha":3},"nat":{"upnp":true,"natpmp":true,
"stun_servers":["stun.l.google.com:19302"]},"limits":{"send_hwm":8388608,
"establish_deadline_ms":15000,"reactor_threads":4}})";
}

// Float-heavy blob (canada.json style): an object holding a big coordinate array.
std::string make_numbers_json(int n) {
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
std::string make_strings_json(int n) {
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
std::string make_integers_json(int n) {
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
std::string make_long_strings_json(int n, int len) {
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
std::string make_large_object_json(int n) {
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
std::string make_deep_json(int depth) {
    std::string s;
    for (int i = 0; i < depth; ++i) s += "{\"n\":";
    s += "0";
    for (int i = 0; i < depth; ++i) s += "}";
    return s;
}

}  // namespace

// ── Per-library benchmark wiring ─────────────────────────────────────────────
//
// Each library gets a `parse`, `dump`, `dump_pretty`, `build`, and `access`
// routine. Reference libraries are guarded so the bench builds with any subset.

int main() {
    const auto peers = make_peers(256);
    const std::string peers_src    = peers_to_json(peers);
    const std::string config_src   = make_config_json();
    const std::string numbers_src  = make_numbers_json(2000);
    const std::string strings_src  = make_strings_json(1000);
    const std::string integers_src = make_integers_json(10000);
    const std::string longstr_src  = make_long_strings_json(500, 256);
    const std::string bigobj_src   = make_large_object_json(1000);
    const std::string deep_src     = make_deep_json(256);
    // A valid-looking peers array truncated to malformed: the parser scans the
    // whole payload before rejecting, so this measures reject throughput.
    std::string peers_bad = peers_src;
    peers_bad.back() = ',';

    std::printf("environment: ");
#if defined(__clang__)
    std::printf("clang %d.%d.%d", __clang_major__, __clang_minor__, __clang_patchlevel__);
#elif defined(__GNUC__)
    std::printf("gcc %d.%d.%d", __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#elif defined(_MSC_VER)
    std::printf("msvc %d", _MSC_VER);
#endif
    std::printf("  |  reference libs:");
#ifdef HAVE_NLOHMANN
    std::printf(" nlohmann");
#endif
#ifdef HAVE_RAPIDJSON
    std::printf(" rapidjson");
#endif
    std::printf("\ndatasets: peers=%zuB  config=%zuB  numbers=%zuB  strings=%zuB\n"
                "          integers=%zuB  longstr=%zuB  bigobj=%zuB  deep=%zuB\n",
                peers_src.size(), config_src.size(), numbers_src.size(),
                strings_src.size(), integers_src.size(), longstr_src.size(),
                bigobj_src.size(), deep_src.size());

    bench::Bench b("librats::Json vs reference DOM libraries");
    b.config().min_time = 0.5;
    b.config().rounds   = 9;

    // ── PARSE ────────────────────────────────────────────────────────────────
    auto parse_group = [&](const char* label, const std::string& src) {
        b.group(label);
        b.bytes(static_cast<double>(src.size()));
        b.run("librats", [&] {
            auto j = librats::Json::parse(src);
            do_not_optimize(j);
        });
#ifdef HAVE_NLOHMANN
        b.run("nlohmann", [&] {
            auto j = nlohmann::json::parse(src);
            do_not_optimize(j);
        });
#endif
#ifdef HAVE_RAPIDJSON
        b.run("rapidjson", [&] {
            rapidjson::Document d;
            d.Parse(src.c_str(), src.size());
            do_not_optimize(d);
        });
#endif
    };
    parse_group("Parse · config   (small nested object)", config_src);
    parse_group("Parse · peers    (256 records)", peers_src);
    parse_group("Parse · numbers  (2000 float pairs)", numbers_src);
    parse_group("Parse · strings  (1000 escaped strings)", strings_src);
    parse_group("Parse · integers (10000 int64)", integers_src);
    parse_group("Parse · longstr  (500 × 256B, no escapes)", longstr_src);
    parse_group("Parse · bigobj   (1000-key object)", bigobj_src);
    parse_group("Parse · deep     (256-level nesting)", deep_src);

    // Pre-parsed DOMs reused by serialize / access benchmarks.
    librats::Json lr_peers = librats::Json::parse(peers_src);
    librats::Json lr_ints  = librats::Json::parse(integers_src);
    librats::Json lr_bigobj = librats::Json::parse(bigobj_src);
#ifdef HAVE_NLOHMANN
    nlohmann::json nl_peers = nlohmann::json::parse(peers_src);
    nlohmann::json nl_ints  = nlohmann::json::parse(integers_src);
    nlohmann::json nl_bigobj = nlohmann::json::parse(bigobj_src);
#endif
#ifdef HAVE_RAPIDJSON
    rapidjson::Document rj_peers;
    rj_peers.Parse(peers_src.c_str(), peers_src.size());
    rapidjson::Document rj_ints;
    rj_ints.Parse(integers_src.c_str(), integers_src.size());
    rapidjson::Document rj_bigobj;
    rj_bigobj.Parse(bigobj_src.c_str(), bigobj_src.size());
#endif

    // ── SERIALIZE (compact) ──────────────────────────────────────────────────
    b.group("Serialize compact · peers");
    b.bytes(static_cast<double>(peers_src.size()));
    b.run("librats", [&] {
        std::string s = lr_peers.dump();
        do_not_optimize(s);
    });
#ifdef HAVE_NLOHMANN
    b.run("nlohmann", [&] {
        std::string s = nl_peers.dump();
        do_not_optimize(s);
    });
#endif
#ifdef HAVE_RAPIDJSON
    b.run("rapidjson", [&] {
        rapidjson::StringBuffer sb;
        rapidjson::Writer<rapidjson::StringBuffer> w(sb);
        rj_peers.Accept(w);
        do_not_optimize(sb);
    });
#endif

    // ── SERIALIZE (pretty, 2-space) ──────────────────────────────────────────
    b.group("Serialize pretty · peers  (2-space indent)");
    b.run("librats", [&] {
        std::string s = lr_peers.dump(2);
        do_not_optimize(s);
    });
#ifdef HAVE_NLOHMANN
    b.run("nlohmann", [&] {
        std::string s = nl_peers.dump(2);
        do_not_optimize(s);
    });
#endif
#ifdef HAVE_RAPIDJSON
    b.run("rapidjson", [&] {
        rapidjson::StringBuffer sb;
        rapidjson::PrettyWriter<rapidjson::StringBuffer> w(sb);
        w.SetIndent(' ', 2);
        rj_peers.Accept(w);
        do_not_optimize(sb);
    });
#endif

    // ── DOM BUILD (programmatic construction) ────────────────────────────────
    b.group("DOM build · 256 peer objects");
    b.bytes(static_cast<double>(peers_src.size()));
    b.run("librats", [&] {
        librats::Json arr = librats::Json::array();
        for (const Peer& p : peers) {
            librats::Json o = librats::Json::object();
            o["id"]        = p.id;
            o["ip"]        = p.ip;
            o["port"]      = p.port;
            o["last_seen"] = p.last_seen;
            o["score"]     = p.score;
            o["seed"]      = p.seed;
            o["agent"]     = p.agent;
            arr.push_back(std::move(o));
        }
        do_not_optimize(arr);
    });
#ifdef HAVE_NLOHMANN
    b.run("nlohmann", [&] {
        nlohmann::json arr = nlohmann::json::array();
        for (const Peer& p : peers) {
            nlohmann::json o = nlohmann::json::object();
            o["id"]        = p.id;
            o["ip"]        = p.ip;
            o["port"]      = p.port;
            o["last_seen"] = p.last_seen;
            o["score"]     = p.score;
            o["seed"]      = p.seed;
            o["agent"]     = p.agent;
            arr.push_back(std::move(o));
        }
        do_not_optimize(arr);
    });
#endif
#ifdef HAVE_RAPIDJSON
    b.run("rapidjson", [&] {
        rapidjson::Document d;
        d.SetArray();
        auto& al = d.GetAllocator();
        for (const Peer& p : peers) {
            rapidjson::Value o(rapidjson::kObjectType);
            o.AddMember("id", rapidjson::Value(p.id.c_str(), al), al);
            o.AddMember("ip", rapidjson::Value(p.ip.c_str(), al), al);
            o.AddMember("port", p.port, al);
            o.AddMember("last_seen", p.last_seen, al);
            o.AddMember("score", p.score, al);
            o.AddMember("seed", p.seed, al);
            o.AddMember("agent", rapidjson::Value(p.agent.c_str(), al), al);
            d.PushBack(o, al);
        }
        do_not_optimize(d);
    });
#endif

    // ── FIELD ACCESS (traverse + typed extraction) ───────────────────────────
    b.group("Field access · sum over 256 peers");
    b.items(static_cast<double>(peers.size()));
    b.run("librats", [&] {
        long long acc = 0;
        double sc = 0;
        for (librats::Json& e : lr_peers.as_array()) {
            acc += e["port"].get<long long>();
            acc += e["last_seen"].get<long long>();
            sc  += e["score"].get<double>();
            if (e["seed"].get<bool>()) ++acc;
        }
        do_not_optimize(acc);
        do_not_optimize(sc);
    });
#ifdef HAVE_NLOHMANN
    b.run("nlohmann", [&] {
        long long acc = 0;
        double sc = 0;
        for (auto& e : nl_peers) {
            acc += e["port"].get<long long>();
            acc += e["last_seen"].get<long long>();
            sc  += e["score"].get<double>();
            if (e["seed"].get<bool>()) ++acc;
        }
        do_not_optimize(acc);
        do_not_optimize(sc);
    });
#endif
#ifdef HAVE_RAPIDJSON
    b.run("rapidjson", [&] {
        long long acc = 0;
        double sc = 0;
        for (auto& e : rj_peers.GetArray()) {
            acc += e["port"].GetInt();
            acc += e["last_seen"].GetInt64();
            sc  += e["score"].GetDouble();
            if (e["seed"].GetBool()) ++acc;
        }
        do_not_optimize(acc);
        do_not_optimize(sc);
    });
#endif

    // ── SERIALIZE compact · integers (to_chars path) ─────────────────────────
    b.group("Serialize compact · integers");
    b.bytes(static_cast<double>(integers_src.size()));
    b.run("librats", [&] {
        std::string s = lr_ints.dump();
        do_not_optimize(s);
    });
#ifdef HAVE_NLOHMANN
    b.run("nlohmann", [&] {
        std::string s = nl_ints.dump();
        do_not_optimize(s);
    });
#endif
#ifdef HAVE_RAPIDJSON
    b.run("rapidjson", [&] {
        rapidjson::StringBuffer sb;
        rapidjson::Writer<rapidjson::StringBuffer> w(sb);
        rj_ints.Accept(w);
        do_not_optimize(sb);
    });
#endif

    // ── SERIALIZE compact · longstr (escape-free run batching) ───────────────
    librats::Json lr_long = librats::Json::parse(longstr_src);
#ifdef HAVE_NLOHMANN
    nlohmann::json nl_long = nlohmann::json::parse(longstr_src);
#endif
#ifdef HAVE_RAPIDJSON
    rapidjson::Document rj_long;
    rj_long.Parse(longstr_src.c_str(), longstr_src.size());
#endif
    b.group("Serialize compact · longstr");
    b.bytes(static_cast<double>(longstr_src.size()));
    b.run("librats", [&] {
        std::string s = lr_long.dump();
        do_not_optimize(s);
    });
#ifdef HAVE_NLOHMANN
    b.run("nlohmann", [&] {
        std::string s = nl_long.dump();
        do_not_optimize(s);
    });
#endif
#ifdef HAVE_RAPIDJSON
    b.run("rapidjson", [&] {
        rapidjson::StringBuffer sb;
        rapidjson::Writer<rapidjson::StringBuffer> w(sb);
        rj_long.Accept(w);
        do_not_optimize(sb);
    });
#endif

    // Keys for the wide-object build / lookup benchmarks.
    const int kBigKeys = 1000;
    std::vector<std::string> keys;
    keys.reserve(kBigKeys);
    for (int i = 0; i < kBigKeys; ++i) keys.push_back("key_" + std::to_string(i));

    // ── DOM build · 1000-key object (indexed insert path) ────────────────────
    b.group("DOM build · 1000-key object");
    b.bytes(static_cast<double>(bigobj_src.size()));
    b.run("librats", [&] {
        librats::Json o = librats::Json::object();
        for (int i = 0; i < kBigKeys; ++i) o[keys[i]] = i;
        do_not_optimize(o);
    });
#ifdef HAVE_NLOHMANN
    b.run("nlohmann", [&] {
        nlohmann::json o = nlohmann::json::object();
        for (int i = 0; i < kBigKeys; ++i) o[keys[i]] = i;
        do_not_optimize(o);
    });
#endif
#ifdef HAVE_RAPIDJSON
    b.run("rapidjson", [&] {
        rapidjson::Document d;
        d.SetObject();
        auto& al = d.GetAllocator();
        for (int i = 0; i < kBigKeys; ++i) {
            rapidjson::Value k(keys[i].c_str(), al);
            d.AddMember(k, rapidjson::Value(i), al);
        }
        do_not_optimize(d);
    });
#endif

    // ── Keyed lookup · 1000 hits in the wide object (hash path) ──────────────
    b.group("Keyed lookup · 1000-key object");
    b.items(static_cast<double>(kBigKeys));
    b.run("librats", [&] {
        const librats::Json& o = lr_bigobj;
        long long acc = 0;
        for (const std::string& k : keys) acc += o[k].get<long long>();
        do_not_optimize(acc);
    });
#ifdef HAVE_NLOHMANN
    b.run("nlohmann", [&] {
        const nlohmann::json& o = nl_bigobj;
        long long acc = 0;
        for (const std::string& k : keys) acc += o[k].get<long long>();
        do_not_optimize(acc);
    });
#endif
#ifdef HAVE_RAPIDJSON
    b.run("rapidjson", [&] {
        long long acc = 0;
        for (const std::string& k : keys) acc += rj_bigobj[k.c_str()].GetInt64();
        do_not_optimize(acc);
    });
#endif

    // ── Reject · malformed input (non-throwing parse, robustness) ────────────
    b.group("Reject · malformed peers  (non-throwing)");
    b.bytes(static_cast<double>(peers_bad.size()));
    b.run("librats", [&] {
        auto j = librats::Json::parse(peers_bad, nullptr, false);
        do_not_optimize(j);
    });
#ifdef HAVE_NLOHMANN
    b.run("nlohmann", [&] {
        auto j = nlohmann::json::parse(peers_bad, nullptr, false);
        do_not_optimize(j);
    });
#endif
#ifdef HAVE_RAPIDJSON
    b.run("rapidjson", [&] {
        rapidjson::Document d;
        d.Parse(peers_bad.c_str(), peers_bad.size());
        do_not_optimize(d);
    });
#endif

    b.report();
    return 0;
}
