// ─────────────────────────────────────────────────────────────────────────────
//  bench_complex.cpp — one deliberately nasty document.
//
//  A single deeply-nested, heterogeneous JSON tree that mixes everything a real
//  payload throws at a DOM library at once:
//    • deep nesting (a recursive "tree" of regions → zones → racks → nodes)
//    • large arrays (per-node metric series: thousands of float/int samples)
//    • every scalar kind (signed, unsigned, huge uint64, float, bool, null)
//    • escape/Unicode-heavy strings interleaved with escape-free ones
//    • wide objects (per-node tag maps with many keys → hash-index path)
//    • mixed-type arrays (objects, arrays, scalars side by side)
//
//  We measure parse, serialize (compact + pretty), full-tree walk with typed
//  extraction, and a parse→dump→parse round-trip equality check, comparing
//  librats::Json against nlohmann::json and RapidJSON on the SAME bytes.
// ─────────────────────────────────────────────────────────────────────────────

#include "framework/bench.h"
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

// ── A tiny deterministic PRNG so the document is identical every run ──────────
struct Rng {
    uint64_t s;
    explicit Rng(uint64_t seed) : s(seed ? seed : 0x9e3779b97f4a7c15ull) {}
    uint64_t next() { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s; }
    int range(int lo, int hi) { return lo + static_cast<int>(next() % static_cast<uint64_t>(hi - lo + 1)); }
    double unit() { return static_cast<double>(next() >> 11) * (1.0 / 9007199254740992.0); }
};

// ── Build the complex document directly as text (so parse() is the thing under
//    test, and every library parses byte-identical input) ───────────────────────
namespace {

void emit_escaped_name(std::string& out, Rng& r, int idx) {
    // Half the strings carry escapes / unicode, half are clean — exercises both
    // the fast escape-free run and the slow escape path.
    static const char* unicodes[] = {u8"αβγ", u8"区域", u8"naïve", u8"emoji\\u2764"};
    if (idx % 2 == 0) {
        out += "\"node-";
        out += std::to_string(idx);
        out += "/path\\twith\\ttabs and \\\"quotes\\\" ";
        out += unicodes[r.range(0, 3)];
        out += '"';
    } else {
        out += "\"node_";
        out += std::to_string(idx);
        out += "_clean_ascii_identifier\"";
    }
}

// One leaf node: a wide-ish object with mixed scalars, a big numeric series,
// a tag map (wide object), and a small mixed-type array.
void emit_node(std::string& out, Rng& r, int id, int series_len, int tag_count) {
    out += '{';
    out += "\"id\":"; out += std::to_string(id);
    out += ",\"uuid\":\""; for (int i = 0; i < 4; ++i) { char b[9]; std::snprintf(b, sizeof b, "%08x", static_cast<unsigned>(r.next())); out += b; } out += '"';
    out += ",\"name\":"; emit_escaped_name(out, r, id);
    out += ",\"active\":"; out += (r.range(0, 1) ? "true" : "false");
    out += ",\"parent\":"; if (id == 0) out += "null"; else out += std::to_string(id - 1);
    out += ",\"big_counter\":"; out += std::to_string(9000000000000000000ull + static_cast<uint64_t>(r.next() >> 4)); // huge uint64
    out += ",\"signed_delta\":"; out += std::to_string(-(r.range(1, 1000000)));                                        // negative
    out += ",\"ratio\":"; { char b[32]; std::snprintf(b, sizeof b, "%.12g", r.unit() * 1e6 - 5e5); out += b; }          // float
    // big numeric series array (alternating int / float)
    out += ",\"series\":[";
    for (int i = 0; i < series_len; ++i) {
        if (i) out += ',';
        if (i & 1) { char b[32]; std::snprintf(b, sizeof b, "%.9g", r.unit() * 1e3); out += b; }
        else out += std::to_string(r.range(-100000, 100000));
    }
    out += ']';
    // wide tag object (hash-index path)
    out += ",\"tags\":{";
    for (int i = 0; i < tag_count; ++i) {
        if (i) out += ',';
        out += "\"tag_key_"; out += std::to_string(i); out += "\":";
        switch (i % 4) {
            case 0: out += '"'; out += "v"; out += std::to_string(r.next() % 1000); out += '"'; break;
            case 1: out += std::to_string(r.range(0, 1 << 20)); break;
            case 2: out += (r.range(0, 1) ? "true" : "false"); break;
            default: { char b[24]; std::snprintf(b, sizeof b, "%.6g", r.unit()); out += b; } break;
        }
    }
    out += '}';
    // small mixed-type array: scalar, array, object cheek by jowl
    out += ",\"mixed\":[";
    out += std::to_string(r.range(0, 9)); out += ",\"s\",[1,2,[3,[4,5]]],{\"k\":null,\"f\":";
    { char b[24]; std::snprintf(b, sizeof b, "%.4g", r.unit()); out += b; } out += "}]";
    out += '}';
}

// Recursive container: a region holds metadata, a big array of child regions
// (until depth runs out), and at the bottom a fan of leaf nodes.
void emit_region(std::string& out, Rng& r, int depth, int& node_id,
                 int fanout, int leaf_per_region, int series_len, int tag_count) {
    out += '{';
    out += "\"level\":"; out += std::to_string(depth);
    out += ",\"label\":\"region-L"; out += std::to_string(depth); out += "\"";
    out += ",\"coord\":["; { for (int i = 0; i < 3; ++i) { if (i) out += ','; char b[24]; std::snprintf(b, sizeof b, "%.8g", r.unit() * 360 - 180); out += b; } } out += ']';
    out += ",\"flags\":[true,false,null,true,";
    out += std::to_string(r.range(0, 255)); out += "]";

    if (depth > 0) {
        out += ",\"children\":[";
        for (int i = 0; i < fanout; ++i) {
            if (i) out += ',';
            emit_region(out, r, depth - 1, node_id, fanout, leaf_per_region, series_len, tag_count);
        }
        out += ']';
    } else {
        out += ",\"nodes\":[";
        for (int i = 0; i < leaf_per_region; ++i) {
            if (i) out += ',';
            emit_node(out, r, node_id++, series_len, tag_count);
        }
        out += ']';
    }
    out += '}';
}

std::string build_complex_document(int depth, int fanout, int leaf_per_region,
                                   int series_len, int tag_count) {
    Rng r(0xC0FFEEull);
    std::string out;
    out.reserve(4u * 1024 * 1024);
    out += '{';
    out += "\"schema\":\"librats.complex.v1\",";
    out += "\"generated_unix\":1750000000000,";
    out += "\"meta\":{\"depth\":"; out += std::to_string(depth);
    out += ",\"fanout\":"; out += std::to_string(fanout);
    out += ",\"pi\":3.141592653589793,\"big\":18446744073709551615,";
    out += "\"note\":\"mixed \\u2603 snowman / tab\\there / quote\\\" end\"},";
    out += "\"root\":";
    int node_id = 0;
    emit_region(out, r, depth, node_id, fanout, leaf_per_region, series_len, tag_count);
    out += '}';
    return out;
}

// Recursively walk a librats::Json, touching every scalar so the optimizer can't
// elide the traversal and so we exercise typed extraction across all kinds.
struct Acc { long long ints = 0; double floats = 0; std::size_t strs = 0; std::size_t bools = 0, nulls = 0; };

void walk(const librats::Json& j, Acc& a) {
    switch (j.type()) {
        case librats::Json::Type::Object:
            for (const auto& kv : j.as_object()) { a.strs += kv.first.size(); walk(kv.second, a); }
            break;
        case librats::Json::Type::Array:
            for (const librats::Json& e : j.as_array()) walk(e, a);
            break;
        case librats::Json::Type::String:   a.strs += j.get<std::string>().size(); break;
        case librats::Json::Type::Integer:
        case librats::Json::Type::Unsigned: a.ints += j.get<long long>(); break;
        case librats::Json::Type::Float:    a.floats += j.get<double>(); break;
        case librats::Json::Type::Boolean:  a.bools += j.get<bool>() ? 1 : 0; break;
        default: a.nulls++; break;
    }
}

#ifdef HAVE_NLOHMANN
void walk_nl(const nlohmann::json& j, Acc& a) {
    if (j.is_object()) { for (auto it = j.begin(); it != j.end(); ++it) { a.strs += it.key().size(); walk_nl(it.value(), a); } }
    else if (j.is_array()) { for (const auto& e : j) walk_nl(e, a); }
    else if (j.is_string()) a.strs += j.get<std::string>().size();
    else if (j.is_number_float()) a.floats += j.get<double>();
    else if (j.is_number()) a.ints += j.get<long long>();
    else if (j.is_boolean()) a.bools += j.get<bool>() ? 1 : 0;
    else a.nulls++;
}
#endif
#ifdef HAVE_RAPIDJSON
void walk_rj(const rapidjson::Value& v, Acc& a) {
    if (v.IsObject()) { for (auto it = v.MemberBegin(); it != v.MemberEnd(); ++it) { a.strs += it->name.GetStringLength(); walk_rj(it->value, a); } }
    else if (v.IsArray()) { for (auto& e : v.GetArray()) walk_rj(e, a); }
    else if (v.IsString()) a.strs += v.GetStringLength();
    else if (v.IsDouble()) a.floats += v.GetDouble();
    else if (v.IsInt64()) a.ints += v.GetInt64();
    else if (v.IsUint64()) a.ints += static_cast<long long>(v.GetUint64());
    else if (v.IsBool()) a.bools += v.GetBool() ? 1 : 0;
    else a.nulls++;
}
#endif

} // namespace

int main() {
    // depth 6, fanout 3 → 3^6 = 729 leaf regions, each with leaf nodes.
    const int depth = 6, fanout = 3, leaf_per_region = 4, series_len = 64, tag_count = 24;
    const std::string src = build_complex_document(depth, fanout, leaf_per_region, series_len, tag_count);

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
    std::printf("\n");

    // Count leaf nodes for context.
    int leaves = 1; for (int i = 0; i < depth; ++i) leaves *= fanout; leaves *= leaf_per_region;
    std::printf("complex document: %.2f MB  |  nesting depth ~%d  |  %d leaf nodes  |  series=%d  tags/node=%d\n\n",
                src.size() / (1024.0 * 1024.0), depth + 6, leaves, series_len, tag_count);

    // ── Correctness gate: parse with every library, walk it, and round-trip
    //    librats (parse → dump → parse) for byte/structural stability. If this
    //    fails, the speed numbers below are meaningless — so check first. ──────
    {
        librats::Json j = librats::Json::parse(src);
        Acc a; walk(j, a);
        std::string redump = j.dump();
        librats::Json j2 = librats::Json::parse(redump);
        bool roundtrip_ok = (j == j2);
        bool redump_stable = (redump == j2.dump());
        std::printf("librats parse OK: ints=%lld floats=%.3g strs=%zu bools=%zu nulls=%zu\n",
                    a.ints, a.floats, a.strs, a.bools, a.nulls);
        std::printf("librats round-trip (parse==parse(dump)): %s   redump-stable: %s\n",
                    roundtrip_ok ? "PASS" : "*** FAIL ***", redump_stable ? "PASS" : "*** FAIL ***");
#ifdef HAVE_NLOHMANN
        nlohmann::json nl = nlohmann::json::parse(src);
        Acc an; walk_nl(nl, an);
        std::printf("cross-check vs nlohmann: ints %s  floats %s  bools %s  nulls %s\n",
                    a.ints == an.ints ? "match" : "DIFF",
                    (a.floats - an.floats) * (a.floats - an.floats) < 1e-3 ? "match" : "DIFF",
                    a.bools == an.bools ? "match" : "DIFF",
                    a.nulls == an.nulls ? "match" : "DIFF");
#endif
        std::printf("\n");
    }

    bench::Bench b("librats::Json — one big complex document");
    b.config().min_time = 0.5;
    b.config().rounds   = 9;

    // ── PARSE ────────────────────────────────────────────────────────────────
    b.group("Parse · complex document");
    b.bytes(static_cast<double>(src.size()));
    b.run("librats", [&] { auto j = librats::Json::parse(src); do_not_optimize(j); });
#ifdef HAVE_NLOHMANN
    b.run("nlohmann", [&] { auto j = nlohmann::json::parse(src); do_not_optimize(j); });
#endif
#ifdef HAVE_RAPIDJSON
    b.run("rapidjson", [&] { rapidjson::Document d; d.Parse(src.c_str(), src.size()); do_not_optimize(d); });
#endif

    // Pre-parsed DOMs for the downstream benchmarks.
    librats::Json lr = librats::Json::parse(src);
#ifdef HAVE_NLOHMANN
    nlohmann::json nl = nlohmann::json::parse(src);
#endif
#ifdef HAVE_RAPIDJSON
    rapidjson::Document rj; rj.Parse(src.c_str(), src.size());
#endif

    // ── SERIALIZE compact ────────────────────────────────────────────────────
    const std::string compact = lr.dump();
    b.group("Serialize compact · complex document");
    b.bytes(static_cast<double>(compact.size()));
    b.run("librats", [&] { std::string s = lr.dump(); do_not_optimize(s); });
#ifdef HAVE_NLOHMANN
    b.run("nlohmann", [&] { std::string s = nl.dump(); do_not_optimize(s); });
#endif
#ifdef HAVE_RAPIDJSON
    b.run("rapidjson", [&] {
        rapidjson::StringBuffer sb; rapidjson::Writer<rapidjson::StringBuffer> w(sb);
        rj.Accept(w); do_not_optimize(sb);
    });
#endif

    // ── SERIALIZE pretty ─────────────────────────────────────────────────────
    b.group("Serialize pretty · complex document  (2-space)");
    b.run("librats", [&] { std::string s = lr.dump(2); do_not_optimize(s); });
#ifdef HAVE_NLOHMANN
    b.run("nlohmann", [&] { std::string s = nl.dump(2); do_not_optimize(s); });
#endif
#ifdef HAVE_RAPIDJSON
    b.run("rapidjson", [&] {
        rapidjson::StringBuffer sb; rapidjson::PrettyWriter<rapidjson::StringBuffer> w(sb);
        w.SetIndent(' ', 2); rj.Accept(w); do_not_optimize(sb);
    });
#endif

    // ── FULL-TREE WALK + typed extraction ────────────────────────────────────
    b.group("Walk + typed extract · whole tree");
    b.run("librats", [&] { Acc a; walk(lr, a); do_not_optimize(a.ints); do_not_optimize(a.floats); });
#ifdef HAVE_NLOHMANN
    b.run("nlohmann", [&] { Acc a; walk_nl(nl, a); do_not_optimize(a.ints); do_not_optimize(a.floats); });
#endif
#ifdef HAVE_RAPIDJSON
    b.run("rapidjson", [&] { Acc a; walk_rj(rj, a); do_not_optimize(a.ints); do_not_optimize(a.floats); });
#endif

    // ── ROUND-TRIP (parse → dump → parse) ────────────────────────────────────
    b.group("Round-trip · parse → dump → parse");
    b.bytes(static_cast<double>(src.size()));
    b.run("librats", [&] {
        auto j = librats::Json::parse(src); auto s = j.dump(); auto j2 = librats::Json::parse(s);
        do_not_optimize(j2);
    });
#ifdef HAVE_NLOHMANN
    b.run("nlohmann", [&] {
        auto j = nlohmann::json::parse(src); auto s = j.dump(); auto j2 = nlohmann::json::parse(s);
        do_not_optimize(j2);
    });
#endif

    b.report();
    return 0;
}
