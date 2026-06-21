#include <gtest/gtest.h>

#include "util/json.h"

#include <cmath>
#include <cstdint>
#include <limits>
#include <sstream>
#include <string>

using librats::Json;
using librats::JsonError;

// ─────────────────────────────────────────────────────────────────────────────
// Construction & type inspection
// ─────────────────────────────────────────────────────────────────────────────

TEST(JsonConstruct, DefaultIsNull) {
    Json j;
    EXPECT_TRUE(j.is_null());
    EXPECT_TRUE(j.empty());
    EXPECT_EQ(j.size(), 0u);
    EXPECT_EQ(j.dump(), "null");
}

TEST(JsonConstruct, Nullptr) {
    Json j(nullptr);
    EXPECT_TRUE(j.is_null());
}

TEST(JsonConstruct, Boolean) {
    Json t(true), f(false);
    EXPECT_TRUE(t.is_boolean());
    EXPECT_TRUE(f.is_boolean());
    EXPECT_EQ(t.dump(), "true");
    EXPECT_EQ(f.dump(), "false");
    EXPECT_TRUE(t.get<bool>());
    EXPECT_FALSE(f.get<bool>());
}

TEST(JsonConstruct, SignedInteger) {
    Json j(-42);
    EXPECT_TRUE(j.is_number());
    EXPECT_TRUE(j.is_number_integer());
    EXPECT_FALSE(j.is_number_unsigned());
    EXPECT_EQ(j.get<int>(), -42);
    EXPECT_EQ(j.dump(), "-42");
}

TEST(JsonConstruct, UnsignedInteger) {
    Json j(static_cast<unsigned>(42));
    EXPECT_TRUE(j.is_number_integer());
    EXPECT_TRUE(j.is_number_unsigned());
    EXPECT_EQ(j.get<unsigned>(), 42u);
    EXPECT_EQ(j.dump(), "42");
}

TEST(JsonConstruct, Double) {
    Json j(3.5);
    EXPECT_TRUE(j.is_number_float());
    EXPECT_DOUBLE_EQ(j.get<double>(), 3.5);
}

TEST(JsonConstruct, CStringAndStdString) {
    Json a("hello");
    Json b(std::string("world"));
    EXPECT_TRUE(a.is_string());
    EXPECT_TRUE(b.is_string());
    EXPECT_EQ(a.get<std::string>(), "hello");
    EXPECT_EQ(b.get<std::string>(), "world");
    EXPECT_EQ(a.dump(), "\"hello\"");
}

TEST(JsonConstruct, NullCStringIsEmpty) {
    const char* p = nullptr;
    Json j(p);
    EXPECT_TRUE(j.is_string());
    EXPECT_EQ(j.get<std::string>(), "");
}

TEST(JsonConstruct, ExplicitArrayAndObject) {
    Json a = Json::array();
    Json o = Json::object();
    EXPECT_TRUE(a.is_array());
    EXPECT_TRUE(o.is_object());
    EXPECT_TRUE(a.empty());
    EXPECT_TRUE(o.empty());
    EXPECT_EQ(a.dump(), "[]");
    EXPECT_EQ(o.dump(), "{}");
}

// ─────────────────────────────────────────────────────────────────────────────
// Initializer-list object/array detection (nlohmann-style)
// ─────────────────────────────────────────────────────────────────────────────

TEST(JsonInitList, ObjectDetection) {
    Json j = {{"hello", "world"}, {"n", 7}};
    EXPECT_TRUE(j.is_object());
    EXPECT_EQ(j.size(), 2u);
    EXPECT_EQ(j["hello"].get<std::string>(), "world");
    EXPECT_EQ(j["n"].get<int>(), 7);
}

TEST(JsonInitList, ArrayWhenNotAllPairs) {
    Json j = {1, 2, 3, 4, 5};
    EXPECT_TRUE(j.is_array());
    EXPECT_EQ(j.size(), 5u);
    EXPECT_EQ(j[0].get<int>(), 1);
    EXPECT_EQ(j[4].get<int>(), 5);
}

TEST(JsonInitList, TwoStringsIsArrayNotObject) {
    Json j = {"name", "value"};  // both elements scalar strings -> array
    EXPECT_TRUE(j.is_array());
    EXPECT_EQ(j.size(), 2u);
    EXPECT_EQ(j[0].get<std::string>(), "name");
}

TEST(JsonInitList, NestedObjectsAndArrays) {
    Json j = {
        {"name", "test"},
        {"count", 42},
        {"nested", {{"a", 1}, {"b", 2}}},
        {"array", {1, 2, 3, 4, 5}},
    };
    ASSERT_TRUE(j.is_object());
    EXPECT_EQ(j["name"].get<std::string>(), "test");
    EXPECT_EQ(j["count"].get<int>(), 42);
    ASSERT_TRUE(j["nested"].is_object());
    EXPECT_EQ(j["nested"]["a"].get<int>(), 1);
    EXPECT_EQ(j["nested"]["b"].get<int>(), 2);
    ASSERT_TRUE(j["array"].is_array());
    EXPECT_EQ(j["array"].size(), 5u);
    EXPECT_EQ(j["array"][2].get<int>(), 3);
}

TEST(JsonInitList, SinglePairBraceIsObject) {
    Json j = Json({{"a", 1}});
    ASSERT_TRUE(j.is_object());
    EXPECT_EQ(j["a"].get<int>(), 1);
}

// ─────────────────────────────────────────────────────────────────────────────
// Mutation: operator[], push_back, assignment, erase
// ─────────────────────────────────────────────────────────────────────────────

TEST(JsonMutate, BuildObjectByIndexing) {
    Json j;
    j["version"] = 1;
    j["family"] = "ipv4";
    j["enabled"] = true;
    EXPECT_TRUE(j.is_object());
    EXPECT_EQ(j["version"].get<int>(), 1);
    EXPECT_EQ(j["family"].get<std::string>(), "ipv4");
    EXPECT_TRUE(j["enabled"].get<bool>());
    EXPECT_TRUE(j.contains("version"));
    EXPECT_FALSE(j.contains("missing"));
}

TEST(JsonMutate, BuildArrayByPushBack) {
    Json arr = Json::array();
    for (int i = 0; i < 5; ++i) arr.push_back(i);
    EXPECT_EQ(arr.size(), 5u);
    EXPECT_EQ(arr.front().get<int>(), 0);
    EXPECT_EQ(arr.back().get<int>(), 4);
}

TEST(JsonMutate, PushBackOnNullBecomesArray) {
    Json j;
    j.push_back("a");
    j.push_back("b");
    ASSERT_TRUE(j.is_array());
    EXPECT_EQ(j.size(), 2u);
}

TEST(JsonMutate, IndexAssignGrowsArray) {
    Json j = Json::array();
    j[3] = 99;  // fills 0..2 with null
    ASSERT_TRUE(j.is_array());
    EXPECT_EQ(j.size(), 4u);
    EXPECT_TRUE(j[0].is_null());
    EXPECT_EQ(j[3].get<int>(), 99);
}

TEST(JsonMutate, MoveAssignNested) {
    Json arr = Json::array();
    arr.push_back(1);
    Json obj;
    obj["items"] = std::move(arr);
    ASSERT_TRUE(obj["items"].is_array());
    EXPECT_EQ(obj["items"].size(), 1u);
}

TEST(JsonMutate, EraseKey) {
    Json j = {{"a", 1}, {"b", 2}};
    EXPECT_TRUE(j.erase("a"));
    EXPECT_FALSE(j.erase("missing"));
    EXPECT_FALSE(j.contains("a"));
    EXPECT_TRUE(j.contains("b"));
    EXPECT_EQ(j.size(), 1u);
}

TEST(JsonMutate, EraseIndex) {
    Json j = {10, 20, 30};
    j.erase(static_cast<std::size_t>(1));
    EXPECT_EQ(j.size(), 2u);
    EXPECT_EQ(j[0].get<int>(), 10);
    EXPECT_EQ(j[1].get<int>(), 30);
}

TEST(JsonMutate, ObjectKeysPreserveInsertionOrder) {
    Json j;
    j["zebra"] = 1;
    j["apple"] = 2;
    j["mango"] = 3;
    // Insertion order, not alphabetical.
    EXPECT_EQ(j.dump(), "{\"zebra\":1,\"apple\":2,\"mango\":3}");
}

// ─────────────────────────────────────────────────────────────────────────────
// value() / get() / implicit conversion
// ─────────────────────────────────────────────────────────────────────────────

TEST(JsonAccess, ValueWithDefaults) {
    Json j = {{"text", "hi"}, {"n", 7}};
    EXPECT_EQ(j.value("text", std::string("def")), "hi");
    EXPECT_EQ(j.value("text", ""), "hi");           // const char* default -> std::string
    EXPECT_EQ(j.value("missing", ""), "");
    EXPECT_EQ(j.value("n", 0), 7);
    EXPECT_EQ(j.value("missing_n", -1), -1);
}

TEST(JsonAccess, ValueOnNonObjectReturnsDefault) {
    Json j = 5;
    EXPECT_EQ(j.value("anything", 42), 42);
}

TEST(JsonAccess, ImplicitConversions) {
    Json j = {{"port", 8080}, {"ip", "127.0.0.1"}, {"rtt", 50}};
    int port = j["port"];
    std::string ip = j["ip"];
    uint16_t rtt = j["rtt"];
    EXPECT_EQ(port, 8080);
    EXPECT_EQ(ip, "127.0.0.1");
    EXPECT_EQ(rtt, 50);
}

TEST(JsonAccess, AtThrowsOnMissing) {
    Json j = {{"a", 1}};
    EXPECT_NO_THROW(j.at("a"));
    EXPECT_THROW(j.at("b"), JsonError);
    EXPECT_THROW(j.at(static_cast<std::size_t>(0)), JsonError);  // not an array
}

TEST(JsonAccess, ConstIndexThrowsOnMissing) {
    const Json j = {{"a", 1}};
    EXPECT_EQ(j["a"].get<int>(), 1);
    EXPECT_THROW(j["missing"], JsonError);
}

TEST(JsonAccess, WrongTypeGetThrows) {
    Json s = "text";
    EXPECT_THROW(s.get<int>(), JsonError);
    Json n = 5;
    EXPECT_THROW(n.get<std::string>(), JsonError);
}

// ─────────────────────────────────────────────────────────────────────────────
// Iteration
// ─────────────────────────────────────────────────────────────────────────────

TEST(JsonIterate, ArrayValues) {
    Json j = {1, 2, 3};
    int sum = 0;
    for (const auto& el : j) sum += el.get<int>();
    EXPECT_EQ(sum, 6);
}

TEST(JsonIterate, ObjectValues) {
    Json j = {{"a", 1}, {"b", 2}, {"c", 3}};
    int sum = 0;
    for (const auto& el : j) sum += el.get<int>();
    EXPECT_EQ(sum, 6);
}

TEST(JsonIterate, ItemsKeyValue) {
    Json j;
    j["a"] = 1;
    j["b"] = 2;
    std::string keys;
    int sum = 0;
    for (auto it = j.items().begin(); it != j.items().end(); ++it) {
        keys += it.key();
        sum += it.value().get<int>();
    }
    EXPECT_EQ(keys, "ab");
    EXPECT_EQ(sum, 3);
}

// ─────────────────────────────────────────────────────────────────────────────
// Serialisation
// ─────────────────────────────────────────────────────────────────────────────

TEST(JsonDump, CompactObject) {
    Json j = {{"a", 1}, {"b", "x"}};
    EXPECT_EQ(j.dump(), "{\"a\":1,\"b\":\"x\"}");
}

TEST(JsonDump, PrettyPrint) {
    Json j;
    j["a"] = 1;
    j["b"] = Json::array();
    j["b"].push_back(2);
    const std::string expected =
        "{\n"
        "  \"a\": 1,\n"
        "  \"b\": [\n"
        "    2\n"
        "  ]\n"
        "}";
    EXPECT_EQ(j.dump(2), expected);
}

TEST(JsonDump, StringEscaping) {
    Json j = "a\"b\\c\n\t\r\b\f/";
    // Forward slash is not escaped; control chars are.
    EXPECT_EQ(j.dump(), "\"a\\\"b\\\\c\\n\\t\\r\\b\\f/\"");
}

TEST(JsonDump, ControlCharUnicodeEscape) {
    std::string s;
    s.push_back('\x01');
    s.push_back('\x1f');
    Json j = s;
    EXPECT_EQ(j.dump(), "\"\\u0001\\u001f\"");
}

TEST(JsonDump, Utf8PassThrough) {
    Json j = "héllo \xE2\x9C\x93";  // accented e + check mark, raw UTF-8
    // Non-ASCII bytes are emitted verbatim.
    EXPECT_EQ(j.dump(), "\"héllo \xE2\x9C\x93\"");
}

TEST(JsonDump, FloatFormatting) {
    EXPECT_EQ(Json(2.0).dump(), "2.0");      // stays a float
    EXPECT_EQ(Json(3.5).dump(), "3.5");
    EXPECT_EQ(Json(0.1).dump(), "0.1");      // shortest round-trip
    EXPECT_EQ(Json(-1.25).dump(), "-1.25");
}

TEST(JsonDump, NaNAndInfBecomeNull) {
    EXPECT_EQ(Json(std::nan("")).dump(), "null");
    EXPECT_EQ(Json(std::numeric_limits<double>::infinity()).dump(), "null");
}

TEST(JsonStream, OutputOperator) {
    Json j = {{"k", 1}};
    std::ostringstream os;
    os << j;
    EXPECT_EQ(os.str(), "{\"k\":1}");
}

TEST(JsonStream, InputOperator) {
    std::istringstream is("{\"k\": 42}");
    Json j;
    is >> j;
    EXPECT_EQ(j["k"].get<int>(), 42);
}

// ─────────────────────────────────────────────────────────────────────────────
// Parsing
// ─────────────────────────────────────────────────────────────────────────────

TEST(JsonParse, Primitives) {
    EXPECT_TRUE(Json::parse("null").is_null());
    EXPECT_TRUE(Json::parse("true").get<bool>());
    EXPECT_FALSE(Json::parse("false").get<bool>());
    EXPECT_EQ(Json::parse("42").get<int>(), 42);
    EXPECT_EQ(Json::parse("-7").get<int>(), -7);
    EXPECT_DOUBLE_EQ(Json::parse("3.14").get<double>(), 3.14);
    EXPECT_EQ(Json::parse("\"hi\"").get<std::string>(), "hi");
}

TEST(JsonParse, WhitespaceAndLeadingBom) {
    EXPECT_EQ(Json::parse("  \n\t 5 \n").get<int>(), 5);
    EXPECT_EQ(Json::parse("\xEF\xBB\xBF{\"a\":1}")["a"].get<int>(), 1);
}

TEST(JsonParse, NestedStructure) {
    Json j = Json::parse(R"({"a":[1,2,{"b":true}],"c":null})");
    EXPECT_EQ(j["a"][0].get<int>(), 1);
    EXPECT_TRUE(j["a"][2]["b"].get<bool>());
    EXPECT_TRUE(j["c"].is_null());
}

TEST(JsonParse, NumberKinds) {
    EXPECT_TRUE(Json::parse("100").is_number_integer());
    EXPECT_TRUE(Json::parse("1.0").is_number_float());
    EXPECT_TRUE(Json::parse("1e3").is_number_float());
    EXPECT_DOUBLE_EQ(Json::parse("1e3").get<double>(), 1000.0);
    EXPECT_DOUBLE_EQ(Json::parse("2.5E-2").get<double>(), 0.025);
}

TEST(JsonParse, BigIntegers) {
    Json max64 = Json::parse("9223372036854775807");  // INT64_MAX
    EXPECT_EQ(max64.get<int64_t>(), INT64_MAX);

    Json big = Json::parse("18446744073709551615");   // UINT64_MAX
    EXPECT_TRUE(big.is_number_unsigned());
    EXPECT_EQ(big.get<uint64_t>(), UINT64_MAX);
}

TEST(JsonParse, UnicodeEscapes) {
    EXPECT_EQ(Json::parse("\"\\u0041\"").get<std::string>(), "A");
    // Euro sign U+20AC -> 3-byte UTF-8.
    EXPECT_EQ(Json::parse("\"\\u20AC\"").get<std::string>(), "\xE2\x82\xAC");
    // Surrogate pair U+1F600 (emoji) -> 4-byte UTF-8.
    EXPECT_EQ(Json::parse("\"\\uD83D\\uDE00\"").get<std::string>(),
              "\xF0\x9F\x98\x80");
}

TEST(JsonParse, EscapeSequences) {
    EXPECT_EQ(Json::parse("\"a\\nb\\tc\\\"d\\\\e\\/f\"").get<std::string>(),
              "a\nb\tc\"d\\e/f");
}

TEST(JsonParse, ThrowsOnMalformed) {
    EXPECT_THROW(Json::parse("{"), JsonError);
    EXPECT_THROW(Json::parse("[1,2"), JsonError);
    EXPECT_THROW(Json::parse("{\"a\":}"), JsonError);
    EXPECT_THROW(Json::parse("nul"), JsonError);
    EXPECT_THROW(Json::parse("01"), JsonError);          // leading zero
    EXPECT_THROW(Json::parse("1.2.3"), JsonError);       // trailing junk
    EXPECT_THROW(Json::parse(""), JsonError);            // empty
    EXPECT_THROW(Json::parse("\"unterminated"), JsonError);
    EXPECT_THROW(Json::parse("[1] extra"), JsonError);   // trailing content
}

TEST(JsonParse, NonThrowingReturnsDiscarded) {
    Json j = Json::parse("{bad json", nullptr, false);
    EXPECT_TRUE(j.is_discarded());

    Json ok = Json::parse("{\"a\":1}", nullptr, false);
    EXPECT_FALSE(ok.is_discarded());
    EXPECT_EQ(ok["a"].get<int>(), 1);
}

TEST(JsonParse, FromCharPointerRange) {
    const std::string text = "{\"x\":1,\"y\":2}";
    const uint8_t* first = reinterpret_cast<const uint8_t*>(text.data());
    const uint8_t* last = first + text.size();
    Json j = Json::parse(first, last, nullptr, false);
    ASSERT_FALSE(j.is_discarded());
    EXPECT_EQ(j["x"].get<int>(), 1);
    EXPECT_EQ(j["y"].get<int>(), 2);
}

TEST(JsonParse, DuplicateKeysKeepLast) {
    Json j = Json::parse("{\"a\":1,\"a\":2}");
    EXPECT_EQ(j.size(), 1u);
    EXPECT_EQ(j["a"].get<int>(), 2);
}

TEST(JsonParse, DeeplyNestedFailsCleanly) {
    // Far past the depth guard: must throw, not crash the stack.
    std::string deep(5000, '[');
    EXPECT_THROW(Json::parse(deep), JsonError);
    Json safe = Json::parse(deep, nullptr, false);
    EXPECT_TRUE(safe.is_discarded());
}

// ─────────────────────────────────────────────────────────────────────────────
// Round-trips & equality
// ─────────────────────────────────────────────────────────────────────────────

TEST(JsonRoundTrip, StructuralEquality) {
    Json original = {
        {"name", "rats"},
        {"version", 1},
        {"peers", {"a", "b", "c"}},
        {"config", {{"port", 8080}, {"secure", true}}},
        {"ratio", 0.75},
    };
    Json reparsed = Json::parse(original.dump());
    EXPECT_EQ(original, reparsed);
    Json reparsed_pretty = Json::parse(original.dump(4));
    EXPECT_EQ(original, reparsed_pretty);
}

TEST(JsonEquality, NumericCrossKind) {
    EXPECT_EQ(Json(5), Json(static_cast<unsigned>(5)));
    EXPECT_EQ(Json(5), Json(5.0));
    EXPECT_NE(Json(-1), Json(static_cast<unsigned>(0)));
    EXPECT_NE(Json(5), Json(6));
}

TEST(JsonEquality, ObjectOrderIndependent) {
    Json a = {{"x", 1}, {"y", 2}};
    Json b = {{"y", 2}, {"x", 1}};
    EXPECT_EQ(a, b);
}

TEST(JsonEquality, DifferentTypes) {
    EXPECT_NE(Json(1), Json("1"));
    EXPECT_NE(Json(true), Json(1));
    EXPECT_NE(Json::array(), Json::object());
    EXPECT_NE(Json(nullptr), Json(0));
}

TEST(JsonEquality, CopyAndMove) {
    Json a = {{"k", {1, 2, 3}}};
    Json copy = a;
    EXPECT_EQ(a, copy);
    Json moved = std::move(copy);
    EXPECT_EQ(a, moved);
    EXPECT_TRUE(copy.is_null());  // moved-from is a valid null
}

// ─────────────────────────────────────────────────────────────────────────────
// Scale: works with large volumes
// ─────────────────────────────────────────────────────────────────────────────

TEST(JsonScale, LargeArrayRoundTrip) {
    Json arr = Json::array();
    for (int i = 0; i < 50000; ++i) {
        arr.push_back(Json{{"i", i}, {"s", "item-" + std::to_string(i)}});
    }
    EXPECT_EQ(arr.size(), 50000u);

    std::string text = arr.dump();
    Json back = Json::parse(text);
    ASSERT_EQ(back.size(), 50000u);
    EXPECT_EQ(back[0]["i"].get<int>(), 0);
    EXPECT_EQ(back[49999]["i"].get<int>(), 49999);
    EXPECT_EQ(back.back()["s"].get<std::string>(), "item-49999");
    EXPECT_EQ(arr, back);
}

TEST(JsonScale, WideObjectLookup) {
    // Many keys: lookups stay correct (and are index-backed, not linear scans).
    Json obj = Json::object();
    for (int i = 0; i < 10000; ++i) obj["key_" + std::to_string(i)] = i;
    EXPECT_EQ(obj.size(), 10000u);
    EXPECT_EQ(obj["key_0"].get<int>(), 0);
    EXPECT_EQ(obj["key_9999"].get<int>(), 9999);
    EXPECT_FALSE(obj.contains("key_10000"));
}
