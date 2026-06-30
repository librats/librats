#include "bittorrent/bencode.h"

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace librats {

// =============================================================================
// Container boxing helpers — the only code aware of LIBRATS_BENCODE_BOXED_CONTAINERS
// =============================================================================

void BencodeValue::set_list(BencodeList l) {
#if LIBRATS_BENCODE_BOXED_CONTAINERS
    value_ = std::make_shared<BencodeList>(std::move(l));
#else
    value_ = std::move(l);
#endif
}

void BencodeValue::set_dict(BencodeDict d) {
#if LIBRATS_BENCODE_BOXED_CONTAINERS
    value_ = std::make_shared<BencodeDict>(std::move(d));
#else
    value_ = std::move(d);
#endif
}

BencodeList& BencodeValue::list_ref() {
#if LIBRATS_BENCODE_BOXED_CONTAINERS
    return *std::get<std::shared_ptr<BencodeList>>(value_);
#else
    return std::get<BencodeList>(value_);
#endif
}
const BencodeList& BencodeValue::list_ref() const {
#if LIBRATS_BENCODE_BOXED_CONTAINERS
    return *std::get<std::shared_ptr<BencodeList>>(value_);
#else
    return std::get<BencodeList>(value_);
#endif
}
BencodeDict& BencodeValue::dict_ref() {
#if LIBRATS_BENCODE_BOXED_CONTAINERS
    return *std::get<std::shared_ptr<BencodeDict>>(value_);
#else
    return std::get<BencodeDict>(value_);
#endif
}
const BencodeDict& BencodeValue::dict_ref() const {
#if LIBRATS_BENCODE_BOXED_CONTAINERS
    return *std::get<std::shared_ptr<BencodeDict>>(value_);
#else
    return std::get<BencodeDict>(value_);
#endif
}

// =============================================================================
// Construction / value semantics
// =============================================================================

BencodeValue::BencodeValue() : type_(Type::String), value_(std::string()) {}
BencodeValue::BencodeValue(std::int64_t v) : type_(Type::Integer), value_(v) {}
BencodeValue::BencodeValue(std::string v) : type_(Type::String), value_(std::move(v)) {}
BencodeValue::BencodeValue(const char* v) : type_(Type::String), value_(std::string(v)) {}
BencodeValue::BencodeValue(BencodeList v) : type_(Type::List) { set_list(std::move(v)); }
BencodeValue::BencodeValue(BencodeDict v) : type_(Type::Dictionary) { set_dict(std::move(v)); }

BencodeValue::BencodeValue(const BencodeValue& other) : type_(other.type_) {
    // Always a deep copy, regardless of whether containers are boxed.
    switch (type_) {
        case Type::Integer:    value_ = std::get<std::int64_t>(other.value_); break;
        case Type::String:     value_ = std::get<std::string>(other.value_); break;
        case Type::List:       set_list(other.list_ref()); break;
        case Type::Dictionary: set_dict(other.dict_ref()); break;
    }
}

BencodeValue::BencodeValue(BencodeValue&& other) noexcept
    : type_(other.type_), value_(std::move(other.value_)) {}

BencodeValue& BencodeValue::operator=(const BencodeValue& other) {
    if (this != &other) {
        BencodeValue tmp(other);          // copy-and-swap keeps it exception-safe and simple
        *this = std::move(tmp);
    }
    return *this;
}

BencodeValue& BencodeValue::operator=(BencodeValue&& other) noexcept {
    if (this != &other) {
        type_  = other.type_;
        value_ = std::move(other.value_);
    }
    return *this;
}

BencodeValue::~BencodeValue() = default;

// =============================================================================
// Typed access
// =============================================================================

std::int64_t BencodeValue::as_integer() const {
    if (type_ != Type::Integer) throw std::runtime_error("BencodeValue is not an integer");
    return std::get<std::int64_t>(value_);
}

const std::string& BencodeValue::as_string() const {
    if (type_ != Type::String) throw std::runtime_error("BencodeValue is not a string");
    return std::get<std::string>(value_);
}

const BencodeList& BencodeValue::as_list() const {
    if (type_ != Type::List) throw std::runtime_error("BencodeValue is not a list");
    return list_ref();
}

BencodeList& BencodeValue::as_list() {
    if (type_ != Type::List) throw std::runtime_error("BencodeValue is not a list");
    return list_ref();
}

const BencodeDict& BencodeValue::as_dict() const {
    if (type_ != Type::Dictionary) throw std::runtime_error("BencodeValue is not a dictionary");
    return dict_ref();
}

// =============================================================================
// Dictionary lookup / building (sorted-vector invariant)
// =============================================================================

namespace {
// Compare a (key, value) entry against a bare key — used for binary search.
struct KeyLess {
    bool operator()(const std::pair<std::string, BencodeValue>& e, std::string_view k) const {
        return e.first < k;
    }
    bool operator()(std::string_view k, const std::pair<std::string, BencodeValue>& e) const {
        return k < e.first;
    }
};
} // namespace

const BencodeValue* BencodeValue::find(std::string_view key) const noexcept {
    if (type_ != Type::Dictionary) return nullptr;
    const BencodeDict& d = dict_ref();
    auto it = std::lower_bound(d.begin(), d.end(), key, KeyLess{});
    if (it != d.end() && it->first == key) return &it->second;
    return nullptr;
}

const BencodeValue& BencodeValue::operator[](std::string_view key) const {
    const BencodeValue* v = find(key);
    if (!v) throw std::runtime_error("Key not found in dictionary: " + std::string(key));
    return *v;
}

BencodeValue& BencodeValue::operator[](std::string_view key) {
    if (type_ != Type::Dictionary) throw std::runtime_error("BencodeValue is not a dictionary");
    BencodeDict& d = dict_ref();
    auto it = std::lower_bound(d.begin(), d.end(), key, KeyLess{});
    if (it != d.end() && it->first == key) return it->second;
    it = d.emplace(it, std::string(key), BencodeValue());  // insert keeps the vector sorted
    return it->second;
}

// =============================================================================
// List access
// =============================================================================

const BencodeValue& BencodeValue::operator[](std::size_t index) const {
    if (type_ != Type::List) throw std::runtime_error("BencodeValue is not a list");
    const BencodeList& l = list_ref();
    if (index >= l.size()) throw std::runtime_error("Index out of bounds");
    return l[index];
}

BencodeValue& BencodeValue::operator[](std::size_t index) {
    if (type_ != Type::List) throw std::runtime_error("BencodeValue is not a list");
    BencodeList& l = list_ref();
    if (index >= l.size()) throw std::runtime_error("Index out of bounds");
    return l[index];
}

void BencodeValue::push_back(BencodeValue value) {
    if (type_ != Type::List) throw std::runtime_error("BencodeValue is not a list");
    list_ref().push_back(std::move(value));
}

std::size_t BencodeValue::size() const {
    switch (type_) {
        case Type::String:     return std::get<std::string>(value_).size();
        case Type::List:       return list_ref().size();
        case Type::Dictionary: return dict_ref().size();
        default: throw std::runtime_error("Size not applicable to this type");
    }
}

// =============================================================================
// Encoding (dictionaries are already sorted → output is canonical)
// =============================================================================

void BencodeValue::encode_to(std::vector<std::uint8_t>& out) const {
    auto append = [&out](const char* s, std::size_t n) {
        out.insert(out.end(), s, s + n);
    };
    auto append_str = [&](const std::string& s) {
        std::string len = std::to_string(s.size());
        append(len.data(), len.size());
        out.push_back(':');
        out.insert(out.end(), s.begin(), s.end());
    };

    switch (type_) {
        case Type::Integer: {
            std::string s = "i" + std::to_string(std::get<std::int64_t>(value_)) + "e";
            append(s.data(), s.size());
            break;
        }
        case Type::String:
            append_str(std::get<std::string>(value_));
            break;
        case Type::List:
            out.push_back('l');
            for (const BencodeValue& item : list_ref()) item.encode_to(out);
            out.push_back('e');
            break;
        case Type::Dictionary:
            out.push_back('d');
            for (const auto& [key, val] : dict_ref()) {  // already sorted, no duplicates
                append_str(key);
                val.encode_to(out);
            }
            out.push_back('e');
            break;
    }
}

std::vector<std::uint8_t> BencodeValue::encode() const {
    std::vector<std::uint8_t> out;
    encode_to(out);
    return out;
}

std::string BencodeValue::encode_string() const {
    std::vector<std::uint8_t> out = encode();
    return std::string(out.begin(), out.end());
}

// =============================================================================
// Decoding — hardened recursive-descent parser
// =============================================================================

namespace {

constexpr int kMaxDepth = 100;  // libtorrent's default nesting limit; stops stack-overflow bombs

/// Parses one bencode value out of [p, end). All methods advance `p` past what
/// they consume and return std::nullopt on any malformed input — never throw,
/// never read out of bounds, never overflow.
class Parser {
public:
    Parser(const std::uint8_t* data, const std::uint8_t* end) : p_(data), end_(end) {}

    std::optional<BencodeValue> parse(int depth) {
        if (depth > kMaxDepth || p_ >= end_) return std::nullopt;
        const std::uint8_t c = *p_;
        if (c == 'i') return parse_integer();
        if (c == 'l') return parse_list(depth);
        if (c == 'd') return parse_dict(depth);
        if (c >= '0' && c <= '9') return parse_string();
        return std::nullopt;
    }

    const std::uint8_t* cursor() const { return p_; }

private:
    bool eof() const { return p_ >= end_; }

    // Strict canonical integer: optional '-', no leading zeros, no "-0", in
    // int64 range. `term` is the terminating byte ('e' for ints, ':' for strings).
    std::optional<std::int64_t> parse_raw_int(std::uint8_t term) {
        bool negative = false;
        if (!eof() && *p_ == '-') { negative = true; ++p_; }
        if (eof() || *p_ < '0' || *p_ > '9') return std::nullopt;  // need at least one digit

        if (*p_ == '0') {                       // canonical: a lone zero, never "-0" or "0..."
            ++p_;
            if (negative) return std::nullopt;
            if (eof() || *p_ != term) return std::nullopt;
            ++p_;
            return 0;
        }

        constexpr std::uint64_t kMaxMag = 9223372036854775808ull;  // |INT64_MIN|
        std::uint64_t mag = 0;
        while (!eof() && *p_ >= '0' && *p_ <= '9') {
            const std::uint64_t d = std::uint64_t(*p_ - '0');
            if (mag > (kMaxMag - d) / 10) return std::nullopt;     // would exceed int64 range
            mag = mag * 10 + d;
            ++p_;
        }
        if (eof() || *p_ != term) return std::nullopt;
        ++p_;

        if (negative) {
            if (mag == kMaxMag) return std::numeric_limits<std::int64_t>::min();
            return -std::int64_t(mag);
        }
        if (mag >= kMaxMag) return std::nullopt;  // > INT64_MAX
        return std::int64_t(mag);
    }

    // String length is bounded by the remaining buffer, which both rejects
    // impossible lengths early and keeps the accumulation far from overflow.
    std::optional<std::string> parse_raw_string() {
        if (eof() || *p_ < '0' || *p_ > '9') return std::nullopt;
        const std::uint64_t cap = std::uint64_t(end_ - p_);
        std::uint64_t len = 0;
        while (!eof() && *p_ >= '0' && *p_ <= '9') {
            len = len * 10 + std::uint64_t(*p_ - '0');
            if (len > cap) return std::nullopt;  // cannot possibly fit in the buffer
            ++p_;
        }
        if (eof() || *p_ != ':') return std::nullopt;
        ++p_;
        if (std::uint64_t(end_ - p_) < len) return std::nullopt;
        std::string s(reinterpret_cast<const char*>(p_), std::size_t(len));
        p_ += len;
        return s;
    }

    std::optional<BencodeValue> parse_integer() {
        ++p_;  // 'i'
        auto v = parse_raw_int('e');
        if (!v) return std::nullopt;
        return BencodeValue(*v);
    }

    std::optional<BencodeValue> parse_string() {
        auto s = parse_raw_string();
        if (!s) return std::nullopt;
        return BencodeValue(std::move(*s));
    }

    std::optional<BencodeValue> parse_list(int depth) {
        ++p_;  // 'l'
        BencodeList items;
        while (!eof() && *p_ != 'e') {
            auto v = parse(depth + 1);
            if (!v) return std::nullopt;
            items.push_back(std::move(*v));
        }
        if (eof()) return std::nullopt;  // unterminated
        ++p_;  // 'e'
        return BencodeValue(std::move(items));
    }

    std::optional<BencodeValue> parse_dict(int depth) {
        ++p_;  // 'd'
        BencodeDict entries;
        while (!eof() && *p_ != 'e') {
            auto key = parse_raw_string();
            if (!key) return std::nullopt;
            auto val = parse(depth + 1);
            if (!val) return std::nullopt;
            entries.emplace_back(std::move(*key), std::move(*val));
        }
        if (eof()) return std::nullopt;  // unterminated
        ++p_;  // 'e'

        // Establish the sorted, duplicate-free invariant. We accept any input
        // order (lenient, for interop) but reject genuinely ambiguous duplicate
        // keys. Stable sort preserves first-seen order among would-be dups so the
        // duplicate check below is deterministic.
        std::stable_sort(entries.begin(), entries.end(),
                         [](const auto& a, const auto& b) { return a.first < b.first; });
        for (std::size_t i = 1; i < entries.size(); ++i)
            if (entries[i].first == entries[i - 1].first) return std::nullopt;
        return BencodeValue(std::move(entries));
    }

    const std::uint8_t* p_;
    const std::uint8_t* end_;
};

// Decode exactly one value that must span the whole buffer.
std::optional<BencodeValue> decode_full(const std::uint8_t* data, std::size_t size) noexcept {
    if (data == nullptr || size == 0) return std::nullopt;
    Parser parser(data, data + size);
    std::optional<BencodeValue> value = parser.parse(0);
    if (!value) return std::nullopt;
    if (parser.cursor() != data + size) return std::nullopt;  // trailing garbage
    return value;
}

BencodeValue decode_or_throw(const std::uint8_t* data, std::size_t size) {
    std::optional<BencodeValue> value = decode_full(data, size);
    if (!value) throw std::runtime_error("Invalid bencode data");
    return std::move(*value);
}

} // namespace

BencodeValue BencodeDecoder::decode(const std::vector<std::uint8_t>& data) {
    return decode_or_throw(data.data(), data.size());
}
BencodeValue BencodeDecoder::decode(const std::string& data) {
    return decode_or_throw(reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
}
BencodeValue BencodeDecoder::decode(const std::uint8_t* data, std::size_t size) {
    return decode_or_throw(data, size);
}

namespace bencode {

BencodeValue decode(const std::vector<std::uint8_t>& data) {
    return decode_or_throw(data.data(), data.size());
}
BencodeValue decode(const std::string& data) {
    return decode_or_throw(reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
}

std::optional<BencodeValue> try_decode(const std::uint8_t* data, std::size_t size) noexcept {
    return decode_full(data, size);
}
std::optional<BencodeValue> try_decode(std::string_view data) noexcept {
    return decode_full(reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
}

std::vector<std::uint8_t> encode(const BencodeValue& value) { return value.encode(); }
std::string               encode_string(const BencodeValue& value) { return value.encode_string(); }

} // namespace bencode

} // namespace librats
