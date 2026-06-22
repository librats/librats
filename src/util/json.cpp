#include "util/json.h"

#include <cerrno>
#include <charconv>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <istream>
#include <iterator>
#include <ostream>

// std::to_chars / std::from_chars for floating-point is a C++17 feature, but
// some standard libraries shipped it later than the integer overloads. The
// feature-test macro is defined (to 201611L) only once full support — including
// the floating-point overloads — is present (libstdc++ ≥ 11, MSVC STL ≥ 19.24,
// libc++ once complete). When it is absent we fall back to the classic
// snprintf / strtod path, which is slower but produces identical results.
#if defined(__cpp_lib_to_chars) && __cpp_lib_to_chars >= 201611L
#  define LIBRATS_JSON_CHARCONV 1
#else
#  define LIBRATS_JSON_CHARCONV 0
#endif

namespace librats {

// ── Object ──────────────────────────────────────────────────────────────────

void Json::Object::build_index() {
    index_.clear();
    index_.reserve(items_.size());
    for (std::size_t i = 0; i < items_.size(); ++i) index_.emplace(items_[i].first, i);
    indexed_ = true;
}

void Json::Object::reindex() {
    // Called after an erase shifts indices: rebuild while large, else drop the
    // index and fall back to linear scans (keeping the size invariant).
    if (items_.size() > kIndexThreshold) {
        build_index();
    } else {
        index_.clear();
        indexed_ = false;
    }
}

template <typename K>
Json& Json::Object::emplace_key(K&& key) {
    if (indexed_) {
        auto it = index_.find(key);
        if (it != index_.end()) return items_[it->second].second;
        // The map needs its own copy of the key; the vector then takes the
        // original by perfect-forward (a move when the caller passed an rvalue).
        index_.emplace(key, items_.size());
        items_.emplace_back(std::forward<K>(key), Json());
        return items_.back().second;
    }
    for (auto& kv : items_)
        if (kv.first == key) return kv.second;
    items_.emplace_back(std::forward<K>(key), Json());
    if (items_.size() > kIndexThreshold) build_index();
    return items_.back().second;
}

Json& Json::Object::operator[](const std::string& key) { return emplace_key(key); }
Json& Json::Object::operator[](std::string&& key) { return emplace_key(std::move(key)); }

const Json* Json::Object::find(const std::string& key) const {
    if (indexed_) {
        auto it = index_.find(key);
        return it == index_.end() ? nullptr : &items_[it->second].second;
    }
    for (const auto& kv : items_)
        if (kv.first == key) return &kv.second;
    return nullptr;
}

Json* Json::Object::find(const std::string& key) {
    const Object* self = this;
    return const_cast<Json*>(self->find(key));
}

bool Json::Object::erase(const std::string& key) {
    std::size_t pos;
    if (indexed_) {
        auto it = index_.find(key);
        if (it == index_.end()) return false;
        pos = it->second;
    } else {
        pos = items_.size();
        for (std::size_t i = 0; i < items_.size(); ++i)
            if (items_[i].first == key) { pos = i; break; }
        if (pos == items_.size()) return false;
    }
    items_.erase(items_.begin() + static_cast<std::ptrdiff_t>(pos));
    reindex();
    return true;
}

bool Json::Object::operator==(const Object& other) const {
    if (items_.size() != other.items_.size()) return false;
    for (const auto& kv : items_) {
        const Json* o = other.find(kv.first);
        if (!o || !(*o == kv.second)) return false;
    }
    return true;
}

// ── Lifetime ────────────────────────────────────────────────────────────────

void Json::destroy() noexcept {
    switch (type_) {
        case Type::String: delete str_; break;
        case Type::Array:  delete arr_; break;
        case Type::Object: delete obj_; break;
        default: break;
    }
}

void Json::copy_from(const Json& o) {
    // Commit type_ only after the (possibly throwing) allocation succeeds: if
    // `new` throws, this value keeps its prior type_/payload untouched, so a
    // caller that started from a valid state (Null in the ctor / after the reset
    // in operator=) stays valid and its destructor never frees a stale pointer.
    switch (o.type_) {
        case Type::Boolean:  bool_  = o.bool_;  break;
        case Type::Integer:  int_   = o.int_;   break;
        case Type::Unsigned: uint_  = o.uint_;  break;
        case Type::Float:    float_ = o.float_; break;
        case Type::String:   { auto* p = new std::string(*o.str_); str_ = p; } break;
        case Type::Array:    { auto* p = new Array(*o.arr_);       arr_ = p; } break;
        case Type::Object:   { auto* p = new Object(*o.obj_);      obj_ = p; } break;
        default: break;  // Null / Discarded carry no payload
    }
    type_ = o.type_;
}

void Json::move_from(Json& o) noexcept {
    type_ = o.type_;
    switch (o.type_) {
        case Type::Boolean:  bool_  = o.bool_;  break;
        case Type::Integer:  int_   = o.int_;   break;
        case Type::Unsigned: uint_  = o.uint_;  break;
        case Type::Float:    float_ = o.float_; break;
        case Type::String:   str_ = o.str_; break;
        case Type::Array:    arr_ = o.arr_; break;
        case Type::Object:   obj_ = o.obj_; break;
        default: break;
    }
    o.type_ = Type::Null;  // ownership transferred; leave source a valid null
}

Json& Json::operator=(const Json& o) {
    if (this == &o) return *this;
    destroy();
    // Reset to a valid Null first: destroy() freed the old payload but left the
    // old type_/pointer in place, so if copy_from below throws, the destructor
    // would otherwise free a dangling pointer. As Null, a failed copy is safe.
    type_ = Type::Null;
    copy_from(o);
    return *this;
}

Json& Json::operator=(Json&& o) noexcept {
    if (this == &o) return *this;
    destroy();
    move_from(o);
    return *this;
}

// ── initializer_list construction ───────────────────────────────────────────

Json::Json(std::initializer_list<Json> init) {
    // nlohmann's heuristic: a non-empty list whose every element is a
    // two-element array starting with a string is an object; else an array.
    bool looks_like_object = init.size() > 0;
    for (const Json& el : init) {
        if (!(el.is_array() && el.size() == 2 && el.as_array()[0].is_string())) {
            looks_like_object = false;
            break;
        }
    }

    if (looks_like_object) {
        type_ = Type::Object;
        obj_ = new Object();
        for (const Json& el : init) {
            const Array& pair = el.as_array();
            (*obj_)[pair[0].as_string()] = pair[1];
        }
    } else {
        type_ = Type::Array;
        arr_ = new Array(init.begin(), init.end());
    }
}

// ── Scalar extraction ───────────────────────────────────────────────────────

bool Json::as_bool() const {
    switch (type_) {
        case Type::Boolean:  return bool_;
        case Type::Integer:  return int_ != 0;
        case Type::Unsigned: return uint_ != 0;
        case Type::Float:    return float_ != 0.0;
        default: throw JsonError("Json: value is not convertible to bool");
    }
}

int64_t Json::as_int64() const {
    switch (type_) {
        case Type::Integer:  return int_;
        case Type::Unsigned: return static_cast<int64_t>(uint_);
        case Type::Float:    return static_cast<int64_t>(float_);
        case Type::Boolean:  return bool_ ? 1 : 0;
        default: throw JsonError("Json: value is not a number");
    }
}

uint64_t Json::as_uint64() const {
    switch (type_) {
        case Type::Integer:  return static_cast<uint64_t>(int_);
        case Type::Unsigned: return uint_;
        case Type::Float:    return static_cast<uint64_t>(float_);
        case Type::Boolean:  return bool_ ? 1u : 0u;
        default: throw JsonError("Json: value is not a number");
    }
}

double Json::as_double() const {
    switch (type_) {
        case Type::Integer:  return static_cast<double>(int_);
        case Type::Unsigned: return static_cast<double>(uint_);
        case Type::Float:    return float_;
        case Type::Boolean:  return bool_ ? 1.0 : 0.0;
        default: throw JsonError("Json: value is not a number");
    }
}

const std::string& Json::as_string() const {
    if (type_ != Type::String) throw JsonError("Json: value is not a string");
    return *str_;
}

// ── Size / emptiness ────────────────────────────────────────────────────────

std::size_t Json::size() const noexcept {
    switch (type_) {
        case Type::Null:
        case Type::Discarded: return 0;
        case Type::Array:     return arr_->size();
        case Type::Object:    return obj_->size();
        default:              return 1;  // a scalar counts as one element
    }
}

bool Json::empty() const noexcept {
    switch (type_) {
        case Type::Null:      return true;
        case Type::Array:     return arr_->empty();
        case Type::Object:    return obj_->empty();
        default:              return false;
    }
}

// ── Object / array access ───────────────────────────────────────────────────

Json& Json::operator[](const std::string& key) {
    if (is_null()) { type_ = Type::Object; obj_ = new Object(); }
    if (!is_object()) throw JsonError("Json: operator[](key) on a non-object value");
    return (*obj_)[key];
}

const Json& Json::operator[](const std::string& key) const {
    if (!is_object()) throw JsonError("Json: operator[](key) on a non-object value");
    const Json* v = obj_->find(key);
    if (!v) throw JsonError("Json: key not found: " + key);
    return *v;
}

Json& Json::operator[](std::size_t index) {
    if (is_null()) { type_ = Type::Array; arr_ = new Array(); }
    if (!is_array()) throw JsonError("Json: operator[](index) on a non-array value");
    if (index >= arr_->size()) arr_->resize(index + 1);
    return (*arr_)[index];
}

const Json& Json::operator[](std::size_t index) const {
    if (!is_array()) throw JsonError("Json: operator[](index) on a non-array value");
    if (index >= arr_->size()) throw JsonError("Json: array index out of range");
    return (*arr_)[index];
}

Json& Json::at(const std::string& key) {
    if (!is_object()) throw JsonError("Json: at(key) on a non-object value");
    Json* v = obj_->find(key);
    if (!v) throw JsonError("Json: key not found: " + key);
    return *v;
}

const Json& Json::at(const std::string& key) const {
    if (!is_object()) throw JsonError("Json: at(key) on a non-object value");
    const Json* v = obj_->find(key);
    if (!v) throw JsonError("Json: key not found: " + key);
    return *v;
}

Json& Json::at(std::size_t index) {
    if (!is_array()) throw JsonError("Json: at(index) on a non-array value");
    if (index >= arr_->size()) throw JsonError("Json: array index out of range");
    return (*arr_)[index];
}

const Json& Json::at(std::size_t index) const {
    if (!is_array()) throw JsonError("Json: at(index) on a non-array value");
    if (index >= arr_->size()) throw JsonError("Json: array index out of range");
    return (*arr_)[index];
}

bool Json::erase(const std::string& key) {
    if (!is_object()) return false;
    return obj_->erase(key);
}

void Json::erase(std::size_t index) {
    if (!is_array()) throw JsonError("Json: erase(index) on a non-array value");
    if (index >= arr_->size()) throw JsonError("Json: array index out of range");
    arr_->erase(arr_->begin() + static_cast<std::ptrdiff_t>(index));
}

Json& Json::front() {
    if (is_array()) { if (arr_->empty()) throw JsonError("Json: front() on empty array"); return arr_->front(); }
    if (is_object()) { if (obj_->empty()) throw JsonError("Json: front() on empty object"); return obj_->begin()->second; }
    throw JsonError("Json: front() on a non-container value");
}

const Json& Json::front() const {
    if (is_array()) { if (arr_->empty()) throw JsonError("Json: front() on empty array"); return arr_->front(); }
    if (is_object()) { if (obj_->empty()) throw JsonError("Json: front() on empty object"); return obj_->begin()->second; }
    throw JsonError("Json: front() on a non-container value");
}

Json& Json::back() {
    if (is_array()) { if (arr_->empty()) throw JsonError("Json: back() on empty array"); return arr_->back(); }
    if (is_object()) { if (obj_->empty()) throw JsonError("Json: back() on empty object"); return (obj_->end() - 1)->second; }
    throw JsonError("Json: back() on a non-container value");
}

const Json& Json::back() const {
    if (is_array()) { if (arr_->empty()) throw JsonError("Json: back() on empty array"); return arr_->back(); }
    if (is_object()) { if (obj_->empty()) throw JsonError("Json: back() on empty object"); return (obj_->end() - 1)->second; }
    throw JsonError("Json: back() on a non-container value");
}

void Json::push_back(const Json& value) {
    if (is_null()) { type_ = Type::Array; arr_ = new Array(); }
    if (!is_array()) throw JsonError("Json: push_back on a non-array value");
    arr_->push_back(value);
}

void Json::push_back(Json&& value) {
    if (is_null()) { type_ = Type::Array; arr_ = new Array(); }
    if (!is_array()) throw JsonError("Json: push_back on a non-array value");
    arr_->push_back(std::move(value));
}

void Json::clear() {
    switch (type_) {
        case Type::Array:    arr_->clear(); break;
        case Type::Object:   obj_->clear(); break;
        case Type::String:   str_->clear(); break;
        case Type::Integer:  int_ = 0; break;
        case Type::Unsigned: uint_ = 0; break;
        case Type::Float:    float_ = 0.0; break;
        case Type::Boolean:  bool_ = false; break;
        default: break;
    }
}

Json::Array& Json::as_array() {
    if (!is_array()) throw JsonError("Json: value is not an array");
    return *arr_;
}
const Json::Array& Json::as_array() const {
    if (!is_array()) throw JsonError("Json: value is not an array");
    return *arr_;
}
Json::Object& Json::as_object() {
    if (!is_object()) throw JsonError("Json: value is not an object");
    return *obj_;
}
const Json::Object& Json::as_object() const {
    if (!is_object()) throw JsonError("Json: value is not an object");
    return *obj_;
}

// ── Equality ────────────────────────────────────────────────────────────────

bool Json::operator==(const Json& o) const {
    // Numbers compare by mathematical value across the three numeric kinds.
    if (is_number() && o.is_number()) {
        if (is_number_float() || o.is_number_float()) return as_double() == o.as_double();
        if (type_ == Type::Unsigned && o.type_ == Type::Unsigned) return uint_ == o.uint_;
        if (type_ == Type::Integer && o.type_ == Type::Integer)   return int_ == o.int_;
        // Mixed signed/unsigned: a negative signed value never equals an unsigned.
        auto eq = [](int64_t s, uint64_t u) {
            return s >= 0 && static_cast<uint64_t>(s) == u;
        };
        if (type_ == Type::Integer) return eq(int_, o.uint_);
        return eq(o.int_, uint_);
    }

    if (type_ != o.type_) return false;
    switch (type_) {
        case Type::Null:
        case Type::Discarded: return true;
        case Type::Boolean:   return bool_ == o.bool_;
        case Type::String:    return *str_ == *o.str_;
        case Type::Array:     return *arr_ == *o.arr_;   // element-wise via Json::operator==
        case Type::Object:    return *obj_ == *o.obj_;   // order-independent
        default:              return false;
    }
}

// ── Serialisation ───────────────────────────────────────────────────────────

namespace {

void dump_string(std::string& out, const std::string& s) {
    // Escapes are rare in real payloads (ids, ips, agent strings carry none), so
    // we copy maximal runs of pass-through bytes in one append() and only break
    // the run for a character that needs escaping.
    out += '"';
    const char* const begin = s.data();
    const char* const end   = begin + s.size();
    const char* run = begin;  // start of the current pass-through run
    for (const char* p = begin; p != end; ++p) {
        const char* esc = nullptr;  // two-char escape for *p, if any
        switch (*p) {
            case '"':  esc = "\\\""; break;
            case '\\': esc = "\\\\"; break;
            case '\b': esc = "\\b";  break;
            case '\f': esc = "\\f";  break;
            case '\n': esc = "\\n";  break;
            case '\r': esc = "\\r";  break;
            case '\t': esc = "\\t";  break;
            default: break;
        }
        if (esc) {
            out.append(run, static_cast<std::size_t>(p - run));
            out += esc;
            run = p + 1;
        } else if (static_cast<unsigned char>(*p) < 0x20) {
            // Other control characters use the \uXXXX form.
            out.append(run, static_cast<std::size_t>(p - run));
            char buf[7];
            std::snprintf(buf, sizeof buf, "\\u%04x", static_cast<unsigned char>(*p));
            out += buf;
            run = p + 1;
        }
        // Printable ASCII and raw UTF-8 bytes stay in the run.
    }
    out.append(run, static_cast<std::size_t>(end - run));
    out += '"';
}

// ── Fast integer formatting ──────────────────────────────────────────────────
//
// Integers are emitted two decimal digits at a time by indexing a table of all
// hundred digit pairs, which halves the number of (comparatively slow) integer
// divisions a digit-at-a-time loop performs. This is the well-worn approach used
// inside libstdc++, abseil and fmt; spelling it out keeps the fast path byte-for
// -byte identical on every toolchain instead of silently degrading to an
// allocating std::to_string wherever std::to_chars' integer overloads are
// missing.

// Every two-digit value "00", "01", … "99" laid out back to back, so the digits
// of `n` live at kDigitPairs[2*n] and kDigitPairs[2*n + 1].
constexpr char kDigitPairs[] =
    "00010203040506070809"
    "10111213141516171819"
    "20212223242526272829"
    "30313233343536373839"
    "40414243444546474849"
    "50515253545556575859"
    "60616263646566676869"
    "70717273747576777879"
    "80818283848586878889"
    "90919293949596979899";

// Write the decimal digits of an unsigned magnitude backward, finishing at
// `last`, and return a pointer to the most significant digit produced. The
// caller owns the buffer; 20 digits span the full 64-bit range.
inline char* write_decimal(char* last, uint64_t value) {
    while (value >= 100) {
        const unsigned pair = static_cast<unsigned>(value % 100) * 2;
        value /= 100;
        *--last = kDigitPairs[pair + 1];
        *--last = kDigitPairs[pair];
    }
    if (value >= 10) {
        const unsigned pair = static_cast<unsigned>(value) * 2;
        *--last = kDigitPairs[pair + 1];
        *--last = kDigitPairs[pair];
    } else {
        *--last = static_cast<char>('0' + value);
    }
    return last;
}

// Append the shortest decimal form of an integer with no heap allocation.
template <typename Int>
void dump_int(std::string& out, Int v) {
    char buf[21];                        // 20 digits + sign: the 64-bit worst case
    char* const last = buf + sizeof buf;
    char* first;
    if constexpr (std::is_signed<Int>::value) {
        uint64_t mag = static_cast<uint64_t>(v);
        if (v < 0) {
            mag = ~mag + 1;              // two's-complement magnitude (safe at INT64_MIN)
            first = write_decimal(last, mag);
            *--first = '-';
        } else {
            first = write_decimal(last, mag);
        }
    } else {
        first = write_decimal(last, static_cast<uint64_t>(v));
    }
    out.append(first, last);
}

void dump_double(std::string& out, double d) {
    if (std::isnan(d) || std::isinf(d)) { out += "null"; return; }  // JSON has no NaN/Inf

    char buf[32];
    char* last;
#if LIBRATS_JSON_CHARCONV
    // to_chars (no precision) yields the shortest string that round-trips exactly.
    last = std::to_chars(buf, buf + sizeof buf, d).ptr;
#else
    // Fallback: grow precision until the value round-trips.
    int n = 0;
    for (int prec = 15; prec <= 17; ++prec) {
        n = std::snprintf(buf, sizeof buf, "%.*g", prec, d);
        if (std::strtod(buf, nullptr) == d) break;
    }
    last = buf + n;
#endif
    out.append(buf, last);

    // Keep it recognisable as a float so it parses back to a float, not an int:
    // a token with no '.', 'e' or 'E' (e.g. "2") gets a trailing ".0".
    for (const char* q = buf; q != last; ++q) {
        if (*q == '.' || *q == 'e' || *q == 'E') return;
    }
    out += ".0";
}

void newline_indent(std::string& out, int indent, int depth) {
    if (indent < 0) return;
    out += '\n';
    out.append(static_cast<std::size_t>(indent) * static_cast<std::size_t>(depth), ' ');
}

} // namespace

void Json::dump_to(std::string& out, int indent, int depth) const {
    switch (type_) {
        case Type::Null:      out += "null"; break;
        case Type::Discarded: out += "null"; break;  // dumping a discarded value falls back to null
        case Type::Boolean:   out += bool_ ? "true" : "false"; break;
        case Type::Integer:   dump_int(out, int_); break;
        case Type::Unsigned:  dump_int(out, uint_); break;
        case Type::Float:     dump_double(out, float_); break;
        case Type::String:    dump_string(out, *str_); break;
        case Type::Array: {
            if (arr_->empty()) { out += "[]"; break; }
            out += '[';
            bool first = true;
            for (const Json& el : *arr_) {
                if (!first) out += ',';
                first = false;
                newline_indent(out, indent, depth + 1);
                el.dump_to(out, indent, depth + 1);
            }
            newline_indent(out, indent, depth);
            out += ']';
            break;
        }
        case Type::Object: {
            if (obj_->empty()) { out += "{}"; break; }
            out += '{';
            bool first = true;
            for (const auto& kv : *obj_) {
                if (!first) out += ',';
                first = false;
                newline_indent(out, indent, depth + 1);
                dump_string(out, kv.first);
                out += ':';
                if (indent >= 0) out += ' ';
                kv.second.dump_to(out, indent, depth + 1);
            }
            newline_indent(out, indent, depth);
            out += '}';
            break;
        }
    }
}

std::string Json::dump(int indent) const {
    std::string out;
    dump_to(out, indent, 0);
    return out;
}

// ── Parsing ─────────────────────────────────────────────────────────────────

class JsonParser {
public:
    JsonParser(const char* begin, const char* end) : p_(begin), end_(end) {}

    Json parse() {
        skip_ws();
        if (p_ == end_) error("empty document");
        Json v = parse_value(0);
        skip_ws();
        if (p_ != end_) error("unexpected trailing characters");
        return v;
    }

private:
    const char* p_;
    const char* end_;
    static constexpr int kMaxDepth = 1000;

    [[noreturn]] void error(const std::string& msg) const {
        throw JsonError("JSON parse error: " + msg);
    }

    static bool is_digit(char c) { return c >= '0' && c <= '9'; }

    void skip_ws() {
        while (p_ != end_) {
            char c = *p_;
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') ++p_;
            else break;
        }
    }

    char peek() const { return p_ != end_ ? *p_ : '\0'; }

    Json parse_value(int depth) {
        if (depth > kMaxDepth) error("maximum nesting depth exceeded");
        skip_ws();
        if (p_ == end_) error("unexpected end of input");
        switch (*p_) {
            case '{': return parse_object(depth);
            case '[': return parse_array(depth);
            case '"': return Json(parse_string());
            case 't': case 'f': return parse_bool();
            case 'n': return parse_null();
            case '-': return parse_number();
            default:
                if (is_digit(*p_)) return parse_number();
                error(std::string("unexpected character '") + *p_ + "'");
        }
    }

    Json parse_object(int depth) {
        ++p_;  // consume '{'
        Json obj = Json::object();
        Json::Object& o = obj.as_object();
        skip_ws();
        if (peek() == '}') { ++p_; return obj; }
        while (true) {
            skip_ws();
            if (peek() != '"') error("expected string key in object");
            std::string key = parse_string();
            skip_ws();
            if (peek() != ':') error("expected ':' after object key");
            ++p_;
            o[std::move(key)] = parse_value(depth + 1);
            skip_ws();
            char c = peek();
            if (c == ',') { ++p_; continue; }
            if (c == '}') { ++p_; break; }
            error("expected ',' or '}' in object");
        }
        return obj;
    }

    Json parse_array(int depth) {
        ++p_;  // consume '['
        Json arr = Json::array();
        Json::Array& a = arr.as_array();
        skip_ws();
        if (peek() == ']') { ++p_; return arr; }
        while (true) {
            a.push_back(parse_value(depth + 1));
            skip_ws();
            char c = peek();
            if (c == ',') { ++p_; continue; }
            if (c == ']') { ++p_; break; }
            error("expected ',' or ']' in array");
        }
        return arr;
    }

    Json parse_bool() {
        if (end_ - p_ >= 4 && std::strncmp(p_, "true", 4) == 0) { p_ += 4; return Json(true); }
        if (end_ - p_ >= 5 && std::strncmp(p_, "false", 5) == 0) { p_ += 5; return Json(false); }
        error("invalid literal");
    }

    Json parse_null() {
        if (end_ - p_ >= 4 && std::strncmp(p_, "null", 4) == 0) { p_ += 4; return Json(nullptr); }
        error("invalid literal");
    }

    unsigned parse_hex4() {
        if (end_ - p_ < 4) error("invalid \\u escape");
        unsigned v = 0;
        for (int i = 0; i < 4; ++i) {
            char h = *p_++;
            v <<= 4;
            if (h >= '0' && h <= '9') v |= static_cast<unsigned>(h - '0');
            else if (h >= 'a' && h <= 'f') v |= static_cast<unsigned>(h - 'a' + 10);
            else if (h >= 'A' && h <= 'F') v |= static_cast<unsigned>(h - 'A' + 10);
            else error("invalid hex digit in \\u escape");
        }
        return v;
    }

    static void append_utf8(std::string& out, unsigned cp) {
        if (cp <= 0x7F) {
            out += static_cast<char>(cp);
        } else if (cp <= 0x7FF) {
            out += static_cast<char>(0xC0 | (cp >> 6));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else if (cp <= 0xFFFF) {
            out += static_cast<char>(0xE0 | (cp >> 12));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else {
            out += static_cast<char>(0xF0 | (cp >> 18));
            out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        }
    }

    std::string parse_string() {
        ++p_;  // consume opening '"'
        std::string out;
        // Most string bytes need no translation, so copy maximal escape-free
        // runs in a single append() and only stop for '"', '\\' or a control
        // character. `run` marks the start of the run still to be flushed.
        const char* run = p_;
        while (true) {
            if (p_ == end_) error("unterminated string");
            unsigned char c = static_cast<unsigned char>(*p_);
            if (c == '"') { out.append(run, static_cast<std::size_t>(p_ - run)); ++p_; break; }
            if (c == '\\') {
                out.append(run, static_cast<std::size_t>(p_ - run));
                ++p_;  // consume backslash
                if (p_ == end_) error("unterminated escape sequence");
                char e = *p_++;
                switch (e) {
                    case '"':  out += '"';  break;
                    case '\\': out += '\\'; break;
                    case '/':  out += '/';  break;
                    case 'b':  out += '\b'; break;
                    case 'f':  out += '\f'; break;
                    case 'n':  out += '\n'; break;
                    case 'r':  out += '\r'; break;
                    case 't':  out += '\t'; break;
                    case 'u': {
                        unsigned cp = parse_hex4();
                        if (cp >= 0xD800 && cp <= 0xDBFF) {
                            // High surrogate must be followed by a low surrogate.
                            if (end_ - p_ < 2 || p_[0] != '\\' || p_[1] != 'u')
                                error("invalid surrogate pair");
                            p_ += 2;
                            unsigned lo = parse_hex4();
                            if (lo < 0xDC00 || lo > 0xDFFF) error("invalid low surrogate");
                            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                        } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                            error("unexpected low surrogate");
                        }
                        append_utf8(out, cp);
                        break;
                    }
                    default: error("invalid escape sequence");
                }
                run = p_;  // next run resumes after the escape
            } else if (c < 0x20) {
                error("unescaped control character in string");
            } else {
                ++p_;  // ordinary byte: defer the copy until the run is flushed
            }
        }
        return out;
    }

    Json parse_number() {
        const char* start = p_;
        bool is_float = false;

        if (peek() == '-') ++p_;
        if (p_ == end_) error("invalid number");

        if (peek() == '0') {
            ++p_;
        } else if (is_digit(peek())) {
            while (p_ != end_ && is_digit(*p_)) ++p_;
        } else {
            error("invalid number");
        }

        if (p_ != end_ && *p_ == '.') {
            is_float = true;
            ++p_;
            if (p_ == end_ || !is_digit(*p_)) error("invalid number: expected digits after '.'");
            while (p_ != end_ && is_digit(*p_)) ++p_;
        }

        if (p_ != end_ && (*p_ == 'e' || *p_ == 'E')) {
            is_float = true;
            ++p_;
            if (p_ != end_ && (*p_ == '+' || *p_ == '-')) ++p_;
            if (p_ == end_ || !is_digit(*p_)) error("invalid number: expected digits in exponent");
            while (p_ != end_ && is_digit(*p_)) ++p_;
        }

        // The grammar above is already validated, so the only conversion
        // outcome we still handle is integer overflow → fall back to double.
        return finish_number(start, is_float);
    }

    // Convert the already-scanned token [start, p_) into a Json number.
    Json finish_number(const char* start, bool is_float) {
#if LIBRATS_JSON_CHARCONV
        if (is_float) {
            double d = 0.0;
            std::from_chars(start, p_, d);
            return Json(d);
        }
        if (*start == '-') {
            int64_t v = 0;
            if (std::from_chars(start, p_, v).ec == std::errc{}) return Json(v);
        } else {
            uint64_t v = 0;
            if (std::from_chars(start, p_, v).ec == std::errc{}) {
                // Prefer signed storage when it fits, so small positive ints
                // compare equal to literal-constructed ones however they were built.
                if (v <= static_cast<uint64_t>(INT64_MAX))
                    return Json(static_cast<int64_t>(v));
                return Json(v);
            }
        }
        // Integer overflowed 64 bits: represent it (approximately) as a double.
        double d = 0.0;
        std::from_chars(start, p_, d);
        return Json(d);
#else
        std::string num(start, p_);
        if (is_float) return Json(std::strtod(num.c_str(), nullptr));

        errno = 0;
        if (num[0] == '-') {
            long long v = std::strtoll(num.c_str(), nullptr, 10);
            if (errno == ERANGE) return Json(std::strtod(num.c_str(), nullptr));
            return Json(static_cast<int64_t>(v));
        }
        unsigned long long v = std::strtoull(num.c_str(), nullptr, 10);
        if (errno == ERANGE) return Json(std::strtod(num.c_str(), nullptr));
        if (v <= static_cast<unsigned long long>(INT64_MAX))
            return Json(static_cast<int64_t>(v));
        return Json(static_cast<uint64_t>(v));
#endif
    }
};

Json Json::parse(const std::string& text, std::nullptr_t, bool allow_exceptions) {
    const char* begin = text.data();
    const char* end = begin + text.size();
    // Skip a leading UTF-8 byte-order mark if present.
    if (text.size() >= 3 && static_cast<unsigned char>(begin[0]) == 0xEF &&
        static_cast<unsigned char>(begin[1]) == 0xBB &&
        static_cast<unsigned char>(begin[2]) == 0xBF) {
        begin += 3;
    }
    try {
        JsonParser parser(begin, end);
        return parser.parse();
    } catch (const std::exception&) {
        if (allow_exceptions) throw;
        return make_discarded();
    }
}

Json Json::parse(const char* text, std::nullptr_t, bool allow_exceptions) {
    return parse(std::string(text ? text : ""), nullptr, allow_exceptions);
}

// ── Stream operators ────────────────────────────────────────────────────────

std::istream& operator>>(std::istream& is, Json& j) {
    std::string content((std::istreambuf_iterator<char>(is)),
                        std::istreambuf_iterator<char>());
    j = Json::parse(content);  // throws JsonError on malformed input
    return is;
}

std::ostream& operator<<(std::ostream& os, const Json& j) {
    return os << j.dump();
}

} // namespace librats
