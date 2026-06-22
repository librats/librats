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

// Serialization needs no standard charconv at all: integers go through a
// hand-rolled two-digit writer and doubles through the Ryū formatter below.
// Parsing still uses std::from_chars for floating-point, a C++17 feature that
// some standard libraries shipped later than the integer overloads. The
// feature-test macro is defined (to 201611L) only once full support — including
// the floating-point overloads — is present (libstdc++ ≥ 11, MSVC STL ≥ 19.24,
// libc++ once complete). When it is absent we fall back to the classic
// strtod / strtoull path, which is slower but produces identical results.
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

// -- Shortest-round-trip double formatting (Ryu) -----------------------------
//
// Ulf Adams' Ryu algorithm (PLDI 2018) renders a double as the *shortest*
// decimal string that parses back to the exact same value. It does so with a
// fixed amount of work -- a single 64x128-bit multiply against a precomputed
// power-of-five table, then a short digit-trimming loop -- instead of the
// iterative "try more digits until it round-trips" approach. This is both faster
// and fully portable, which lets us drop std::to_chars (and its missing-overload
// fallbacks) from serialization entirely.
//
// The two tables hold 5^i (and its reciprocal) normalised to a fixed width; the
// algorithm's shift constants assume that width is two bits below the bit-count
// named in the multiply, so the entries are generated at 123-bit precision while
// the math below uses 125. The whole thing is validated digit-for-digit against
// std::to_chars over tens of millions of values.
namespace ryu {

constexpr int32_t kPow5InvBitcount = 125;
constexpr int32_t kPow5Bitcount    = 125;

static const uint64_t DOUBLE_POW5_INV_SPLIT[292][2] = {
    { 1u, 576460752303423488u },
    { 7378697629483820647u, 461168601842738790u },
    { 5902958103587056518u, 368934881474191032u },
    { 15790412927095376184u, 295147905179352825u },
    { 6817916609643050278u, 472236648286964521u },
    { 1764984472972529899u, 377789318629571617u },
    { 12480034022603754889u, 302231454903657293u },
    { 16278705621424097499u, 483570327845851669u },
    { 16712313311881188322u, 386856262276681335u },
    { 13369850649504950658u, 309485009821345068u },
    { 17702412224466010729u, 495176015714152109u },
    { 17851278594314718907u, 396140812571321687u },
    { 6902325245967954479u, 316912650057057350u },
    { 11043720393548727166u, 507060240091291760u },
    { 8834976314838981733u, 405648192073033408u },
    { 14446678681355006033u, 324518553658426726u },
    { 15735988260684189006u, 519229685853482762u },
    { 5210092979063530559u, 415383748682786210u },
    { 4168074383250824447u, 332306998946228968u },
    { 2979570198459408792u, 531691198313966349u },
    { 6073004973509437357u, 425352958651173079u },
    { 8547752793549460209u, 340282366920938463u },
    { 9987055654937226010u, 544451787073501541u },
    { 4300295709207870485u, 435561429658801233u },
    { 10818934196850117035u, 348449143727040986u },
    { 9931597085476366609u, 557518629963265578u },
    { 15323975297864913933u, 446014903970612462u },
    { 4880482608808110500u, 356811923176489970u },
    { 7808772174092976800u, 570899077082383952u },
    { 17315064183500112410u, 456719261665907161u },
    { 10162702532058179605u, 365375409332725729u },
    { 11819510840388454007u, 292300327466180583u },
    { 15221868529879616088u, 467680523945888933u },
    { 1109448379677961901u, 374144419156711147u },
    { 11955605147968100490u, 299315535325368917u },
    { 4371572977781319492u, 478904856520590268u },
    { 10875956011708876240u, 383123885216472214u },
    { 12390113624109011315u, 306499108173177771u },
    { 12445484169090597458u, 490398573077084434u },
    { 13645736150014388289u, 392318858461667547u },
    { 3537891290527689985u, 313855086769334038u },
    { 1971277250102393653u, 502168138830934461u },
    { 16334417059049556215u, 401734511064747568u },
    { 1999487203013914003u, 321387608851798055u },
    { 3199179524822262404u, 514220174162876888u },
    { 9938041249341630570u, 411376139330301510u },
    { 7950432999473304456u, 329100911464241208u },
    { 9031343984415376806u, 526561458342785933u },
    { 14603772817016122091u, 421249166674228746u },
    { 7993669438870987350u, 336999333339382997u },
    { 16479219916935490083u, 539198933343012795u },
    { 13183375933548392066u, 431359146674410236u },
    { 6857351932096803330u, 345087317339528189u },
    { 18350460720838705974u, 552139707743245102u },
    { 7301670947187144133u, 441711766194596082u },
    { 16909383201975446276u, 353369412955676865u },
    { 8608269049451162425u, 565391060729082985u },
    { 6886615239560929940u, 452312848583266388u },
    { 12887989821132564599u, 361850278866613110u },
    { 10310391856906051679u, 289480223093290488u },
    { 12807278156307772363u, 463168356949264781u },
    { 6556473710304307567u, 370534685559411825u },
    { 5245178968243446054u, 296427748447529460u },
    { 8392286349189513686u, 474284397516047136u },
    { 3024480264609700626u, 379427518012837709u },
    { 6108933026429670824u, 303542014410270167u },
    { 13463641657029383641u, 485667223056432267u },
    { 3392215696139686266u, 388533778445145814u },
    { 6403121371653659336u, 310827022756116651u },
    { 2866296565162034292u, 497323236409786642u },
    { 13361083696355358403u, 397858589127829313u },
    { 18067564586568107369u, 318286871302263450u },
    { 10461359264799420174u, 509258994083621521u },
    { 4679738597097625816u, 407407195266897217u },
    { 14811837321903831623u, 325925756213517773u },
    { 1562846826594668657u, 521481209941628438u },
    { 8628975090759555572u, 417184967953302750u },
    { 6903180072607644458u, 333747974362642200u },
    { 11045088116172231132u, 533996758980227520u },
    { 8836070492937784906u, 427197407184182016u },
    { 3379507579608317601u, 341757925747345613u },
    { 1717863312631397839u, 546812681195752981u },
    { 16131685909072759564u, 437450144956602384u },
    { 16594697542000117974u, 349960115965281907u },
    { 11794120808232547466u, 559936185544451052u },
    { 2056599017102217326u, 447948948435560842u },
    { 12713325657907504831u, 358359158748448673u },
    { 16651972237910097406u, 573374653997517877u },
    { 5942880160844257278u, 458699723198014302u },
    { 15822350572901136792u, 366959778558411441u },
    { 8968531643578999111u, 293567822846729153u },
    { 10660301814984488254u, 469708516554766645u },
    { 8528241451987590603u, 375766813243813316u },
    { 3133244346848162159u, 300613450595050653u },
    { 1323842140215149131u, 480981520952081045u },
    { 1059073712172119305u, 384785216761664836u },
    { 15604654228705336737u, 307828173409331868u },
    { 2831353877477076840u, 492525077454930990u },
    { 2265083101981661472u, 394020061963944792u },
    { 12880112925811060147u, 315216049571155833u },
    { 16918831866555785912u, 504345679313849333u },
    { 2467019049018897760u, 403476543451079467u },
    { 13041661683440849178u, 322781234760863573u },
    { 17177309878763448361u, 516449975617381717u },
    { 6363150273526938043u, 413159980493905374u },
    { 8779869033563460757u, 330527984395124299u },
    { 2979744009475806242u, 528844775032198879u },
    { 6073144022322555317u, 423075820025759103u },
    { 12237212847341864900u, 338460656020607282u },
    { 4822145296779342547u, 541537049632971652u },
    { 14925762681649205007u, 433229639706377321u },
    { 8251261330577453683u, 346583711765101857u },
    { 16891366943665836215u, 554533938824162971u },
    { 9823744740190758649u, 443627151059330377u },
    { 480298162668786273u, 354901720847464302u },
    { 4457825875011968360u, 567842753355942883u },
    { 10944958329493395334u, 454274202684754306u },
    { 5066617848852805944u, 363419362147803445u },
    { 4053294279082244755u, 290735489718242756u },
    { 17553317290757322578u, 465176783549188409u },
    { 17732002647347768386u, 372141426839350727u },
    { 6806904488394394062u, 297713141471480582u },
    { 14580395996172940823u, 476341026354368931u },
    { 7974967982196442335u, 381072821083495145u },
    { 6379974385757153868u, 304858256866796116u },
    { 2829261387727625542u, 487773210986873786u },
    { 17020804369149741727u, 390218568789499028u },
    { 2548597051094062412u, 312174855031599223u },
    { 388406467008589535u, 499479768050558757u },
    { 11378771617832602598u, 399583814440447005u },
    { 9103017294266082079u, 319667051552357604u },
    { 3496781226600000356u, 511467282483772167u },
    { 13865471425505731254u, 409173825987017733u },
    { 24330696178854034u, 327339060789614187u },
    { 3728277928628076777u, 523742497263382699u },
    { 6671971157644371745u, 418993997810706159u },
    { 9026925740857407719u, 335195198248564927u },
    { 18132430000113762674u, 536312317197703883u },
    { 3437897555865279170u, 429049853758163107u },
    { 13818364488917954305u, 343239883006530485u },
    { 3662639108559175272u, 549183812810448777u },
    { 13998157731073071188u, 439347050248359021u },
    { 7509177370116546627u, 351477640198687217u },
    { 15704032606928384926u, 562364224317899547u },
    { 5184528456058887295u, 449891379454319638u },
    { 11526320394330930482u, 359913103563455710u },
    { 18442112630929488771u, 575860965701529136u },
    { 11064341290001680694u, 460688772561223309u },
    { 12540821846743254878u, 368551018048978647u },
    { 2653959847910783256u, 294840814439182918u },
    { 556986941915342887u, 471745303102692669u },
    { 4134938368274184633u, 377396242482154135u },
    { 3307950694619347706u, 301916993985723308u },
    { 1603372296649046006u, 483067190377157293u },
    { 8661395466803057452u, 386453752301725834u },
    { 10618465188184356285u, 309163001841380667u },
    { 2232149042127328762u, 494660802946209068u },
    { 9164416863185683656u, 395728642356967254u },
    { 11020882305290457248u, 316582913885573803u },
    { 13944062873722821274u, 506532662216918085u },
    { 11155250298978257019u, 405226129773534468u },
    { 16302897868666426262u, 324180903818827574u },
    { 15016590145640551049u, 518689446110124119u },
    { 15702620931254351163u, 414951556888099295u },
    { 12562096745003480930u, 331961245510479436u },
    { 12720657162521748842u, 531137992816767098u },
    { 17555223359501219720u, 424910394253413678u },
    { 2976132243375244806u, 339928315402730943u },
    { 1072462774658481367u, 543885304644369509u },
    { 4547319034468695417u, 435108243715495607u },
    { 14705901671800687303u, 348086594972396485u },
    { 5082698601171548068u, 556938551955834377u },
    { 15134205325162969424u, 445550841564667501u },
    { 8418015445388465216u, 356440673251734001u },
    { 6090127083137723700u, 570305077202774402u },
    { 15940148110735909929u, 456244061762219521u },
    { 9062769673846817620u, 364995249409775617u },
    { 18318262183303185066u, 291996199527820493u },
    { 7173126604833634166u, 467193919244512790u },
    { 5738501283866907333u, 373755135395610232u },
    { 15658847471319256836u, 299004108316488185u },
    { 6607411880401259321u, 478406573306381097u },
    { 16353975948546738427u, 382725258645104877u },
    { 5704483129353570095u, 306180206916083902u },
    { 12816521821707622475u, 489888331065734243u },
    { 17631915086849918627u, 391910664852587394u },
    { 17794880884221845225u, 313528531882069915u },
    { 10025065341045400743u, 501645651011311865u },
    { 8020052272836320595u, 401316520809049492u },
    { 17484088262494787445u, 321053216647239593u },
    { 5838448331540197973u, 513685146635583350u },
    { 4670758665232158379u, 410948117308466680u },
    { 3736606932185726703u, 328758493846773344u },
    { 13357268720980983371u, 526013590154837350u },
    { 10685814976784786697u, 420810872123869880u },
    { 8548651981427829358u, 336648697699095904u },
    { 2609796726058796002u, 538637916318553447u },
    { 13155883825072767771u, 430910333054842757u },
    { 3146009430574393571u, 344728266443874206u },
    { 16101661533144760683u, 551565226310198729u },
    { 16570678041257718869u, 441252181048158983u },
    { 2188495988780444126u, 353001744838527187u },
    { 7190942396790620925u, 564802791741643499u },
    { 9442102732174407063u, 451842233393314799u },
    { 11243031000481435974u, 361473786714651839u },
    { 12683773615127059102u, 289179029371721471u },
    { 12915340154719473917u, 462686446994754354u },
    { 14021620938517489457u, 370149157595803483u },
    { 149250306588260596u, 296119326076642787u },
    { 3928149305283127276u, 473790921722628459u },
    { 6831868258968412144u, 379032737378102767u },
    { 16533541051400460685u, 303226189902482213u },
    { 4317572793789275157u, 485161903843971542u },
    { 14522104679257151095u, 388129523075177233u },
    { 549637299179989907u, 310503618460141787u },
    { 4568768493429894174u, 496805789536226859u },
    { 7344363609485825662u, 397444631628981487u },
    { 16943537331814391499u, 317955705303185189u },
    { 16041613286677295429u, 508729128485096303u },
    { 1765244185116105374u, 406983302788077043u },
    { 8790892977576704946u, 325586642230461634u },
    { 2997382319896996943u, 520938627568738615u },
    { 2397905855917597554u, 416750902054990892u },
    { 12986371128959809013u, 333400721643992713u },
    { 17088844991593784098u, 533441154630388341u },
    { 9981727178533116955u, 426752923704310673u },
    { 15364079372310314211u, 341402338963448538u },
    { 2446434107245040797u, 546243742341517662u },
    { 13025193730021763608u, 436994993873214129u },
    { 14109503798759321209u, 349595995098571303u },
    { 439113189563451996u, 559353592157714086u },
    { 15108685810618402889u, 447482873726171268u },
    { 1018902204268991342u, 357986298980937015u },
    { 1630243526830386147u, 572778078369499224u },
    { 4993543636206219241u, 458222462695599379u },
    { 7684183723706885716u, 366577970156479503u },
    { 13526044608449329219u, 293262376125183602u },
    { 6884276114551285458u, 469219801800293764u },
    { 9196769706382938689u, 375375841440235011u },
    { 3668066950364440628u, 300300673152188009u },
    { 13247604750066925652u, 480481077043500814u },
    { 14287432614795450845u, 384384861634800651u },
    { 7740597277094450353u, 307507889307840521u },
    { 5006258013867299917u, 492012622892544834u },
    { 7694355225835750257u, 393610098314035867u },
    { 17223530624894331176u, 314888078651228693u },
    { 5421556111379467941u, 503820925841965910u },
    { 4337244889103574353u, 403056740673572728u },
    { 10848493540766680129u, 322445392538858182u },
    { 2600194406259046913u, 515912628062173092u },
    { 13148201969232968500u, 412730102449738473u },
    { 17897259204870195447u, 330184081959790778u },
    { 6499521839340850775u, 528294531135665246u },
    { 1510268656730770297u, 422635624908532197u },
    { 12276261369610347207u, 338108499926825757u },
    { 4884622932408914239u, 540973599882921212u },
    { 14975744790152862361u, 432778879906336969u },
    { 15669944646864200212u, 346223103925069575u },
    { 6625167361273168723u, 553956966280111321u },
    { 1610785074276624655u, 443165573024089057u },
    { 12356674503647030694u, 354532458419271245u },
    { 1323935132125697494u, 567251933470833993u },
    { 8437845735184378642u, 453801546776667194u },
    { 10439625402889413237u, 363041237421333755u },
    { 8351700322311530589u, 290432989937067004u },
    { 2294674071472717973u, 464692783899307207u },
    { 12903785701403905348u, 371754227119445765u },
    { 10323028561123124279u, 297403381695556612u },
    { 1759450438829357553u, 475845410712890580u },
    { 1407560351063486042u, 380676328570312464u },
    { 4815397095592699157u, 304541062856249971u },
    { 325937723464498005u, 487265700569999954u },
    { 3950098993513508727u, 389812560455999963u },
    { 10538776824294627628u, 311850048364799970u },
    { 16862042918871404205u, 498960077383679952u },
    { 6110936705613302717u, 399168061906943962u },
    { 15956795808716373144u, 319334449525555169u },
    { 14462826849720466060u, 510935119240888271u },
    { 7880912665034462525u, 408748095392710617u },
    { 17372776576253300990u, 326998476314168493u },
    { 5660349633553819644u, 523197562102669590u },
    { 4528279706843055715u, 418558049682135672u },
    { 14690670209700175542u, 334846439745708537u },
    { 8747677076552639574u, 535754303593133660u },
    { 6998141661242111659u, 428603442874506928u },
    { 12977210958477509974u, 342882754299605542u },
    { 6006142274596374665u, 548612406879368868u },
    { 12183611449160920378u, 438889925503495094u },
    { 13436237974070646626u, 351111940402796075u },
    { 3051236684803482985u, 561779104644473721u },
    { 17198384606810427681u, 449423283715578976u },
    { 10069358870706431822u, 359538626972463181u },
};

static const uint64_t DOUBLE_POW5_SPLIT[326][2] = {
    { 0u, 288230376151711744u },
    { 0u, 360287970189639680u },
    { 0u, 450359962737049600u },
    { 0u, 562949953421312000u },
    { 0u, 351843720888320000u },
    { 0u, 439804651110400000u },
    { 0u, 549755813888000000u },
    { 0u, 343597383680000000u },
    { 0u, 429496729600000000u },
    { 0u, 536870912000000000u },
    { 0u, 335544320000000000u },
    { 0u, 419430400000000000u },
    { 0u, 524288000000000000u },
    { 0u, 327680000000000000u },
    { 0u, 409600000000000000u },
    { 0u, 512000000000000000u },
    { 0u, 320000000000000000u },
    { 0u, 400000000000000000u },
    { 0u, 500000000000000000u },
    { 0u, 312500000000000000u },
    { 0u, 390625000000000000u },
    { 0u, 488281250000000000u },
    { 0u, 305175781250000000u },
    { 0u, 381469726562500000u },
    { 0u, 476837158203125000u },
    { 0u, 298023223876953125u },
    { 4611686018427387904u, 372529029846191406u },
    { 14987979559889010688u, 465661287307739257u },
    { 2449958197289549824u, 291038304567337036u },
    { 3062447746611937280u, 363797880709171295u },
    { 17663117738547085312u, 454747350886464118u },
    { 12855525136329080832u, 568434188608080148u },
    { 17258075247060451328u, 355271367880050092u },
    { 3125849985116012544u, 444089209850062616u },
    { 3907312481395015680u, 555111512312578270u },
    { 16277128356154048512u, 346944695195361418u },
    { 11123038408337784832u, 433680868994201773u },
    { 68739955140067328u, 542101086242752217u },
    { 11572177518031011840u, 338813178901720135u },
    { 9853535879111376896u, 423516473627150169u },
    { 16928605867316609024u, 529395592033937711u },
    { 17497907694713962496u, 330872245021211069u },
    { 8037326563110289408u, 413590306276513837u },
    { 14658344222315249664u, 516987882845642296u },
    { 9161465138947031040u, 323117426778526435u },
    { 6840145405256400896u, 403896783473158044u },
    { 8550181756570501120u, 504870979341447555u },
    { 3038020588642869248u, 315544362088404722u },
    { 13020897772658362368u, 394430452610505902u },
    { 7052750178968177152u, 493038065763132378u },
    { 9019654880282498624u, 308148791101957736u },
    { 11274568600353123280u, 385185988877447170u },
    { 4869838713586628292u, 481482486096808963u },
    { 737806186777948730u, 300926553810505602u },
    { 10145629770327211721u, 376158192263132002u },
    { 3458665176054238843u, 470197740328915003u },
    { 18302566799529756941u, 293873587705571876u },
    { 4431464425702644560u, 367341984631964846u },
    { 14762702568983081508u, 459177480789956057u },
    { 4618320155946688173u, 573971850987445072u },
    { 2886450097466680108u, 358732406867153170u },
    { 12831434658688125943u, 448415508583941462u },
    { 6815921286505381621u, 560519385729926828u },
    { 13483322840920639321u, 350324616081204267u },
    { 12242467532723411247u, 437905770101505334u },
    { 6079712379049488251u, 547382212626881668u },
    { 13023192273760705965u, 342113882891801042u },
    { 7055618305346106648u, 427642353614751303u },
    { 4207836863255245406u, 534552942018439129u },
    { 14159113085602998139u, 334095588761524455u },
    { 13087205338576359770u, 417619485951905569u },
    { 2523948617938286000u, 522024357439881962u },
    { 6189153904638816654u, 326265223399926226u },
    { 16959814417653296626u, 407831529249907782u },
    { 11976395985211844974u, 509789411562384728u },
    { 7485247490757403109u, 318618382226490455u },
    { 4744873345019365982u, 398272977783113069u },
    { 10542777699701595381u, 497841222228891336u },
    { 6589236062313497113u, 311150763893057085u },
    { 12848231096319259296u, 388938454866321356u },
    { 16060288870399074120u, 486173068582901695u },
    { 16955209571640503181u, 303858167864313559u },
    { 16582325946123241072u, 379822709830391949u },
    { 6892849377371887628u, 474778387287989937u },
    { 15837245906925899527u, 296736492054993710u },
    { 10573185346802598601u, 370920615068742138u },
    { 3993109646648472444u, 463650768835927673u },
    { 14024908575223765037u, 289781730522454795u },
    { 12919449700602318393u, 362227163153068494u },
    { 6925940088898122183u, 452783953941335618u },
    { 17880797147977428537u, 565979942426669522u },
    { 15787184235913280739u, 353737464016668451u },
    { 15122294276464213020u, 442171830020835564u },
    { 456123771870714659u, 552714787526044456u },
    { 285077357419196662u, 345446742203777785u },
    { 4968032715201383731u, 431808427754722231u },
    { 1598354875574341760u, 539760534693402789u },
    { 3304814806447657552u, 337350334183376743u },
    { 17966076563341735652u, 421687917729220928u },
    { 4010851630467617949u, 527109897161526161u },
    { 14035997315110730978u, 329443685725953850u },
    { 8321624607033637915u, 411804607157442313u },
    { 15013716777219435298u, 514755758946802891u },
    { 7077729976548453109u, 321722349341751807u },
    { 4235476452258178482u, 402152936677189759u },
    { 682659546895335199u, 502691170846487199u },
    { 7344191244450666355u, 314181981779054499u },
    { 4568553037135945040u, 392727477223818124u },
    { 5710691296419931300u, 490909346529772655u },
    { 10486711087903538918u, 306818341581107909u },
    { 17720074878306811552u, 383522926976384886u },
    { 12926721561028738632u, 479403658720481108u },
    { 17302573012497737453u, 299627286700300692u },
    { 3181472191912620200u, 374534108375375866u },
    { 13200212276745551059u, 468167635469219832u },
    { 8250132672965969411u, 292604772168262395u },
    { 5700979822780073860u, 365755965210327994u },
    { 16349596815329868134u, 457194956512909992u },
    { 1990251945452783551u, 571493695641137491u },
    { 17384808530403847383u, 357183559775710931u },
    { 17119324644577421325u, 446479449719638664u },
    { 2952411732012225041u, 558099312149548331u },
    { 17986158397003498314u, 348812070093467706u },
    { 13259325959399597085u, 436015087616834633u },
    { 2739099393967332644u, 545018859521043292u },
    { 10935309158084358711u, 340636787200652057u },
    { 18280822466032836292u, 425795984000815071u },
    { 18239342064113657461u, 532244980001018839u },
    { 18317117817712117769u, 332653112500636774u },
    { 13673025235285371404u, 415816390625795968u },
    { 17091281544106714255u, 519770488282244960u },
    { 10682050965066696409u, 324856555176403100u },
    { 13352563706333370511u, 406070693970503875u },
    { 12079018614489325235u, 507588367463129844u },
    { 16772758670910604080u, 317242729664456152u },
    { 2519204264928703484u, 396553412080570191u },
    { 16984063386443043067u, 495691765100712738u },
    { 15226725634954289821u, 309807353187945461u },
    { 5198348988410698564u, 387259191484931827u },
    { 1886250217085985301u, 484073989356164784u },
    { 1178906385678740813u, 302546243347602990u },
    { 10697005018953201824u, 378182804184503737u },
    { 17982942292118890185u, 472728505230629671u },
    { 18156867960215388221u, 295455315769143544u },
    { 4249340876559683661u, 369319144711429431u },
    { 699990077272216672u, 461648930889286789u },
    { 2743336807508829372u, 288530581805804243u },
    { 17264229064668200427u, 360663227257255303u },
    { 16968600312407862630u, 450829034071569129u },
    { 7375692335227664575u, 563536292589461412u },
    { 13833179746372066167u, 352210182868413382u },
    { 8068102646110306901u, 440262728585516728u },
    { 10085128307637883627u, 550328410731895910u },
    { 1691519173846289363u, 343955256707434944u },
    { 2114398967307861703u, 429944070884293680u },
    { 2642998709134827129u, 537430088605367100u },
    { 10875246230064042764u, 335893805378354437u },
    { 18205743806007441359u, 419867256722943046u },
    { 13533807720654525890u, 524834070903678808u },
    { 8458629825409078681u, 328021294314799255u },
    { 5961601263333960448u, 410026617893499069u },
    { 12063687597594838464u, 512533272366873836u },
    { 16763176785351549848u, 320333295229296147u },
    { 16342284963262049406u, 400416619036620184u },
    { 1981112130368010141u, 500520773795775231u },
    { 8155724109121088194u, 312825483622359519u },
    { 5582969117973972339u, 391031854527949399u },
    { 2367025379040077520u, 488789818159936749u },
    { 3785233871113742402u, 305493636349960468u },
    { 4731542338892178002u, 381867045437450585u },
    { 10526113942042610407u, 477333806796813231u },
    { 13496350241417713360u, 298333629248008269u },
    { 3035379746489977988u, 372917036560010337u },
    { 8405910701539860389u, 466146295700012921u },
    { 16782909234530882503u, 291341434812508075u },
    { 16366950524736215225u, 364176793515635094u },
    { 11235316119065493223u, 455220991894543868u },
    { 14044145148831866529u, 569026239868179835u },
    { 6471747708806222629u, 355641399917612397u },
    { 12701370654435166190u, 444551749897015496u },
    { 15876713318043957738u, 555689687371269370u },
    { 14534631842204861490u, 347306054607043356u },
    { 18168289802756076862u, 434132568258804195u },
    { 18098676235017708174u, 542665710323505244u },
    { 2088300610031291801u, 339166068952190778u },
    { 11833747799393890559u, 423957586190238472u },
    { 14792184749242363199u, 529946982737798090u },
    { 13856801486703864903u, 331216864211123806u },
    { 8097629821525055321u, 414021080263904758u },
    { 898665240051543343u, 517526350329880948u },
    { 9785037811886990397u, 323453968956175592u },
    { 12231297264858737997u, 404317461195219490u },
    { 6065749544218646688u, 505396826494024363u },
    { 1485250455922960228u, 315873016558765227u },
    { 15691621125185863997u, 394841270698456533u },
    { 5779468351200166284u, 493551588373070667u },
    { 1306324710286409976u, 308469742733169167u },
    { 15467963943140176182u, 385587178416461458u },
    { 10111582892070444419u, 481983973020576823u },
    { 13237268335185109618u, 301239983137860514u },
    { 7323213382126611214u, 376549978922325643u },
    { 4542330709230876114u, 470687473652907054u },
    { 16674014748551461283u, 294179671033066908u },
    { 2395774361979774988u, 367724588791333636u },
    { 2994717952474718735u, 459655735989167045u },
    { 8355083459020786323u, 574569669986458806u },
    { 610241143460603548u, 359106043741536754u },
    { 9986173466180530243u, 448882554676920942u },
    { 3259344795870886996u, 561103193346151178u },
    { 6648776515846692276u, 350689495841344486u },
    { 17534342681663141153u, 438361869801680607u },
    { 17306242333651538538u, 547952337252100759u },
    { 17733930486173293442u, 342470210782562974u },
    { 12944041070861840994u, 428087763478203718u },
    { 6956679301722525435u, 535109704347754648u },
    { 4347924563576578397u, 334443565217346655u },
    { 823219686043335092u, 418054456521683319u },
    { 14864082662836332577u, 522568070652104148u },
    { 66679627417932053u, 326605044157565093u },
    { 4695035552699802970u, 408256305196956366u },
    { 15092166477729529520u, 510320381496195457u },
    { 2515075020939874094u, 318950238435122161u },
    { 7755529794602230522u, 398687798043902701u },
    { 14306098261680176056u, 498359747554878376u },
    { 8941311413550110035u, 311474842221798985u },
    { 15788325285365025448u, 389343552777248731u },
    { 15123720588278893906u, 486679440971560914u },
    { 14064011386101696595u, 304174650607225571u },
    { 12968328214199732840u, 380218313259031964u },
    { 16210410267749666050u, 475272891573789955u },
    { 7825663408129847329u, 297045557233618722u },
    { 558707223307533353u, 371306946542023403u },
    { 14533442084416580404u, 464133683177529253u },
    { 11389244311974056704u, 290083551985955783u },
    { 9624869371540182976u, 362604439982444729u },
    { 16642772732852616625u, 453255549978055911u },
    { 16191779897638382877u, 566569437472569889u },
    { 3202333408382907442u, 354105898420356181u },
    { 8614602778906022207u, 442632373025445226u },
    { 1544881436777751950u, 553290466281806533u },
    { 3271393907199788921u, 345806541426129083u },
    { 17924300439281899863u, 432258176782661353u },
    { 8570317493820211117u, 540322720978326692u },
    { 14579820470492407756u, 337701700611454182u },
    { 9001403551260733887u, 422127125764317728u },
    { 11251754439075917359u, 527658907205397160u },
    { 7032346524422448349u, 329786817003373225u },
    { 13402119173955448341u, 412233521254216531u },
    { 12140962949016922522u, 515291901567770664u },
    { 7588101843135576576u, 322057438479856665u },
    { 14096813322346858624u, 402571798099820831u },
    { 13009330634506185376u, 503214747624776039u },
    { 15048360674207447716u, 314509217265485024u },
    { 363706769049758029u, 393136521581856281u },
    { 5066319479739585440u, 491420651977320351u },
    { 10083978702478322756u, 307137907485825219u },
    { 7993287359670515541u, 383922384357281524u },
    { 9991609199588144427u, 479902980446601905u },
    { 17773970795811060026u, 299939362779126190u },
    { 12994091457909049225u, 374924203473907738u },
    { 7019242285531535724u, 468655254342384673u },
    { 15916241474525679587u, 292909533963990420u },
    { 1448557769447547868u, 366136917454988026u },
    { 11034069248664210643u, 457671146818735032u },
    { 13792586560830263304u, 572088933523418790u },
    { 4008680582091526661u, 357555583452136744u },
    { 5010850727614408326u, 446944479315170930u },
    { 15486935446372786216u, 558680599143963662u },
    { 5067648635555603481u, 349175374464977289u },
    { 10946246812871892255u, 436469218081221611u },
    { 9071122497662477415u, 545586522601527014u },
    { 1057765542611660480u, 340991576625954384u },
    { 1322206928264575600u, 426239470782442980u },
    { 1652758660330719500u, 532799338478053725u },
    { 3338817171920393640u, 332999586548783578u },
    { 13396893501755267858u, 416249483185979472u },
    { 16746116877194084822u, 520311853982474340u },
    { 1242951011391527206u, 325194908739046463u },
    { 15388746819521572719u, 406493635923808078u },
    { 10012561487547190091u, 508117044904760098u },
    { 10869536948144381711u, 317573153065475061u },
    { 18198607203607865043u, 396966441331843826u },
    { 13524886967655055495u, 496208051664804783u },
    { 15370583382425491540u, 310130032290502989u },
    { 5378171172749700714u, 387662540363128737u },
    { 11334399984364513796u, 484578175453910921u },
    { 166470962586739266u, 302861359658694326u },
    { 9431460740088199891u, 378576699573367907u },
    { 7177639906682861960u, 473220874466709884u },
    { 13709396978531564533u, 295763046541693677u },
    { 3301688167882291954u, 369703808177117097u },
    { 8738796228280252847u, 462129760221396371u },
    { 3155904633461464077u, 288831100138372732u },
    { 3944880791826830096u, 361038875172965915u },
    { 319414971356149717u, 451298593966207394u },
    { 9622640751049962954u, 564123242457759242u },
    { 10625836487833614750u, 352577026536099526u },
    { 4058923572937242630u, 440721283170124408u },
    { 5073654466171553287u, 550901603962655510u },
    { 17006092096639384516u, 344313502476659693u },
    { 7422557065517066934u, 430391878095824617u },
    { 13889882350323721571u, 537989847619780771u },
    { 6375333459738632030u, 336243654762362982u },
    { 17192538861528065845u, 420304568452953727u },
    { 16878987558482694403u, 525380710566192159u },
    { 17466896251692765858u, 328362944103870099u },
    { 17221934296188569418u, 410453680129837624u },
    { 3080673796526160157u, 513067100162297031u },
    { 8842950150469931954u, 320666937601435644u },
    { 11053687688087414942u, 400833672001794555u },
    { 9205423591681880774u, 501042090002243194u },
    { 10365075763228563388u, 313151306251401996u },
    { 12956344704035704235u, 391439132814252495u },
    { 11583744861617242389u, 489298916017815619u },
    { 4933997529297082541u, 305811822511134762u },
    { 15390868948476128985u, 382264778138918452u },
    { 791842111885609615u, 477830972673648066u },
    { 5106587338355893913u, 298644357921030041u },
    { 10994920191372255296u, 373305447401287551u },
    { 9131964220787931216u, 466631809251609439u },
    { 12625006665633538866u, 291644880782255899u },
    { 11169572313614535678u, 364556100977819874u },
    { 4738593355163393790u, 455695126222274843u },
    { 1311555675526854333u, 569618907777843554u },
    { 5431408315631671862u, 356011817361152221u },
    { 11400946412966977732u, 445014771701440276u },
};

// 64x64 -> 128-bit multiply, returning the low word and writing the high word.
inline uint64_t umul128(uint64_t a, uint64_t b, uint64_t* hi) {
#if defined(__SIZEOF_INT128__)
    const __uint128_t product = static_cast<__uint128_t>(a) * b;
    *hi = static_cast<uint64_t>(product >> 64);
    return static_cast<uint64_t>(product);
#else
    const uint32_t aLo = static_cast<uint32_t>(a), aHi = static_cast<uint32_t>(a >> 32);
    const uint32_t bLo = static_cast<uint32_t>(b), bHi = static_cast<uint32_t>(b >> 32);
    const uint64_t b00 = static_cast<uint64_t>(aLo) * bLo;
    const uint64_t b01 = static_cast<uint64_t>(aLo) * bHi;
    const uint64_t b10 = static_cast<uint64_t>(aHi) * bLo;
    const uint64_t b11 = static_cast<uint64_t>(aHi) * bHi;
    const uint64_t mid = (b00 >> 32) + static_cast<uint32_t>(b10) + static_cast<uint32_t>(b01);
    *hi = b11 + (b10 >> 32) + (b01 >> 32) + (mid >> 32);
    return (b00 & 0xffffffffu) | (mid << 32);
#endif
}

// Right-shift a 128-bit value (hi:lo) by dist in (0, 64), returning the low word.
inline uint64_t shiftright128(uint64_t lo, uint64_t hi, uint32_t dist) {
    return (hi << (64 - dist)) | (lo >> dist);
}

// floor(m * mul / 2^j) for j in (64, 128), using only the high half of the product.
inline uint64_t mulShift64(uint64_t m, const uint64_t* mul, int32_t j) {
    uint64_t high1;
    const uint64_t low1 = umul128(m, mul[1], &high1);
    uint64_t high0;
    umul128(m, mul[0], &high0);          // low half is irrelevant at this precision
    const uint64_t sum = high0 + low1;
    if (sum < high0) ++high1;            // propagate the carry
    return shiftright128(sum, high1, static_cast<uint32_t>(j - 64));
}

// Compute the three boundary values vr, vp, vm in one go (all share the multiply).
inline uint64_t mulShiftAll64(uint64_t m, const uint64_t* mul, int32_t j,
                              uint64_t* vp, uint64_t* vm, uint32_t mmShift) {
    *vp = mulShift64(4 * m + 2, mul, j);
    *vm = mulShift64(4 * m - 1 - mmShift, mul, j);
    return mulShift64(4 * m, mul, j);
}

inline uint32_t pow5Factor(uint64_t value) {
    uint32_t count = 0;
    for (;;) {
        const uint64_t q = value / 5;
        if (static_cast<uint32_t>(value - 5 * q) != 0) break;
        value = q;
        ++count;
    }
    return count;
}
inline bool multipleOfPowerOf5(uint64_t value, uint32_t p) { return pow5Factor(value) >= p; }
inline bool multipleOfPowerOf2(uint64_t value, uint32_t p) { return (value & ((1ull << p) - 1)) == 0; }

// Cheap integer approximations, exact over the range the algorithm needs them.
inline uint32_t log10Pow2(int32_t e) { return (static_cast<uint32_t>(e) * 78913) >> 18; }
inline uint32_t log10Pow5(int32_t e) { return (static_cast<uint32_t>(e) * 732923) >> 20; }
inline int32_t  pow5bits(int32_t e)  { return static_cast<int32_t>(((static_cast<uint32_t>(e) * 1217359) >> 19) + 1); }

inline uint32_t decimalLength17(uint64_t v) {
    uint32_t len = 1;
    while (v >= 10) { v /= 10; ++len; }
    return len;
}

// value == mantissa * 10^exponent, where mantissa carries the fewest digits that
// still round-trip. ieeeMantissa / ieeeExponent are the raw 52-/11-bit fields.
struct Decimal { uint64_t mantissa; int32_t exponent; };

inline Decimal d2d(uint64_t ieeeMantissa, uint32_t ieeeExponent) {
    int32_t e2;
    uint64_t m2;
    if (ieeeExponent == 0) {
        e2 = 1 - 1023 - 52;
        m2 = ieeeMantissa;
    } else {
        e2 = static_cast<int32_t>(ieeeExponent) - 1023 - 52;
        m2 = (1ull << 52) | ieeeMantissa;
    }
    const bool acceptBounds = (m2 & 1) == 0;

    const uint64_t mv = 4 * m2;
    const uint32_t mmShift = (ieeeMantissa != 0 || ieeeExponent <= 1) ? 1 : 0;

    uint64_t vr, vp, vm;
    int32_t e10;
    bool vmIsTrailingZeros = false, vrIsTrailingZeros = false;

    if (e2 >= 0) {
        const uint32_t q = log10Pow2(e2) - (e2 > 3);
        e10 = static_cast<int32_t>(q);
        const int32_t k = kPow5InvBitcount + pow5bits(static_cast<int32_t>(q)) - 1;
        const int32_t i = -e2 + static_cast<int32_t>(q) + k;
        vr = mulShiftAll64(m2, DOUBLE_POW5_INV_SPLIT[q], i, &vp, &vm, mmShift);
        if (q <= 21) {
            if (mv % 5 == 0)            vrIsTrailingZeros = multipleOfPowerOf5(mv, q);
            else if (acceptBounds)      vmIsTrailingZeros = multipleOfPowerOf5(mv - 1 - mmShift, q);
            else                        vp -= multipleOfPowerOf5(mv + 2, q);
        }
    } else {
        const uint32_t q = log10Pow5(-e2) - (-e2 > 1);
        e10 = static_cast<int32_t>(q) + e2;
        const int32_t i = -e2 - static_cast<int32_t>(q);
        const int32_t k = pow5bits(i) - kPow5Bitcount;
        const int32_t j = static_cast<int32_t>(q) - k;
        vr = mulShiftAll64(m2, DOUBLE_POW5_SPLIT[i], j, &vp, &vm, mmShift);
        if (q <= 1) {
            vrIsTrailingZeros = true;
            if (acceptBounds) vmIsTrailingZeros = mmShift == 1;
            else --vp;
        } else if (q < 63) {
            vrIsTrailingZeros = multipleOfPowerOf2(mv, q);
        }
    }

    int32_t removed = 0;
    uint8_t lastRemovedDigit = 0;
    uint64_t output;
    if (vmIsTrailingZeros || vrIsTrailingZeros) {
        // Rare path: vm or vr ends in exact zeros, so track them precisely.
        for (;;) {
            const uint64_t vpDiv10 = vp / 10, vmDiv10 = vm / 10;
            if (vpDiv10 <= vmDiv10) break;
            const uint32_t vmMod10 = static_cast<uint32_t>(vm - 10 * vmDiv10);
            const uint64_t vrDiv10 = vr / 10;
            const uint32_t vrMod10 = static_cast<uint32_t>(vr - 10 * vrDiv10);
            vmIsTrailingZeros &= vmMod10 == 0;
            vrIsTrailingZeros &= lastRemovedDigit == 0;
            lastRemovedDigit = static_cast<uint8_t>(vrMod10);
            vr = vrDiv10; vp = vpDiv10; vm = vmDiv10; ++removed;
        }
        if (vmIsTrailingZeros) {
            for (;;) {
                const uint64_t vmDiv10 = vm / 10;
                const uint32_t vmMod10 = static_cast<uint32_t>(vm - 10 * vmDiv10);
                if (vmMod10 != 0) break;
                const uint64_t vpDiv10 = vp / 10, vrDiv10 = vr / 10;
                const uint32_t vrMod10 = static_cast<uint32_t>(vr - 10 * vrDiv10);
                vrIsTrailingZeros &= lastRemovedDigit == 0;
                lastRemovedDigit = static_cast<uint8_t>(vrMod10);
                vr = vrDiv10; vp = vpDiv10; vm = vmDiv10; ++removed;
            }
        }
        if (vrIsTrailingZeros && lastRemovedDigit == 5 && vr % 2 == 0)
            lastRemovedDigit = 4;       // round half to even
        output = vr + ((vr == vm && (!acceptBounds || !vmIsTrailingZeros)) || lastRemovedDigit >= 5);
    } else {
        // Common path: trim two digits at a time, then one, rounding at the end.
        bool roundUp = false;
        const uint64_t vpDiv100 = vp / 100, vmDiv100 = vm / 100;
        if (vpDiv100 > vmDiv100) {
            const uint64_t vrDiv100 = vr / 100;
            const uint32_t vrMod100 = static_cast<uint32_t>(vr - 100 * vrDiv100);
            roundUp = vrMod100 >= 50;
            vr = vrDiv100; vp = vpDiv100; vm = vmDiv100; removed += 2;
        }
        for (;;) {
            const uint64_t vpDiv10 = vp / 10, vmDiv10 = vm / 10;
            if (vpDiv10 <= vmDiv10) break;
            const uint64_t vrDiv10 = vr / 10;
            roundUp = static_cast<uint32_t>(vr - 10 * vrDiv10) >= 5;
            vr = vrDiv10; vp = vpDiv10; vm = vmDiv10; ++removed;
        }
        output = vr + (vr == vm || roundUp);
    }
    return { output, e10 + removed };
}

} // namespace ryu


void dump_double(std::string& out, double d) {
    if (std::isnan(d) || std::isinf(d)) { out += "null"; return; }  // JSON has no NaN/Inf

    uint64_t bits;
    std::memcpy(&bits, &d, sizeof bits);
    if (bits >> 63) out += '-';
    const uint64_t mantissa = bits & ((1ull << 52) - 1);
    const uint32_t exponent = static_cast<uint32_t>((bits >> 52) & 0x7ff);
    if (mantissa == 0 && exponent == 0) { out += "0.0"; return; }  // +/-0

    const ryu::Decimal dec = ryu::d2d(mantissa, exponent);

    char digits[17];                       // a double needs at most 17 significant digits
    const uint32_t olen = ryu::decimalLength17(dec.mantissa);
    uint64_t m = dec.mantissa;
    for (uint32_t k = olen; k > 0; --k) {  // fill least-significant digit first
        digits[k - 1] = static_cast<char>('0' + m % 10);
        m /= 10;
    }

    const int32_t e10      = dec.exponent;
    const int32_t pointPos = static_cast<int32_t>(olen) + e10;  // decimal point from the left
    const int32_t sciExp   = pointPos - 1;                      // exponent in d.ddd x 10^sciExp form

    // Pick fixed or scientific by whichever is shorter (ties -> fixed), the same
    // shortest-form rule std::to_chars applies; then guarantee a '.' or 'e' so the
    // token always reparses as a float rather than an integer.
    int fixedLen;
    if (pointPos <= 0)                 fixedLen = 2 - pointPos + static_cast<int>(olen);  // 0.00ddd
    else if (pointPos >= (int)olen)    fixedLen = pointPos + 2;                            // ddd00.0
    else                               fixedLen = static_cast<int>(olen) + 1;             // dd.ddd
    const int expDigits = ((sciExp < 0 ? -sciExp : sciExp) >= 100) ? 3 : 2;
    const int sciLen = static_cast<int>(olen) + (olen > 1 ? 1 : 0) + 2 + expDigits;

    if (fixedLen <= sciLen) {
        if (pointPos <= 0) {
            out += "0.";
            out.append(static_cast<std::size_t>(-pointPos), '0');
            out.append(digits, olen);
        } else if (pointPos >= static_cast<int>(olen)) {
            out.append(digits, olen);
            out.append(static_cast<std::size_t>(pointPos - static_cast<int>(olen)), '0');
            out += ".0";
        } else {
            out.append(digits, static_cast<std::size_t>(pointPos));
            out += '.';
            out.append(digits + pointPos, olen - static_cast<uint32_t>(pointPos));
        }
    } else {
        out += digits[0];
        if (olen > 1) { out += '.'; out.append(digits + 1, olen - 1); }
        out += 'e';
        out += (sciExp < 0) ? '-' : '+';
        uint32_t ae = static_cast<uint32_t>(sciExp < 0 ? -sciExp : sciExp);
        char eb[3];
        if (ae >= 100) {
            eb[0] = static_cast<char>('0' + ae / 100);
            eb[1] = static_cast<char>('0' + ae / 10 % 10);
            eb[2] = static_cast<char>('0' + ae % 10);
            out.append(eb, 3);
        } else {
            eb[0] = static_cast<char>('0' + ae / 10);
            eb[1] = static_cast<char>('0' + ae % 10);
            out.append(eb, 2);
        }
    }
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
