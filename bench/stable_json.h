#pragma once

/**
 * @file json.h
 * @brief A small, self-contained JSON value type for librats.
 *
 * `librats::Json` is a dynamically-typed JSON value with a deliberately
 * nlohmann-flavoured surface so existing call sites read naturally:
 *
 *   Json j;                         // null
 *   j["name"]   = "rats";           // becomes an object
 *   j["count"]  = 42;               // signed integer
 *   j["tags"]   = Json::array();    // empty array
 *   j["tags"].push_back("p2p");
 *
 *   Json cfg = {                    // initializer-list "object" detection,
 *       {"version", 1},             // exactly like nlohmann: a list whose
 *       {"nodes", {{"id", "ab"}}},  // every element is a [string, value] pair
 *   };                              // is treated as an object.
 *
 *   std::string text = j.dump();            // compact
 *   std::string nice = j.dump(2);           // pretty, 2-space indent
 *   Json back = Json::parse(text);          // throws on malformed input
 *   Json safe = Json::parse(text, nullptr, false);  // never throws; see is_discarded()
 *
 * Design notes:
 *  - Numbers keep their kind (signed / unsigned / floating) so integers
 *    round-trip exactly and large 64-bit values are not silently truncated.
 *  - Objects preserve insertion order while offering O(1) average key lookup.
 *  - Heavy payloads (string / array / object) live behind a pointer, so a Json
 *    value is small (a tag plus one word) and cheap to move.
 *  - The parser is iterative-friendly recursive descent with a depth guard, so
 *    adversarial deeply-nested input fails cleanly instead of smashing the stack.
 */

#include <cstdint>
#include <initializer_list>
#include <iosfwd>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

namespace librats_stable {

/// Thrown by the throwing parse path and by type-mismatched accessors.
/// Derives from std::runtime_error so existing catch(const std::exception&)
/// blocks keep working unchanged.
class JsonError : public std::runtime_error {
public:
    explicit JsonError(const std::string& what) : std::runtime_error(what) {}
};

class Json {
public:
    enum class Type : uint8_t {
        Null,
        Boolean,
        Integer,   // signed, stored as int64_t
        Unsigned,  // unsigned, stored as uint64_t
        Float,     // stored as double
        String,
        Array,
        Object,
        Discarded, // result of a non-throwing parse failure
    };

    using Array = std::vector<Json>;

    /// Insertion-ordered string->Json map with O(1) average lookup.
    class Object {
    public:
        using value_type = std::pair<std::string, Json>;
        using storage    = std::vector<value_type>;

        Object() = default;
        Object(const Object&) = default;
        Object(Object&&) noexcept = default;
        Object& operator=(const Object&) = default;
        Object& operator=(Object&&) noexcept = default;

        Json& operator[](const std::string& key);          // inserts null if absent
        Json& operator[](std::string&& key);                // ditto, moves key on insert
        const Json* find(const std::string& key) const;     // nullptr if absent
        Json* find(const std::string& key);                 // nullptr if absent
        bool contains(const std::string& key) const { return find(key) != nullptr; }
        bool erase(const std::string& key);

        std::size_t size() const { return items_.size(); }
        bool empty() const { return items_.empty(); }
        void clear() { items_.clear(); index_.clear(); indexed_ = false; }

        storage::iterator begin() { return items_.begin(); }
        storage::iterator end() { return items_.end(); }
        storage::const_iterator begin() const { return items_.begin(); }
        storage::const_iterator end() const { return items_.end(); }

        bool operator==(const Object& other) const;  // order-independent

    private:
        // Small objects (the common case — a peer record, a config node) keep
        // only the insertion-ordered vector and look keys up with a linear scan,
        // which beats hashing for a handful of entries and costs no allocation.
        // The hash index is built lazily once the object grows past the
        // threshold; invariant: indexed_ is true whenever size() > threshold.
        static constexpr std::size_t kIndexThreshold = 16;

        void build_index();  // populate index_ from items_, set indexed_
        void reindex();      // rebuild (if large) or drop (if small) after erase

        // Shared find-or-insert for both operator[] overloads. K is deduced as
        // `const std::string&` or `std::string&&`, so the key is copied or moved
        // into storage to match how the caller supplied it.
        template <typename K>
        Json& emplace_key(K&& key);

        storage items_;
        std::unordered_map<std::string, std::size_t> index_;
        bool indexed_ = false;
    };

    // ── Construction ────────────────────────────────────────────────────────

    Json() noexcept : type_(Type::Null) {}
    Json(std::nullptr_t) noexcept : type_(Type::Null) {}
    Json(bool b) noexcept : type_(Type::Boolean) { bool_ = b; }

    template <typename T,
              typename std::enable_if<std::is_integral<T>::value &&
                                          !std::is_same<T, bool>::value,
                                      int>::type = 0>
    Json(T v) noexcept {
        if (std::is_signed<T>::value) {
            type_ = Type::Integer;
            int_  = static_cast<int64_t>(v);
        } else {
            type_ = Type::Unsigned;
            uint_ = static_cast<uint64_t>(v);
        }
    }

    template <typename T,
              typename std::enable_if<std::is_floating_point<T>::value, int>::type = 0>
    Json(T v) noexcept : type_(Type::Float) { float_ = static_cast<double>(v); }

    Json(const char* s) : type_(Type::String) { str_ = new std::string(s ? s : ""); }
    Json(const std::string& s) : type_(Type::String) { str_ = new std::string(s); }
    Json(std::string&& s) : type_(Type::String) { str_ = new std::string(std::move(s)); }

    /// nlohmann-style brace initialisation. A list whose every element is a
    /// two-element array with a string first element is read as an object;
    /// otherwise it is an array.
    Json(std::initializer_list<Json> init);

    Json(const Json& other) { copy_from(other); }
    Json(Json&& other) noexcept { move_from(other); }

    Json& operator=(const Json& other);
    Json& operator=(Json&& other) noexcept;

    ~Json() { destroy(); }

    /// Explicit empties (also handy to force kind on an otherwise-null value).
    static Json array() { Json j; j.type_ = Type::Array; j.arr_ = new Array(); return j; }
    static Json object() { Json j; j.type_ = Type::Object; j.obj_ = new Object(); return j; }

    // ── Parsing ─────────────────────────────────────────────────────────────
    //
    // The second argument exists only for nlohmann call-site compatibility
    // (a parser callback, which this implementation ignores). When
    // allow_exceptions is false a malformed document yields a Discarded value
    // (see is_discarded()) instead of throwing.

    static Json parse(const std::string& text, std::nullptr_t = nullptr,
                      bool allow_exceptions = true);
    static Json parse(const char* text, std::nullptr_t = nullptr,
                      bool allow_exceptions = true);

    template <typename InputIt>
    static Json parse(InputIt first, InputIt last, std::nullptr_t = nullptr,
                      bool allow_exceptions = true) {
        // std::string's range constructor copies [first, last), converting each
        // element to char — this handles const char*, const uint8_t*, etc.
        std::string buf(first, last);
        return parse(buf, nullptr, allow_exceptions);
    }

    // ── Serialisation ───────────────────────────────────────────────────────
    //
    // indent < 0 (the default) produces the most compact form. indent >= 0
    // pretty-prints with that many spaces per level.
    std::string dump(int indent = -1) const;

    // ── Type inspection ─────────────────────────────────────────────────────

    Type type() const noexcept { return type_; }
    bool is_null() const noexcept { return type_ == Type::Null; }
    bool is_boolean() const noexcept { return type_ == Type::Boolean; }
    bool is_number() const noexcept {
        return type_ == Type::Integer || type_ == Type::Unsigned || type_ == Type::Float;
    }
    bool is_number_integer() const noexcept {
        return type_ == Type::Integer || type_ == Type::Unsigned;
    }
    bool is_number_unsigned() const noexcept { return type_ == Type::Unsigned; }
    bool is_number_float() const noexcept { return type_ == Type::Float; }
    bool is_string() const noexcept { return type_ == Type::String; }
    bool is_array() const noexcept { return type_ == Type::Array; }
    bool is_object() const noexcept { return type_ == Type::Object; }
    bool is_discarded() const noexcept { return type_ == Type::Discarded; }
    bool is_primitive() const noexcept {
        return is_null() || is_boolean() || is_number() || is_string();
    }
    bool is_structured() const noexcept { return is_array() || is_object(); }

    /// Number of elements (array/object), or 0 for null, 1 for any scalar.
    std::size_t size() const noexcept;
    /// True for null, an empty array, or an empty object.
    bool empty() const noexcept;

    // ── Object / array access ───────────────────────────────────────────────

    Json& operator[](const std::string& key);
    Json& operator[](const char* key) { return operator[](std::string(key)); }
    const Json& operator[](const std::string& key) const;
    const Json& operator[](const char* key) const { return operator[](std::string(key)); }

    Json& operator[](int index) { return operator[](static_cast<std::size_t>(index)); }
    Json& operator[](std::size_t index);
    const Json& operator[](int index) const {
        return operator[](static_cast<std::size_t>(index));
    }
    const Json& operator[](std::size_t index) const;

    /// Bounds/existence-checked access; throws JsonError when missing.
    Json& at(const std::string& key);
    const Json& at(const std::string& key) const;
    Json& at(std::size_t index);
    const Json& at(std::size_t index) const;

    bool contains(const std::string& key) const {
        return is_object() && obj_->contains(key);
    }
    bool erase(const std::string& key);
    void erase(std::size_t index);

    Json& front();
    const Json& front() const;
    Json& back();
    const Json& back() const;

    void push_back(const Json& value);
    void push_back(Json&& value);
    template <typename... Args>
    Json& emplace_back(Args&&... args) {
        push_back(Json(std::forward<Args>(args)...));
        return back();
    }

    void clear();

    // ── Typed extraction ────────────────────────────────────────────────────

    template <typename T>
    T get() const {
        if constexpr (std::is_same<T, bool>::value) {
            return static_cast<T>(as_bool());
        } else if constexpr (std::is_integral<T>::value) {
            if constexpr (std::is_unsigned<T>::value) return static_cast<T>(as_uint64());
            else return static_cast<T>(as_int64());
        } else if constexpr (std::is_floating_point<T>::value) {
            return static_cast<T>(as_double());
        } else {
            return get_impl(static_cast<T*>(nullptr));
        }
    }

    /// Implicit conversion to arithmetic types and std::string, so call sites
    /// like `int v = j["x"];` and `std::string s = j["y"];` read naturally.
    template <typename T,
              typename std::enable_if<(std::is_arithmetic<T>::value ||
                                       std::is_same<T, std::string>::value) &&
                                          !std::is_same<T, Json>::value,
                                      int>::type = 0>
    operator T() const { return get<T>(); }

    /// value(key, default): typed object lookup with a fallback. Returns the
    /// default when this is not an object or the key is absent.
    template <typename T>
    T value(const std::string& key, const T& default_value) const {
        if (is_object()) {
            if (const Json* v = obj_->find(key)) return v->get<T>();
        }
        return default_value;
    }
    /// const char* default resolves to a std::string result (nlohmann parity).
    std::string value(const std::string& key, const char* default_value) const {
        if (is_object()) {
            if (const Json* v = obj_->find(key)) return v->get<std::string>();
        }
        return std::string(default_value);
    }

    // ── Iteration ───────────────────────────────────────────────────────────
    //
    // Range-for visits array elements, or object values in insertion order.
    // The iterator exposes .key()/.value() (nlohmann-style). For key/value
    // structured bindings, use items(): `for (auto e : j.items()) ...`.

    template <bool Const>
    class Iterator {
    public:
        using JsonRef = typename std::conditional<Const, const Json&, Json&>::type;
        using JsonPtr = typename std::conditional<Const, const Json*, Json*>::type;

        Iterator(JsonPtr owner, std::size_t idx) : owner_(owner), idx_(idx) {}

        JsonRef operator*() const { return value(); }
        JsonPtr operator->() const { return &value(); }
        Iterator& operator++() { ++idx_; return *this; }
        Iterator operator++(int) { Iterator tmp = *this; ++idx_; return tmp; }
        bool operator==(const Iterator& o) const { return owner_ == o.owner_ && idx_ == o.idx_; }
        bool operator!=(const Iterator& o) const { return !(*this == o); }

        const std::string& key() const;
        JsonRef value() const;

    private:
        JsonPtr owner_;
        std::size_t idx_;
    };

    using iterator = Iterator<false>;
    using const_iterator = Iterator<true>;

    iterator begin() { return iterator(this, 0); }
    iterator end() { return iterator(this, size()); }
    const_iterator begin() const { return const_iterator(this, 0); }
    const_iterator end() const { return const_iterator(this, size()); }
    const_iterator cbegin() const { return const_iterator(this, 0); }
    const_iterator cend() const { return const_iterator(this, size()); }

    /// A key/value view supporting structured bindings:
    ///   for (auto&& [key, val] : obj.items()) { ... }
    /// For arrays, key() is the decimal index.
    template <bool Const>
    class ItemsProxy {
    public:
        using JsonPtr = typename std::conditional<Const, const Json*, Json*>::type;
        explicit ItemsProxy(JsonPtr owner) : owner_(owner) {}
        Iterator<Const> begin() const { return Iterator<Const>(owner_, 0); }
        Iterator<Const> end() const { return Iterator<Const>(owner_, owner_->size()); }
    private:
        JsonPtr owner_;
    };

    ItemsProxy<false> items() { return ItemsProxy<false>(this); }
    ItemsProxy<true> items() const { return ItemsProxy<true>(this); }

    // ── Equality ────────────────────────────────────────────────────────────

    bool operator==(const Json& other) const;
    bool operator!=(const Json& other) const { return !(*this == other); }

    // ── Direct container access (advanced) ──────────────────────────────────

    Array& as_array();
    const Array& as_array() const;
    Object& as_object();
    const Object& as_object() const;

private:
    // value storage: scalars live inline, heavy payloads behind a pointer.
    Type type_ = Type::Null;
    union {
        bool bool_;
        int64_t int_;
        uint64_t uint_;
        double float_;
        std::string* str_;
        Array* arr_;
        Object* obj_;
    };

    void destroy() noexcept;
    void copy_from(const Json& other);
    void move_from(Json& other) noexcept;

    bool as_bool() const;
    int64_t as_int64() const;
    uint64_t as_uint64() const;
    double as_double() const;
    const std::string& as_string() const;

    // get_impl tag overloads — only std::string is supported as a class type.
    std::string get_impl(std::string*) const { return as_string(); }

    void dump_to(std::string& out, int indent, int depth) const;

    static Json make_discarded() { Json j; j.type_ = Type::Discarded; return j; }

    // The parser is implemented in json.cpp.
    friend class JsonParser;
};

// Stream helpers: `is >> j` parses the whole stream; `os << j` writes dump().
std::istream& operator>>(std::istream& is, Json& j);
std::ostream& operator<<(std::ostream& os, const Json& j);

// ── Iterator member definitions (need the complete Json type) ───────────────

template <bool Const>
inline const std::string& Json::Iterator<Const>::key() const {
    if (owner_->type_ == Type::Object) {
        return (owner_->obj_->begin() + idx_)->first;
    }
    // Arrays: synthesise a decimal index string on demand (thread-local cache).
    static thread_local std::string idx_str;
    idx_str = std::to_string(idx_);
    return idx_str;
}

template <bool Const>
inline typename Json::Iterator<Const>::JsonRef Json::Iterator<Const>::value() const {
    if (owner_->type_ == Type::Object) {
        return (owner_->obj_->begin() + idx_)->second;
    }
    if (owner_->type_ == Type::Array) {
        return (*owner_->arr_)[idx_];
    }
    // Scalars iterate as a single element.
    return *owner_;
}

} // namespace librats_stable
