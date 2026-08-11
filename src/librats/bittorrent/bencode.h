#pragma once

/**
 * @file bencode.h
 * @brief Bencode value tree, decoder and encoder (BEP 3).
 *
 * Bencode is the serialization format used by every part of BitTorrent and by
 * the DHT's KRPC protocol. This module is shared between both, so it is built
 * unconditionally (not behind RATS_SEARCH_FEATURES).
 *
 * Design:
 *  - `BencodeValue` is an owning value tree: an integer, a (binary-safe) string,
 *    a list, or a dictionary. The ergonomic accessors make reading parsed data
 *    read like the structure itself: `root["info"]["piece length"].as_integer()`.
 *  - A dictionary is stored as a *sorted, duplicate-free* vector of key/value
 *    pairs. That keeps lookups O(log n) without a per-dict hash allocation, and
 *    makes encoding canonical by construction (bencode requires sorted keys).
 *  - Decoding is hardened against hostile input: bounded recursion depth,
 *    overflow-safe length/integer parsing, strict canonical integers, and a
 *    full-buffer-consumption check. Malformed input never crashes — the
 *    non-throwing `try_decode` returns `std::nullopt`, the throwing `decode`
 *    throws `std::runtime_error`.
 */

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

// Some older standard libraries can't place a container of an incomplete type
// directly inside std::variant (the recursion `BencodeValue` -> container of
// `BencodeValue`). On those toolchains we box the containers in a shared_ptr.
// This is fully isolated behind the list_ref()/dict_ref() helpers below, so the
// rest of the code never sees it. (Deep-copy is implemented explicitly either
// way, so value semantics are identical on both paths.)
#ifndef LIBRATS_BENCODE_BOXED_CONTAINERS
#  if defined(__GNUC__) && (__GNUC__ <= 11)
#    define LIBRATS_BENCODE_BOXED_CONTAINERS 1
#  else
#    define LIBRATS_BENCODE_BOXED_CONTAINERS 0
#  endif
#endif

#if LIBRATS_BENCODE_BOXED_CONTAINERS
#include <memory>
#endif

namespace librats {

class BencodeValue;

/// A bencode list is a plain vector of values.
using BencodeList = std::vector<BencodeValue>;

/// A bencode dictionary, stored sorted by key with no duplicates. Keys are
/// byte strings (binary-safe). The sorted invariant is maintained by both the
/// decoder and the mutable `operator[]`, so iteration and encoding are canonical.
using BencodeDict = std::vector<std::pair<std::string, BencodeValue>>;

/**
 * @brief One bencode value: integer, string, list or dictionary.
 *
 * Copying is a deep copy (true value semantics). Construct leaves directly
 * (`BencodeValue(42)`, `BencodeValue("x")`) or containers via `create_list()` /
 * `create_dict()` and the mutable accessors.
 */
class BencodeValue {
public:
    enum class Type { Integer, String, List, Dictionary };

    BencodeValue();                       ///< empty string (binary-safe, zero length)
    BencodeValue(std::int64_t value);
    BencodeValue(std::string value);
    BencodeValue(const char* value);
    BencodeValue(BencodeList value);
    BencodeValue(BencodeDict value);

    BencodeValue(const BencodeValue& other);
    BencodeValue(BencodeValue&& other) noexcept;
    BencodeValue& operator=(const BencodeValue& other);
    BencodeValue& operator=(BencodeValue&& other) noexcept;
    ~BencodeValue();

    // ---- type ----
    Type type()     const noexcept { return type_; }
    Type get_type() const noexcept { return type_; }  ///< alias
    bool is_integer() const noexcept { return type_ == Type::Integer; }
    bool is_string()  const noexcept { return type_ == Type::String; }
    bool is_list()    const noexcept { return type_ == Type::List; }
    bool is_dict()    const noexcept { return type_ == Type::Dictionary; }

    // ---- typed access (throw std::runtime_error on a type mismatch) ----
    std::int64_t        as_integer() const;
    const std::string&  as_string()  const;
    const BencodeList&  as_list()    const;
    const BencodeDict&  as_dict()    const;
    BencodeList&        as_list();   ///< mutable list (lists carry no invariant)

    // ---- safe, non-throwing helpers ----
    /// Dictionary lookup. Returns nullptr if this is not a dict or the key is
    /// absent. Never throws — the preferred way to read untrusted input.
    const BencodeValue* find(std::string_view key) const noexcept;
    bool has_key(std::string_view key) const noexcept { return find(key) != nullptr; }

    // ---- dictionary building / reading ----
    /// Const dictionary read; throws std::runtime_error if the key is missing.
    const BencodeValue& operator[](std::string_view key) const;
    /// Mutable dictionary access; inserts a default-constructed value (keeping
    /// the sorted invariant) if the key is absent. Throws if this is not a dict.
    BencodeValue& operator[](std::string_view key);

    // ---- list building / reading ----
    const BencodeValue& operator[](std::size_t index) const;  ///< throws if out of range
    BencodeValue&       operator[](std::size_t index);        ///< throws if out of range
    void push_back(BencodeValue value);                        ///< append to a list
    std::size_t size() const;  ///< element/byte count for string/list/dict; throws otherwise

    // ---- encoding ----
    std::vector<std::uint8_t> encode() const;
    std::string               encode_string() const;
    void                      encode_to(std::vector<std::uint8_t>& out) const;

    // ---- factories (kept for readability at call sites) ----
    static BencodeValue create_integer(std::int64_t v) { return BencodeValue(v); }
    static BencodeValue create_string(std::string v)   { return BencodeValue(std::move(v)); }
    static BencodeValue create_list()                  { return BencodeValue(BencodeList{}); }
    static BencodeValue create_dict()                  { return BencodeValue(BencodeDict{}); }

private:
    Type type_;
#if LIBRATS_BENCODE_BOXED_CONTAINERS
    std::variant<std::int64_t, std::string,
                 std::shared_ptr<BencodeList>, std::shared_ptr<BencodeDict>> value_;
#else
    std::variant<std::int64_t, std::string, BencodeList, BencodeDict> value_;
#endif

    // The only place that knows about container boxing.
    void set_list(BencodeList l);
    void set_dict(BencodeDict d);
    BencodeList&       list_ref();
    const BencodeList& list_ref() const;
    BencodeDict&       dict_ref();
    const BencodeDict& dict_ref() const;
};

/**
 * @brief Bencode decoder entry points (throwing — kept for existing callers).
 *
 * Each decodes exactly one value and requires it to span the whole buffer.
 * Throws std::runtime_error on any malformed input.
 */
class BencodeDecoder {
public:
    static BencodeValue decode(const std::vector<std::uint8_t>& data);
    static BencodeValue decode(const std::string& data);
    static BencodeValue decode(const std::uint8_t* data, std::size_t size);
};

namespace bencode {
    /// Throwing decode (one value, whole buffer). Throws std::runtime_error.
    BencodeValue decode(const std::vector<std::uint8_t>& data);
    BencodeValue decode(const std::string& data);

    /// Non-throwing decode (one value, whole buffer). nullopt on malformed input.
    std::optional<BencodeValue> try_decode(const std::uint8_t* data, std::size_t size) noexcept;
    std::optional<BencodeValue> try_decode(std::string_view data) noexcept;

    std::vector<std::uint8_t> encode(const BencodeValue& value);
    std::string               encode_string(const BencodeValue& value);
}

} // namespace librats
