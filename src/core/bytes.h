#pragma once

/**
 * @file bytes.h
 * @brief Lightweight byte container aliases and a non-owning byte view.
 *
 * `ByteView` is a C++17 stand-in for std::span<const uint8_t>: a cheap
 * (pointer, length) pair used to pass payloads around without copying. It does
 * NOT own its storage — the referenced bytes must outlive the view. On the
 * receive path views point straight into the connection's ReceiveBuffer and are
 * only valid until the buffer is consumed.
 *
 * `ByteSpan` is the mutable counterpart (std::span<uint8_t>), handed out by
 * ReceiveBuffer::prepare() as the destination of a recv().
 */

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>

namespace librats {

using Bytes = std::vector<uint8_t>;

/// Non-owning view over a contiguous run of bytes.
class ByteView {
public:
    constexpr ByteView() = default;
    constexpr ByteView(const uint8_t* data, size_t size) : data_(data), size_(size) {}
    ByteView(const Bytes& b) : data_(b.data()), size_(b.size()) {}
    ByteView(const std::string& s)
        : data_(reinterpret_cast<const uint8_t*>(s.data())), size_(s.size()) {}

    const uint8_t* data()  const noexcept { return data_; }
    size_t         size()  const noexcept { return size_; }
    bool           empty() const noexcept { return size_ == 0; }

    const uint8_t* begin() const noexcept { return data_; }
    const uint8_t* end()   const noexcept { return data_ + size_; }

    Bytes to_bytes() const { return Bytes(data_, data_ + size_); }

private:
    const uint8_t* data_ = nullptr;
    size_t         size_ = 0;
};

/// Non-owning view over a contiguous run of *writable* bytes.
class ByteSpan {
public:
    constexpr ByteSpan() = default;
    constexpr ByteSpan(uint8_t* data, size_t size) : data_(data), size_(size) {}

    uint8_t* data()  const noexcept { return data_; }
    size_t   size()  const noexcept { return size_; }
    bool     empty() const noexcept { return size_ == 0; }

    uint8_t* begin() const noexcept { return data_; }
    uint8_t* end()   const noexcept { return data_ + size_; }

    operator ByteView() const noexcept { return ByteView(data_, size_); }

private:
    uint8_t* data_ = nullptr;
    size_t   size_ = 0;
};

} // namespace librats
