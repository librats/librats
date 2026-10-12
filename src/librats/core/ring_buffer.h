#pragma once

/**
 * @file ring_buffer.h
 * @brief A growable FIFO with random access, that holds no memory while empty.
 *
 * std::deque would do the job but allocates on construction (libstdc++ keeps a
 * map and a block even for an empty one), and an idle connection has several of
 * these: a sent log, its frames, a send stream's chunks. This one is a vector
 * used as a ring, doubling when full, so it costs nothing until used and can be
 * handed back with release() once drained.
 *
 * Not thread-safe, like everything it is used in.
 */

#include <algorithm>
#include <cstddef>
#include <utility>
#include <vector>

namespace librats {

/// A first-in, first-out buffer with random access, growing in powers of two. An
/// empty one holds no memory, which is what an idle connection's logs should cost.
template <typename T>
class RingBuffer {
public:
    RingBuffer() = default;
    RingBuffer(const RingBuffer&) = default;
    RingBuffer& operator=(const RingBuffer&) = default;
    /// A moved-from ring is empty, not a size with no storage behind it.
    RingBuffer(RingBuffer&& other) noexcept
        : buf_(std::move(other.buf_)), head_(other.head_), size_(other.size_) {
        other.head_ = other.size_ = 0;
    }
    RingBuffer& operator=(RingBuffer&& other) noexcept {
        buf_  = std::move(other.buf_);
        head_ = other.head_;
        size_ = other.size_;
        other.buf_.clear();
        other.head_ = other.size_ = 0;
        return *this;
    }

    size_t size()  const noexcept { return size_; }
    bool   empty() const noexcept { return size_ == 0; }

    T&       operator[](size_t i) noexcept       { return buf_[(head_ + i) & (buf_.size() - 1)]; }
    const T& operator[](size_t i) const noexcept { return buf_[(head_ + i) & (buf_.size() - 1)]; }
    T&       front() noexcept { return (*this)[0]; }
    T&       back()  noexcept { return (*this)[size_ - 1]; }
    const T& front() const noexcept { return (*this)[0]; }
    const T& back()  const noexcept { return (*this)[size_ - 1]; }

    void push_back(T v) {
        if (size_ == buf_.size()) grow();
        buf_[(head_ + size_) & (buf_.size() - 1)] = std::move(v);
        ++size_;
    }
    /// The element stays in its slot until overwritten; one that owns memory
    /// should be moved out first.
    void pop_front() noexcept {
        head_ = (head_ + 1) & (buf_.size() - 1);
        if (--size_ == 0) head_ = 0;
    }
    void pop_back() noexcept {
        if (--size_ == 0) head_ = 0;
    }
    void clear() noexcept { head_ = size_ = 0; }
    /// Give the memory back once nothing is in it.
    void release() noexcept {
        if (size_ == 0) { std::vector<T>().swap(buf_); head_ = 0; }
    }

private:
    void grow() {
        std::vector<T> next((std::max)(size_t{16}, buf_.size() * 2));
        for (size_t i = 0; i < size_; ++i) next[i] = std::move((*this)[i]);
        buf_.swap(next);
        head_ = 0;
    }

    std::vector<T> buf_;
    size_t         head_ = 0;
    size_t         size_ = 0;
};

} // namespace librats
