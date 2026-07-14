#include "baseline/legacy_buffers.h"

#include <algorithm>
#include <cstring>

namespace librats_legacy {

// ── ReceiveBuffer (verbatim from 5d64343^) ───────────────────────────────────

ReceiveBuffer::ReceiveBuffer(std::size_t initial_capacity)
    : buffer_(initial_capacity), recv_start_(0), recv_end_(0) {}

void ReceiveBuffer::received(std::size_t bytes) {
    recv_end_ += bytes;
    if (recv_end_ > buffer_.size()) {
        recv_end_ = buffer_.size();  // Safety clamp
    }
}

void ReceiveBuffer::ensure_space(std::size_t bytes) {
    std::size_t available = buffer_.size() - recv_end_;

    if (available >= bytes) {
        return;  // Already have enough space
    }

    // Try normalizing first to reclaim front space
    if (recv_start_ > 0) {
        normalize();
        available = buffer_.size() - recv_end_;
        if (available >= bytes) {
            return;
        }
    }

    // Need to grow the buffer
    std::size_t needed   = recv_end_ + bytes;
    std::size_t new_size = buffer_.size();

    // Grow by 1.5x or to needed size, whichever is larger
    while (new_size < needed) {
        new_size = new_size * 3 / 2;
        if (new_size < 256) new_size = 256;  // Minimum growth
    }

    buffer_.resize(new_size);
}

void ReceiveBuffer::consume(std::size_t bytes) {
    recv_start_ += bytes;
    if (recv_start_ > recv_end_) {
        recv_start_ = recv_end_;  // Safety clamp
    }

    // If buffer is now empty, reset pointers
    if (recv_start_ == recv_end_) {
        recv_start_ = 0;
        recv_end_   = 0;
    }
}

void ReceiveBuffer::normalize() {
    if (recv_start_ == 0) {
        return;  // Nothing to do
    }

    std::size_t data_size = recv_end_ - recv_start_;

    if (data_size > 0) {
        // Move data to the beginning
        std::memmove(buffer_.data(), buffer_.data() + recv_start_, data_size);
    }

    recv_end_   = data_size;
    recv_start_ = 0;
}

void ReceiveBuffer::clear() {
    recv_start_ = 0;
    recv_end_   = 0;
}

// ── ChainedSendBuffer (verbatim from 5d64343^) ───────────────────────────────

void ChainedSendBuffer::append(std::vector<uint8_t> data) {
    if (data.empty()) return;

    total_bytes_ += data.size();
    chunks_.emplace_back(std::move(data));
}

void ChainedSendBuffer::append(const uint8_t* data, std::size_t length) {
    if (length == 0) return;

    std::vector<uint8_t> chunk(data, data + length);
    append(std::move(chunk));
}

const uint8_t* ChainedSendBuffer::front_data() const {
    if (chunks_.empty()) {
        return nullptr;
    }
    return chunks_.front().current();
}

std::size_t ChainedSendBuffer::front_size() const {
    if (chunks_.empty()) {
        return 0;
    }
    return chunks_.front().remaining();
}

void ChainedSendBuffer::pop_front(std::size_t bytes) {
    while (bytes > 0 && !chunks_.empty()) {
        SendChunk&  front     = chunks_.front();
        std::size_t remaining = front.remaining();

        if (bytes >= remaining) {
            // Consume entire chunk
            bytes -= remaining;
            total_bytes_ -= remaining;
            chunks_.pop_front();
        } else {
            // Partial consume
            front.offset += bytes;
            total_bytes_ -= bytes;
            bytes = 0;
        }
    }
}

void ChainedSendBuffer::clear() {
    chunks_.clear();
    total_bytes_ = 0;
}

std::size_t ChainedSendBuffer::allocated() const {
    std::size_t n = 0;
    for (const SendChunk& c : chunks_) n += c.data.capacity();
    return n;
}

}  // namespace librats_legacy
