#include "receive_buffer.h"
#include <cstring>

namespace librats {

ReceiveBuffer::ReceiveBuffer(size_t initial_capacity)
    : buffer_(initial_capacity)
    , recv_start_(0)
    , recv_end_(0) {
}

void ReceiveBuffer::received(size_t bytes) {
    recv_end_ += bytes;
    if (recv_end_ > buffer_.size()) {
        recv_end_ = buffer_.size();  // Safety clamp
    }
}

void ReceiveBuffer::ensure_space(size_t bytes) {
    size_t available = buffer_.size() - recv_end_;
    
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
    size_t needed = recv_end_ + bytes;
    size_t new_size = buffer_.size();
    
    // Grow by 1.5x or to needed size, whichever is larger
    while (new_size < needed) {
        new_size = new_size * 3 / 2;
        if (new_size < 256) new_size = 256;  // Minimum growth
    }
    
    buffer_.resize(new_size);
}

void ReceiveBuffer::consume(size_t bytes) {
    recv_start_ += bytes;
    if (recv_start_ > recv_end_) {
        recv_start_ = recv_end_;  // Safety clamp
    }
    
    // If buffer is now empty, reset pointers
    if (recv_start_ == recv_end_) {
        recv_start_ = 0;
        recv_end_ = 0;
    }
}

void ReceiveBuffer::normalize() {
    if (recv_start_ == 0) {
        return;  // Nothing to do
    }
    
    size_t data_size = recv_end_ - recv_start_;
    
    if (data_size > 0) {
        // Move data to the beginning
        std::memmove(buffer_.data(), buffer_.data() + recv_start_, data_size);
    }
    
    recv_end_ = data_size;
    recv_start_ = 0;
}

void ReceiveBuffer::clear() {
    recv_start_ = 0;
    recv_end_ = 0;
}

} // namespace librats
