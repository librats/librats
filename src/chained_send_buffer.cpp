#include "chained_send_buffer.h"
#include <cstring>
#include <algorithm>

namespace librats {

void ChainedSendBuffer::append(std::vector<uint8_t> data) {
    if (data.empty()) return;
    
    total_bytes_ += data.size();
    chunks_.emplace_back(std::move(data));
}

void ChainedSendBuffer::append(const uint8_t* data, size_t length) {
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

size_t ChainedSendBuffer::front_size() const {
    if (chunks_.empty()) {
        return 0;
    }
    return chunks_.front().remaining();
}

void ChainedSendBuffer::pop_front(size_t bytes) {
    while (bytes > 0 && !chunks_.empty()) {
        SendChunk& front = chunks_.front();
        size_t remaining = front.remaining();
        
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

size_t ChainedSendBuffer::copy_to(uint8_t* buffer, size_t max_bytes) const {
    size_t copied = 0;
    
    for (const auto& chunk : chunks_) {
        if (copied >= max_bytes) break;
        
        size_t remaining = chunk.remaining();
        size_t to_copy = (std::min)(remaining, max_bytes - copied);
        
        std::memcpy(buffer + copied, chunk.current(), to_copy);
        copied += to_copy;
    }
    
    return copied;
}

} // namespace librats
