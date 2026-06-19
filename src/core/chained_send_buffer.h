#pragma once

/**
 * @file chained_send_buffer.h
 * @brief Zero-copy chained send buffer for efficient network sending
 * 
 * Stores a chain of buffers to be sent. Supports:
 * - Appending without copying (move semantics)
 * - Efficient partial sends via pop_front()
 * - Direct access to front chunk for send()
 * 
 * Zero-copy chained buffer for efficient sending.
 */

#include <vector>
#include <deque>
#include <cstdint>
#include <cstddef>

namespace librats {

/**
 * @brief A chunk of data in the send chain
 */
struct SendChunk {
    std::vector<uint8_t> data;  ///< Owned data
    size_t offset = 0;          ///< Current read offset (for partial sends)
    
    SendChunk() = default;
    explicit SendChunk(std::vector<uint8_t> d) : data(std::move(d)), offset(0) {}
    
    /// Bytes remaining to send
    size_t remaining() const { return data.size() - offset; }
    
    /// Pointer to current data position
    const uint8_t* current() const { return data.data() + offset; }
};

/**
 * @brief Zero-copy chained send buffer
 * 
 * Stores a chain of buffers to be sent. Supports:
 * - Appending without copying (move semantics)
 * - Efficient partial sends via pop_front()
 * - Direct access to front chunk for send()
 * 
 * Zero-copy chained buffer for efficient sending.
 * 
 * Usage:
 *   1. append(data) - queue data for sending
 *   2. send(socket, front_data(), front_size())
 *   3. pop_front(bytes_sent) - remove sent data
 */
class ChainedSendBuffer {
public:
    ChainedSendBuffer() = default;
    
    //=========================================================================
    // Append interface
    //=========================================================================
    
    /**
     * @brief Append data by moving (zero-copy)
     */
    void append(std::vector<uint8_t> data);
    
    /**
     * @brief Append data by copying
     */
    void append(const uint8_t* data, size_t length);
    
    //=========================================================================
    // Send interface
    //=========================================================================
    
    /**
     * @brief Get pointer to front chunk data (for send())
     * 
     * Returns nullptr if buffer is empty.
     */
    const uint8_t* front_data() const;
    
    /**
     * @brief Get size of front chunk (for send())
     * 
     * Returns 0 if buffer is empty.
     */
    size_t front_size() const;
    
    /**
     * @brief Remove bytes from front after successful send
     */
    void pop_front(size_t bytes);
    
    //=========================================================================
    // Buffer state
    //=========================================================================
    
    /**
     * @brief Get total bytes pending across all chunks
     */
    size_t size() const { return total_bytes_; }
    
    /**
     * @brief Check if buffer is empty
     */
    bool empty() const { return total_bytes_ == 0; }
    
    /**
     * @brief Clear all pending data
     */
    void clear();
    
    /**
     * @brief Get number of chunks
     */
    size_t chunk_count() const { return chunks_.size(); }
    
    //=========================================================================
    // Advanced: Gather I/O support
    //=========================================================================
    
    /**
     * @brief Copy data to a contiguous buffer (for legacy APIs)
     * 
     * @param buffer Output buffer
     * @param max_bytes Maximum bytes to copy
     * @return Actual bytes copied
     */
    size_t copy_to(uint8_t* buffer, size_t max_bytes) const;

private:
    std::deque<SendChunk> chunks_;
    size_t total_bytes_ = 0;
};

} // namespace librats
