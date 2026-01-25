#pragma once

/**
 * @file receive_buffer.h
 * @brief Efficient receive buffer with O(1) consume operation
 * 
 * Unlike std::vector where erase() is O(n), this buffer uses
 * start/end pointers to mark the valid data region. The consume()
 * operation simply advances the start pointer.
 */

#include <vector>
#include <cstdint>
#include <cstddef>

namespace librats {

/**
 * @brief Efficient receive buffer with O(1) consume operation
 * 
 * Unlike std::vector where erase() is O(n), this buffer uses
 * start/end pointers to mark the valid data region. The consume()
 * operation simply advances the start pointer.
 * 
 * Periodically call normalize() to compact the buffer and reclaim space.
 * 
 * Usage:
 *   1. ensure_space(bytes) - make room for recv()
 *   2. recv(socket, write_ptr(), write_space())
 *   3. received(bytes) - mark bytes as received
 *   4. Process data via data()/size()
 *   5. consume(bytes) - mark bytes as processed
 *   6. normalize() - periodically compact buffer
 */
class ReceiveBuffer {
public:
    /**
     * @brief Create receive buffer with initial capacity
     */
    explicit ReceiveBuffer(size_t initial_capacity = 4096);
    
    //=========================================================================
    // Write interface (for recv())
    //=========================================================================
    
    /**
     * @brief Get pointer where new data should be written
     */
    uint8_t* write_ptr() { return buffer_.data() + recv_end_; }
    
    /**
     * @brief Get available space for writing
     */
    size_t write_space() const { return buffer_.size() - recv_end_; }
    
    /**
     * @brief Mark bytes as received (after successful recv())
     */
    void received(size_t bytes);
    
    /**
     * @brief Ensure at least 'bytes' space is available for writing
     * 
     * May reallocate or normalize the buffer.
     */
    void ensure_space(size_t bytes);
    
    //=========================================================================
    // Read interface (for parsing)
    //=========================================================================
    
    /**
     * @brief Get pointer to unprocessed data
     */
    const uint8_t* data() const { return buffer_.data() + recv_start_; }
    
    /**
     * @brief Get size of unprocessed data
     */
    size_t size() const { return recv_end_ - recv_start_; }
    
    /**
     * @brief Check if buffer has no unprocessed data
     */
    bool empty() const { return recv_start_ == recv_end_; }
    
    /**
     * @brief Mark bytes as consumed/processed - O(1) operation!
     * 
     * This is the key advantage over vector::erase().
     */
    void consume(size_t bytes);
    
    //=========================================================================
    // Buffer management
    //=========================================================================
    
    /**
     * @brief Compact buffer by moving data to the beginning
     * 
     * Call this periodically to reclaim space at the front.
     * This is O(n) but should be called infrequently.
     */
    void normalize();
    
    /**
     * @brief Clear all data
     */
    void clear();
    
    /**
     * @brief Get total buffer capacity
     */
    size_t capacity() const { return buffer_.size(); }
    
    /**
     * @brief Get wasted space at the front (for diagnostics)
     */
    size_t front_waste() const { return recv_start_; }

private:
    std::vector<uint8_t> buffer_;
    size_t recv_start_ = 0;  ///< Start of unprocessed data
    size_t recv_end_ = 0;    ///< End of received data (write position)
};

} // namespace librats
