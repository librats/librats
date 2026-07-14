#pragma once

// ─────────────────────────────────────────────────────────────────────────────
//  legacy_buffers.h — the pre-optimization ReceiveBuffer / ChainedSendBuffer.
//
//  Verbatim copies of src/core/{receive_buffer,chained_send_buffer}.{h,cpp} as
//  they stood at commit 5d64343^ ("optimized receive_buffer + chained_send_buffer"
//  minus one), moved into `namespace librats_legacy` so the old and the new
//  implementation can be linked into one binary and compared side by side.
//
//  Same trick as stable_json.h. Do not "fix" anything in here — the whole point
//  is that it behaves exactly like the code that shipped.
// ─────────────────────────────────────────────────────────────────────────────

#include <cstddef>
#include <cstdint>
#include <deque>
#include <vector>

namespace librats_legacy {

// ── The old receive buffer ───────────────────────────────────────────────────
//
// std::vector storage, start/end cursors, O(1) consume, manual normalize().
// Grows by 1.5x and *never* shrinks: whatever high-water a peer drove it to is
// held for the life of the connection.

class ReceiveBuffer {
public:
    explicit ReceiveBuffer(std::size_t initial_capacity = 4096);

    uint8_t*    write_ptr()          { return buffer_.data() + recv_end_; }
    std::size_t write_space() const  { return buffer_.size() - recv_end_; }
    void        received(std::size_t bytes);
    void        ensure_space(std::size_t bytes);

    const uint8_t* data()  const { return buffer_.data() + recv_start_; }
    std::size_t    size()  const { return recv_end_ - recv_start_; }
    bool           empty() const { return recv_start_ == recv_end_; }
    void           consume(std::size_t bytes);

    void        normalize();
    void        clear();
    std::size_t capacity()    const { return buffer_.size(); }
    std::size_t front_waste() const { return recv_start_; }

private:
    std::vector<uint8_t> buffer_;
    std::size_t          recv_start_ = 0;
    std::size_t          recv_end_   = 0;
};

// ── The old send buffer ──────────────────────────────────────────────────────
//
// A deque of owned chunks with a read offset. Partial sends advance the offset,
// but there is no gather: the caller may only ever see the *front* chunk, so a
// backlog of N queued messages costs N send() syscalls.

struct SendChunk {
    std::vector<uint8_t> data;
    std::size_t          offset = 0;

    SendChunk() = default;
    explicit SendChunk(std::vector<uint8_t> d) : data(std::move(d)), offset(0) {}

    std::size_t    remaining() const { return data.size() - offset; }
    const uint8_t* current()   const { return data.data() + offset; }
};

class ChainedSendBuffer {
public:
    ChainedSendBuffer() = default;

    void append(std::vector<uint8_t> data);
    void append(const uint8_t* data, std::size_t length);

    const uint8_t* front_data() const;
    std::size_t    front_size() const;
    void           pop_front(std::size_t bytes);

    std::size_t size()        const { return total_bytes_; }
    bool        empty()       const { return total_bytes_ == 0; }
    void        clear();
    std::size_t chunk_count() const { return chunks_.size(); }

    /// Heap actually held by the chain — not part of the original API, added
    /// here only so the two implementations can be compared on memory.
    std::size_t allocated() const;

private:
    std::deque<SendChunk> chunks_;
    std::size_t           total_bytes_ = 0;
};

}  // namespace librats_legacy
