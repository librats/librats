#include "librats/transport/udp_streams.h"

#include <cstring>

namespace librats {
namespace udp {

namespace {

/// Drained send chunks, shared by every stream on this thread. A stream lives and
/// dies on one reactor thread, so this needs no lock; pooling per thread rather
/// than per stream is what lets a thousand quiet connections hold none.
using Chunk = std::unique_ptr<uint8_t[]>;

std::vector<Chunk>& pooled_chunks() {
    static thread_local std::vector<Chunk> pool;
    return pool;
}

Chunk take_chunk() {
    auto& pool = pooled_chunks();
    if (pool.empty()) return Chunk(new uint8_t[SendStream::kChunk]);   // default-initialised: not zeroed
    Chunk chunk = std::move(pool.back());
    pool.pop_back();
    return chunk;
}

void give_chunk(Chunk&& chunk) {
    auto& pool = pooled_chunks();
    if (pool.size() < SendStream::kMaxPooledChunks) pool.push_back(std::move(chunk));
    else                                            chunk.reset();
}

} // namespace

// ── RangeSet ────────────────────────────────────────────────────────────────

void RangeSet::add(uint64_t lo, uint64_t hi) {
    if (lo >= hi) return;
    // First range that could touch [lo, hi): the one before the first starting
    // past lo, if it reaches lo.
    auto it = std::upper_bound(ranges_.begin(), ranges_.end(), std::make_pair(lo, UINT64_MAX));
    if (it != ranges_.begin() && std::prev(it)->second >= lo) --it;
    auto last = it;
    while (last != ranges_.end() && last->first <= hi) {
        lo = (std::min)(lo, last->first);
        hi = (std::max)(hi, last->second);
        ++last;
    }
    if (it == last) {
        ranges_.insert(it, {lo, hi});
        return;
    }
    *it = {lo, hi};
    ranges_.erase(it + 1, last);
}

void RangeSet::remove(uint64_t lo, uint64_t hi) {
    if (lo >= hi || ranges_.empty()) return;
    auto it = std::upper_bound(ranges_.begin(), ranges_.end(), std::make_pair(lo, UINT64_MAX));
    if (it != ranges_.begin() && std::prev(it)->second > lo) --it;
    while (it != ranges_.end() && it->first < hi) {
        const uint64_t a = it->first, b = it->second;
        if (a < lo && b > hi) {   // a hole in the middle splits it
            it->second = lo;
            ranges_.insert(it + 1, {hi, b});
            return;
        }
        if (a < lo) { it->second = lo; ++it; continue; }
        if (b > hi) { it->first = hi; return; }
        it = ranges_.erase(it);
    }
}

bool RangeSet::covers(uint64_t lo, uint64_t hi) const noexcept {
    if (lo >= hi) return true;
    auto it = std::upper_bound(ranges_.begin(), ranges_.end(), std::make_pair(lo, UINT64_MAX));
    if (it == ranges_.begin()) return false;
    --it;
    return it->first <= lo && it->second >= hi;
}

// ── SendStream ──────────────────────────────────────────────────────────────

SendStream::~SendStream() { clear(); }

void SendStream::write(const uint8_t* data, size_t len) {
    while (len > 0) {
        const size_t within = static_cast<size_t>(end_ % kChunk);
        // A drained stream holds no chunk at all, wherever its offset stands, so
        // its first one is the chunk that offset lies in; after that a new one is
        // needed only at a boundary.
        if (chunks_.empty() || within == 0) {
            if (chunks_.empty()) first_chunk_ = end_ / kChunk;
            chunks_.push_back(take_chunk());
        }
        const size_t n = (std::min)(len, kChunk - within);
        std::memcpy(chunk_at(end_), data, n);
        data += n;
        len  -= n;
        end_ += n;
    }
}

uint8_t* SendStream::chunk_at(uint64_t offset) noexcept {
    const size_t idx = static_cast<size_t>(offset / kChunk - first_chunk_);
    return chunks_[idx].get() + offset % kChunk;
}

const uint8_t* SendStream::chunk_at(uint64_t offset) const noexcept {
    const size_t idx = static_cast<size_t>(offset / kChunk - first_chunk_);
    return chunks_[idx].get() + offset % kChunk;
}

bool SendStream::peek(uint64_t new_budget, Piece& out) const noexcept {
    // Repairs first: the peer holds everything behind a hole until it fills, so
    // spending the window on new data first only grows its reorder buffer.
    if (!lost_.empty()) {
        out.offset = lost_.front().first;
        out.len    = static_cast<size_t>(lost_.front().second - out.offset);
        out.repair = true;
        return true;
    }
    if (end_ == sent_end_ || new_budget == 0) return false;
    out.offset = sent_end_;
    out.len    = static_cast<size_t>((std::min<uint64_t>)(end_ - sent_end_, new_budget));
    out.repair = false;
    return true;
}

void SendStream::take(const Piece& piece, size_t len) {
    if (piece.repair) {
        lost_.remove(piece.offset, piece.offset + len);
        lost_bytes_ -= len;
    } else {
        sent_end_ += len;
    }
}

void SendStream::copy(uint64_t offset, size_t len, uint8_t* out) const noexcept {
    while (len > 0) {
        const size_t within = static_cast<size_t>(offset % kChunk);
        const size_t n = (std::min)(len, kChunk - within);
        std::memcpy(out, chunk_at(offset), n);
        out    += n;
        offset += n;
        len    -= n;
    }
}

bool SendStream::unacked_part(uint64_t& offset, size_t& len) const noexcept {
    // Below base_ the chunks may already be gone, so that part is cut off; above
    // it every byte is still held, acknowledged or not.
    const uint64_t lo = (std::max)(offset, base_);
    const uint64_t hi = offset + len;
    if (lo >= hi || acked_.covers(lo, hi)) return false;
    offset = lo;
    len    = static_cast<size_t>(hi - lo);
    return true;
}

void SendStream::on_acked(uint64_t offset, size_t len) {
    const uint64_t lo = (std::max)(offset, base_);
    const uint64_t hi = offset + len;
    if (lo >= hi) return;
    // Delivered, so not owed any more — even if it was given up on and is
    // waiting to go again.
    if (lost_bytes_ > 0) {
        // What of [lo, hi) was owed: its length less the parts lost_ does not have.
        uint64_t gaps = 0;
        lost_.for_each_gap(lo, hi, [&](uint64_t a, uint64_t b) { gaps += b - a; });
        if (const uint64_t owed = (hi - lo) - gaps; owed > 0) {
            lost_.remove(lo, hi);
            lost_bytes_ -= owed;
        }
    }
    acked_.add(lo, hi);
    if (acked_.front().first == base_) {
        base_ = acked_.front().second;
        acked_.pop_front();
        release_acked_chunks();
    }
}

void SendStream::on_lost(uint64_t offset, size_t len) {
    const uint64_t lo = (std::max)(offset, base_);
    const uint64_t hi = (std::min)(offset + len, sent_end_);
    if (lo >= hi) return;
    // Only what has not arrived by another route, and is not already owed.
    acked_.for_each_gap(lo, hi, [&](uint64_t a, uint64_t b) {
        lost_.for_each_gap(a, b, [&](uint64_t x, uint64_t y) { lost_bytes_ += y - x; });
        lost_.add(a, b);
    });
}

void SendStream::release_acked_chunks() {
    // Every chunk wholly below base_ is done with.
    while (!chunks_.empty() && (first_chunk_ + 1) * kChunk <= base_) {
        give_chunk(std::move(chunks_.front()));
        chunks_.pop_front();
        ++first_chunk_;
    }
    if (base_ == end_ && !chunks_.empty()) {
        // Everything written is delivered: the tail chunk goes too, and the next
        // write starts a new one wherever the offset then is.
        while (!chunks_.empty()) {
            give_chunk(std::move(chunks_.front()));
            chunks_.pop_front();
        }
    }
    if (chunks_.empty()) chunks_.release();
}

void SendStream::clear() {
    while (!chunks_.empty()) {
        give_chunk(std::move(chunks_.front()));
        chunks_.pop_front();
    }
    chunks_.release();
    acked_.clear();
    lost_.clear();
    lost_bytes_ = 0;
    base_ = sent_end_ = end_;
}

// ── RecvStream ──────────────────────────────────────────────────────────────

void RecvStream::append(const uint8_t* data, size_t len) {
    const ByteSpan into = inbox_.prepare(len);
    std::memcpy(into.data(), data, len);
    inbox_.commit(len);
}

bool RecvStream::on_data(uint64_t offset, ByteView data, HoldAccount& account) {
    uint64_t       lo  = offset;
    const uint64_t hi  = offset + data.size();
    const uint8_t* src = data.data();
    if (hi <= next_) return true;   // all of it has arrived before
    highest_ = (std::max)(highest_, hi);

    if (lo <= next_) {
        // The next bytes in order, perhaps with a head already delivered.
        append(src + (next_ - lo), static_cast<size_t>(hi - next_));
        next_ = hi;
        drain_held(account);
        return true;
    }

    // Past a hole: hold the parts not already held. A repair can be cut
    // differently from the packet it replaces, so a fragment may overlap several
    // held ones and fill the gaps between them.
    auto it = held_.upper_bound(lo);
    if (it != held_.begin()) {
        auto prev = std::prev(it);
        const uint64_t prev_end = prev->first + prev->second.size();
        if (prev_end > lo) lo = (std::min)(prev_end, hi);
    }
    while (lo < hi) {
        const uint64_t stop = (it != held_.end() && it->first < hi) ? it->first : hi;
        if (stop > lo) {
            const size_t n = static_cast<size_t>(stop - lo);
            if (!account.charge(held_cost(n))) return false;
            const uint8_t* from = src + (lo - offset);
            held_.emplace_hint(it, lo, Bytes(from, from + n));
        }
        if (it == held_.end() || it->first >= hi) break;
        lo = (std::min)(it->first + it->second.size(), hi);
        ++it;
    }
    return true;
}

void RecvStream::drain_held(HoldAccount& account) {
    while (!held_.empty()) {
        auto it = held_.begin();
        if (it->first > next_) break;
        const uint64_t end = it->first + it->second.size();
        if (end > next_) {
            const size_t skip = static_cast<size_t>(next_ - it->first);
            append(it->second.data() + skip, it->second.size() - skip);
            next_ = end;
        }
        account.release(held_cost(it->second.size()));
        held_.erase(it);
    }
}

void RecvStream::clear(HoldAccount& account) {
    for (const auto& entry : held_) account.release(held_cost(entry.second.size()));
    held_.clear();
    inbox_ = ReceiveBuffer();
}

} // namespace udp
} // namespace librats
