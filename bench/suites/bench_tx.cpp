// ─────────────────────────────────────────────────────────────────────────────
//  bench_tx — the send path, before and after 5d64343.
//
//  As with bench_rx, the buffer alone is not the subject: what matters is the
//  send loop around it. Both are reproduced verbatim from their commits:
//
//    mesh/old  Connection::{queue_block,flush} @5d64343^ — encode_block() copies
//              the whole (already allocated, already encrypted) frame into a new
//              vector just to prepend 4 bytes; flush() may only see the *front*
//              chunk, so a backlog of N frames costs N send() calls.
//    mesh/new  Connection::{queue_block,flush} @5d64343  — the length prefix is
//              its own gather slice, big bodies are moved in, and the whole
//              backlog leaves in one sendmsg().
//    bt/old    PeerConnection::{queue,flush} @5d64343^   — every queue() memcpy's
//              into one contiguous vector AND flushes; a congested socket erases
//              the sent prefix on every writable event (an O(n) memmove each).
//    bt/new    PeerConnection::{queue,flush} @5d64343.
//
//  Plus a third variant the library does NOT have yet:
//
//    */cork    queue every message of a batch, then flush ONCE — libtorrent's
//              `cork` (peer_connection.hpp:1220). The gather machinery is already
//              in the tree; nothing triggers it, because every send_*() flushes.
//              This column is what that leaves on the table.
// ─────────────────────────────────────────────────────────────────────────────

#include "framework/bench.h"
#include "framework/alloc_track.h"
#include "baseline/legacy_buffers.h"
#include "support/net_mock.h"

#include "core/chained_send_buffer.h"
#include "wire/frame.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using librats::ByteView;
using librats::Bytes;
namespace framer = librats::framer;

/// Mirrors librats::kMaxSendSlices (core/socket.h). Declared here rather than
/// included, so the bench does not have to drag winsock2 in next to bench.h.
constexpr std::size_t kMaxSendSlices = 256;

/// Mirrors Connection::kInlineBlockLimit (transport/connection.cpp).
constexpr std::size_t kInlineBlockLimit = librats::ChainedSendBuffer::kScratchCapacity;

static inline void write_u32_be(uint8_t* p, std::uint32_t v) {
    p[0] = uint8_t(v >> 24);
    p[1] = uint8_t(v >> 16);
    p[2] = uint8_t(v >> 8);
    p[3] = uint8_t(v);
}

// ── mesh: the OLD send path (Connection @5d64343^) ───────────────────────────

struct MeshTxOld {
    librats_legacy::ChainedSendBuffer tx_;
    mock::TxKernel*                   k = nullptr;

    void queue_block(ByteView body) {
        Bytes block;
        framer::encode_block(block, body);  // alloc + copy the WHOLE body
        tx_.append(std::move(block));
    }
    void send(Bytes cipher) {
        queue_block(ByteView(cipher));
        flush();
    }
    void flush() {
        while (!tx_.empty()) {
            const std::ptrdiff_t n = k->send(tx_.front_data(), tx_.front_size());
            if (n > 0) {
                tx_.pop_front(std::size_t(n));
                continue;
            }
            break;  // EWOULDBLOCK — one chunk at a time, whatever happens
        }
    }
    std::size_t pending()   const { return tx_.size(); }
    std::size_t allocated() const { return tx_.allocated(); }
};

// ── mesh: the NEW send path (Connection @5d64343) ────────────────────────────

struct MeshTxNew {
    librats::ChainedSendBuffer tx_;
    mock::TxKernel*            k    = nullptr;
    bool                       cork = false;  ///< defer the flush to the end of the batch

    void queue_block(Bytes body) {
        uint8_t prefix[framer::kLengthPrefixSize];
        framer::encode_block_header(prefix, body.size());
        tx_.append(ByteView(prefix, sizeof prefix));
        if (body.size() <= kInlineBlockLimit) tx_.append(ByteView(body));
        else                                  tx_.append(std::move(body));
    }
    void send(Bytes cipher) {
        queue_block(std::move(cipher));
        if (!cork) flush();
    }
    void flush() {
        while (!tx_.empty()) {
            ByteView          slices[kMaxSendSlices];
            const std::size_t count = tx_.gather(slices, kMaxSendSlices);
            const std::ptrdiff_t n  = k->sendv(slices, count);
            if (n > 0) {
                tx_.pop_front(std::size_t(n));
                continue;
            }
            break;
        }
    }
    std::size_t pending()   const { return tx_.size(); }
    std::size_t allocated() const { return tx_.allocated(); }
};

// ── BitTorrent: the OLD send path (PeerConnection @5d64343^) ─────────────────

struct BtTxOld {
    std::vector<uint8_t> out_;
    std::size_t          out_sent_ = 0;
    mock::TxKernel*      k         = nullptr;

    void queue(const uint8_t* d, std::size_t len) {
        if (len == 0) return;
        out_.insert(out_.end(), d, d + len);  // memcpy every message into one vector
        flush();                              // …and a syscall after every one
    }
    void flush() {
        while (out_sent_ < out_.size()) {
            const std::ptrdiff_t n =
                k->send(out_.data() + out_sent_, out_.size() - out_sent_);
            if (n > 0) {
                out_sent_ += std::size_t(n);
                continue;
            }
            // EWOULDBLOCK: reclaim the sent prefix — an O(backlog) memmove, every
            // single writable event.
            if (out_sent_ > 0) {
                out_.erase(out_.begin(), out_.begin() + std::ptrdiff_t(out_sent_));
                out_sent_ = 0;
            }
            return;
        }
        out_.clear();
        out_sent_ = 0;
    }

    void send_message(uint8_t id, const uint8_t* p, std::uint32_t len) {
        uint8_t header[5];
        write_u32_be(header, len + 1);
        header[4] = id;
        queue(header, 5);
        if (len) queue(p, len);
    }
    void send_request(std::uint32_t piece, std::uint32_t off, std::uint32_t len) {
        uint8_t p[12];
        write_u32_be(p, piece);
        write_u32_be(p + 4, off);
        write_u32_be(p + 8, len);
        send_message(6, p, 12);
    }
    void send_piece(std::uint32_t piece, std::uint32_t off, ByteView data) {
        uint8_t head[8];
        write_u32_be(head, piece);
        write_u32_be(head + 4, off);
        uint8_t header[5];
        write_u32_be(header, std::uint32_t(9 + data.size()));
        header[4] = 7;
        queue(header, 5);
        queue(head, 8);
        if (!data.empty()) queue(data.data(), data.size());  // the whole block, copied
    }

    std::size_t pending()   const { return out_.size() - out_sent_; }
    std::size_t allocated() const { return out_.capacity(); }
};

// ── BitTorrent: the NEW send path (PeerConnection @5d64343) ──────────────────

struct BtTxNew {
    librats::ChainedSendBuffer tx_;
    mock::TxKernel*            k    = nullptr;
    bool                       cork = false;

    void queue(ByteView b) { tx_.append(b); }
    void queue(Bytes b) { tx_.append(std::move(b)); }

    void flush() {
        while (!tx_.empty()) {
            ByteView          slices[kMaxSendSlices];
            const std::size_t count = tx_.gather(slices, kMaxSendSlices);
            const std::ptrdiff_t n  = k->sendv(slices, count);
            if (n > 0) {
                tx_.pop_front(std::size_t(n));
                continue;
            }
            break;
        }
    }
    void maybe_flush() {
        if (!cork) flush();
    }

    void send_message(uint8_t id, const uint8_t* p, std::uint32_t len) {
        uint8_t header[5];
        write_u32_be(header, len + 1);
        header[4] = id;
        queue(ByteView(header, 5));
        if (len) queue(ByteView(p, len));
        maybe_flush();
    }
    void send_request(std::uint32_t piece, std::uint32_t off, std::uint32_t len) {
        uint8_t p[12];
        write_u32_be(p, piece);
        write_u32_be(p + 4, off);
        write_u32_be(p + 8, len);
        send_message(6, p, 12);
    }
    void send_piece(std::uint32_t piece, std::uint32_t off, Bytes data) {
        uint8_t header[13];
        write_u32_be(header, std::uint32_t(9 + data.size()));
        header[4] = 7;
        write_u32_be(header + 5, piece);
        write_u32_be(header + 9, off);
        queue(ByteView(header, sizeof header));
        if (!data.empty()) queue(std::move(data));  // moved — never copied
        maybe_flush();
    }

    std::size_t pending()   const { return tx_.size(); }
    std::size_t allocated() const { return tx_.allocated(); }
};

// ── Workloads ────────────────────────────────────────────────────────────────
//
// Each returns after every byte has been handed to the kernel: the reactor keeps
// getting writable events (k.refill()) until the backlog is gone.

/// What a workload reports back about the memory the send queue held.
struct Held {
    std::size_t peak   = 0;  ///< high-water of the queue's own allocated()
    std::size_t hidden = 0;  ///< high-water of (real live heap − allocated()) while draining
};

/// Compare the queue's allocated() against the heap it is really sitting on.
///
/// That gap is the whole point of this instrument. allocated() is what the send
/// high-water mark reads, so a queue that frees a drained chunk's buffer *later* than it
/// subtracts that chunk from its counter is one that can hold well past the mark while
/// reporting that it is under it — and no assertion on the public API can catch that,
/// because the counter lies consistently. Only the heap can tell.
///
/// Sampled while the socket is draining the queue, not over the whole run, so a growth
/// transient (a vector doubling to hold what it already holds) does not read as
/// retention.
template <typename D>
void sample_hidden(const D& d, Held& held) {
    const auto live      = std::size_t((std::max)(track::g_stats.live, std::int64_t{0}));
    const auto allocated = d.allocated();
    if (live > allocated) held.hidden = (std::max)(held.hidden, live - allocated);
}

/// Hand the backlog to the kernel, one writable event at a time.
template <typename D>
void drain(D& d, mock::TxKernel& k, Held& held) {
    while (d.pending() > 0) {
        k.refill();  // the next PollOut
        d.flush();
        sample_hidden(d, held);
    }
}

/// N mesh frames of `size` bytes each (the payload arrives already encrypted, so
/// each one is a fresh heap buffer — both implementations pay for that).
template <typename D>
Held mesh_frames(D& d, mock::TxKernel& k, const Bytes& payload, int n) {
    Held h;
    for (int i = 0; i < n; ++i) {
        d.send(Bytes(payload));
        h.peak = (std::max)(h.peak, d.allocated());
    }
    drain(d, k, h);
    return h;
}

/// The same frames, but corked into batches of `batch` — one flush per batch, as
/// a handler generating several messages in response to one event would.
template <typename D>
Held mesh_batched(D& d, mock::TxKernel& k, const Bytes& payload, int n, int batch) {
    Held h;
    for (int i = 0; i < n; ++i) {
        d.send(Bytes(payload));
        if ((i + 1) % batch == 0) d.flush();  // the cork pops
        h.peak = (std::max)(h.peak, d.allocated());
    }
    d.flush();
    drain(d, k, h);
    return h;
}

/// A seeder answering `n` piece requests: each block is a fresh buffer, as it
/// would be coming back from the disk thread.
template <typename D, bool Move>
Held bt_seed(D& d, mock::TxKernel& k, const Bytes& block, int n) {
    Held h;
    for (int i = 0; i < n; ++i) {
        Bytes disk(block);  // the disk read
        if constexpr (Move) d.send_piece(std::uint32_t(i), 0, std::move(disk));
        else                d.send_piece(std::uint32_t(i), 0, ByteView(disk));
        h.peak = (std::max)(h.peak, d.allocated());
    }
    drain(d, k, h);
    return h;
}

/// A live peer rather than a pure seeder: every block goes out sandwiched between the
/// control chatter that rides alongside it — a HAVE for the piece we just completed and
/// a REQUEST for the next one, as a peer that is simultaneously downloading emits.
///
/// The point is the *interleaving*. Every other workload here is homogeneous, and a
/// homogeneous stream of small messages is the one case coalescable_tail() is perfect
/// at: they all pack into the spare capacity of one scratch chunk. Alternate them with
/// a 16 KiB block and the tail is a payload buffer with no room in it, so each small
/// message has to open a chunk of its own — which is exactly the allocation the
/// recycled chunk exists to absorb, and exactly the pressure the chain's slot
/// bookkeeping has to survive.
template <typename D, bool Move>
Held bt_mixed(D& d, mock::TxKernel& k, const Bytes& block, int n) {
    Held h;
    for (int i = 0; i < n; ++i) {
        Bytes disk(block);  // the disk read
        if constexpr (Move) d.send_piece(std::uint32_t(i), 0, std::move(disk));
        else                d.send_piece(std::uint32_t(i), 0, ByteView(disk));

        uint8_t have[4];
        write_u32_be(have, std::uint32_t(i));
        d.send_message(4, have, 4);                          // HAVE — we finished a piece
        d.send_request(std::uint32_t(i), 0, 16 * 1024);      // …and we want the next one

        h.peak = (std::max)(h.peak, d.allocated());
    }
    drain(d, k, h);
    return h;
}

/// A seeder in its steady state: the disk keeps the queue topped up to `depth` bytes
/// while the socket drains it, so the backlog never empties and never runs away.
///
/// This is the only workload where append() and pop_front() genuinely interleave. Every
/// other one fills the queue to its peak and only *then* drains it, so the head only
/// ever chases a shrinking chain. Here new chunks land behind the head while drained
/// ones pile up in front of it — the case a queue that retires its dead slots lazily
/// (as the chain does, in bulk) has to be measured on, because it is the one where the
/// slots could creep.
template <typename D, bool Move>
Held bt_steady(D& d, mock::TxKernel& k, const Bytes& block, int n, std::size_t depth) {
    Held h;
    int queued = 0;
    while (queued < n) {
        while (queued < n && d.pending() < depth) {  // the disk tops the queue back up
            Bytes disk(block);
            if constexpr (Move) d.send_piece(std::uint32_t(queued), 0, std::move(disk));
            else                d.send_piece(std::uint32_t(queued), 0, ByteView(disk));
            ++queued;
        }
        h.peak = (std::max)(h.peak, d.allocated());

        k.refill();  // the next PollOut takes a window's worth away again
        d.flush();
        sample_hidden(d, h);
    }
    drain(d, k, h);
    return h;
}

/// The request pipeline: `rounds` batches of kPipelineDepth=16 requests each,
/// exactly what Torrent::request_more_blocks (torrent.cpp:299) emits.
template <typename D>
Held bt_requests(D& d, mock::TxKernel& k, int rounds, bool cork_batch = false) {
    Held h;
    for (int r = 0; r < rounds; ++r) {
        for (int i = 0; i < 16; ++i)
            d.send_request(std::uint32_t(r), std::uint32_t(i * 16384), 16384);
        if (cork_batch) d.flush();  // the cork pops at the end of the batch
        h.peak = (std::max)(h.peak, d.allocated());
    }
    drain(d, k, h);
    return h;
}

// ── Reporting ────────────────────────────────────────────────────────────────

/// A real send() costs far more than the memcpy the mock charges for it: ~1 µs on
/// a modern Linux box with the speculation mitigations on, more on Windows. The
/// mock deliberately makes it nearly free, which isolates the *userland* cost of
/// each buffer — and then this constant puts the syscalls back so the two columns
/// can be read together.
constexpr double kSyscallNs = 1000.0;

struct Metrics {
    std::uint64_t calls    = 0;  ///< send()/sendmsg() invocations
    std::uint64_t slices   = 0;  ///< iovec entries
    std::uint64_t bytes    = 0;
    std::uint64_t allocs   = 0;
    std::uint64_t alloc_kb = 0;
    std::size_t   peak     = 0;  ///< high-water of the queue's own allocated()
    std::size_t   hidden   = 0;  ///< heap held at the peak *beyond* what allocated() admits
    double        user_us  = 0;  ///< measured userland time, syscalls ~free
    double        model_us = 0;  ///< user_us + calls x kSyscallNs
};

static std::string kib(std::size_t b) {
    char buf[32];
    if (b >= 1024 * 1024) std::snprintf(buf, sizeof buf, "%.1f M", double(b) / (1024 * 1024));
    else if (b >= 1024)   std::snprintf(buf, sizeof buf, "%.0f K", double(b) / 1024);
    else                  std::snprintf(buf, sizeof buf, "%zu B", b);
    return buf;
}

static void head(const char* what) {
    std::printf("\n  \033[1m%s\033[0m\n", what);
    std::printf("  \033[2m%-10s %8s %9s %7s %9s %9s %8s %10s %11s\033[0m\n", "impl", "send()",
                "iov", "allocs", "churn", "peak q", "hidden", "userland", "modelled");
}
static void row(const char* tag, const Metrics& m, const char* col) {
    std::printf("  %s%-10s %8llu %9llu %7llu %8lluK %9s %8s %8.1f us %8.1f us\033[0m\n", col, tag,
                (unsigned long long)m.calls, (unsigned long long)m.slices,
                (unsigned long long)m.allocs, (unsigned long long)m.alloc_kb,
                kib(m.peak).c_str(), kib(m.hidden).c_str(), m.user_us, m.model_us);
}

template <typename Fn>
static Metrics measure(mock::TxKernel& k, Fn&& fn) {
    Metrics m;

    // One instrumented run for the counters.
    k.reset();
    track::Stats mem;
    Held         held;
    {
        track::Scope scope(mem);
        held = fn();
    }
    m.calls    = k.c.calls;
    m.slices   = k.c.slices;
    m.bytes    = k.c.bytes;
    m.allocs   = mem.allocs;
    m.alloc_kb = mem.bytes / 1024;
    m.peak     = held.peak;
    m.hidden   = held.hidden;

    // Then a few timed runs; the median is the userland cost.
    std::vector<double> t;
    for (int i = 0; i < 7; ++i) {
        k.reset();
        const auto t0 = std::chrono::steady_clock::now();
        fn();
        const auto t1 = std::chrono::steady_clock::now();
        t.push_back(std::chrono::duration<double, std::micro>(t1 - t0).count());
    }
    std::sort(t.begin(), t.end());
    m.user_us  = t[t.size() / 2];
    m.model_us = m.user_us + double(m.calls) * kSyscallNs / 1000.0;
    return m;
}

// ── main ─────────────────────────────────────────────────────────────────────

static const char* OLD  = "\033[33m";
static const char* NEW  = "\033[32m";
static const char* CORK = "\033[36m";

int main() {
    const Bytes small(200);          // a control-plane frame
    const Bytes medium(16 * 1024);   // an app payload
    const Bytes big(1024 * 1024);    // a 1 MiB blob
    const Bytes block(16 * 1024);    // a BitTorrent piece block

    constexpr std::size_t kSndBuf = 256 * 1024;  // what one send() will take
    constexpr std::size_t kTight  = 16 * 1024;   // a congested peer's window per event

    /// How much a steadily-seeding peer keeps in flight: the queue is topped back up to
    /// this on every writable event, so it is never empty and never unbounded.
    constexpr std::size_t kSteadyDepth = 512 * 1024;

    std::printf("\n\033[1;36mSend path — syscalls & memory\033[0m\n");

    // 1) mesh, 2000 small frames, uncongested.
    {
        head("mesh: 2000 x 200 B frames, peer keeps up");
        mock::TxKernel k(kSndBuf);
        row("old", measure(k, [&] { MeshTxOld d; d.k = &k; return mesh_frames(d, k, small, 2000); }), OLD);
        row("new", measure(k, [&] { MeshTxNew d; d.k = &k; return mesh_frames(d, k, small, 2000); }), NEW);
        row("new+cork", measure(k, [&] { MeshTxNew d; d.k = &k; d.cork = true;
                                         return mesh_batched(d, k, small, 2000, 16); }), CORK);
    }

    // 2) mesh, same frames, congested peer (16 KiB per writable event).
    {
        head("mesh: 2000 x 200 B frames, congested peer (16K/event)");
        mock::TxKernel k(kSndBuf, kTight);
        row("old", measure(k, [&] { MeshTxOld d; d.k = &k; return mesh_frames(d, k, small, 2000); }), OLD);
        row("new", measure(k, [&] { MeshTxNew d; d.k = &k; return mesh_frames(d, k, small, 2000); }), NEW);
    }

    // 3) mesh, 1 MiB frames — the framing copy.
    {
        head("mesh: 32 x 1 MiB frames");
        mock::TxKernel k(kSndBuf);
        row("old", measure(k, [&] { MeshTxOld d; d.k = &k; return mesh_frames(d, k, big, 32); }), OLD);
        row("new", measure(k, [&] { MeshTxNew d; d.k = &k; return mesh_frames(d, k, big, 32); }), NEW);
    }

    // 4) BitTorrent seeder.
    {
        head("bt: seed 1024 x 16 KiB blocks, peer keeps up");
        mock::TxKernel k(kSndBuf);
        row("old", measure(k, [&] { BtTxOld d; d.k = &k; return bt_seed<BtTxOld, false>(d, k, block, 1024); }), OLD);
        row("new", measure(k, [&] { BtTxNew d; d.k = &k; return bt_seed<BtTxNew, true>(d, k, block, 1024); }), NEW);
    }

    // 5) BitTorrent seeder into a congested peer — the O(n^2) erase.
    {
        head("bt: seed 512 x 16 KiB blocks, congested peer (16K/event)");
        mock::TxKernel k(kSndBuf, kTight);
        row("old", measure(k, [&] { BtTxOld d; d.k = &k; return bt_seed<BtTxOld, false>(d, k, block, 512); }), OLD);
        row("new", measure(k, [&] { BtTxNew d; d.k = &k; return bt_seed<BtTxNew, true>(d, k, block, 512); }), NEW);
    }

    // 6) The request pipeline — the cork case.
    {
        head("bt: 200 rounds x 16 requests (Torrent::request_more_blocks)");
        mock::TxKernel k(kSndBuf);
        row("old", measure(k, [&] { BtTxOld d; d.k = &k; return bt_requests(d, k, 200); }), OLD);
        row("new", measure(k, [&] { BtTxNew d; d.k = &k; return bt_requests(d, k, 200); }), NEW);
        row("new+cork", measure(k, [&] { BtTxNew d; d.k = &k; d.cork = true; return bt_requests(d, k, 200, true); }), CORK);
    }

    // 7) A real peer: blocks interleaved with the chatter that rides alongside them.
    {
        head("bt: 512 x (16 KiB block + HAVE + REQUEST), congested peer (16K/event)");
        mock::TxKernel k(kSndBuf, kTight);
        row("old", measure(k, [&] { BtTxOld d; d.k = &k; return bt_mixed<BtTxOld, false>(d, k, block, 512); }), OLD);
        row("new", measure(k, [&] { BtTxNew d; d.k = &k; return bt_mixed<BtTxNew, true>(d, k, block, 512); }), NEW);
    }

    // 8) The steady state: the disk refills the queue while the socket drains it, so
    //    appends and pops interleave and the backlog never empties.
    {
        head("bt: seed 1024 x 16 KiB, queue held at 512 KiB (append while draining)");
        mock::TxKernel k(kSndBuf, kTight);
        row("old", measure(k, [&] { BtTxOld d; d.k = &k; return bt_steady<BtTxOld, false>(d, k, block, 1024, kSteadyDepth); }), OLD);
        row("new", measure(k, [&] { BtTxNew d; d.k = &k; return bt_steady<BtTxNew, true>(d, k, block, 1024, kSteadyDepth); }), NEW);
    }

    // 9) The high-water case: 8 MiB of backlog made of *small* chunks, not big ones.
    {
        head("mesh: 40k x 200 B frames, peer stopped reading (8 MiB backlog)");
        mock::TxKernel k(kSndBuf, kTight);
        row("old", measure(k, [&] { MeshTxOld d; d.k = &k; return mesh_frames(d, k, small, 40000); }), OLD);
        row("new", measure(k, [&] { MeshTxNew d; d.k = &k; return mesh_frames(d, k, small, 40000); }), NEW);
    }

    std::printf(
        "\n  \033[2m'iov'      buffers handed to the kernel in total. The old queue could only\n"
        "             ever show it the front chunk, so iov == send().\n"
        "  'peak q'   the queue's own allocated() at its high-water. This is what the\n"
        "             send high-water mark reads, and so what decides when a slow\n"
        "             consumer is dropped.\n"
        "  'hidden'   heap the queue was really sitting on, over and above what its\n"
        "             allocated() admitted to — sampled at every writable event while\n"
        "             the backlog drains. It must stay near zero: whatever shows up here\n"
        "             is memory a peer that stops reading can make us carry *past* the\n"
        "             high-water mark, invisibly, because the counter guarding the mark\n"
        "             is the very thing under-reporting. No assertion on the public API\n"
        "             can catch that — the counter lies consistently — so it is measured.\n"
        "  'userland' measured with the syscall mocked down to a memcpy — the naked cost\n"
        "             of the buffer machinery, with the kernel taken out of the picture.\n"
        "  'modelled' userland + send() x 1 us, a realistic syscall. This is the column\n"
        "             that decides; the one before it explains why.\n"
        "  'new+cork' queue the batch, flush once (libtorrent's cork). NOT in the library\n"
        "             yet — this is what the gather machinery is still leaving on the"
        " table.\033[0m\n");

    // ── Timing ───────────────────────────────────────────────────────────────

    bench::Bench b("Send path — throughput");
    b.config().min_time = 0.35;

    {
        b.group("mesh: 2000 x 200 B, peer keeps up");
        b.bytes(2000 * 204.0);
        mock::TxKernel k(kSndBuf);
        b.run("old", [&] { MeshTxOld d; d.k = &k; mesh_frames(d, k, small, 2000); });
        b.run("new", [&] { MeshTxNew d; d.k = &k; mesh_frames(d, k, small, 2000); });
        b.run("new+cork", [&] {
            MeshTxNew d; d.k = &k; d.cork = true;
            mesh_batched(d, k, small, 2000, 16);
        });
    }
    {
        b.group("mesh: 2000 x 200 B, congested (16K/event)");
        b.bytes(2000 * 204.0);
        mock::TxKernel k(kSndBuf, kTight);
        b.run("old", [&] { MeshTxOld d; d.k = &k; mesh_frames(d, k, small, 2000); });
        b.run("new", [&] { MeshTxNew d; d.k = &k; mesh_frames(d, k, small, 2000); });
    }
    {
        b.group("mesh: 32 x 1 MiB frames");
        b.bytes(32.0 * 1024 * 1024);
        mock::TxKernel k(kSndBuf);
        b.run("old", [&] { MeshTxOld d; d.k = &k; mesh_frames(d, k, big, 32); });
        b.run("new", [&] { MeshTxNew d; d.k = &k; mesh_frames(d, k, big, 32); });
    }
    {
        b.group("bt: seed 1024 x 16 KiB blocks");
        b.bytes(1024.0 * (16 * 1024 + 13));
        mock::TxKernel k(kSndBuf);
        b.run("old", [&] { BtTxOld d; d.k = &k; bt_seed<BtTxOld, false>(d, k, block, 1024); });
        b.run("new", [&] { BtTxNew d; d.k = &k; bt_seed<BtTxNew, true>(d, k, block, 1024); });
    }
    {
        b.group("bt: seed 512 x 16 KiB, congested (16K/event)");
        b.bytes(512.0 * (16 * 1024 + 13));
        mock::TxKernel k(kSndBuf, kTight);
        b.run("old", [&] { BtTxOld d; d.k = &k; bt_seed<BtTxOld, false>(d, k, block, 512); });
        b.run("new", [&] { BtTxNew d; d.k = &k; bt_seed<BtTxNew, true>(d, k, block, 512); });
    }
    {
        b.group("bt: 200 x 16 requests (pipeline)");
        b.bytes(200 * 16 * 17.0);
        mock::TxKernel k(kSndBuf);
        b.run("old", [&] { BtTxOld d; d.k = &k; bt_requests(d, k, 200); });
        b.run("new", [&] { BtTxNew d; d.k = &k; bt_requests(d, k, 200); });
        b.run("new+cork", [&] { BtTxNew d; d.k = &k; d.cork = true; bt_requests(d, k, 200, true); });
    }
    {
        b.group("bt: 512 x (block + HAVE + REQUEST), congested");
        b.bytes(512.0 * (16 * 1024 + 13 + 9 + 17));
        mock::TxKernel k(kSndBuf, kTight);
        b.run("old", [&] { BtTxOld d; d.k = &k; bt_mixed<BtTxOld, false>(d, k, block, 512); });
        b.run("new", [&] { BtTxNew d; d.k = &k; bt_mixed<BtTxNew, true>(d, k, block, 512); });
    }
    {
        b.group("bt: seed 1024 x 16 KiB, append while draining");
        b.bytes(1024.0 * (16 * 1024 + 13));
        mock::TxKernel k(kSndBuf, kTight);
        b.run("old", [&] { BtTxOld d; d.k = &k; bt_steady<BtTxOld, false>(d, k, block, 1024, kSteadyDepth); });
        b.run("new", [&] { BtTxNew d; d.k = &k; bt_steady<BtTxNew, true>(d, k, block, 1024, kSteadyDepth); });
    }
    {
        b.group("mesh: 40k x 200 B, 8 MiB backlog");
        b.bytes(40000 * 204.0);
        mock::TxKernel k(kSndBuf, kTight);
        b.run("old", [&] { MeshTxOld d; d.k = &k; mesh_frames(d, k, small, 40000); });
        b.run("new", [&] { MeshTxNew d; d.k = &k; mesh_frames(d, k, small, 40000); });
    }
    b.report();
    return 0;
}
