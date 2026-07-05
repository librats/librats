#include "bittorrent/torrent.h"

#include "bittorrent/byte_io.h"
#include "bittorrent/log.h"
#include "util/fs.h"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <unordered_map>

namespace librats::bittorrent {

Torrent::Torrent(Reactor& reactor, TorrentHost& host, TorrentInfo info, std::string save_path)
    : reactor_(reactor)
    , host_(host)
    , info_(std::move(info))
    , save_path_(std::move(save_path))
    , choker_(4) {}

Torrent::~Torrent() {
    // Invalidate the liveness token before tearing down: stop() joins the disk /
    // tracker workers, and a completion a worker posts during that join lands in
    // the reactor queue after `this` is gone — the guard in post() drops it.
    alive_->store(false, std::memory_order_release);
    stop();
}

void Torrent::post(std::function<void()> fn) {
    reactor_.post([alive = alive_, fn = std::move(fn)]() mutable {
        if (alive->load(std::memory_order_acquire)) fn();
    });
}

void Torrent::start() {
    if (running_) return;
    running_ = true;
    has_metadata_ = info_.has_metadata();

    if (has_metadata_) {
        picker_ = std::make_unique<PiecePicker>(info_.num_pieces(), info_.piece_length(), info_.total_size());
        disk_   = std::make_unique<ThreadedDiskIo>(
            info_, save_path_,
            [this](std::function<void()> fn) { post(std::move(fn)); });
        state_ = State::Checking;
        LOG_INFO("bt.torrent", short_hash(info_hash()) << " \"" << info_.name() << "\" → Checking ("
                               << info_.num_pieces() << " pieces, " << info_.total_size() << " bytes)");
        // Pieces in resume_have_ are trusted (skip the hash); the rest are verified.
        disk_->async_check_files(resume_have_, nullptr,
                                 [this](Bitfield have) { on_check_complete(std::move(have)); });
    } else {
        // Magnet: no metadata yet — fetch the info dict from peers (BEP 9) first.
        state_ = State::Metadata;
        LOG_INFO("bt.torrent", short_hash(info_hash()) << " → Metadata (magnet, awaiting info dict)");
    }

    // Trackers come from the .torrent or the magnet link; announce to find peers
    // (which also seeds the metadata fetch for magnets).
    if (!info_.all_trackers().empty()) {
        trackers_ = std::make_unique<TrackerAnnouncer>(
            info_.all_trackers(), [this](std::function<void()> fn) { post(std::move(fn)); });
        announce_trackers(TrackerEvent::Started);
    }

    schedule_tick();
    try_connect();
}

void Torrent::stop() {
    if (!running_) return;
    running_ = false;
    LOG_INFO("bt.torrent", short_hash(info_hash()) << " stopped (" << peers_.size() << " peers)");
    if (tick_timer_ != kInvalidTimerId) { reactor_.cancel(tick_timer_); tick_timer_ = kInvalidTimerId; }
    if (trackers_) {
        announce_trackers(TrackerEvent::Stopped);  // tell trackers we're leaving (H12)
        trackers_->stop();                          // drains the in-flight Stopped announce
        trackers_.reset();
    }
    for (PeerConnection* pc : peers_) pc->close("torrent stopped");
    peers_.clear();
    outstanding_.clear();
    recent_down_.clear();
    seed_peers_.clear();
    if (disk_) disk_->stop();
    disk_.reset();
    picker_.reset();
    state_ = State::Stopped;
}

void Torrent::on_check_complete(Bitfield have) {
    if (!running_) return;
    picker_->set_have_bitfield(have);
    // Account the bytes already on disk toward `left` via verified_bytes_ — NOT
    // bytes_downloaded_, which is the cumulative download counter restored verbatim
    // from resume. Folding on-disk pieces into it too would double-count a resumed
    // torrent (and drive `left` to 0, falsely announcing us as a seed).
    for (std::uint32_t p = 0; p < info_.num_pieces(); ++p)
        if (picker_->have_piece(p)) verified_bytes_ += info_.piece_size(p);

    if (picker_->is_finished()) { state_ = State::Seeding; completed_announced_ = true; }
    else                        { state_ = State::Downloading; }

    if (state_ == State::Seeding)
        LOG_INFO("bt.torrent", short_hash(info_hash()) << " check complete: all "
                               << info_.num_pieces() << " pieces present → Seeding");
    else
        LOG_INFO("bt.torrent", short_hash(info_hash()) << " check complete: " << picker_->num_have()
                               << '/' << info_.num_pieces() << " pieces (" << int(progress() * 100)
                               << "%) → Downloading");

    try_connect();
}

void Torrent::add_peer(const std::string& ip, std::uint16_t port) {
    if (peer_list_.add(ip, port, PeerSource::Tracker) && running_)
        post([this] { try_connect(); });
}

void Torrent::try_connect() {
    if (!running_ || peers_.size() >= kMaxPeers) return;
    auto candidates = peer_list_.connect_candidates(kMaxPeers - peers_.size());
    for (const auto& c : candidates) host_.connect_peer(*this, c.ip, c.port);
}

void Torrent::on_connect_failed(const std::string& ip, std::uint16_t port) {
    peer_list_.on_connect_failed(ip, port);
}

// ---- scheduling ----

void Torrent::schedule_tick() {
    if (!running_) return;
    tick_timer_ = reactor_.schedule(std::chrono::seconds(1), [this] { tick(); });
}

void Torrent::tick() {
    if (!running_) return;
    ++tick_count_;

    check_request_timeouts();  // free blocks stuck on stalled peers before anything else

    // Ask the DHT for fresh peers periodically (every ~30 s).
    if (tick_count_ % 30 == 1) {
        LOG_DEBUG("bt.torrent", short_hash(info_hash()) << " → DHT get_peers");
        host_.find_peers_via_dht(info_hash(), [this](const std::string& ip, std::uint16_t port) {
            if (peer_list_.add(ip, port, PeerSource::Dht)) try_connect();
        });
    }
    // Announce ourselves to the DHT so others can find us — promptly on startup,
    // then every ~15 min per BEP 5 (H15). Was previously never done → undiscoverable.
    if (tick_count_ % 900 == 5) {
        LOG_DEBUG("bt.torrent", short_hash(info_hash()) << " → DHT announce_peer port "
                                << host_.listen_port());
        host_.announce_to_dht(info_hash(), host_.listen_port());
    }
    // Re-announce when the tracker's requested interval has elapsed (H13).
    if (tick_count_ >= next_announce_tick_) {
        next_announce_tick_ = tick_count_ + 300;  // fallback until the response updates it
        announce_trackers(TrackerEvent::None);
    }

    try_connect();
    send_pex();

    // Choking runs on a coarse cadence, not every tick: recompute the unchoke set
    // every ~10 s and rotate the optimistic slot every ~30 s. Recomputing every
    // second (with a 1 s scoring window) made peers near the slot boundary flip
    // choke/unchoke constantly (H4). The tit-for-tat window therefore accumulates
    // over the whole 10 s and is only reset when we recompute.
    if (tick_count_ % 30 == 0) rotate_optimistic();
    if (tick_count_ % 10 == 0) {
        recompute_choker();
        for (auto& [pc, score] : recent_down_) score = 0;
        for (auto& [pc, score] : recent_up_)   score = 0;
    }
    schedule_tick();
}

// ---- peer event handling ----

void Torrent::on_handshake(PeerConnection& pc, const InfoHash&, const PeerId&) {
    // Cap peers per torrent. Outbound dials are already gated by try_connect(), but
    // inbound peers reach us straight through the handshake, so enforce it here too
    // (H3) — otherwise a flood of incoming handshakes grows peers_ without bound.
    if (peers_.size() >= kMaxPeers) { pc.close("too many peers"); return; }
    peers_.push_back(&pc);
    outstanding_[&pc] = 0;
    recent_down_[&pc] = 0;
    peer_list_.set_connected(pc.remote_ip(), pc.remote_port(), true);
    // Milestone: the first peer on a torrent is worth an INFO line; the rest are
    // routine (each peer's handshake is already logged at DEBUG in bt.peer).
    if (peers_.size() == 1)
        LOG_INFO("bt.torrent", short_hash(info_hash()) << " first peer connected "
                               << pc.remote_ip() << ':' << pc.remote_port());

    if (pc.peer_supports_extensions()) send_extended_handshake(pc);
    // Only announce a bitfield once we know the piece count (i.e. have metadata).
    if (has_metadata_ && picker_) pc.send_bitfield(picker_->have_bitfield());
}

void Torrent::on_bitfield(PeerConnection& pc, const Bitfield& bf) {
    if (!picker_) return;
    // A full bitfield is a seed: count it as one O(1) seed instead of bumping every
    // piece's availability. Remember which peers we counted this way so remove_peer
    // undoes it symmetrically. The insert() guard also makes a (spurious) repeat
    // full bitfield idempotent for the seed count.
    const std::uint32_t n = info_.num_pieces();
    if (n > 0 && bf.size() == n && bf.count() == n) {
        if (seed_peers_.insert(&pc).second) picker_->inc_availability_all();
    } else {
        picker_->inc_availability(bf);
    }
    update_interest(pc);
}

void Torrent::on_have(PeerConnection& pc, std::uint32_t piece) {
    if (!picker_ || piece >= info_.num_pieces()) return;
    picker_->peer_has_piece(piece);
    // A single new piece can only *gain* us interest, never lose it, and the piece
    // the peer just announced is enough to decide — so this stays O(1) instead of
    // rescanning the peer's whole bitfield via is_interesting() on every HAVE.
    if (!pc.am_interested() && picker_->piece_interesting(piece)) pc.send_interested();
    if (pc.am_interested() && !pc.peer_choking()) refill(pc);
}

void Torrent::on_choke(PeerConnection& pc, bool peer_choking) {
    if (!picker_) return;
    if (peer_choking) {
        picker_->cancel_peer(&pc);  // they dropped our outstanding requests
        outstanding_[&pc] = 0;
        request_time_.erase(&pc);
    } else {
        refill(pc);
    }
}

void Torrent::on_interest(PeerConnection&, bool) {
    recompute_choker();  // a peer's interest in us changed → re-evaluate upload slots
}

void Torrent::update_interest(PeerConnection& pc) {
    const bool want = picker_->is_interesting(pc.peer_bitfield());
    if (want && !pc.am_interested())       pc.send_interested();
    else if (!want && pc.am_interested())  pc.send_not_interested();
    if (want && !pc.peer_choking())        refill(pc);
}

void Torrent::refill(PeerConnection& pc) {
    if (!running_ || !picker_ || pc.peer_choking() || !pc.am_interested()) return;
    // Disk backpressure: while too many writes are still pending, stop requesting
    // new blocks so the write queue can drain (D-2). on_block_written() resumes
    // requesting once it falls back under the watermark.
    if (disk_ && disk_->queued_write_bytes() > kDiskWriteHighWater) { write_stalled_ = true; return; }
    int budget = kPipelineDepth - outstanding_[&pc];
    if (budget <= 0) return;

    const int before = outstanding_[&pc];
    auto blocks = picker_->pick_blocks(pc.peer_bitfield(), budget, &pc);
    for (const PieceBlock& b : blocks) {
        picker_->mark_requested(b, &pc);
        pc.send_request(b.piece, b.block * kBlockSize, picker_->block_size(b.piece, b.block));
        ++outstanding_[&pc];
    }
    if (!blocks.empty())
        LOG_DEBUG("bt.torrent", short_hash(info_hash()) << " → request " << blocks.size()
                                << " block(s) from " << pc.remote_ip() << ':' << pc.remote_port()
                                << " (" << outstanding_[&pc] << " in flight)");
    // Start the stall clock when a previously-idle peer gets a fresh batch. If it
    // already had requests in flight, keep the older timestamp so a peer that
    // stops delivering can't hide behind newly-added requests.
    if (before == 0 && outstanding_[&pc] > 0)
        request_time_[&pc] = std::chrono::steady_clock::now();
}

void Torrent::on_piece(PeerConnection& pc, std::uint32_t piece, std::uint32_t offset, ByteView data) {
    if (!picker_ || piece >= info_.num_pieces()) return;

    // Reject a malformed or unsolicited block before it can index the picker's
    // block vector out of bounds: the offset must be block-aligned and inside the
    // piece, and the payload must be exactly that block's size. A hostile peer
    // could otherwise drive an out-of-bounds access via mark_writing()/mark_finished().
    const std::uint32_t piece_bytes = info_.piece_size(piece);
    if (offset % kBlockSize != 0 || offset >= piece_bytes) {
        LOG_WARN("bt.torrent", short_hash(info_hash()) << " ✗ bad block from " << pc.remote_ip()
                               << ':' << pc.remote_port() << " piece " << piece << " off " << offset
                               << " (misaligned/out of range), dropped");
        return;
    }
    if (data.size() != picker_->block_size(piece, offset / kBlockSize)) {
        LOG_WARN("bt.torrent", short_hash(info_hash()) << " ✗ bad block from " << pc.remote_ip()
                               << ':' << pc.remote_port() << " piece " << piece
                               << " wrong size " << data.size() << ", dropped");
        return;
    }

    if (outstanding_[&pc] > 0) --outstanding_[&pc];
    // Progress: this peer just delivered, so reset its stall clock — any remaining
    // outstanding blocks get a fresh timeout window.
    request_time_[&pc] = std::chrono::steady_clock::now();

    // We already completed this piece — an end-game duplicate that crossed our
    // CANCEL, or a block arriving after the piece verified. Discard it: writing it
    // again would be wasted I/O and would resurrect a stale picker entry. The
    // request slot is already freed, so just keep this peer's pipeline full.
    if (picker_->have_piece(piece)) { refill(pc); return; }

    const PieceBlock block{piece, offset / kBlockSize};
    bytes_downloaded_ += data.size();
    recent_down_[&pc] += data.size();

    // End-game: this block may have been requested from several peers at once. Now
    // that it has arrived, CANCEL the duplicate requests still outstanding on the
    // *other* peers so we don't download the same block again from each of them.
    const std::vector<const void*> others = picker_->mark_writing(block, &pc);
    for (const void* o : others) {
        auto* opc = static_cast<PeerConnection*>(const_cast<void*>(o));
        if (!alive(opc)) continue;
        auto it = outstanding_.find(opc);
        if (it != outstanding_.end() && it->second > 0) --it->second;  // freed a slot
        opc->send_cancel(piece, block.block * kBlockSize, picker_->block_size(piece, block.block));
    }

    disk_->async_write(piece, offset, data.to_bytes(),
                       [this, block](bool ok) { on_block_written(block, ok); });

    refill(pc);  // keep the pipeline full while the write is in flight
}

void Torrent::check_request_timeouts() {
    if (!picker_) return;
    const auto now = std::chrono::steady_clock::now();

    // Find peers that hold outstanding requests but have made no progress within
    // the timeout. A peer sending only keep-alives (which refresh the 120 s idle
    // deadline) would otherwise sit on its blocks forever, stalling those pieces.
    std::vector<PeerConnection*> stalled;
    for (const auto& [pc, n] : outstanding_) {
        if (n <= 0) continue;
        auto it = request_time_.find(pc);
        if (it != request_time_.end() && now - it->second > request_timeout_)
            stalled.push_back(pc);
    }
    if (stalled.empty()) return;

    // Release each stalled peer's blocks back to the picker so another peer can
    // pick them, and leave the peer idle (no re-request this round) so we don't
    // immediately hand the same blocks back to the peer that just stalled.
    for (PeerConnection* pc : stalled) {
        picker_->cancel_peer(pc);
        outstanding_[pc] = 0;
        request_time_.erase(pc);
    }
    LOG_WARN("bt.torrent", short_hash(info_hash()) << " snubbed " << stalled.size()
                           << " stalled peer(s), freed their blocks for re-request");

    // Re-request the freed blocks from peers that are actually delivering.
    for (PeerConnection* pc : peers_) {
        if (std::find(stalled.begin(), stalled.end(), pc) != stalled.end()) continue;
        if (pc->am_interested() && !pc->peer_choking()) refill(*pc);
    }
}

void Torrent::on_block_written(PieceBlock block, bool ok) {
    if (!running_ || !picker_) return;
    if (!ok) {
        LOG_ERROR("bt.torrent", short_hash(info_hash()) << " ✗ disk write failed for piece "
                                << block.piece << ", will refetch");
        picker_->restore_piece(block.piece);
        return;
    }
    if (picker_->mark_finished(block)) verify_piece(block.piece);

    // A write just drained: if backpressure had paused requesting and the queue is
    // back under the watermark, resume filling peers' pipelines (D-2).
    if (write_stalled_ && (!disk_ || disk_->queued_write_bytes() <= kDiskWriteHighWater)) {
        write_stalled_ = false;
        refill_all();
    }
}

void Torrent::refill_all() {
    for (PeerConnection* pc : peers_)
        if (pc->am_interested() && !pc->peer_choking()) refill(*pc);
}

void Torrent::verify_piece(std::uint32_t piece) {
    disk_->async_hash(piece, [this, piece](bool ok, std::array<std::uint8_t, 20> hash) {
        on_piece_hashed(piece, ok, hash);
    });
}

void Torrent::on_piece_hashed(std::uint32_t piece, bool ok, std::array<std::uint8_t, 20> hash) {
    if (!running_ || !picker_) return;
    if (!ok || hash != info_.piece_hash(piece)) {
        LOG_WARN("bt.torrent", short_hash(info_hash()) << " ✗ piece " << piece
                               << " hash mismatch, refetch");
        picker_->restore_piece(piece);  // corrupt — fetch it again
        return;
    }

    picker_->we_have(piece);
    verified_bytes_ += info_.piece_size(piece);  // one more piece is now on disk → shrinks `left`
    for (PeerConnection* pc : peers_) {
        pc->send_have(piece);
        update_interest(*pc);  // we may no longer need some peers
    }

    LOG_DEBUG("bt.torrent", short_hash(info_hash()) << " ✓ piece " << piece << " verified ("
                            << picker_->num_have() << '/' << info_.num_pieces() << ')');
    // Progress milestone: log once per 10% crossed, not once per piece (H: keep INFO
    // readable as a clean per-torrent story instead of thousands of lines).
    const int pct = int(progress() * 100);
    if (pct / 10 > progress_logged_ && pct < 100) {
        progress_logged_ = pct / 10;
        LOG_INFO("bt.torrent", short_hash(info_hash()) << " progress " << (progress_logged_ * 10) << '%');
    }

    if (picker_->is_finished() && !completed_announced_) {
        completed_announced_ = true;
        state_ = State::Seeding;
        LOG_INFO("bt.torrent", short_hash(info_hash()) << " ✓ download complete → Seeding");
        announce_trackers(TrackerEvent::Completed);  // tell trackers we're now a seed (H12)
        if (on_complete_) on_complete_();
    }
}

void Torrent::on_request(PeerConnection& pc, std::uint32_t piece, std::uint32_t offset, std::uint32_t length) {
    if (!picker_ || pc.am_choking()) return;             // we are not serving this peer
    if (piece >= info_.num_pieces() || !picker_->have_piece(piece)) return;
    if (length == 0 || length > kMaxBlockSize) return;
    // The requested range must lie wholly within the piece, else the disk read
    // would spill into an adjacent piece's file region and serve unrelated bytes.
    const std::uint32_t piece_bytes = info_.piece_size(piece);
    if (offset >= piece_bytes || length > piece_bytes - offset) return;

    PeerConnection* peer = &pc;
    disk_->async_read(piece, offset, length, [this, peer, piece, offset](bool ok, Bytes data) {
        if (ok && alive(peer)) {
            peer->send_piece(piece, offset, ByteView(data));
            bytes_uploaded_    += data.size();
            recent_up_[peer]   += data.size();  // seed-choking score for this window
        }
    });
}

void Torrent::on_closed(PeerConnection& pc, const std::string&) {
    peer_list_.set_connected(pc.remote_ip(), pc.remote_port(), false);
    pex_sent_.erase(&pc);
    remove_peer(&pc);
}

// ---- choking ----

void Torrent::recompute_choker() {
    if (!running_) return;
    // Score peers by what they've done for us this window: while downloading that
    // is bytes received (tit-for-tat); while seeding we receive nothing, so score
    // by bytes we served them instead — otherwise every peer scores 0 and a seed
    // would serve only whichever peers happened to connect first, forever (H2).
    const bool seeding = picker_ && picker_->is_finished();
    std::vector<Choker::Candidate> candidates;
    for (PeerConnection* pc : peers_)
        if (pc->peer_interested())
            candidates.push_back(Choker::Candidate{pc, seeding ? recent_up_[pc] : recent_down_[pc]});

    auto unchoke = choker_.select(std::move(candidates), optimistic_);
    for (PeerConnection* pc : peers_) {
        const bool should_unchoke =
            std::find(unchoke.begin(), unchoke.end(), pc) != unchoke.end();
        if (should_unchoke && pc->am_choking())       pc->send_unchoke();
        else if (!should_unchoke && !pc->am_choking()) pc->send_choke();
    }
}

void Torrent::rotate_optimistic() {
    // Round-robin the optimistic slot through the interested-but-choked peers so a
    // newcomer that hasn't earned a tit-for-tat slot still gets a chance to prove
    // itself (H1). Advance from just after the current optimistic in peer order.
    std::vector<PeerConnection*> candidates;
    for (PeerConnection* pc : peers_)
        if (pc->peer_interested()) candidates.push_back(pc);
    if (candidates.empty()) { optimistic_ = nullptr; return; }

    auto it = std::find(candidates.begin(), candidates.end(), optimistic_);
    const std::size_t next = (it == candidates.end()) ? 0
                           : (std::size_t(it - candidates.begin()) + 1) % candidates.size();
    optimistic_ = candidates[next];
    recompute_choker();  // apply the new optimistic slot immediately
}

// ---- helpers ----

bool Torrent::alive(PeerConnection* pc) const {
    return std::find(peers_.begin(), peers_.end(), pc) != peers_.end();
}

void Torrent::remove_peer(PeerConnection* pc) {
    auto it = std::find(peers_.begin(), peers_.end(), pc);
    if (it == peers_.end()) return;
    if (picker_) {
        // Undo the availability accounting the same way it was applied: a seed via
        // the seed counter, anyone else per-piece from their bitfield.
        if (seed_peers_.erase(pc)) picker_->dec_availability_all();
        else                       picker_->dec_availability(pc->peer_bitfield());
        picker_->cancel_peer(pc);
    }
    if (optimistic_ == pc) optimistic_ = nullptr;
    peers_.erase(it);
    outstanding_.erase(pc);
    request_time_.erase(pc);
    recent_down_.erase(pc);
    recent_up_.erase(pc);
    peer_ext_.erase(pc);
    pex_last_tick_.erase(pc);
}

std::size_t Torrent::num_outstanding_requests() const noexcept {
    std::size_t n = 0;
    for (const auto& [pc, count] : outstanding_) if (count > 0) n += std::size_t(count);
    return n;
}

double Torrent::progress() const {
    if (!picker_ || info_.num_pieces() == 0) return 0.0;
    return double(picker_->num_have()) / double(info_.num_pieces());
}

// ---- extension protocol / metadata (BEP 10 / BEP 9) ----

void Torrent::on_extended(PeerConnection& pc, std::uint8_t ext_id, ByteView payload) {
    if (ext_id == 0)                            handle_ext_handshake(pc, payload);
    else if (ext_id == ext::kUtMetadataLocalId) handle_ut_metadata(pc, payload);
    else if (ext_id == ext::kUtPexLocalId)      handle_pex(pc, payload);
}

void Torrent::send_extended_handshake(PeerConnection& pc) {
    const std::uint32_t ms = has_metadata_ ? std::uint32_t(info_.info_dict_bytes().size()) : 0;
    const Bytes hs = ext::encode_handshake(ms, host_.listen_port());
    pc.send_extended(0, ByteView(hs));
}

void Torrent::handle_ext_handshake(PeerConnection& pc, ByteView payload) {
    auto pe = ext::decode_handshake(payload);
    if (!pe) return;
    peer_ext_[&pc] = *pe;
    if (!has_metadata_ && pe->metadata_size > 0) {
        ensure_metadata_buffer(pe->metadata_size);
        request_metadata(pc);
    }
}

void Torrent::ensure_metadata_buffer(std::uint32_t total_size) {
    if (metadata_size_ != 0 || total_size == 0) return;  // already sized, or unknown
    // The size is self-reported by a peer (extended handshake or ut_metadata data
    // message), so reject an implausible value before allocating — otherwise a
    // hostile peer advertising ~4 GiB drives an out-of-memory allocation (C3).
    if (total_size > kMaxMetadataSize) {
        LOG_WARN("bt.meta", short_hash(info_hash()) << " ✗ rejected oversize metadata "
                            << total_size << " bytes (> " << kMaxMetadataSize << ')');
        return;
    }
    metadata_size_     = total_size;
    metadata_pieces_   = (total_size + kMetadataPieceSize - 1) / kMetadataPieceSize;
    metadata_buf_.assign(total_size, 0);
    metadata_have_.assign(metadata_pieces_, false);
    metadata_received_ = 0;
}

void Torrent::request_metadata(PeerConnection& pc) {
    if (has_metadata_ || metadata_pieces_ == 0) return;
    auto it = peer_ext_.find(&pc);
    if (it == peer_ext_.end() || it->second.ut_metadata_id == 0) return;
    for (std::uint32_t p = 0; p < metadata_pieces_; ++p)
        if (!metadata_have_[p])
            pc.send_extended(it->second.ut_metadata_id, ByteView(ext::encode_metadata_request(p)));
}

void Torrent::handle_ut_metadata(PeerConnection& pc, ByteView payload) {
    auto msg = ext::decode_metadata(payload);
    if (!msg) return;

    if (msg->type == ext::MetadataType::Request) {
        auto it = peer_ext_.find(&pc);
        const std::uint8_t id = (it != peer_ext_.end()) ? it->second.ut_metadata_id : 0;
        if (id == 0) return;
        if (has_metadata_) {
            const Bytes& info  = info_.info_dict_bytes();
            const std::uint32_t total  = std::uint32_t(info.size());
            const std::uint32_t pieces = (total + kMetadataPieceSize - 1) / kMetadataPieceSize;
            if (msg->piece < pieces) {
                const std::uint32_t off = msg->piece * kMetadataPieceSize;
                const std::uint32_t len = (std::min)(kMetadataPieceSize, total - off);
                pc.send_extended(id, ByteView(ext::encode_metadata_data(
                                            msg->piece, total, ByteView(info.data() + off, len))));
                return;
            }
        }
        pc.send_extended(id, ByteView(ext::encode_metadata_reject(msg->piece)));
    } else if (msg->type == ext::MetadataType::Data) {
        on_metadata_piece(msg->piece, msg->total_size, ByteView(msg->block));
    }
    // Reject: leave the piece unmarked so it can be re-requested from another peer.
}

void Torrent::on_metadata_piece(std::uint32_t piece, std::uint32_t total_size, ByteView block) {
    if (has_metadata_) return;
    ensure_metadata_buffer(total_size);
    if (metadata_size_ == 0 || piece >= metadata_pieces_ || metadata_have_[piece]) return;

    const std::uint32_t off    = piece * kMetadataPieceSize;
    const std::uint32_t expect = (std::min)(kMetadataPieceSize, metadata_size_ - off);
    if (block.size() != expect) return;  // malformed slice — ignore

    std::copy(block.begin(), block.end(), metadata_buf_.begin() + std::ptrdiff_t(off));
    metadata_have_[piece] = true;
    if (++metadata_received_ == metadata_pieces_) try_complete_metadata();
}

void Torrent::try_complete_metadata() {
    if (info_.set_metadata(metadata_buf_)) {       // verifies SHA-1 == info-hash
        has_metadata_ = true;
        LOG_INFO("bt.meta", short_hash(info_hash()) << " ✓ metadata resolved: \"" << info_.name()
                            << "\" " << info_.num_pieces() << " pieces, " << info_.total_size() << " bytes");
        if (on_metadata_) on_metadata_(info_);
        promote_to_downloading();
    } else {
        // Verification failed — discard and re-request from every peer.
        LOG_WARN("bt.meta", short_hash(info_hash()) << " ✗ metadata verification failed, re-requesting");
        std::fill(metadata_have_.begin(), metadata_have_.end(), false);
        metadata_received_ = 0;
        for (PeerConnection* pc : peers_) request_metadata(*pc);
    }
}

void Torrent::promote_to_downloading() {
    picker_ = std::make_unique<PiecePicker>(info_.num_pieces(), info_.piece_length(), info_.total_size());
    disk_   = std::make_unique<ThreadedDiskIo>(
        info_, save_path_, [this](std::function<void()> fn) { post(std::move(fn)); });
    state_ = State::Downloading;

    // Adopt the bitfields we received while metadata-less and (re)evaluate interest.
    for (PeerConnection* pc : peers_) {
        picker_->inc_availability(pc->peer_bitfield());
        update_interest(*pc);
    }
    disk_->async_check_files(Bitfield{}, nullptr,
                             [this](Bitfield have) { on_check_complete(std::move(have)); });
}

// ---- peer exchange (BEP 11) ----

void Torrent::handle_pex(PeerConnection& pc, ByteView payload) {
    auto msg = ext::decode_pex(payload);
    if (!msg) return;
    bool added_any = false;
    for (const auto& p : msg->added)
        if (peer_list_.add(p.ip, p.port, PeerSource::Pex)) added_any = true;
    if (added_any) try_connect();
}

std::optional<ext::PexPeer> Torrent::dialable(PeerConnection& pc) const {
    if (pc.remote_ip().empty()) return std::nullopt;
    if (pc.outgoing())  // we dialed its listen port directly
        return ext::PexPeer{pc.remote_ip(), pc.remote_port()};
    // Incoming: the source port is ephemeral; use the listen port it advertised.
    auto it = peer_ext_.find(const_cast<PeerConnection*>(&pc));
    if (it == peer_ext_.end() || it->second.listen_port == 0) return std::nullopt;
    return ext::PexPeer{pc.remote_ip(), it->second.listen_port};
}

void Torrent::send_pex() {
    for (PeerConnection* pc : peers_) {
        auto ext_it = peer_ext_.find(pc);
        if (ext_it == peer_ext_.end() || ext_it->second.ut_pex_id == 0) continue;

        // BEP 11: the first PEX message to a peer may go out promptly, but
        // subsequent ones must be at least 60 s apart or the peer treats it as
        // abuse and disconnects (too_frequent_pex) (H14). Gate per peer.
        auto tick_it = pex_last_tick_.find(pc);
        const bool first = (tick_it == pex_last_tick_.end());
        if (!first && tick_count_ - tick_it->second < 60) continue;

        // Diff the set of dialable peers we've told this one about against the
        // current set: newly-seen peers go in `added`, departed ones in `dropped`.
        std::unordered_map<std::string, ext::PexPeer> current;
        for (PeerConnection* other : peers_) {
            if (other == pc) continue;
            if (auto ep = dialable(*other))
                current.emplace(ep->ip + ":" + std::to_string(ep->port), *ep);
        }

        auto& sent = pex_sent_[pc];
        std::vector<ext::PexPeer> added, dropped;
        for (const auto& [key, ep] : current)
            if (!sent.count(key)) added.push_back(ep);
        for (const std::string& key : sent) {
            if (current.count(key)) continue;
            const std::size_t c = key.rfind(':');  // reconstruct the departed peer's endpoint
            if (c != std::string::npos)
                dropped.push_back(ext::PexPeer{key.substr(0, c),
                                               std::uint16_t(std::atoi(key.c_str() + c + 1))});
        }

        if (!added.empty() || !dropped.empty()) {
            pc->send_extended(ext_it->second.ut_pex_id, ByteView(ext::encode_pex(added, dropped)));
            pex_last_tick_[pc] = tick_count_;
        }

        sent.clear();
        for (const auto& [key, ep] : current) sent.insert(key);
    }
}

// ---- trackers ----

TrackerRequest Torrent::make_tracker_request(TrackerEvent event) const {
    TrackerRequest r;
    r.info_hash  = info_hash();
    r.peer_id    = host_.peer_id();
    r.port       = host_.listen_port();
    r.uploaded   = bytes_uploaded_;
    r.downloaded = bytes_downloaded_;
    // `left` is what remains to fetch = total size minus what is verified on disk.
    // Must use verified_bytes_, not the cumulative bytes_downloaded_ (which can
    // exceed on-disk bytes after re-downloads and would understate `left`).
    r.left = (has_metadata_ && info_.total_size() > std::int64_t(verified_bytes_))
                 ? std::uint64_t(info_.total_size()) - verified_bytes_
                 : 0;
    r.event   = event;
    r.numwant = 50;
    return r;
}

void Torrent::announce_trackers(TrackerEvent event) {
    if (!trackers_) return;
    trackers_->announce(make_tracker_request(event),
                        [this](const std::vector<Address>& peers, std::uint32_t interval) {
        // Schedule the next periodic announce off the tracker's requested interval
        // rather than a fixed cadence (H13). tick_count_ advances ~1/s.
        next_announce_tick_ = tick_count_ + int(interval);
        int added = 0;
        for (const Address& a : peers)
            if (peer_list_.add(a.ip.to_string(), a.port, PeerSource::Tracker)) ++added;
        LOG_INFO("bt.tracker", short_hash(info_hash()) << " ← " << peers.size() << " peers (+"
                               << added << " new), next announce in " << interval << "s");
        if (added) try_connect();
    });
}

// ---- fast resume ----

void Torrent::load_resume_data(const ResumeData& rd) {
    if (running_) return;  // must be applied before start()
    // Recover metadata for a magnet torrent from the embedded info section.
    if (!info_.has_metadata() && !rd.info_dict.empty()) info_.set_metadata(rd.info_dict);
    if (!is_all_zero(rd.info_hash) && rd.info_hash != info_hash()) return;  // not ours
    resume_have_     = rd.have;
    bytes_uploaded_  = rd.total_uploaded;
    bytes_downloaded_ = rd.total_downloaded;
}

ResumeData Torrent::generate_resume_data() const {
    ResumeData rd;
    rd.info_hash        = info_hash();
    rd.name             = info_.name();
    rd.save_path        = save_path_;
    rd.have             = picker_ ? picker_->have_bitfield() : Bitfield{};
    rd.total_uploaded   = bytes_uploaded_;
    rd.total_downloaded = bytes_downloaded_;
    if (info_.has_metadata()) rd.info_dict = info_.info_dict_bytes();
    return rd;
}

std::string Torrent::default_resume_path() const {
    return combine_paths(combine_paths(save_path_, ".resume"), info_.info_hash_hex() + ".resume");
}

bool Torrent::save_resume_data() const {
    return save_resume_data(default_resume_path());
}

bool Torrent::save_resume_data(const std::string& path) const {
    const std::string parent = get_parent_directory(path.c_str());
    if (!parent.empty() && !directory_exists(parent.c_str())) create_directories(parent.c_str());
    const Bytes data = generate_resume_data().encode();
    return create_file_binary(path.c_str(), data.data(), data.size());
}

} // namespace librats::bittorrent
