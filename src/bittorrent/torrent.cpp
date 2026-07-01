#include "bittorrent/torrent.h"

#include "bittorrent/byte_io.h"
#include "util/fs.h"

#include <algorithm>
#include <chrono>

namespace librats::bittorrent {

Torrent::Torrent(Reactor& reactor, TorrentHost& host, TorrentInfo info, std::string save_path)
    : reactor_(reactor)
    , host_(host)
    , info_(std::move(info))
    , save_path_(std::move(save_path))
    , choker_(4) {}

Torrent::~Torrent() {
    stop();
}

void Torrent::start() {
    if (running_) return;
    running_ = true;
    has_metadata_ = info_.has_metadata();

    if (has_metadata_) {
        picker_ = std::make_unique<PiecePicker>(info_.num_pieces(), info_.piece_length(), info_.total_size());
        disk_   = std::make_unique<ThreadedDiskIo>(
            info_, save_path_,
            [this](std::function<void()> fn) { reactor_.post(std::move(fn)); });
        state_ = State::Checking;
        // Pieces in resume_have_ are trusted (skip the hash); the rest are verified.
        disk_->async_check_files(resume_have_, nullptr,
                                 [this](Bitfield have) { on_check_complete(std::move(have)); });
    } else {
        // Magnet: no metadata yet — fetch the info dict from peers (BEP 9) first.
        state_ = State::Metadata;
    }

    // Trackers come from the .torrent or the magnet link; announce to find peers
    // (which also seeds the metadata fetch for magnets).
    if (!info_.all_trackers().empty()) {
        trackers_ = std::make_unique<TrackerAnnouncer>(
            info_.all_trackers(), [this](std::function<void()> fn) { reactor_.post(std::move(fn)); });
        announce_trackers(TrackerEvent::Started);
    }

    schedule_tick();
    try_connect();
}

void Torrent::stop() {
    if (!running_) return;
    running_ = false;
    if (tick_timer_ != kInvalidTimerId) { reactor_.cancel(tick_timer_); tick_timer_ = kInvalidTimerId; }
    if (trackers_) { trackers_->stop(); trackers_.reset(); }
    for (PeerConnection* pc : peers_) pc->close("torrent stopped");
    peers_.clear();
    outstanding_.clear();
    recent_down_.clear();
    if (disk_) disk_->stop();
    disk_.reset();
    picker_.reset();
    state_ = State::Stopped;
}

void Torrent::on_check_complete(Bitfield have) {
    if (!running_) return;
    picker_->set_have_bitfield(have);
    for (std::uint32_t p = 0; p < info_.num_pieces(); ++p)
        if (picker_->have_piece(p)) bytes_downloaded_ += info_.piece_size(p);

    if (picker_->is_finished()) { state_ = State::Seeding; completed_announced_ = true; }
    else                        { state_ = State::Downloading; }

    try_connect();
}

void Torrent::add_peer(const std::string& ip, std::uint16_t port) {
    if (peer_list_.add(ip, port, PeerSource::Tracker) && running_)
        reactor_.post([this] { try_connect(); });
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

    // Ask the DHT for fresh peers periodically (every ~30 s).
    if (tick_count_ % 30 == 1) {
        host_.find_peers_via_dht(info_hash(), [this](const std::string& ip, std::uint16_t port) {
            if (peer_list_.add(ip, port, PeerSource::Dht)) try_connect();
        });
    }
    // Re-announce to trackers on a coarse cadence (the precise interval handling
    // can refine this later; ~5 min keeps the swarm fresh without being chatty).
    if (tick_count_ % 300 == 1) announce_trackers(TrackerEvent::None);

    try_connect();
    send_pex();
    recompute_choker();
    for (auto& [pc, score] : recent_down_) score = 0;  // reset the tit-for-tat window
    schedule_tick();
}

// ---- peer event handling ----

void Torrent::on_handshake(PeerConnection& pc, const InfoHash&, const PeerId&) {
    peers_.push_back(&pc);
    outstanding_[&pc] = 0;
    recent_down_[&pc] = 0;
    peer_list_.set_connected(pc.remote_ip(), pc.remote_port(), true);

    if (pc.peer_supports_extensions()) send_extended_handshake(pc);
    // Only announce a bitfield once we know the piece count (i.e. have metadata).
    if (has_metadata_ && picker_) pc.send_bitfield(picker_->have_bitfield());
}

void Torrent::on_bitfield(PeerConnection& pc, const Bitfield& bf) {
    if (!picker_) return;
    picker_->inc_availability(bf);
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
    int budget = kPipelineDepth - outstanding_[&pc];
    if (budget <= 0) return;

    auto blocks = picker_->pick_blocks(pc.peer_bitfield(), budget, &pc);
    for (const PieceBlock& b : blocks) {
        picker_->mark_requested(b, &pc);
        pc.send_request(b.piece, b.block * kBlockSize, picker_->block_size(b.piece, b.block));
        ++outstanding_[&pc];
    }
}

void Torrent::on_piece(PeerConnection& pc, std::uint32_t piece, std::uint32_t offset, ByteView data) {
    if (!picker_ || piece >= info_.num_pieces()) return;

    // Reject a malformed or unsolicited block before it can index the picker's
    // block vector out of bounds: the offset must be block-aligned and inside the
    // piece, and the payload must be exactly that block's size. A hostile peer
    // could otherwise drive an out-of-bounds access via mark_writing()/mark_finished().
    const std::uint32_t piece_bytes = info_.piece_size(piece);
    if (offset % kBlockSize != 0 || offset >= piece_bytes) return;
    if (data.size() != picker_->block_size(piece, offset / kBlockSize)) return;

    if (outstanding_[&pc] > 0) --outstanding_[&pc];

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

void Torrent::on_block_written(PieceBlock block, bool ok) {
    if (!running_ || !picker_) return;
    if (!ok) { picker_->restore_piece(block.piece); return; }
    if (picker_->mark_finished(block)) verify_piece(block.piece);
}

void Torrent::verify_piece(std::uint32_t piece) {
    disk_->async_hash(piece, [this, piece](bool ok, std::array<std::uint8_t, 20> hash) {
        on_piece_hashed(piece, ok, hash);
    });
}

void Torrent::on_piece_hashed(std::uint32_t piece, bool ok, std::array<std::uint8_t, 20> hash) {
    if (!running_ || !picker_) return;
    if (!ok || hash != info_.piece_hash(piece)) {
        picker_->restore_piece(piece);  // corrupt — fetch it again
        return;
    }

    picker_->we_have(piece);
    for (PeerConnection* pc : peers_) {
        pc->send_have(piece);
        update_interest(*pc);  // we may no longer need some peers
    }

    if (picker_->is_finished() && !completed_announced_) {
        completed_announced_ = true;
        state_ = State::Seeding;
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
            bytes_uploaded_ += data.size();
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
    std::vector<Choker::Candidate> candidates;
    for (PeerConnection* pc : peers_)
        if (pc->peer_interested())
            candidates.push_back(Choker::Candidate{pc, recent_down_[pc]});

    auto unchoke = choker_.select(std::move(candidates));
    for (PeerConnection* pc : peers_) {
        const bool should_unchoke =
            std::find(unchoke.begin(), unchoke.end(), pc) != unchoke.end();
        if (should_unchoke && pc->am_choking())       pc->send_unchoke();
        else if (!should_unchoke && !pc->am_choking()) pc->send_choke();
    }
}

// ---- helpers ----

bool Torrent::alive(PeerConnection* pc) const {
    return std::find(peers_.begin(), peers_.end(), pc) != peers_.end();
}

void Torrent::remove_peer(PeerConnection* pc) {
    auto it = std::find(peers_.begin(), peers_.end(), pc);
    if (it == peers_.end()) return;
    if (picker_) {
        picker_->dec_availability(pc->peer_bitfield());
        picker_->cancel_peer(pc);
    }
    peers_.erase(it);
    outstanding_.erase(pc);
    recent_down_.erase(pc);
    peer_ext_.erase(pc);
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
                const std::uint32_t len = std::min(kMetadataPieceSize, total - off);
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
    const std::uint32_t expect = std::min(kMetadataPieceSize, metadata_size_ - off);
    if (block.size() != expect) return;  // malformed slice — ignore

    std::copy(block.begin(), block.end(), metadata_buf_.begin() + std::ptrdiff_t(off));
    metadata_have_[piece] = true;
    if (++metadata_received_ == metadata_pieces_) try_complete_metadata();
}

void Torrent::try_complete_metadata() {
    if (info_.set_metadata(metadata_buf_)) {       // verifies SHA-1 == info-hash
        has_metadata_ = true;
        if (on_metadata_) on_metadata_(info_);
        promote_to_downloading();
    } else {
        // Verification failed — discard and re-request from every peer.
        std::fill(metadata_have_.begin(), metadata_have_.end(), false);
        metadata_received_ = 0;
        for (PeerConnection* pc : peers_) request_metadata(*pc);
    }
}

void Torrent::promote_to_downloading() {
    picker_ = std::make_unique<PiecePicker>(info_.num_pieces(), info_.piece_length(), info_.total_size());
    disk_   = std::make_unique<ThreadedDiskIo>(
        info_, save_path_, [this](std::function<void()> fn) { reactor_.post(std::move(fn)); });
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

        // Advertise the dialable address of every *other* peer we haven't already
        // told this one about (a simple running diff — never re-send a peer).
        auto& sent = pex_sent_[pc];
        std::vector<ext::PexPeer> added;
        for (PeerConnection* other : peers_) {
            if (other == pc) continue;
            auto ep = dialable(*other);
            if (!ep) continue;
            const std::string key = ep->ip + ":" + std::to_string(ep->port);
            if (sent.insert(key).second) added.push_back(*ep);
        }
        if (!added.empty())
            pc->send_extended(ext_it->second.ut_pex_id, ByteView(ext::encode_pex(added, {})));
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
    r.left = (has_metadata_ && info_.total_size() > std::int64_t(bytes_downloaded_))
                 ? std::uint64_t(info_.total_size()) - bytes_downloaded_
                 : 0;
    r.event   = event;
    r.numwant = 50;
    return r;
}

void Torrent::announce_trackers(TrackerEvent event) {
    if (!trackers_) return;
    trackers_->announce(make_tracker_request(event), [this](const std::vector<Address>& peers) {
        bool any = false;
        for (const Address& a : peers)
            if (peer_list_.add(a.ip, a.port, PeerSource::Tracker)) any = true;
        if (any) try_connect();
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
