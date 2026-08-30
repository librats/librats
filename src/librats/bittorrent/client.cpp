#include "librats/bittorrent/client.h"
#include "librats/bittorrent/log.h"

#include <algorithm>
#include <chrono>
#include <mutex>
#include <utility>

namespace librats::bittorrent {

Client::Client() : Client(Config{}) {}

Client::Client(Config config)
    : config_(std::move(config))
    , utp_(reactor_)
    , peer_id_(generate_peer_id(config_.peer_id_prefix)) {}

Client::~Client() {
    stop();
}

void Client::open() {
    if (opened_) return;
    opened_ = true;
    open_listener();
    schedule_reap();
}

void Client::start() {
    open();
    reactor_.start();
}

void Client::stop() {
    if (!opened_) return;
    // Disarm the DHT callbacks BEFORE the reactor goes away: the shared DHT keeps
    // running after us (node teardown is reverse-attach order) and a get_peers reply
    // for a torrent we are about to drop would otherwise post to a destroyed reactor.
    {
        std::lock_guard<std::mutex> lock(dht_guard_->mutex);
        dht_guard_->alive = false;
    }
    reactor_.stop();  // join the loop thread first so nothing touches state concurrently
    opened_ = false;
    if (reap_timer_ != kInvalidTimerId) { reactor_.cancel(reap_timer_); reap_timer_ = kInvalidTimerId; }
    for (auto& [hash, t] : torrents_) {
        // Drop the traversal too: nothing consumes its result any more, and it would
        // keep hammering the DHT for a torrent that no longer exists.
        if (dht_) dht_->cancel_search(hash);
        t->stop();
    }
    torrents_.clear();
    connections_.clear();
    // Reclaim any outbound sockets still mid-connect (their completion lambda will
    // never run now that the reactor is stopped).
    for (const auto& [s, deadline] : pending_connects_) {
        reactor_.cancel(deadline);
        reactor_.remove(s);
        close_socket(s);
    }
    pending_connects_.clear();
    if (is_valid_socket(listener_)) { reactor_.remove(listener_); close_socket(listener_); listener_ = RATS_INVALID_SOCKET; }
    // After connections_, so every UtpPeerLink has already handed its stream back.
    utp_.close();
    // Fresh token, so a Client that is start()ed again gets DHT peers delivered.
    // Safe to swap unsynchronised: the reactor thread is joined and the old token is
    // kept alive by whatever callbacks still hold it.
    dht_guard_ = std::make_shared<DhtCallbackGuard>();
}

void Client::open_listener() {
    const bool want_utp = config_.enable_outgoing_utp || config_.enable_incoming_utp;

    // TCP and uTP must answer on the *same* port: a peer learns one number for us
    // (from the tracker, the DHT or PEX) and has to be able to reach us with it
    // over either wire. When the port is ephemeral the TCP bind picks it and the
    // UDP bind may then find that number already taken by something else, so the
    // pair is acquired as a pair and retried as one.
    constexpr int kPairAttempts = 8;
    for (int attempt = 0; attempt < kPairAttempts; ++attempt) {
        const socket_t tcp = create_tcp_server(config_.listen_port, 16, "", AddressFamily::IPv4);
        if (!is_valid_socket(tcp)) break;
        const std::uint16_t port = std::uint16_t(get_bound_port(tcp));
        // Keep this TCP socket when the pair came up, when a fixed port leaves us
        // nowhere to move, or when this was the last go — running out of attempts
        // must not cost us a listener we already hold. Only a retry that is really
        // going to happen may throw one away.
        if (!want_utp || utp_.open(port) || config_.listen_port != 0
            || attempt + 1 == kPairAttempts) {
            listener_    = tcp;
            actual_port_ = port;
            break;
        }
        close_socket(tcp);
    }

    // The matching UDP port was taken — most often by our own DHT, which by mainline
    // convention serves the torrent port. An ephemeral one is still worth having:
    // an outgoing dial is answered on the source port of its own SYN, so it does not
    // care what that number is. Only inbound uTP needs the advertised port, and it is
    // the half we give up here. Nothing is lost by trying — with outgoing uTP off
    // there is nothing left for a mux to do, so we do not open one.
    if (want_utp && !utp_.is_open() && config_.enable_outgoing_utp) {
        if (!utp_.open(0)) {
            LOG_WARN("bt.client", "no UDP port available — running without uTP");
        } else if (actual_port_ != 0) {
            LOG_WARN("bt.client", "UDP port " << actual_port_ << " is held by another socket — "
                                  "uTP on port " << utp_.port() << " instead: dialling out works, "
                                  "inbound uTP does not");
        } else {
            // No listener at all, so there is no advertised number to have missed.
            LOG_WARN("bt.client", "uTP on port " << utp_.port() << ", outgoing only");
        }
    }

    // Inbound uTP only means anything on the port peers are told about. On any other
    // number nothing would ever arrive, so say so rather than pretend to listen.
    const bool utp_inbound = utp_.is_open() && utp_.port() == actual_port_
                             && config_.enable_incoming_utp;
    if (utp_.is_open()) {
        utp_.set_accept_incoming(utp_inbound);
        utp_.set_accept_handler([this](utp::Stream& s) { on_utp_accept(s); });
    }

    if (!is_valid_socket(listener_)) {
        // Outgoing uTP may well be up, so this is not the end of the session — but
        // nobody can reach us, which is worth an error either way.
        LOG_ERROR("bt.client", "failed to bind listen port " << config_.listen_port
                               << " — inbound peers disabled");
        return;
    }
    set_socket_nonblocking(listener_);
    reactor_.add(listener_, PollIn, [this](std::uint32_t) { on_accept(); });

    LOG_INFO("bt.client", "listening on port " << actual_port_
                          << (utp_inbound              ? " (TCP + uTP)"
                              : utp_.is_open()         ? " (TCP, uTP outgoing only)"
                                                       : " (TCP)"));
}

void Client::on_accept() {
    for (;;) {
        // Raw accept so a non-blocking EWOULDBLOCK drain is quiet (accept_client
        // logs it as an error). nullptr addr: we read the peer address elsewhere.
        socket_t s = ::accept(listener_, nullptr, nullptr);
        if (!is_valid_socket(s)) break;  // drained (non-blocking listener)
        suppress_sigpipe(s);  // not inherited from the listener; raw accept()
        // Cap total connections so an inbound flood can't exhaust memory / fds (H3).
        // Keep draining the accept queue, but immediately drop anything over the cap.
        if (connections_.size() >= kMaxConnections) {
            LOG_DEBUG("bt.client", "connection cap " << kMaxConnections << " reached, dropping inbound");
            close_socket(s);
            continue;
        }
        set_socket_nonblocking(s);

        // Remote source endpoint (for logging / PEX). The peer's *listen* port is
        // learned later from its extended handshake; this is the ephemeral source.
        std::string ip;
        std::uint16_t port = 0;
        if (const std::string ep = get_peer_address(s); !ep.empty()) {
            const std::size_t colon = ep.rfind(':');
            if (colon != std::string::npos) {
                ip   = ep.substr(0, colon);
                port = std::uint16_t(std::atoi(ep.c_str() + colon + 1));
            }
        }

        adopt_inbound(std::make_unique<TcpPeerLink>(reactor_, s), std::move(ip), port);
    }
}

void Client::adopt_inbound(std::unique_ptr<PeerLink> link, std::string ip, std::uint16_t port) {
    auto resolver = [this](const InfoHash& ih, PeerConnection::Binding& out) -> bool {
        auto it = torrents_.find(ih);
        if (it == torrents_.end() || !it->second) return false;
        out.observer   = it->second.get();
        out.num_pieces = it->second->num_pieces();
        return true;
    };
    // An inbound peer may open either protocol; the connection sniffs which and
    // enforces in_enc_policy. The stream-key resolver is what lets an obfuscated
    // peer name its torrent without ever putting the info-hash on the wire.
    mse::Handshake::SkeyResolver skey =
        [this](const std::uint8_t* obfuscated, const std::uint8_t* req3, InfoHash& out) {
            return resolve_mse_skey(obfuscated, req3, out);
        };
    LOG_DEBUG("bt.client", "inbound connection from " << ip << ':' << port);
    auto pc = std::make_unique<PeerConnection>(reactor_, std::move(link), peer_id_,
                                               std::move(resolver), std::move(ip), port,
                                               config_.in_enc_policy, std::move(skey));
    PeerConnection* raw = pc.get();
    connections_.push_back(std::move(pc));
    raw->start();
}

void Client::on_utp_accept(utp::Stream& stream) {
    // The stream cap is the manager's; this is the session-wide connection cap. A
    // stream we refuse here is simply left without an observer, which is exactly
    // what tells the manager to reap it on its next pass.
    if (connections_.size() >= kMaxConnections) {
        LOG_DEBUG("bt.client", "connection cap " << kMaxConnections
                               << " reached, dropping inbound uTP");
        return;
    }
    const Address& from = stream.remote();
    adopt_inbound(std::make_unique<UtpPeerLink>(utp_, stream), from.ip.to_string(), from.port);
}

bool Client::dial_encrypted(bool prefer_encrypted) const noexcept {
    switch (config_.out_enc_policy) {
        case EncPolicy::Forced:   return true;
        case EncPolicy::Disabled: return false;
        case EncPolicy::Enabled:  break;
    }
    return prefer_encrypted;
}

bool Client::resolve_mse_skey(const std::uint8_t* obfuscated, const std::uint8_t* req3_hash,
                              InfoHash& out) const {
    // Linear over the session's torrents: the stream key is deliberately not
    // reversible, so guess-and-check is the only way, and a node holds few enough
    // torrents for one SHA-1 each to be nothing next to the DH that just ran.
    for (const auto& [ih, t] : torrents_) {
        if (mse::skey_matches(obfuscated, req3_hash, ih)) { out = ih; return true; }
    }
    return false;
}

void Client::connect_peer(Torrent& torrent, const PeerList::Endpoint& peer) {
    if (connections_.size() >= kMaxConnections) {
        torrent.on_connect_failed(peer.ip, peer.port);
        return;
    }

    DialOptions opts;
    opts.obfuscate = dial_encrypted(peer.prefer_encrypted);
    // Only an alternating policy has a second encryption form to fall back to. Under
    // Forced or Disabled there is nothing else to try there, so a refusal is a plain
    // failure and the peer should serve its usual backoff.
    const bool enc_alternates = config_.out_enc_policy == EncPolicy::Enabled;

    if (config_.enable_outgoing_utp && peer.prefer_utp && utp_.is_open()) {
        // A uTP dial that never reaches a handshake is worth retrying immediately —
        // over TCP if we have it, otherwise with the other encryption form.
        opts.retry_other_form_on_failure = enc_alternates || config_.enable_outgoing_tcp;
        if (connect_peer_utp(torrent, peer, opts)) return;
    }
    if (!config_.enable_outgoing_tcp) {
        torrent.on_connect_failed(peer.ip, peer.port);
        return;
    }
    opts.retry_other_form_on_failure = enc_alternates;
    connect_peer_tcp(torrent, peer, opts);
}

bool Client::connect_peer_utp(Torrent& torrent, const PeerList::Endpoint& peer, DialOptions opts) {
    // IpAddress::parse rather than the Address(string, port) constructor: that one
    // asserts on anything non-numeric, and while every peer source we have hands us
    // numeric addresses, a dial is not the place to discover otherwise.
    const auto ip = IpAddress::parse(peer.ip);
    if (!ip) return false;
    utp::Stream* stream = utp_.connect(Address(*ip, peer.port));
    if (stream == nullptr) return false;

    // No pending-connect bookkeeping, unlike TCP: the stream accepts the handshake
    // bytes immediately and holds them until its SYN is answered, so there is no
    // half-open state for the Client to track. The stream's own connect timeout and
    // the connection's handshake deadline both still apply.
    auto pc = std::make_unique<PeerConnection>(reactor_,
                                               std::make_unique<UtpPeerLink>(utp_, *stream),
                                               /*outgoing=*/true, torrent.info_hash(), peer_id_,
                                               torrent.num_pieces(), &torrent,
                                               peer.ip, peer.port, opts);
    LOG_DEBUG("bt.client", "dialing " << peer.ip << ':' << peer.port << " over uTP");
    PeerConnection* raw = pc.get();
    connections_.push_back(std::move(pc));
    raw->start();
    return true;
}

void Client::connect_peer_tcp(Torrent& torrent, const PeerList::Endpoint& endpoint, DialOptions enc) {
    const std::string   ip   = endpoint.ip;
    const std::uint16_t port = endpoint.port;
    socket_t s = tcp_connect_start(ip, int(port));
    if (!is_valid_socket(s)) { torrent.on_connect_failed(ip, port); return; }

    // Capture the info-hash, not a raw Torrent*: the torrent may be removed before
    // the connect completes, so we re-resolve it (and bail if it's gone) rather
    // than dereference a dangling pointer (H10). The socket is tracked so a
    // mid-connect stop() can reclaim it.
    const InfoHash ih = torrent.info_hash();

    // The connect deadline. Whichever of the two fires first takes the socket out
    // of pending_connects_; the other then finds it gone and does nothing, so the
    // fd is closed exactly once and the peer is reported to the torrent once.
    const TimerId deadline = reactor_.schedule(config_.connect_timeout, [this, s, ih, ip, port] {
        if (pending_connects_.erase(s) == 0) return;  // the connect already completed
        reactor_.remove(s);
        close_socket(s);
        LOG_DEBUG("bt.client", "connect to " << ip << ':' << port << " timed out after "
                               << config_.connect_timeout.count() << " ms");
        auto it = torrents_.find(ih);
        if (it != torrents_.end()) it->second->on_connect_failed(ip, port);
    });
    pending_connects_.emplace(s, deadline);

    reactor_.add(s, PollOut, [this, ih, s, ip, port, enc](std::uint32_t) {
        auto pending = pending_connects_.find(s);
        if (pending == pending_connects_.end()) return;  // the deadline already reclaimed it
        reactor_.cancel(pending->second);
        pending_connects_.erase(pending);
        reactor_.remove(s);  // done watching for connect completion
        auto it = torrents_.find(ih);
        Torrent* t = (it != torrents_.end()) ? it->second.get() : nullptr;
        if (tcp_connect_result(s) != 0 || !t) {
            close_socket(s);
            if (t) t->on_connect_failed(ip, port);
            return;
        }
        auto pc = std::make_unique<PeerConnection>(reactor_,
                                                   std::make_unique<TcpPeerLink>(reactor_, s),
                                                   /*outgoing=*/true, t->info_hash(), peer_id_,
                                                   t->num_pieces(), t, ip, port, enc);
        PeerConnection* raw = pc.get();
        connections_.push_back(std::move(pc));
        raw->start();
    });
}

void Client::find_peers_via_dht(const InfoHash& info_hash,
                                std::function<void(const std::string&, std::uint16_t)> on_peer) {
    if (!dht_ || !dht_->is_running()) return;
    // DhtClient delivers results on its own thread; marshal them onto the reactor.
    // Re-resolve the torrent by info-hash before invoking on_peer: the torrent may
    // have been removed between the get_peers request and its (seconds-later) reply,
    // and on_peer captures the Torrent by pointer — dereferencing it after removal is
    // a use-after-free of peer_list_ (same H10 hazard fixed in connect_peer). Removal
    // happens only on the reactor thread, so a torrent present here stays alive for
    // the whole callback.
    // The guard covers the *other* half of that hazard: the whole Client may be gone
    // by the time the reply lands, since the shared DHT is torn down after us. Held
    // for the post() only — the work itself still runs on the reactor.
    dht_->find_peers(info_hash, [this, guard = dht_guard_, info_hash, on_peer](const std::vector<Address>& peers,
                                                                              const InfoHash&) {
        std::lock_guard<std::mutex> lock(guard->mutex);
        if (!guard->alive) return;  // Client stopped/destroyed — its reactor is gone
        reactor_.post([this, info_hash, peers, on_peer] {
            if (torrents_.find(info_hash) == torrents_.end()) return;  // torrent gone
            for (const Address& a : peers) on_peer(a.ip.to_string(), a.port);
        });
    });
}

void Client::announce_to_dht(const InfoHash& info_hash, std::uint16_t port,
                             std::function<void(const std::string&, std::uint16_t)> on_peer) {
    // Publish ourselves to the info-hash's DHT nodes so other clients' get_peers
    // find us (BEP 5). DhtClient is the node's shared, thread-safe instance.
    if (!dht_ || !dht_->is_running()) return;
    if (!on_peer) { dht_->announce_peer(info_hash, port); return; }
    // An announce runs a get_peers traversal of its own, so it discovers the same
    // peers a find_peers would. Deliver them through the identical guarded marshal
    // as find_peers_via_dht (see the reasoning there) instead of discarding them.
    dht_->announce_peer(info_hash, port,
                        [this, guard = dht_guard_, info_hash, on_peer](const std::vector<Address>& peers,
                                                                      const InfoHash&) {
        std::lock_guard<std::mutex> lock(guard->mutex);
        if (!guard->alive) return;  // Client stopped/destroyed — its reactor is gone
        reactor_.post([this, info_hash, peers, on_peer] {
            if (torrents_.find(info_hash) == torrents_.end()) return;  // torrent gone
            for (const Address& a : peers) on_peer(a.ip.to_string(), a.port);
        });
    });
}

Torrent* Client::add_torrent(const TorrentInfo& info, const std::string& save_path) {
    return run_on_reactor([&] { return add_torrent_impl(info, save_path); });
}

Torrent* Client::add_torrent_impl(const TorrentInfo& info, const std::string& save_path) {
    if (!info.is_valid() || !info.has_metadata()) {
        LOG_WARN("bt.client", "rejected invalid/incomplete torrent");
        return nullptr;
    }
    const InfoHash ih = info.info_hash();
    if (torrents_.count(ih)) return torrents_[ih].get();

    const std::string path = save_path.empty() ? config_.download_path : save_path;
    auto t = std::make_unique<Torrent>(reactor_, *this, info, path);
    Torrent* raw = t.get();
    torrents_.emplace(ih, std::move(t));
    LOG_INFO("bt.client", "added torrent " << short_hash(ih) << " \"" << info.name() << "\" → " << path);
    raw->start();
    return raw;
}

Torrent* Client::add_magnet(const std::string& magnet_uri, const std::string& save_path) {
    return run_on_reactor([&] { return add_magnet_impl(magnet_uri, save_path, /*resume=*/false); });
}

Torrent* Client::add_magnet_resumed(const std::string& magnet_uri, const std::string& save_path) {
    return run_on_reactor([&] { return add_magnet_impl(magnet_uri, save_path, /*resume=*/true); });
}

Torrent* Client::add_magnet_impl(const std::string& magnet_uri, const std::string& save_path, bool resume) {
    auto info = TorrentInfo::from_magnet(magnet_uri);
    if (!info || !info->is_valid()) {
        LOG_WARN("bt.client", "rejected invalid magnet uri");
        return nullptr;
    }
    const InfoHash ih = info->info_hash();
    if (torrents_.count(ih)) return torrents_[ih].get();

    const std::string path = save_path.empty() ? config_.download_path : save_path;
    auto t = std::make_unique<Torrent>(reactor_, *this, *info, path);
    Torrent* raw = t.get();
    torrents_.emplace(ih, std::move(t));
    // Resume must be applied before start(); it completes the metadata + trusted have
    // set if a resume file exists next to the download.
    if (resume && raw->try_load_resume_data())
        LOG_INFO("bt.client", "restored resume data for " << short_hash(ih));
    LOG_INFO("bt.client", "added magnet" << (resume ? " (resumed) " : " ") << short_hash(ih) << " → " << path);
    raw->start();
    return raw;
}

Torrent* Client::add_torrent_with_resume(const TorrentInfo& info, const ResumeData& resume,
                                         const std::string& save_path) {
    return run_on_reactor([&] { return add_torrent_with_resume_impl(info, resume, save_path); });
}

Torrent* Client::add_torrent_with_resume_impl(const TorrentInfo& info, const ResumeData& resume,
                                              const std::string& save_path) {
    if (!info.is_valid()) return nullptr;
    const InfoHash ih = info.info_hash();
    if (torrents_.count(ih)) return torrents_[ih].get();

    const std::string path = save_path.empty() ? config_.download_path : save_path;
    auto t = std::make_unique<Torrent>(reactor_, *this, info, path);
    Torrent* raw = t.get();
    torrents_.emplace(ih, std::move(t));
    raw->load_resume_data(resume);  // must precede start()
    raw->start();
    return raw;
}

Torrent* Client::add_torrent_for_seeding(const TorrentInfo& info, const std::string& save_path) {
    return run_on_reactor([&]() -> Torrent* {
        if (!info.is_valid() || !info.has_metadata()) return nullptr;
        ResumeData rd;
        rd.info_hash = info.info_hash();
        rd.have      = Bitfield(info.num_pieces(), true);  // assume every piece is present
        return add_torrent_with_resume_impl(info, rd, save_path);
    });
}

void Client::save_all_resume_data() {
    run_on_reactor([&] { for (auto& [hash, t] : torrents_) t->save_resume_data(); });
}

Torrent* Client::get_torrent(const InfoHash& info_hash) {
    auto it = torrents_.find(info_hash);
    return it == torrents_.end() ? nullptr : it->second.get();
}

void Client::remove_torrent(const InfoHash& info_hash, bool /*delete_files*/) {
    run_on_reactor([&] { remove_torrent_impl(info_hash); });
}

void Client::remove_torrent_impl(const InfoHash& info_hash) {
    auto it = torrents_.find(info_hash);
    if (it == torrents_.end()) return;
    LOG_INFO("bt.client", "removed torrent " << short_hash(info_hash));
    it->second->stop();  // closes the peers the torrent has registered in its peer list
    // stop() only closes connections the torrent knows about (its peers_ list). An
    // *outgoing* connection that has completed connect() but not yet the wire
    // handshake holds obs_ = this torrent, yet is not in peers_ until on_handshake —
    // so stop() misses it. Erasing the torrent now would leave that live connection
    // with a dangling observer, and its next message (handshake reply + payload in
    // one segment) dereferences the freed Torrent → use-after-free crashing in
    // dispatch(). Close every remaining live connection bound to this info-hash
    // while the torrent is still alive (close() fires on_closed() on it).
    for (auto& pc : connections_)
        if (!pc->closed() && pc->info_hash() == info_hash) pc->close("torrent removed");
    torrents_.erase(it);
    // Stop the DHT traversal started for this torrent: its result has no consumer
    // left, and letting it run keeps a lookup alive for a hash we no longer hold.
    if (dht_) dht_->cancel_search(info_hash);
    // File deletion is not yet implemented; the torrent's data is left on disk.
}

TorrentStatus Client::torrent_status(const InfoHash& info_hash) {
    return run_on_reactor([&]() -> TorrentStatus {
        TorrentStatus s;
        auto it = torrents_.find(info_hash);
        if (it == torrents_.end() || !it->second) return s;
        const Torrent*     t    = it->second.get();
        const TorrentInfo& info = t->torrent_info();
        s.exists       = true;
        s.name         = info.name();
        s.has_metadata = t->has_metadata();
        s.is_complete  = t->is_complete();
        s.paused       = t->is_paused();
        s.progress     = t->progress();
        s.downloaded   = t->bytes_downloaded();
        s.uploaded     = t->bytes_uploaded();
        s.num_peers    = t->num_peers();
        if (info.has_metadata()) {
            s.total_size = std::uint64_t(info.total_size());
            for (const FileEntry& f : info.files().files())
                s.files.push_back({f.path, f.size});
        }
        return s;
    });
}

std::optional<TorrentInfo> Client::torrent_metadata(const InfoHash& info_hash) {
    return run_on_reactor([&]() -> std::optional<TorrentInfo> {
        auto it = torrents_.find(info_hash);
        if (it == torrents_.end() || !it->second) return std::nullopt;
        const Torrent* t = it->second.get();
        if (!t->has_metadata()) return std::nullopt;
        // Copy the info out under reactor ownership; TorrentInfo is a value type,
        // so the caller gets a standalone snapshot safe to use off-thread.
        return t->torrent_info();
    });
}

void Client::pause_torrent(const InfoHash& info_hash) {
    run_on_reactor([&] {
        auto it = torrents_.find(info_hash);
        if (it != torrents_.end() && it->second) it->second->pause();
    });
}

void Client::resume_torrent(const InfoHash& info_hash) {
    run_on_reactor([&] {
        auto it = torrents_.find(info_hash);
        if (it != torrents_.end() && it->second) it->second->resume();
    });
}

bool Client::save_resume_data(const InfoHash& info_hash) {
    return run_on_reactor([&]() -> bool {
        auto it = torrents_.find(info_hash);
        return it != torrents_.end() && it->second && it->second->save_resume_data();
    });
}

std::vector<Torrent*> Client::torrents() {
    std::vector<Torrent*> out;
    out.reserve(torrents_.size());
    for (auto& [hash, t] : torrents_) out.push_back(t.get());
    return out;
}

Torrent* Client::add_torrent_file(const std::string& path, const std::string& save_path) {
    auto info = TorrentInfo::from_file(path);  // pure parse — safe off the reactor thread
    if (!info) return nullptr;
    return run_on_reactor([&] { return add_torrent_impl(*info, save_path); });
}

std::size_t Client::total_peers() const {
    std::size_t n = 0;
    for (const auto& [hash, t] : torrents_) n += t->num_peers();
    return n;
}

void Client::schedule_reap() {
    if (!opened_) return;
    reap_timer_ = reactor_.schedule(std::chrono::seconds(1), [this] {
        reap_closed();
        sample_rates();
        schedule_reap();
    });
}

void Client::reap_closed() {
    connections_.erase(
        std::remove_if(connections_.begin(), connections_.end(),
                       [](const std::unique_ptr<PeerConnection>& pc) { return pc->closed(); }),
        connections_.end());
}

void Client::sample_rates() {
    std::uint64_t down = 0, up = 0;
    for (auto& [hash, t] : torrents_) {
        down += t->bytes_downloaded();
        up   += t->bytes_uploaded();
    }
    const auto now = std::chrono::steady_clock::now();
    if (last_sample_.time_since_epoch().count() != 0) {
        const double dt = std::chrono::duration<double>(now - last_sample_).count();
        if (dt > 0) {
            // Counters are monotonic, but guard against a torrent being removed
            // between samples (which would make the aggregate drop).
            const std::uint64_t d_down = down >= last_down_bytes_ ? down - last_down_bytes_ : 0;
            const std::uint64_t d_up   = up   >= last_up_bytes_   ? up   - last_up_bytes_   : 0;
            down_rate_.store(std::uint64_t(double(d_down) / dt), std::memory_order_relaxed);
            up_rate_.store(std::uint64_t(double(d_up) / dt), std::memory_order_relaxed);
        }
    }
    last_down_bytes_ = down;
    last_up_bytes_   = up;
    last_sample_     = now;
}

} // namespace librats::bittorrent
