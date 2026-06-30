#include "bittorrent/client.h"

#include <algorithm>
#include <chrono>
#include <utility>

namespace librats::bittorrent {

Client::Client() : Client(Config{}) {}

Client::Client(Config config)
    : config_(std::move(config))
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
    reactor_.stop();  // join the loop thread first so nothing touches state concurrently
    opened_ = false;
    if (reap_timer_ != kInvalidTimerId) { reactor_.cancel(reap_timer_); reap_timer_ = kInvalidTimerId; }
    for (auto& [hash, t] : torrents_) t->stop();
    torrents_.clear();
    connections_.clear();
    if (is_valid_socket(listener_)) { reactor_.remove(listener_); close_socket(listener_); listener_ = INVALID_SOCKET_VALUE; }
}

void Client::open_listener() {
    listener_ = create_tcp_server(config_.listen_port, 16, "", AddressFamily::IPv4);
    if (!is_valid_socket(listener_)) return;
    set_socket_nonblocking(listener_);
    actual_port_ = std::uint16_t(get_bound_port(listener_));
    reactor_.add(listener_, PollIn, [this](std::uint32_t) { on_accept(); });
}

void Client::on_accept() {
    for (;;) {
        // Raw accept so a non-blocking EWOULDBLOCK drain is quiet (accept_client
        // logs it as an error). nullptr addr: we read the peer address elsewhere.
        socket_t s = ::accept(listener_, nullptr, nullptr);
        if (!is_valid_socket(s)) break;  // drained (non-blocking listener)
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

        auto resolver = [this](const InfoHash& ih, PeerConnection::Binding& out) -> bool {
            auto it = torrents_.find(ih);
            if (it == torrents_.end() || !it->second) return false;
            out.observer   = it->second.get();
            out.num_pieces = it->second->num_pieces();
            return true;
        };
        auto pc = std::make_unique<PeerConnection>(reactor_, s, peer_id_, std::move(resolver),
                                                   std::move(ip), port);
        PeerConnection* raw = pc.get();
        connections_.push_back(std::move(pc));
        raw->start();
    }
}

void Client::connect_peer(Torrent& torrent, const std::string& ip, std::uint16_t port) {
    socket_t s = tcp_connect_start(ip, int(port));
    if (!is_valid_socket(s)) { torrent.on_connect_failed(ip, port); return; }

    Torrent* t = &torrent;
    reactor_.add(s, PollOut, [this, t, s, ip, port](std::uint32_t) {
        reactor_.remove(s);  // done watching for connect completion
        if (tcp_connect_result(s) != 0) {
            close_socket(s);
            t->on_connect_failed(ip, port);
            return;
        }
        auto pc = std::make_unique<PeerConnection>(reactor_, s, /*outgoing=*/true,
                                                   t->info_hash(), peer_id_, t->num_pieces(), t,
                                                   ip, port);
        PeerConnection* raw = pc.get();
        connections_.push_back(std::move(pc));
        raw->start();
    });
}

void Client::find_peers_via_dht(const InfoHash& info_hash,
                                std::function<void(const std::string&, std::uint16_t)> on_peer) {
    if (!dht_ || !dht_->is_running()) return;
    // DhtClient delivers results on its own thread; marshal them onto the reactor.
    dht_->find_peers(info_hash, [this, on_peer](const std::vector<Address>& peers, const InfoHash&) {
        reactor_.post([peers, on_peer] {
            for (const Address& a : peers) on_peer(a.ip, a.port);
        });
    });
}

Torrent* Client::add_torrent(const TorrentInfo& info, const std::string& save_path) {
    if (!info.is_valid() || !info.has_metadata()) return nullptr;
    const InfoHash ih = info.info_hash();
    if (torrents_.count(ih)) return torrents_[ih].get();

    const std::string path = save_path.empty() ? config_.download_path : save_path;
    auto t = std::make_unique<Torrent>(reactor_, *this, info, path);
    Torrent* raw = t.get();
    torrents_.emplace(ih, std::move(t));
    raw->start();
    return raw;
}

Torrent* Client::add_magnet(const std::string& magnet_uri, const std::string& save_path) {
    auto info = TorrentInfo::from_magnet(magnet_uri);
    if (!info || !info->is_valid()) return nullptr;
    const InfoHash ih = info->info_hash();
    if (torrents_.count(ih)) return torrents_[ih].get();

    const std::string path = save_path.empty() ? config_.download_path : save_path;
    auto t = std::make_unique<Torrent>(reactor_, *this, *info, path);
    Torrent* raw = t.get();
    torrents_.emplace(ih, std::move(t));
    raw->start();
    return raw;
}

Torrent* Client::add_torrent_with_resume(const TorrentInfo& info, const ResumeData& resume,
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
    if (!info.is_valid() || !info.has_metadata()) return nullptr;
    ResumeData rd;
    rd.info_hash = info.info_hash();
    rd.have      = Bitfield(info.num_pieces(), true);  // assume every piece is present
    return add_torrent_with_resume(info, rd, save_path);
}

void Client::save_all_resume_data() {
    for (auto& [hash, t] : torrents_) t->save_resume_data();
}

Torrent* Client::get_torrent(const InfoHash& info_hash) {
    auto it = torrents_.find(info_hash);
    return it == torrents_.end() ? nullptr : it->second.get();
}

void Client::remove_torrent(const InfoHash& info_hash, bool /*delete_files*/) {
    auto it = torrents_.find(info_hash);
    if (it == torrents_.end()) return;
    it->second->stop();
    torrents_.erase(it);
    // File deletion is not yet implemented; the torrent's data is left on disk.
}

std::vector<Torrent*> Client::torrents() {
    std::vector<Torrent*> out;
    out.reserve(torrents_.size());
    for (auto& [hash, t] : torrents_) out.push_back(t.get());
    return out;
}

void Client::schedule_reap() {
    if (!opened_) return;
    reap_timer_ = reactor_.schedule(std::chrono::seconds(1), [this] {
        reap_closed();
        schedule_reap();
    });
}

void Client::reap_closed() {
    connections_.erase(
        std::remove_if(connections_.begin(), connections_.end(),
                       [](const std::unique_ptr<PeerConnection>& pc) { return pc->closed(); }),
        connections_.end());
}

} // namespace librats::bittorrent
