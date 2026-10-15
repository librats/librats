#include "HybridRatsNode.hpp"

#include <librats/core/address.h>
#include <librats/core/bytes.h>
#include <librats/core/types.h>
#include <librats/node/config.h>
#include <librats/node/nat_status.h>
#include <librats/node/node.h>
#include <librats/peer/peer.h>
#include <librats/peer/peer_id.h>
#include <librats/peer/peer_info.h>
#include <librats/subsystems/dht_discovery.h>
#include <librats/subsystems/file_transfer.h>
#include <librats/subsystems/hole_punch.h>
#include <librats/subsystems/mdns_discovery.h>
#include <librats/subsystems/message_json.h>
#include <librats/subsystems/peer_exchange.h>
#include <librats/subsystems/ping_service.h>
#include <librats/subsystems/port_mapping_service.h>
#include <librats/subsystems/pubsub.h>
#include <librats/subsystems/reconnection.h>
#include <librats/subsystems/relay.h>
#include <librats/util/json.h>
#include <librats/util/network_utils.h>

#include <limits>
#include <stdexcept>
#include <utility>

namespace margelo::nitro::librats {

namespace rats = ::librats;

namespace {

// ── conversions ─────────────────────────────────────────────────────────────

/// JS has one number type, so every count, size and port arrives as a double.
/// A fraction, a negative or an out-of-range value is a programming error on the
/// JS side, better as an exception than as a silent truncation.
uint64_t to_uint(double value, const char* what, uint64_t max) {
  if (!(value >= 0) || value > static_cast<double>(max) ||
      value != static_cast<double>(static_cast<uint64_t>(value))) {
    throw std::invalid_argument(std::string(what) + " must be an integer in 0.." +
                                std::to_string(max));
  }
  return static_cast<uint64_t>(value);
}

uint16_t to_port(double value, const char* what) {
  return static_cast<uint16_t>(to_uint(value, what, 65535));
}

uint32_t to_u32(double value, const char* what) {
  return static_cast<uint32_t>(to_uint(value, what, std::numeric_limits<uint32_t>::max()));
}

size_t to_size(double value, const char* what) {
  // 2^53 is where a double stops representing every integer.
  return static_cast<size_t>(to_uint(value, what, uint64_t{1} << 53));
}

rats::PeerId parse_peer_id(const std::string& hex) {
  auto id = rats::PeerId::from_hex(hex);
  if (!id) throw std::invalid_argument("not a valid peer id: " + hex);
  return *id;
}

rats::ByteView view_of(const std::shared_ptr<ArrayBuffer>& data) {
  if (data == nullptr) throw std::invalid_argument("data must not be null");
  return rats::ByteView(data->data(), data->size());
}

/// Transfer ids come from an incrementing counter starting at 1, so every real id
/// is far inside the 2^53 a double represents exactly -- which is why the JS API
/// uses `number` rather than the bigint a uint64 would otherwise demand.
double id_to_double(uint64_t id) { return static_cast<double>(id); }

uint64_t id_from_double(double id) { return to_uint(id, "transferId", uint64_t{1} << 53); }

rats::SendOptions send_options(std::optional<double> lifetime_ms, size_t size) {
  rats::SendOptions options;
  if (lifetime_ms.has_value()) {
    options.lifetime = std::chrono::milliseconds(to_u32(*lifetime_ms, "lifetimeMs"));
  }
  if (options.live() && size > rats::SendOptions::kMaxLivePayload) {
    throw std::invalid_argument("a live message carries at most 4 MiB");
  }
  return options;
}

std::vector<Transport> to_transports(uint8_t mask) {
  std::vector<Transport> out;
  if (mask & rats::PeerTransportUdp) out.push_back(Transport::UDP);
  if (mask & rats::PeerTransportTcp) out.push_back(Transport::TCP);
  return out;
}

rats::TransportKind to_kind(Transport t) {
  return t == Transport::TCP ? rats::TransportKind::Tcp : rats::TransportKind::Udp;
}

PeerTransport to_peer_transport(rats::TransportKind kind) {
  switch (kind) {
    case rats::TransportKind::Udp:   return PeerTransport::UDP;
    case rats::TransportKind::Tcp:   return PeerTransport::TCP;
    case rats::TransportKind::Relay: return PeerTransport::RELAY;
  }
  return PeerTransport::TCP;
}

CloseReason to_reason(rats::CloseReason r) {
  using R = rats::CloseReason;
  switch (r) {
    case R::LocalClose:      return CloseReason::LOCAL;
    case R::PeerClosed:      return CloseReason::PEER_CLOSED;
    case R::PeerReset:       return CloseReason::PEER_RESET;
    case R::ConnectFailed:   return CloseReason::CONNECT_FAILED;
    case R::HandshakeFailed: return CloseReason::HANDSHAKE_FAILED;
    case R::ProtocolError:   return CloseReason::PROTOCOL_ERROR;
    case R::SlowConsumer:    return CloseReason::SLOW_CONSUMER;
    case R::ReactorShutdown: return CloseReason::SHUTDOWN;
    case R::DuplicateConn:   return CloseReason::DUPLICATE_CONNECTION;
    case R::PeerLimit:       return CloseReason::PEER_LIMIT;
    case R::IdleTimeout:     return CloseReason::IDLE_TIMEOUT;
    case R::DialSuperseded:  return CloseReason::DIAL_SUPERSEDED;
  }
  return CloseReason::PEER_RESET;
}

PathStats to_path_stats(const rats::PathStats& s) {
  return PathStats(static_cast<double>(s.bandwidth_bps), s.app_limited,
                   static_cast<double>(s.pacing_bps), static_cast<double>(s.srtt_us),
                   static_cast<double>(s.min_rtt_us), static_cast<double>(s.queued_bytes),
                   static_cast<double>(s.bytes_in_flight), s.loss,
                   static_cast<double>(s.bytes_delivered), static_cast<double>(s.bytes_lost),
                   static_cast<double>(s.live_sent), static_cast<double>(s.live_expired),
                   static_cast<double>(s.live_repair_bytes));
}

PeerInfo to_peer_info(const rats::PeerInfo& info) {
  std::vector<std::string> addresses;
  addresses.reserve(info.addresses.size());
  for (const auto& a : info.addresses) addresses.push_back(a.to_string());
  return PeerInfo(to_peer_transport(info.transport), to_transports(info.supported_transports),
                  info.direction == rats::ConnRole::Inbound ? PeerDirection::INBOUND
                                                            : PeerDirection::OUTBOUND,
                  std::move(addresses));
}

TransferDirection to_direction(rats::FileTransfer::Direction d) {
  return d == rats::FileTransfer::Direction::Sending ? TransferDirection::SENDING
                                                     : TransferDirection::RECEIVING;
}

TransferStatus to_status(rats::FileTransfer::Status s) {
  using S = rats::FileTransfer::Status;
  switch (s) {
    case S::Pending:   return TransferStatus::PENDING;
    case S::Active:    return TransferStatus::ACTIVE;
    case S::Paused:    return TransferStatus::PAUSED;
    case S::Completed: return TransferStatus::COMPLETED;
    case S::Failed:    return TransferStatus::FAILED;
    case S::Cancelled: return TransferStatus::CANCELLED;
  }
  return TransferStatus::FAILED;
}

FileOffer to_offer(const rats::FileTransfer::Offer& o) {
  std::vector<FileEntry> files;
  files.reserve(o.files.size());
  for (const auto& f : o.files) {
    files.emplace_back(f.relative_path, static_cast<double>(f.size));
  }
  return FileOffer(o.from.to_hex(), id_to_double(o.id), o.name,
                   static_cast<double>(o.size), o.is_directory, std::move(files));
}

FileProgress to_progress(const rats::FileTransfer::Progress& p) {
  return FileProgress(id_to_double(p.id), p.peer.to_hex(), to_direction(p.direction),
                      to_status(p.status), static_cast<double>(p.bytes_transferred),
                      static_cast<double>(p.total_bytes),
                      static_cast<double>(p.files_completed),
                      static_cast<double>(p.total_files), p.percent(),
                      p.transfer_rate_bps, p.average_rate_bps,
                      static_cast<double>(p.elapsed.count()),
                      static_cast<double>(p.estimated_time_remaining.count()));
}

std::vector<std::string> to_hex(const std::vector<rats::PeerId>& ids) {
  std::vector<std::string> out;
  out.reserve(ids.size());
  for (const auto& id : ids) out.push_back(id.to_hex());
  return out;
}

/// A literal is used as is; a hostname is resolved here (IPv4 first, then IPv6),
/// so the reconnection subsystem only ever holds resolved endpoints.
rats::Address resolve(const std::string& host, double port) {
  const uint16_t p = to_port(port, "port");
  if (auto ip = rats::IpAddress::parse(host)) return rats::Address{*ip, p};
  std::string resolved = rats::network_utils::resolve_hostname(host);
  if (resolved.empty()) resolved = rats::network_utils::resolve_hostname_v6(host);
  if (auto ip = rats::IpAddress::parse(resolved)) return rats::Address{*ip, p};
  throw std::invalid_argument("cannot resolve host: " + host);
}

rats::Json parse_json(const std::string& text) {
  auto value = rats::Json::parse(text, nullptr, /*allow_exceptions=*/false);
  if (value.is_discarded()) throw std::invalid_argument("not valid JSON");
  return value;
}

} // namespace

// ── lifecycle ───────────────────────────────────────────────────────────────

HybridRatsNode::HybridRatsNode() : HybridObject(TAG) {}

// Out-of-line so unique_ptr can destroy the forward-declared types. Stopping the
// node here joins its reactor threads, which is what guarantees no listener is
// still running by the time this object is gone.
HybridRatsNode::~HybridRatsNode() {
  if (node_ != nullptr) node_->stop();
}

rats::Node& HybridRatsNode::node() {
  if (node_ == nullptr) {
    node_ = std::make_unique<rats::Node>(config_ != nullptr ? *config_
                                                            : rats::NodeConfig{});
  }
  return *node_;
}

void HybridRatsNode::require_not_started(const char* what) const {
  if (started_) {
    throw std::runtime_error(
        std::string(what) +
        " must be called before start(): librats keeps listeners and subsystems in "
        "tables its reactor threads read without a lock");
  }
}

template <class T, class Make>
void HybridRatsNode::enable(T*& slot, const char* what, Make make) {
  require_not_started(what);
  if (slot != nullptr) throw std::runtime_error(std::string(what) + ": already enabled");
  slot = node().add_subsystem(make());
}

template <class T>
T& HybridRatsNode::require(T* slot, const char* enable_call) const {
  if (slot == nullptr) {
    throw std::runtime_error(std::string("not enabled - call ") + enable_call +
                             " before start()");
  }
  return *slot;
}

void HybridRatsNode::configure(const RatsConfig& config) {
  require_not_started("configure()");
  if (node_ != nullptr) {
    // Something built the Node first, by registering a listener or enabling a
    // subsystem, and librats fixes configuration at construction. Rebuilding it
    // here would silently drop whatever was already attached, so refuse instead.
    throw std::runtime_error(
        "configure() must be called first, before enabling subsystems or "
        "registering listeners");
  }

  auto cfg = std::make_unique<rats::NodeConfig>();
  if (config.listenPort) cfg->listen_port = to_port(*config.listenPort, "listenPort");
  if (config.bindAddress) cfg->bind_address = *config.bindAddress;
  if (config.dialOnly) cfg->enable_listen = !*config.dialOnly;
  if (config.protocol && !config.protocol->empty()) cfg->protocol = *config.protocol;
  if (config.dataDir) cfg->data_dir = *config.dataDir;
  if (config.security) {
    cfg->security = *config.security == Security::PLAINTEXT
                        ? rats::NodeConfig::Security::Plaintext
                        : rats::NodeConfig::Security::Noise;
  }
  if (config.maxPeers) cfg->max_peers = to_size(*config.maxPeers, "maxPeers");

  if (config.transports) {
    if (config.transports->empty()) {
      throw std::invalid_argument("transports must name at least one transport");
    }
    cfg->enable_udp = cfg->enable_tcp = false;
    for (Transport t : *config.transports) {
      (t == Transport::TCP ? cfg->enable_tcp : cfg->enable_udp) = true;
    }
  }
  const auto enabled = [&](rats::TransportKind k) {
    return k == rats::TransportKind::Tcp ? cfg->enable_tcp : cfg->enable_udp;
  };
  if (config.preferredTransport) {
    cfg->preferred_transport = to_kind(*config.preferredTransport);
    if (!enabled(cfg->preferred_transport)) {
      throw std::invalid_argument("preferredTransport is not among transports");
    }
  } else if (!enabled(cfg->preferred_transport)) {
    // The default preference (UDP) follows the transports when UDP is off.
    cfg->preferred_transport = rats::TransportKind::Tcp;
  }
  if (config.transportFallbackMs) {
    cfg->transport_fallback_ms = to_u32(*config.transportFallbackMs, "transportFallbackMs");
  }

  if (config.sendQueueLimit) cfg->send_queue_limit = to_size(*config.sendQueueLimit, "sendQueueLimit");
  if (config.pathSampleMs) cfg->path_sample_ms = to_u32(*config.pathSampleMs, "pathSampleMs");

  if (config.congestionControl) {
    cfg->congestion_control = *config.congestionControl == CongestionControl::RENO
                                  ? rats::CongestionAlgorithm::Reno
                                  : rats::CongestionAlgorithm::Bbr;
  }
  if (config.udpReceiveWindow) {
    cfg->udp_receive_window = to_size(*config.udpReceiveWindow, "udpReceiveWindow");
  }
  if (config.udpReceiveBudget) {
    cfg->udp_receive_budget = to_size(*config.udpReceiveBudget, "udpReceiveBudget");
  }
  if (config.udpOffload) cfg->udp_offload = *config.udpOffload;

  if (config.reactorThreads) {
    cfg->reactor_threads = to_size(*config.reactorThreads, "reactorThreads");
    if (cfg->reactor_threads == 0) throw std::invalid_argument("reactorThreads must be at least 1");
  }
  if (config.networkMonitor) cfg->enable_network_monitor = *config.networkMonitor;

  config_ = std::move(cfg);
}

bool HybridRatsNode::start() {
  if (started_) return true;
  started_ = node().start();
  return started_;
}

void HybridRatsNode::stop() {
  if (node_ != nullptr) node_->stop();
  started_ = false;
}

bool HybridRatsNode::getIsRunning() { return started_; }

// ── this node ───────────────────────────────────────────────────────────────

double HybridRatsNode::getListenPort() {
  return node_ != nullptr ? static_cast<double>(node_->listen_port()) : 0.0;
}

std::string HybridRatsNode::getLocalId() { return node().local_id().to_hex(); }

std::string HybridRatsNode::getProtocol() { return node().protocol(); }

std::vector<Transport> HybridRatsNode::getTransports() {
  return node_ != nullptr ? to_transports(node_->transports()) : std::vector<Transport>{};
}

NatMapping HybridRatsNode::getNatMapping() {
  if (node_ == nullptr) return NatMapping::UNKNOWN;
  switch (node_->nat_status().udp_mapping()) {
    case rats::NatMapping::Open:                return NatMapping::OPEN;
    case rats::NatMapping::EndpointIndependent: return NatMapping::ENDPOINT_INDEPENDENT;
    case rats::NatMapping::EndpointDependent:   return NatMapping::ENDPOINT_DEPENDENT;
    case rats::NatMapping::Unknown:             break;
  }
  return NatMapping::UNKNOWN;
}

std::vector<std::string> HybridRatsNode::observedAddresses() {
  std::vector<std::string> out;
  if (node_ == nullptr) return out;
  for (const auto& a : node_->observed_addresses()) out.push_back(a.to_string());
  return out;
}

// ── peers ───────────────────────────────────────────────────────────────────

void HybridRatsNode::connect(const std::string& host, double port) {
  node().connect(host, to_port(port, "port"));
}

bool HybridRatsNode::disconnect(const std::string& peerId) {
  const auto id = parse_peer_id(peerId);
  if (node_ == nullptr) return false;
  auto peer = node_->peer(id);
  if (!peer) return false;
  peer->disconnect();
  return true;
}

double HybridRatsNode::getPeerCount() {
  return node_ != nullptr ? static_cast<double>(node_->peer_count()) : 0.0;
}

std::vector<std::string> HybridRatsNode::peerIds() {
  return node_ != nullptr ? to_hex(node_->connected_peers()) : std::vector<std::string>{};
}

std::optional<PeerInfo> HybridRatsNode::peerInfo(const std::string& peerId) {
  const auto id = parse_peer_id(peerId);
  if (node_ == nullptr) return std::nullopt;
  for (const auto& info : node_->peers()) {
    if (info.id == id) return to_peer_info(info);
  }
  return std::nullopt;
}

double HybridRatsNode::getMaxPeers() { return static_cast<double>(node().max_peers()); }

void HybridRatsNode::setMaxPeers(double maxPeers) {
  node().set_max_peers(to_size(maxPeers, "maxPeers"));
}

// ── messaging ───────────────────────────────────────────────────────────────

bool HybridRatsNode::send(const std::string& peerId, const std::string& channel,
                          const std::shared_ptr<ArrayBuffer>& data,
                          std::optional<double> lifetimeMs) {
  // Safe to hand a JS-owned (non-owning) buffer straight through: Node::send
  // copies the payload before it returns, so nothing retains this pointer.
  const auto payload = view_of(data);
  return node().send(parse_peer_id(peerId), channel, payload,
                     send_options(lifetimeMs, payload.size()));
}

bool HybridRatsNode::broadcast(const std::string& channel,
                               const std::shared_ptr<ArrayBuffer>& data,
                               std::optional<double> lifetimeMs) {
  const auto payload = view_of(data);
  return node().broadcast(channel, payload, send_options(lifetimeMs, payload.size()));
}

bool HybridRatsNode::peerWritable(const std::string& peerId) {
  const auto id = parse_peer_id(peerId);
  return node_ != nullptr && node_->peer_writable(id);
}

std::optional<PathStats> HybridRatsNode::pathStats(const std::string& peerId) {
  const auto id = parse_peer_id(peerId);
  if (node_ == nullptr) return std::nullopt;
  const auto stats = node_->path_stats(id);
  if (!stats) return std::nullopt;
  return to_path_stats(*stats);
}

void HybridRatsNode::onMessage(
    const std::string& channel,
    const std::function<void(const std::string&,
                             const std::shared_ptr<ArrayBuffer>&)>& listener) {
  require_not_started("onMessage()");
  node().on(channel, [listener](const rats::Peer& peer, rats::ByteView payload) {
    // The payload is a view into the connection's receive buffer, which is
    // recycled as soon as this handler returns — so it must be copied, not
    // wrapped, to give JS a buffer that outlives the event.
    listener(peer.id().to_hex(), ArrayBuffer::copy(payload.data(), payload.size()));
  });
}

// ── peer events ─────────────────────────────────────────────────────────────

void HybridRatsNode::onPeerConnected(
    const std::function<void(const std::string&)>& listener) {
  require_not_started("onPeerConnected()");
  node().on_peer_connected(
      [listener](const rats::Peer& peer) { listener(peer.id().to_hex()); });
}

void HybridRatsNode::onPeerDisconnected(
    const std::function<void(const std::string&, CloseReason)>& listener) {
  require_not_started("onPeerDisconnected()");
  // Disconnect reports the id rather than a Peer handle: by the time it fires
  // there is no connection left to reach.
  node().on_peer_disconnected([listener](const rats::PeerId& id, rats::CloseReason reason) {
    listener(id.to_hex(), to_reason(reason));
  });
}

void HybridRatsNode::onDialFailed(const std::function<void(const std::string&)>& listener) {
  require_not_started("onDialFailed()");
  node().on_dial_failed(
      [listener](const rats::Address& address) { listener(address.to_string()); });
}

void HybridRatsNode::onPeerWritable(
    const std::function<void(const std::string&)>& listener) {
  require_not_started("onPeerWritable()");
  node().on_peer_writable(
      [listener](const rats::Peer& peer) { listener(peer.id().to_hex()); });
}

void HybridRatsNode::onPeerPath(
    const std::function<void(const std::string&, const PathStats&)>& listener) {
  require_not_started("onPeerPath()");
  node().on_peer_path([listener](const rats::Peer& peer, const rats::PathStats& stats) {
    listener(peer.id().to_hex(), to_path_stats(stats));
  });
}

// ── discovery ───────────────────────────────────────────────────────────────

void HybridRatsNode::enableDht(const std::optional<DhtConfig>& config) {
  enable(dht_, "enableDht()", [&] {
    rats::DhtDiscovery::Config cfg;
    // Keep the routing table beside the identity, as the C API does.
    if (config_ != nullptr) cfg.data_dir = config_->data_dir;
    if (config && config->port) cfg.dht_port = to_port(*config->port, "port");
    if (config && config->discoveryKey) cfg.discovery_key = *config->discoveryKey;
    return std::make_unique<rats::DhtDiscovery>(std::move(cfg));
  });
}

void HybridRatsNode::enableMdns() {
  enable(mdns_, "enableMdns()", [] { return std::make_unique<rats::MdnsDiscovery>(); });
}

void HybridRatsNode::enablePeerExchange() {
  enable(pex_, "enablePeerExchange()", [] {
    return std::make_unique<rats::PeerExchange>(rats::PeerExchange::Config{});
  });
}

// ── NAT traversal ───────────────────────────────────────────────────────────

void HybridRatsNode::enablePortMapping(const std::optional<PortMappingConfig>& config) {
  enable(portmap_, "enablePortMapping()", [&] {
    rats::PortMappingConfig cfg;
    if (config && config->upnp) cfg.enable_upnp = *config->upnp;
    if (config && config->natpmp) cfg.enable_natpmp = *config->natpmp;
    return std::make_unique<rats::PortMappingService>(cfg);
  });
}

void HybridRatsNode::enableHolePunch(std::optional<bool> serveRendezvous) {
  enable(punch_, "enableHolePunch()", [&] {
    rats::HolePunch::Config cfg;
    cfg.enable_relay = serveRendezvous.value_or(true);
    return std::make_unique<rats::HolePunch>(cfg);
  });
}

bool HybridRatsNode::punchPeer(const std::string& peerId) {
  const auto id = parse_peer_id(peerId);
  return require(punch_, "enableHolePunch()").punch(id);
}

void HybridRatsNode::enableRelay(std::optional<bool> serve) {
  enable(relay_, "enableRelay()", [&] {
    rats::Relay::Config cfg;
    cfg.serve = serve.value_or(false);
    return std::make_unique<rats::Relay>(cfg);
  });
}

bool HybridRatsNode::connectViaRelay(const std::string& peerId) {
  const auto id = parse_peer_id(peerId);
  return require(relay_, "enableRelay()").connect_via_relay(id);
}

// ── JSON messaging ──────────────────────────────────────────────────────────

void HybridRatsNode::enableJson() {
  enable(json_, "enableJson()", [] { return std::make_unique<rats::MessageJson>(); });
}

void HybridRatsNode::onJson(
    const std::string& type,
    const std::function<void(const std::string&, const std::string&)>& listener) {
  require(json_, "enableJson()").on(type, [listener](const rats::PeerId& from, const rats::Json& data) {
    listener(from.to_hex(), data.dump());
  });
}

void HybridRatsNode::onceJson(
    const std::string& type,
    const std::function<void(const std::string&, const std::string&)>& listener) {
  require(json_, "enableJson()").once(type, [listener](const rats::PeerId& from, const rats::Json& data) {
    listener(from.to_hex(), data.dump());
  });
}

void HybridRatsNode::offJson(const std::string& type) {
  require(json_, "enableJson()").off(type);
}

bool HybridRatsNode::sendJson(const std::string& peerId, const std::string& type,
                              const std::string& json) {
  auto& messages = require(json_, "enableJson()");
  const auto id = parse_peer_id(peerId);
  const auto value = parse_json(json);
  if (!node().peer(id)) return false;
  messages.send(id, type, value);
  return true;
}

void HybridRatsNode::broadcastJson(const std::string& type, const std::string& json) {
  require(json_, "enableJson()").send(type, parse_json(json));
}

// ── file transfer ───────────────────────────────────────────────────────────

void HybridRatsNode::enableFileTransfer(const FileTransferConfig& config) {
  if (config.tempDirectory.empty()) {
    // The library would fall back to ".", the process working directory, which is
    // not writable on iOS or Android -- so every transfer would fail at the first
    // temp-file write rather than here, where the cause is obvious.
    throw std::invalid_argument("tempDirectory must not be empty");
  }
  enable(files_, "enableFileTransfer()", [&] {
    rats::FileTransfer::Config cfg;
    cfg.temp_directory = config.tempDirectory;
    if (config.chunkSize) cfg.chunk_size = to_u32(*config.chunkSize, "chunkSize");
    if (config.windowBytes) cfg.window_bytes = to_u32(*config.windowBytes, "windowBytes");
    if (config.transferTimeoutSecs) {
      cfg.transfer_timeout_secs = to_u32(*config.transferTimeoutSecs, "transferTimeoutSecs");
    }
    if (config.verifyIntegrity) cfg.verify_integrity = *config.verifyIntegrity;
    return std::make_unique<rats::FileTransfer>(std::move(cfg));
  });
}

double HybridRatsNode::sendFile(const std::string& peerId, const std::string& path) {
  auto& files = require(files_, "enableFileTransfer()");
  return id_to_double(files.send_file(parse_peer_id(peerId), path));
}

double HybridRatsNode::sendDirectory(const std::string& peerId, const std::string& path) {
  auto& files = require(files_, "enableFileTransfer()");
  return id_to_double(files.send_directory(parse_peer_id(peerId), path));
}

void HybridRatsNode::acceptFile(const std::string& peerId, double transferId,
                                const std::string& destPath) {
  auto& files = require(files_, "enableFileTransfer()");
  files.accept(parse_peer_id(peerId), id_from_double(transferId), destPath);
}

void HybridRatsNode::rejectFile(const std::string& peerId, double transferId) {
  auto& files = require(files_, "enableFileTransfer()");
  files.reject(parse_peer_id(peerId), id_from_double(transferId));
}

bool HybridRatsNode::pauseTransfer(const std::string& peerId, double transferId) {
  auto& files = require(files_, "enableFileTransfer()");
  return files.pause(parse_peer_id(peerId), id_from_double(transferId));
}

bool HybridRatsNode::resumeTransfer(const std::string& peerId, double transferId) {
  auto& files = require(files_, "enableFileTransfer()");
  return files.resume(parse_peer_id(peerId), id_from_double(transferId));
}

bool HybridRatsNode::cancelTransfer(const std::string& peerId, double transferId) {
  auto& files = require(files_, "enableFileTransfer()");
  return files.cancel(parse_peer_id(peerId), id_from_double(transferId));
}

TransferStats HybridRatsNode::transferStats() {
  const auto s = require(files_, "enableFileTransfer()").stats();
  return TransferStats(static_cast<double>(s.bytes_sent),
                       static_cast<double>(s.bytes_received),
                       static_cast<double>(s.completed),
                       static_cast<double>(s.failed));
}

void HybridRatsNode::onFileOffer(const std::function<void(const FileOffer&)>& listener) {
  require_not_started("onFileOffer()");
  require(files_, "enableFileTransfer()").on_offer(
      [listener](const rats::FileTransfer::Offer& offer) { listener(to_offer(offer)); });
}

void HybridRatsNode::onFileProgress(
    const std::function<void(const FileProgress&)>& listener) {
  require_not_started("onFileProgress()");
  require(files_, "enableFileTransfer()").on_progress(
      [listener](const rats::FileTransfer::Progress& progress) {
        listener(to_progress(progress));
      });
}

void HybridRatsNode::onFileComplete(
    const std::function<void(double, const std::string&, bool, const std::string&)>&
        listener) {
  require_not_started("onFileComplete()");
  require(files_, "enableFileTransfer()").on_complete(
      [listener](const rats::PeerId& peer, uint64_t id, bool success,
                 const std::string& path) {
        listener(id_to_double(id), peer.to_hex(), success, path);
      });
}

// ── pub/sub ─────────────────────────────────────────────────────────────────

void HybridRatsNode::enablePubSub(const std::optional<PubSubConfig>& config) {
  enable(pubsub_, "enablePubSub()", [&] {
    rats::PubSub::Config cfg;
    if (config) {
      const auto& c = *config;
      if (c.meshTarget)   cfg.mesh_target   = static_cast<int>(to_u32(*c.meshTarget, "meshTarget"));
      if (c.meshLow)      cfg.mesh_low      = static_cast<int>(to_u32(*c.meshLow, "meshLow"));
      if (c.meshHigh)     cfg.mesh_high     = static_cast<int>(to_u32(*c.meshHigh, "meshHigh"));
      if (c.fanoutSize)   cfg.fanout_size   = static_cast<int>(to_u32(*c.fanoutSize, "fanoutSize"));
      if (c.gossipFactor) cfg.gossip_factor = static_cast<int>(to_u32(*c.gossipFactor, "gossipFactor"));
      if (c.heartbeatIntervalMs) {
        cfg.heartbeat_interval =
            std::chrono::milliseconds(to_u32(*c.heartbeatIntervalMs, "heartbeatIntervalMs"));
      }
      if (c.seenLimit) cfg.seen_limit = to_size(*c.seenLimit, "seenLimit");
    }
    return std::make_unique<rats::PubSub>(std::move(cfg));
  });
}

void HybridRatsNode::subscribe(
    const std::string& topic,
    const std::function<void(const std::string&, const std::string&,
                             const std::shared_ptr<ArrayBuffer>&)>& listener) {
  require(pubsub_, "enablePubSub()").subscribe(
      topic, [listener](const rats::PeerId& from, const std::string& t, rats::ByteView data) {
        // Copied for the same reason as a channel message: the view points into
        // buffers the subsystem reuses once this handler returns.
        listener(from.to_hex(), t, ArrayBuffer::copy(data.data(), data.size()));
      });
}

void HybridRatsNode::unsubscribe(const std::string& topic) {
  require(pubsub_, "enablePubSub()").unsubscribe(topic);
}

void HybridRatsNode::publish(const std::string& topic,
                             const std::shared_ptr<ArrayBuffer>& data) {
  require(pubsub_, "enablePubSub()").publish(topic, view_of(data));
}

bool HybridRatsNode::isSubscribed(const std::string& topic) {
  return require(pubsub_, "enablePubSub()").is_subscribed(topic);
}

std::vector<std::string> HybridRatsNode::subscribedTopics() {
  return require(pubsub_, "enablePubSub()").subscribed_topics();
}

std::vector<std::string> HybridRatsNode::topicPeers(const std::string& topic) {
  return to_hex(require(pubsub_, "enablePubSub()").peers_for_topic(topic));
}

std::vector<std::string> HybridRatsNode::meshPeers(const std::string& topic) {
  return to_hex(require(pubsub_, "enablePubSub()").mesh_peers(topic));
}

// ── ping and reconnection ───────────────────────────────────────────────────

void HybridRatsNode::enablePing() {
  enable(ping_, "enablePing()", [] { return std::make_unique<rats::PingService>(); });
}

std::optional<double> HybridRatsNode::peerRttMs(const std::string& peerId) {
  const auto id = parse_peer_id(peerId);
  const auto rtt = require(ping_, "enablePing()").last_rtt(id);
  if (!rtt) return std::nullopt;
  return static_cast<double>(rtt->count());
}

void HybridRatsNode::enableReconnect() {
  enable(reconnect_, "enableReconnect()", [&] {
    rats::ReconnectionService::Config cfg;
    if (config_ != nullptr && !config_->data_dir.empty()) {
      cfg.store_path = config_->data_dir + "/peers.json";
    }
    return std::make_unique<rats::ReconnectionService>(cfg);
  });
}

void HybridRatsNode::addReconnect(const std::string& host, double port) {
  auto& reconnect = require(reconnect_, "enableReconnect()");
  reconnect.add(resolve(host, port));
}

void HybridRatsNode::removeReconnect(const std::string& host, double port) {
  auto& reconnect = require(reconnect_, "enableReconnect()");
  reconnect.remove(resolve(host, port));
}

} // namespace margelo::nitro::librats
