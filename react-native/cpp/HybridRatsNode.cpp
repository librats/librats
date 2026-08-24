#include "HybridRatsNode.hpp"

#include <librats/core/bytes.h>
#include <librats/node/config.h>
#include <librats/node/node.h>
#include <librats/peer/peer.h>
#include <librats/peer/peer_id.h>
#include <librats/subsystems/file_transfer.h>
#include <librats/node/nat_status.h>
#include <librats/subsystems/dht_discovery.h>
#include <librats/subsystems/hole_punch.h>
#include <librats/subsystems/message_json.h>
#include <librats/subsystems/port_mapping_service.h>
#include <librats/subsystems/relay.h>
#include <librats/storage/storage.h>
#include <librats/subsystems/peer_exchange.h>
#include <librats/subsystems/pubsub.h>

#include <stdexcept>
#include <utility>

namespace margelo::nitro::librats {

namespace rats = ::librats;

namespace {

/// JS has one number type, so every numeric field arrives as a double. Ports must
/// be whole and inside the 16-bit range; anything else is a programming error on
/// the JS side and is better as an exception than a silent truncation.
uint16_t to_port(double value, const char* what) {
  if (value < 0 || value > 65535 || value != static_cast<double>(static_cast<uint16_t>(value))) {
    throw std::invalid_argument(std::string(what) + " must be an integer in 0..65535");
  }
  return static_cast<uint16_t>(value);
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

uint64_t id_from_double(double id, const char* what) {
  if (id < 0 || id != static_cast<double>(static_cast<uint64_t>(id))) {
    throw std::invalid_argument(std::string(what) + " must be a non-negative integer");
  }
  return static_cast<uint64_t>(id);
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
  // Every enumerator is handled above; this keeps the compiler quiet about a
  // value arriving from a future library version.
  return TransferStatus::PENDING;
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

/// Lowercase hex of a 20-byte DHT hash.
///
/// Written out rather than calling librats' own to_hex: that lives in the
/// librats::dht namespace, and inside HybridRatsNode the member function dht()
/// shadows the namespace name, so neither rats::dht:: nor ::librats::dht::
/// resolves at the call site.
template <class Bytes20>
std::string hash_to_hex(const Bytes20& hash) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  out.reserve(hash.size() * 2);
  for (uint8_t byte : hash) {
    out.push_back(kDigits[byte >> 4]);
    out.push_back(kDigits[byte & 0x0f]);
  }
  return out;
}

} // namespace

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

void HybridRatsNode::configure(const RatsConfig& config) {
  if (started_) {
    throw std::runtime_error("configure() must be called before start()");
  }
  if (node_ != nullptr) {
    // The Node already exists -- something built it first, by registering a
    // listener or enabling a subsystem -- and librats fixes configuration at
    // construction. Rebuilding it here would silently drop whatever was already
    // attached to it, so refuse instead.
    throw std::runtime_error(
        "configure() must be called first, before enabling subsystems or "
        "registering listeners");
  }

  auto cfg = std::make_unique<rats::NodeConfig>();
  if (config.listenPort.has_value()) {
    cfg->listen_port = to_port(*config.listenPort, "listenPort");
  }
  if (config.protocol.has_value()) cfg->protocol = *config.protocol;
  if (config.dataDir.has_value()) cfg->data_dir = *config.dataDir;
  if (config.enableListen.has_value()) cfg->enable_listen = *config.enableListen;
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

double HybridRatsNode::getListenPort() {
  return node_ != nullptr ? static_cast<double>(node_->listen_port()) : 0.0;
}

std::string HybridRatsNode::getLocalId() { return node().local_id().to_hex(); }

double HybridRatsNode::getPeerCount() {
  return node_ != nullptr ? static_cast<double>(node_->peer_count()) : 0.0;
}

void HybridRatsNode::connect(const std::string& host, double port) {
  node().connect(host, to_port(port, "port"));
}

std::vector<std::string> HybridRatsNode::peerIds() {
  if (node_ == nullptr) return {};
  std::vector<std::string> out;
  for (const auto& id : node_->connected_peers()) out.push_back(id.to_hex());
  return out;
}

bool HybridRatsNode::send(const std::string& peerId, const std::string& channel,
                          const std::shared_ptr<ArrayBuffer>& data) {
  // Safe to hand a JS-owned (non-owning) buffer straight through: Node::send
  // copies the payload into an owned Bytes before it returns, so nothing retains
  // this pointer past the call.
  return node().send(parse_peer_id(peerId), channel, view_of(data));
}

void HybridRatsNode::broadcast(const std::string& channel,
                               const std::shared_ptr<ArrayBuffer>& data) {
  node().broadcast(channel, view_of(data));
}

void HybridRatsNode::onMessage(
    const std::string& channel,
    const std::function<void(const std::string&,
                             const std::shared_ptr<ArrayBuffer>&)>& listener) {
  if (started_) {
    throw std::runtime_error(
        "onMessage() must be called before start(): librats registers handlers without "
        "a lock and dispatches them from reactor threads, so registering on a "
        "running node is a data race");
  }
  node().on(channel, [listener](const rats::Peer& peer, rats::ByteView payload) {
    // The payload is a view into the connection's receive buffer, which is
    // recycled as soon as this handler returns — so it must be copied, not
    // wrapped, to give JS a buffer that outlives the event.
    listener(peer.id().to_hex(), ArrayBuffer::copy(payload.data(), payload.size()));
  });
}

void HybridRatsNode::onPeerConnected(
    const std::function<void(const std::string&)>& listener) {
  if (started_) {
    throw std::runtime_error(
        "onPeerConnected() must be called before start(): librats registers handlers without "
        "a lock and dispatches them from reactor threads, so registering on a "
        "running node is a data race");
  }
  node().on_peer_connected(
      [listener](const rats::Peer& peer) { listener(peer.id().to_hex()); });
}

void HybridRatsNode::onPeerDisconnected(
    const std::function<void(const std::string&)>& listener) {
  if (started_) {
    throw std::runtime_error(
        "onPeerDisconnected() must be called before start(): librats registers handlers without "
        "a lock and dispatches them from reactor threads, so registering on a "
        "running node is a data race");
  }
  // Disconnect reports the id rather than a Peer handle: by the time it fires
  // there is no connection left to reach.
  node().on_peer_disconnected(
      [listener](const rats::PeerId& id) { listener(id.to_hex()); });
}

// ── file transfer ───────────────────────────────────────────────────────────

rats::FileTransfer& HybridRatsNode::files() {
  if (files_ == nullptr) {
    throw std::runtime_error(
        "file transfer is not enabled - call enableFileTransfer() before start()");
  }
  return *files_;
}

void HybridRatsNode::enableFileTransfer(const FileTransferConfig& config) {
  if (started_) {
    throw std::runtime_error("enableFileTransfer() must be called before start()");
  }
  if (files_ != nullptr) {
    throw std::runtime_error("file transfer is already enabled");
  }
  if (config.tempDirectory.empty()) {
    // The library would fall back to ".", the process working directory, which is
    // not writable on iOS or Android -- so every transfer would fail at the first
    // temp-file write rather than here, where the cause is obvious.
    throw std::invalid_argument("tempDirectory must not be empty");
  }

  rats::FileTransfer::Config cfg;
  cfg.temp_directory = config.tempDirectory;
  if (config.chunkSize.has_value()) {
    cfg.chunk_size = static_cast<uint32_t>(*config.chunkSize);
  }
  if (config.windowBytes.has_value()) {
    cfg.window_bytes = static_cast<uint32_t>(*config.windowBytes);
  }
  if (config.transferTimeoutSecs.has_value()) {
    cfg.transfer_timeout_secs = static_cast<uint32_t>(*config.transferTimeoutSecs);
  }
  if (config.verifyIntegrity.has_value()) {
    cfg.verify_integrity = *config.verifyIntegrity;
  }

  files_ = node().add_subsystem(std::make_unique<rats::FileTransfer>(std::move(cfg)));
}

double HybridRatsNode::sendFile(const std::string& peerId, const std::string& path) {
  return id_to_double(files().send_file(parse_peer_id(peerId), path));
}

double HybridRatsNode::sendDirectory(const std::string& peerId,
                                     const std::string& path) {
  return id_to_double(files().send_directory(parse_peer_id(peerId), path));
}

void HybridRatsNode::acceptFile(const std::string& peerId, double transferId,
                                const std::string& destPath) {
  files().accept(parse_peer_id(peerId), id_from_double(transferId, "transferId"),
                 destPath);
}

void HybridRatsNode::rejectFile(const std::string& peerId, double transferId) {
  files().reject(parse_peer_id(peerId), id_from_double(transferId, "transferId"));
}

bool HybridRatsNode::pauseTransfer(const std::string& peerId, double transferId) {
  return files().pause(parse_peer_id(peerId), id_from_double(transferId, "transferId"));
}

bool HybridRatsNode::resumeTransfer(const std::string& peerId, double transferId) {
  return files().resume(parse_peer_id(peerId), id_from_double(transferId, "transferId"));
}

bool HybridRatsNode::cancelTransfer(const std::string& peerId, double transferId) {
  return files().cancel(parse_peer_id(peerId), id_from_double(transferId, "transferId"));
}

TransferStats HybridRatsNode::transferStats() {
  const auto s = files().stats();
  return TransferStats(static_cast<double>(s.bytes_sent),
                       static_cast<double>(s.bytes_received),
                       static_cast<double>(s.completed),
                       static_cast<double>(s.failed));
}

void HybridRatsNode::onFileOffer(
    const std::function<void(const FileOffer&)>& listener) {
  if (started_) {
    throw std::runtime_error(
        "onFileOffer() must be called before start(): librats registers handlers without "
        "a lock and dispatches them from reactor threads, so registering on a "
        "running node is a data race");
  }
  files().on_offer([listener](const rats::FileTransfer::Offer& offer) {
    listener(to_offer(offer));
  });
}

void HybridRatsNode::onFileProgress(
    const std::function<void(const FileProgress&)>& listener) {
  if (started_) {
    throw std::runtime_error(
        "onFileProgress() must be called before start(): librats registers handlers without "
        "a lock and dispatches them from reactor threads, so registering on a "
        "running node is a data race");
  }
  files().on_progress([listener](const rats::FileTransfer::Progress& progress) {
    listener(to_progress(progress));
  });
}

void HybridRatsNode::onFileComplete(
    const std::function<void(double, bool, const std::string&)>& listener) {
  if (started_) {
    throw std::runtime_error(
        "onFileComplete() must be called before start(): librats registers handlers without "
        "a lock and dispatches them from reactor threads, so registering on a "
        "running node is a data race");
  }
  files().on_complete(
      [listener](uint64_t id, bool success, const std::string& path) {
        listener(id_to_double(id), success, path);
      });
}

// ── pub/sub ─────────────────────────────────────────────────────────────────

rats::PubSub& HybridRatsNode::pubsub() {
  if (pubsub_ == nullptr) {
    throw std::runtime_error(
        "pub/sub is not enabled - call enablePubSub() before start()");
  }
  return *pubsub_;
}

void HybridRatsNode::enablePubSub(const std::optional<PubSubConfig>& config) {
  if (started_) {
    throw std::runtime_error("enablePubSub() must be called before start()");
  }
  if (pubsub_ != nullptr) {
    throw std::runtime_error("pub/sub is already enabled");
  }

  rats::PubSub::Config cfg;
  if (config.has_value()) {
    const auto& c = *config;
    if (c.meshTarget.has_value())   cfg.mesh_target   = static_cast<int>(*c.meshTarget);
    if (c.meshLow.has_value())      cfg.mesh_low      = static_cast<int>(*c.meshLow);
    if (c.meshHigh.has_value())     cfg.mesh_high     = static_cast<int>(*c.meshHigh);
    if (c.fanoutSize.has_value())   cfg.fanout_size   = static_cast<int>(*c.fanoutSize);
    if (c.gossipFactor.has_value()) cfg.gossip_factor = static_cast<int>(*c.gossipFactor);
    if (c.heartbeatIntervalMs.has_value()) {
      cfg.heartbeat_interval =
          std::chrono::milliseconds(static_cast<int64_t>(*c.heartbeatIntervalMs));
    }
    if (c.seenLimit.has_value()) cfg.seen_limit = static_cast<size_t>(*c.seenLimit);
  }

  pubsub_ = node().add_subsystem(std::make_unique<rats::PubSub>(std::move(cfg)));
}

void HybridRatsNode::subscribe(
    const std::string& topic,
    const std::function<void(const std::string&, const std::string&,
                             const std::shared_ptr<ArrayBuffer>&)>& listener) {
  pubsub().subscribe(topic, [listener](const rats::PeerId& from,
                                       const std::string& t, rats::ByteView data) {
    // Copied for the same reason as a channel message: the view points into
    // buffers the subsystem reuses once this handler returns.
    listener(from.to_hex(), t, ArrayBuffer::copy(data.data(), data.size()));
  });
}

void HybridRatsNode::unsubscribe(const std::string& topic) {
  pubsub().unsubscribe(topic);
}

void HybridRatsNode::publish(const std::string& topic,
                             const std::shared_ptr<ArrayBuffer>& data) {
  pubsub().publish(topic, view_of(data));
}

bool HybridRatsNode::isSubscribed(const std::string& topic) {
  return pubsub().is_subscribed(topic);
}

std::vector<std::string> HybridRatsNode::subscribedTopics() {
  return pubsub().subscribed_topics();
}

std::vector<std::string> HybridRatsNode::topicPeers(const std::string& topic) {
  std::vector<std::string> out;
  for (const auto& id : pubsub().peers_for_topic(topic)) out.push_back(id.to_hex());
  return out;
}

std::vector<std::string> HybridRatsNode::meshPeers(const std::string& topic) {
  std::vector<std::string> out;
  for (const auto& id : pubsub().mesh_peers(topic)) out.push_back(id.to_hex());
  return out;
}

// ── DHT discovery ───────────────────────────────────────────────────────────

rats::DhtDiscovery& HybridRatsNode::dht() {
  if (dht_ == nullptr) {
    throw std::runtime_error(
        "DHT discovery is not enabled - call enableDht() before start()");
  }
  return *dht_;
}

void HybridRatsNode::enableDht(const std::optional<DhtConfig>& config) {
  if (started_) {
    throw std::runtime_error("enableDht() must be called before start()");
  }
  if (dht_ != nullptr) {
    throw std::runtime_error("DHT discovery is already enabled");
  }

  rats::DhtDiscovery::Config cfg;

  // Co-locate the routing table with the node's own state unless told otherwise.
  // The library default is the working directory, which is not writable on either
  // mobile platform, so inheriting data_dir is what makes persistence work at all
  // here. Reading config_ (rather than the live Node) keeps this correct whether
  // or not the Node has been constructed yet.
  if (config_ != nullptr) cfg.data_dir = config_->data_dir;

  if (config.has_value()) {
    const auto& c = *config;
    if (c.dhtPort.has_value())      cfg.dht_port      = to_port(*c.dhtPort, "dhtPort");
    if (c.dataDir.has_value())      cfg.data_dir      = *c.dataDir;
    if (c.enableIpv4.has_value())   cfg.enable_ipv4   = *c.enableIpv4;
    if (c.enableIpv6.has_value())   cfg.enable_ipv6   = *c.enableIpv6;
    if (c.discoveryKey.has_value()) cfg.discovery_key = *c.discoveryKey;
    if (c.discoverExternalIp.has_value()) {
      cfg.discover_external_ip = *c.discoverExternalIp;
    }
    if (c.searchIntervalMs.has_value()) {
      cfg.search_interval =
          std::chrono::milliseconds(static_cast<int64_t>(*c.searchIntervalMs));
    }
    if (c.announceIntervalMs.has_value()) {
      cfg.announce_interval =
          std::chrono::milliseconds(static_cast<int64_t>(*c.announceIntervalMs));
    }
    if (c.bootstrapNodes.has_value()) {
      for (const auto& entry : *c.bootstrapNodes) {
        auto parsed = rats::HostEndpoint::parse(entry);
        if (!parsed) {
          throw std::invalid_argument(
              "bootstrapNodes entry is not \"host:port\": " + entry);
        }
        cfg.bootstrap_nodes.push_back(*parsed);
      }
    }
  }

  dht_ = node().add_subsystem(std::make_unique<rats::DhtDiscovery>(std::move(cfg)));
}

DhtStatus HybridRatsNode::dhtStatus() {
  auto& d = dht();
  return DhtStatus(d.is_running(), static_cast<double>(d.dht_port()),
                   static_cast<double>(d.dht_port_v6()),
                   hash_to_hex(d.discovery_hash()), d.external_address());
}

// ── NAT traversal ───────────────────────────────────────────────────────────

NatStatus HybridRatsNode::natStatus() {
  // No subsystem to enable: the node collects these observations from the
  // identify exchange for free. Before any UDP peer has connected the mapping is
  // simply Unknown.
  const auto& status = node().nat_status();

  std::vector<std::string> endpoints;
  for (const auto& address : status.external_udp_endpoints()) {
    endpoints.push_back(address.to_string());
  }

  NatMapping mapping = NatMapping::UNKNOWN;
  switch (status.udp_mapping()) {
    case rats::NatMapping::Unknown:             mapping = NatMapping::UNKNOWN; break;
    case rats::NatMapping::Open:                mapping = NatMapping::OPEN; break;
    case rats::NatMapping::EndpointIndependent: mapping = NatMapping::ENDPOINTINDEPENDENT; break;
    case rats::NatMapping::EndpointDependent:   mapping = NatMapping::ENDPOINTDEPENDENT; break;
  }

  return NatStatus(mapping, static_cast<double>(status.observation_count()),
                   std::move(endpoints));
}

rats::PortMappingService& HybridRatsNode::portMapping() {
  if (port_mapping_ == nullptr) {
    throw std::runtime_error(
        "port mapping is not enabled - call enablePortMapping() before start()");
  }
  return *port_mapping_;
}

void HybridRatsNode::enablePortMapping(
    const std::optional<PortMappingConfig>& config) {
  if (started_) {
    throw std::runtime_error("enablePortMapping() must be called before start()");
  }
  if (port_mapping_ != nullptr) {
    throw std::runtime_error("port mapping is already enabled");
  }

  rats::PortMappingConfig cfg;
  if (config.has_value()) {
    const auto& c = *config;
    if (c.enabled.has_value())       cfg.enabled       = *c.enabled;
    if (c.enableUpnp.has_value())    cfg.enable_upnp   = *c.enableUpnp;
    if (c.enableNatpmp.has_value())  cfg.enable_natpmp = *c.enableNatpmp;
    if (c.leaseDurationSeconds.has_value()) {
      cfg.lease_duration_seconds =
          static_cast<uint32_t>(*c.leaseDurationSeconds);
    }
  }

  port_mapping_ =
      node().add_subsystem(std::make_unique<rats::PortMappingService>(std::move(cfg)));
}

PortMappingStatus HybridRatsNode::portMappingStatus() {
  auto& service = portMapping();
  // The two protocols are mapped independently -- a router may grant one and
  // refuse the other -- so both are reported separately rather than as one flag.
  const auto tcp = service.mapped_public_address(rats::PortMapProtocol::TCP);
  const auto udp = service.mapped_public_address(rats::PortMapProtocol::UDP);

  std::string ip;
  if (tcp.has_value())      ip = tcp->first;
  else if (udp.has_value()) ip = udp->first;

  return PortMappingStatus(ip,
                           tcp.has_value() ? static_cast<double>(tcp->second) : 0.0,
                           udp.has_value() ? static_cast<double>(udp->second) : 0.0);
}

rats::HolePunch& HybridRatsNode::holePunch() {
  if (hole_punch_ == nullptr) {
    throw std::runtime_error(
        "hole punching is not enabled - call enableHolePunch() before start()");
  }
  return *hole_punch_;
}

void HybridRatsNode::enableHolePunch(const std::optional<HolePunchConfig>& config) {
  if (started_) {
    throw std::runtime_error("enableHolePunch() must be called before start()");
  }
  if (hole_punch_ != nullptr) {
    throw std::runtime_error("hole punching is already enabled");
  }

  rats::HolePunch::Config cfg;
  if (config.has_value()) {
    const auto& c = *config;
    if (c.maxRelays.has_value())    cfg.max_relays    = static_cast<size_t>(*c.maxRelays);
    if (c.maxAddresses.has_value()) cfg.max_addresses = static_cast<size_t>(*c.maxAddresses);
    if (c.attempts.has_value())     cfg.attempts      = static_cast<int>(*c.attempts);
    if (c.roundTimeoutMs.has_value()) {
      cfg.round_timeout =
          std::chrono::milliseconds(static_cast<int64_t>(*c.roundTimeoutMs));
    }
  }

  hole_punch_ = node().add_subsystem(std::make_unique<rats::HolePunch>(std::move(cfg)));
}

bool HybridRatsNode::punch(const std::string& peerId) {
  return holePunch().punch(parse_peer_id(peerId));
}

rats::Relay& HybridRatsNode::relay() {
  if (relay_ == nullptr) {
    throw std::runtime_error(
        "relaying is not enabled - call enableRelay() before start()");
  }
  return *relay_;
}

void HybridRatsNode::enableRelay(const std::optional<RelayConfig>& config) {
  if (started_) {
    throw std::runtime_error("enableRelay() must be called before start()");
  }
  if (relay_ != nullptr) {
    throw std::runtime_error("relaying is already enabled");
  }

  rats::Relay::Config cfg;
  if (config.has_value()) {
    const auto& c = *config;
    if (c.enableClient.has_value())   cfg.enable_client   = *c.enableClient;
    if (c.acceptInbound.has_value())  cfg.accept_inbound  = *c.acceptInbound;
    if (c.serve.has_value())          cfg.serve           = *c.serve;
    if (c.maxOutboundCircuits.has_value()) {
      cfg.max_outbound_circuits = static_cast<size_t>(*c.maxOutboundCircuits);
    }
    if (c.maxCircuits.has_value()) {
      cfg.max_circuits = static_cast<size_t>(*c.maxCircuits);
    }
    if (c.maxBytesPerCircuit.has_value()) {
      cfg.max_bytes_per_circuit = static_cast<uint64_t>(*c.maxBytesPerCircuit);
    }
    if (c.openTimeoutMs.has_value()) {
      cfg.open_timeout =
          std::chrono::milliseconds(static_cast<int64_t>(*c.openTimeoutMs));
    }
  }

  relay_ = node().add_subsystem(std::make_unique<rats::Relay>(std::move(cfg)));
}

bool HybridRatsNode::connectViaRelay(const std::string& peerId) {
  return relay().connect_via_relay(parse_peer_id(peerId));
}

// ── typed JSON messaging ────────────────────────────────────────────────────

rats::MessageJson& HybridRatsNode::json() {
  if (json_ == nullptr) {
    throw std::runtime_error(
        "JSON messaging is not enabled - call enableJsonMessaging() before start()");
  }
  return *json_;
}

void HybridRatsNode::enableJsonMessaging() {
  if (started_) {
    throw std::runtime_error("enableJsonMessaging() must be called before start()");
  }
  if (json_ != nullptr) {
    throw std::runtime_error("JSON messaging is already enabled");
  }
  json_ = node().add_subsystem(std::make_unique<rats::MessageJson>());
}

namespace {

/// Parse a JS-supplied JSON string into the library's Json type, turning a parse
/// failure into an argument error naming the type -- otherwise the only symptom is
/// a message that silently never goes out.
rats::Json parse_json(const std::string& text, const std::string& type) {
  try {
    return rats::Json::parse(text);
  } catch (const rats::JsonError& e) {
    throw std::invalid_argument("json for type \"" + type + "\" is not valid JSON: " +
                                e.what());
  }
}

} // namespace

bool HybridRatsNode::sendJson(const std::string& peerId, const std::string& type,
                              const std::string& json) {
  // MessageJson's callback is invoked inline before send() returns, so capturing
  // the verdict into a local and returning it is accurate rather than racy.
  bool ok = false;
  this->json().send(parse_peer_id(peerId), type, parse_json(json, type),
                    [&ok](bool success, const std::string&) { ok = success; });
  return ok;
}

bool HybridRatsNode::broadcastJson(const std::string& type, const std::string& json) {
  bool ok = false;
  this->json().send(type, parse_json(json, type),
                    [&ok](bool success, const std::string&) { ok = success; });
  return ok;
}

void HybridRatsNode::onJson(
    const std::string& type,
    const std::function<void(const std::string&, const std::string&)>& listener) {
  json().on(type, [listener](const rats::PeerId& from, const rats::Json& data) {
    // Back to a string for JS, which parses it with Hermes' native JSON.parse.
    // dump() with no indent gives compact text, the same form the wire carries.
    listener(from.to_hex(), data.dump());
  });
}

void HybridRatsNode::onceJson(
    const std::string& type,
    const std::function<void(const std::string&, const std::string&)>& listener) {
  json().once(type, [listener](const rats::PeerId& from, const rats::Json& data) {
    listener(from.to_hex(), data.dump());
  });
}

void HybridRatsNode::offJson(const std::string& type) { json().off(type); }

// ── peer exchange ───────────────────────────────────────────────────────────

void HybridRatsNode::enablePeerExchange(
    const std::optional<PeerExchangeConfig>& config) {
  if (started_) {
    throw std::runtime_error("enablePeerExchange() must be called before start()");
  }
  if (pex_ != nullptr) {
    throw std::runtime_error("peer exchange is already enabled");
  }

  rats::PeerExchange::Config cfg;
  if (config.has_value()) {
    const auto& c = *config;
    if (c.maxAddressesPerResponse.has_value()) {
      cfg.max_addresses_per_response =
          static_cast<size_t>(*c.maxAddressesPerResponse);
    }
    if (c.requestMax.has_value())        cfg.request_max        = static_cast<size_t>(*c.requestMax);
    if (c.requestOnConnect.has_value())  cfg.request_on_connect = *c.requestOnConnect;
    if (c.publicOnly.has_value())        cfg.public_only        = *c.publicOnly;
    if (c.peerTarget.has_value())        cfg.peer_target        = static_cast<size_t>(*c.peerTarget);
    if (c.punchOnDialFailure.has_value()) {
      cfg.punch_on_dial_failure = *c.punchOnDialFailure;
    }
    if (c.dialCooldownMs.has_value()) {
      cfg.dial_cooldown =
          std::chrono::milliseconds(static_cast<int64_t>(*c.dialCooldownMs));
    }
  }

  // Nothing is stored beyond the pointer: PEX has no post-attach API, it just
  // asks each new peer for its peers and dials what it learns.
  pex_ = node().add_subsystem(std::make_unique<rats::PeerExchange>(std::move(cfg)));
}

// ── distributed key-value storage ───────────────────────────────────────────

namespace {

StorageValueType to_value_type(rats::StorageValueType t) {
  switch (t) {
    case rats::StorageValueType::BINARY: return StorageValueType::BINARY;
    case rats::StorageValueType::STRING: return StorageValueType::STRING;
    case rats::StorageValueType::INT64:  return StorageValueType::INT;
    case rats::StorageValueType::DOUBLE: return StorageValueType::DOUBLE;
    case rats::StorageValueType::JSON:   return StorageValueType::JSON;
  }
  return StorageValueType::BINARY;
}

StorageChangeEvent to_change_event(const rats::StorageChangeEvent& e) {
  // The values themselves are left out: read them back with the typed getters if
  // needed, so a 16 MiB write does not cross the bridge merely to announce itself.
  return StorageChangeEvent(
      e.operation == rats::StorageOperation::OP_PUT ? StorageOperation::PUT
                                                    : StorageOperation::DELETE,
      e.key, to_value_type(e.type), static_cast<double>(e.timestamp_ms),
      e.origin_peer_id, e.is_remote);
}

} // namespace

rats::StorageManager& HybridRatsNode::storage() {
  if (storage_ == nullptr) {
    throw std::runtime_error(
        "storage is not enabled - call enableStorage() before start()");
  }
  return *storage_;
}

void HybridRatsNode::enableStorage(const std::optional<StorageConfig>& config) {
  if (started_) {
    throw std::runtime_error("enableStorage() must be called before start()");
  }
  if (storage_ != nullptr) {
    throw std::runtime_error("storage is already enabled");
  }

  rats::StorageConfig cfg;

  // The library default is "./storage", relative to the working directory, which
  // is not writable on either mobile platform. Inherit the node's data_dir so the
  // database lands beside the identity; refuse outright when neither is available
  // rather than letting every single write fail later.
  if (config_ != nullptr && !config_->data_dir.empty()) {
    cfg.data_directory = config_->data_dir + "/storage";
  } else {
    cfg.data_directory.clear();
  }

  if (config.has_value()) {
    const auto& c = *config;
    if (c.dataDirectory.has_value())  cfg.data_directory = *c.dataDirectory;
    if (c.databaseName.has_value())   cfg.database_name  = *c.databaseName;
    if (c.enableSync.has_value())     cfg.enable_sync    = *c.enableSync;
    if (c.persistToDisk.has_value())  cfg.persist_to_disk = *c.persistToDisk;
    if (c.compactionThreshold.has_value()) {
      cfg.compaction_threshold = static_cast<uint32_t>(*c.compactionThreshold);
    }
    if (c.maxValueSize.has_value()) {
      cfg.max_value_size = static_cast<uint32_t>(*c.maxValueSize);
    }
  }

  if (cfg.persist_to_disk && cfg.data_directory.empty()) {
    throw std::invalid_argument(
        "storage needs a writable directory: set dataDirectory, or the node's "
        "dataDir, or persistToDisk: false for a memory-only store");
  }

  storage_ = node().add_subsystem(std::make_unique<rats::StorageManager>(cfg));
}

bool HybridRatsNode::putString(const std::string& key, const std::string& value) {
  return storage().put(key, value);
}

bool HybridRatsNode::putInt(const std::string& key, double value) {
  // JS numbers are doubles, so only integers up to 2^53 survive exactly. Reject
  // anything else instead of silently truncating into an int64 slot.
  if (value != static_cast<double>(static_cast<int64_t>(value)) ||
      value > 9007199254740992.0 || value < -9007199254740992.0) {
    throw std::invalid_argument(
        "putInt needs an integer within +/-2^53; use putDouble or putString "
        "for anything else");
  }
  return storage().put(key, static_cast<int64_t>(value));
}

bool HybridRatsNode::putDouble(const std::string& key, double value) {
  return storage().put(key, value);
}

bool HybridRatsNode::putBinary(const std::string& key,
                               const std::shared_ptr<ArrayBuffer>& value) {
  const auto view = view_of(value);
  return storage().put(key, std::vector<uint8_t>(view.data(), view.data() + view.size()));
}

bool HybridRatsNode::putJson(const std::string& key, const std::string& json) {
  return storage().put_json(key, parse_json(json, key));
}

std::optional<std::string> HybridRatsNode::getString(const std::string& key) {
  return storage().get_string(key);
}

std::optional<double> HybridRatsNode::getInt(const std::string& key) {
  const auto v = storage().get_int(key);
  if (!v.has_value()) return std::nullopt;
  return static_cast<double>(*v);
}

std::optional<double> HybridRatsNode::getDouble(const std::string& key) {
  return storage().get_double(key);
}

std::optional<std::shared_ptr<ArrayBuffer>> HybridRatsNode::getBinary(
    const std::string& key) {
  const auto v = storage().get_binary(key);
  if (!v.has_value()) return std::nullopt;
  return ArrayBuffer::copy(v->data(), v->size());
}

std::optional<std::string> HybridRatsNode::getJson(const std::string& key) {
  const auto v = storage().get_json(key);
  if (!v.has_value()) return std::nullopt;
  return v->dump();
}

std::optional<StorageValueType> HybridRatsNode::getValueType(const std::string& key) {
  const auto t = storage().get_type(key);
  if (!t.has_value()) return std::nullopt;
  return to_value_type(*t);
}

bool HybridRatsNode::removeKey(const std::string& key) { return storage().remove(key); }
bool HybridRatsNode::hasKey(const std::string& key) { return storage().has(key); }

std::vector<std::string> HybridRatsNode::storageKeys() { return storage().keys(); }

std::vector<std::string> HybridRatsNode::storageKeysWithPrefix(
    const std::string& prefix) {
  return storage().keys_with_prefix(prefix);
}

double HybridRatsNode::storageCount() {
  return static_cast<double>(storage().size());
}

void HybridRatsNode::clearStorage() { storage().clear(); }
bool HybridRatsNode::saveStorage() { return storage().save(); }
bool HybridRatsNode::loadStorage() { return storage().load(); }

double HybridRatsNode::compactStorage() {
  return static_cast<double>(storage().compact());
}

bool HybridRatsNode::requestStorageSync() { return storage().request_sync(); }
bool HybridRatsNode::isStorageSynced() { return storage().is_synced(); }

StorageStats HybridRatsNode::storageStats() {
  const auto s = storage().get_statistics();
  return StorageStats(static_cast<double>(s.total_entries),
                      static_cast<double>(s.deleted_entries),
                      static_cast<double>(s.total_data_bytes),
                      static_cast<double>(s.disk_usage_bytes),
                      static_cast<double>(s.entries_synced),
                      static_cast<double>(s.entries_sent));
}

void HybridRatsNode::onStorageChange(
    const std::function<void(const StorageChangeEvent&)>& listener) {
  storage().set_change_callback(
      [listener](const rats::StorageChangeEvent& e) { listener(to_change_event(e)); });
}

} // namespace margelo::nitro::librats
