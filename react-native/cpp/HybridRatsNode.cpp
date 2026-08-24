#include "HybridRatsNode.hpp"

#include <librats/core/bytes.h>
#include <librats/node/config.h>
#include <librats/node/node.h>
#include <librats/peer/peer.h>
#include <librats/peer/peer_id.h>
#include <librats/subsystems/file_transfer.h>
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

} // namespace margelo::nitro::librats
