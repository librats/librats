#include "HybridRatsNode.hpp"

#include <librats/core/bytes.h>
#include <librats/node/config.h>
#include <librats/node/node.h>
#include <librats/peer/peer.h>
#include <librats/peer/peer_id.h>

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
    // The Node already exists because a listener was registered first, and
    // librats fixes configuration at construction. Rebuilding it here would
    // silently drop those listeners, so refuse instead.
    throw std::runtime_error(
        "configure() must be called before registering listeners");
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
  node().on(channel, [listener](const rats::Peer& peer, rats::ByteView payload) {
    // The payload is a view into the connection's receive buffer, which is
    // recycled as soon as this handler returns — so it must be copied, not
    // wrapped, to give JS a buffer that outlives the event.
    listener(peer.id().to_hex(), ArrayBuffer::copy(payload.data(), payload.size()));
  });
}

void HybridRatsNode::onPeerConnected(
    const std::function<void(const std::string&)>& listener) {
  node().on_peer_connected(
      [listener](const rats::Peer& peer) { listener(peer.id().to_hex()); });
}

void HybridRatsNode::onPeerDisconnected(
    const std::function<void(const std::string&)>& listener) {
  // Disconnect reports the id rather than a Peer handle: by the time it fires
  // there is no connection left to reach.
  node().on_peer_disconnected(
      [listener](const rats::PeerId& id) { listener(id.to_hex()); });
}

} // namespace margelo::nitro::librats
