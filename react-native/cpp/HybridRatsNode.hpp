#pragma once

#include "HybridRatsNodeSpec.hpp"

#include <memory>
#include <optional>
#include <string>
#include <vector>

// librats headers stay out of this header so the generated Nitro umbrella does
// not have to see them; the Node and its subsystems are held behind forward
// declarations, which is why the destructor is declared here and defined in the
// .cpp.
namespace librats {
class Node;
struct NodeConfig;
class DhtDiscovery;
class MdnsDiscovery;
class PeerExchange;
class PortMappingService;
class HolePunch;
class Relay;
class MessageJson;
class FileTransfer;
class PubSub;
class PingService;
class ReconnectionService;
} // namespace librats

namespace margelo::nitro::librats {

/**
 * The React Native binding for a librats Node.
 *
 * One C++ implementation serves iOS and Android — there is no per-platform glue,
 * because librats is C++ and Nitro can call C++ directly on both.
 *
 * Threading: every method here is invoked from the JS thread (Nitro dispatches
 * synchronous methods on the caller's thread), so `node_` and the subsystem
 * pointers are only mutated there. librats events, by contrast, fire on reactor
 * threads; the listeners registered below are async Nitro callbacks, which
 * Nitro schedules back onto the JS thread. The listener lambdas deliberately
 * capture *only* the `std::function` they forward to — never `this` — so a
 * reactor thread mid-event cannot touch a partially destroyed HybridObject
 * during teardown.
 */
class HybridRatsNode : public HybridRatsNodeSpec {
public:
  HybridRatsNode();
  ~HybridRatsNode() override;

  // — lifecycle —
  void configure(const RatsConfig& config) override;
  bool start() override;
  void stop() override;
  bool getIsRunning() override;

  // — this node —
  double getListenPort() override;
  std::string getLocalId() override;
  std::string getProtocol() override;
  std::vector<Transport> getTransports() override;
  NatMapping getNatMapping() override;
  std::vector<std::string> observedAddresses() override;

  // — peers —
  void connect(const std::string& host, double port) override;
  bool disconnect(const std::string& peerId) override;
  double getPeerCount() override;
  std::vector<std::string> peerIds() override;
  std::optional<PeerInfo> peerInfo(const std::string& peerId) override;
  double getMaxPeers() override;
  void setMaxPeers(double maxPeers) override;

  // — messaging —
  bool send(const std::string& peerId, const std::string& channel,
            const std::shared_ptr<ArrayBuffer>& data,
            std::optional<double> lifetimeMs) override;
  bool broadcast(const std::string& channel, const std::shared_ptr<ArrayBuffer>& data,
                 std::optional<double> lifetimeMs) override;
  bool peerWritable(const std::string& peerId) override;
  std::optional<PathStats> pathStats(const std::string& peerId) override;
  void onMessage(
      const std::string& channel,
      const std::function<void(const std::string& /* peerId */,
                               const std::shared_ptr<ArrayBuffer>& /* data */)>&
          listener) override;

  // — peer events —
  void onPeerConnected(
      const std::function<void(const std::string& /* peerId */)>& listener)
      override;
  void onPeerDisconnected(
      const std::function<void(const std::string& /* peerId */,
                               CloseReason /* reason */)>& listener) override;
  void onDialFailed(
      const std::function<void(const std::string& /* address */)>& listener)
      override;
  void onPeerWritable(
      const std::function<void(const std::string& /* peerId */)>& listener)
      override;
  void onPeerPath(
      const std::function<void(const std::string& /* peerId */,
                               const PathStats& /* stats */)>& listener) override;

  // — discovery —
  void enableDht(const std::optional<DhtConfig>& config) override;
  void enableMdns() override;
  void enablePeerExchange() override;

  // — NAT traversal —
  void enablePortMapping(const std::optional<PortMappingConfig>& config) override;
  void enableHolePunch(std::optional<bool> serveRendezvous) override;
  bool punchPeer(const std::string& peerId) override;
  void enableRelay(std::optional<bool> serve) override;
  bool connectViaRelay(const std::string& peerId) override;

  // — JSON messaging —
  void enableJson() override;
  void onJson(const std::string& type,
              const std::function<void(const std::string& /* peerId */,
                                       const std::string& /* json */)>& listener)
      override;
  void onceJson(const std::string& type,
                const std::function<void(const std::string& /* peerId */,
                                         const std::string& /* json */)>& listener)
      override;
  void offJson(const std::string& type) override;
  bool sendJson(const std::string& peerId, const std::string& type,
                const std::string& json) override;
  void broadcastJson(const std::string& type, const std::string& json) override;

  // — file transfer —
  void enableFileTransfer(const FileTransferConfig& config) override;
  double sendFile(const std::string& peerId, const std::string& path) override;
  double sendDirectory(const std::string& peerId, const std::string& path) override;
  void acceptFile(const std::string& peerId, double transferId,
                  const std::string& destPath) override;
  void rejectFile(const std::string& peerId, double transferId) override;
  bool pauseTransfer(const std::string& peerId, double transferId) override;
  bool resumeTransfer(const std::string& peerId, double transferId) override;
  bool cancelTransfer(const std::string& peerId, double transferId) override;
  TransferStats transferStats() override;
  void onFileOffer(
      const std::function<void(const FileOffer&)>& listener) override;
  void onFileProgress(
      const std::function<void(const FileProgress&)>& listener) override;
  void onFileComplete(
      const std::function<void(double /* transferId */, const std::string& /* peerId */,
                               bool /* success */, const std::string& /* path */)>& listener)
      override;

  // — pub/sub —
  void enablePubSub(const std::optional<PubSubConfig>& config) override;
  void subscribe(const std::string& topic,
                 const std::function<void(const std::string& /* peerId */,
                                          const std::string& /* topic */,
                                          const std::shared_ptr<ArrayBuffer>& /* data */)>&
                     listener) override;
  void unsubscribe(const std::string& topic) override;
  void publish(const std::string& topic,
               const std::shared_ptr<ArrayBuffer>& data) override;
  bool isSubscribed(const std::string& topic) override;
  std::vector<std::string> subscribedTopics() override;
  std::vector<std::string> topicPeers(const std::string& topic) override;
  std::vector<std::string> meshPeers(const std::string& topic) override;

  // — ping and reconnection —
  void enablePing() override;
  std::optional<double> peerRttMs(const std::string& peerId) override;
  void enableReconnect() override;
  void addReconnect(const std::string& host, double port) override;
  void removeReconnect(const std::string& host, double port) override;

private:
  /**
   * The Node, constructed on first use from whatever `configure()` last set.
   * Construction is deferred because librats takes its config in the Node
   * constructor, while JS wants to configure and attach listeners in either
   * order before starting.
   */
  ::librats::Node& node();

  /// Throws unless the node is not running yet: subsystems and event listeners
  /// live in tables reactor threads read without a lock.
  void require_not_started(const char* what) const;

  /// Attach a subsystem once, before start. `slot` records it, both to refuse a
  /// second enable and so the methods that use it can find it.
  template <class T, class Make>
  void enable(T*& slot, const char* what, Make make);

  /// The attached subsystem, or throws naming the enable call that was missed.
  template <class T>
  T& require(T* slot, const char* enable_call) const;

  std::unique_ptr<::librats::NodeConfig> config_;
  std::unique_ptr<::librats::Node> node_;
  bool started_ = false;

  ::librats::DhtDiscovery* dht_ = nullptr;
  ::librats::MdnsDiscovery* mdns_ = nullptr;
  ::librats::PeerExchange* pex_ = nullptr;
  ::librats::PortMappingService* portmap_ = nullptr;
  ::librats::HolePunch* punch_ = nullptr;
  ::librats::Relay* relay_ = nullptr;
  ::librats::MessageJson* json_ = nullptr;
  ::librats::FileTransfer* files_ = nullptr;
  ::librats::PubSub* pubsub_ = nullptr;
  ::librats::PingService* ping_ = nullptr;
  ::librats::ReconnectionService* reconnect_ = nullptr;
};

} // namespace margelo::nitro::librats
