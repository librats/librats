#pragma once

#include "HybridRatsNodeSpec.hpp"

#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

// librats headers stay out of this header so the generated Nitro umbrella does
// not have to see them; the Node is held behind a forward declaration, which is
// why the destructor is declared here and defined in the .cpp.
namespace librats {
class Node;
class FileTransfer;
class PubSub;
class DhtDiscovery;
class MdnsDiscovery;
class HolePunch;
class Relay;
class PortMappingService;
class MessageJson;
class StorageManager;
class PeerExchange;
class Bittorrent;
class PingService;
class ReconnectionService;
struct NodeConfig;
} // namespace librats

namespace margelo::nitro::librats {

/**
 * The React Native binding for a librats Node.
 *
 * One C++ implementation serves iOS and Android — there is no per-platform glue,
 * because librats is C++ and Nitro can call C++ directly on both.
 *
 * Threading: every method here is invoked from the JS thread (Nitro dispatches
 * synchronous methods on the caller's thread), so `node_` is only mutated there.
 * librats events, by contrast, fire on reactor threads; the listeners registered
 * below are async Nitro callbacks, which Nitro is responsible for scheduling back
 * onto the JS thread. The listener lambdas deliberately capture *only* the
 * `std::function` they forward to — never `this` — so a reactor thread mid-event
 * cannot touch a partially destroyed HybridObject during teardown.
 */
class HybridRatsNode : public HybridRatsNodeSpec {
public:
  HybridRatsNode();
  ~HybridRatsNode() override;

  // — lifecycle —
  void configure(const RatsConfig& config) override;
  bool start() override;
  void stop() override;

  // — properties —
  bool getIsRunning() override;
  double getListenPort() override;
  std::string getLocalId() override;
  double getPeerCount() override;

  // — connections —
  void connect(const std::string& host, double port) override;
  std::vector<std::string> peerIds() override;

  // — messaging —
  bool send(const std::string& peerId, const std::string& channel,
            const std::shared_ptr<ArrayBuffer>& data) override;
  void broadcast(const std::string& channel,
                 const std::shared_ptr<ArrayBuffer>& data) override;
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
      const std::function<void(const std::string& /* peerId */)>& listener)
      override;

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
      const std::function<void(double /* transferId */, bool /* success */,
                               const std::string& /* path */)>& listener)
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

  // — DHT discovery —
  void enableDht(const std::optional<DhtConfig>& config) override;
  void enableMdns(const std::optional<MdnsConfig>& config) override;
  DhtStatus dhtStatus() override;

  // — NAT traversal —
  NatStatus natStatus() override;
  void enablePortMapping(const std::optional<PortMappingConfig>& config) override;
  PortMappingStatus portMappingStatus() override;
  void enableHolePunch(const std::optional<HolePunchConfig>& config) override;
  bool punch(const std::string& peerId) override;
  void enableRelay(const std::optional<RelayConfig>& config) override;
  bool connectViaRelay(const std::string& peerId) override;

  // — typed JSON messaging —
  void enableJsonMessaging() override;
  bool sendJson(const std::string& peerId, const std::string& type,
                const std::string& json) override;
  bool broadcastJson(const std::string& type, const std::string& json) override;
  void onJson(const std::string& type,
              const std::function<void(const std::string& /* peerId */,
                                       const std::string& /* json */)>& listener) override;
  void onceJson(const std::string& type,
                const std::function<void(const std::string& /* peerId */,
                                         const std::string& /* json */)>& listener) override;
  void offJson(const std::string& type) override;

  // — peer exchange —
  void enablePeerExchange(const std::optional<PeerExchangeConfig>& config) override;

  // — BitTorrent —
  void enableBittorrent(const std::optional<BittorrentConfig>& config) override;
  std::string addMagnet(const std::string& magnetUri,
                        const std::optional<std::string>& savePath) override;
  std::string addTorrentFile(const std::string& path,
                             const std::optional<std::string>& savePath) override;
  void removeTorrent(const std::string& infoHash,
                     std::optional<bool> deleteFiles) override;
  void pauseTorrent(const std::string& infoHash) override;
  void resumeTorrent(const std::string& infoHash) override;
  TorrentStatus torrentStatus(const std::string& infoHash) override;
  std::vector<std::string> torrentInfoHashes() override;
  BittorrentStats bittorrentStats() override;
  bool saveResumeData(const std::string& infoHash) override;
  void saveAllResumeData() override;
  void fetchTorrentMetadata(
      const std::string& infoHash, double timeoutMs,
      const std::function<void(bool, const TorrentMetadata&, const std::string&)>& listener)
      override;

  // — keepalive and reconnection —
  void enablePing(const std::optional<PingConfig>& config) override;
  double peerRtt(const std::string& peerId) override;
  double alivePeerCount() override;
  void enableReconnection(const std::optional<ReconnectionConfig>& config) override;
  void addReconnectTarget(const std::string& address) override;
  void removeReconnectTarget(const std::string& address) override;
  double reconnectTargetCount() override;
  std::vector<std::string> knownPeers(double limit) override;

  // — distributed key-value storage —
  void enableStorage(const std::optional<StorageConfig>& config) override;
  bool putString(const std::string& key, const std::string& value) override;
  bool putInt(const std::string& key, double value) override;
  bool putDouble(const std::string& key, double value) override;
  bool putBinary(const std::string& key,
                 const std::shared_ptr<ArrayBuffer>& value) override;
  bool putJson(const std::string& key, const std::string& json) override;
  std::optional<std::string> getString(const std::string& key) override;
  std::optional<double> getInt(const std::string& key) override;
  std::optional<double> getDouble(const std::string& key) override;
  std::optional<std::shared_ptr<ArrayBuffer>> getBinary(const std::string& key) override;
  std::optional<std::string> getJson(const std::string& key) override;
  std::optional<StorageValueType> getValueType(const std::string& key) override;
  bool removeKey(const std::string& key) override;
  bool hasKey(const std::string& key) override;
  std::vector<std::string> storageKeys() override;
  std::vector<std::string> storageKeysWithPrefix(const std::string& prefix) override;
  double storageCount() override;
  void clearStorage() override;
  bool saveStorage() override;
  bool loadStorage() override;
  double compactStorage() override;
  bool requestStorageSync() override;
  bool isStorageSynced() override;
  StorageStats storageStats() override;
  void onStorageChange(
      const std::function<void(const StorageChangeEvent&)>& listener) override;

private:
  /**
   * The Node, constructed on first use from whatever `configure()` last set.
   * Construction is deferred because librats takes its config in the Node
   * constructor, while JS wants to configure and attach listeners in either
   * order before starting.
   */
  ::librats::Node& node();

  /// The attached FileTransfer subsystem, or throws if enableFileTransfer() was
  /// never called. Ownership stays with the Node, which outlives every use here.
  ::librats::FileTransfer& files();

  /// The attached PubSub subsystem, or throws if enablePubSub() was never called.
  ::librats::PubSub& pubsub();

  /// The attached DhtDiscovery subsystem, or throws if enableDht() was never called.
  ::librats::DhtDiscovery& dht();

  /// Attached NAT-traversal subsystems, or throw if their enable was never called.
  ::librats::PortMappingService& portMapping();
  ::librats::HolePunch& holePunch();
  ::librats::Relay& relay();

  /// The attached MessageJson subsystem, or throws if enableJsonMessaging() was
  /// never called.
  ::librats::MessageJson& json();

  /// The attached StorageManager, or throws if enableStorage() was never called.
  ::librats::StorageManager& storage();

  std::unique_ptr<::librats::NodeConfig> config_;
  std::unique_ptr<::librats::Node> node_;
  ::librats::FileTransfer* files_ = nullptr;
  ::librats::PubSub* pubsub_ = nullptr;
  ::librats::DhtDiscovery* dht_ = nullptr;
  ::librats::MdnsDiscovery* mdns_ = nullptr;
  ::librats::PortMappingService* port_mapping_ = nullptr;
  ::librats::HolePunch* hole_punch_ = nullptr;
  ::librats::Relay* relay_ = nullptr;
  ::librats::MessageJson* json_ = nullptr;
  ::librats::StorageManager* storage_ = nullptr;
  ::librats::PeerExchange* pex_ = nullptr;
  ::librats::Bittorrent* bittorrent_ = nullptr;
  ::librats::PingService* ping_ = nullptr;
  ::librats::ReconnectionService* reconnect_ = nullptr;
  /// Info hashes added through this object, in order. The client owns Torrents on
  /// its reactor and hands out pointers that must not be touched off-thread, so
  /// enumerating them is not safe from here — but what *we* added is ours to track.
  std::vector<std::string> torrents_;
  bool started_ = false;
};

} // namespace margelo::nitro::librats
