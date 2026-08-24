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

  std::unique_ptr<::librats::NodeConfig> config_;
  std::unique_ptr<::librats::Node> node_;
  ::librats::FileTransfer* files_ = nullptr;
  ::librats::PubSub* pubsub_ = nullptr;
  bool started_ = false;
};

} // namespace margelo::nitro::librats
