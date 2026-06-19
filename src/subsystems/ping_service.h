#pragma once

/**
 * @file ping_service.h
 * @brief Liveness + round-trip-time probing, built purely on PeerNetwork.
 *
 * The first real subsystem on the redesigned plugin model — and the template for
 * porting the larger ones. It depends on NOTHING but the PeerNetwork contract:
 * no Node, no reactor internals, no `friend`. Its own thread periodically pings
 * every connected peer; a peer echoes the probe back, letting the sender measure
 * RTT. Easily mocked by handing it a fake PeerNetwork in tests.
 *
 * Wire format (MessageType::Ping payload): [tag:u8][token:8 bytes].
 *   tag 0 = ping, tag 1 = pong. The 8 token bytes are echoed back verbatim, so
 *   the original sender decodes them in its own format (endianness irrelevant).
 */

#include "node/peer_network.h"
#include "node/peer.h"
#include "net/peer_id.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <optional>
#include <thread>
#include <unordered_map>

namespace librats {

class PingService final : public Subsystem {
public:
    explicit PingService(std::chrono::milliseconds interval = std::chrono::seconds(10));
    ~PingService() override;

    void attach(PeerNetwork& network) override;
    void start() override;
    void stop() override;

    /// Most recent measured round-trip time to a peer, if one has been seen.
    std::optional<std::chrono::milliseconds> last_rtt(const PeerId& id) const;

    /// Number of peers we have received at least one pong from.
    size_t alive_peer_count() const;

private:
    void run();                                       ///< own thread: ping loop
    void handle(const PeerHandle& peer, ByteView payload);
    void ping_all();

    PeerNetwork*              network_ = nullptr;
    std::chrono::milliseconds interval_;

    std::thread             thread_;
    std::atomic<bool>       running_{false};
    std::mutex              wait_mutex_;
    std::condition_variable wake_;

    mutable std::mutex mutex_;
    std::unordered_map<PeerId, std::chrono::milliseconds, PeerId::Hash> rtt_;
};

} // namespace librats
