#pragma once

/**
 * @file reflexive_probe.h
 * @brief Where a STUN server sees the shared datagram socket: the endpoint a NAT
 *        maps it to, which is the one a peer has to dial.
 *
 * A node behind a NAT announces itself somewhere (the DHT) for peers to dial. The
 * address there has to be the one the NAT maps the node's *shared* datagram socket
 * to — every UDP peer's packets go out of that socket, through one mapping. A NAT
 * that keeps the port as it is makes that the listen port; most carrier-grade NATs
 * do not, and only someone outside can say which it picked. NatStatus learns it
 * from peers already connected; a node no peer has reached yet asks STUN — from
 * that very socket, or the answer is about another socket's mapping.
 *
 * So the request goes out through the mux (UdpMux::send_foreign) and the answer
 * comes back with every other datagram of another protocol (UdpMux::on_foreign),
 * matched by its transaction id: 96 random bits, which is what makes a forged
 * answer — the datagram can come from anyone — a guess.
 *
 * Published in the node's ServiceRegistry as ReflexiveAddressService. Threading:
 * on_datagram() runs on the mux's reactor thread; udp_endpoint() blocks the caller,
 * a thread of its own (a discovery loop), never a reactor's.
 */

#include "librats/core/address.h"
#include "librats/core/bytes.h"
#include "librats/util/rats_export.h"

#include <array>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>

namespace librats {

class ReflexiveAddressService {
public:
    virtual ~ReflexiveAddressService() = default;

    /// Where the STUN server at `server` (numeric) sees the shared datagram socket:
    /// the endpoint a peer dials. Blocks until the answer, `timeout` at most;
    /// nullopt without a datagram socket or an answer. Never from a reactor thread.
    virtual std::optional<Address> udp_endpoint(const Address& server,
                                                std::chrono::milliseconds timeout) = 0;
};

class RATS_API ReflexiveProbe final : public ReflexiveAddressService {
public:
    /// A request unanswered this long is sent again, as RFC 8489 does (at first).
    static constexpr std::chrono::milliseconds kRepeat{500};

    /// `send` puts a datagram on the shared socket; false when there is none.
    using Send = std::function<bool(const Address& to, Bytes datagram)>;
    explicit ReflexiveProbe(Send send) : send_(std::move(send)) {}

    std::optional<Address> udp_endpoint(const Address& server,
                                        std::chrono::milliseconds timeout) override;

    /// A datagram of another protocol from the shared socket: an answer, maybe.
    void on_datagram(ByteView datagram, const Address& from);

private:
    using TransactionId = std::array<uint8_t, 12>;

    Send                                         send_;
    std::mutex                                   mutex_;
    std::condition_variable                      answered_;
    std::map<TransactionId, std::optional<Address>> waiting_;  ///< by request
};

} // namespace librats
