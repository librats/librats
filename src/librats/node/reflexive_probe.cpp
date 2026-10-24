#include "librats/node/reflexive_probe.h"
#include "librats/nat/stun.h"

#include <algorithm>
#include <cstring>

namespace librats {

std::optional<Address> ReflexiveProbe::udp_endpoint(const Address& server,
                                                    std::chrono::milliseconds timeout) {
    const StunMessage request(StunMessageType::BindingRequest);
    const Bytes datagram = request.serialize();
    const TransactionId id = request.transaction_id;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        waiting_[id];
    }

    std::optional<Address> answer;
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    for (;;) {
        if (!send_(server, datagram)) break;
        const auto repeat = (std::min)(std::chrono::steady_clock::now() + kRepeat, deadline);
        std::unique_lock<std::mutex> lock(mutex_);
        if (answered_.wait_until(lock, repeat, [&] { return waiting_[id].has_value(); })) {
            answer = waiting_[id];
            break;
        }
        if (repeat >= deadline) break;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    waiting_.erase(id);
    return answer;
}

void ReflexiveProbe::on_datagram(ByteView datagram, const Address& /*from*/) {
    // Anyone's datagram: the cookie first, before anything is copied.
    if (datagram.size() < STUN_HEADER_SIZE) return;
    uint32_t cookie = 0;
    for (size_t i = 4; i < 8; ++i) cookie = (cookie << 8) | datagram.data()[i];
    if (cookie != STUN_MAGIC_COOKIE) return;

    const std::optional<StunMessage> message = StunMessage::deserialize(datagram.to_bytes());
    if (!message || !message->is_success_response()) return;
    std::optional<StunMappedAddress> mapped = message->get_xor_mapped_address();
    if (!mapped) mapped = message->get_mapped_address();
    if (!mapped || !mapped->is_valid()) return;
    const std::optional<IpAddress> ip = IpAddress::parse(mapped->address);
    if (!ip) return;

    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = waiting_.find(message->transaction_id);
    if (it == waiting_.end() || it->second) return;
    it->second = Address{*ip, mapped->port};
    answered_.notify_all();
}

} // namespace librats
