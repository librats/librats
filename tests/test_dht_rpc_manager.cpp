#include <gtest/gtest.h>
#include "dht/rpc_manager.h"
#include "dht/observer.h"
#include "dht/transport.h"
#include "dht/krpc.h"

#include <chrono>
#include <utility>
#include <vector>

using namespace librats::dht;
using librats::Address;
using librats::KrpcMessage;
using librats::KrpcProtocol;
using librats::KrpcMessageType;
using librats::KrpcErrorCode;
using librats::NodeId;

namespace {

class RecordingTransport : public Transport {
public:
    std::vector<std::pair<Address, std::vector<uint8_t>>> sent;
    void send(const Address& to, const std::vector<uint8_t>& d) override { sent.emplace_back(to, d); }
};

// Minimal observer that just records which callback fired.
class TestObserver : public Observer {
public:
    using Observer::Observer;
    int responses = 0, timeouts = 0, shorts = 0;
    uint16_t last_rtt = 0;
    void on_response(const KrpcMessage&, uint16_t rtt, TimePoint) override { ++responses; last_rtt = rtt; }
    void on_timeout(TimePoint) override { ++timeouts; }
    void on_short_timeout(TimePoint) override { ++shorts; set(kShortTimeout); }
};

NodeId nid(uint8_t v) { NodeId id; id.fill(v); return id; }
TimePoint at(int sec) { return TimePoint{} + std::chrono::seconds(sec); }

std::string sent_txn(RecordingTransport& t, std::size_t i) {
    auto m = KrpcProtocol::decode_message(t.sent[i].second);
    return m ? m->transaction_id : std::string();
}

} // namespace

TEST(DhtRpcManager, InvokeSendsAndTracks) {
    RecordingTransport tp;
    RpcManager rpc(tp);
    const Address to("1.2.3.4", 6881);

    auto obs = std::make_shared<TestObserver>(nid(1), to);
    KrpcMessage q = KrpcProtocol::create_ping_query("", nid(0));
    EXPECT_TRUE(rpc.invoke(q, to, obs, at(0)));

    EXPECT_EQ(tp.sent.size(), 1u);
    EXPECT_EQ(tp.sent[0].first, to);
    EXPECT_EQ(rpc.outstanding(), 1u);
}

TEST(DhtRpcManager, ResponseDispatchesToObserver) {
    RecordingTransport tp;
    RpcManager rpc(tp);
    const Address to("1.2.3.4", 6881);

    auto obs = std::make_shared<TestObserver>(nid(1), to);
    KrpcMessage q = KrpcProtocol::create_ping_query("", nid(0));
    rpc.invoke(q, to, obs, at(0));

    KrpcMessage reply = KrpcProtocol::create_ping_response(sent_txn(tp, 0), nid(1));
    EXPECT_TRUE(rpc.handle_response(reply, to, at(0)));
    EXPECT_EQ(obs->responses, 1);
    EXPECT_EQ(obs->timeouts, 0);
    EXPECT_EQ(rpc.outstanding(), 0u);
}

TEST(DhtRpcManager, AntiSpoofRejectsWrongSource) {
    RecordingTransport tp;
    RpcManager rpc(tp);
    const Address to("1.2.3.4", 6881);
    const Address impostor("9.9.9.9", 6881);

    auto obs = std::make_shared<TestObserver>(nid(1), to);
    KrpcMessage q = KrpcProtocol::create_ping_query("", nid(0));
    rpc.invoke(q, to, obs, at(0));

    KrpcMessage reply = KrpcProtocol::create_ping_response(sent_txn(tp, 0), nid(1));
    EXPECT_FALSE(rpc.handle_response(reply, impostor, at(0)));  // right txn, wrong source
    EXPECT_EQ(obs->responses, 0);
    EXPECT_EQ(rpc.outstanding(), 1u);                           // still pending
}

TEST(DhtRpcManager, UnknownTransactionIgnored) {
    RecordingTransport tp;
    RpcManager rpc(tp);
    const Address to("1.2.3.4", 6881);

    KrpcMessage reply = KrpcProtocol::create_ping_response(std::string("\x12\x34", 2), nid(1));
    EXPECT_FALSE(rpc.handle_response(reply, to, at(0)));
}

TEST(DhtRpcManager, ErrorReplyCountsAsTimeout) {
    RecordingTransport tp;
    RpcManager rpc(tp);
    const Address to("1.2.3.4", 6881);

    auto obs = std::make_shared<TestObserver>(nid(1), to);
    KrpcMessage q = KrpcProtocol::create_ping_query("", nid(0));
    rpc.invoke(q, to, obs, at(0));

    KrpcMessage err = KrpcProtocol::create_error(sent_txn(tp, 0), KrpcErrorCode::ServerError, "nope");
    EXPECT_TRUE(rpc.handle_response(err, to, at(0)));
    EXPECT_EQ(obs->responses, 0);
    EXPECT_EQ(obs->timeouts, 1);   // an error means the query failed
    EXPECT_EQ(rpc.outstanding(), 0u);
}

TEST(DhtRpcManager, ShortThenFullTimeout) {
    RecordingTransport tp;
    RpcManager rpc(tp);
    const Address to("1.2.3.4", 6881);

    auto obs = std::make_shared<TestObserver>(nid(1), to);
    KrpcMessage q = KrpcProtocol::create_ping_query("", nid(0));
    rpc.invoke(q, to, obs, at(0));

    rpc.tick(at(1));                       // before the short timeout: nothing
    EXPECT_EQ(obs->shorts, 0);

    rpc.tick(at(3));                       // past 2s short timeout: slot freed, still waiting
    EXPECT_EQ(obs->shorts, 1);
    EXPECT_EQ(rpc.outstanding(), 1u);

    rpc.tick(at(5));                       // does not re-fire the short timeout
    EXPECT_EQ(obs->shorts, 1);

    rpc.tick(at(16));                      // past 15s full timeout: gives up
    EXPECT_EQ(obs->timeouts, 1);
    EXPECT_EQ(rpc.outstanding(), 0u);
}
