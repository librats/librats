#include <gtest/gtest.h>

#include "librats/crypto/noise.h"
#include "librats/security/noise_security.h"
#include "librats/security/plaintext_security.h"
#include "librats/transport/stream_transport.h"

#include <deque>
#include <memory>
#include <string>
#include <vector>

using namespace librats;

namespace {

/// One direction of an in-memory byte stream.
struct Pipe {
    std::deque<uint8_t> bytes;
    bool                closed = false;
};

/// A Link over two pipes, with a write budget a test can close and reopen to play
/// a peer that has stopped reading.
class MemoryLink final : public Link {
public:
    MemoryLink(std::shared_ptr<Pipe> in, std::shared_ptr<Pipe> out) : in_(std::move(in)), out_(std::move(out)) {}

    TransportKind kind() const noexcept override { return TransportKind::Tcp; }

    IoResult read(ByteSpan into) override {
        if (in_->bytes.empty()) return {0, in_->closed ? Status::Closed : Status::WouldBlock};
        const size_t n = (std::min)(into.size(), in_->bytes.size());
        std::copy(in_->bytes.begin(), in_->bytes.begin() + static_cast<std::ptrdiff_t>(n), into.data());
        in_->bytes.erase(in_->bytes.begin(), in_->bytes.begin() + static_cast<std::ptrdiff_t>(n));
        return {n, Status::Ok};
    }

    IoResult write(const ByteView* slices, size_t count) override {
        size_t taken = 0;
        for (size_t i = 0; i < count && budget > 0; ++i) {
            const size_t n = (std::min)(slices[i].size(), budget);
            out_->bytes.insert(out_->bytes.end(), slices[i].begin(), slices[i].begin() + static_cast<std::ptrdiff_t>(n));
            budget -= n;
            taken  += n;
            if (n < slices[i].size()) break;
        }
        return {taken, taken ? Status::Ok : Status::WouldBlock};
    }

    bool connect_completed() override { return true; }
    void want_write(bool on) override { wants_write = on; }
    std::optional<Address> remote_endpoint() const override { return std::nullopt; }
    void close(CloseReason) override { out_->closed = true; }

    size_t budget      = SIZE_MAX;   ///< bytes write() still takes
    bool   wants_write = false;

private:
    std::shared_ptr<Pipe> in_, out_;
};

struct Received {
    MessageType type;
    uint16_t    channel;
    std::string payload;
};

class RecordingSink final : public TransportSink {
public:
    void transport_connected() override { connected = true; }
    void transport_established(const PeerId& id) override { remote = id; established = true; }
    bool transport_frame(const Frame& f) override {
        frames.push_back({f.header.type, f.header.channel,
                          std::string(f.payload.begin(), f.payload.end())});
        return true;
    }

    bool                  connected = false, established = false;
    PeerId                remote;
    std::vector<Received> frames;
};

/// Two StreamTransports joined by a pair of pipes, driven by hand.
struct Pair {
    Pair(SecurityProvider& a_sec, SecurityProvider& b_sec) {
        ab = std::make_shared<Pipe>();
        ba = std::make_shared<Pipe>();
        auto a_link = std::make_unique<MemoryLink>(ba, ab);
        auto b_link = std::make_unique<MemoryLink>(ab, ba);
        a_wire = a_link.get();
        b_wire = b_link.get();
        a = std::make_unique<StreamTransport>(std::move(a_link), ConnRole::Outbound, a_sec);
        b = std::make_unique<StreamTransport>(std::move(b_link), ConnRole::Inbound, b_sec);
        a->attach(1, a_sink);
        b->attach(2, b_sink);
    }

    /// Run both ends until neither has anything left to do.
    void pump() {
        for (int i = 0; i < 64; ++i) {
            ASSERT_TRUE(a->flush());
            ASSERT_TRUE(b->flush());
            ASSERT_TRUE(a->on_readable());
            ASSERT_TRUE(b->on_readable());
        }
    }

    void connect() {
        ASSERT_TRUE(b->start());
        ASSERT_TRUE(a->on_writable());   // the outbound side's connect completes
        pump();
        ASSERT_TRUE(a_sink.established && b_sink.established);
    }

    std::shared_ptr<Pipe>            ab, ba;   ///< a → b and b → a
    std::unique_ptr<StreamTransport> a, b;
    MemoryLink*  a_wire = nullptr;
    MemoryLink*  b_wire = nullptr;
    RecordingSink a_sink, b_sink;
};

} // namespace

TEST(StreamTransportTest, HandshakesAndCarriesMessagesBothWays) {
    Identity alice = Identity::generate(), bob = Identity::generate();
    NoiseSecurity a_sec(alice), b_sec(bob);
    Pair p(a_sec, b_sec);
    p.connect();
    EXPECT_TRUE(p.a_sink.connected && p.b_sink.connected);
    EXPECT_EQ(p.a_sink.remote, bob.id);
    EXPECT_EQ(p.b_sink.remote, alice.id);
    EXPECT_TRUE(p.a->is_secure());

    ASSERT_TRUE(p.a->send(FrameHeader{MessageType::App, 0, 9}, ByteView(std::string("hello")), {}));
    ASSERT_TRUE(p.a->send(FrameHeader{MessageType::App, 0, 9}, ByteView(std::string(70000, 'z')), {}));
    ASSERT_TRUE(p.b->send(FrameHeader{MessageType::Gossip, 0, 0}, ByteView(std::string("back")), {}));
    p.pump();

    ASSERT_EQ(p.b_sink.frames.size(), 2u);
    EXPECT_EQ(p.b_sink.frames[0].payload, "hello");
    EXPECT_EQ(p.b_sink.frames[0].channel, 9);
    EXPECT_EQ(p.b_sink.frames[1].payload, std::string(70000, 'z'));
    ASSERT_EQ(p.a_sink.frames.size(), 1u);
    EXPECT_EQ(p.a_sink.frames[0].type, MessageType::Gossip);
    // All written: what is left is the one small chunk the send buffer keeps for
    // re-use, not anything still owed to the peer.
    EXPECT_LE(p.a->backlog(), ChainedSendBuffer::kMaxRecycledCapacity)
        << "everything was written, yet memory is still held";
}

// The point of sealing late: a message queued behind a bulk backlog the link is not
// taking overtakes all of it except what was already sealed in front of the link.
TEST(StreamTransportTest, AnUrgentMessageOvertakesABacklogTheLinkHasNotTaken) {
    Identity alice = Identity::generate(), bob = Identity::generate();
    NoiseSecurity a_sec(alice), b_sec(bob);
    Pair p(a_sec, b_sec);
    p.connect();

    p.a_wire->budget = 0;   // the peer has stopped reading
    constexpr int    kChunks = 40;
    constexpr size_t kChunk  = 16 * 1024;
    for (int i = 0; i < kChunks; ++i)
        ASSERT_TRUE(p.a->send(FrameHeader{MessageType::FileChunk, 0, 0},
                              ByteView(std::string(kChunk, static_cast<char>('0' + i % 10))), {}));
    ASSERT_TRUE(p.a->flush());
    EXPECT_TRUE(p.a_wire->wants_write) << "a refused write must ask to be told when to retry";
    ASSERT_TRUE(p.a->send(FrameHeader{MessageType::Ping, 0, 0}, ByteView(std::string("ping")), {}));

    p.a_wire->budget = SIZE_MAX;   // and reads again
    ASSERT_TRUE(p.a->on_writable());
    p.pump();

    ASSERT_EQ(p.b_sink.frames.size(), static_cast<size_t>(kChunks + 1));
    size_t ping_at = 0;
    while (p.b_sink.frames[ping_at].type != MessageType::Ping) ++ping_at;
    // What was sealed before the ping existed is all it waits behind.
    constexpr size_t sealed_ahead = StreamTransport::kSealAhead / kChunk + 1;
    static_assert(sealed_ahead * 4 < kChunks, "the backlog must dwarf what is sealed ahead");
    EXPECT_LE(ping_at, sealed_ahead) << "the ping waited behind the unsealed backlog";
    // And the bulk lane itself still arrived whole and in order.
    int expected = 0;
    for (const auto& f : p.b_sink.frames) {
        if (f.type != MessageType::FileChunk) continue;
        EXPECT_EQ(f.payload, std::string(kChunk, static_cast<char>('0' + expected % 10)));
        ++expected;
    }
    EXPECT_EQ(expected, kChunks);
}

// The shape that hung bench_transport over real TCP paths while app channels were
// separate lanes: data on one channel, then a "flush" on another that the peer
// answers with its final count. Held behind a link that is not taking anything,
// the flush must still arrive after every byte of data.
TEST(StreamTransportTest, AMarkerOnAnotherChannelArrivesBehindTheDataBeforeIt) {
    Identity alice = Identity::generate(), bob = Identity::generate();
    NoiseSecurity a_sec(alice), b_sec(bob);
    Pair p(a_sec, b_sec);
    p.connect();

    p.a_wire->budget = 4096;   // the kernel takes a little, then stops
    constexpr int kData = 2000;
    for (int i = 0; i < kData; ++i)
        ASSERT_TRUE(p.a->send(FrameHeader{MessageType::App, 0, 1}, ByteView(std::string(256, 'd')), {}));
    ASSERT_TRUE(p.a->flush());
    ASSERT_TRUE(p.a->send(FrameHeader{MessageType::App, 0, 2}, ByteView(std::string("flush")), {}));
    ASSERT_TRUE(p.a->flush());

    p.a_wire->budget = SIZE_MAX;
    ASSERT_TRUE(p.a->on_writable());
    p.pump();

    ASSERT_EQ(p.b_sink.frames.size(), static_cast<size_t>(kData + 1));
    EXPECT_EQ(p.b_sink.frames.back().payload, "flush") << "the marker overtook the data it closes";
}

TEST(StreamTransportTest, ACorruptedBlockBreaksTheTransportAsAProtocolError) {
    Identity alice = Identity::generate(), bob = Identity::generate();
    NoiseSecurity a_sec(alice), b_sec(bob);
    Pair p(a_sec, b_sec);
    p.connect();

    ASSERT_TRUE(p.a->send(FrameHeader{MessageType::App, 0, 0}, ByteView(std::string("intact")), {}));
    ASSERT_TRUE(p.a->send(FrameHeader{MessageType::App, 0, 0}, ByteView(std::string("tampered")), {}));
    ASSERT_TRUE(p.a->flush());
    // The second block still frames, but one byte of its tag is wrong.
    p.ab->bytes.back() ^= 0x01;

    EXPECT_FALSE(p.b->on_readable());
    EXPECT_EQ(p.b->error_reason(), CloseReason::ProtocolError);
    ASSERT_EQ(p.b_sink.frames.size(), 1u) << "what authenticated before it must still be delivered";
    EXPECT_EQ(p.b_sink.frames[0].payload, "intact");
}

TEST(StreamTransportTest, DeliversWhatArrivedBeforeTheFinAndThenReportsTheClose) {
    Identity alice = Identity::generate(), bob = Identity::generate();
    PlaintextSecurity a_sec(alice), b_sec(bob);
    Pair p(a_sec, b_sec);
    p.connect();
    EXPECT_FALSE(p.a->is_secure());

    ASSERT_TRUE(p.a->send(FrameHeader{MessageType::App, 0, 0}, ByteView(std::string("last words")), {}));
    ASSERT_TRUE(p.a->flush());
    p.a->close(CloseReason::LocalClose);

    // The read that brings the bytes delivers them; the one after finds the end.
    EXPECT_TRUE(p.b->on_readable());
    ASSERT_EQ(p.b_sink.frames.size(), 1u);
    EXPECT_EQ(p.b_sink.frames[0].payload, "last words");
    EXPECT_FALSE(p.b->on_readable());
    EXPECT_EQ(p.b->error_reason(), CloseReason::PeerClosed);
}

TEST(StreamTransportTest, RefusesNothingItCanCarryAndReportsWhatItCannot) {
    Identity alice = Identity::generate(), bob = Identity::generate();
    NoiseSecurity a_sec(alice), b_sec(bob);
    Pair p(a_sec, b_sec);
    p.connect();
    EXPECT_EQ(p.a->max_payload(),
              framer::kMaxBlockSize - framer::kHeaderSize - librats::NOISE_TAG_SIZE);
}
