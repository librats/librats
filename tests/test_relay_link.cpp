#include <gtest/gtest.h>

#include "librats/core/io_poller.h"      // PollIn / PollOut / PollErr
#include "librats/security/identity.h"
#include "librats/security/noise_security.h"
#include "librats/transport/reactor.h"
#include "librats/transport/relay_link.h"

#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace librats;

namespace {

/// A carrier that records instead of sending, and can be told to report its send
/// queue as full — which is the whole of what a real carrier ever tells a circuit.
class FakeCarrier final : public CircuitCarrier {
public:
    struct Sent {
        uint32_t circuit;
        Bytes    payload;
    };

    std::vector<Sent>     data;
    std::vector<uint32_t> credits;
    std::vector<CloseReason> closes;
    int                   released = 0;
    /// What circuit_send_data answers: false is "queued, but stop and wait".
    bool                  has_room = true;

    bool circuit_send_data(uint32_t circuit, const ByteView* slices, size_t count) override {
        Bytes joined;
        for (size_t i = 0; i < count; ++i)
            joined.insert(joined.end(), slices[i].begin(), slices[i].end());
        data.push_back(Sent{circuit, std::move(joined)});
        return has_room;
    }
    void circuit_send_credit(uint32_t, uint32_t bytes) override { credits.push_back(bytes); }
    void circuit_send_close(uint32_t, CloseReason reason) override { closes.push_back(reason); }
    void circuit_released(uint32_t) override { ++released; }

    /// Everything handed over so far, in order — the far end's view of the stream.
    Bytes stream() const {
        Bytes all;
        for (const Sent& s : data) all.insert(all.end(), s.payload.begin(), s.payload.end());
        return all;
    }
};

/// A circuit that is already open — the inbound case, where the far end's request
/// carried the window it will receive. `peer_window` is that window.
struct Fixture {
    std::shared_ptr<FakeCarrier> carrier = std::make_shared<FakeCarrier>();
    std::shared_ptr<Circuit>     circuit;

    explicit Fixture(uint32_t peer_window = Circuit::kDefaultWindow,
                     uint32_t recv_window = Circuit::kDefaultWindow)
        : circuit(Circuit::accepted(7, carrier, peer_window, recv_window)) {}
};

/// The outbound case: opened and waiting for the far end to accept.
struct PendingFixture {
    std::shared_ptr<FakeCarrier> carrier = std::make_shared<FakeCarrier>();
    std::shared_ptr<Circuit>     circuit;

    explicit PendingFixture(uint32_t recv_window = Circuit::kDefaultWindow)
        : circuit(Circuit::opening(7, carrier, recv_window)) {}
};

Bytes pattern(size_t n, uint8_t seed = 0) {
    Bytes b(n);
    for (size_t i = 0; i < n; ++i) b[i] = static_cast<uint8_t>((i + seed) & 0xFF);
    return b;
}

/// Write `data` the way Connection::flush does: keep going while the link reports
/// Ok, stop on WouldBlock. Returns how much the link took.
size_t write_all(Circuit& circuit, const Bytes& data) {
    size_t written = 0;
    while (written < data.size()) {
        const ByteView slice(data.data() + written, data.size() - written);
        const Link::IoResult r = circuit.write(&slice, 1);
        if (r.status != Link::Status::Ok) break;
        if (r.bytes == 0) break;
        written += r.bytes;
    }
    return written;
}

/// Read the way Connection::on_readable does: drain to would-block (or the end).
Bytes read_all(Circuit& circuit, Link::Status& final_status) {
    Bytes out;
    uint8_t buffer[4096];
    while (true) {
        const Link::IoResult r = circuit.read(ByteSpan(buffer, sizeof(buffer)));
        if (r.status != Link::Status::Ok) { final_status = r.status; return out; }
        out.insert(out.end(), buffer, buffer + r.bytes);
    }
}

} // namespace

// An outbound circuit is not a byte stream yet — it is a request. Until the far end
// accepts, nothing may go out, and the Connection holding it stays in Connecting.
// This is exactly the shape of a non-blocking connect, which is why the Connection
// needs no special case for it.
TEST(CircuitTest, NothingFlowsUntilTheFarEndAccepts) {
    PendingFixture f;

    const Bytes payload = pattern(64);
    const ByteView slice(payload);
    EXPECT_EQ(f.circuit->write(&slice, 1).status, Link::Status::WouldBlock);
    EXPECT_TRUE(f.carrier->data.empty());
    EXPECT_FALSE(f.circuit->is_open());

    // Acceptance is what the waiting Connection is woken by, and it carries the
    // window the far end is willing to receive.
    EXPECT_EQ(f.circuit->on_accept(4096), static_cast<uint32_t>(PollOut));
    EXPECT_TRUE(f.circuit->is_open());
    EXPECT_EQ(f.circuit->send_credit(), 4096u);

    EXPECT_EQ(write_all(*f.circuit, payload), payload.size());
    EXPECT_EQ(f.carrier->stream(), payload);
}

// A stream handed to the circuit comes out the other side byte for byte, split into
// messages no larger than one chunk. The splitting is the point: a relay forwards
// whole messages, so an unbounded one would pin its memory and its loop.
TEST(CircuitTest, TheStreamIsChoppedIntoBoundedChunksAndArrivesIntact) {
    Fixture f(/*peer_window=*/4 * 1024 * 1024);

    const Bytes payload = pattern(Circuit::kMaxDataChunk * 3 + 100);
    EXPECT_EQ(write_all(*f.circuit, payload), payload.size());

    EXPECT_EQ(f.carrier->data.size(), 4u) << "the stream was not split as expected";
    for (const auto& sent : f.carrier->data) {
        EXPECT_EQ(sent.circuit, 7u);
        EXPECT_LE(sent.payload.size(), Circuit::kMaxDataChunk);
    }
    EXPECT_EQ(f.carrier->stream(), payload);
}

// One write gathers across the caller's slices rather than emitting a message per
// slice. It matters because the send buffer hands out a four-byte length prefix and
// a body per queued frame — a message per slice would put half the traffic in
// four-byte messages.
TEST(CircuitTest, OneMessageGathersAcrossSeveralSlices) {
    Fixture f;

    const Bytes a = pattern(4, 1), b = pattern(1000, 2), c = pattern(4, 3);
    const ByteView slices[3]{ByteView(a), ByteView(b), ByteView(c)};

    const Link::IoResult r = f.circuit->write(slices, 3);
    EXPECT_EQ(r.status, Link::Status::Ok);
    EXPECT_EQ(r.bytes, a.size() + b.size() + c.size());
    ASSERT_EQ(f.carrier->data.size(), 1u) << "the slices did not travel as one message";
}

// The credit window is the bound on everything: what the far end may have in flight,
// and therefore what the relay in between can ever be holding. Running out has to
// stop the sender rather than make it drop or grow.
TEST(CircuitTest, RunningOutOfCreditStopsTheSenderUntilMoreIsGranted) {
    Fixture f(/*peer_window=*/1000);

    const Bytes payload = pattern(4000);
    EXPECT_EQ(write_all(*f.circuit, payload), 1000u) << "the sender wrote past its window";
    EXPECT_EQ(f.circuit->send_credit(), 0u);

    // The Connection has more queued, so it has asked to be told when it may write.
    f.circuit->want_write(true);
    EXPECT_EQ(f.circuit->on_credit(500), static_cast<uint32_t>(PollOut));

    const ByteView rest(payload.data() + 1000, payload.size() - 1000);
    const Link::IoResult r = f.circuit->write(&rest, 1);
    EXPECT_EQ(r.status, Link::Status::Ok);
    EXPECT_EQ(r.bytes, 500u) << "the sender did not stop at the new window either";
}

// A credit grant with nobody waiting for it must not wake the connection: a spurious
// writable event costs a whole pass over the send path for nothing.
TEST(CircuitTest, CreditRaisesNoEventWhenNothingIsWaitingToWrite) {
    Fixture f(/*peer_window=*/100);
    EXPECT_EQ(f.circuit->on_credit(100), 0u);

    // Even after a write ran out of credit, an unwanted write stays unwanted.
    const Bytes payload = pattern(500);
    write_all(*f.circuit, payload);
    EXPECT_EQ(f.circuit->on_credit(100), 0u) << "want_write was never asked for";
}

// The other half of backpressure: the carrier itself filling up. The bytes are
// queued either way — that is what PeerNetwork::send promises — so they count as
// written, and the circuit simply stops until the carrier says there is room.
TEST(CircuitTest, CarrierBackpressureStopsTheCircuitWithoutLosingBytes) {
    Fixture f;
    f.carrier->has_room = false;

    const Bytes payload = pattern(Circuit::kMaxDataChunk * 2);
    const size_t written = write_all(*f.circuit, payload);
    EXPECT_EQ(written, Circuit::kMaxDataChunk) << "the circuit kept writing into a full carrier";
    EXPECT_EQ(f.carrier->stream().size(), written) << "the chunk it did write was lost";

    f.circuit->want_write(true);
    f.carrier->has_room = true;
    EXPECT_EQ(f.circuit->on_carrier_writable(), static_cast<uint32_t>(PollOut));
    EXPECT_EQ(write_all(*f.circuit, Bytes(payload.begin() + written, payload.end())),
              payload.size() - written);
}

// Inbound bytes wait in the circuit until the connection reads them, and reading
// them is what returns the window to the far end — in batches, so the grant costs
// one small message per half-window rather than one per chunk.
TEST(CircuitTest, ReadingReturnsTheWindowInBatches) {
    Fixture f(/*peer_window=*/Circuit::kDefaultWindow, /*recv_window=*/1000);

    const Bytes first = pattern(400);
    EXPECT_EQ(f.circuit->on_data(ByteView(first)), static_cast<uint32_t>(PollIn));
    EXPECT_EQ(f.circuit->pending_input(), first.size());

    Link::Status status = Link::Status::Ok;
    EXPECT_EQ(read_all(*f.circuit, status), first);
    EXPECT_EQ(status, Link::Status::WouldBlock);
    EXPECT_TRUE(f.carrier->credits.empty()) << "credit was granted below the batch threshold";

    // Past half the window, the grant goes out — covering everything consumed so far.
    const Bytes second = pattern(200, 9);
    f.circuit->on_data(ByteView(second));
    read_all(*f.circuit, status);
    ASSERT_EQ(f.carrier->credits.size(), 1u);
    EXPECT_EQ(f.carrier->credits.front(), 600u);
}

// A far end that sends past the window it was granted is doing precisely the thing
// the window exists to prevent, so the circuit fails rather than buffering it. This
// is what keeps a relay's memory a matter of configuration rather than of goodwill.
TEST(CircuitTest, OverrunningTheReceiveWindowFailsTheCircuit) {
    Fixture f(/*peer_window=*/Circuit::kDefaultWindow, /*recv_window=*/100);

    EXPECT_EQ(f.circuit->on_data(ByteView(pattern(100))), static_cast<uint32_t>(PollIn));

    const Bytes flood = pattern(1);
    EXPECT_EQ(f.circuit->on_data(ByteView(flood)), static_cast<uint32_t>(PollErr));
    EXPECT_TRUE(f.circuit->is_closed());
    EXPECT_EQ(f.circuit->close_reason(), CloseReason::ProtocolError);
}

// An orderly close still owes the application everything the far end sent before
// it. Data and end-of-stream are never reported together (see Link::read), so the
// circuit drains first and only then says the stream is over.
TEST(CircuitTest, AnOrderlyCloseDeliversWhatArrivedBeforeIt) {
    Fixture f;

    const Bytes payload = pattern(128);
    f.circuit->on_data(ByteView(payload));
    EXPECT_EQ(f.circuit->on_closed(CloseReason::PeerClosed, /*orderly=*/true),
              static_cast<uint32_t>(PollIn));

    Link::Status status = Link::Status::Ok;
    EXPECT_EQ(read_all(*f.circuit, status), payload) << "buffered data was dropped by the close";
    EXPECT_EQ(status, Link::Status::Closed);
}

// A circuit that fails — the relay went away, the far end refused — has nothing
// worth flushing, and the connection has to hear the reason it failed with.
TEST(CircuitTest, AFailedCircuitReportsItsReasonAtOnce) {
    Fixture f;
    f.circuit->on_data(ByteView(pattern(16)));
    EXPECT_EQ(f.circuit->on_closed(CloseReason::PeerReset, /*orderly=*/false),
              static_cast<uint32_t>(PollErr));

    Link::Status status = Link::Status::Ok;
    read_all(*f.circuit, status);
    EXPECT_EQ(status, Link::Status::Error);
    EXPECT_EQ(f.circuit->close_reason(), CloseReason::PeerReset);
}

// Closing from our side tells the far end exactly once, however the teardown is
// driven — the reactor closes the link and then destroys it, and a second goodbye
// would be a message about a circuit that no longer exists.
TEST(CircuitTest, OurOwnCloseIsAnnouncedExactlyOnce) {
    Fixture f;
    f.circuit->shutdown(CloseReason::LocalClose);
    f.circuit->shutdown(CloseReason::PeerReset);

    ASSERT_EQ(f.carrier->closes.size(), 1u);
    EXPECT_EQ(f.carrier->closes.front(), CloseReason::LocalClose);
    EXPECT_TRUE(f.circuit->is_closed());
}

// The Link is the Connection's; the Circuit is shared with whoever drives the relay
// protocol. Destroying the Link is therefore the signal that the circuit will never
// be read or written again, and that its bookkeeping can go.
TEST(RelayLinkTest, DestroyingTheLinkReleasesTheCircuit) {
    Fixture f;
    {
        RelayLink link(f.circuit);
        EXPECT_EQ(link.kind(), TransportKind::Relay);
        EXPECT_TRUE(link.connect_completed());
        EXPECT_EQ(f.carrier->released, 0);
    }
    EXPECT_EQ(f.carrier->released, 1);
}

// A relayed link reports no endpoint of its own, and deliberately not the relay's:
// identify would pair that address with the peer's listen port and call the result
// dialable, and NatStatus would read it as our own NAT mapping. Both belong to the
// node in the middle, not to either end.
TEST(RelayLinkTest, ItHasNoEndpointOfItsOwn) {
    Fixture f;
    RelayLink link(f.circuit);
    EXPECT_FALSE(link.remote_endpoint().has_value());
    EXPECT_EQ(link.fd(), RATS_INVALID_SOCKET);
}

// The Link is a handle and nothing more — every call has to reach the shared state,
// or the module driving the protocol and the Connection would be looking at
// different circuits.
TEST(RelayLinkTest, ItIsAHandleOntoTheSharedCircuit) {
    Fixture f;
    RelayLink link(f.circuit);

    const Bytes payload = pattern(200);
    const ByteView slice(payload);
    EXPECT_EQ(link.write(&slice, 1).bytes, payload.size());
    EXPECT_EQ(f.carrier->stream(), payload);

    const Bytes inbound = pattern(50, 4);
    f.circuit->on_data(ByteView(inbound));
    uint8_t buffer[64];
    const Link::IoResult r = link.read(ByteSpan(buffer, sizeof(buffer)));
    EXPECT_EQ(r.status, Link::Status::Ok);
    EXPECT_EQ(Bytes(buffer, buffer + r.bytes), inbound);

    link.close(CloseReason::LocalClose);
    EXPECT_EQ(link.error_reason(), CloseReason::LocalClose);
    ASSERT_EQ(f.carrier->closes.size(), 1u);
}

// ── The plumbing, end to end ────────────────────────────────────────────────
//
// Everything above tests the circuit's own arithmetic. What follows tests the
// claim the whole design rests on: that a Connection cannot tell a circuit from a
// socket. Two reactors are given one circuit each, wired to each other by a pipe
// standing in for the relay, and the ordinary Noise_XX handshake is asked to run
// across it. Nothing here knows about relaying — the reactors adopt a Link, the
// connections do what they always do.

namespace {

/// The two ends of one relayed connection, joined by a pipe instead of a relay.
///
/// A real carrier hands bytes to a peer's connection and they come back out on the
/// far side's read path; here they are posted to the other end's reactor, which is
/// the same thing minus the network — and, importantly, the same threading: each
/// circuit is only ever touched by the reactor that owns it.
class LoopbackRelay final : public CircuitCarrier {
public:
    struct End {
        Reactor*                 reactor = nullptr;
        std::shared_ptr<Circuit> circuit;
        ConnId                   conn = kInvalidConnId;
    };

    End left, right;

    /// Circuit ids are what tell the two ends apart, exactly as they would on a
    /// carrier link shared by many circuits.
    static constexpr uint32_t kLeftId  = 1;
    static constexpr uint32_t kRightId = 2;

    bool circuit_send_data(uint32_t id, const ByteView* slices, size_t count) override {
        Bytes payload;
        for (size_t i = 0; i < count; ++i)
            payload.insert(payload.end(), slices[i].begin(), slices[i].end());
        deliver(id, [payload = std::move(payload)](End& dst) {
            return dst.circuit->on_data(ByteView(payload));
        });
        return true;
    }

    void circuit_send_credit(uint32_t id, uint32_t bytes) override {
        deliver(id, [bytes](End& dst) { return dst.circuit->on_credit(bytes); });
    }

    void circuit_send_close(uint32_t id, CloseReason) override {
        deliver(id, [](End& dst) {
            return dst.circuit->on_closed(CloseReason::PeerClosed, /*orderly=*/true);
        });
    }

    void circuit_released(uint32_t) override {}

private:
    End& other(uint32_t id) { return id == kLeftId ? right : left; }

    /// Run `fn` against the far end on ITS reactor thread, then hand the events it
    /// produced to that end's connection.
    template <typename F>
    void deliver(uint32_t id, F fn) {
        End& dst = other(id);
        if (!dst.reactor) return;
        dst.reactor->post([&dst, fn = std::move(fn)] {
            dst.reactor->wake(dst.conn, fn(dst));
        });
    }
};

/// Records what a connection did, and answers one frame with another.
class RecordingDelegate final : public ConnectionDelegate {
public:
    void on_established(Connection& conn) override {
        std::lock_guard<std::mutex> lock(mutex_);
        remote_ = conn.remote_id();
        transport_ = conn.transport();
        ++established_;
    }
    void on_frame(Connection&, const Frame& frame) override {
        std::lock_guard<std::mutex> lock(mutex_);
        received_.emplace_back(frame.payload.begin(), frame.payload.end());
    }
    void on_closed(Connection&, CloseReason reason) override {
        std::lock_guard<std::mutex> lock(mutex_);
        closed_reason_ = reason;
        ++closed_;
    }

    int           established() const { std::lock_guard<std::mutex> l(mutex_); return established_; }
    int           closed() const      { std::lock_guard<std::mutex> l(mutex_); return closed_; }
    PeerId        remote() const      { std::lock_guard<std::mutex> l(mutex_); return remote_; }
    TransportKind transport() const   { std::lock_guard<std::mutex> l(mutex_); return transport_; }
    std::vector<Bytes> received() const { std::lock_guard<std::mutex> l(mutex_); return received_; }
    CloseReason   close_reason() const { std::lock_guard<std::mutex> l(mutex_); return closed_reason_; }

private:
    mutable std::mutex mutex_;
    int                established_ = 0;
    int                closed_ = 0;
    PeerId             remote_;
    TransportKind      transport_ = TransportKind::Tcp;
    std::vector<Bytes> received_;
    CloseReason        closed_reason_ = CloseReason::PeerClosed;
};

template <typename Pred>
bool wait_for(Pred pred, std::chrono::milliseconds timeout = std::chrono::seconds(10)) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return pred();
}

} // namespace

// The claim, tested: give two reactors a relayed byte stream and they build the
// same encrypted, authenticated connection they would over a socket — the full
// Noise_XX handshake, both peers' real identities, application frames in both
// directions. Not one line of the transport above the Link knows what it is
// running on, which is the entire reason relaying was put here.
TEST(CircuitPlumbingTest, AFullNoiseHandshakeRunsOverARelayedStream) {
    auto relay = std::make_shared<LoopbackRelay>();

    const Identity left_identity  = Identity::generate();
    const Identity right_identity = Identity::generate();
    NoiseSecurity  left_security(left_identity, "librats/test");
    NoiseSecurity  right_security(right_identity, "librats/test");

    RecordingDelegate left_delegate, right_delegate;
    // Declared after the relay so they are destroyed first: stopping a reactor
    // drains its tasks, and those tasks name the relay.
    Reactor left_reactor(0, left_delegate, left_security);
    Reactor right_reactor(1, right_delegate, right_security);
    left_reactor.start();
    right_reactor.start();

    // The end that opens the circuit: pending until the far end accepts, exactly
    // like a non-blocking connect that has not completed.
    relay->left.reactor = &left_reactor;
    relay->left.circuit = Circuit::opening(LoopbackRelay::kLeftId, relay);
    relay->left.conn    = left_reactor.reserve_conn_id();
    left_reactor.adopt_link(relay->left.conn, std::make_unique<RelayLink>(relay->left.circuit),
                            ConnRole::Outbound, /*connected=*/false);

    // The end it was opened to: already there, and already told what the opener
    // will receive, so its stream is live from the first instant.
    relay->right.reactor = &right_reactor;
    relay->right.circuit = Circuit::accepted(LoopbackRelay::kRightId, relay,
                                             relay->left.circuit->recv_window());
    relay->right.conn    = right_reactor.reserve_conn_id();
    right_reactor.adopt_link(relay->right.conn, std::make_unique<RelayLink>(relay->right.circuit),
                             ConnRole::Inbound, /*connected=*/true);

    // The acceptance coming back is what finishes the opener's "connect" and lets
    // its handshake start.
    const uint32_t peer_window = relay->right.circuit->recv_window();
    left_reactor.post([&] {
        left_reactor.wake(relay->left.conn, relay->left.circuit->on_accept(peer_window));
    });

    ASSERT_TRUE(wait_for([&] {
        return left_delegate.established() == 1 && right_delegate.established() == 1;
    })) << "the handshake never completed over the circuit";

    // Each end authenticated the other's real key — the pipe in the middle could
    // not have produced this, which is the whole point of handshaking end to end.
    EXPECT_EQ(left_delegate.remote(), right_identity.id);
    EXPECT_EQ(right_delegate.remote(), left_identity.id);
    EXPECT_EQ(left_delegate.transport(), TransportKind::Relay);
    EXPECT_EQ(right_delegate.transport(), TransportKind::Relay);

    // And frames flow both ways, encrypted per connection as usual.
    const std::string ping = "ping over the circuit";
    const std::string pong = "pong over the circuit";
    left_reactor.post([&] {
        if (auto* c = left_reactor.find(relay->left.conn))
            c->send(FrameHeader{MessageType::App, 0, 42}, ByteView(ping));
    });
    ASSERT_TRUE(wait_for([&] { return right_delegate.received().size() == 1; }))
        << "the frame never arrived at the far end";
    EXPECT_EQ(Bytes(ping.begin(), ping.end()), right_delegate.received().front());

    right_reactor.post([&] {
        if (auto* c = right_reactor.find(relay->right.conn))
            c->send(FrameHeader{MessageType::App, 0, 42}, ByteView(pong));
    });
    ASSERT_TRUE(wait_for([&] { return left_delegate.received().size() == 1; }))
        << "the reply never came back";
    EXPECT_EQ(Bytes(pong.begin(), pong.end()), left_delegate.received().front());

    // Closing one end tells the other, and the far end sees an ordinary clean close
    // rather than a broken link.
    left_reactor.close(relay->left.conn, CloseReason::LocalClose);
    ASSERT_TRUE(wait_for([&] { return right_delegate.closed() == 1; }))
        << "the far end was never told the circuit ended";
    EXPECT_EQ(right_delegate.close_reason(), CloseReason::PeerClosed);

    left_reactor.stop();
    right_reactor.stop();
}

// A payload far larger than one chunk and larger than the window has to arrive
// whole and in order: the credit scheme has to be a brake, never a filter. This is
// the case where the sender genuinely outruns the window and has to be paced by
// grants coming back from the far end's reads.
TEST(CircuitPlumbingTest, ABulkTransferIsPacedByTheWindowAndArrivesIntact) {
    auto relay = std::make_shared<LoopbackRelay>();

    const Identity left_identity  = Identity::generate();
    const Identity right_identity = Identity::generate();
    NoiseSecurity  left_security(left_identity, "librats/test");
    NoiseSecurity  right_security(right_identity, "librats/test");

    RecordingDelegate left_delegate, right_delegate;
    Reactor left_reactor(0, left_delegate, left_security);
    Reactor right_reactor(1, right_delegate, right_security);
    left_reactor.start();
    right_reactor.start();

    // A deliberately small window, so the transfer below has to be paced by credit
    // rather than sailing through on the first grant.
    constexpr uint32_t kWindow = 32 * 1024;

    relay->left.reactor = &left_reactor;
    relay->left.circuit = Circuit::opening(LoopbackRelay::kLeftId, relay, kWindow);
    relay->left.conn    = left_reactor.reserve_conn_id();
    left_reactor.adopt_link(relay->left.conn, std::make_unique<RelayLink>(relay->left.circuit),
                            ConnRole::Outbound, false);

    relay->right.reactor = &right_reactor;
    relay->right.circuit = Circuit::accepted(LoopbackRelay::kRightId, relay, kWindow, kWindow);
    relay->right.conn    = right_reactor.reserve_conn_id();
    right_reactor.adopt_link(relay->right.conn, std::make_unique<RelayLink>(relay->right.circuit),
                             ConnRole::Inbound, true);

    left_reactor.post([&] {
        left_reactor.wake(relay->left.conn, relay->left.circuit->on_accept(kWindow));
    });
    ASSERT_TRUE(wait_for([&] {
        return left_delegate.established() == 1 && right_delegate.established() == 1;
    }));

    // Twenty frames of 64 KiB: forty times the window, so the sender stalls on
    // credit repeatedly and only the grants coming back keep it moving.
    constexpr int    kFrames    = 20;
    constexpr size_t kFrameSize = 64 * 1024;
    const Bytes      payload    = pattern(kFrameSize, 0x5A);
    left_reactor.post([&] {
        auto* c = left_reactor.find(relay->left.conn);
        ASSERT_NE(c, nullptr);
        for (int i = 0; i < kFrames; ++i)
            c->send(FrameHeader{MessageType::App, 0, 7}, ByteView(payload));
    });

    ASSERT_TRUE(wait_for([&] {
        return right_delegate.received().size() == static_cast<size_t>(kFrames);
    })) << "the transfer stalled: " << right_delegate.received().size() << " of " << kFrames
        << " frames arrived";

    for (const Bytes& frame : right_delegate.received())
        ASSERT_EQ(frame, payload) << "a frame arrived corrupted or out of order";

    left_reactor.stop();
    right_reactor.stop();
}
