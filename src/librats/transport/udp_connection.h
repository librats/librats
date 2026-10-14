#pragma once

/**
 * @file udp_connection.h
 * @brief One peer over the shared datagram socket: handshake, packets, streams.
 *
 * This is the datagram transport proper — the QUIC-shaped protocol of
 * udp_wire.h, run for one peer. What it gives the layers above is what a
 * StreamTransport gives them over TCP: a peer proven by the Noise handshake and
 * whole messages each way. What it does differently is the point of it:
 *
 *   - Every packet is sealed on its own, its number the nonce, so a lost packet
 *     costs only what it carried. What it carried is sent again in a new packet.
 *   - Messages travel on streams, one per lane (MessageType). A hole in one holds
 *     up only that one: a ping is not stuck behind a lost piece of a file.
 *   - Which lane goes next is decided as each packet is built, not when the
 *     message was queued, so priority holds however deep the backlog is.
 *   - Live messages (SendOptions::lifetime) travel outside the streams, repaired
 *     only while they can still arrive in time and dropped whole once they
 *     cannot (udp_live.h). They go at Priority::Live, nearest deadline first;
 *     on a path that loses packets, with repair symbols behind them that
 *     stand in for what is lost without a round trip (udp_fec.h).
 *
 * ── The handshake ────────────────────────────────────────────────────────────
 * Noise XX is three messages, carried in long-header packets (udp_wire.h):
 *
 *      dialer                                   responder
 *      Initial  #0  e                ──▶        (padded to kMaxDatagram)
 *                                    ◀──        Handshake #1  e, ee, s, es
 *      Handshake #2  s, se           ──▶
 *      ...and from here, short packets either way
 *
 * Neither side needs a timer of its own beyond the dialer's: the dialer repeats
 * its Initial (on the DialProfile's schedule) until it hears anything, and the
 * responder answers a repeated Initial by repeating its reply. The dialer has its
 * keys first and starts sending at once; it repeats its last message until a
 * short packet from the responder proves the responder has them too. A
 * responder that is established first (the plaintext handshake has no third
 * message) needs nothing more: the dialer's next Initial gets the reply again.
 *
 * Until the dialer has proved it can receive at its address — any packet after
 * its Initial does that — the responder sends at most kAmplificationFactor times
 * what it received, so a forged source address cannot turn the node into an
 * amplifier.
 *
 * ── Migration ────────────────────────────────────────────────────────────────
 * A connection is its pair of ids, not an address. A peer's address changes
 * under it — a NAT hands its socket a new mapping, a phone goes from Wi-Fi to
 * LTE — and the peer, which usually cannot tell, just goes on sending. So the
 * receiving side follows (RFC 9000 §9, cut down to what that needs):
 *
 *   - Where the peer is, its newest packet says: one that opens under our keys
 *     and is numbered above every packet before it moves the connection to the
 *     address it came from. A duplicate never does — a copy an attacker on the
 *     path sends from elsewhere is one — nor a packet overtaken on the way.
 *   - Sending follows at once, but the new address is asked (PATH_CHALLENGE) to
 *     prove the peer receives there, and until it has (PATH_RESPONSE), what goes
 *     to it is held to kAmplificationFactor times what came from it — so a
 *     forged move redirects nothing worth having to the forger's victim. An
 *     unanswered challenge moves the connection back to the last proven address,
 *     as does the peer's next packet from there.
 *   - What was learnt about the path stays, unless the IP changed: then it is
 *     another path, and once the peer is proven there the round trip and the
 *     controller start again (Recovery::on_new_path). The challenge tells the
 *     peer which it was, so its own estimate starts again too.
 *   - Before the handshake is confirmed nothing moves.
 *
 * The side that moved usually keeps sending and so shows itself. One that only
 * receives — a viewer — is shown by kQuietProbe: when the data stops coming it
 * speaks up, from wherever it now is. (UdpMux::nudge does the same at once when
 * the host sees its network change.)
 *
 * The host hears of every proven move (peer_moved), and the transport above of
 * that and of every challenge we answer (take_moved): a peer's view of our
 * address has changed, which identify is there to tell it.
 *
 * ── Ownership and threading ──────────────────────────────────────────────────
 * A connection belongs to the UdpMux and is touched only by its reactor thread;
 * no locks, no atomics. It reaches the wire and reports events through
 * UdpConnectionHost and never sees the socket, the reactor or the Connection.
 * Events are recorded by the host, not delivered inline, so a connection is
 * never destroyed underneath a call still running inside it. It never reads the
 * clock: every entry point takes `now`, which is what lets the path benchmark and
 * the tests drive it in virtual time.
 */

#include "librats/core/address.h"
#include "librats/core/bytes.h"
#include "librats/core/types.h"
#include "librats/peer/peer_id.h"
#include "librats/security/handshaker.h"
#include "librats/transport/priority.h"
#include "librats/transport/udp_live.h"
#include "librats/transport/udp_recovery.h"
#include "librats/transport/udp_streams.h"
#include "librats/transport/udp_wire.h"
#include "librats/wire/frame.h"

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

namespace librats {

class UdpConnection;

/// What a connection needs from its owner: the wire, somewhere to leave events,
/// and the secret its stateless resets are made from.
class UdpConnectionHost {
public:
    virtual ~UdpConnectionHost() = default;

    /// Room for one datagram of up to udp::kMaxDatagram bytes, written in place and
    /// handed back with send_datagram(). Good until that call.
    virtual uint8_t* datagram_buffer() = 0;

    /// Send the first `len` bytes of the room datagram_buffer() returned. Best
    /// effort by design: a datagram the socket refuses is indistinguishable from
    /// one the path drops, and recovery covers both.
    virtual void send_datagram(const Address& to, size_t len) = 0;

    /// Record PollIn / PollOut / PollErr for `conn`'s transport. Record only: they
    /// are dispatched once the current batch of datagrams or timers is done, so a
    /// handler that tears the connection down cannot free it under the code still
    /// walking it. Repeats within a batch are expected and may be coalesced.
    virtual void connection_events(UdpConnection& conn, uint32_t events) = 0;

    /// The stateless-reset token for our connection id `cid`: what a reset for it
    /// ends with, made from a secret only this node has (see udp_mux.cpp).
    virtual void reset_token(udp::Cid cid, uint8_t* out) = 0;

    /// `conn`'s peer has been proven at a new address, `conn.remote()` (see
    /// "Migration"). Called from inside the connection's packet handling: record,
    /// do not reenter it.
    virtual void peer_moved(UdpConnection& /*conn*/) {}
};

/// How one connection is set up.
struct UdpConnectionConfig {
    /// Bytes of flow-control window a receiver grows to by default: ~1.3 Gbit/s at
    /// 100 ms.
    static constexpr size_t kDefaultMaxWindow = 16 * 1024 * 1024;
    /// See max_unfinished.
    static constexpr size_t kDefaultMaxUnfinished = 32 * 1024 * 1024;

    CongestionAlgorithm congestion = CongestionAlgorithm::Bbr;
    /// How hard a dial retries its Initial (see DialProfile). Ignored inbound.
    DialProfile         dial;
    /// Ceiling on the flow-control window this side grants. Never below
    /// UdpConnection::kInitialWindow, which the peer may assume from the start.
    size_t              max_window = kDefaultMaxWindow;
    /// What out-of-order data is charged to, or none (a connection on its own).
    udp::UdpReceiveBudget* budget = nullptr;
    /// Bytes of unfinished messages one side may make the other hold, beyond the
    /// largest one. Flow control counts a byte as consumed once it is in order,
    /// but a message is delivered only whole — up to framer::kMaxBlockSize — and
    /// every stream can have one under way: without this a peer could start a
    /// maximal message on each of 255 streams and finish none. The largest is
    /// exempt so the streams never deadlock (it can always be finished); the rest
    /// together stay under this. The receiver enforces it, the sender keeps to it,
    /// so both ends must use the same value — a node always uses the default.
    size_t max_unfinished = kDefaultMaxUnfinished;
    /// Send live messages with repair symbols on a path that loses packets
    /// (udp_fec.h). Off only to measure what they are worth.
    bool live_fec = true;
};

class UdpConnection final : private udp::FrameSink {
public:
    using Clock = std::chrono::steady_clock;

    // ── Tunables ────────────────────────────────────────────────────────────

    /// How long an acknowledgement may wait for company. Only a pure ACK waits: a
    /// packet that opens or fills a hole is acknowledged at once, and any packet we
    /// send carries the ACK for free. Recovery assumes the same of the peer.
    static constexpr std::chrono::milliseconds kDelayedAck = udp::Recovery::kMaxAckDelay;
    /// Packets one burst may hold its acknowledgement for (see begin_burst).
    static constexpr int kMaxBurstAck = 64;
    /// Idle gap after which a packet goes out to prove we are still here — and to
    /// keep a NAT's mapping for the socket open.
    static constexpr std::chrono::seconds kKeepAlive{10};
    /// Silence from the peer that ends the connection: four keep-alives and more.
    static constexpr std::chrono::seconds kIdleTimeout{45};
    /// A peer that was streaming data and has gone quiet — for kQuietGaps of its
    /// usual gaps, and at least kQuietProbe — is sent a keep-alive, and again as
    /// often for kQuietSteady, then at doubling intervals up to kKeepAlive. If it
    /// is our address that changed (a phone gone to another network while it only
    /// listened), the peer cannot reach us until we say something from where we
    /// are now ("Migration"); a handover is over within a second or two. A peer
    /// whose messages are seconds apart is never quiet in this sense.
    static constexpr std::chrono::milliseconds kQuietProbe{250};
    static constexpr int                       kQuietGaps = 8;
    static constexpr std::chrono::seconds      kQuietSteady{2};

    /// The flow-control window both sides start with, which a sender may count on
    /// before it has heard a single MAX_DATA. ~80 Mbit/s at 100 ms — enough for
    /// most peers never to grow it, which keeps a slow one cheap.
    static constexpr uint64_t kInitialWindow = 1024 * 1024;
    /// Silence after which a grown window goes back to where it started: what it
    /// was grown for is over, and a large window is what the budget has to cover
    /// if a peer fills it with holes.
    static constexpr std::chrono::seconds kWindowDecay{10};

    /// The most a responder sends, per byte received, before the dialer has proved
    /// its address (RFC 9000 §8.1) — and either side to a peer's new address
    /// before the peer has proved it receives there.
    static constexpr uint64_t kAmplificationFactor = 3;
    /// Challenges sent to an address before it is given up on, each a doubling
    /// probe timeout after the last.
    static constexpr int kMaxPathChallenges = 3;
    /// Short packets kept while the keys to open them do not exist yet: the dialer
    /// sends its first data right behind its last handshake message, and on a path
    /// that reorders them the data would otherwise cost a round trip.
    static constexpr size_t kMaxEarlyPackets = 4;
    /// Times the dialer repeats its last handshake message before giving up on a
    /// responder that never shows it has its keys.
    static constexpr int kMaxConfirmAttempts = 8;
    /// Close codes. Anything but an orderly close reads as a reset at the far end.
    static constexpr uint64_t kCloseOrderly  = 0;
    static constexpr uint64_t kCloseAbort    = 1;
    static constexpr uint64_t kCloseProtocol = 2;
    static constexpr uint64_t kCloseRefused  = 3;

    /// A dialer: sends the Initial at once. `local` is our (even) connection id.
    static std::unique_ptr<UdpConnection> dial(UdpConnectionHost& host, SecurityProvider& security,
                                               const Address& remote, udp::Cid local,
                                               Clock::time_point now, UdpConnectionConfig config = {});

    /// A responder, from an Initial the mux has already admitted. `validated` says
    /// the dialer has proved its address (it brought back a Retry token). Sends
    /// nothing until answer(); nullptr when the Initial is not a handshake opening.
    static std::unique_ptr<UdpConnection> accept(UdpConnectionHost& host, SecurityProvider& security,
                                                 const Address& remote, const udp::LongPacket& initial,
                                                 size_t datagram_len, bool validated,
                                                 Clock::time_point now, UdpConnectionConfig config = {});

    ~UdpConnection() override;
    UdpConnection(const UdpConnection&) = delete;
    UdpConnection& operator=(const UdpConnection&) = delete;

    /// Send the responder's answer to the Initial it was accepted from.
    void answer(Clock::time_point now);

    // ── Identity ────────────────────────────────────────────────────────────

    udp::Cid       local_cid()  const noexcept { return local_cid_; }
    udp::Cid       remote_cid() const noexcept { return remote_cid_; }
    const Address& remote()     const noexcept { return remote_; }
    ConnRole       role()       const noexcept { return role_; }
    const PeerId&  remote_id()  const noexcept { return remote_id_; }
    bool           is_secure()  const noexcept { return session_ && session_->is_secure(); }

    ConnId conn_id() const noexcept { return conn_id_; }
    void   set_conn_id(ConnId id) noexcept { conn_id_ = id; }

    // ── Driven by the mux ───────────────────────────────────────────────────

    /// One datagram addressed to this connection, from `from`. It is decrypted in
    /// place.
    void on_datagram(uint8_t* data, size_t len, const Address& from, Clock::time_point now);

    /// Ask the peer whether it receives at `candidate` — where someone sent a
    /// packet of a connection the host forwards to this peer (udp_mux.h). Proven,
    /// the connection moves there when the answer comes from there. A no-op while
    /// another challenge runs.
    void probe_path(const Address& candidate, Clock::time_point now);
    /// Our own side of the path may have changed (the host's network did): send
    /// the peer something it answers, so it learns where we are now.
    void nudge(Clock::time_point now);
    /// The peer was proven at a new address, or told us it sees us at one, since
    /// the last call.
    bool take_moved() noexcept { return std::exchange(moved_, false); }

    /// Datagrams that arrived together are about to be handed over one by one. The
    /// ACK they owe is held until end_burst() and sent once, naming everything:
    /// the sender processes one ACK where it would have processed thirty. Past
    /// kMaxBurstAck packets it goes anyway, so a long burst keeps the window open.
    void begin_burst() noexcept { in_burst_ = true; }
    bool in_burst() const noexcept { return in_burst_; }
    void end_burst(Clock::time_point now);

    /// Timers: the loss timer, the pacer, delayed ACKs, the handshake's repeats,
    /// keep-alive and idle death.
    void tick(Clock::time_point now);

    /// When tick() next has something to do; nullopt for a dead connection, the
    /// clock epoch for "at once". Every mutating entry point re-reads it, so a
    /// deadline never moves earlier without the owner being told.
    std::optional<Clock::time_point> next_deadline() const noexcept;

    // ── Driven by the transport ─────────────────────────────────────────────

    /// Queue one message on its lane. False, queueing nothing, unless established.
    bool send_message(FrameHeader header, ByteView payload);
    /// Queue one live message, worth delivering until `deadline`; its payload is no
    /// larger than SendOptions::kMaxLivePayload. False, queueing nothing, unless
    /// established.
    bool send_live(FrameHeader header, ByteView payload, Clock::time_point deadline);

    /// Send what the windows and the pacer allow.
    void flush(Clock::time_point now);

    /// Hand every complete message to `fn(const Frame&)`, lanes in priority order
    /// and live messages at theirs, until it returns false. False when one is
    /// malformed — the connection then tells the peer and is dead with ProtocolError.
    template <typename Fn>
    bool deliver(Clock::time_point now, Fn&& fn);

    /// The application is done with this connection. An orderly close (LocalClose,
    /// PeerClosed) delivers everything queued first and then says goodbye; any
    /// other reason says goodbye at once.
    void close(CloseReason reason, Clock::time_point now);
    /// Say goodbye now and stop.
    void abort(Clock::time_point now) { fail(now, CloseReason::LocalClose, kCloseAbort); events_ = 0; }

    /// Ask for a PollOut each time sending frees queue space.
    void want_write(bool on) noexcept { want_write_ = on; }

    /// Nobody will read this connection again (its transport is gone, and it only
    /// lingers to hand over what it owes). What has arrived is dropped, and what
    /// still arrives is acknowledged and discarded, with no more window granted:
    /// an inbox nobody empties must not grow.
    void stop_reading();

    // ── State ───────────────────────────────────────────────────────────────

    /// A packet has come back from the peer: the path works.
    bool heard_from_peer() const noexcept { return heard_; }
    bool handshaking() const noexcept { return phase_ == Phase::Handshaking; }
    bool established() const noexcept { return phase_ == Phase::Established; }
    bool dead()        const noexcept { return phase_ == Phase::Dead; }
    /// Why it died (once dead()).
    CloseReason close_reason() const noexcept { return close_reason_; }
    /// Everything queued has been delivered and the goodbye, if one was asked
    /// for, has gone — what the mux lingers a released connection until.
    bool flushed() const noexcept;

    /// Bytes queued and not yet sent, first time or again, live messages included
    /// — not their repair symbols, which only fill time nothing else wants.
    size_t queued_bytes() const noexcept;
    PathStats path_stats() const noexcept;
    void      release_memory();

    const udp::Recovery& recovery() const noexcept { return recovery_; }
    /// The flow-control window this side currently grants.
    uint64_t receive_window() const noexcept { return recv_window_; }
    size_t   held_bytes() const noexcept { return account_.held; }
    /// Bytes arrived and not yet delivered: in order on every stream, and live
    /// messages complete or being put together.
    size_t   buffered_bytes() const noexcept;

private:
    enum class Phase { Handshaking, Established, Dead };

    /// One lane: the two halves of the stream for one MessageType.
    struct Lane {
        MessageType     type     = MessageType::App;
        uint8_t         priority = 0;
        udp::SendStream send;
        udp::RecvStream recv;
    };

    UdpConnection(UdpConnectionHost& host, SecurityProvider& security, const Address& remote,
                  ConnRole role, udp::Cid local, udp::Cid remote_cid, Clock::time_point now,
                  const UdpConnectionConfig& config);

    // — handshake —
    bool start_dial(Clock::time_point now);
    void send_initial(Clock::time_point now);
    void send_handshake_message(Clock::time_point now);
    void on_long(const udp::LongPacket& p, size_t len, Clock::time_point now);
    void consume_handshake(ByteView message, Clock::time_point now);
    void establish(std::unique_ptr<Session> session, const PeerId& remote, Clock::time_point now);
    void handshake_timer(Clock::time_point now);

    // — packets in —
    void on_short(uint8_t* data, size_t len, const Address& from, Clock::time_point now);
    bool is_reset(const uint8_t* data, size_t len) const noexcept;
    /// Apply one authenticated packet's frames; false on a protocol violation.
    bool apply_frames(const uint8_t* payload, size_t len, Clock::time_point now,
                      bool& ack_eliciting, bool& refused);
    bool on_stream(const udp::StreamFrame& f, Clock::time_point now, bool& refused);
    bool on_live(const udp::LiveFrame& f, Clock::time_point now, bool& refused);
    bool on_live_repair(const udp::LiveRepairFrame& f, Clock::time_point now, bool& refused);
    void on_data_blocked(uint64_t limit);

    // — migration —
    /// The handshake is confirmed and the peer proven somewhere: it may move.
    bool may_move() const noexcept;
    /// The peer's newest packet, `len` bytes, came from `to`.
    void move_to(const Address& to, size_t len, Clock::time_point now);
    void start_challenge(const Address& to, Clock::time_point now);
    void send_challenge(Clock::time_point now);
    void on_path_challenge(uint64_t data, uint8_t flags, Clock::time_point now);
    /// The peer answered the challenge: it receives where that went.
    void path_proven(Clock::time_point now);
    void path_timer(Clock::time_point now);
    /// Start what describes the path again: it is another one.
    void restart_path(Clock::time_point now);
    /// A packet of data came, `gap` after the one before it.
    void note_data_gap(Clock::duration gap, Clock::time_point now);

    // — acknowledgements we owe —
    bool is_duplicate(uint64_t pn) const noexcept;
    void record_received(uint64_t pn, Clock::time_point now);
    void on_ack_eliciting(bool urgent, Clock::time_point now);
    size_t ack_size(Clock::time_point now) const noexcept;
    uint8_t* write_ack(uint8_t* p, Clock::time_point now);
    void ack_sent() noexcept;
    void send_ack(Clock::time_point now);

    // — packets out —
    void   pump(Clock::time_point now);
    void   send_probe(Clock::time_point now);
    /// Build, seal and send one short packet. `data` lets it carry stream data;
    /// `probe` makes it ack-eliciting whatever it holds, past every window.
    /// `keepalive` sends a packet even with nothing in it, never ack-eliciting.
    size_t send_packet(Clock::time_point now, bool data, bool probe, bool force_ack,
                       bool keepalive = false);
    uint8_t* write_control(uint8_t* p, uint8_t* end, bool& eliciting);
    /// Stream data and live messages, in priority order.
    uint8_t* write_data(uint8_t* p, uint8_t* end, Clock::time_point now, bool& repair);
    uint8_t* write_lanes(uint8_t* p, uint8_t* end, size_t from, size_t to, bool& repair);
    /// `first`: nothing else of the packet's data is in it yet.
    uint8_t* write_live(uint8_t* p, uint8_t* end, Clock::time_point now, bool first, bool& repair);
    /// Write repair symbol `piece` as a LIVE_REPAIR frame at `p`, if it fits before
    /// `end`, and move `p` past it.
    bool     put_parity(uint8_t*& p, uint8_t* end, const udp::LiveSender::Piece& piece,
                        Clock::time_point now);
    /// Settle how the live message `piece` begins is protected (udp_live.h).
    void     protect_live(const udp::LiveSender::Piece& piece, Clock::time_point now);
    /// Repair symbols per block for a live message of `layout` due at `deadline`:
    /// enough that a block is lost with the path's loss rate seldom — rarely, if
    /// what the path loses could not be sent again in time.
    uint32_t live_repairs(const udp::fec::Layout& layout, Clock::time_point deadline,
                          Clock::time_point now);
    uint8_t* write_repeat(uint8_t* p, uint8_t* end, Clock::time_point now);
    bool   has_control() const noexcept;
    bool   has_sendable_data() const noexcept;
    bool   has_repairs() const noexcept;
    /// Repairs are owed, few enough to send without asking the pacer.
    bool   repairs_go_at_once() const noexcept;
    uint64_t new_data_budget() const noexcept;
    bool   amplification_allows(size_t bytes) const noexcept;
    /// The largest packet an unproven dialer has earned (kMaxDatagram once proven).
    size_t amplification_room() const noexcept;
    void   note_sent(size_t bytes) noexcept;
    /// Tell the peer, then die with `reason`.
    void   fail(Clock::time_point now, CloseReason reason, uint64_t code);
    void   send_close(Clock::time_point now, uint64_t code);
    /// The first bytes of a short packet: returns where its frames begin.
    size_t begin_packet(uint8_t* buf, uint64_t pn, size_t& pn_len) const noexcept;
    /// Pad, seal and mask a short packet whose frames end at `end`; its length.
    size_t seal_packet(uint8_t* buf, size_t header, size_t pn_len, uint8_t* end, uint64_t pn);
    /// Seal a short packet and send it to the peer.
    size_t finish_packet(uint8_t* buf, size_t header, size_t pn_len, uint8_t* end, uint64_t pn,
                         Clock::time_point now, bool eliciting, bool data, bool repair, bool probe);
    size_t estimate_packet(Clock::time_point now) const noexcept;

    // — flow control —
    void maybe_update_window(Clock::time_point now);
    /// Double the window (to its ceiling, budget permitting). True if it grew.
    bool grow_window();

    // — lanes —
    Lane*  lane_for(MessageType type, bool create);
    /// Stream bytes never sent, all lanes: what the peer's window holds back.
    uint64_t stream_unsent() const noexcept;
    /// What the one-way delay is taken to be: half the smoothed round trip. A live
    /// message that cannot arrive by its deadline at that is no longer sent.
    Clock::duration one_way() const noexcept;
    /// The unfinished-message bounds of every lane: their sum, the largest, the
    /// next largest, and whose is the largest (see max_unfinished).
    struct Spread {
        uint64_t    sum = 0, top = 0, second = 0;
        const Lane* top_lane = nullptr;
    };
    Spread spread() const noexcept;
    /// New bytes `lane` may send before the receiver would hold more of unfinished
    /// messages than max_unfinished allows.
    uint64_t unfinished_room(const Lane& lane, const Spread& s) const noexcept;
    /// Whether a STREAM frame just taken on `lane` leaves the peer within
    /// max_unfinished — what it agreed to.
    bool   unfinished_ok(const Lane& lane) const noexcept;

    // — FrameSink —
    void frames_acked(const RingBuffer<udp::SentFrame>& log, size_t first, size_t count) override;
    void frames_lost(const RingBuffer<udp::SentFrame>& log, size_t first, size_t count) override;
    bool repairs_pending() const override { return has_repairs(); }

    void die(CloseReason reason, bool keep_inbox = false);
    void raise(uint32_t events) noexcept { events_ |= events; }
    void flush_events();

    UdpConnectionHost& host_;
    SecurityProvider&  security_;
    Address            remote_;
    ConnRole           role_;
    udp::Cid           local_cid_;
    udp::Cid           remote_cid_;
    ConnId             conn_id_ = kInvalidConnId;
    UdpConnectionConfig config_;

    Phase       phase_        = Phase::Handshaking;
    CloseReason close_reason_ = CloseReason::PeerClosed;
    uint32_t    events_       = 0;
    bool        heard_        = false;  ///< a packet came back from the peer
    bool        want_write_   = false;
    bool        closing_      = false;  ///< an orderly close waits for the queue to drain
    bool        reading_      = true;   ///< see stop_reading()
    bool        close_sent_   = false;

    // — handshake —
    std::unique_ptr<Handshaker> handshaker_;
    std::unique_ptr<Session>    session_;
    PeerId                      remote_id_;
    Bytes             hs_last_;            ///< our latest handshake message, to repeat
    uint8_t           hs_number_     = 0;  ///< its number
    /// The number of the next handshake message the peer owes us. The messages are
    /// numbered across both sides — the dialer's Initial is 0, the reply 1, the
    /// dialer's answer 2 — so this starts at 1 for a dialer and 2 for a responder.
    uint8_t           hs_expect_     = 1;
    bool              answered_      = false;
    bool              confirmed_     = false;  ///< the peer has its keys
    bool              retried_       = false;
    Bytes             token_;              ///< what a Retry handed us
    int               hs_attempts_   = 0;
    int               hs_max_attempts_ = 0;
    bool              hs_backoff_    = true;
    Clock::duration   hs_interval_{};
    Clock::time_point hs_deadline_{};      ///< epoch = no repeat scheduled
    Clock::time_point hs_sent_at_{};       ///< when our latest handshake packet left
    int               hs_sends_      = 0;  ///< handshake packets sent (Initials apart)
    /// The peer has proved it receives at remote_: a dialer chose the address, a
    /// responder learns it from the handshake, and after a move a PATH_RESPONSE
    /// says so. Until then what goes there is held to the amplification limit.
    bool              address_validated_ = false;
    uint64_t          amp_received_  = 0;   ///< from remote_ while unproven
    uint64_t          amp_sent_      = 0;   ///< to remote_ while unproven
    std::vector<Bytes> early_;

    // — migration —
    /// The last address the peer was proven at, while remote_ is a newer one that
    /// is not proven yet.
    std::optional<Address> previous_;
    struct Challenge {
        bool              active = false;
        Address           to;
        uint64_t          data   = 0;
        bool              new_ip = false;   ///< `to` has another IP than the proven address
        int               sends  = 0;
        Clock::time_point due{};            ///< the next send, or giving up
    };
    Challenge         challenge_;
    uint64_t          challenges_    = 0;   ///< made so far: the next one's data
    bool              path_answered_ = false;   ///< the packet being applied answers it
    bool              response_owed_ = false;
    uint64_t          response_data_ = 0;
    uint64_t          last_challenge_ = 0;  ///< the latest one we answered
    bool              moved_         = false;   ///< see take_moved()

    // — sending —
    udp::Recovery     recovery_;
    /// Sorted by priority, then type. Held by pointer so a lane stays where it is
    /// when another is added — which a message handler can do in the middle of a
    /// delivery, by sending something of a type not seen before.
    std::vector<std::unique_ptr<Lane>> lanes_;
    std::array<size_t, kPriorityCount> rr_{};   ///< per priority: the lane that goes first next
    udp::LiveSender   live_send_;
    udp::fec::LossEstimate live_loss_;   ///< what live_repairs() goes by
    uint64_t          sent_new_total_ = 0; ///< new stream bytes ever sent, all lanes
    uint64_t          peer_max_data_  = kInitialWindow;
    uint64_t          blocked_at_     = 0; ///< the limit a DATA_BLOCKED was sent for
    bool              blocked_owed_   = false;
    bool              max_data_owed_  = false;
    bool              ping_owed_      = false;
    bool              token_owed_     = false;
    bool              token_acked_    = false;
    Clock::time_point last_send_{};
    Clock::time_point last_eliciting_send_{};
    bool              sent_data_ = false;   ///< the last packet built carried data

    // — receiving —
    Clock::time_point last_recv_{};
    std::array<uint8_t, udp::kResetTokenSize> peer_token_{};
    bool              have_peer_token_ = false;
    /// Packet numbers received, as inclusive [lo, hi] runs, newest first. Anything
    /// below ack_floor_ is no longer tracked and counts as a duplicate.
    std::vector<std::pair<uint64_t, uint64_t>> received_;
    uint64_t          ack_floor_      = 0;
    uint64_t          largest_recv_   = 0;
    bool              have_recv_      = false;
    Clock::time_point largest_recv_at_{};
    bool              ack_owed_       = false;   ///< something ack-eliciting is unacknowledged
    int               unacked_        = 0;
    Clock::time_point ack_due_{};                ///< epoch = at once
    bool              ack_now_        = false;
    /// The packet being applied opened or closed a hole in a stream.
    bool              ack_urgent_     = false;
    bool              in_burst_       = false;
    bool              burst_ack_owed_ = false;

    udp::LiveReceiver live_recv_;

    // — flow control, receive side —
    udp::HoldAccount  account_;
    uint64_t          recv_window_;
    uint64_t          initial_window_;
    uint64_t          max_window_;
    uint64_t          advertised_     = kInitialWindow;
    uint64_t          consumed_       = 0;   ///< in-order bytes, all lanes
    uint64_t          received_highest_ = 0; ///< highest offsets, all lanes
    /// What was advertised when the window last grew: a DATA_BLOCKED at or below
    /// it was sent against an older, smaller window.
    uint64_t          grown_mark_     = 0;
    bool              have_grown_     = false;
    /// When the window was last measured against the round trip, and how much had
    /// been consumed then (see maybe_update_window).
    Clock::time_point window_epoch_{};
    uint64_t          window_epoch_bytes_ = 0;
    Clock::time_point last_data_recv_{};
    /// The usual gap between the peer's packets of data, smoothed: what tells a
    /// stream gone quiet from one that is merely sparse (kQuietProbe).
    Clock::duration   data_gap_ = kKeepAlive;
    /// When a peer gone quiet is next shown we are here; epoch = it has not been
    /// streaming.
    Clock::time_point quiet_due_{};
    Clock::duration   quiet_wait_{};
};

template <typename Fn>
bool UdpConnection::deliver(Clock::time_point now, Fn&& fn) {
    // The lanes as they stand: one added by a handler has nothing to deliver yet.
    Lane* lanes[256];
    size_t n = 0;
    for (const auto& lane : lanes_) lanes[n++] = lane.get();
    // Live messages go where their priority puts them: after the lanes ahead of it.
    size_t live_at = 0;
    while (live_at < n && lanes[live_at]->priority < static_cast<uint8_t>(Priority::Live)) ++live_at;

    bool bad = false;
    const auto protocol_error = [&] {
        fail(now, CloseReason::ProtocolError, kCloseProtocol);
        flush_events();
        return false;
    };
    for (size_t i = 0; i <= n; ++i) {
        if (i == live_at && live_recv_.has_messages()) {
            bool stopped = false;
            live_recv_.deliver([&](ByteView inner) {
                const auto msg = framer::parse_message(inner);
                if (!msg.ok) { bad = true; return false; }
                return fn(msg.frame);
            }, stopped);
            if (bad) return protocol_error();
            if (stopped || dead()) return true;
        }
        if (i == n) break;
        Lane& lane = *lanes[i];
        if (!lane.recv.has_messages()) continue;
        bool stopped = false;
        const bool ok = lane.recv.deliver(framer::kMaxBlockSize, [&](ByteView inner) {
            const auto msg = framer::parse_message(inner);
            // A message on another type's lane would be one a subsystem was never
            // told about in the order it was sent: not something a peer does.
            if (!msg.ok || msg.frame.header.type != lane.type) { bad = true; return false; }
            return fn(msg.frame);
        }, stopped);
        if (!ok || bad) return protocol_error();
        if (stopped || dead()) return true;
    }
    return true;
}

} // namespace librats
