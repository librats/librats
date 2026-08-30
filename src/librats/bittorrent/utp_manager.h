#pragma once

/**
 * @file utp_manager.h
 * @brief The one UDP socket every uTP peer shares, and the demultiplexer in front
 *        of it.
 *
 * uTP puts every connection on a single socket and separates them by a 16-bit
 * connection id — the same shape as the node's own `UdpMux`, and for the same
 * reasons: one NAT mapping for the whole swarm rather than one per peer, one
 * pollable descriptor however many peers there are, and a source port a third
 * party can dial back (which is what makes hole punching possible at all).
 *
 * The manager owns the socket, the streams, and the one timer that drives all of
 * their retransmission clocks. Everything lives on the BitTorrent reactor thread.
 *
 * ## Deferred acknowledgements
 *
 * A peer sending at line rate delivers a burst of datagrams per wakeup. Acking
 * each one costs a syscall per packet and floods the reverse path with 20-byte
 * datagrams that say almost the same thing. So a stream that owes an ack registers
 * here instead of sending, and the whole set is flushed once, after the socket has
 * been drained — one ack per burst rather than one per packet. There is no timer
 * involved: the ack still leaves in the same event-loop iteration it was earned in,
 * so nothing waits on it.
 *
 * ## Port sharing
 *
 * The socket binds the *same* port as the TCP listener, because a peer learns one
 * port for us (from the tracker or the DHT) and must be able to reach us over
 * either transport with it. Client::open_listener() is what keeps the two in step.
 */

#include "librats/bittorrent/reactor.h"
#include "librats/bittorrent/utp_stream.h"
#include "librats/core/address.h"
#include "librats/core/socket.h"

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace librats::bittorrent::utp {

/// How often every stream's timers are examined. Fine enough that a retransmission
/// timeout (500 ms at the very least) is not measurably late, coarse enough that a
/// few hundred idle streams cost nothing.
constexpr std::chrono::milliseconds kTickInterval{50};

class Manager final : public Host {
public:
    /// Called with a freshly accepted inbound stream, once its SYN has been
    /// processed. The handler takes over the stream by setting an observer on it;
    /// leaving it without one lets the manager reap it in short order.
    using AcceptHandler = std::function<void(Stream&)>;

    explicit Manager(Reactor& reactor);
    ~Manager() override;

    Manager(const Manager&) = delete;
    Manager& operator=(const Manager&) = delete;

    /// Bind the shared socket to @p port and start listening. Returns false if the
    /// bind failed, in which case the session simply runs TCP-only.
    bool open(std::uint16_t port, const std::string& bind_address = "");
    void close();

    bool          is_open() const noexcept { return is_valid_socket(socket_); }
    std::uint16_t port()    const noexcept { return port_; }

    void set_accept_handler(AcceptHandler h) { accept_ = std::move(h); }
    /// Whether a SYN from an unknown peer opens a stream. Off means we still dial
    /// out over uTP but never answer — the equivalent of a firewalled TCP port.
    void set_accept_incoming(bool on) noexcept { accept_incoming_ = on; }

    /// Open an outgoing stream to @p to and send its SYN. Returns nullptr if the
    /// socket is not open or the stream cap has been reached. The stream is owned
    /// here; the caller attaches an observer and must call release() when done.
    Stream* connect(const Address& to);

    /// Hand a stream back: it is detached from its observer and closed, then reaped
    /// once it has finished saying goodbye. The caller's pointer is dead on return.
    void release(Stream& s);

    std::size_t num_streams() const noexcept { return streams_.size(); }

    // ---- Host ----
    void utp_send(const Address& to, const std::uint8_t* data, std::size_t len) override;
    void utp_defer_ack(Stream& s) override;

    /// Largest number of streams held at once, inbound and outbound together. A SYN
    /// arriving past it is dropped rather than answered, so a flood costs one
    /// hash lookup and nothing else.
    static constexpr std::size_t kMaxStreams = 500;

private:
    void on_readable();
    void handle_datagram(const std::uint8_t* data, std::size_t len, const Address& from,
                         Stream::Clock::time_point now);
    void tick();
    void flush_deferred_acks(Stream::Clock::time_point now);
    void reap(Stream::Clock::time_point now);
    /// The stream registered under @p id that is also talking to @p from. Both must
    /// match: an id alone is guessable, and a stream must not be hijackable by
    /// anyone who happens to send from a different address.
    Stream* find(const Address& from, std::uint16_t id);

    Reactor&      reactor_;
    socket_t      socket_ = RATS_INVALID_SOCKET;
    std::uint16_t port_   = 0;
    TimerId       tick_timer_ = kInvalidTimerId;
    AcceptHandler accept_;
    bool          accept_incoming_ = true;

    /// Keyed by the stream's *receive* id — the id a peer puts in the datagrams it
    /// sends us. A multimap because two unrelated peers may pick the same id; the
    /// endpoint then separates them.
    std::unordered_multimap<std::uint16_t, std::unique_ptr<Stream>> streams_;

    /// Streams owing an acknowledgement at the end of the current drain.
    std::vector<Stream*> deferred_;
    /// Reused snapshot for iteration, so a callback that releases a stream cannot
    /// invalidate the loop it fired from.
    std::vector<Stream*> scratch_;
};

} // namespace librats::bittorrent::utp
