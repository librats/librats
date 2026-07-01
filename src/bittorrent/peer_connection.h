#pragma once

/**
 * @file peer_connection.h
 * @brief One peer link: the BitTorrent wire handshake, message codec and the
 *        choke/interest state machine.
 *
 * A PeerConnection owns a non-blocking TCP socket registered with a Reactor and
 * lives entirely on that reactor's thread. It turns the byte stream into
 * protocol events delivered to an Observer, and offers send_* methods to emit
 * messages. It deliberately knows nothing about pieces-to-request strategy or
 * disk — the owning Torrent (a later phase) drives those through this surface.
 *
 * Wire format: a 68-byte handshake, then length-prefixed messages
 * `[u32 length][u8 id][payload]` (length 0 = keep-alive). All integers are
 * big-endian.
 */

#include "bittorrent/bitfield.h"
#include "bittorrent/reactor.h"
#include "bittorrent/types.h"
#include "core/bytes.h"
#include "core/receive_buffer.h"

#include <chrono>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace librats::bittorrent {

enum class MessageId : std::uint8_t {
    Choke         = 0,
    Unchoke       = 1,
    Interested    = 2,
    NotInterested = 3,
    Have          = 4,
    Bitfield      = 5,
    Request       = 6,
    Piece         = 7,
    Cancel        = 8,
    Port          = 9,
    Extended      = 20,
};

class PeerConnection {
public:
    /// Protocol events. All fire on the reactor thread; ByteView arguments are
    /// only valid for the duration of the call (copy if you need to keep them).
    struct Observer {
        virtual ~Observer() = default;
        virtual void on_handshake(PeerConnection&, const InfoHash&, const PeerId&) {}
        virtual void on_choke(PeerConnection&, bool peer_choking) {}
        virtual void on_interest(PeerConnection&, bool peer_interested) {}
        virtual void on_have(PeerConnection&, std::uint32_t piece) {}
        virtual void on_bitfield(PeerConnection&, const Bitfield&) {}
        virtual void on_request(PeerConnection&, std::uint32_t piece, std::uint32_t offset, std::uint32_t length) {}
        virtual void on_piece(PeerConnection&, std::uint32_t piece, std::uint32_t offset, ByteView data) {}
        virtual void on_cancel(PeerConnection&, std::uint32_t piece, std::uint32_t offset, std::uint32_t length) {}
        virtual void on_port(PeerConnection&, std::uint16_t port) {}
        virtual void on_extended(PeerConnection&, std::uint8_t ext_id, ByteView payload) {}
        virtual void on_closed(PeerConnection&, const std::string& reason) {}
    };

    /// Late-binding info for an incoming connection: filled by the Resolver once
    /// the peer's handshake reveals which torrent it is for.
    struct Binding {
        Observer*     observer   = nullptr;
        std::uint32_t num_pieces = 0;
    };
    /// Maps an incoming handshake's info-hash to a torrent. Return false to reject.
    using Resolver = std::function<bool(const InfoHash& their_info_hash, Binding& out)>;

    /// Outgoing connection: we know the torrent up front.
    /// @param num_pieces sizes the peer's bitfield; 0 if metadata isn't known yet.
    PeerConnection(Reactor& reactor, socket_t sock, bool outgoing,
                   const InfoHash& info_hash, const PeerId& our_peer_id,
                   std::uint32_t num_pieces, Observer* observer,
                   std::string remote_ip = "", std::uint16_t remote_port = 0);
    /// Incoming connection: the torrent is resolved from the peer's handshake.
    PeerConnection(Reactor& reactor, socket_t sock, const PeerId& our_peer_id,
                   Resolver resolver, std::string remote_ip = "", std::uint16_t remote_port = 0);
    ~PeerConnection();

    PeerConnection(const PeerConnection&) = delete;
    PeerConnection& operator=(const PeerConnection&) = delete;

    /// Register with the reactor; an outgoing connection sends its handshake now.
    void start();
    /// Tear down: deregister, close the socket, fire on_closed once.
    void close(const std::string& reason);

    // ---- state ----
    bool            closed()          const noexcept { return closed_; }
    bool            handshake_done()  const noexcept { return handshake_sent_ && handshake_received_; }
    bool            outgoing()        const noexcept { return outgoing_; }
    bool            am_choking()      const noexcept { return am_choking_; }
    bool            am_interested()   const noexcept { return am_interested_; }
    bool            peer_choking()    const noexcept { return peer_choking_; }
    bool            peer_interested() const noexcept { return peer_interested_; }
    const Bitfield& peer_bitfield()   const noexcept { return peer_have_; }
    const PeerId&   peer_id()         const noexcept { return peer_id_; }
    const InfoHash& info_hash()       const noexcept { return info_hash_; }
    bool            peer_supports_extensions() const noexcept { return reserved::has_extensions(peer_reserved_); }
    const std::string& remote_ip()   const noexcept { return remote_ip_; }
    std::uint16_t      remote_port()  const noexcept { return remote_port_; }

    // ---- send ----
    void send_keepalive();
    void send_choke();
    void send_unchoke();
    void send_interested();
    void send_not_interested();
    void send_have(std::uint32_t piece);
    void send_bitfield(const Bitfield& bitfield);
    void send_request(std::uint32_t piece, std::uint32_t offset, std::uint32_t length);
    void send_piece(std::uint32_t piece, std::uint32_t offset, ByteView data);
    void send_cancel(std::uint32_t piece, std::uint32_t offset, std::uint32_t length);
    void send_port(std::uint16_t port);
    void send_extended(std::uint8_t ext_id, ByteView payload);

private:
    void on_io(std::uint32_t events);
    void do_read();
    void parse();
    bool parse_handshake();
    void send_handshake();
    void dispatch(MessageId id, const std::uint8_t* payload, std::uint32_t len);

    void send_message(MessageId id, const std::uint8_t* payload, std::uint32_t len);
    void queue(const std::uint8_t* data, std::size_t len);
    void flush();
    void want_write(bool on);
    /// Periodic self-rescheduling tick: enforces the handshake/idle deadlines and
    /// emits keep-alives. Stops rescheduling once the connection is closed.
    void tick();

    Reactor&      reactor_;
    socket_t      sock_;
    bool          outgoing_;
    InfoHash      info_hash_;
    PeerId        our_peer_id_;
    PeerId        peer_id_{};
    std::uint32_t num_pieces_;
    Observer*     obs_;
    Resolver      resolver_;        ///< incoming only; resolves the torrent
    bool          bound_ = true;    ///< false for an unresolved incoming connection
    std::string   remote_ip_;       ///< peer's address (source for incoming, dialed for outgoing)
    std::uint16_t remote_port_ = 0;

    ReceiveBuffer        rx_;
    std::vector<std::uint8_t> out_;
    std::size_t          out_sent_ = 0;
    bool                 want_write_ = false;

    // Timeout bookkeeping, all evaluated by the periodic tick().
    TimerId                               tick_timer_ = kInvalidTimerId;
    std::chrono::steady_clock::time_point created_{};    ///< start() time — handshake deadline
    std::chrono::steady_clock::time_point last_recv_{};  ///< last byte received — idle deadline
    std::chrono::steady_clock::time_point last_sent_{};  ///< last byte sent — keep-alive timer

    bool          started_           = false;
    bool          handshake_sent_    = false;
    bool          handshake_received_= false;
    bool          closed_            = false;

    bool          am_choking_      = true;
    bool          am_interested_   = false;
    bool          peer_choking_    = true;
    bool          peer_interested_ = false;
    Bitfield      peer_have_;
    ReservedBytes peer_reserved_{};
};

} // namespace librats::bittorrent
