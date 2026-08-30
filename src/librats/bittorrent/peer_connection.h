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
 *
 * That stream may be wrapped in MSE/PE obfuscation (see mse.h). When it is, an
 * MSE handshake runs first and the bytes above are then RC4'd in both directions
 * — but only between here and the socket: everything from parse() and the send_*
 * methods inward sees the same plaintext protocol either way. An inbound
 * connection does not announce which it is, so the first 20 bytes are sniffed —
 * a literal "\x13BitTorrent protocol" is plaintext, anything else is a DH key.
 */

#include "librats/bittorrent/bitfield.h"
#include "librats/bittorrent/mse.h"
#include "librats/bittorrent/reactor.h"
#include "librats/bittorrent/types.h"
#include "librats/core/bytes.h"
#include "librats/core/chained_send_buffer.h"
#include "librats/core/receive_buffer.h"

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
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
    /// @param encrypt   open with an MSE handshake rather than a plaintext one.
    ///                  The caller decides (policy, plus what worked for this peer
    ///                  last time); the connection just does as it is told.
    PeerConnection(Reactor& reactor, socket_t sock, bool outgoing,
                   const InfoHash& info_hash, const PeerId& our_peer_id,
                   std::uint32_t num_pieces, Observer* observer,
                   std::string remote_ip = "", std::uint16_t remote_port = 0,
                   bool encrypt = false);
    /// Incoming connection: the torrent is resolved from the peer's handshake.
    /// @param enc_policy what we accept — plaintext, MSE, or either.
    /// @param skey       resolves an obfuscated MSE stream key to a torrent;
    ///                   required whenever @p enc_policy permits MSE.
    PeerConnection(Reactor& reactor, socket_t sock, const PeerId& our_peer_id,
                   Resolver resolver, std::string remote_ip = "", std::uint16_t remote_port = 0,
                   EncPolicy enc_policy = EncPolicy::Disabled,
                   mse::Handshake::SkeyResolver skey = {});
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
    /// True once an MSE handshake has completed. Note this says the *connection*
    /// was obfuscated, not that the payload is still encrypted — crypto_select may
    /// have settled on plaintext after the obfuscated header.
    bool            encrypted()       const noexcept { return encrypted_; }
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
    /// Takes ownership of `data` — the block goes into the send queue as its own
    /// chunk, so a disk read is handed straight to the socket without a copy.
    void send_piece(std::uint32_t piece, std::uint32_t offset, Bytes data);
    void send_cancel(std::uint32_t piece, std::uint32_t offset, std::uint32_t length);
    void send_port(std::uint16_t port);
    void send_extended(std::uint8_t ext_id, ByteView payload);

private:
    void on_io(std::uint32_t events);
    void do_read();
    std::size_t read_size() const;  ///< bytes to offer the next recv() (see rx_need_)
    void parse();
    bool parse_handshake();
    void send_handshake();
    /// The 68 bytes of the BitTorrent handshake, built but not queued — MSE needs
    /// them as its initial payload rather than as something to write directly.
    Bytes build_handshake();
    void dispatch(MessageId id, const std::uint8_t* payload, std::uint32_t len);

    // ---- MSE ----
    /// Decide from the first 20 bytes of an inbound stream whether the peer is
    /// speaking plaintext or MSE, and start the obfuscated handshake if it is.
    /// Returns false if it closed the connection (a policy refusal) or is still
    /// waiting for bytes.
    bool detect_inbound_encryption();
    /// Write whatever the handshake produced, then act on @p status.
    void pump_mse(mse::Handshake::Status status);
    /// Adopt the negotiated ciphers and hand the handshake's leftovers to parse().
    void finish_mse();

    void send_message(MessageId id, const std::uint8_t* payload, std::uint32_t len);
    /// Append to the send queue, encrypting first if the payload stream is RC4'd.
    /// No syscall: the caller flushes once the whole message is queued, so a
    /// message never costs more than one send().
    ///
    /// This is the single funnel every protocol message goes through, and that is
    /// what makes the cipher correct: RC4 is one keystream, so bytes have to be
    /// encrypted in exactly the order they enter the queue, exactly once each.
    void queue(ByteView bytes);
    /// Queue a buffer the caller already owns — moved in, and encrypted in place if
    /// need be, so a block read from disk is never copied.
    void queue(Bytes bytes);
    /// Queue bytes that must bypass the payload cipher: the MSE handshake, which
    /// carries its own encryption and establishes the cipher everything else uses.
    void queue_raw(Bytes bytes) { if (!closed_) tx_.append(std::move(bytes)); }
    /// Push the queue to the socket with one gather-send, (dis)arm write interest,
    /// and enforce the send high-water mark. May close the connection.
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

    // ---- MSE / PE ----
    EncPolicy                       enc_policy_ = EncPolicy::Disabled;  ///< inbound only
    mse::Handshake::SkeyResolver    skey_;                              ///< inbound only
    /// Runs the obfuscated handshake and owns the byte stream while it does, so
    /// nothing reaches rx_ until it has finished and been destroyed.
    std::unique_ptr<mse::Handshake> mse_;
    mse::Rc4Cipher                  rc4_send_;
    mse::Rc4Cipher                  rc4_recv_;
    bool                            rc4_active_ = false;  ///< payload stream is RC4'd
    bool                            encrypted_  = false;  ///< an MSE handshake completed
    bool                            want_mse_   = false;  ///< outbound: dial obfuscated
    bool                            detecting_  = false;  ///< inbound: still sniffing
    InfoHash                        mse_skey_{};          ///< torrent the stream key named
    /// Scratch for encrypting copy-appends, kept around so a steady stream of small
    /// messages does not allocate a buffer each.
    Bytes                           enc_scratch_;

    ReceiveBuffer     rx_;
    /// Wire size of the message rx_ is mid-way through (4-byte prefix included), once
    /// that prefix has been read; 0 when no message is in flight. Lets the next recv()
    /// size rx_ for the whole message in one go. Peer-declared, hence capped.
    std::size_t       rx_need_ = 0;
    ChainedSendBuffer tx_;
    bool              want_write_ = false;

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
    /// A bitfield is only valid as the peer's first piece-state message (BEP 3).
    /// Set once the peer has sent a bitfield or any HAVE; a later bitfield is then
    /// rejected so we can't double-count its availability against a single per-bit
    /// decrement at disconnect.
    bool          piece_state_begun_ = false;
    Bitfield      peer_have_;
    ReservedBytes peer_reserved_{};
};

} // namespace librats::bittorrent
