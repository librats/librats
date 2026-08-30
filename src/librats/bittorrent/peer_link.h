#pragma once

/**
 * @file peer_link.h
 * @brief The byte stream a PeerConnection runs on, independent of how it is carried.
 *
 * Everything above this line — the BitTorrent handshake, the message codec, MSE
 * obfuscation, the choke machine, backpressure, the idle deadlines — only ever
 * needs an ordered, reliable, non-blocking byte stream. A PeerLink is exactly that
 * and nothing more, so the same PeerConnection code drives a kernel TCP socket and
 * the library's own uTP implementation. Neither is a special case of the other: a
 * peer reached over either is indistinguishable to every layer above.
 *
 * This mirrors `transport/link.h` on the node side of the library, and libtorrent's
 * `aux::socket_type` variant on the BitTorrent side, for the same reason all three
 * exist: without it, "which transport is this?" leaks into every function that
 * touches the wire.
 *
 * The read/write calls deliberately mirror non-blocking socket semantics, because
 * that is what a reactor loop is built around:
 *   - read()  fills the caller's span and reports WouldBlock once nothing more is
 *             ready, or Closed when the peer has finished sending.
 *   - write() takes what it can and reports WouldBlock when it can take no more;
 *             the caller keeps the remainder queued and calls want_write(true) so
 *             it is told when to retry.
 *
 * Ownership and threading: a link belongs to exactly one PeerConnection, lives on
 * the BitTorrent reactor thread, and holds no locks. Events arrive through the
 * Observer the connection installs in start().
 */

#include "librats/bittorrent/reactor.h"
#include "librats/bittorrent/types.h"
#include "librats/bittorrent/utp_stream.h"
#include "librats/core/bytes.h"
#include "librats/core/socket.h"

#include <cstddef>
#include <string>

namespace librats::bittorrent {

namespace utp { class Manager; }

class PeerLink {
public:
    /// Outcome of a read/write attempt. `Closed` is orderly (the peer is done
    /// sending); `Error` means the link is broken and must be torn down.
    enum class Status : std::uint8_t { Ok, WouldBlock, Closed, Error };

    struct IoResult {
        std::size_t bytes  = 0;
        Status      status = Status::WouldBlock;
    };

    /// How the link tells its connection that something happened. Every callback
    /// runs on the reactor thread, and the connection may close the link from
    /// inside one — so a link must not touch its own state after calling out.
    struct Observer {
        virtual ~Observer() = default;
        virtual void on_link_readable() = 0;
        virtual void on_link_writable() = 0;
        virtual void on_link_error(const std::string& reason) = 0;
    };

    virtual ~PeerLink() = default;

    virtual PeerTransport transport() const noexcept = 0;

    /// Begin delivering events to @p obs.
    virtual void start(Observer* obs) = 0;

    /// Read up to `into.size()` bytes. A Closed or Error result always carries zero
    /// bytes — data and end-of-stream are never reported together, so the caller
    /// drains first and only then sees the close.
    virtual IoResult read(ByteSpan into) = 0;

    /// Hand `count` contiguous slices to the link in order, writing as many bytes
    /// as it will take (a partial write is normal and expected).
    virtual IoResult write(const ByteView* slices, std::size_t count) = 0;

    /// Ask to be woken (via on_link_writable) when more can be written. Called only
    /// when the state actually changes, so an implementation may treat it as an
    /// unconditional set.
    virtual void want_write(bool on) = 0;

    /// Tear down. Idempotent, and safe to call from inside an Observer callback.
    virtual void close() = 0;
};

/// A plain TCP socket, registered with the reactor. The kernel does the work.
class TcpPeerLink final : public PeerLink {
public:
    TcpPeerLink(Reactor& reactor, socket_t sock);
    ~TcpPeerLink() override;

    PeerTransport transport() const noexcept override { return PeerTransport::Tcp; }
    void          start(PeerLink::Observer* obs) override;
    IoResult      read(ByteSpan into) override;
    IoResult      write(const ByteView* slices, std::size_t count) override;
    void          want_write(bool on) override;
    void          close() override;

private:
    void on_io(std::uint32_t events);

    Reactor&  reactor_;
    socket_t  sock_;
    Observer* obs_        = nullptr;
    bool      want_write_ = false;
};

/**
 * The same guarantee obtained from a uTP stream instead of a socket.
 *
 * The stream is owned by the utp::Manager (it may have to outlive this object to
 * finish flushing a FIN), so the link holds a pointer and hands it back on close().
 * Readiness is pushed rather than polled: the manager's socket is the only thing
 * registered with the reactor, and it drives the stream, which drives us.
 */
class UtpPeerLink final : public PeerLink, private utp::Stream::Observer {
public:
    UtpPeerLink(utp::Manager& manager, utp::Stream& stream);
    ~UtpPeerLink() override;

    PeerTransport transport() const noexcept override { return PeerTransport::Utp; }
    void          start(PeerLink::Observer* obs) override;
    IoResult      read(ByteSpan into) override;
    IoResult      write(const ByteView* slices, std::size_t count) override;
    void          want_write(bool on) override { want_write_ = on; }
    void          close() override;

private:
    // ---- utp::Stream::Observer ----
    void on_utp_readable() override;
    void on_utp_writable() override;
    void on_utp_error(const std::string& why) override;

    utp::Manager& manager_;
    utp::Stream*  stream_;
    PeerLink::Observer* obs_  = nullptr;
    bool          want_write_ = false;
};

} // namespace librats::bittorrent
