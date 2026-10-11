#include "librats/core/udp_io.h"
#include "librats/util/logger.h"

#include <cstring>

#ifdef _WIN32
    #include <mswsock.h>    // WSARecvMsg's extension id; mingw's WSA_CMSG_* macros
#else
    #include <errno.h>
    #include <netinet/in.h>
    #include <netinet/udp.h>
    #include <sys/uio.h>
#endif

// recvmmsg/sendmmsg — one syscall for a whole array of datagrams. Linux has had
// both since 2.6.33 (bionic exposes them from API 21); everything else takes the
// one-datagram-per-call path. FreeBSD has them too, but only as of 11, and the
// version guard is not worth the cost of being wrong there.
#if defined(__linux__) && (!defined(__ANDROID__) || __ANDROID_API__ >= 21)
    #define RATS_HAVE_MMSG 1
#endif

// Segmentation offload option names, from their stable values where the headers
// predate them (older glibc, the NDK, mingw). Values the kernel does not know are
// refused at the probe, so a stale header can cost the offload, never correctness.
#ifdef __linux__
    #ifndef SOL_UDP
        #define SOL_UDP 17
    #endif
    #ifndef UDP_SEGMENT
        #define UDP_SEGMENT 103   // Linux 4.18
    #endif
    #ifndef UDP_GRO
        #define UDP_GRO 104       // Linux 5.0
    #endif
#endif
#ifdef _WIN32
    #ifndef UDP_SEND_MSG_SIZE
        #define UDP_SEND_MSG_SIZE 2             // USO: Windows 10 2004 / Server 2022
    #endif
    #ifndef UDP_RECV_MAX_COALESCED_SIZE
        #define UDP_RECV_MAX_COALESCED_SIZE 3   // URO: Windows 11 / Server 2022
    #endif
    #ifndef UDP_COALESCED_INFO
        #define UDP_COALESCED_INFO 3            // the cmsg URO reports a segment size in
    #endif
#endif

#define LOG_UDPIO_DEBUG(message) LOG_DEBUG("socket", message)
#define LOG_UDPIO_INFO(message)  LOG_INFO("socket", message)

namespace librats {

namespace {

[[maybe_unused]] int last_error() {
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

/// The socket is out of room for now. A datagram it refuses is dropped exactly as
/// a congested link would drop it, so this ends the flush; retransmission does
/// the rest.
bool is_would_block(int error) {
#ifdef _WIN32
    return error == WSAEWOULDBLOCK || error == WSAENOBUFS;
#else
    return error == EAGAIN || error == EWOULDBLOCK || error == ENOBUFS;
#endif
}

#ifdef _WIN32
/// WSARecvMsg is an extension function: there is no import for it, only a pointer
/// the provider hands out. Resolved once — every socket here comes from the same
/// (the system's) provider.
LPFN_WSARECVMSG wsa_recvmsg(socket_t socket) {
    static const LPFN_WSARECVMSG fn = [socket]() -> LPFN_WSARECVMSG {
        LPFN_WSARECVMSG out = nullptr;
        GUID  id    = WSAID_WSARECVMSG;
        DWORD bytes = 0;
        if (WSAIoctl(socket, SIO_GET_EXTENSION_FUNCTION_POINTER, &id, sizeof(id),
                     &out, sizeof(out), &bytes, nullptr, nullptr) != 0)
            return nullptr;
        return out;
    }();
    return fn;
}
#endif

} // namespace

// ── Probe ───────────────────────────────────────────────────────────────────

UdpOffload enable_udp_offload(socket_t socket) {
    UdpOffload offload;
#if defined(__linux__)
    // A kernel that knows UDP_SEGMENT answers getsockopt for it; one that does
    // not fails it, and every segmented send would fail too.
    int       gso     = 0;
    socklen_t gso_len = sizeof(gso);
    if (getsockopt(socket, SOL_UDP, UDP_SEGMENT, &gso, &gso_len) == 0)
        offload.max_segments = kUdpMaxSegments;

    const int on = 1;
    if (setsockopt(socket, SOL_UDP, UDP_GRO, &on, sizeof(on)) == 0)
        offload.coalesced_receive = true;
#elif defined(_WIN32)
    // The probe msquic uses: a stack with USO answers for the option, one
    // without fails it.
    DWORD uso     = 0;
    int   uso_len = sizeof(uso);
    if (getsockopt(socket, IPPROTO_UDP, UDP_SEND_MSG_SIZE,
                   reinterpret_cast<char*>(&uso), &uso_len) == 0)
        offload.max_segments = kUdpMaxSegments;

    // URO is opt-in, and the size given is the largest run it may hand us — the
    // buffer every receive then has to be ready for. It also needs WSARecvMsg,
    // the only receive that reports the segment size.
    DWORD uro = static_cast<DWORD>(kUdpMaxReceiveBytes - 8);  // a UDP payload's worth
    if (wsa_recvmsg(socket) != nullptr &&
        setsockopt(socket, IPPROTO_UDP, UDP_RECV_MAX_COALESCED_SIZE,
                   reinterpret_cast<const char*>(&uro), sizeof(uro)) == 0)
        offload.coalesced_receive = true;
#else
    (void)socket;
#endif
    LOG_UDPIO_DEBUG("UDP offload on socket " << socket << ": "
                    << (offload.max_segments > 1 ? "segmented send" : "no segmented send")
                    << ", " << (offload.coalesced_receive ? "coalesced receive"
                                                          : "no coalesced receive"));
    return offload;
}

// ── Send ────────────────────────────────────────────────────────────────────

UdpSendBatch::UdpSendBatch(size_t max_segments)
    : buffer_(new uint8_t[kCapacity]),   // default-initialised on purpose: see the header
      max_segments_((std::max)(size_t{1}, (std::min)(max_segments, kUdpMaxSegments))) {
    runs_.reserve(kMaxRuns);
}

bool UdpSendBatch::add(const Address& to, const uint8_t* data, size_t len) {
    if (len == 0 || len > kUdpMaxSendBytes) return false;
    if (used_ + len > kCapacity) return false;

    // Joins the run in front of it if offload could send the two as one: same
    // destination, no longer than its segments, room left in the send — and the
    // run not already ended by a short datagram, since only the last segment may
    // be short.
    if (!runs_.empty()) {
        Run& run = runs_.back();
        if (run.open && run.count < max_segments_ && len <= run.segment &&
            run.bytes + len <= kUdpMaxSendBytes && run.to == to) {
            std::memcpy(buffer_.get() + used_, data, len);
            used_     += len;
            run.bytes += len;
            ++run.count;
            ++datagrams_;
            if (len < run.segment) run.open = false;
            return true;
        }
    }

    if (runs_.size() == kMaxRuns) return false;
    Run run;
    run.to      = to;
    run.offset  = used_;
    run.bytes   = len;
    run.segment = len;
    run.count   = 1;
    runs_.push_back(run);
    std::memcpy(buffer_.get() + used_, data, len);
    used_ += len;
    ++datagrams_;
    return true;
}

void UdpSendBatch::disable_segmentation(int error) {
    if (max_segments_ == 1) return;
    max_segments_ = 1;
    // Once, and loudly enough to find: it is a property of the path's device
    // (no checksum offload, an IPsec or tunnel route), and it costs CPU, not data.
    LOG_UDPIO_INFO("Kernel refused a segmented UDP send (error " << error
                   << "); sending one datagram per packet on this socket from now on");
}

#ifdef RATS_HAVE_MMSG

size_t UdpSendBatch::flush(socket_t socket, AddressFamily af) {
    if (runs_.empty()) return 0;

    // Messages per sendmmsg. With segmentation that is up to 64 runs; without it,
    // 64 datagrams — either way far past where the syscall stops mattering.
    constexpr size_t kChunk = 64;
    mmsghdr          msgs[kChunk];
    iovec            iov[kChunk];
    sockaddr_storage addrs[kChunk];
    alignas(cmsghdr) uint8_t control[kChunk][CMSG_SPACE(sizeof(uint16_t))];
    struct Unit { size_t run, first, count; };   // which datagrams each message carries
    Unit             units[kChunk];

    size_t sent  = 0;
    size_t run   = 0;   // the next datagram to go: runs_[run], datagram `first` of it
    size_t first = 0;
    while (run < runs_.size()) {
        size_t n = 0;
        size_t r = run, f = first;
        while (n < kChunk && r < runs_.size()) {
            const Run& cur = runs_[r];
            socklen_t  addr_len = 0;
            if (!to_sockaddr(cur.to, af, addrs[n], addr_len)) { ++r; f = 0; continue; }

            std::memset(&msgs[n], 0, sizeof(msgs[n]));
            msghdr& m      = msgs[n].msg_hdr;
            m.msg_name     = &addrs[n];
            m.msg_namelen  = addr_len;
            m.msg_iov      = &iov[n];
            m.msg_iovlen   = 1;

            const size_t offset = cur.offset + f * cur.segment;
            if (max_segments_ > 1 && cur.count - f > 1) {
                // The rest of the run, as one buffer the kernel cuts into segments.
                iov[n].iov_base  = buffer_.get() + offset;
                iov[n].iov_len   = cur.bytes - f * cur.segment;
                m.msg_control    = control[n];
                m.msg_controllen = sizeof(control[n]);
                cmsghdr* c       = CMSG_FIRSTHDR(&m);
                c->cmsg_level    = SOL_UDP;
                c->cmsg_type     = UDP_SEGMENT;
                c->cmsg_len      = CMSG_LEN(sizeof(uint16_t));
                const uint16_t segment = static_cast<uint16_t>(cur.segment);
                std::memcpy(CMSG_DATA(c), &segment, sizeof(segment));
                units[n] = Unit{r, f, cur.count - f};
                ++r;
                f = 0;
            } else {
                iov[n].iov_base = buffer_.get() + offset;
                iov[n].iov_len  = (std::min)(cur.segment, cur.bytes - f * cur.segment);
                units[n] = Unit{r, f, 1};
                if (++f == cur.count) { ++r; f = 0; }
            }
            ++n;
        }
        if (n == 0) break;   // nothing left with an address to go to

        const int got = sendmmsg(socket, msgs, static_cast<unsigned int>(n),
                                 MSG_DONTWAIT | MSG_NOSIGNAL);
        if (got > 0) {
            for (int i = 0; i < got; ++i) sent += units[i].count;
            if (static_cast<size_t>(got) == n) { run = r; first = f; continue; }
            // A short count means the next message failed and its error was
            // swallowed; sending from it again either goes through or reports it.
            run   = units[got].run;
            first = units[got].first;
            continue;
        }

        const int error = last_error();
        if (is_would_block(error)) break;
        if (units[0].count > 1 && (error == EIO || error == EINVAL)) {
            // The device cannot segment (EIO: no checksum offload, an IPsec
            // route) or not this one (EINVAL). Losing the run would be a burst of
            // dozens of packets that a congestion controller reads as the path
            // collapsing, so the same datagrams go again, one apiece.
            disable_segmentation(error);
            run   = units[0].run;
            first = units[0].first;
            continue;
        }
        // About this destination alone (a route that went away, a firewall), so
        // only its message is dropped, not everyone's behind it.
        LOG_UDPIO_DEBUG("Datagram to " << runs_[units[0].run].to.to_string()
                        << " refused (errno " << error << ")");
        run   = units[0].run;
        first = units[0].first + units[0].count;
        if (first >= runs_[run].count) { ++run; first = 0; }
    }

    runs_.clear();
    used_      = 0;
    datagrams_ = 0;
    return sent;
}

#else  // one call per send

#ifdef _WIN32
namespace {
/// One run as a single USO send. Returns 0 on success, or the WSA error.
int send_segmented(socket_t socket, const sockaddr_storage& addr, socklen_t addr_len,
                   const uint8_t* data, size_t bytes, size_t segment) {
    WSABUF buf;
    buf.buf = reinterpret_cast<CHAR*>(const_cast<uint8_t*>(data));
    buf.len = static_cast<ULONG>(bytes);

    alignas(WSACMSGHDR) char control[WSA_CMSG_SPACE(sizeof(DWORD))] = {};
    WSAMSG msg = {};
    msg.name          = reinterpret_cast<LPSOCKADDR>(const_cast<sockaddr_storage*>(&addr));
    msg.namelen       = addr_len;
    msg.lpBuffers     = &buf;
    msg.dwBufferCount = 1;
    msg.Control.buf   = control;
    msg.Control.len   = sizeof(control);

    WSACMSGHDR* c = WSA_CMSG_FIRSTHDR(&msg);
    c->cmsg_level = IPPROTO_UDP;
    c->cmsg_type  = UDP_SEND_MSG_SIZE;
    c->cmsg_len   = WSA_CMSG_LEN(sizeof(DWORD));
    const DWORD size = static_cast<DWORD>(segment);
    std::memcpy(WSA_CMSG_DATA(c), &size, sizeof(size));

    DWORD sent = 0;
    if (WSASendMsg(socket, &msg, 0, &sent, nullptr, nullptr) == 0) return 0;
    return last_error();
}

/// Errors that are about where a datagram was going rather than about the
/// segmentation, so trying the run unsegmented would only fail again.
bool is_destination_error(int error) {
    return error == WSAEHOSTUNREACH || error == WSAENETUNREACH ||
           error == WSAEADDRNOTAVAIL || error == WSAEACCES;
}
} // namespace
#endif

size_t UdpSendBatch::flush(socket_t socket, AddressFamily af) {
    if (runs_.empty()) return 0;

    size_t sent = 0;
    for (const Run& run : runs_) {
        size_t first = 0;
#ifdef _WIN32
        if (max_segments_ > 1 && run.count > 1) {
            sockaddr_storage addr;
            socklen_t        addr_len = 0;
            if (!to_sockaddr(run.to, af, addr, addr_len)) continue;
            const int error = send_segmented(socket, addr, addr_len,
                                             buffer_.get() + run.offset, run.bytes, run.segment);
            if (error == 0) { sent += run.count; continue; }
            if (is_would_block(error)) break;
            if (is_destination_error(error)) continue;
            // Anything else is the stack declining to segment: the same datagrams
            // go again one apiece rather than as a burst of losses (see the
            // sendmmsg path).
            disable_segmentation(error);
        }
#endif
        bool full = false;
        for (; first < run.count; ++first) {
            const size_t off = first * run.segment;
            const std::ptrdiff_t n = send_udp_to(socket, buffer_.get() + run.offset + off,
                                                 (std::min)(run.segment, run.bytes - off),
                                                 run.to, af);
            if (n > 0) { ++sent; continue; }
            if (n == 0) { full = true; break; }   // would block: see is_would_block
            break;                                // this destination refused it
        }
        if (full) break;
    }

    runs_.clear();
    used_      = 0;
    datagrams_ = 0;
    return sent;
}

#endif  // RATS_HAVE_MMSG

// ── Receive ─────────────────────────────────────────────────────────────────

UdpRecvBatch::UdpRecvBatch(size_t max_datagram, bool coalesced)
    : capacity_(coalesced ? kUdpMaxReceiveBytes : max_datagram), coalesced_(coalesced) {
    // Default-initialised, never zeroed: a coalescing batch reserves 2 MiB, and a
    // page of it costs memory only once a receive has actually written to it.
    storage_.reset(new uint8_t[kUdpBatchMax * capacity_]);
    for (size_t i = 0; i < kUdpBatchMax; ++i) buffers_[i].data = storage_.get() + i * capacity_;
}

std::ptrdiff_t UdpRecvBatch::receive(socket_t socket, size_t count) {
    if (count == 0) return kUdpRecvWouldBlock;
    if (count > kUdpBatchMax) count = kUdpBatchMax;

#ifdef RATS_HAVE_MMSG
    mmsghdr          msgs[kUdpBatchMax];
    iovec            iov[kUdpBatchMax];
    sockaddr_storage addrs[kUdpBatchMax];
    alignas(cmsghdr) uint8_t control[kUdpBatchMax][CMSG_SPACE(sizeof(int))];

    std::memset(msgs, 0, sizeof(mmsghdr) * count);
    for (size_t i = 0; i < count; ++i) {
        iov[i].iov_base             = buffers_[i].data;
        iov[i].iov_len              = capacity_;
        msgs[i].msg_hdr.msg_name    = &addrs[i];
        msgs[i].msg_hdr.msg_namelen = sizeof(sockaddr_storage);
        msgs[i].msg_hdr.msg_iov     = &iov[i];
        msgs[i].msg_hdr.msg_iovlen  = 1;
        if (coalesced_) {
            msgs[i].msg_hdr.msg_control    = control[i];
            msgs[i].msg_hdr.msg_controllen = sizeof(control[i]);
        }
    }

    // MSG_DONTWAIT matters even on a socket that is already non-blocking: without
    // it recvmmsg() waits for the *whole* array to fill when no timeout is given.
    const int n = recvmmsg(socket, msgs, static_cast<unsigned int>(count), MSG_DONTWAIT, nullptr);
    if (n > 0) {
        for (int i = 0; i < n; ++i) {
            Buffer&       b = buffers_[i];
            const msghdr& m = msgs[i].msg_hdr;
            b.len     = msgs[i].msg_len;
            b.segment = b.len;
            b.from    = address_from_sockaddr(addrs[i]);
            if (coalesced_) {
                for (cmsghdr* c = CMSG_FIRSTHDR(&m); c != nullptr;
                     c = CMSG_NXTHDR(const_cast<msghdr*>(&m), c)) {
                    if (c->cmsg_level != SOL_UDP || c->cmsg_type != UDP_GRO) continue;
                    int segment = 0;
                    std::memcpy(&segment, CMSG_DATA(c), sizeof(segment));
                    if (segment > 0) b.segment = static_cast<size_t>(segment);
                }
            }
            if (m.msg_flags & MSG_TRUNC) {
                // Datagrams the buffer ends in the middle of are lost either way.
                // From a run, the whole ones in front of the cut are still good;
                // a lone datagram cut short is not one at all.
                b.len = b.segment < b.len ? (b.len / b.segment) * b.segment : 0;
            }
        }
        return n;
    }
    if (n == 0) return kUdpRecvWouldBlock;

    const int error = last_error();
    if (error == EAGAIN || error == EWOULDBLOCK) return kUdpRecvWouldBlock;
    // Only an error on the *first* datagram is reported here; one further in simply
    // truncates the batch, which is why a short result is not proof of an empty
    // queue. Either way this concerns one destination, not the socket.
    if (error != EINTR && error != ECONNREFUSED)
        LOG_UDPIO_DEBUG("Failed to receive a datagram batch (errno " << error << ")");
    return kUdpRecvError;
#else
    size_t got = 0;
    for (size_t i = 0; i < count; ++i) {
        Buffer& b = buffers_[i];
        std::ptrdiff_t n;
#ifdef _WIN32
        if (coalesced_) {
            // WSARecvMsg, because only it hands back the cmsg URO puts the
            // segment size in.
            sockaddr_storage addr;
            WSABUF           buf;
            buf.buf = reinterpret_cast<CHAR*>(b.data);
            buf.len = static_cast<ULONG>(capacity_);
            alignas(WSACMSGHDR) char control[WSA_CMSG_SPACE(sizeof(DWORD))];
            WSAMSG msg = {};
            msg.name          = reinterpret_cast<LPSOCKADDR>(&addr);
            msg.namelen       = sizeof(addr);
            msg.lpBuffers     = &buf;
            msg.dwBufferCount = 1;
            msg.Control.buf   = control;
            msg.Control.len   = sizeof(control);

            DWORD bytes = 0;
            if (wsa_recvmsg(socket)(socket, &msg, &bytes, nullptr, nullptr) == 0) {
                b.len     = bytes;
                b.segment = bytes;
                b.from    = address_from_sockaddr(addr);
                for (WSACMSGHDR* c = WSA_CMSG_FIRSTHDR(&msg); c != nullptr;
                     c = WSA_CMSG_NXTHDR(&msg, c)) {
                    if (c->cmsg_level != IPPROTO_UDP || c->cmsg_type != UDP_COALESCED_INFO)
                        continue;
                    DWORD segment = 0;
                    std::memcpy(&segment, WSA_CMSG_DATA(c), sizeof(segment));
                    if (segment > 0) b.segment = segment;
                }
                ++got;
                continue;
            }
            const int error = last_error();
            if (error == WSAEWOULDBLOCK) break;
            // WSAEMSGSIZE (cut short, and Windows discards the rest), an ICMP
            // complaint about an earlier send: one datagram's business. Report
            // what already arrived and let the caller come back for the rest.
            return got > 0 ? static_cast<std::ptrdiff_t>(got) : kUdpRecvError;
        }
#endif
        n = recv_udp_from(socket, b.data, capacity_, b.from);
        if (n == kUdpRecvWouldBlock) break;
        // Report what has already arrived and let the caller come back for the rest;
        // only an error on the very first datagram has nothing to report alongside it.
        if (n == kUdpRecvError) return got > 0 ? static_cast<std::ptrdiff_t>(got) : kUdpRecvError;
        b.len     = static_cast<size_t>(n);
        b.segment = b.len;
        ++got;
    }
    return got > 0 ? static_cast<std::ptrdiff_t>(got) : kUdpRecvWouldBlock;
#endif
}

} // namespace librats
