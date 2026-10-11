#include "librats/transport/tcp_link.h"
#include "librats/transport/reactor.h"
#include "librats/core/io_poller.h"

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>

#if defined(__linux__)
#include <netinet/in.h>
#include <netinet/tcp.h>   // TCP_INFO
#include <sys/socket.h>
#endif

namespace librats {

namespace {

#if defined(__linux__)
/// The kernel's struct tcp_info as far as tcpi_bytes_retrans (Linux 4.19),
/// spelled out here rather than taken from <netinet/tcp.h>: glibc's copy trails
/// the kernel by years, and an older one has no tcpi_delivery_rate to name. The
/// layout is kernel ABI — fields are only ever appended — and the kernel copies
/// min(our size, its size), reporting how much it filled, so an older kernel is
/// answered by checking that length rather than by failing.
struct KernelTcpInfo {
    uint8_t  state, ca_state, retransmits, probes, backoff, options;
    uint8_t  snd_wscale : 4, rcv_wscale : 4;
    uint8_t  delivery_rate_app_limited : 1, fastopen_client_fail : 2;
    uint32_t rto, ato, snd_mss, rcv_mss;
    uint32_t unacked, sacked, lost, retrans, fackets;
    uint32_t last_data_sent, last_ack_sent, last_data_recv, last_ack_recv;
    uint32_t pmtu, rcv_ssthresh, rtt, rttvar, snd_ssthresh, snd_cwnd, advmss, reordering;
    uint32_t rcv_rtt, rcv_space;
    uint32_t total_retrans;
    uint64_t pacing_rate, max_pacing_rate, bytes_acked, bytes_received;
    uint32_t segs_out, segs_in;
    uint32_t notsent_bytes, min_rtt, data_segs_in, data_segs_out;
    uint64_t delivery_rate;
    uint64_t busy_time, rwnd_limited, sndbuf_limited;
    uint32_t delivered, delivered_ce;
    uint64_t bytes_sent, bytes_retrans;
};
#endif

#ifdef _WIN32
inline bool last_error_would_block() { return WSAGetLastError() == WSAEWOULDBLOCK; }
#else
inline bool last_error_would_block() { return errno == EAGAIN || errno == EWOULDBLOCK; }
#endif

} // namespace

Link::IoResult TcpLink::read(ByteSpan into) {
    const int n = ::recv(socket_, reinterpret_cast<char*>(into.data()),
                         static_cast<int>(into.size()), 0);
    if (n > 0) return {static_cast<size_t>(n), Status::Ok};
    if (n == 0) return {0, Status::Closed};  // FIN: the peer is done sending
    return {0, last_error_would_block() ? Status::WouldBlock : Status::Error};
}

Link::IoResult TcpLink::write(const ByteView* slices, size_t count) {
    const std::ptrdiff_t n = send_vectored(socket_, slices, count);
    if (n > 0) return {static_cast<size_t>(n), Status::Ok};
    // n == 0 means the socket accepted nothing this round — indistinguishable from
    // a full send buffer as far as the caller is concerned, so report would-block
    // and let the next writable event drive the retry.
    if (n == 0) return {0, Status::WouldBlock};
    return {0, last_error_would_block() ? Status::WouldBlock : Status::Error};
}

bool TcpLink::connect_completed() {
    return tcp_connect_result(socket_) == 0;
}

void TcpLink::want_write(bool on) {
    reactor_.set_interest(socket_, on ? (PollIn | PollOut) : static_cast<uint32_t>(PollIn));
}

std::optional<Address> TcpLink::remote_endpoint() const {
    return get_peer_endpoint(socket_);
}

PathStats TcpLink::path_stats() const {
    PathStats s;
#if defined(__linux__)
    KernelTcpInfo ti{};
    socklen_t len = sizeof(ti);
    if (::getsockopt(socket_, IPPROTO_TCP, TCP_INFO, &ti, &len) != 0) return s;
    const auto has = [len](size_t end) { return static_cast<size_t>(len) >= end; };
    if (!has(offsetof(KernelTcpInfo, pacing_rate))) return s;

    s.valid  = true;
    s.srtt_us = ti.rtt;
    const uint64_t mss = ti.snd_mss ? ti.snd_mss : 1;
    // What tcp_packets_in_flight() counts, in bytes.
    const uint64_t pkts = uint64_t{ti.unacked} + ti.retrans - (std::min)(uint64_t{ti.unacked},
                                                                          uint64_t{ti.sacked} + ti.lost);
    s.bytes_in_flight = pkts * mss;
    // ~0 is "unlimited" — no pacing at all.
    if (ti.pacing_rate != ~uint64_t{0}) s.pacing_bps = ti.pacing_rate * 8;
    if (has(offsetof(KernelTcpInfo, bytes_received)))
        s.bytes_delivered = ti.bytes_acked;
    if (has(offsetof(KernelTcpInfo, data_segs_in))) {
        s.queued_bytes = ti.notsent_bytes;
        s.min_rtt_us   = ti.min_rtt;
    }
    if (has(offsetof(KernelTcpInfo, busy_time))) {
        s.bandwidth_bps = ti.delivery_rate * 8;
        s.app_limited   = ti.delivery_rate_app_limited;
    } else if (ti.rtt > 0) {
        s.bandwidth_bps = uint64_t{ti.snd_cwnd} * mss * 8 * 1000000 / ti.rtt;
    }
    // Retransmitted bytes stand in for lost ones: the kernel counts no other.
    if (has(offsetof(KernelTcpInfo, bytes_retrans) + sizeof(ti.bytes_retrans)))
        s.bytes_lost = ti.bytes_retrans;
#endif
    return s;
}

} // namespace librats
