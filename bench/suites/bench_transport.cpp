// bench_transport.cpp — the two wires, end to end, head to head.
//
// Every other suite here measures a component against the implementation it
// replaced. This one measures a *path*: the same encrypted protocol carried by
// the kernel's TCP stack and by the library's own reliability layer over
// datagrams (src/librats/transport/udp_stream.{h,cpp} + udp_mux.{h,cpp}). A transport is
// only meaningful as a whole path — framing, congestion control, acknowledgement
// timing and syscall batching only make sense together — so nothing is mocked:
// two real librats::Node instances in this process, real loopback sockets, a real
// Noise_XX handshake, one reactor thread each.
//
// TCP is the reference side, and it is a *hard* one: it is a mature kernel stack
// with zero-copy loopback and no user-space packet accounting at all. The
// question this suite answers is therefore not "is our UDP faster" but:
//
//     what does moving reliability into user space actually cost, and where do
//     the two transports stop being interchangeable?
//
// The second half of that question is the more useful one. `Link` (src/librats/transport/
// link.h) promises that a peer over either wire is indistinguishable to every
// layer above; the experiments below are chosen to find the places where that
// promise is thin — dial cost, latency under delayed acks, and how big an
// application burst each wire absorbs before the connection is dropped as a slow
// consumer.
//
// ── What is measured ────────────────────────────────────────────────────────
//
//   dial        connect() → on_peer_connected. Exposes round trips spent before
//               the first byte of application data: TCP's connect + Noise_XX vs
//               the datagram Syn + Noise_XX.
//   rtt         strictly serial request/response of a small message. This is the
//               experiment that would catch a delayed acknowledgement landing on
//               the critical path (UdpStream::kDelayedAck is 20 ms — an order of
//               magnitude above everything else here, so it cannot hide).
//   bulk        one-way transfer, paced so neither wire hits its high-water mark.
//               Reports MB/s and, more importantly, CPU-seconds per gigabyte:
//               throughput on loopback flatters a user-space stack, CPU per byte
//               does not.
//   small       many small frames. Per-packet costs dominate, which is where
//               syscall batching (sendmmsg/recvmmsg, kUdpBatchMax) pays off.
//   idle        N connected peers doing nothing. The datagram side schedules
//               each stream at its own deadline rather than sweeping them, so
//               this is what a connected-but-silent stream still costs.
//   burst       the largest unpaced application burst the connection survives
//               before Connection::kDefaultSendHighWater drops it as a slow
//               consumer. The two wires differ sharply here — see the note at
//               bench_burst().
//   fallback    dialing a TCP-only node with UDP preferred: what the Happy-
//               Eyeballs race in node/dialer.h actually costs.
//
// ── Reading the numbers ─────────────────────────────────────────────────────
//
// CPU is whole-process: both nodes live here, so a figure covers sender *and*
// receiver. That is the honest number for a P2P node, which is usually both.
// Loopback has no loss, no reordering and an RTT near zero, so congestion
// control, retransmission and the selective-ack machinery are all measured at
// their cheapest — treat every UDP figure as a floor on cost, not a ceiling.
// Loss behaviour needs a lossy path (netem) and is deliberately out of scope.
//
// Build:  cmake -S bench -B bench/build && cmake --build bench/build --target bench_transport
// Run:    ./bench/build/bin/bench_transport
//
// Self-timing: framework/bench.h calibrates iteration counts against a wall-time
// target, which suits a nanosecond-scale loop and not a benchmark whose unit of
// work is a whole connection. Like bench_dht, this suite brings its own loop.

#include "librats/node/node.h"
#include "librats/util/logger.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
    #include <windows.h>
    #include <psapi.h>
#else
    #include <sys/resource.h>
    #include <unistd.h>   // isatty, sysconf(_SC_PAGESIZE)
#endif

using namespace librats;
using namespace std::chrono_literals;
using Clock = std::chrono::steady_clock;

namespace {

// ── Process counters ────────────────────────────────────────────────────────

/// CPU consumed by this process (user + system), in seconds. Whole-process on
/// purpose: both nodes run here, so one figure covers both ends of the link.
double cpu_seconds() {
#if defined(_WIN32)
    FILETIME creation, exit, kernel, user;
    if (!GetProcessTimes(GetCurrentProcess(), &creation, &exit, &kernel, &user)) return 0.0;
    const auto to_s = [](const FILETIME& ft) {
        ULARGE_INTEGER v;
        v.LowPart  = ft.dwLowDateTime;
        v.HighPart = ft.dwHighDateTime;
        return static_cast<double>(v.QuadPart) * 1e-7;  // 100 ns ticks
    };
    return to_s(kernel) + to_s(user);
#else
    rusage ru{};
    getrusage(RUSAGE_SELF, &ru);
    return ru.ru_utime.tv_sec + ru.ru_utime.tv_usec * 1e-6 +
           ru.ru_stime.tv_sec + ru.ru_stime.tv_usec * 1e-6;
#endif
}

/// Resident set size in bytes, or 0 where we cannot ask. Used only as a delta
/// across a known number of connections, never as an absolute.
size_t resident_bytes() {
#if defined(_WIN32)
    PROCESS_MEMORY_COUNTERS pmc{};
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) return pmc.WorkingSetSize;
    return 0;
#elif defined(__linux__)
    // statm reports *pages*; field 2 is resident. /proc is the only portable-enough
    // way to get a current (not peak) figure — ru_maxrss is monotonic and useless
    // for a delta taken after an earlier, larger experiment.
    std::FILE* f = std::fopen("/proc/self/statm", "r");
    if (!f) return 0;
    unsigned long total = 0, resident = 0;
    const int n = std::fscanf(f, "%lu %lu", &total, &resident);
    std::fclose(f);
    if (n != 2) return 0;
    return static_cast<size_t>(resident) * static_cast<size_t>(sysconf(_SC_PAGESIZE));
#else
    return 0;
#endif
}

// ── Reporting ───────────────────────────────────────────────────────────────

bool g_color = false;

const char* col(const char* code) { return g_color ? code : ""; }

/// One comparison row. `lower_is_better` decides which way the verdict reads;
/// a zero on either side prints as "—" rather than a meaningless ratio.
void row(const char* label, double tcp, double udp, const char* unit,
         bool lower_is_better, const char* fmt = "%8.2f") {
    char tcp_s[64], udp_s[64];
    std::snprintf(tcp_s, sizeof(tcp_s), fmt, tcp);
    std::snprintf(udp_s, sizeof(udp_s), fmt, udp);

    std::string verdict = "—";
    if (tcp > 0 && udp > 0) {
        const double ratio = lower_is_better ? udp / tcp : tcp / udp;
        char buf[64];
        std::snprintf(buf, sizeof(buf), "%5.2fx %s", ratio > 1.0 ? ratio : 1.0 / ratio,
                      ratio > 1.0 ? "worse" : "better");
        verdict = buf;
        if (g_color) verdict = std::string(ratio > 1.0 ? "\x1b[33m" : "\x1b[32m") + verdict + "\x1b[0m";
    }
    std::printf("  %-34s %10s %10s   %-6s  %s\n", label, tcp_s, udp_s, unit, verdict.c_str());
}

void header(const char* title) {
    std::printf("\n%s%s%s\n", col("\x1b[1m"), title, col("\x1b[0m"));
    std::printf("  %-34s %10s %10s   %-6s  %s\n", "", "TCP", "UDP", "unit", "UDP vs TCP");
    std::printf("  %-34s %10s %10s   %-6s  %s\n",
                "----------------------------------", "----------", "----------",
                "------", "------------");
}

double percentile(std::vector<double> v, double p) {
    if (v.empty()) return 0.0;
    std::sort(v.begin(), v.end());
    const double idx = p * (v.size() - 1);
    const size_t lo  = static_cast<size_t>(idx);
    const size_t hi  = (std::min)(lo + 1, v.size() - 1);
    return v[lo] + (idx - lo) * (v[hi] - v[lo]);
}

// ── Rig ─────────────────────────────────────────────────────────────────────

const char* wire(TransportKind k) { return k == TransportKind::Udp ? "UDP" : "TCP"; }

/// A node configured to speak exactly one wire, so nothing can silently fall
/// back and measure the other transport under this one's name.
NodeConfig config_for(TransportKind kind, bool listen) {
    NodeConfig c;
    c.bind_address           = "127.0.0.1";
    c.protocol               = "bench-transport/1";
    c.security               = NodeConfig::Security::Noise;
    c.enable_listen          = listen;
    c.enable_tcp             = (kind == TransportKind::Tcp);
    c.enable_udp             = (kind == TransportKind::Udp);
    c.preferred_transport    = kind;
    c.max_peers              = 0;
    // The host-network monitor is a thread per node that has nothing to do with
    // the transport; it would show up as noise in the idle measurement.
    c.enable_network_monitor = false;
    return c;
}

template <typename Pred>
bool wait_for(Pred pred, std::chrono::milliseconds timeout = 10s) {
    const auto deadline = Clock::now() + timeout;
    while (Clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(200us);
    }
    return pred();
}

/// Spin rather than sleep: the latencies under test here are microseconds, and a
/// condition-variable wakeup (5-10 us) would be most of what we are measuring.
template <typename Pred>
bool spin_for(Pred pred, std::chrono::milliseconds timeout = 5s) {
    const auto deadline = Clock::now() + timeout;
    while (!pred()) {
        if (Clock::now() >= deadline) return false;
        std::this_thread::yield();
    }
    return true;
}

/// A connected client→server pair over one wire, torn down in the right order.
struct Link2 {
    std::unique_ptr<Node> server;
    std::unique_ptr<Node> client;
    bool ok = false;

    Link2() = default;
    // Movable, not copyable: connect_pair() returns one by value, and the
    // user-declared destructor below would otherwise suppress the move.
    Link2(Link2&&) = default;
    Link2& operator=(Link2&&) = default;
    Link2(const Link2&) = delete;
    Link2& operator=(const Link2&) = delete;

    /// Client first: it holds the outbound connection, and stopping the listener
    /// out from under it would race the teardown.
    ~Link2() {
        if (client) client->stop();
        if (server) server->stop();
    }
};

/// Bring up a pair and wait until both ends agree they are connected. Handlers
/// must be registered before start(), so the caller passes them in.
template <typename ServerSetup, typename ClientSetup>
Link2 connect_pair(TransportKind kind, ServerSetup&& on_server, ClientSetup&& on_client) {
    Link2 link;
    link.server = std::make_unique<Node>(config_for(kind, /*listen=*/true));
    link.client = std::make_unique<Node>(config_for(kind, /*listen=*/false));

    on_server(*link.server);
    on_client(*link.client);

    if (!link.server->start() || !link.client->start()) return link;
    link.client->connect("127.0.0.1", link.server->listen_port());
    link.ok = wait_for([&] {
        return link.client->peer_count() == 1 && link.server->peer_count() == 1;
    });
    return link;
}

// ── Experiment: dial cost ───────────────────────────────────────────────────
//
// Time from connect() to on_peer_connected: everything spent before a single
// application byte can move.
//
// The two are at parity by construction, and the measurement confirms it: TCP
// spends one round trip in the kernel's three-way handshake before data may
// flow, and the datagram side spends one on Syn → Ack before Noise_XX starts
// (UdpStream's constructor, then UdpMux::accept_inbound()). Neither is ahead.
//
// What the row is really for is the round trip *both* of them spend. The Syn
// carries nothing but the optional address-validation cookie, so there is room
// in it for the initiator's first Noise message — carrying it there would make a
// dial 0-RTT-to-handshake and put the datagram wire a full round trip ahead of
// TCP, which is the kind of win a NAT-traversing P2P dial actually notices. On
// loopback that round trip is tens of microseconds and invisible next to node
// setup and the X25519 work; on a 100 ms path it is the whole difference.

struct DialResult { double median_ms = 0, p95_ms = 0; };

DialResult bench_dial(TransportKind kind, int dials) {
    Node server(config_for(kind, /*listen=*/true));
    if (!server.start()) return {};

    std::vector<double> samples;
    samples.reserve(static_cast<size_t>(dials));

    for (int i = 0; i < dials; ++i) {
        Node client(config_for(kind, /*listen=*/false));
        std::atomic<bool> up{false};
        client.on_peer_connected([&](Peer) { up.store(true, std::memory_order_release); });
        if (!client.start()) break;

        const auto t0 = Clock::now();
        client.connect("127.0.0.1", server.listen_port());
        const bool ok = spin_for([&] { return up.load(std::memory_order_acquire); });
        const double ms = std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
        client.stop();
        if (!ok) continue;

        if (i >= 2) samples.push_back(ms);  // first dials warm the allocator/page cache
        // Let the server retire the peer before the next dial, so a fresh dial is
        // never racing a teardown.
        wait_for([&] { return server.peer_count() == 0; }, 2s);
    }

    server.stop();
    return {percentile(samples, 0.50), percentile(samples, 0.95)};
}

// ── Experiment: request/response latency ────────────────────────────────────
//
// Strictly serial: one message out, wait for the echo, repeat. Nothing else is
// in flight, so nothing can carry an acknowledgement for free — which is the
// condition under which a delayed ack would show up. UdpStream sends a pure ack
// immediately for an out-of-order packet, a Syn or a Fin, and otherwise every
// second packet (unacked_packets_ >= 2); a ping-pong sends one packet per turn,
// so this is the shape that probes that rule hardest.

struct RttResult { double median_us = 0, p99_us = 0; };

RttResult bench_rtt(TransportKind kind, int iterations, size_t payload_size) {
    std::atomic<uint64_t> replies{0};

    Link2 link = connect_pair(
        kind,
        [](Node& server) {
            server.on("echo", [&server](Peer, ByteView payload) {
                server.broadcast("echo", payload);  // one peer; broadcast is the reply
            });
        },
        [&](Node& client) {
            client.on("echo", [&](Peer, ByteView) { replies.fetch_add(1, std::memory_order_release); });
        });
    if (!link.ok) return {};

    const std::string msg(payload_size, 'p');
    std::vector<double> samples;
    samples.reserve(static_cast<size_t>(iterations));

    for (int i = 0; i < iterations; ++i) {
        const uint64_t before = replies.load(std::memory_order_acquire);
        const auto     t0     = Clock::now();
        link.client->broadcast("echo", ByteView(msg));
        if (!spin_for([&] { return replies.load(std::memory_order_acquire) > before; }, 2s)) break;
        const double us = std::chrono::duration<double, std::micro>(Clock::now() - t0).count();
        if (i >= iterations / 10) samples.push_back(us);  // discard the warm-up tenth
    }

    return {percentile(samples, 0.50), percentile(samples, 0.99)};
}

// ── Experiment: bulk throughput ─────────────────────────────────────────────
//
// Paced: the sender never lets more than `credit` bytes go unacknowledged by the
// application. Without that, the two wires would be measured under different
// conditions — see bench_burst() for why — and this row is about steady-state
// cost, not about buffer limits.

struct BulkResult { double mb_per_s = 0, cpu_s_per_gb = 0; };

BulkResult bench_bulk(TransportKind kind, size_t total_bytes, size_t frame_size, size_t credit) {
    std::atomic<size_t> got{0};

    Link2 link = connect_pair(
        kind,
        [&](Node& server) {
            server.on("bulk", [&](Peer, ByteView p) {
                got.fetch_add(p.size(), std::memory_order_release);
            });
        },
        [](Node&) {});
    if (!link.ok) return {};

    const std::string chunk(frame_size, 'z');
    const size_t      frames = total_bytes / frame_size;

    const auto   t0 = Clock::now();
    const double c0 = cpu_seconds();
    for (size_t i = 0; i < frames; ++i) {
        link.client->broadcast("bulk", ByteView(chunk));
        const size_t sent = (i + 1) * frame_size;
        if (!spin_for([&] { return got.load(std::memory_order_acquire) + credit >= sent; }, 30s))
            return {};
    }
    if (!spin_for([&] { return got.load(std::memory_order_acquire) >= frames * frame_size; }, 30s))
        return {};

    const double secs = std::chrono::duration<double>(Clock::now() - t0).count();
    const double cpu  = cpu_seconds() - c0;
    const double moved = static_cast<double>(frames) * frame_size;

    return {moved / 1e6 / secs, cpu / (moved / 1e9)};
}

// ── Experiment: small messages ──────────────────────────────────────────────
//
// Per-message costs rather than per-byte ones: framing, encryption, one trip
// through the send queue, and one packet on the wire.
//
// This is the row where the two wires diverge most, and not for the reason one
// would guess. UdpStream deliberately has no Nagle (udp_stream.h: "Frames are
// already batched by the connection's send queue, so delaying a partial packet
// would buy nothing and cost a round trip"). The TCP side has no matching
// decision: TCP_NODELAY is never set anywhere in the library, so the kernel's
// Nagle stays on. With a window of small messages outstanding — exactly what
// this experiment creates — that is the classic Nagle / delayed-ACK interaction,
// and it costs far more than the user-space stack's whole per-packet overhead.
//
// So the gap here is not "the datagram transport is faster". It is a missing
// setsockopt on the TCP path, measured. A strict ping-pong (the rtt row above)
// never has unacknowledged small data outstanding, so Nagle cannot trigger
// there — which is why the two rows disagree so sharply, and why they have to be
// read together.

struct SmallResult { double msgs_per_s = 0, cpu_us_per_msg = 0; };

SmallResult bench_small(TransportKind kind, int count, size_t size, int credit_msgs) {
    std::atomic<int> got{0};

    Link2 link = connect_pair(
        kind,
        [&](Node& server) {
            server.on("small", [&](Peer, ByteView) { got.fetch_add(1, std::memory_order_release); });
        },
        [](Node&) {});
    if (!link.ok) return {};

    const std::string msg(size, 'm');

    const auto   t0 = Clock::now();
    const double c0 = cpu_seconds();
    for (int i = 0; i < count; ++i) {
        link.client->broadcast("small", ByteView(msg));
        if (!spin_for([&] { return got.load(std::memory_order_acquire) + credit_msgs >= i + 1; }, 30s))
            return {};
    }
    if (!spin_for([&] { return got.load(std::memory_order_acquire) >= count; }, 30s)) return {};

    const double secs = std::chrono::duration<double>(Clock::now() - t0).count();
    const double cpu  = cpu_seconds() - c0;
    return {count / secs, cpu * 1e6 / count};
}

// ── Experiment: idle cost ───────────────────────────────────────────────────
//
// N connected peers with no traffic at all. TCP's cost here is a poll that never
// fires. The datagram side runs UdpMux::tick() from the reactor loop, but that is
// a single comparison against the earliest scheduled deadline unless something has
// actually come due — an idle stream schedules itself one keep-alive ahead. This
// row is what is left of that: the reactor's own idle poll cap, plus the keep-alive
// traffic itself.
//
// Also reports resident memory. Each peer here is a whole Node, so the figure
// covers both ends — and on the datagram side most of the difference is not
// per-stream at all but per-*node*: UdpMux allocates its batch staging up front
// and keeps it for life (recv_storage_ + send_storage_, 2 x kUdpBatchMax x
// kMaxDatagram ~ 76 KiB), so even a dial-only node pays it just for having a UDP
// socket. A stream itself starts nearly empty — its queues and reorder map only
// grow to what is actually outstanding.

struct IdleResult { double cpu_percent_core = 0, bytes_per_peer = 0; };

IdleResult bench_idle(TransportKind kind, int peers, std::chrono::milliseconds window) {
    Node server(config_for(kind, /*listen=*/true));
    if (!server.start()) return {};

    const size_t rss_before = resident_bytes();

    std::vector<std::unique_ptr<Node>> clients;
    clients.reserve(static_cast<size_t>(peers));
    for (int i = 0; i < peers; ++i) {
        clients.push_back(std::make_unique<Node>(config_for(kind, /*listen=*/false)));
        if (!clients.back()->start()) break;
        clients.back()->connect("127.0.0.1", server.listen_port());
    }
    if (!wait_for([&] { return server.peer_count() >= static_cast<size_t>(peers); }, 30s)) {
        for (auto& c : clients) c->stop();
        server.stop();
        return {};
    }

    const size_t rss_after = resident_bytes();

    const double c0 = cpu_seconds();
    const auto   t0 = Clock::now();
    std::this_thread::sleep_for(window);
    const double cpu  = cpu_seconds() - c0;
    const double secs = std::chrono::duration<double>(Clock::now() - t0).count();

    for (auto& c : clients) c->stop();
    server.stop();

    // Each peer is a full Node here (its own reactor), so the per-peer figure
    // covers both ends of the connection — it is an upper bound on what one peer
    // costs a server, not the connection's own footprint.
    const double per_peer = (rss_after > rss_before)
                                ? static_cast<double>(rss_after - rss_before) / peers
                                : 0.0;
    return {100.0 * cpu / secs, per_peer};
}

// ── Experiment: burst tolerance ─────────────────────────────────────────────
//
// How much an application can hand the connection in one unpaced go before it is
// dropped with CloseReason::SlowConsumer.
//
// This is the sharpest place the two wires stop being interchangeable, and it is
// structural rather than incidental. On TCP a burst lands in the kernel's send
// buffer, which on loopback is large and auto-tuned, so Connection's own queue
// barely grows. On the datagram side there is no kernel buffer to absorb
// anything: UdpStream::write() takes at most kSendQueueLimit (2 MiB) and drains
// only as fast as cwnd/RTT allows, so the remainder piles up in the connection's
// ChainedSendBuffer until it crosses Connection::kDefaultSendHighWater (8 MiB)
// and the peer is dropped.
//
// The consequence is worth stating plainly: identical application code can
// survive on TCP and lose its peer on UDP, with no API through which the
// application could have known. What this row reports is where that line sits.

double bench_burst(TransportKind kind, size_t frame_size, size_t cap_bytes) {
    std::atomic<bool>   dropped{false};
    std::atomic<size_t> got{0};

    Link2 link = connect_pair(
        kind,
        [&](Node& server) {
            server.on("burst", [&](Peer, ByteView p) {
                got.fetch_add(p.size(), std::memory_order_release);
            });
        },
        [&](Node& client) {
            client.on_peer_disconnected([&](const PeerId&) {
                dropped.store(true, std::memory_order_release);
            });
        });
    if (!link.ok) return 0;

    const std::string chunk(frame_size, 'b');
    size_t offered = 0;
    while (offered < cap_bytes && !dropped.load(std::memory_order_acquire)) {
        link.client->broadcast("burst", ByteView(chunk));
        offered += frame_size;
    }
    // The drop is decided on a reactor thread and may land just after the loop.
    wait_for([&] { return dropped.load(std::memory_order_acquire); }, 500ms);

    return dropped.load(std::memory_order_acquire) ? static_cast<double>(offered) : 0.0;
}

// ── Experiment: the fallback race ───────────────────────────────────────────
//
// A node that speaks only TCP, dialed by a node that prefers UDP. The Happy-
// Eyeballs race in node/dialer.h starts UDP at t=0 and brings TCP in after
// NodeConfig::transport_fallback_ms; whichever handshake finishes first wins and
// the loser is closed with CloseReason::DialSuperseded.
//
// Two dials are timed, because only one of them has to cost what it costs:
//
//   cold   — the first dial to a peer nobody has ever talked to. Paying the
//            fallback delay is inherent: there is nothing to go on.
//   re-dial — dialing the same address again, after a connection to it has
//            already completed and reported (via IdentifyMessage::transports)
//            that the peer is TCP-only.
//
// The gap between the two is the whole point. A re-dial should cost nothing like
// a cold one: Node::handle_identify hands the transports bitmask to
// Dialer::remember(), keyed by the address rather than by the peer — so it
// outlives the disconnect that erases the PeerTable entry — and the next dial to
// that address starts with the transport the peer actually has. The fallback
// timer is still armed behind it, because the knowledge can be stale, but it
// never fires when the hint is right.
//
// A re-dial back up at the cold figure would mean that path has been broken:
// either identify is not reaching the dialer, or the address the reconnect uses
// is not the one that was recorded.

struct FallbackResult { double cold_ms = 0, warm_ms = 0; uint32_t configured_ms = 0; };

FallbackResult bench_fallback(uint32_t fallback_ms) {
    FallbackResult out;
    out.configured_ms = fallback_ms;

    // A TCP-only listener, on a port we pin so the re-dial targets the SAME
    // address the first dial did — otherwise the second dial is a different
    // target and proves nothing. Bind once on an ephemeral port to find a free
    // one, then reuse that number for the node that is actually measured.
    uint16_t port = 0;
    {
        Node probe(config_for(TransportKind::Tcp, /*listen=*/true));
        if (!probe.start()) return out;
        port = probe.listen_port();
        probe.stop();
    }

    NodeConfig server_cfg  = config_for(TransportKind::Tcp, /*listen=*/true);  // TCP only
    server_cfg.listen_port = port;

    auto server = std::make_unique<Node>(server_cfg);
    if (!server->start()) return out;

    NodeConfig client_cfg            = config_for(TransportKind::Udp, /*listen=*/false);
    client_cfg.enable_tcp            = true;   // both offered...
    client_cfg.enable_udp            = true;
    client_cfg.preferred_transport   = TransportKind::Udp;  // ...UDP tried first
    client_cfg.transport_fallback_ms = fallback_ms;

    Node client(client_cfg);
    std::atomic<int> ups{0};
    client.on_peer_connected([&](Peer) { ups.fetch_add(1, std::memory_order_release); });
    if (!client.start()) { server->stop(); return out; }

    const auto dial_once = [&](double& into) {
        const int  before = ups.load(std::memory_order_acquire);
        const auto t0     = Clock::now();
        client.connect("127.0.0.1", port);
        if (wait_for([&] { return ups.load(std::memory_order_acquire) > before; }, 30s))
            into = std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
    };

    dial_once(out.cold_ms);

    // Wait for the identify to actually land before tearing the peer down.
    //
    // Not a formality: on Noise_XX the initiator is established a message earlier
    // than the responder, so on_peer_connected — which is what dial_once waits for
    // — fires on this side before the peer has even finished its own handshake,
    // let alone sent its identify. Dropping the server here would measure a
    // re-dial to a peer this node never actually learned anything about, which is
    // the cold case wearing the warm case's name. A non-zero transports mask is
    // exactly the fact the re-dial is supposed to exploit, so it is the condition
    // worth waiting on.
    wait_for([&] {
        const std::vector<PeerInfo> known = client.peers();
        return !known.empty() && known.front().supported_transports != PeerTransportNone;
    }, 5s);

    // Drop the connection but keep the client node alive, so the second dial is
    // made by a node that has already completed a connection to this address and
    // seen its identify. There is no public disconnect(), so the listener is
    // replaced instead — same port, so the dial target is unchanged.
    server->stop();
    server.reset();
    wait_for([&] { return client.peer_count() == 0; }, 5s);

    server = std::make_unique<Node>(server_cfg);
    if (!server->start()) { client.stop(); return out; }

    dial_once(out.warm_ms);

    client.stop();
    server->stop();
    return out;
}

} // namespace

// ── Main ────────────────────────────────────────────────────────────────────

int main() {
    Logger::getInstance().set_log_level(LogLevel::ERROR);
#if !defined(_WIN32)
    g_color = isatty(1) != 0;
#endif

    std::printf("%slibrats transport suite — the same encrypted protocol over two wires%s\n",
                col("\x1b[1m"), col("\x1b[0m"));
    std::printf("two real Nodes in this process, 127.0.0.1, Noise_XX, one reactor thread each\n");
    std::printf("CPU figures are whole-process: they cover sender AND receiver\n");

    // ── dial ────────────────────────────────────────────────────────────────
    {
        constexpr int kDials = 25;
        const auto tcp = bench_dial(TransportKind::Tcp, kDials);
        const auto udp = bench_dial(TransportKind::Udp, kDials);
        header("dial — connect() to established peer (25 dials)");
        row("median", tcp.median_ms, udp.median_ms, "ms", true);
        row("p95",    tcp.p95_ms,    udp.p95_ms,    "ms", true);
        std::printf("  (parity by construction: TCP spends a round trip on its three-way handshake,\n"
                    "   the datagram side spends one on Syn/Ack — then both run Noise_XX. The Syn\n"
                    "   carries no handshake payload, so putting the initiator's first Noise message\n"
                    "   in it would drop that round trip and put UDP ahead of TCP on a real path.)\n");
    }

    // ── rtt ─────────────────────────────────────────────────────────────────
    {
        constexpr int    kIters   = 3000;
        constexpr size_t kPayload = 64;
        const auto tcp = bench_rtt(TransportKind::Tcp, kIters, kPayload);
        const auto udp = bench_rtt(TransportKind::Udp, kIters, kPayload);
        header("rtt — serial request/response, 64 B (3000 turns)");
        row("median", tcp.median_us, udp.median_us, "us", true);
        row("p99",    tcp.p99_us,    udp.p99_us,    "us", true);
        std::printf("  (a p99 anywhere near 20000 us would mean UdpStream::kDelayedAck has landed\n"
                    "   on the critical path; a ping-pong is the shape most likely to put it there.)\n");
    }

    // ── bulk ────────────────────────────────────────────────────────────────
    {
        constexpr size_t kTotal  = 64u * 1024 * 1024;
        constexpr size_t kFrame  = 16u * 1024;
        constexpr size_t kCredit = 2u * 1024 * 1024;   // safe for both wires
        const auto tcp = bench_bulk(TransportKind::Tcp, kTotal, kFrame, kCredit);
        const auto udp = bench_bulk(TransportKind::Udp, kTotal, kFrame, kCredit);
        header("bulk — 64 MiB one way, 16 KiB frames, 2 MiB credit");
        row("throughput",  tcp.mb_per_s,     udp.mb_per_s,     "MB/s", false);
        row("CPU per GB",  tcp.cpu_s_per_gb, udp.cpu_s_per_gb, "s/GB", true);
        std::printf("  (throughput on loopback flatters user space — there is no kernel TCP work\n"
                    "   to skip. CPU per gigabyte is the figure that survives a real network.)\n");
    }

    // ── small ───────────────────────────────────────────────────────────────
    {
        constexpr int    kCount  = 200000;
        constexpr size_t kSize   = 256;
        constexpr int    kCredit = 512;
        const auto tcp = bench_small(TransportKind::Tcp, kCount, kSize, kCredit);
        const auto udp = bench_small(TransportKind::Udp, kCount, kSize, kCredit);
        header("small — 200k x 256 B, 512 messages in flight");
        row("messages",   tcp.msgs_per_s,     udp.msgs_per_s,     "msg/s", false, "%10.0f");
        row("CPU per msg", tcp.cpu_us_per_msg, udp.cpu_us_per_msg, "us",   true, "%8.3f");
        std::printf("  (this gap is NOT the datagram stack being fast — it is Nagle. UdpStream\n"
                    "   disables it by design; the TCP path never sets TCP_NODELAY, so a window of\n"
                    "   small messages hits the classic Nagle/delayed-ACK interaction. The rtt row\n"
                    "   above cannot trigger it (nothing outstanding), which is why they disagree.)\n");
    }

    // ── idle ────────────────────────────────────────────────────────────────
    {
        constexpr int kPeers = 32;
        const auto tcp = bench_idle(TransportKind::Tcp, kPeers, 3000ms);
        const auto udp = bench_idle(TransportKind::Udp, kPeers, 3000ms);
        header("idle — 32 connected peers, no traffic, 3 s");
        row("CPU",             tcp.cpu_percent_core, udp.cpu_percent_core, "% core", true);
        row("resident / peer", tcp.bytes_per_peer / 1024.0, udp.bytes_per_peer / 1024.0,
            "KiB", true);
        std::printf("  (the datagram side schedules each stream at its own next deadline\n"
                    "   (UdpStream::next_deadline), so an idle stream asks to be woken once\n"
                    "   per keep-alive rather than every 20 ms. What is left here is the\n"
                    "   reactor's own Reactor::kMaxPollMs = 50 ms idle poll cap, which both\n"
                    "   transports pay. Each peer is a whole Node, so 'resident / peer'\n"
                    "   covers both ends.)\n");
    }

    // ── burst ───────────────────────────────────────────────────────────────
    {
        constexpr size_t kFrame = 64u * 1024;
        constexpr size_t kCap   = 512u * 1024 * 1024;
        const double tcp = bench_burst(TransportKind::Tcp, kFrame, kCap);
        const double udp = bench_burst(TransportKind::Udp, kFrame, kCap);
        header("burst — unpaced offer until SlowConsumer (cap 512 MiB)");
        row("survived", tcp / (1024.0 * 1024.0), udp / (1024.0 * 1024.0), "MiB", false, "%8.1f");
        std::printf("  (0.0 = never dropped inside the cap. A gap here means identical application\n"
                    "   code survives on one wire and loses its peer on the other — there is no\n"
                    "   writable/backpressure callback through which it could have known.)\n");
    }

    // ── fallback ────────────────────────────────────────────────────────────
    {
        const auto fb = bench_fallback(/*fallback_ms=*/1200);
        std::printf("\n%sfallback — dialing a TCP-only peer with UDP preferred%s\n",
                    col("\x1b[1m"), col("\x1b[0m"));
        std::printf("  configured transport_fallback_ms   %8u ms\n", fb.configured_ms);
        std::printf("  cold dial  (address never tried)   %8.1f ms\n", fb.cold_ms);
        std::printf("  re-dial    (same address, met it)  %8.1f ms\n", fb.warm_ms);
        std::printf("  (identify already told this node the peer is TCP-only, and Dialer::remember\n"
                    "   keeps that by address, so it outlives the disconnect. The re-dial should\n"
                    "   therefore start on TCP and never reach the fallback timer; a figure back up\n"
                    "   at the cold one means that knowledge stopped reaching the dial.)\n");
    }

    std::printf("\nnote: loopback has no loss, no reordering and a near-zero RTT, so congestion\n"
                "control, retransmission and the selective-ack path are all measured at their\n"
                "cheapest. Every UDP figure above is a floor on cost, not a ceiling.\n");
    return 0;
}
