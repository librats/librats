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
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
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
// This is the row where the two wires diverge most, and the reason is NOT the
// one it looks like. Nagle is the obvious suspect — the library never sets
// TCP_NODELAY, and a window of small messages outstanding is exactly the shape
// that triggers it — and this comment used to say so. It is wrong. Setting
// TCP_NODELAY makes this row *worse*, measured, three runs of each build:
//
//     as built             TCP  50-72 k msg/s (16-22 us)   UDP 282-379 k msg/s
//     + TCP_NODELAY        TCP  19-20 k msg/s (57 us)      UDP 314-379 k
//     + deferred flush     TCP 592-656 k      (3.0-3.3 us) UDP 767-786 k
//     + both               TCP 733-906 k      (2.6-2.8 us) UDP 790-797 k
//
// Two measurements say why. The kernel's own segment counter (/proc/net/snmp)
// puts 200 k messages into 14'284 segments with Nagle on and 264'340 with it
// off, so Nagle is currently the ONLY thing coalescing small frames — turning it
// off just buys the receiver a wakeup per message. And strace counts 20'086
// sendmsg calls for 20'000 messages in BOTH builds: the syscall is paid per
// frame either way, because Connection::send() flushes write-through.
//
// So the real gap is that every frame costs its own trip into the kernel, and
// the datagram side partly escapes it on its own: UdpStream::write() tops up the
// tail packet, so consecutive small frames share one 1200-byte datagram, and
// UdpMux hands the socket kUdpBatchMax of them per syscall. The TCP path has
// neither and leans entirely on Nagle to do that batching for it. Deferring the
// flush to the end of a reactor turn brings the two wires to ~1.1-1.3x of each
// other, which is what Link promises — and only THEN is TCP_NODELAY worth
// setting, for a further ~30%.
//
// The rtt row above can show none of this: a strict ping-pong has one frame in
// flight, so there is nothing to coalesce and nothing to batch. The two rows
// have to be read together.

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

// ── Remote mode: the same experiments over a real path ──────────────────────
//
// Everything above runs both ends in this process over 127.0.0.1. That is the
// only way to get a controlled A/B of two transports — same CPU, same clock, no
// third party in the middle — but it is also the one path on which most of what
// the datagram stack exists for is invisible. Loopback has no propagation delay
// for an ack to hide behind, no MTU to size a packet against, no loss for the
// SACK path to repair, no reordering, and no middlebox holding a mapping. Slow
// start never ends, the retransmit queue never has an entry in it, and the RTO
// never fires. Every UDP figure above is a floor on cost for exactly that reason.
//
// This mode answers the other half by running the same experiments against a
// *second copy of this binary* on another host:
//
//     there:  ./bench_transport --serve              # stays up, prints its port
//     here:   ./bench_transport --connect HOST:PORT  # measures, prints, exits
//
// Both ends must agree on --protocol (it is bound into the Noise handshake, so a
// mismatch cannot complete a handshake at all) and the responder must be
// reachable on that port over both wires if both are to be measured.
//
// ── What changes when the path is real ──────────────────────────────────────
//
// The measurements are the same shape, but three of them mean something they
// could not mean on loopback:
//
//   dial      now counts *round trips*, not microseconds of node setup. TCP
//             spends connect + Noise_XX; the datagram side spends Syn/Ack +
//             Noise_XX. On a path with a real RTT the note under bench_dial()
//             stops being theoretical: folding the initiator's first Noise
//             message into the Syn is worth one whole RTT of every dial here.
//   rtt       min is the path itself, median is the path plus this stack, and
//             the gap between median and p99 is queueing — either the network's
//             or ours. A p99 near 20 ms on an otherwise fast path is
//             UdpStream::kDelayedAck landing on the critical path, which no
//             amount of loopback testing will show you.
//   bulk      throughput here is bounded by the path, so the two wires converge
//             on a link that is not the bottleneck — and diverge exactly where
//             congestion control, loss recovery and pacing start to matter,
//             which is the comparison loopback cannot make.
//
// CPU is still whole-process, but in this mode a process is ONE end, so the
// per-gigabyte figures are per-node — a cleaner number than the combined one
// above, and directly comparable between the upload row (sender) and the
// download row (receiver).
//
// ── The wire between the two copies ─────────────────────────────────────────
//
// Four application channels, deliberately tiny:
//
//   "echo"  responder returns the payload verbatim               → rtt
//   "data"  bulk/small payload in either direction; the receiver counts it
//   "ack"   [u64 bytes][u64 msgs] LE, cumulative, from the receiver of "data"
//   "ctl"   ASCII: "flush" (ack now), "push <bytes> <frame> <credit>" (send that
//           much back to me), "push-done"
//
// The acks are what make a one-way measurement honest over a path with delay.
// They serve two purposes at once: they pace the sender (never more than
// `credit` bytes unacknowledged, so neither wire is measured while it is being
// dropped as a slow consumer — see bench_burst) and they are how the sender
// knows the transfer actually landed rather than merely left. Channels are
// multiplexed onto one ordered stream, so a "flush" sent after the last data
// frame is delivered after it: the final ack is exact, not a guess.

namespace remote {

// ── Options ─────────────────────────────────────────────────────────────────

struct Options {
    enum class Role { Loopback, Serve, Connect };
    Role        role     = Role::Loopback;
    std::string host;                              ///< --connect target
    uint16_t    port     = 9977;
    std::string bind;                              ///< "" = dual-stack wildcard
    std::string protocol = "bench-transport/1";
    bool        tcp      = true;                   ///< wires to offer (serve) / measure (connect)
    bool        udp      = true;

    size_t bulk_bytes   = 16u * 1024 * 1024;
    size_t frame_bytes  = 16u * 1024;
    size_t credit_bytes = 4u * 1024 * 1024;
    size_t rtt_payload   = 64;
    int    rtt_turns     = 200;
    int    small_count   = 20000;
    size_t small_bytes   = 256;
    int    small_credit  = 512;
    int    dials         = 8;

    bool   help          = false;
};

constexpr auto kConnectTimeout = 20s;
constexpr auto kBulkTimeout    = 300s;

/// How much a receiver lets accumulate before it acknowledges. Small enough that
/// a sender paced by acks is never starved by the ack cadence itself, large
/// enough that the reverse direction stays negligible next to the forward one.
constexpr uint64_t kAckBytes = 128u * 1024;
constexpr uint64_t kAckMsgs  = 64;

// ── Ack payload ─────────────────────────────────────────────────────────────

void put_u64(std::string& out, uint64_t v) {
    for (int i = 0; i < 8; ++i) out.push_back(static_cast<char>((v >> (8 * i)) & 0xff));
}

uint64_t get_u64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(p[i]) << (8 * i);
    return v;
}

// ── Per-peer state ──────────────────────────────────────────────────────────
//
// Both ends run the same endpoint: the responder may be receiving an upload
// while pushing a download, and the client is the mirror of that. So the
// counters are per peer and per direction, not per role.

struct Session {
    std::atomic<uint64_t> in_bytes{0};      ///< "data" bytes we have received
    std::atomic<uint64_t> in_msgs{0};
    std::atomic<uint64_t> acked_bytes{0};   ///< what the far end says it received
    std::atomic<uint64_t> acked_msgs{0};
    std::atomic<uint64_t> echoes{0};        ///< "echo" replies seen
    std::atomic<bool>     alive{true};

    // Reactor thread only: the last counters we sent an ack for.
    uint64_t sent_ack_bytes = 0;
    uint64_t sent_ack_msgs  = 0;
};

/// Installs the four channels on a node and keeps a Session per peer. The
/// responder additionally serves "ctl", which is the only asymmetry.
class Endpoint {
public:
    Endpoint(Node& node, bool responder, bool verbose)
        : node_(node), responder_(responder), verbose_(verbose) {}

    ~Endpoint() {
        // The node must already be stopped: these threads send through it.
        for (auto& p : pushers_)
            if (p.thread.joinable()) p.thread.join();
    }

    /// Register everything. Handlers run on a reactor thread, so this must be
    /// called before Node::start().
    void install() {
        node_.on_peer_connected([this](const Peer& p) {
            auto s = session(p.id());
            if (verbose_)
                std::printf("  peer up    %s\n", p.id().short_hex().c_str());
            (void)s;
        });
        node_.on_peer_disconnected([this](const PeerId& id) {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = sessions_.find(id);
            if (it != sessions_.end()) {
                it->second->alive.store(false, std::memory_order_release);
                sessions_.erase(it);
            }
            if (verbose_) std::printf("  peer down  %s\n", id.short_hex().c_str());
        });

        node_.on("echo", [this](const Peer& p, ByteView payload) {
            if (responder_) p.send("echo", payload);
            else            session(p.id())->echoes.fetch_add(1, std::memory_order_release);
        });

        node_.on("data", [this](const Peer& p, ByteView payload) {
            auto s = session(p.id());
            const uint64_t bytes = s->in_bytes.fetch_add(payload.size(), std::memory_order_release)
                                   + payload.size();
            const uint64_t msgs  = s->in_msgs.fetch_add(1, std::memory_order_release) + 1;
            if (bytes - s->sent_ack_bytes >= kAckBytes || msgs - s->sent_ack_msgs >= kAckMsgs)
                send_ack(p, *s, bytes, msgs);
        });

        node_.on("ack", [this](const Peer& p, ByteView payload) {
            if (payload.size() < 16) return;
            auto s = session(p.id());
            s->acked_bytes.store(get_u64(payload.data()),     std::memory_order_release);
            s->acked_msgs.store (get_u64(payload.data() + 8), std::memory_order_release);
        });

        node_.on("ctl", [this](const Peer& p, ByteView payload) {
            const std::string cmd(reinterpret_cast<const char*>(payload.data()), payload.size());
            auto s = session(p.id());
            if (cmd == "flush") {
                // Ordered behind every "data" frame that preceded it, so this ack
                // is the exact end of the transfer rather than a sample of it.
                send_ack(p, *s, s->in_bytes.load(std::memory_order_acquire),
                         s->in_msgs.load(std::memory_order_acquire));
                return;
            }
            if (!responder_) return;
            unsigned long long total = 0, frame = 0, credit = 0;
            if (std::sscanf(cmd.c_str(), "push %llu %llu %llu", &total, &frame, &credit) == 3)
                start_push(p.id(), s, static_cast<size_t>(total), static_cast<size_t>(frame),
                           static_cast<size_t>(credit));
        });
    }

    std::shared_ptr<Session> session(const PeerId& id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sessions_.find(id);
        if (it != sessions_.end()) return it->second;
        return sessions_.emplace(id, std::make_shared<Session>()).first->second;
    }

private:
    void send_ack(const Peer& p, Session& s, uint64_t bytes, uint64_t msgs) {
        std::string payload;
        payload.reserve(16);
        put_u64(payload, bytes);
        put_u64(payload, msgs);
        p.send("ack", ByteView(payload));
        s.sent_ack_bytes = bytes;
        s.sent_ack_msgs  = msgs;
    }

    /// Serve a "push": send `total` bytes back to the requester, paced by the
    /// acks it sends us. Off the reactor thread — a reactor callback that blocked
    /// on flow control would deadlock the connection it is waiting on.
    void start_push(PeerId to, std::shared_ptr<Session> s, size_t total, size_t frame,
                    size_t credit) {
        if (frame == 0 || total == 0) return;
        if (verbose_)
            std::printf("  push       %.1f MiB -> %s\n", total / (1024.0 * 1024.0),
                        to.short_hex().c_str());

        // Retire the threads of earlier pushes before starting one more, so a
        // responder left up across many runs does not accumulate them. Only the
        // reactor thread gets here, and it is the only writer of pushers_.
        pushers_.erase(std::remove_if(pushers_.begin(), pushers_.end(),
                                      [](Pusher& p) {
                                          if (!p.finished->load(std::memory_order_acquire))
                                              return false;
                                          p.thread.join();
                                          return true;
                                      }),
                       pushers_.end());

        Pusher pusher;
        auto   finished = pusher.finished;
        pusher.thread = std::thread([this, to, s, total, frame, credit, finished] {
            const std::string chunk(frame, 'd');
            size_t sent = 0;
            while (sent < total && s->alive.load(std::memory_order_acquire)) {
                const bool room = wait_for(
                    [&] {
                        return !s->alive.load(std::memory_order_acquire) ||
                               s->acked_bytes.load(std::memory_order_acquire) + credit >= sent;
                    },
                    kBulkTimeout);
                if (!room) break;
                node_.send(to, "data", ByteView(chunk));
                sent += frame;
            }
            const std::string done = "push-done";
            node_.send(to, "ctl", ByteView(done));
            finished->store(true, std::memory_order_release);
        });
        pushers_.push_back(std::move(pusher));
    }

    /// A push in flight, plus the flag its thread sets on the way out so a later
    /// push can join it instead of leaving the handle behind.
    struct Pusher {
        std::thread                        thread;
        std::shared_ptr<std::atomic<bool>> finished = std::make_shared<std::atomic<bool>>(false);
    };

    Node&      node_;
    const bool responder_;
    const bool verbose_;

    std::mutex mutex_;
    std::unordered_map<PeerId, std::shared_ptr<Session>, PeerId::Hash> sessions_;
    std::vector<Pusher> pushers_;
};

// ── Node configuration for a real interface ─────────────────────────────────

NodeConfig remote_config(const Options& o, bool listen, bool tcp, bool udp) {
    NodeConfig c;
    c.bind_address           = o.bind;
    c.protocol               = o.protocol;
    c.security               = NodeConfig::Security::Noise;
    c.enable_listen          = listen;
    c.listen_port            = listen ? o.port : 0;
    c.enable_tcp             = tcp;
    c.enable_udp             = udp;
    c.preferred_transport    = udp ? TransportKind::Udp : TransportKind::Tcp;
    // Only ever one wire is enabled on the measuring side, so there is nothing to
    // race — and a fallback that could quietly switch wires would report one
    // transport's numbers under the other's name.
    c.transport_fallback_ms  = 0;
    c.max_peers              = 0;
    c.enable_network_monitor = false;
    return c;
}

// ── The responder ───────────────────────────────────────────────────────────

volatile std::sig_atomic_t g_stop = 0;

void on_signal(int) { g_stop = 1; }

int serve(const Options& o) {
    Node node(remote_config(o, /*listen=*/true, o.tcp, o.udp));
    Endpoint endpoint(node, /*responder=*/true, /*verbose=*/true);
    endpoint.install();

    if (!node.start()) {
        std::fprintf(stderr, "bench_transport: cannot listen on port %u\n",
                     static_cast<unsigned>(o.port));
        return 1;
    }

    const uint8_t t = node.transports();
    std::printf("%sbench_transport responder%s\n", col("\x1b[1m"), col("\x1b[0m"));
    std::printf("  listening on port %u  (%s%s%s)\n", static_cast<unsigned>(node.listen_port()),
                (t & PeerTransportTcp) ? "TCP" : "",
                ((t & PeerTransportTcp) && (t & PeerTransportUdp)) ? " + " : "",
                (t & PeerTransportUdp) ? "UDP" : "");
    std::printf("  protocol  %s\n", o.protocol.c_str());
    std::printf("  peer id   %s\n", node.local_id().short_hex().c_str());
    std::printf("\n  run on the other host:\n"
                "    ./bench_transport --connect <this-host>:%u%s%s\n\n"
                "  waiting (Ctrl-C to stop)\n",
                static_cast<unsigned>(node.listen_port()),
                o.protocol == "bench-transport/1" ? "" : " --protocol ",
                o.protocol == "bench-transport/1" ? "" : o.protocol.c_str());

    std::signal(SIGINT, on_signal);
#if defined(SIGTERM)
    std::signal(SIGTERM, on_signal);
#endif
    while (g_stop == 0) std::this_thread::sleep_for(100ms);

    std::printf("\nstopping\n");
    node.stop();
    return 0;
}

// ── The measuring side ──────────────────────────────────────────────────────

struct Run {
    bool        attempted = false;
    bool        connected = false;
    std::string remote_id;
    std::string failure;

    double dial_median_ms = 0, dial_p95_ms = 0;
    double rtt_min_ms = 0, rtt_median_ms = 0, rtt_p99_ms = 0;
    double up_mb_s = 0, up_cpu_s_gb = 0;
    double down_mb_s = 0, down_cpu_s_gb = 0;
    double small_msgs_s = 0;
};

/// One connected client node, plus the endpoint whose handlers it runs.
struct Wire {
    std::unique_ptr<Endpoint> endpoint;   // declared first: destroyed last
    std::unique_ptr<Node>     node;
    PeerId                    remote;
    std::shared_ptr<Session>  session;
    bool                      ok = false;

    Wire() = default;
    // Movable, not copyable — open_wire() returns one by value, and the
    // user-declared destructor below would otherwise suppress the move (Link2
    // above carries the same note for the same reason).
    Wire(Wire&&) = default;
    Wire& operator=(Wire&&) = default;
    Wire(const Wire&) = delete;
    Wire& operator=(const Wire&) = delete;

    ~Wire() {
        if (node) node->stop();           // joins the reactors before anything is freed
    }
};

Wire open_wire(TransportKind kind, const Options& o) {
    Wire w;
    w.node = std::make_unique<Node>(
        remote_config(o, /*listen=*/false, kind == TransportKind::Tcp, kind == TransportKind::Udp));
    w.endpoint = std::make_unique<Endpoint>(*w.node, /*responder=*/false, /*verbose=*/false);
    w.endpoint->install();

    std::atomic<bool> up{false};
    w.node->on_peer_connected([&](const Peer&) { up.store(true, std::memory_order_release); });
    if (!w.node->start()) return w;

    w.node->connect(o.host, o.port);
    if (!wait_for([&] { return up.load(std::memory_order_acquire); }, kConnectTimeout)) return w;

    const std::vector<PeerInfo> known = w.node->peers();
    if (known.empty()) return w;
    w.remote  = known.front().id;
    w.session = w.endpoint->session(w.remote);
    w.ok      = true;
    return w;
}

/// connect() → on_peer_connected against the remote host, with a fresh node each
/// time so nothing is reused: a full dial, every round trip of it.
void measure_dial(TransportKind kind, const Options& o, Run& run) {
    std::vector<double> samples;
    samples.reserve(static_cast<size_t>(o.dials));

    for (int i = 0; i < o.dials; ++i) {
        Node client(remote_config(o, /*listen=*/false, kind == TransportKind::Tcp,
                                  kind == TransportKind::Udp));
        std::atomic<bool> up{false};
        client.on_peer_connected([&](const Peer&) { up.store(true, std::memory_order_release); });
        if (!client.start()) break;

        const auto t0 = Clock::now();
        client.connect(o.host, o.port);
        const bool ok = wait_for([&] { return up.load(std::memory_order_acquire); }, kConnectTimeout);
        const double ms = std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
        client.stop();
        // The first dial warms name resolution, so it is dropped — unless it is
        // the only one asked for, in which case a warm figure beats no figure.
        if (ok && (i > 0 || o.dials == 1)) samples.push_back(ms);
    }

    run.dial_median_ms = percentile(samples, 0.50);
    run.dial_p95_ms    = percentile(samples, 0.95);
}

/// Serial echo. min is the path, median is the path plus this stack, and the
/// spread between them and p99 is queueing on one side or the other.
void measure_rtt(const Options& o, Wire& w, Run& run) {
    const std::string msg(o.rtt_payload, 'p');
    std::vector<double> samples;
    samples.reserve(static_cast<size_t>(o.rtt_turns));

    for (int i = 0; i < o.rtt_turns; ++i) {
        const uint64_t before = w.session->echoes.load(std::memory_order_acquire);
        const auto     t0     = Clock::now();
        w.node->send(w.remote, "echo", ByteView(msg));
        if (!spin_for([&] { return w.session->echoes.load(std::memory_order_acquire) > before; },
                      std::chrono::milliseconds(30000)))
            break;
        const double ms = std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
        if (i >= o.rtt_turns / 10) samples.push_back(ms);   // discard the warm-up tenth
    }

    if (samples.empty()) return;
    run.rtt_min_ms    = *std::min_element(samples.begin(), samples.end());
    run.rtt_median_ms = percentile(samples, 0.50);
    run.rtt_p99_ms    = percentile(samples, 0.99);
}

/// Upload: we send, the remote counts and acks. Ack-paced, so the connection is
/// never measured while it is over its send high-water mark, and the transfer is
/// timed to the final ack — bytes that landed, not bytes that left.
void measure_upload(const Options& o, Wire& w, Run& run) {
    const std::string chunk(o.frame_bytes, 'z');
    const size_t      frames = o.bulk_bytes / o.frame_bytes;
    const uint64_t    base   = w.session->acked_bytes.load(std::memory_order_acquire);

    const auto   t0 = Clock::now();
    const double c0 = cpu_seconds();
    for (size_t i = 0; i < frames; ++i) {
        w.node->send(w.remote, "data", ByteView(chunk));
        const uint64_t sent = static_cast<uint64_t>(i + 1) * o.frame_bytes;
        if (!wait_for(
                [&] {
                    return w.session->acked_bytes.load(std::memory_order_acquire) + o.credit_bytes
                           >= base + sent;
                },
                kBulkTimeout))
            return;
    }
    const std::string flush = "flush";
    w.node->send(w.remote, "ctl", ByteView(flush));
    const uint64_t target = base + static_cast<uint64_t>(frames) * o.frame_bytes;
    if (!wait_for([&] { return w.session->acked_bytes.load(std::memory_order_acquire) >= target; },
                  kBulkTimeout))
        return;

    const double secs  = std::chrono::duration<double>(Clock::now() - t0).count();
    const double cpu   = cpu_seconds() - c0;
    const double moved = static_cast<double>(frames) * o.frame_bytes;
    run.up_mb_s      = moved / 1e6 / secs;
    run.up_cpu_s_gb  = cpu / (moved / 1e9);
}

/// Download: the remote sends, paced by our acks. Asymmetric links are the rule
/// rather than the exception, so this is not the upload row read backwards.
void measure_download(const Options& o, Wire& w, Run& run) {
    const size_t   frames = o.bulk_bytes / o.frame_bytes;
    const uint64_t total  = static_cast<uint64_t>(frames) * o.frame_bytes;
    const uint64_t base   = w.session->in_bytes.load(std::memory_order_acquire);

    char cmd[96];
    std::snprintf(cmd, sizeof(cmd), "push %llu %llu %llu",
                  static_cast<unsigned long long>(total),
                  static_cast<unsigned long long>(o.frame_bytes),
                  static_cast<unsigned long long>(o.credit_bytes));
    const std::string request(cmd);

    const auto   t0 = Clock::now();
    const double c0 = cpu_seconds();
    w.node->send(w.remote, "ctl", ByteView(request));
    if (!wait_for([&] { return w.session->in_bytes.load(std::memory_order_acquire) >= base + total; },
                  kBulkTimeout))
        return;

    const double secs = std::chrono::duration<double>(Clock::now() - t0).count();
    const double cpu  = cpu_seconds() - c0;
    run.down_mb_s     = static_cast<double>(total) / 1e6 / secs;
    run.down_cpu_s_gb = cpu / (static_cast<double>(total) / 1e9);
}

/// Many small frames, paced by messages rather than bytes: per-message cost over
/// a path where a per-packet round trip is not free.
void measure_small(const Options& o, Wire& w, Run& run) {
    const std::string msg(o.small_bytes, 'm');
    const uint64_t    base = w.session->acked_msgs.load(std::memory_order_acquire);

    const auto t0 = Clock::now();
    for (int i = 0; i < o.small_count; ++i) {
        w.node->send(w.remote, "data", ByteView(msg));
        const uint64_t sent = static_cast<uint64_t>(i) + 1;
        if (!wait_for(
                [&] {
                    return w.session->acked_msgs.load(std::memory_order_acquire) +
                               static_cast<uint64_t>(o.small_credit) >= base + sent;
                },
                kBulkTimeout))
            return;
    }
    const std::string flush = "flush";
    w.node->send(w.remote, "ctl", ByteView(flush));
    const uint64_t target = base + static_cast<uint64_t>(o.small_count);
    if (!wait_for([&] { return w.session->acked_msgs.load(std::memory_order_acquire) >= target; },
                  kBulkTimeout))
        return;

    const double secs = std::chrono::duration<double>(Clock::now() - t0).count();
    run.small_msgs_s  = o.small_count / secs;
}

Run measure_wire(TransportKind kind, const Options& o) {
    Run run;
    run.attempted = true;

    std::printf("  %s: dialing %s:%u ...\n", wire(kind), o.host.c_str(),
                static_cast<unsigned>(o.port));
    Wire w = open_wire(kind, o);
    if (!w.ok) {
        run.failure = "no connection";
        return run;
    }
    run.connected = true;
    run.remote_id = w.remote.short_hex();

    std::printf("  %s: connected to %s — rtt ...", wire(kind), run.remote_id.c_str());
    std::fflush(stdout);
    measure_rtt(o, w, run);
    std::printf(" upload ...");
    std::fflush(stdout);
    measure_upload(o, w, run);
    std::printf(" download ...");
    std::fflush(stdout);
    measure_download(o, w, run);
    std::printf(" small ...");
    std::fflush(stdout);
    measure_small(o, w, run);
    std::printf(" dial ...");
    std::fflush(stdout);

    // Dials last: each one is a fresh node, and doing them while the measured
    // connection is idle keeps them off the path of everything above.
    measure_dial(kind, o, run);
    std::printf(" done\n");
    return run;
}

/// The two-column comparison needs both wires. A run that measured only one
/// (--transport tcp, or a path where the other never came up) prints the same
/// rows in one column rather than a column of zeros next to a verdict that
/// cannot be computed.
struct Table {
    bool tcp = false;
    bool udp = false;

    bool both() const { return tcp && udp; }

    void head(const char* title) const {
        if (both()) { header(title); return; }
        std::printf("\n%s%s%s\n", col("\x1b[1m"), title, col("\x1b[0m"));
        std::printf("  %-34s %10s   %-6s\n", "", tcp ? "TCP" : "UDP", "unit");
        std::printf("  %-34s %10s   %-6s\n", "----------------------------------",
                    "----------", "------");
    }

    void line(const char* label, double t, double u, const char* unit, bool lower_is_better,
              const char* fmt = "%8.2f") const {
        if (both()) { row(label, t, u, unit, lower_is_better, fmt); return; }
        char value[64];
        std::snprintf(value, sizeof(value), fmt, tcp ? t : u);
        std::printf("  %-34s %10s   %-6s\n", label, value, unit);
    }
};

int connect_and_measure(const Options& o) {
    std::printf("%slibrats transport suite — a real path, not loopback%s\n",
                col("\x1b[1m"), col("\x1b[0m"));
    std::printf("responder %s:%u, protocol %s\n", o.host.c_str(), static_cast<unsigned>(o.port),
                o.protocol.c_str());
    std::printf("CPU figures cover THIS end only — one process is one node here\n\n");

    Run tcp, udp;
    if (o.tcp) tcp = measure_wire(TransportKind::Tcp, o);
    if (o.udp) udp = measure_wire(TransportKind::Udp, o);

    for (const auto* r : {&tcp, &udp}) {
        if (r->attempted && !r->connected)
            std::printf("\n  %s%s over %s — is the responder up, is the port reachable over\n"
                        "  this wire, and does --protocol match on both sides?%s\n",
                        col("\x1b[33m"), r->failure.c_str(), (r == &tcp) ? "TCP" : "UDP",
                        col("\x1b[0m"));
    }
    if (!tcp.connected && !udp.connected) return 1;

    const Table table{tcp.connected, udp.connected};

    table.head("dial — connect() to established peer, over the real path");
    table.line("median", tcp.dial_median_ms, udp.dial_median_ms, "ms", true);
    table.line("p95",    tcp.dial_p95_ms,    udp.dial_p95_ms,    "ms", true);
    std::printf("  (round trips now, not node setup: TCP pays connect + Noise_XX, the datagram\n"
                "   side Syn/Ack + Noise_XX. Carrying the initiator's first Noise message in the\n"
                "   Syn would remove one full RTT from every dial on a path like this one.)\n");

    table.head("rtt — serial request/response");
    table.line("min",    tcp.rtt_min_ms,    udp.rtt_min_ms,    "ms", true, "%8.3f");
    table.line("median", tcp.rtt_median_ms, udp.rtt_median_ms, "ms", true, "%8.3f");
    table.line("p99",    tcp.rtt_p99_ms,    udp.rtt_p99_ms,    "ms", true, "%8.3f");
    std::printf("  (min is the path itself; median-minus-min is what this stack adds; a p99 that\n"
                "   jumps ~20 ms above the median is UdpStream::kDelayedAck on the critical path.)\n");

    table.head("bulk — one way, ack-paced");
    table.line("upload   (we send)",   tcp.up_mb_s,       udp.up_mb_s,       "MB/s", false);
    table.line("download (we recv)",   tcp.down_mb_s,     udp.down_mb_s,     "MB/s", false);
    table.line("CPU per GB, upload",   tcp.up_cpu_s_gb,   udp.up_cpu_s_gb,   "s/GB", true);
    table.line("CPU per GB, download", tcp.down_cpu_s_gb, udp.down_cpu_s_gb, "s/GB", true);
    std::printf("  (both directions are measured because real links are asymmetric. Throughput\n"
                "   converges when the path, not the stack, is the bottleneck — raise --bulk-mb\n"
                "   until it stops changing before reading the two wires against each other.\n"
                "   The upload figure is timed to the final ack, so it includes one closing round\n"
                "   trip: the larger the transfer, the smaller that share. On a very fast path\n"
                "   both wires carry one extra artifact — the ack stream is small messages, and\n"
                "   every frame currently costs its own write (see the note above bench_small),\n"
                "   so a narrow credit window paces the sender late. --credit-kb is the runway\n"
                "   that absorbs it, and on any link slow enough for its bandwidth-delay product\n"
                "   to fit inside the credit window it does not arise at all.)\n");

    table.head("small — many small frames, message-paced");
    table.line("messages", tcp.small_msgs_s, udp.small_msgs_s, "msg/s", false, "%10.0f");
    std::printf("  (as on loopback, read this next to rtt. The gap is not Nagle — it is one\n"
                "   syscall per frame on both wires (Connection::send flushes write-through),\n"
                "   which the datagram side partly escapes by packing and batching. See the\n"
                "   note above bench_small().)\n");

    std::printf("\nconfiguration: bulk %.0f MiB in %.0f KiB frames, %.0f KiB credit; "
                "rtt %d x %zu B; small %d x %zu B, %d in flight; %d dials\n",
                o.bulk_bytes / (1024.0 * 1024.0), o.frame_bytes / 1024.0,
                o.credit_bytes / 1024.0, o.rtt_turns, o.rtt_payload, o.small_count,
                o.small_bytes, o.small_credit, o.dials);
    std::printf("note: unlike the loopback suite this path has loss, reordering and a real MTU,\n"
                "so congestion control, the RTO and the selective-ack repair path are all in\n"
                "play — these are the numbers the UDP figures on loopback are a floor for.\n");
    return 0;
}

// ── Command line ────────────────────────────────────────────────────────────

void usage() {
    std::printf(
        "librats transport benchmark\n"
        "\n"
        "  bench_transport                     two nodes on loopback (default)\n"
        "  bench_transport --serve             stay up as the remote end of a real-path run\n"
        "  bench_transport --connect HOST[:PORT]  measure against a --serve on another host\n"
        "\n"
        "options\n"
        "  --port N          listen port for --serve, or target port (default 9977)\n"
        "  --bind ADDR       interface to bind (default: dual-stack wildcard)\n"
        "  --transport WIRE  tcp | udp | both   (default both)\n"
        "  --protocol NAME   must match on both ends (default bench-transport/1)\n"
        "  --bulk-mb N       bytes per bulk direction, MiB      (default 16)\n"
        "  --frame-kb N      bulk frame size, KiB               (default 16)\n"
        "  --credit-kb N     unacked bytes allowed in flight    (default 4096)\n"
        "  --rtt N           serial request/response turns      (default 200)\n"
        "  --rtt-bytes N     rtt payload size                   (default 64)\n"
        "  --small N         small messages                     (default 20000)\n"
        "  --small-bytes N   small message size                 (default 256)\n"
        "  --small-credit N  small messages in flight           (default 512)\n"
        "  --dials N         dial samples                       (default 8)\n"
        "  -h, --help        this text\n"
        "\n"
        "both ends must run the same --protocol; the responder must be reachable on\n"
        "the port over every wire that is measured.\n");
}

/// Split "host:port" / "[v6]:port" / "host". Leaves the port alone when absent,
/// so --port still applies.
void split_target(const std::string& text, Options& o) {
    if (!text.empty() && text.front() == '[') {
        const size_t close = text.find(']');
        if (close != std::string::npos) {
            o.host = text.substr(1, close - 1);
            if (close + 1 < text.size() && text[close + 1] == ':')
                o.port = static_cast<uint16_t>(std::strtoul(text.c_str() + close + 2, nullptr, 10));
            return;
        }
    }
    const size_t colon = text.rfind(':');
    // A bare IPv6 literal has several colons and no port.
    if (colon != std::string::npos && text.find(':') == colon) {
        o.host = text.substr(0, colon);
        o.port = static_cast<uint16_t>(std::strtoul(text.c_str() + colon + 1, nullptr, 10));
        return;
    }
    o.host = text;
}

/// Returns false if the arguments are unusable (message already printed).
bool parse_args(int argc, char** argv, Options& o) {
    const auto value = [&](int& i) -> const char* {
        if (i + 1 >= argc) {
            std::fprintf(stderr, "bench_transport: %s needs a value\n", argv[i]);
            return nullptr;
        }
        return argv[++i];
    };
    const auto number = [&](int& i, size_t& into, size_t scale) {
        const char* v = value(i);
        if (!v) return false;
        into = static_cast<size_t>(std::strtoull(v, nullptr, 10)) * scale;
        return true;
    };

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        size_t n = 0;
        if (arg == "-h" || arg == "--help") { o.help = true; return true; }
        else if (arg == "--serve") o.role = Options::Role::Serve;
        else if (arg == "--connect") {
            const char* v = value(i);
            if (!v) return false;
            o.role = Options::Role::Connect;
            split_target(v, o);
        }
        else if (arg == "--port")   { if (!number(i, n, 1)) return false; o.port = static_cast<uint16_t>(n); }
        else if (arg == "--bind")   { const char* v = value(i); if (!v) return false; o.bind = v; }
        else if (arg == "--protocol") { const char* v = value(i); if (!v) return false; o.protocol = v; }
        else if (arg == "--transport") {
            const char* v = value(i);
            if (!v) return false;
            const std::string wire_name = v;
            o.tcp = (wire_name == "tcp" || wire_name == "both");
            o.udp = (wire_name == "udp" || wire_name == "both");
            if (!o.tcp && !o.udp) {
                std::fprintf(stderr, "bench_transport: --transport takes tcp, udp or both\n");
                return false;
            }
        }
        else if (arg == "--bulk-mb")      { if (!number(i, o.bulk_bytes, 1024 * 1024)) return false; }
        else if (arg == "--frame-kb")     { if (!number(i, o.frame_bytes, 1024)) return false; }
        else if (arg == "--credit-kb")    { if (!number(i, o.credit_bytes, 1024)) return false; }
        else if (arg == "--rtt")          { if (!number(i, n, 1)) return false; o.rtt_turns = static_cast<int>(n); }
        else if (arg == "--rtt-bytes")    { if (!number(i, o.rtt_payload, 1)) return false; }
        else if (arg == "--small")        { if (!number(i, n, 1)) return false; o.small_count = static_cast<int>(n); }
        else if (arg == "--small-bytes")  { if (!number(i, o.small_bytes, 1)) return false; }
        else if (arg == "--small-credit") { if (!number(i, n, 1)) return false; o.small_credit = static_cast<int>(n); }
        else if (arg == "--dials")        { if (!number(i, n, 1)) return false; o.dials = static_cast<int>(n); }
        else {
            std::fprintf(stderr, "bench_transport: unknown option '%s' (try --help)\n", arg.c_str());
            return false;
        }
    }

    if (o.role == Options::Role::Connect && o.host.empty()) {
        std::fprintf(stderr, "bench_transport: --connect needs a host\n");
        return false;
    }
    if (o.frame_bytes == 0 || o.frame_bytes > o.bulk_bytes) {
        std::fprintf(stderr, "bench_transport: --frame-kb must be non-zero and no larger than --bulk-mb\n");
        return false;
    }
    return true;
}

} // namespace remote

} // namespace

// ── Main ────────────────────────────────────────────────────────────────────

/// The loopback suite: both ends in this process, the controlled A/B. Unchanged
/// by the remote mode below it — `bench_transport` with no arguments still runs
/// exactly this and nothing else.
int run_loopback_suite() {
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
        std::printf("  (this gap is NOT the datagram stack being fast, and it is NOT Nagle —\n"
                    "   setting TCP_NODELAY makes this row 3.2x worse, measured. Connection::send()\n"
                    "   flushes write-through, so every frame costs its own syscall on both wires;\n"
                    "   the datagram side only partly escapes that, by packing frames into one\n"
                    "   datagram and batching datagrams per send. See the note above bench_small().)\n");
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
                "cheapest. Every UDP figure above is a floor on cost, not a ceiling.\n"
                "for the ceiling, run the same experiments over a real path:\n"
                "  there: ./bench_transport --serve      here: ./bench_transport --connect HOST:PORT\n");
    return 0;
}

int main(int argc, char** argv) {
    Logger::getInstance().set_log_level(LogLevel::ERROR);
#if !defined(_WIN32)
    g_color = isatty(1) != 0;
#endif
    // --serve prints and then blocks for as long as the run takes; fully-buffered
    // stdout (which is what a redirect to a file gets) would hold all of it until
    // the process ends, including the port line the other side needs.
    std::setvbuf(stdout, nullptr, _IOLBF, 0);

    remote::Options options;
    if (!remote::parse_args(argc, argv, options)) return 1;
    if (options.help) { remote::usage(); return 0; }

    switch (options.role) {
        case remote::Options::Role::Serve:   return remote::serve(options);
        case remote::Options::Role::Connect: return remote::connect_and_measure(options);
        case remote::Options::Role::Loopback:
        default:                             return run_loopback_suite();
    }
}
