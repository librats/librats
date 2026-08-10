// bench_poller — what one readiness notification costs
//
// Every other I/O suite here measures what happens *after* the poller says a
// socket is ready. This one measures the saying: how many times the poller has to
// wake the reactor to deliver one application message, and what each of those
// wakeups costs as the registered set grows.
//
// The subject is `src/librats/core/io_poller.cpp` on whatever backend the platform picks,
// driven exactly the way `Reactor::run()` drives it — one blocking wait(), read
// the socket dry, then keep asking with a zero timeout until wait() has nothing
// more to say. Nothing is mocked: real loopback sockets, the real poller. A
// readiness notification is not something you can mock and still be measuring it.
//
// Three experiments, each of which exists because it can fail:
//
//   reports    How many readiness reports one burst of data costs. The floor is
//              1.00 and every backend can reach it, but a completion-port design
//              has to work for it: arming the next overlapped receive while the
//              data that triggered the last one is still unread makes that receive
//              complete on the spot, and the caller comes back to an empty socket.
//              That was the measured state of this code — exactly 2.00 reports per
//              message, half of them finding nothing — and it doubled wakeups and
//              reads across the whole receive path. It is a ratio, not a duration,
//              so it is reported on its own and it is the number to watch first.
//
//   recovery   The same datagram socket before and after an unreachable
//              destination. On Windows the ICMP report that comes back is handed
//              to the next receive as an error, the arm that follows fails with
//              it, and the poller hands the socket to its WSAPoll fallback so it
//              cannot be left holding nothing. That fallback is correct but a hop
//              slower (~1.3x per datagram when this was found), and nothing else
//              would ever move the socket back — modify() is the only other
//              promotion path and the reactor never calls it on the mux socket.
//              So these two rows must stay EQUAL. A gap means one transient ICMP
//              packet now pins the busiest socket in the process to the slow path
//              for the rest of its life.
//
//   scale      Per-event cost as the registered set grows, and what a listen
//              socket adds. A listen socket cannot carry overlapped I/O, so on
//              Windows it lives in a second mechanism that is polled on every
//              wait() — which every server node pays on every reactor iteration,
//              whether or not anything is connecting.

#include "framework/bench.h"

#include "librats/core/io_poller.h"
#include "librats/core/socket.h"
#include "librats/util/logger.h"

#include <cstdio>
#include <cstring>
#include <chrono>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
#endif

using namespace librats;

namespace {

//=============================================================================
// Scaffolding
//=============================================================================

struct Pair {
    socket_t rx = RATS_INVALID_SOCKET;   // the end registered in the poller
    socket_t tx = RATS_INVALID_SOCKET;   // the end we send from
};

sockaddr_in loopback(int port) {
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port   = htons(static_cast<uint16_t>(port));
    ::inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    return a;
}

Pair make_tcp_pair() {
    socket_t listener = create_tcp_server(0, 8, "127.0.0.1", AddressFamily::IPv4);
    const int port    = get_bound_port(listener);
    socket_t tx       = create_tcp_client("127.0.0.1", port, 2000);
    socket_t rx       = accept_client(listener);
    close_socket(listener);
    set_socket_nonblocking(rx);
    set_socket_nonblocking(tx);
    return {rx, tx};
}

/// A bound UDP socket built by hand rather than through create_udp_socket(),
/// which switches SIO_UDP_CONNRESET off. The `recovery` experiment needs exactly
/// the report that switch suppresses, and the two sockets have to be built the
/// same way for its two rows to be comparable.
socket_t make_udp(int* port_out) {
    socket_t s = ::socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in addr = loopback(0);
    ::bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    set_socket_nonblocking(s);
    if (port_out) *port_out = get_bound_port(s);
    return s;
}

/// A loopback port with nothing on it: bind one to learn a free number, hand it back.
int dead_port() {
    socket_t s = create_tcp_server(0, 1, "127.0.0.1", AddressFamily::IPv4);
    const int p = get_bound_port(s);
    close_socket(s);
    return p;
}

constexpr size_t kMessage = 64;   // one small application message

/// One message, driven the way the reactor drives the poller. Returns how many
/// readiness reports that message cost — the whole point of the first experiment.
int round_trip(IOPoller& poller, socket_t rx, socket_t tx, bool datagram, int rx_port) {
    char msg[kMessage];
    std::memset(msg, 'x', sizeof(msg));

    if (datagram) {
        const std::vector<uint8_t> payload(msg, msg + sizeof(msg));
        send_udp_data(tx, payload, "127.0.0.1", rx_port, AddressFamily::IPv4);
    } else {
        ::send(tx, msg, static_cast<int>(sizeof(msg)), 0);
    }

    int reports = 0;
    for (bool first = true;; first = false) {
        PollResult results[16];
        // Only the first wait of a round may block. The follow-ups ask "anything
        // else?" and must not sit out a timeout to answer no.
        const int n = poller.wait(results, 16, first ? 1000 : 0);
        if (n <= 0) break;
        for (int i = 0; i < n; ++i) {
            if (results[i].fd != rx || !(results[i].events & PollIn)) continue;
            ++reports;
            if (datagram) {
                std::vector<uint8_t> buf(2048);
                Address from;
                while (recv_udp_from(rx, buf.data(), buf.size(), from) >= 0) {}
            } else {
                char buf[512];
                while (::recv(rx, buf, sizeof(buf), 0) > 0) {}
            }
        }
    }
    return reports;
}

//=============================================================================
// Experiment 1 — readiness reports per message
//=============================================================================

struct Reports { double per_message; long long wasted; };

Reports count_reports(IOPoller& poller, socket_t rx, socket_t tx, bool datagram,
                      int rx_port, int rounds) {
    long long total = 0, wasted = 0;
    for (int i = 0; i < rounds; ++i) {
        const int got = round_trip(poller, rx, tx, datagram, rx_port);
        total  += got;
        wasted += got > 1 ? got - 1 : 0;   // one report is the message; the rest are not
    }
    return {double(total) / rounds, wasted};
}

void experiment_reports() {
    std::printf("\nreports — readiness notifications it takes to deliver one message\n");
    std::printf("  %-28s %14s %14s\n", "", "reports/msg", "wasted");

    {
        Pair p = make_tcp_pair();
        auto poller = IOPoller::create();
        poller->add(p.rx, PollIn);
        count_reports(*poller, p.rx, p.tx, false, 0, 50);            // warm up
        const Reports r = count_reports(*poller, p.rx, p.tx, false, 0, 2000);
        std::printf("  %-28s %14.2f %14lld\n", "stream (TCP)", r.per_message, r.wasted);
        poller->remove(p.rx);
        close_socket(p.rx);
        close_socket(p.tx);
    }
    {
        int port = 0;
        socket_t rx = make_udp(&port);
        socket_t tx = make_udp(nullptr);
        auto poller = IOPoller::create();
        poller->add(rx, PollIn);
        count_reports(*poller, rx, tx, true, port, 50);              // warm up
        const Reports r = count_reports(*poller, rx, tx, true, port, 2000);
        std::printf("  %-28s %14.2f %14lld\n", "datagram (UDP)", r.per_message, r.wasted);
        poller->remove(rx);
        close_socket(rx);
        close_socket(tx);
    }

    std::printf("  (1.00 is the floor and every backend can reach it. 2.00 means the poller is\n"
                "   arming its next receive before the caller has read the data that triggered\n"
                "   the last one, so that receive completes at once and the caller comes back to\n"
                "   an empty socket: every wakeup and every read on this path, doubled.)\n");
}

//=============================================================================
// Experiment 2 — does a socket come back from the fallback mechanism?
//=============================================================================

void experiment_recovery() {
    bench::Bench b("");
    b.config().min_time = 0.30;

    int      port   = 0;
    socket_t rx     = make_udp(&port);
    socket_t tx     = make_udp(nullptr);
    auto     poller = IOPoller::create();
    poller->add(rx, PollIn);

    b.group("recovery — one datagram round trip, before and after an ICMP error");
    b.items(1);
    b.run("steady state", [&] { round_trip(*poller, rx, tx, true, port); });

    // Provoke it: a destination nobody is listening on. The ICMP Port Unreachable
    // that comes back is delivered to the next receive as an error, the arm that
    // follows fails with it, and the poller falls back to polling this socket.
    const int dead = dead_port();
    const std::vector<uint8_t> probe(64, 0x11);
    for (int i = 0; i < 3; ++i)
        send_udp_data(rx, probe, "127.0.0.1", dead, AddressFamily::IPv4);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    for (int i = 0; i < 5; ++i) {
        PollResult results[8];
        poller->wait(results, 8, 20);
        std::vector<uint8_t> buf(2048);
        Address from;
        while (recv_udp_from(rx, buf.data(), buf.size(), from) >= 0) {}
    }

    b.run("after an ICMP error", [&] { round_trip(*poller, rx, tx, true, port); });

    poller->remove(rx);
    close_socket(rx);
    close_socket(tx);

    b.report();
    std::printf("  (these two rows must stay EQUAL. A gap means the socket was left on the\n"
                "   fallback mechanism the poller moves it to when it cannot arm a receive —\n"
                "   correct, but a hop slower, and nothing else would ever bring it back: one\n"
                "   transient ICMP packet would pin the mux socket there for good.)\n");
}

//=============================================================================
// Experiment 3 — cost per event as the registered set grows
//=============================================================================

void experiment_scale() {
    bench::Bench b("");
    b.config().min_time = 0.30;

    struct Case { const char* name; int idle; bool listener; };
    static const Case cases[] = {
        {"1 socket",              0, false},
        {"1 socket + a listener", 0, true },
        {"64 sockets",           63, false},
        {"256 sockets",         255, false},
    };

    b.group("scale — one message round trip with N sockets registered");
    b.items(1);

    for (const Case& c : cases) {
        auto              poller   = IOPoller::create();
        Pair              active   = make_tcp_pair();
        socket_t          listener = RATS_INVALID_SOCKET;
        std::vector<Pair> idle;

        poller->add(active.rx, PollIn);
        for (int i = 0; i < c.idle; ++i) {
            idle.push_back(make_tcp_pair());
            poller->add(idle.back().rx, PollIn);
        }
        if (c.listener) {
            listener = create_tcp_server(0, 8, "127.0.0.1", AddressFamily::IPv4);
            set_socket_nonblocking(listener);
            poller->add(listener, PollIn);
        }

        b.run(c.name, [&] { round_trip(*poller, active.rx, active.tx, false, 0); });

        poller.reset();
        close_socket(active.rx);
        close_socket(active.tx);
        for (Pair& p : idle) { close_socket(p.rx); close_socket(p.tx); }
        if (is_valid_socket(listener)) close_socket(listener);
    }

    b.report();
    std::printf("  (the idle sockets never carry a byte, so whatever they add is the poller's own\n"
                "   bookkeeping. The listener row is the interesting one on Windows: a listen\n"
                "   socket cannot carry overlapped I/O, so it lives in a second mechanism that is\n"
                "   polled on every wait() — a cost every server node pays on every iteration of\n"
                "   its reactor loop, whether or not anything is connecting.)\n");
}

} // namespace

int main() {
    // Socket creation logs a line per socket at INFO, and the scale experiment
    // opens hundreds of them inside the timed region.
    Logger::getInstance().set_log_level(LogLevel::ERROR);
    init_socket_library();

    auto probe = IOPoller::create();
    std::printf("librats poller suite — what one readiness notification costs\n");
    std::printf("backend: %s, real loopback sockets, driven as Reactor::run() drives it\n",
                probe->name());
    probe.reset();

    experiment_reports();
    experiment_recovery();
    experiment_scale();

    std::printf("\nnote: loopback delivery is immediate, so these figures isolate the poller's own\n"
                "cost and nothing else. A real network adds latency to the wait, not to the work\n"
                "measured here — which is exactly why a wasted wakeup shows up so clearly.\n");

    cleanup_socket_library();
    return 0;
}
