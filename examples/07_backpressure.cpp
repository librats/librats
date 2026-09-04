// 07_backpressure — streaming as fast as the link allows, without being dropped.
//
// Every example before this one sends a line at a time, so the send queue is
// never under pressure and the question never comes up. A program that streams —
// a log shipper, a media feed, a bulk sync — produces bytes far faster than a
// peer can take them, and librats does NOT block to slow it down: send() always
// queues the message and returns immediately. What it returns is the answer to
// "is there still room?", and an application that ignores it has the peer closed
// under it with CloseReason::SlowConsumer once the queue passes its high-water
// mark (NodeConfig::send_queue_limit, 8 MiB by default).
//
// The contract, in three parts:
//   • send() returning false means STOP — the message was queued like any other,
//     but the queue is past its low-water mark. It is not an error and nothing
//     was lost.
//   • on_peer_writable is the other half: the queue has drained back under the
//     mark and this peer may be written to again.
//   • peer_writable() asks the same question without sending anything.
//
//   07_backpressure <listen_port> [connect_host connect_port] [--reckless]
//
//   ./07_backpressure 9000                       # terminal 1: receiver
//   ./07_backpressure 9001 127.0.0.1 9000        # terminal 2: sender, paced
//   ./07_backpressure 9001 127.0.0.1 9000 --reckless   # sender that ignores it
//
// The paced sender streams indefinitely. The --reckless one keeps calling send()
// regardless of the answer and is disconnected within seconds — by its OWN side,
// which is where the queue lives. Run both and compare. Ctrl-C to quit.

#include <librats/node/node.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace librats;
using namespace std::chrono_literals;

namespace {

/// One message per call to send(). Large enough that the queue fills quickly on
/// loopback, small enough to stay well under the block limit.
constexpr size_t kChunkSize = 64 * 1024;

std::string rate(uint64_t bytes_per_second) {
    const double mb = static_cast<double>(bytes_per_second) / (1024.0 * 1024.0);
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%.1f MiB/s", mb);
    return buf;
}

} // namespace

int main(int argc, char** argv) {
    std::vector<std::string> args;
    bool reckless = false;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--reckless") reckless = true;
        else                   args.push_back(a);
    }
    if (args.empty()) {
        std::cerr << "usage: " << argv[0]
                  << " <listen_port> [connect_host connect_port] [--reckless]\n";
        return 1;
    }
    const bool sending = args.size() >= 3;

    NodeConfig config;
    config.listen_port  = static_cast<uint16_t>(std::stoi(args[0]));
    config.bind_address = "::";  // dual-stack (IPv6 + IPv4-mapped)
    // How much a peer may have queued before it is dropped as a slow consumer.
    // Lowered from the 8 MiB default purely so --reckless demonstrates itself in
    // a second or two; the pacing below is what a real application relies on, and
    // it is correct at any limit.
    config.send_queue_limit = 1024 * 1024;

    Node node(config);

    // Shared between the reactor threads (which run every callback below) and the
    // main thread (which does the sending).
    std::mutex              mutex;
    std::condition_variable cv;
    PeerId                  target;
    bool                    connected = false;
    bool                    writable  = false;
    std::atomic<uint64_t>   received{0};

    node.on_peer_connected([&](const Peer& peer) {
        {
            std::lock_guard<std::mutex> lock(mutex);
            target    = peer.id();
            connected = true;
            writable  = true;
        }
        cv.notify_all();
        std::cout << "[+] connected: " << peer.id().short_hex() << "\n";
    });
    node.on_peer_disconnected([&](const PeerId& id, CloseReason reason) {
        {
            std::lock_guard<std::mutex> lock(mutex);
            connected = false;
        }
        cv.notify_all();
        std::cout << "[-] disconnected: " << id.short_hex()
                  << " (" << to_string(reason) << ")\n";
    });
    // "This peer can be written to again." Runs on a reactor thread, so it does
    // the least possible work — flag the sender and get out of the way.
    node.on_peer_writable([&](const Peer&) {
        {
            std::lock_guard<std::mutex> lock(mutex);
            writable = true;
        }
        cv.notify_all();
    });
    // Receiving side: also a reactor thread. Counting is all it does; the printing
    // happens on the main thread below.
    node.on("bulk", [&](const Peer&, ByteView data) {
        received.fetch_add(data.size(), std::memory_order_relaxed);
    });

    if (!node.start()) {
        std::cerr << "failed to start node (port in use?)\n";
        return 1;
    }
    std::cout << "node " << node.local_id().short_hex()
              << " listening on port " << node.listen_port() << "\n";

    if (!sending) {
        std::cout << "receiver: waiting for a sender (Ctrl-C to quit)\n";
        uint64_t previous = 0;
        for (;;) {
            std::this_thread::sleep_for(1s);
            const uint64_t total = received.load(std::memory_order_relaxed);
            std::cout << "received " << (total / (1024 * 1024)) << " MiB"
                      << "   " << rate(total - previous) << "\n";
            previous = total;
        }
    }

    node.connect(args[1], static_cast<uint16_t>(std::stoi(args[2])));

    // Wait for the handshake; a peer only exists once it has completed.
    PeerId peer;
    {
        std::unique_lock<std::mutex> lock(mutex);
        cv.wait(lock, [&] { return connected; });
        peer = target;
    }

    std::cout << "sender: streaming " << (kChunkSize / 1024) << " KiB chunks"
              << (reckless ? "  [--reckless: ignoring backpressure]" : "  [paced]")
              << "\n";

    const std::vector<uint8_t> chunk(kChunkSize, 0xAB);
    uint64_t sent = 0, previous = 0, stalls = 0;
    auto     next_report = std::chrono::steady_clock::now() + 1s;

    for (;;) {
        {
            std::lock_guard<std::mutex> lock(mutex);
            if (!connected) break;
        }

        // The chunk is queued whichever way this answers. False says the queue is
        // past its mark: keep going and the peer is dropped.
        const bool room = node.send(peer, "bulk", ByteView(chunk));
        sent += chunk.size();

        if (!room && !reckless) {
            ++stalls;
            std::unique_lock<std::mutex> lock(mutex);
            // on_peer_writable is the signal being waited for here. The timeout is
            // not a substitute for it but a guard for the one case that raises no
            // event: a queue that filled only with bytes still in transit to the
            // reactor crossed nothing on the connection, so nothing reports them
            // draining. Re-testing after 50 ms costs nothing and cannot stall.
            //
            // What must NOT happen is looping straight back into send(): that
            // starves the very reactor thread whose job it is to drain the queue
            // and raise the event this sender is waiting for.
            cv.wait_for(lock, 50ms, [&] { return writable || !connected; });
            writable = false;
        }

        const auto now = std::chrono::steady_clock::now();
        if (now >= next_report) {
            std::cout << "sent " << (sent / (1024 * 1024)) << " MiB"
                      << "   " << rate(sent - previous)
                      << "   stalls/s: " << stalls << "\n";
            previous    = sent;
            stalls      = 0;
            next_report = now + 1s;
        }
    }

    std::cout << "sender stopped after " << (sent / (1024 * 1024)) << " MiB"
              << (reckless ? " — this is what ignoring send()'s answer costs\n" : "\n");

    node.stop();
    return 0;
}
