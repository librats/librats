/**
 * @file peer_discovery.cpp
 * @brief Peer discovery example using DHT and mDNS
 *
 * Demonstrates librats peer discovery mechanisms:
 *   - DHT (Distributed Hash Table) discovery over the BitTorrent Mainline DHT
 *   - mDNS local network discovery
 *   - Automatic peer discovery with custom protocol configuration
 *   - Periodic statistics reporting
 *
 * Usage:
 *   peer_discovery <listen_port> [<protocol_name>]
 *
 * Examples:
 *   # Discover peers using the default "rats" protocol
 *   peer_discovery 8080
 *
 *   # Discover peers using a custom protocol name (private overlay)
 *   peer_discovery 8080 my_app
 */

#include "librats.h"

#include <iostream>
#include <string>
#include <chrono>
#include <atomic>
#include <thread>
#include <csignal>
#include <cstdlib>
#include <iomanip>

using namespace librats;

static std::atomic<bool> g_running{true};

static void signal_handler(int) {
    g_running = false;
}

static void print_usage(const char* program) {
    std::cerr << "Usage: " << program << " <listen_port> [<protocol_name>]\n"
              << "\n"
              << "  listen_port     Port to listen on\n"
              << "  protocol_name   (optional) Custom protocol name for private discovery\n"
              << "                  Default: \"rats\"\n"
              << "\n"
              << "Examples:\n"
              << "  " << program << " 8080\n"
              << "  " << program << " 8080 my_app\n";
}

static std::string timestamp_str() {
    auto now   = std::chrono::system_clock::now();
    auto time  = std::chrono::system_clock::to_time_t(now);
    auto ms    = std::chrono::duration_cast<std::chrono::milliseconds>(
                     now.time_since_epoch()).count() % 1000;
    struct tm tm_buf;
#ifdef _WIN32
    localtime_s(&tm_buf, &time);
#else
    localtime_r(&time, &tm_buf);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%H:%M:%S", &tm_buf);
    std::ostringstream oss;
    oss << buf << "." << std::setfill('0') << std::setw(3) << ms;
    return oss.str();
}

int main(int argc, char* argv[]) {
    if (argc < 2 || argc > 3) {
        print_usage(argv[0]);
        return 1;
    }

    const int listen_port = std::atoi(argv[1]);
    if (listen_port <= 0 || listen_port > 65535) {
        std::cerr << "Error: invalid listen port\n";
        return 1;
    }

    std::string protocol_name = "rats";
    if (argc == 3) {
        protocol_name = argv[2];
    }

    // Register signal handler for Ctrl-C
    std::signal(SIGINT, signal_handler);
#ifndef _WIN32
    std::signal(SIGTERM, signal_handler);
#endif

    // ── Create and configure RatsClient ──────────────────────────────────────
    RatsClient client(listen_port);
    client.set_log_level(LogLevel::INFO);

    // Set custom protocol name for private overlay
    client.set_protocol_name(protocol_name);

    // ── Register callbacks ───────────────────────────────────────────────────
    client.set_connection_callback([](socket_t /*socket*/, const std::string& peer_id) {
        std::cout << "[" << timestamp_str() << "] "
                  << "[+] Peer connected: " << peer_id.substr(0, 16) << "...\n";
    });

    client.set_disconnect_callback([](socket_t /*socket*/, const std::string& peer_id) {
        std::cout << "[" << timestamp_str() << "] "
                  << "[-] Peer disconnected: " << peer_id.substr(0, 16) << "...\n";
    });

    // ── Start the client ─────────────────────────────────────────────────────
    if (!client.start()) {
        std::cerr << "Error: failed to start RatsClient on port " << listen_port << "\n";
        return 1;
    }

    std::cout << "=== librats Peer Discovery Example ===\n"
              << "Listening on port:  " << listen_port << "\n"
              << "Protocol:           " << client.get_protocol_name()
              << " v" << client.get_protocol_version() << "\n"
              << "Discovery hash:     " << client.get_discovery_hash() << "\n"
              << "Our peer ID:        " << client.get_our_peer_id().substr(0, 16) << "...\n"
              << "\n";

    // ── Start DHT discovery ──────────────────────────────────────────────────
    int dht_port = listen_port + 1;  // use listen_port+1 for DHT by default
    if (client.start_dht_discovery(dht_port)) {
        std::cout << "[DHT] Started on UDP port " << dht_port << "\n";
    } else {
        std::cerr << "[DHT] Failed to start on port " << dht_port << "\n";
    }

    // ── Start mDNS discovery ─────────────────────────────────────────────────
    if (client.start_mdns_discovery(protocol_name)) {
        std::cout << "[mDNS] Started with service name \"" << protocol_name << "\"\n";
    } else {
        std::cerr << "[mDNS] Failed to start\n";
    }

    // Set mDNS callback
    client.set_mdns_callback([](const std::string& host, int port, const std::string& service_name) {
        std::cout << "[" << timestamp_str() << "] "
                  << "[mDNS] Discovered service: " << service_name
                  << " at " << host << ":" << port << "\n";
    });

    // ── Start automatic peer discovery ───────────────────────────────────────
    client.start_automatic_peer_discovery();
    std::cout << "[AUTO] Automatic peer discovery started\n";

    // ── Announce our presence in DHT ─────────────────────────────────────────
    std::string discovery_hash = client.get_discovery_hash();
    client.announce_for_hash(discovery_hash, static_cast<uint16_t>(listen_port),
        [](const std::vector<std::string>& peers) {
            if (!peers.empty()) {
                std::cout << "[" << timestamp_str() << "] "
                          << "[DHT] Found " << peers.size()
                          << " peers during announce traversal\n";
                for (const auto& peer : peers) {
                    std::cout << "  -> " << peer << "\n";
                }
            }
        });

    // ── Periodic stats loop ──────────────────────────────────────────────────
    constexpr auto STATS_INTERVAL = std::chrono::seconds(10);
    auto last_stats = std::chrono::steady_clock::now();

    std::cout << "\nPress Ctrl+C to quit.\n"
              << "Status printed every " << STATS_INTERVAL.count() << " seconds.\n\n";

    while (g_running) {
        auto now = std::chrono::steady_clock::now();

        if (now - last_stats >= STATS_INTERVAL) {
            last_stats = now;

            std::cout << "[" << timestamp_str() << "] === Status ===\n";

            // Connected peers
            auto peers = client.get_validated_peers();
            std::cout << "  Connected peers:    " << peers.size() << "\n";
            for (const auto& p : peers) {
                std::cout << "    " << p.peer_id.substr(0, 16) << "...  "
                          << p.ip << ":" << p.port
                          << (p.is_outgoing ? " (outgoing)" : " (incoming)")
                          << "\n";
            }

            // DHT info
            if (client.is_dht_running()) {
                std::cout << "  DHT routing table:  "
                          << client.get_dht_routing_table_size() << " nodes\n";
            }

            // mDNS info
            if (client.is_mdns_running()) {
                auto services = client.get_mdns_services();
                std::cout << "  mDNS services:      " << services.size() << "\n";
            }

            // Reconnection queue
            auto reconnect_queue = client.get_reconnect_queue();
            if (!reconnect_queue.empty()) {
                std::cout << "  Reconnect queue:    " << reconnect_queue.size() << "\n";
            }

            std::cout << "  ================\n";
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    // ── Cleanup ──────────────────────────────────────────────────────────────
    std::cout << "\nShutting down...\n";
    client.stop_automatic_peer_discovery();
    client.stop_mdns_discovery();
    client.stop_dht_discovery();
    client.stop();

    return 0;
}
