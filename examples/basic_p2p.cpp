/**
 * @file basic_p2p.cpp
 * @brief Basic peer-to-peer messaging example
 *
 * Demonstrates core librats functionality:
 *   - Starting a RatsClient and listening for connections
 *   - Connecting to another peer
 *   - Sending and receiving string, JSON, and binary messages
 *   - Using the message exchange API (on/send)
 *
 * Usage:
 *   basic_p2p <listen_port> [<remote_ip> <remote_port>]
 *
 * Examples:
 *   # Start a node listening on port 8080
 *   basic_p2p 8080
 *
 *   # Start a node on port 8081 and connect to the first one
 *   basic_p2p 8081 127.0.0.1 8080
 */

#include "librats.h"

#include <iostream>
#include <string>
#include <chrono>
#include <atomic>
#include <thread>
#include <csignal>
#include <cstdlib>

using namespace librats;

static std::atomic<bool> g_running{true};

static void signal_handler(int) {
    g_running = false;
}

static void print_usage(const char* program) {
    std::cerr << "Usage: " << program << " <listen_port> [<remote_ip> <remote_port>]\n"
              << "\n"
              << "  listen_port   Port to listen on for incoming connections\n"
              << "  remote_ip     (optional) IP address of a peer to connect to\n"
              << "  remote_port   (optional) Port of the remote peer\n"
              << "\n"
              << "Examples:\n"
              << "  " << program << " 8080\n"
              << "  " << program << " 8081 127.0.0.1 8080\n";
}

int main(int argc, char* argv[]) {
    if (argc != 2 && argc != 4) {
        print_usage(argv[0]);
        return 1;
    }

    const int listen_port = std::atoi(argv[1]);
    if (listen_port <= 0 || listen_port > 65535) {
        std::cerr << "Error: invalid listen port\n";
        return 1;
    }

    std::string remote_ip;
    int remote_port = 0;
    if (argc == 4) {
        remote_ip   = argv[2];
        remote_port = std::atoi(argv[3]);
    }

    // Register signal handler for Ctrl-C
    std::signal(SIGINT, signal_handler);
#ifndef _WIN32
    std::signal(SIGTERM, signal_handler);
#endif

    // ── Create and configure RatsClient ──────────────────────────────────────
    RatsClient client(listen_port);
    client.set_log_level(LogLevel::INFO);

    // ── Register callbacks ───────────────────────────────────────────────────

    // Connection callback
    client.set_connection_callback([](socket_t /*socket*/, const std::string& peer_id) {
        std::cout << "[+] Peer connected: " << peer_id.substr(0, 16) << "...\n";
    });

    // Disconnect callback
    client.set_disconnect_callback([](socket_t /*socket*/, const std::string& peer_id) {
        std::cout << "[-] Peer disconnected: " << peer_id.substr(0, 16) << "...\n";
    });

    // String message callback
    client.set_string_data_callback([](socket_t /*socket*/, const std::string& peer_id,
                                       const std::string& message) {
        std::cout << "[STRING] " << peer_id.substr(0, 8) << ": " << message << "\n";
    });

    // JSON message callback
    client.set_json_data_callback([](socket_t /*socket*/, const std::string& peer_id,
                                     const nlohmann::json& data) {
        std::cout << "[JSON] " << peer_id.substr(0, 8) << ": " << data.dump() << "\n";
    });

    // Message exchange API — typed message handlers
    client.on("ping", [&client](const std::string& peer_id, const nlohmann::json& data) {
        std::cout << "[PING] from " << peer_id.substr(0, 8)
                  << " seq=" << data.value("seq", 0) << "\n";

        // Reply with a pong
        nlohmann::json pong;
        pong["seq"]       = data.value("seq", 0);
        pong["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::system_clock::now().time_since_epoch()).count();
        client.send(peer_id, "pong", pong);
    });

    client.on("pong", [](const std::string& peer_id, const nlohmann::json& data) {
        std::cout << "[PONG] from " << peer_id.substr(0, 8)
                  << " seq=" << data.value("seq", 0) << "\n";
    });

    // ── Start the client ─────────────────────────────────────────────────────
    if (!client.start()) {
        std::cerr << "Error: failed to start RatsClient on port " << listen_port << "\n";
        return 1;
    }

    std::cout << "=== librats basic P2P example ===\n"
              << "Listening on port " << listen_port << "\n"
              << "Our peer ID: " << client.get_our_peer_id().substr(0, 16) << "...\n";

    // ── Connect to remote peer if specified ──────────────────────────────────
    if (!remote_ip.empty()) {
        std::cout << "Connecting to " << remote_ip << ":" << remote_port << "...\n";
        if (!client.connect_to_peer(remote_ip, remote_port)) {
            std::cerr << "Warning: connect_to_peer() failed\n";
        }
    }

    // ── Main loop: periodic ping + status ────────────────────────────────────
    int ping_seq = 0;
    auto last_ping = std::chrono::steady_clock::now();
    constexpr auto PING_INTERVAL = std::chrono::seconds(5);

    std::cout << "\nPress Ctrl+C to quit.\n\n";

    while (g_running) {
        auto now = std::chrono::steady_clock::now();

        // Send a ping to all peers every PING_INTERVAL
        if (now - last_ping >= PING_INTERVAL && client.get_peer_count() > 0) {
            nlohmann::json ping;
            ping["seq"]       = ++ping_seq;
            ping["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
                                    std::chrono::system_clock::now().time_since_epoch()).count();
            client.send("ping", ping);
            last_ping = now;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    // ── Cleanup ──────────────────────────────────────────────────────────────
    std::cout << "\nShutting down...\n";
    client.stop();

    return 0;
}
