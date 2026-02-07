/**
 * @file bt_metadata_bench.cpp
 * @brief Benchmark: fetch torrent metadata from a specific peer
 *
 * Connects to a single peer, downloads the torrent metadata via BEP 9
 * (ut_metadata extension), and prints how long it took.
 *
 * Usage:
 *   bt_metadata_bench <peer_ip> <peer_port> <info_hash_hex>
 *
 * Example:
 *   bt_metadata_bench 192.168.1.10 6881 aabbccddee11223344556677889900aabbccddee
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

// Global flag for graceful shutdown
static std::atomic<bool> g_done{false};

static void signal_handler(int) {
    g_done = true;
}

static void print_usage(const char* program) {
    std::cerr << "Usage: " << program << " <peer_ip> <peer_port> <info_hash_hex>\n"
              << "\n"
              << "  peer_ip        IP address of the peer that has the torrent\n"
              << "  peer_port      Port of the peer\n"
              << "  info_hash_hex  40-character hex info hash of the torrent\n"
              << "\n"
              << "Example:\n"
              << "  " << program << " 192.168.1.10 6881 aabbccddee11223344556677889900aabbccddee\n";
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        print_usage(argv[0]);
        return 1;
    }

    const std::string peer_ip   = argv[1];
    const uint16_t    peer_port = static_cast<uint16_t>(std::atoi(argv[2]));
    const std::string hash_hex  = argv[3];

    if (hash_hex.size() != 40) {
        std::cerr << "Error: info_hash_hex must be exactly 40 hex characters.\n";
        return 1;
    }

    // Register signal handler for Ctrl-C
    std::signal(SIGINT,  signal_handler);
#ifndef _WIN32
    std::signal(SIGTERM, signal_handler);
#endif

    // ── Create RatsClient ────────────────────────────────────────────────────
    // We need DHT + BitTorrent enabled. The listen port is arbitrary since we
    // only initiate outgoing connections in this benchmark.
    constexpr int LISTEN_PORT = 0;  // random port
    RatsClient client(LISTEN_PORT);
    client.set_console_logging_enabled(true);
    client.set_log_level(LogLevel::DEBUG);

    if (!client.start()) {
        std::cerr << "Error: failed to start RatsClient\n";
        return 1;
    }

    // Enable BitTorrent subsystem
    if (!client.enable_bittorrent()) {
        std::cerr << "Error: failed to enable BitTorrent\n";
        client.stop();
        return 1;
    }

    // ── Start the benchmark ──────────────────────────────────────────────────
    std::cout << "Fetching metadata for " << hash_hex.substr(0, 8) << "... "
              << "from " << peer_ip << ":" << peer_port << "\n";

    auto start_time = std::chrono::steady_clock::now();
    std::atomic<bool> metadata_received{false};
    std::atomic<bool> metadata_failed{false};

    client.get_torrent_metadata_from_peer(
        hash_hex,
        peer_ip,
        peer_port,
        [&](const TorrentInfo& info, bool success, const std::string& error) {
            auto end_time = std::chrono::steady_clock::now();
            auto elapsed  = std::chrono::duration_cast<std::chrono::milliseconds>(
                                end_time - start_time).count();

            if (success) {
                std::cout << "\n";
                std::cout << "=== Metadata received ===\n";
                std::cout << "  Time:        " << elapsed << " ms\n";
                std::cout << "  Name:        " << info.name() << "\n";
                std::cout << "  Info hash:   " << info.info_hash_hex() << "\n";
                std::cout << "  Total size:  " << info.total_size() << " bytes";
                if (info.total_size() > 1024 * 1024) {
                    std::cout << " (" << (info.total_size() / (1024.0 * 1024.0)) << " MiB)";
                }
                std::cout << "\n";
                std::cout << "  Pieces:      " << info.num_pieces()
                          << " x " << info.piece_length() << " bytes\n";
                std::cout << "  Files:       " << info.num_files() << "\n";

                // List files (up to 20)
                const auto& files = info.files().files();
                size_t show = std::min(files.size(), static_cast<size_t>(20));
                for (size_t i = 0; i < show; ++i) {
                    std::cout << "    [" << i << "] " << files[i].path
                              << " (" << files[i].size << " bytes)\n";
                }
                if (files.size() > 20) {
                    std::cout << "    ... and " << (files.size() - 20) << " more files\n";
                }

                if (!info.comment().empty()) {
                    std::cout << "  Comment:     " << info.comment() << "\n";
                }

                auto trackers = info.all_trackers();
                if (!trackers.empty()) {
                    std::cout << "  Trackers:    " << trackers.size() << "\n";
                    for (size_t i = 0; i < std::min(trackers.size(), static_cast<size_t>(5)); ++i) {
                        std::cout << "    " << trackers[i] << "\n";
                    }
                }

                std::cout << "=========================\n";
                metadata_received = true;
            } else {
                std::cerr << "\nMetadata fetch failed after " << elapsed << " ms: "
                          << error << "\n";
                metadata_failed = true;
            }
        }
    );

    // ── Wait for result or Ctrl-C ────────────────────────────────────────────
    constexpr int TIMEOUT_SECONDS = 120;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(TIMEOUT_SECONDS);

    while (!metadata_received && !metadata_failed && !g_done) {
        if (std::chrono::steady_clock::now() > deadline) {
            std::cerr << "Timeout: metadata not received within "
                      << TIMEOUT_SECONDS << " seconds.\n";
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // ── Cleanup ──────────────────────────────────────────────────────────────
    client.disable_bittorrent();
    client.stop_dht_discovery();
    client.stop();

    return metadata_received ? 0 : 1;
}
