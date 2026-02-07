/**
 * @file bt_download.cpp
 * @brief Download a torrent by info hash from a specific peer into a directory
 *
 * Connects to a peer, fetches metadata, then downloads the full torrent
 * content to the specified directory while printing live progress.
 *
 * Usage:
 *   bt_download <peer_ip> <peer_port> <info_hash_hex> <download_dir>
 *
 * Example:
 *   bt_download 192.168.1.10 6881 aabbccddee11223344556677889900aabbccddee ./downloads
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

// Global flag for graceful shutdown
static std::atomic<bool> g_done{false};

static void signal_handler(int) {
    g_done = true;
}

static void print_usage(const char* program) {
    std::cerr << "Usage: " << program << " <peer_ip> <peer_port> <info_hash_hex> <download_dir>\n"
              << "\n"
              << "  peer_ip        IP address of the peer that has the torrent\n"
              << "  peer_port      Port of the peer\n"
              << "  info_hash_hex  40-character hex info hash of the torrent\n"
              << "  download_dir   Directory where files will be saved\n"
              << "\n"
              << "Example:\n"
              << "  " << program << " 192.168.1.10 6881 aabbccddee11223344556677889900aabbccddee ./downloads\n";
}

static std::string format_bytes(uint64_t bytes) {
    const char* units[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    double value = static_cast<double>(bytes);
    int unit = 0;
    while (value >= 1024.0 && unit < 4) {
        value /= 1024.0;
        ++unit;
    }
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2) << value << " " << units[unit];
    return oss.str();
}

static std::string format_speed(uint64_t bytes_per_sec) {
    return format_bytes(bytes_per_sec) + "/s";
}

static std::string format_eta(std::chrono::seconds eta) {
    if (eta.count() <= 0) return "--:--";
    int h = static_cast<int>(eta.count() / 3600);
    int m = static_cast<int>((eta.count() % 3600) / 60);
    int s = static_cast<int>(eta.count() % 60);
    std::ostringstream oss;
    if (h > 0) oss << h << "h ";
    oss << std::setfill('0') << std::setw(2) << m << ":"
        << std::setfill('0') << std::setw(2) << s;
    return oss.str();
}

int main(int argc, char* argv[]) {
    if (argc != 5) {
        print_usage(argv[0]);
        return 1;
    }

    const std::string peer_ip      = argv[1];
    const uint16_t    peer_port    = static_cast<uint16_t>(std::atoi(argv[2]));
    const std::string hash_hex     = argv[3];
    const std::string download_dir = argv[4];

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
    constexpr int LISTEN_PORT = 0;  // random port
    RatsClient client(LISTEN_PORT);
    client.set_console_logging_enabled(true);
    client.set_log_level(LogLevel::INFO);

    if (!client.start()) {
        std::cerr << "Error: failed to start RatsClient\n";
        return 1;
    }

    // Start DHT
    client.start_dht_discovery();

    // Enable BitTorrent subsystem
    if (!client.enable_bittorrent()) {
        std::cerr << "Error: failed to enable BitTorrent\n";
        client.stop();
        return 1;
    }

    // ── Phase 1: Fetch metadata from peer ────────────────────────────────────
    std::cout << "Phase 1: Fetching metadata for " << hash_hex.substr(0, 8) << "... "
              << "from " << peer_ip << ":" << peer_port << "\n";

    auto phase1_start = std::chrono::steady_clock::now();
    std::atomic<bool> metadata_ok{false};
    std::atomic<bool> metadata_fail{false};
    TorrentInfo torrent_info;

    client.get_torrent_metadata_from_peer(
        hash_hex,
        peer_ip,
        peer_port,
        [&](const TorrentInfo& info, bool success, const std::string& error) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - phase1_start).count();

            if (success) {
                torrent_info = info;
                std::cout << "Metadata received in " << elapsed << " ms\n";
                std::cout << "  Name:   " << info.name() << "\n";
                std::cout << "  Size:   " << format_bytes(info.total_size()) << "\n";
                std::cout << "  Files:  " << info.num_files() << "\n";
                std::cout << "  Pieces: " << info.num_pieces()
                          << " x " << format_bytes(info.piece_length()) << "\n";
                metadata_ok = true;
            } else {
                std::cerr << "Metadata fetch failed after " << elapsed << " ms: "
                          << error << "\n";
                metadata_fail = true;
            }
        }
    );

    // Wait for metadata
    constexpr int META_TIMEOUT = 120;
    auto meta_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(META_TIMEOUT);
    while (!metadata_ok && !metadata_fail && !g_done) {
        if (std::chrono::steady_clock::now() > meta_deadline) {
            std::cerr << "Timeout: metadata not received within " << META_TIMEOUT << "s\n";
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    if (!metadata_ok) {
        client.disable_bittorrent();
        client.stop_dht_discovery();
        client.stop();
        return 1;
    }

    // ── Phase 2: Download torrent ────────────────────────────────────────────
    std::cout << "\nPhase 2: Downloading to " << download_dir << "\n";

    auto torrent = client.add_torrent(torrent_info, download_dir);
    if (!torrent) {
        std::cerr << "Error: failed to add torrent for download\n";
        client.disable_bittorrent();
        client.stop_dht_discovery();
        client.stop();
        return 1;
    }

    // Add the known peer
    torrent->add_peer(peer_ip, peer_port);

    auto download_start = std::chrono::steady_clock::now();

    // ── Progress loop ────────────────────────────────────────────────────────
    while (!g_done) {
        auto st = torrent->stats();

        // Print progress bar
        int bar_width = 40;
        int filled = static_cast<int>(st.progress * bar_width);
        std::cout << "\r[";
        for (int i = 0; i < bar_width; ++i) {
            if (i < filled)      std::cout << '#';
            else if (i == filled) std::cout << '>';
            else                  std::cout << ' ';
        }
        std::cout << "] "
                  << std::fixed << std::setprecision(1) << (st.progress * 100.0) << "% "
                  << format_bytes(st.bytes_done) << "/" << format_bytes(st.total_size) << " "
                  << "DL:" << format_speed(st.download_rate) << " "
                  << "UL:" << format_speed(st.upload_rate) << " "
                  << "Peers:" << st.peers_connected << " "
                  << "ETA:" << format_eta(st.eta) << "   "
                  << std::flush;

        // Check if complete
        if (torrent->is_complete()) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - download_start).count();

            std::cout << "\n\n";
            std::cout << "=== Download complete ===\n";
            std::cout << "  Name:       " << torrent->name() << "\n";
            std::cout << "  Size:       " << format_bytes(st.total_size) << "\n";
            std::cout << "  Time:       " << elapsed << " ms";
            if (elapsed > 1000) {
                std::cout << " (" << std::fixed << std::setprecision(1)
                          << (elapsed / 1000.0) << " s)";
            }
            std::cout << "\n";
            if (elapsed > 0) {
                double avg_speed = static_cast<double>(st.total_size) / (elapsed / 1000.0);
                std::cout << "  Avg speed:  " << format_speed(static_cast<uint64_t>(avg_speed)) << "\n";
            }
            std::cout << "  Downloaded: " << format_bytes(st.total_downloaded) << "\n";
            std::cout << "  Uploaded:   " << format_bytes(st.total_uploaded) << "\n";
            std::cout << "  Save path:  " << download_dir << "\n";
            std::cout << "=========================\n";
            break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    if (g_done && !torrent->is_complete()) {
        std::cout << "\n\nInterrupted by user. Download incomplete.\n";
    }

    // ── Cleanup ──────────────────────────────────────────────────────────────
    client.disable_bittorrent();
    client.stop_dht_discovery();
    client.stop();

    return torrent->is_complete() ? 0 : 1;
}
