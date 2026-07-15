// 04_file_transfer — stream a file to a peer with integrity + progress.
//
// The FileTransfer subsystem implements a push model: the sender offers a file,
// the receiver accepts (choosing a destination), the sender streams it, and the
// receiver verifies a per-chunk CRC32 and a whole-file SHA-256 before moving it
// into place.
//
// Receiver (auto-accepts any offer into ./received):
//   04_file_transfer <listen_port>
//
// Sender (dials the receiver, then sends the file once connected):
//   04_file_transfer <listen_port> <host> <port> <path-to-file>
//
//   ./04_file_transfer 9000
//   ./04_file_transfer 9001 127.0.0.1 9000 ./some-file.bin
// Both sides print progress; the process exits once the transfer completes.

#include "node/node.h"
#include "subsystems/file_transfer.h"
#include "util/fs.h"

#include <atomic>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>

using namespace librats;

int main(int argc, char** argv) {
    if (argc != 2 && argc != 5) {
        std::cerr << "usage:\n"
                  << "  receiver: " << argv[0] << " <listen_port>\n"
                  << "  sender:   " << argv[0] << " <listen_port> <host> <port> <file>\n";
        return 1;
    }
    const bool is_sender = (argc == 5);

    NodeConfig config;
    config.listen_port  = static_cast<uint16_t>(std::stoi(argv[1]));
    config.bind_address = "::";

    Node node(config);

    // The receiver stages in-progress downloads in ./received; the sender only
    // needs a temp dir for its own bookkeeping.
    const std::string dest_dir = "./received";
    create_directories(dest_dir.c_str());
    auto* files = node.add_subsystem(std::make_unique<FileTransfer>(dest_dir));

    std::atomic<bool> done{false};

    // Receiver side: auto-accept every offer into ./received/<name>.
    files->on_offer([&](const FileTransfer::Offer& offer) {
        std::cout << "[offer] " << offer.name << " (" << offer.size << " bytes) from "
                  << offer.from.short_hex() << " — accepting\n";
        files->accept(offer.from, offer.id, dest_dir + "/" + offer.name);
    });
    files->on_progress([](const FileTransfer::Progress& p) {
        std::cout << "\r[progress] " << static_cast<int>(p.percent()) << "%   " << std::flush;
    });
    files->on_complete([&](uint64_t id, bool ok, const std::string& path) {
        std::cout << "\n[done] transfer " << id << (ok ? " OK: " : " FAILED: ") << path << "\n";
        done = true;  // let the sender exit; a long-running receiver would omit this
    });

    // Send the file as soon as the peer's handshake completes.
    const std::string send_path = is_sender ? argv[4] : std::string();
    node.on_peer_connected([&](const Peer& peer) {
        std::cout << "[+] connected: " << peer.id().short_hex() << "\n";
        if (is_sender) {
            const uint64_t id = files->send_file(peer.id(), send_path);
            std::cout << (id ? "sending, transfer id " + std::to_string(id)
                             : std::string("send failed (unreadable file?)")) << "\n";
        }
    });

    if (!node.start()) {
        std::cerr << "failed to start node\n";
        return 1;
    }
    std::cout << "node " << node.local_id().short_hex() << " on port " << node.listen_port()
              << (is_sender ? " (sender)\n" : " (receiver, saving into " + dest_dir + ")\n");

    if (is_sender)
        node.connect(argv[2], static_cast<uint16_t>(std::stoi(argv[3])));

    // A receiver waits indefinitely; the sender exits once the transfer finishes.
    if (is_sender) {
        while (!done) std::this_thread::sleep_for(std::chrono::milliseconds(100));
    } else {
        std::cout << "waiting for incoming files (Ctrl-C to quit)\n";
        std::string line;
        std::getline(std::cin, line);  // block until EOF / a keypress
    }

    node.stop();
    return 0;
}
