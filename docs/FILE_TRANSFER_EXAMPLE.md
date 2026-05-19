# LibRATS File Transfer API Example

This document demonstrates how to use the librats file transfer API to send
files and directory trees between connected peers.

## Overview

A transfer streams one file or a whole directory tree to a connected peer over
the reliable (and, when enabled, encrypted) `RatsClient` connection.

The file transfer system provides:
- **Streaming transfers** — data is streamed in order; memory stays bounded no matter how large the file is
- **Directory transfer** — a whole directory tree is sent recursively as a single transfer
- **Backpressure** — a windowed flow-control protocol keeps the sender from outrunning the receiver
- **Integrity verification** — a per-chunk CRC32 plus a whole-file SHA-256 checked before delivery
- **Atomic delivery** — received data lands in a temp file and is renamed to its destination only after the SHA-256 matches
- **Transfer control** — pause, resume, and cancel from either side, with real-time progress callbacks

It is a **push-only** model: the sender *offers* a transfer, and the receiver
*accepts* (choosing a destination) or *rejects* it. There is no pull/request
API — a peer cannot ask another peer to send it a file.

## Basic Usage

### Setting Up File Transfer

```cpp
#include "librats.h"
#include <iostream>

using namespace librats;

// Create RatsClient
RatsClient client(8080);

// Configure file transfer settings (optional — defaults are sensible)
FileTransferConfig config;
config.chunk_size        = 64 * 1024;       // 64KB payload per network chunk
config.window_bytes      = 4 * 1024 * 1024; // max un-acknowledged bytes in flight
config.progress_interval = 256 * 1024;      // receiver acks every 256KB
config.transfer_timeout_secs = 60;          // abort a transfer idle this long
config.worker_threads    = 4;               // concurrent outgoing transfers
config.verify_integrity  = true;            // per-chunk CRC32 + whole-file SHA-256
config.temp_directory    = "./rats_file_transfers"; // holds in-progress downloads
client.set_file_transfer_config(config);

// Handle incoming offers. The handler must eventually call
// accept_file_transfer() or reject_file_transfer(). It may do so synchronously
// (as below) or later, from any thread. Without this callback, every incoming
// offer is auto-rejected.
client.on_file_transfer_request([&client](const IncomingTransferOffer& offer) {
    std::cout << "Incoming offer from " << offer.peer_id << std::endl;
    std::cout << "  Name: " << offer.name
              << (offer.is_directory ? " (directory)" : " (file)") << std::endl;
    std::cout << "  Total: " << offer.total_size << " bytes in "
              << offer.files.size() << " file(s)" << std::endl;

    // Auto-accept transfers smaller than 100MB
    if (offer.total_size < 100 * 1024 * 1024) {
        // For a file, the path is the destination file;
        // for a directory, it is the destination directory.
        client.accept_file_transfer(offer.transfer_id, "./downloads/" + offer.name);
    } else {
        client.reject_file_transfer(offer.transfer_id, "Too large");
    }
});

// Progress fires periodically for both sending and receiving transfers.
client.on_file_transfer_progress([](const FileTransferProgress& progress) {
    std::cout << "Transfer " << progress.transfer_id << ": "
              << progress.get_completion_percentage() << "% complete"
              << " (" << (progress.transfer_rate_bps / 1024) << " KB/s, "
              << progress.estimated_time_remaining.count() / 1000 << "s left)"
              << std::endl;
});

// Completion fires exactly once per transfer, when it reaches a terminal state.
client.on_file_transfer_completed([](const std::string& transfer_id,
                                     bool success,
                                     const std::string& error_message) {
    if (success) {
        std::cout << "Transfer completed: " << transfer_id << std::endl;
    } else {
        std::cout << "Transfer failed: " << transfer_id
                  << " - " << error_message << std::endl;
    }
});

client.start();
```

### Sending Files and Directories

```cpp
// Send a single file
std::string transfer_id = client.send_file("peer_123", "/path/to/document.pdf");
if (!transfer_id.empty()) {
    std::cout << "File transfer initiated: " << transfer_id << std::endl;
} else {
    std::cout << "Failed to initiate file transfer (file missing?)" << std::endl;
}

// Send with a custom name presented to the peer
std::string transfer_id2 =
    client.send_file("peer_123", "/path/to/document.pdf", "renamed_document.pdf");

// Send an entire directory tree (recursive)
std::string dir_transfer_id =
    client.send_directory("peer_123", "/path/to/folder", "remote_folder");
```

`send_file` / `send_directory` return a transfer id immediately, or an empty
string on an immediate failure (e.g. the source path does not exist). The
actual transfer only begins once the peer accepts the offer.

### Managing Active Transfers

```cpp
// Get progress for a specific transfer (nullptr if the id is unknown)
auto progress = client.get_file_transfer_progress(transfer_id);
if (progress) {
    std::cout << "Progress: " << progress->get_completion_percentage() << "%\n";
    std::cout << "Status: "
              << file_transfer_status_name(progress->status) << "\n";
    std::cout << "Rate: " << progress->transfer_rate_bps << " bytes/sec\n";
    std::cout << "Files: " << progress->files_completed << "/"
              << progress->total_files << "\n";
}

// List all non-finished transfers
auto active_transfers = client.get_active_file_transfers();
for (const auto& t : active_transfers) {
    std::cout << "Transfer " << t->transfer_id
              << " (" << t->filename << "): "
              << t->get_completion_percentage() << "%" << std::endl;
}

// Pause / resume / cancel work from either side of a transfer
client.pause_file_transfer(transfer_id);
client.resume_file_transfer(transfer_id);
client.cancel_file_transfer(transfer_id);
```

### Transfer Statistics

```cpp
auto stats = client.get_file_transfer_statistics();
std::cout << "Uptime (s):       " << stats["uptime_seconds"]       << "\n";
std::cout << "Bytes sent:       " << stats["total_bytes_sent"]     << "\n";
std::cout << "Bytes received:   " << stats["total_bytes_received"] << "\n";
std::cout << "Files sent:       " << stats["total_files_sent"]     << "\n";
std::cout << "Files received:   " << stats["total_files_received"] << "\n";
std::cout << "Completed:        " << stats["completed_transfers"]  << "\n";
std::cout << "Failed:           " << stats["failed_transfers"]     << "\n";
std::cout << "Success rate:     " << stats["success_rate"]         << "\n";
std::cout << "Active transfers: " << stats["active_transfers"]     << "\n";
```

## API Reference

### Configuration — `FileTransferConfig`

| Field | Default | Meaning |
|-------|---------|---------|
| `chunk_size` | 64 KB | Payload bytes per network chunk frame |
| `window_bytes` | 4 MB | Max un-acknowledged bytes the sender keeps in flight |
| `progress_interval` | 256 KB | Receiver sends a progress ack every N bytes |
| `transfer_timeout_secs` | 60 | A transfer idle this long is aborted |
| `worker_threads` | 4 | Number of concurrent outgoing transfers |
| `verify_integrity` | `true` | Enable per-chunk CRC32 + whole-file SHA-256 |
| `temp_directory` | `./rats_file_transfers` | Where in-progress downloads are written |

### Incoming offer — `IncomingTransferOffer`

Passed to the offer callback. Carries `transfer_id`, `peer_id`, `name`,
`is_directory`, `total_size`, and `files` — the full manifest, a vector of
`FileInfo { relative_path, size }`.

### Progress snapshot — `FileTransferProgress`

An immutable snapshot returned by `get_file_transfer_progress` /
`get_active_file_transfers` and passed to the progress callback. Key fields:
`status`, `direction`, `filename`, `local_path`, `is_directory`,
`bytes_transferred`, `total_bytes`, `files_completed`, `total_files`,
`transfer_rate_bps`, `average_rate_bps`, `elapsed_time`,
`estimated_time_remaining`, `error_message`, and the helper
`get_completion_percentage()`.

### Status values — `FileTransferStatus`

`PENDING`, `STARTING`, `IN_PROGRESS`, `PAUSED`, `COMPLETED`, `FAILED`,
`CANCELLED`, `RESUMING`. Use `file_transfer_status_name(status)` for a
human-readable name.

### Utility

```cpp
// Hex-encoded SHA-256 of a local file ("" if it cannot be read).
std::string hash = FileTransferManager::compute_file_sha256("/path/to/file");
```

## Complete Example Program

```cpp
#include "librats.h"
#include <iostream>
#include <string>

using namespace librats;

int main() {
    RatsClient client(8080);

    // Auto-accept incoming transfers into ./downloads
    client.on_file_transfer_request([&client](const IncomingTransferOffer& offer) {
        std::cout << "Incoming: " << offer.name
                  << " (" << offer.total_size << " bytes) from "
                  << offer.peer_id << std::endl;
        client.accept_file_transfer(offer.transfer_id, "./downloads/" + offer.name);
    });

    client.on_file_transfer_progress([](const FileTransferProgress& p) {
        std::cout << p.filename << ": " << p.get_completion_percentage()
                  << "% (" << p.transfer_rate_bps / 1024 << " KB/s)" << std::endl;
    });

    client.on_file_transfer_completed([](const std::string& id, bool ok,
                                         const std::string& err) {
        std::cout << (ok ? "Completed: " : "Failed: ") << id
                  << (ok ? "" : " - " + err) << std::endl;
    });

    if (!client.start()) {
        std::cerr << "Failed to start client" << std::endl;
        return 1;
    }

    std::cout << "RatsClient started on port 8080" << std::endl;
    std::cout << "Commands:" << std::endl;
    std::cout << "  send <peer_id> <file_path>    - Send a file" << std::endl;
    std::cout << "  senddir <peer_id> <dir_path>  - Send a directory" << std::endl;
    std::cout << "  list                          - List active transfers" << std::endl;
    std::cout << "  stats                         - Show statistics" << std::endl;
    std::cout << "  quit                          - Exit" << std::endl;

    std::string line;
    while (std::getline(std::cin, line)) {
        if (line == "quit") {
            break;
        } else if (line == "list") {
            auto transfers = client.get_active_file_transfers();
            std::cout << "Active transfers (" << transfers.size() << "):" << std::endl;
            for (const auto& t : transfers) {
                std::cout << "  " << t->transfer_id << " - " << t->filename
                          << " (" << t->get_completion_percentage() << "%)"
                          << std::endl;
            }
        } else if (line == "stats") {
            auto s = client.get_file_transfer_statistics();
            std::cout << "Bytes sent: "     << s["total_bytes_sent"]
                      << ", received: "     << s["total_bytes_received"]
                      << ", success rate: " << s["success_rate"] << std::endl;
        } else if (line.rfind("senddir ", 0) == 0) {
            auto sp = line.find(' ', 8);
            if (sp != std::string::npos) {
                std::string peer = line.substr(8, sp - 8);
                std::string path = line.substr(sp + 1);
                std::string id = client.send_directory(peer, path);
                std::cout << (id.empty() ? "Failed to start transfer"
                                         : "Directory transfer: " + id) << std::endl;
            }
        } else if (line.rfind("send ", 0) == 0) {
            auto sp = line.find(' ', 5);
            if (sp != std::string::npos) {
                std::string peer = line.substr(5, sp - 5);
                std::string path = line.substr(sp + 1);
                std::string id = client.send_file(peer, path);
                std::cout << (id.empty() ? "Failed to start transfer"
                                         : "File transfer: " + id) << std::endl;
            }
        }
    }

    client.stop();
    return 0;
}
```

## How It Works

A transfer uses two channels over the same peer connection:

- **Control channel** — JSON named messages: the offer manifest, the
  accept/reject response, per-file SHA-256 on completion, progress acks, the
  final result, and pause/resume/cancel commands.
- **Data channel** — self-describing binary chunk frames carrying the file
  bytes.

Because the transport is reliable and ordered, chunks are streamed strictly
sequentially — there is no per-chunk retransmission. The receiver keeps a
cursor and fails the transfer if a chunk arrives out of order. The sender keeps
at most `window_bytes` un-acknowledged and waits for a progress ack before
sending more, so memory use stays bounded regardless of file size.

Received data is written into `temp_directory` and is only renamed to the final
destination after its whole-file SHA-256 matches the value the sender reported.
A cancelled, timed-out, or disconnected transfer deletes its temp files, so a
failed transfer never leaves a corrupt file behind.

## Performance Tips

1. **Chunk size** — larger chunks (256KB–1MB) reduce per-frame overhead on fast networks; smaller chunks suit slow links.
2. **Window size** — a larger `window_bytes` improves throughput on high-latency links at the cost of more memory in flight.
3. **Integrity** — `verify_integrity` adds CRC32 + SHA-256 work; leave it on unless you fully trust the link and the peer.
4. **Worker threads** — `worker_threads` bounds how many *outgoing* transfers run at once; raise it if you frequently send several files in parallel.

## Security Considerations

- File transfers ride the `RatsClient` connection, so they are encrypted whenever peer encryption is enabled.
- Integrity is verified end-to-end with a per-chunk CRC32 and a whole-file SHA-256; a mismatch fails the transfer.
- Relative paths inside a directory manifest from a peer are sanitized against directory-traversal (`..`, absolute paths) before anything is written.
- Incoming transfers are never accepted automatically — the application's offer callback decides, and it picks the destination path.

## Limitations

- Push-only: there is no API to request a file from a peer.
- A transfer cannot resume across a disconnect — a dropped connection fails the in-flight transfer, which must be started again.
- Chunks are streamed sequentially; a single transfer does not use multiple connections in parallel.
