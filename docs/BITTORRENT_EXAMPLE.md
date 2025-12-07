# BitTorrent Integration in LibRats

## Features

- Complete BitTorrent protocol implementation (BEP 3)
- DHT integration for decentralized peer discovery (BEP 5)
- Magnet link / info hash support with metadata exchange (BEP 9, BEP 10)
- Torrent file parsing and validation
- Piece verification with SHA1 hashing
- Multi-file torrent support
- Download and upload speed tracking
- Peer connection management with choke/unchoke algorithms
- Seeding support after download completion
- Progress tracking with callbacks

## Basic Usage

### 1. Enable BitTorrent

```cpp
#include "librats.h"

librats::RatsClient client(8080);  // Create RatsClient on port 8080

// Start the RatsClient first
if (!client.start()) {
    std::cerr << "Failed to start RatsClient" << std::endl;
    return -1;
}

// Enable BitTorrent functionality
if (client.enable_bittorrent(6881)) {
    std::cout << "BitTorrent enabled on port 6881" << std::endl;
} else {
    std::cerr << "Failed to enable BitTorrent" << std::endl;
}
```

### 2. Add a Torrent from File

```cpp
// Add a torrent from .torrent file
auto torrent = client.add_torrent("example.torrent", "./downloads/");
if (torrent) {
    const auto& info = torrent->get_torrent_info();
    std::cout << "Added torrent: " << info.get_name() << std::endl;
    std::cout << "Total size: " << info.get_total_length() << " bytes" << std::endl;
    std::cout << "Piece length: " << info.get_piece_length() << " bytes" << std::endl;
    std::cout << "Number of pieces: " << info.get_num_pieces() << std::endl;
    std::cout << "Files: " << info.get_files().size() << std::endl;
} else {
    std::cerr << "Failed to add torrent" << std::endl;
}
```

### 3. Add a Torrent by Info Hash (Magnet Link Style)

```cpp
// Add torrent using only the info hash (requires DHT for peer discovery)
// First, start DHT discovery
if (!client.start_dht_discovery(6881)) {
    std::cerr << "DHT required for adding torrents by hash" << std::endl;
    return -1;
}

// Enable BitTorrent (will integrate with DHT automatically)
client.enable_bittorrent(6882);

// Add by info hash hex string (40 characters)
std::string info_hash_hex = "d5540fc52bef6ce2f9c8c9b5b91f9a6c7c8d1e2f";
auto torrent = client.add_torrent_by_hash(info_hash_hex, "./downloads/");

// Note: This returns nullptr immediately as metadata is downloaded asynchronously
// The torrent will be added once metadata exchange (BEP 9) completes
```

### 4. Get Torrent Metadata Without Downloading

```cpp
// Retrieve torrent metadata (name, files, size) without starting download
client.get_torrent_metadata(info_hash_hex, 
    [](const librats::TorrentInfo& info, bool success, const std::string& error) {
        if (success) {
            std::cout << "Torrent name: " << info.get_name() << std::endl;
            std::cout << "Total size: " << info.get_total_length() << " bytes" << std::endl;
            std::cout << "Files:" << std::endl;
            for (const auto& file : info.get_files()) {
                std::cout << "  - " << file.path << " (" << file.length << " bytes)" << std::endl;
            }
        } else {
            std::cerr << "Failed to get metadata: " << error << std::endl;
        }
    });
```

### 5. Monitor Download Progress

```cpp
if (torrent) {
    // Progress callback - called periodically during download
    torrent->set_progress_callback([](uint64_t downloaded, uint64_t total, double percentage) {
        std::cout << "Progress: " << std::fixed << std::setprecision(1) << percentage << "% "
                  << "(" << downloaded << "/" << total << " bytes)" << std::endl;
    });
    
    // Piece completion callback
    torrent->set_piece_complete_callback([](librats::PieceIndex piece_index) {
        std::cout << "Piece " << piece_index << " completed and verified" << std::endl;
    });
    
    // Torrent completion callback
    torrent->set_torrent_complete_callback([](const std::string& torrent_name) {
        std::cout << "Download completed: " << torrent_name << std::endl;
    });
    
    // Peer connection callbacks
    torrent->set_peer_connected_callback([](const librats::Peer& peer) {
        std::cout << "Peer connected: " << peer.ip << ":" << peer.port << std::endl;
    });
    
    torrent->set_peer_disconnected_callback([](const librats::Peer& peer) {
        std::cout << "Peer disconnected: " << peer.ip << ":" << peer.port << std::endl;
    });
}
```

### 6. Query Torrent Statistics

```cpp
if (torrent) {
    // Progress percentage (0.0 - 100.0)
    double progress = torrent->get_progress_percentage();
    std::cout << "Progress: " << progress << "%" << std::endl;
    
    // Piece statistics
    uint32_t completed = torrent->get_completed_pieces();
    uint32_t total = torrent->get_torrent_info().get_num_pieces();
    std::cout << "Pieces: " << completed << "/" << total << std::endl;
    
    // Download/upload statistics
    uint64_t downloaded = torrent->get_downloaded_bytes();
    uint64_t uploaded = torrent->get_uploaded_bytes();
    std::cout << "Downloaded: " << downloaded << " bytes" << std::endl;
    std::cout << "Uploaded: " << uploaded << " bytes" << std::endl;
    
    // Speed statistics (bytes per second)
    double dl_speed = torrent->get_download_speed();
    double ul_speed = torrent->get_upload_speed();
    std::cout << "Download speed: " << (dl_speed / 1024) << " KB/s" << std::endl;
    std::cout << "Upload speed: " << (ul_speed / 1024) << " KB/s" << std::endl;
    
    // Peer count
    size_t peers = torrent->get_peer_count();
    std::cout << "Connected peers: " << peers << std::endl;
    
    // Check completion status
    if (torrent->is_complete()) {
        std::cout << "Torrent download is complete!" << std::endl;
    }
}
```

### 7. Get Overall BitTorrent Statistics

```cpp
// Get total statistics across all torrents
auto [total_downloaded, total_uploaded] = client.get_bittorrent_stats();
std::cout << "Total downloaded: " << total_downloaded << " bytes" << std::endl;
std::cout << "Total uploaded: " << total_uploaded << " bytes" << std::endl;

// Get active torrent count
size_t active_count = client.get_active_torrents_count();
std::cout << "Active torrents: " << active_count << std::endl;
```

### 8. DHT Integration

BitTorrent automatically integrates with librats' DHT functionality for peer discovery:

```cpp
// Start DHT first (for decentralized peer discovery)
if (client.start_dht_discovery(6881)) {
    std::cout << "DHT started for peer discovery" << std::endl;
}

// Enable BitTorrent - will automatically use DHT
// Use a different port than DHT
client.enable_bittorrent(6882);

// Add torrent - will automatically announce to DHT and discover peers
auto torrent = client.add_torrent("example.torrent", "./downloads/");
```

### 9. Manage Multiple Torrents

```cpp
// Add multiple torrents
auto torrent1 = client.add_torrent("movie.torrent", "./downloads/movies/");
auto torrent2 = client.add_torrent("music.torrent", "./downloads/music/");
auto torrent3 = client.add_torrent("software.torrent", "./downloads/software/");

// List all active torrents
auto all_torrents = client.get_all_torrents();
std::cout << "Managing " << all_torrents.size() << " torrents:" << std::endl;

for (const auto& t : all_torrents) {
    const auto& info = t->get_torrent_info();
    std::cout << "- " << info.get_name() 
              << " (" << std::fixed << std::setprecision(1) 
              << t->get_progress_percentage() << "%)" 
              << " Peers: " << t->get_peer_count()
              << std::endl;
}

// Get a specific torrent by info hash
const auto& info_hash = torrent1->get_torrent_info().get_info_hash();
auto found_torrent = client.get_torrent(info_hash);

// Remove a torrent
if (client.remove_torrent(info_hash)) {
    std::cout << "Torrent removed successfully" << std::endl;
}
```

### 10. Pause and Resume Downloads

```cpp
if (torrent) {
    // Pause the download
    torrent->pause();
    std::cout << "Torrent paused: " << torrent->is_paused() << std::endl;
    
    // Resume the download
    torrent->resume();
    std::cout << "Torrent resumed: " << torrent->is_running() << std::endl;
}
```

## Complete Example

```cpp
#include "librats.h"
#include <iostream>
#include <iomanip>
#include <thread>
#include <chrono>

// Helper function to format bytes
std::string format_bytes(uint64_t bytes) {
    if (bytes >= 1024ULL * 1024 * 1024)
        return std::to_string(bytes / (1024 * 1024 * 1024)) + " GB";
    if (bytes >= 1024 * 1024)
        return std::to_string(bytes / (1024 * 1024)) + " MB";
    if (bytes >= 1024)
        return std::to_string(bytes / 1024) + " KB";
    return std::to_string(bytes) + " B";
}

int main() {
    // Create RatsClient
    librats::RatsClient client(8080);
    
    // Start the client
    if (!client.start()) {
        std::cerr << "Failed to start RatsClient" << std::endl;
        return -1;
    }
    
    // Start DHT for peer discovery (recommended)
    if (client.start_dht_discovery(6881)) {
        std::cout << "DHT started for peer discovery" << std::endl;
    }
    
    // Enable BitTorrent functionality
    if (!client.enable_bittorrent(6882)) {
        std::cerr << "Failed to enable BitTorrent" << std::endl;
        return -1;
    }
    
    std::cout << "BitTorrent enabled successfully!" << std::endl;
    
    // Add a torrent
    auto torrent = client.add_torrent("example.torrent", "./downloads/");
    if (!torrent) {
        std::cerr << "Failed to add torrent" << std::endl;
        return -1;
    }
    
    const auto& info = torrent->get_torrent_info();
    std::cout << "\nTorrent Information:" << std::endl;
    std::cout << "  Name: " << info.get_name() << std::endl;
    std::cout << "  Size: " << format_bytes(info.get_total_length()) << std::endl;
    std::cout << "  Pieces: " << info.get_num_pieces() << std::endl;
    std::cout << "  Files: " << info.get_files().size() << std::endl;
    
    // Set up callbacks
    torrent->set_progress_callback([](uint64_t downloaded, uint64_t total, double percentage) {
        std::cout << "\rProgress: " << std::fixed << std::setprecision(1) 
                  << percentage << "% " << std::flush;
    });
    
    torrent->set_piece_complete_callback([](librats::PieceIndex piece_index) {
        // Piece completed
    });
    
    torrent->set_torrent_complete_callback([](const std::string& name) {
        std::cout << "\n\nDownload completed: " << name << std::endl;
    });
    
    torrent->set_peer_connected_callback([](const librats::Peer& peer) {
        std::cout << "\nPeer connected: " << peer.ip << ":" << peer.port << std::endl;
    });
    
    // Monitor download
    std::cout << "\nDownloading..." << std::endl;
    
    while (!torrent->is_complete()) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        
        // Print detailed stats every 5 seconds
        std::cout << "\n--- Status Update ---" << std::endl;
        std::cout << "Progress: " << std::fixed << std::setprecision(1) 
                  << torrent->get_progress_percentage() << "%" << std::endl;
        std::cout << "Pieces: " << torrent->get_completed_pieces() 
                  << "/" << info.get_num_pieces() << std::endl;
        std::cout << "Downloaded: " << format_bytes(torrent->get_downloaded_bytes()) << std::endl;
        std::cout << "Download speed: " << std::fixed << std::setprecision(1) 
                  << (torrent->get_download_speed() / 1024) << " KB/s" << std::endl;
        std::cout << "Upload speed: " << std::fixed << std::setprecision(1) 
                  << (torrent->get_upload_speed() / 1024) << " KB/s" << std::endl;
        std::cout << "Peers: " << torrent->get_peer_count() << std::endl;
        
        // Check for global stats
        auto [dl, ul] = client.get_bittorrent_stats();
        std::cout << "Total stats: DL " << format_bytes(dl) 
                  << " / UL " << format_bytes(ul) << std::endl;
    }
    
    std::cout << "\nDownload completed successfully!" << std::endl;
    
    // Continue seeding for a while
    std::cout << "Seeding for 60 seconds..." << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(60));
    
    // Clean up
    client.disable_bittorrent();
    client.stop();
    
    std::cout << "Done!" << std::endl;
    return 0;
}
```

## Magnet Link Example

```cpp
#include "librats.h"
#include <iostream>

int main() {
    librats::RatsClient client(8080);
    
    if (!client.start()) {
        std::cerr << "Failed to start client" << std::endl;
        return -1;
    }
    
    // DHT is required for magnet links
    if (!client.start_dht_discovery(6881)) {
        std::cerr << "Failed to start DHT" << std::endl;
        return -1;
    }
    
    if (!client.enable_bittorrent(6882)) {
        std::cerr << "Failed to enable BitTorrent" << std::endl;
        return -1;
    }
    
    // Parse magnet link to extract info hash
    // magnet:?xt=urn:btih:d5540fc52bef6ce2f9c8c9b5b91f9a6c7c8d1e2f&dn=Example
    std::string info_hash_hex = "d5540fc52bef6ce2f9c8c9b5b91f9a6c7c8d1e2f";
    
    // First, get metadata to preview the torrent
    std::cout << "Fetching torrent metadata from DHT..." << std::endl;
    
    client.get_torrent_metadata(info_hash_hex, 
        [&client, &info_hash_hex](const librats::TorrentInfo& info, bool success, const std::string& error) {
            if (!success) {
                std::cerr << "Failed to get metadata: " << error << std::endl;
                return;
            }
            
            std::cout << "Found torrent: " << info.get_name() << std::endl;
            std::cout << "Size: " << info.get_total_length() << " bytes" << std::endl;
            
            // Now add the torrent for download
            auto torrent = client.add_torrent(info, "./downloads/");
            if (torrent) {
                std::cout << "Download started!" << std::endl;
            }
        });
    
    // Or add directly by hash (will download metadata automatically)
    auto torrent = client.add_torrent_by_hash(info_hash_hex, "./downloads/");
    
    // Wait for operations to complete
    std::this_thread::sleep_for(std::chrono::minutes(5));
    
    client.stop();
    return 0;
}
```

## API Reference

### RatsClient BitTorrent Methods

| Method | Description |
|--------|-------------|
| `enable_bittorrent(int port)` | Enable BitTorrent on specified port |
| `disable_bittorrent()` | Disable BitTorrent functionality |
| `is_bittorrent_enabled()` | Check if BitTorrent is enabled |
| `add_torrent(file, path)` | Add torrent from .torrent file |
| `add_torrent(info, path)` | Add torrent from TorrentInfo |
| `add_torrent_by_hash(hash, path)` | Add torrent by info hash |
| `remove_torrent(hash)` | Remove a torrent |
| `get_torrent(hash)` | Get torrent by info hash |
| `get_all_torrents()` | Get all active torrents |
| `get_active_torrents_count()` | Get number of active torrents |
| `get_bittorrent_stats()` | Get total download/upload bytes |
| `get_torrent_metadata(hash, callback)` | Retrieve metadata without downloading |

### TorrentDownload Methods

| Method | Description |
|--------|-------------|
| `is_running()` | Check if download is running |
| `is_paused()` | Check if download is paused |
| `is_complete()` | Check if download is complete |
| `pause()` | Pause the download |
| `resume()` | Resume the download |
| `get_progress_percentage()` | Get progress (0.0 - 100.0) |
| `get_completed_pieces()` | Get number of completed pieces |
| `get_downloaded_bytes()` | Get total downloaded bytes |
| `get_uploaded_bytes()` | Get total uploaded bytes |
| `get_download_speed()` | Get download speed (bytes/sec) |
| `get_upload_speed()` | Get upload speed (bytes/sec) |
| `get_peer_count()` | Get number of connected peers |
| `get_torrent_info()` | Get TorrentInfo object |
| `set_progress_callback()` | Set progress callback |
| `set_piece_complete_callback()` | Set piece completion callback |
| `set_torrent_complete_callback()` | Set torrent completion callback |
| `set_peer_connected_callback()` | Set peer connected callback |
| `set_peer_disconnected_callback()` | Set peer disconnected callback |

### TorrentInfo Methods

| Method | Description |
|--------|-------------|
| `get_name()` | Get torrent name |
| `get_total_length()` | Get total size in bytes |
| `get_piece_length()` | Get piece size in bytes |
| `get_num_pieces()` | Get number of pieces |
| `get_files()` | Get list of files |
| `get_info_hash()` | Get 20-byte info hash |
| `get_announce()` | Get primary tracker URL |
| `get_announce_list()` | Get list of tracker URLs |
| `is_single_file()` | Check if single file torrent |
| `is_private()` | Check if private torrent |
