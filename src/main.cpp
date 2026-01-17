#include "librats.h"
#include "network_utils.h"
#include "version.h"
#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <sstream>
#include <algorithm>

// Main module logging macros
#define LOG_MAIN_DEBUG(message) LOG_DEBUG("rats", message)
#define LOG_MAIN_INFO(message)  LOG_INFO("rats", message)
#define LOG_MAIN_WARN(message)  LOG_WARN("rats", message)
#define LOG_MAIN_ERROR(message) LOG_ERROR("rats", message)

void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [listen_port] [peer_host] [peer_port]\n";
    std::cout << "  listen_port: Port to listen on for incoming connections (default: 8080)\n";
    std::cout << "  peer_host:   Optional hostname/IP to connect to as peer\n";
    std::cout << "  peer_port:   Optional port of peer to connect to\n";
    std::cout << "\nExample:\n";
    std::cout << "  " << program_name << "                     # Listen on default port 8080\n";
    std::cout << "  " << program_name << " 8080              # Listen on port 8080\n";
    std::cout << "  " << program_name << " 8081 localhost 8080  # Listen on 8081 and connect to 8080\n";
}

void print_help() {
    std::cout << "Available commands:" << std::endl;
    std::cout << "  help              - Show this help message" << std::endl;
    std::cout << "  version           - Show version information" << std::endl;
    std::cout << "  peers             - Show number of connected peers" << std::endl;
    std::cout << "  list              - List all connected peers with their hash IDs" << std::endl;
    std::cout << "  broadcast <msg>   - Send message to all connected peers" << std::endl;
    std::cout << "  send <hash> <msg> - Send message to specific peer by hash ID" << std::endl;
    std::cout << "  connect <host> <port> - Connect to a peer" << std::endl;
    std::cout << "  connect6 <host> <port> - Connect to a peer using IPv6" << std::endl;
    std::cout << "  connect_dual <host> <port> - Connect using dual stack (IPv6 first, then IPv4)" << std::endl;
    std::cout << "  dht_start         - Start DHT peer discovery" << std::endl;
    std::cout << "  dht_stop          - Stop DHT peer discovery" << std::endl;
    std::cout << "  dht_status        - Show DHT status" << std::endl;
    std::cout << "  dht_find <hash>   - Find peers for content hash" << std::endl;
    std::cout << "  dht_announce <hash> [port] - Announce as peer for content hash" << std::endl;
    std::cout << "  dht_discovery_status - Show automatic rats peer discovery status" << std::endl;
    std::cout << "  mdns_start          - Start mDNS local network discovery" << std::endl;
    std::cout << "  mdns_stop           - Stop mDNS local network discovery" << std::endl;
    std::cout << "  mdns_status         - Show mDNS discovery status" << std::endl;
    std::cout << "  mdns_services       - List discovered mDNS services" << std::endl;
    std::cout << "  mdns_query          - Manually query for mDNS services" << std::endl;
    std::cout << "  netutils [hostname] - Test network utilities" << std::endl;
    std::cout << "  netutils6 [hostname] - Test IPv6 network utilities" << std::endl;
    std::cout << "  dht_test <ip> <port> - Test DHT protocol with specific peer" << std::endl;
    std::cout << "  test_ipv6 <host> <port> - Test IPv6 connectivity" << std::endl;
    std::cout << "\nFile Transfer Commands:" << std::endl;
    std::cout << "  file_send <peer_hash> <file_path> [remote_name] - Send file to peer" << std::endl;
    std::cout << "  dir_send <peer_hash> <dir_path> [remote_name] [recursive] - Send directory to peer" << std::endl;
    std::cout << "  file_request <peer_hash> <remote_path> <local_path> - Request file from peer" << std::endl;
    std::cout << "  dir_request <peer_hash> <remote_path> <local_path> [recursive] - Request directory from peer" << std::endl;
    std::cout << "  transfer_list     - List active file transfers" << std::endl;
    std::cout << "  transfer_status <transfer_id> - Show transfer progress" << std::endl;
    std::cout << "  transfer_pause <transfer_id> - Pause a transfer" << std::endl;
    std::cout << "  transfer_resume <transfer_id> - Resume a transfer" << std::endl;
    std::cout << "  transfer_cancel <transfer_id> - Cancel a transfer" << std::endl;
    std::cout << "  transfer_stats    - Show transfer statistics" << std::endl;
#ifdef RATS_SEARCH_FEATURES
    std::cout << "\nBitTorrent Commands:" << std::endl;
    std::cout << "  bittorrent_enable [port] - Enable BitTorrent (default port: 6881)" << std::endl;
    std::cout << "  bittorrent_disable - Disable BitTorrent" << std::endl;
    std::cout << "  bittorrent_status  - Show BitTorrent status" << std::endl;
    std::cout << "  torrent_add <file> <path> - Add torrent from .torrent file" << std::endl;
    std::cout << "  torrent_add_hash <hash> <path> - Add torrent by info hash (uses DHT)" << std::endl;
    std::cout << "  torrent_metadata <hash> - Get torrent metadata without downloading" << std::endl;
    std::cout << "  torrent_find_peers <hash> - Find peers for torrent via DHT" << std::endl;
    std::cout << "  torrent_list       - List all active torrents" << std::endl;
    std::cout << "  torrent_remove <hash> - Remove torrent by info hash" << std::endl;
    std::cout << "  torrent_info <hash> - Show torrent information" << std::endl;
    std::cout << "  torrent_pause <hash> - Pause a torrent download" << std::endl;
    std::cout << "  torrent_resume <hash> - Resume a paused torrent" << std::endl;
    std::cout << "  torrent_peers <hash> - Show connected peers for a torrent" << std::endl;
    std::cout << "  bittorrent_stats   - Show BitTorrent statistics" << std::endl;
#endif
#ifdef RATS_STORAGE
    std::cout << "\nDistributed Storage Commands:" << std::endl;
    std::cout << "  storage_put <key> <value> - Store a string value" << std::endl;
    std::cout << "  storage_get <key>     - Get a stored value" << std::endl;
    std::cout << "  storage_delete <key>  - Delete a key" << std::endl;
    std::cout << "  storage_has <key>     - Check if key exists" << std::endl;
    std::cout << "  storage_list          - List all keys" << std::endl;
    std::cout << "  storage_list <prefix> - List keys with prefix" << std::endl;
    std::cout << "  storage_stats         - Show storage statistics" << std::endl;
    std::cout << "  storage_sync          - Request sync from peers" << std::endl;
    std::cout << "  storage_status        - Show sync status" << std::endl;
    std::cout << "  storage_clear         - Clear all storage entries" << std::endl;
#endif
    std::cout << "  quit              - Exit the program" << std::endl;
}

int main(int argc, char* argv[]) {
    // Display ASCII header with version information
    librats::version::rats_print_header();
    
    // Enable debug level logging
    librats::Logger::getInstance().set_log_level(librats::LogLevel::DEBUG);
    
    int listen_port = 8080; // Default port
    
    if (argc >= 2) {
        listen_port = std::stoi(argv[1]);
    } else {
        LOG_MAIN_INFO("No port specified, using default port " << listen_port);
    }
    std::string peer_host = "";
    int peer_port = 0;
    
    if (argc >= 4) {
        peer_host = argv[2];
        peer_port = std::stoi(argv[3]);
    }
    
    LOG_MAIN_DEBUG("Debug logging enabled");
    LOG_MAIN_INFO("Starting RatsClient on port " << listen_port);
    
    // Create and configure the RatsClient
    librats::RatsClient client(listen_port);
    
    // Store connected peers for listing
    std::vector<std::pair<socket_t, std::string>> connected_peers;
    std::mutex peers_list_mutex;
    
    // Set up callbacks
    client.set_connection_callback([&](socket_t socket, const std::string& peer_hash_id) {
        LOG_MAIN_INFO("New peer connected: " << peer_hash_id << " (socket: " << socket << ")");
        
        // Add to connected peers list
        {
            std::lock_guard<std::mutex> lock(peers_list_mutex);
            connected_peers.push_back({socket, peer_hash_id});
        }
    });
    
    client.set_string_data_callback([](socket_t socket, const std::string& peer_hash_id, const std::string& data) {
        LOG_MAIN_INFO("Message from peer " << peer_hash_id << ": " << data);
    });
    
    client.set_disconnect_callback([&](socket_t socket, const std::string& peer_hash_id) {
        LOG_MAIN_INFO("Peer disconnected: " << peer_hash_id << " (socket: " << socket << ")");
        
        // Remove from connected peers list
        {
            std::lock_guard<std::mutex> lock(peers_list_mutex);
            connected_peers.erase(
                std::remove_if(connected_peers.begin(), connected_peers.end(),
                    [socket](const std::pair<socket_t, std::string>& peer) {
                        return peer.first == socket;
                    }),
                connected_peers.end()
            );
        }
    });

    // Set up mDNS callback for local network peer discovery
    client.set_mdns_callback([&](const std::string& host, int port, const std::string& instance_name) {
        LOG_MAIN_INFO("mDNS discovered service: " << instance_name << " at " << host << ":" << port);
        // Auto-connect to discovered rats peers on local network
        if (client.get_peer_count() < client.get_max_peers()) {
            LOG_MAIN_INFO("Attempting to connect to mDNS discovered peer...");
            client.connect_to_peer(host, port);
        }
    });

    // Set up file transfer callbacks
    if (client.is_file_transfer_available()) {
        // Progress callback for file transfers
        client.on_file_transfer_progress([](const librats::FileTransferProgress& progress) {
            LOG_MAIN_INFO("Transfer " << progress.transfer_id << ": " 
                         << progress.get_completion_percentage() << "% complete ("
                         << progress.bytes_transferred << "/" << progress.total_bytes << " bytes)"
                         << " - Rate: " << (progress.transfer_rate_bps / 1024.0) << " KB/s");
        });
        
        // Completion callback for file transfers
        client.on_file_transfer_completed([](const std::string& transfer_id, bool success, const std::string& error_message) {
            if (success) {
                LOG_MAIN_INFO("Transfer " << transfer_id << " completed successfully!");
            } else {
                LOG_MAIN_ERROR("Transfer " << transfer_id << " failed: " << error_message);
            }
        });
        
        // Incoming file transfer request callback
        client.on_file_transfer_request([](const std::string& peer_id, const librats::FileMetadata& metadata, const std::string& transfer_id) {
            LOG_MAIN_INFO("=== Incoming File Transfer Request ===");
            LOG_MAIN_INFO("From peer: " << peer_id);
            LOG_MAIN_INFO("File: " << metadata.filename);
            LOG_MAIN_INFO("Size: " << metadata.file_size << " bytes");
            LOG_MAIN_INFO("Transfer ID: " << transfer_id);
            LOG_MAIN_INFO("Auto-accepting file transfer...");
            return true; // Auto-accept for now - could be made interactive
        });
        
        // Directory transfer progress callback
        client.on_directory_transfer_progress([](const std::string& transfer_id, const std::string& current_file, 
                                                uint64_t files_completed, uint64_t total_files, 
                                                uint64_t bytes_completed, uint64_t total_bytes) {
            double file_progress = total_files > 0 ? (double(files_completed) / total_files) * 100.0 : 0.0;
            double byte_progress = total_bytes > 0 ? (double(bytes_completed) / total_bytes) * 100.0 : 0.0;
            LOG_MAIN_INFO("Directory transfer " << transfer_id << ": " << files_completed << "/" << total_files 
                         << " files (" << file_progress << "%), " << bytes_completed << "/" << total_bytes 
                         << " bytes (" << byte_progress << "%) - Current: " << current_file);
        });
        
        // File request callback (when receiving file requests)
        client.on_file_request([](const std::string& peer_id, const std::string& file_path, const std::string& transfer_id) {
            LOG_MAIN_INFO("=== Incoming File Request ===");
            LOG_MAIN_INFO("From peer: " << peer_id);
            LOG_MAIN_INFO("Requested file: " << file_path);
            LOG_MAIN_INFO("Transfer ID: " << transfer_id);
            LOG_MAIN_INFO("Auto-accepting file request...");
            return true; // Auto-accept for now - could be made interactive
        });
        
        // Directory request callback (when receiving directory requests)
        client.on_directory_request([](const std::string& peer_id, const std::string& directory_path, 
                                      bool recursive, const std::string& transfer_id) {
            LOG_MAIN_INFO("=== Incoming Directory Request ===");
            LOG_MAIN_INFO("From peer: " << peer_id);
            LOG_MAIN_INFO("Requested directory: " << directory_path);
            LOG_MAIN_INFO("Recursive: " << (recursive ? "yes" : "no"));
            LOG_MAIN_INFO("Transfer ID: " << transfer_id);
            LOG_MAIN_INFO("Auto-accepting directory request...");
            return true; // Auto-accept for now - could be made interactive
        });
        
        LOG_MAIN_INFO("File transfer callbacks configured");
    } else {
        LOG_MAIN_WARN("File transfer manager not available");
    }

#ifdef RATS_STORAGE
    // Initialize storage manager (lazy initialization - must call get_storage_manager() first)
    LOG_MAIN_INFO("Initializing distributed storage...");
    client.get_storage_manager(); // This triggers lazy initialization
    
    // Set up storage callbacks
    if (client.is_storage_available()) {
        // Storage change callback
        client.on_storage_change([](const librats::StorageChangeEvent& event) {
            if (event.operation == librats::StorageOperation::OP_PUT) {
                LOG_MAIN_INFO("Storage: key '" << event.key << "' updated" 
                             << (event.is_remote ? " (from peer " + event.origin_peer_id + ")" : ""));
            } else if (event.operation == librats::StorageOperation::OP_DELETE) {
                LOG_MAIN_INFO("Storage: key '" << event.key << "' deleted"
                             << (event.is_remote ? " (from peer " + event.origin_peer_id + ")" : ""));
            }
        });
        
        // Storage sync complete callback
        client.on_storage_sync_complete([](bool success, const std::string& error_message) {
            if (success) {
                LOG_MAIN_INFO("Storage sync completed successfully");
            } else {
                LOG_MAIN_ERROR("Storage sync failed: " << error_message);
            }
        });
        
        LOG_MAIN_INFO("Storage callbacks configured");
    } else {
        LOG_MAIN_WARN("Storage manager not available");
    }
#endif

    // Start the client
    if (!client.start()) {
        LOG_MAIN_ERROR("Failed to start RatsClient on port " << listen_port);
        return 1;
    }
    
    // Start DHT discovery
    LOG_MAIN_INFO("Starting DHT peer discovery...");
    if (client.start_dht_discovery()) {
        LOG_MAIN_INFO("DHT peer discovery started successfully");
    } else {
        LOG_MAIN_WARN("Failed to start DHT peer discovery, but continuing...");
    }
    
    // Start mDNS discovery for local network peer discovery
    LOG_MAIN_INFO("Starting mDNS local network discovery...");
    if (client.start_mdns_discovery()) {
        LOG_MAIN_INFO("mDNS local network discovery started successfully");
    } else {
        LOG_MAIN_WARN("Failed to start mDNS discovery, but continuing...");
    }
    
    // Connect to peer if specified
    if (!peer_host.empty() && peer_port > 0) {
        LOG_MAIN_INFO("Connecting to peer " << peer_host << ":" << peer_port << "...");
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        if (client.connect_to_peer(peer_host, peer_port)) {
            LOG_MAIN_INFO("Successfully connected to peer!");
        } else {
            LOG_MAIN_WARN("Failed to connect to peer, but continuing...");
        }
    }
    
    LOG_MAIN_INFO("RatsClient is running. Current peers: " << client.get_peer_count());
    if (client.is_dht_running()) {
        LOG_MAIN_INFO("DHT peer discovery is active. Routing table size: " << client.get_dht_routing_table_size() << " nodes");
        if (client.is_automatic_discovery_running()) {
            LOG_MAIN_INFO("Automatic rats peer discovery is active using hash: " << librats::RatsClient::get_rats_peer_discovery_hash());
            LOG_MAIN_INFO("This will automatically find and connect to other rats peers!");
        }
    } else {
        LOG_MAIN_INFO("DHT peer discovery is inactive. Use 'dht_start' to enable it.");
    }
    if (client.is_mdns_running()) {
        LOG_MAIN_INFO("mDNS local network discovery is active.");
    } else {
        LOG_MAIN_INFO("mDNS local network discovery is inactive. Use 'mdns_start' to enable it.");
    }
#ifdef RATS_STORAGE
    if (client.is_storage_available()) {
        LOG_MAIN_INFO("Distributed storage is available. Entries: " << client.storage_size());
        if (client.is_storage_synced()) {
            LOG_MAIN_INFO("Storage is synced with peers.");
        } else {
            LOG_MAIN_INFO("Storage sync pending. Use 'storage_sync' to sync with peers.");
        }
    } else {
        LOG_MAIN_INFO("Distributed storage is not available.");
    }
#endif
    print_help();
    
    // Add initial prompt
    std::cout << "\nrats> ";
    std::cout.flush();
    
    // Main command loop
    std::string input;
    while (client.is_running()) {
        std::getline(std::cin, input);
        
        if (input.empty()) {
            std::cout << "rats> ";
            std::cout.flush();
            continue;
        }
        
        std::istringstream iss(input);
        std::string command;
        iss >> command;
        
        if (command == "quit" || command == "exit") {
            LOG_MAIN_INFO("Shutting down...");
            break;
        }
        else if (command == "help") {
            print_help();
        }
        else if (command == "version") {
            librats::version::rats_print_version_info();
        }
        else if (command == "peers") {
            LOG_MAIN_INFO("Connected peers: " << client.get_peer_count());
        }
        else if (command == "list") {
            std::lock_guard<std::mutex> lock(peers_list_mutex);
            if (connected_peers.empty()) {
                std::cout << "No peers connected." << std::endl;
            } else {
                std::cout << "Connected peers:" << std::endl;
                for (const auto& peer : connected_peers) {
                    std::cout << "  Socket: " << peer.first << " | Hash ID: " << peer.second << std::endl;
                }
            }
        }
        else if (command == "broadcast") {
            std::string message;
            std::getline(iss, message);
            if (!message.empty()) {
                message = message.substr(1); // Remove leading space
                int sent = client.broadcast_string_to_peers(message);
                LOG_MAIN_INFO("Broadcasted message to " << sent << " peers");
            } else {
                std::cout << "Usage: broadcast <message>" << std::endl;
            }
        }
        else if (command == "send") {
            std::string hash_id, message;
            iss >> hash_id;
            std::getline(iss, message);
            if (!hash_id.empty() && !message.empty()) {
                message = message.substr(1); // Remove leading space
                if (client.send_string_to_peer_id(hash_id, message)) {
                    LOG_MAIN_INFO("Sent message to peer " << hash_id);
                } else {
                    LOG_MAIN_ERROR("Failed to send message to peer " << hash_id);
                }
            } else {
                std::cout << "Usage: send <hash_id> <message>" << std::endl;
            }
        }
        else if (command == "connect") {
            std::string host;
            int port;
            iss >> host >> port;
            if (!host.empty() && port > 0) {
                LOG_MAIN_INFO("Connecting to " << host << ":" << port << "...");
                if (client.connect_to_peer(host, port)) {
                    LOG_MAIN_INFO("Successfully connected!");
                } else {
                    LOG_MAIN_ERROR("Failed to connect to peer");
                }
            } else {
                std::cout << "Usage: connect <host> <port>" << std::endl;
            }
        }
        else if (command == "dht_start") {
            if (client.is_dht_running()) {
                std::cout << "DHT is already running." << std::endl;
            } else {
                LOG_MAIN_INFO("Starting DHT peer discovery...");
                if (client.start_dht_discovery()) {
                    LOG_MAIN_INFO("DHT peer discovery started successfully");
                } else {
                    LOG_MAIN_ERROR("Failed to start DHT peer discovery");
                }
            }
        }
        else if (command == "dht_stop") {
            if (!client.is_dht_running()) {
                std::cout << "DHT is not running." << std::endl;
            } else {
                LOG_MAIN_INFO("Stopping DHT peer discovery...");
                client.stop_dht_discovery();
                LOG_MAIN_INFO("DHT peer discovery stopped");
            }
        }
        else if (command == "dht_status") {
            if (client.is_dht_running()) {
                size_t routing_table_size = client.get_dht_routing_table_size();
                LOG_MAIN_INFO("DHT Status: RUNNING | Routing table size: " << routing_table_size << " nodes");
            } else {
                LOG_MAIN_INFO("DHT Status: STOPPED");
            }
        }
        else if (command == "dht_find") {
            std::string content_hash;
            iss >> content_hash;
            if (!content_hash.empty()) {
                if (!client.is_dht_running()) {
                    std::cout << "DHT is not running. Start it first with 'dht_start'" << std::endl;
                } else {
                    LOG_MAIN_INFO("Finding peers for content hash: " << content_hash);
                    bool success = client.find_peers_by_hash(content_hash, 
                        [content_hash](const std::vector<std::string>& peers) {
                            LOG_MAIN_INFO("Found " << peers.size() << " peers for hash " << content_hash);
                            for (const auto& peer : peers) {
                                LOG_MAIN_INFO("  Peer: " << peer);
                            }
                        });
                    if (success) {
                        LOG_MAIN_INFO("DHT peer search initiated");
                    } else {
                        LOG_MAIN_ERROR("Failed to initiate DHT peer search");
                    }
                }
            } else {
                std::cout << "Usage: dht_find <content_hash>" << std::endl;
            }
        }
        else if (command == "dht_announce") {
            std::string content_hash;
            int port = 0;
            iss >> content_hash >> port;
            if (!content_hash.empty()) {
                if (!client.is_dht_running()) {
                    std::cout << "DHT is not running. Start it first with 'dht_start'" << std::endl;
                } else {
                    LOG_MAIN_INFO("Announcing as peer for content hash: " << content_hash 
                                  << " (port: " << (port > 0 ? port : listen_port) << ")");
                    if (client.announce_for_hash(content_hash, port)) {
                        LOG_MAIN_INFO("DHT peer announcement initiated");
                    } else {
                        LOG_MAIN_ERROR("Failed to initiate DHT peer announcement");
                    }
                }
            } else {
                std::cout << "Usage: dht_announce <content_hash> [port]" << std::endl;
            }
        }
        else if (command == "dht_discovery_status") {
            LOG_MAIN_INFO("=== Automatic Rats Peer Discovery Status ===");
            if (client.is_automatic_discovery_running()) {
                LOG_MAIN_INFO("Automatic discovery: RUNNING");
                LOG_MAIN_INFO("Discovery hash: " << librats::RatsClient::get_rats_peer_discovery_hash());
                LOG_MAIN_INFO("Discovery works by:");
                LOG_MAIN_INFO("  - Announcing our presence for the rats discovery hash every 10 minutes");
                LOG_MAIN_INFO("  - Searching for other rats peers every 5 minutes");
                LOG_MAIN_INFO("  - Automatically connecting to discovered rats peers");
            } else {
                LOG_MAIN_INFO("Automatic discovery: STOPPED");
            }
            if (client.is_dht_running()) {
                LOG_MAIN_INFO("DHT Status: RUNNING | Routing table size: " << client.get_dht_routing_table_size() << " nodes");
            } else {
                LOG_MAIN_INFO("DHT Status: STOPPED");
            }
        }
        else if (command == "mdns_start") {
            if (client.is_mdns_running()) {
                std::cout << "mDNS is already running." << std::endl;
            } else {
                LOG_MAIN_INFO("Starting mDNS local network discovery...");
                if (client.start_mdns_discovery()) {
                    LOG_MAIN_INFO("mDNS local network discovery started successfully");
                } else {
                    LOG_MAIN_ERROR("Failed to start mDNS discovery");
                }
            }
        }
        else if (command == "mdns_stop") {
            if (!client.is_mdns_running()) {
                std::cout << "mDNS is not running." << std::endl;
            } else {
                LOG_MAIN_INFO("Stopping mDNS local network discovery...");
                client.stop_mdns_discovery();
                LOG_MAIN_INFO("mDNS local network discovery stopped");
            }
        }
        else if (command == "mdns_status") {
            if (client.is_mdns_running()) {
                auto services = client.get_mdns_services();
                LOG_MAIN_INFO("mDNS Status: RUNNING | Discovered services: " << services.size());
            } else {
                LOG_MAIN_INFO("mDNS Status: STOPPED");
            }
        }
        else if (command == "mdns_services") {
            if (!client.is_mdns_running()) {
                LOG_MAIN_ERROR("mDNS is not running. Use 'mdns_start' first.");
            } else {
                auto services = client.get_mdns_services();
                if (services.empty()) {
                    std::cout << "No mDNS services discovered yet." << std::endl;
                } else {
                    std::cout << "Discovered mDNS services (" << services.size() << "):" << std::endl;
                    for (const auto& service : services) {
                        std::cout << "  Service: " << service.service_name << std::endl;
                        std::cout << "    Host: " << service.host_name << " (" << service.ip_address << ":" << service.port << ")" << std::endl;
                        if (!service.txt_records.empty()) {
                            std::cout << "    TXT records:" << std::endl;
                            for (const auto& txt : service.txt_records) {
                                std::cout << "      " << txt.first << "=" << txt.second << std::endl;
                            }
                        }
                        std::cout << std::endl;
                    }
                }
            }
        }
        else if (command == "mdns_query") {
            if (!client.is_mdns_running()) {
                LOG_MAIN_ERROR("mDNS is not running. Use 'mdns_start' first.");
            } else {
                LOG_MAIN_INFO("Querying for mDNS services...");
                if (client.query_mdns_services()) {
                    LOG_MAIN_INFO("mDNS query sent. Results will appear as services are discovered.");
                } else {
                    LOG_MAIN_ERROR("Failed to send mDNS query");
                }
            }
        }
        else if (command == "file_send") {
            std::string peer_hash, file_path, remote_name;
            iss >> peer_hash >> file_path;
            std::getline(iss, remote_name);
            if (!remote_name.empty()) {
                remote_name = remote_name.substr(1); // Remove leading space
            }
            
            if (!peer_hash.empty() && !file_path.empty()) {
                if (!client.is_file_transfer_available()) {
                    LOG_MAIN_ERROR("File transfer not available");
                } else {
                    LOG_MAIN_INFO("Sending file '" << file_path << "' to peer " << peer_hash 
                                 << (remote_name.empty() ? "" : " as '" + remote_name + "'"));
                    std::string transfer_id = client.send_file(peer_hash, file_path, remote_name);
                    if (!transfer_id.empty()) {
                        LOG_MAIN_INFO("File transfer initiated with ID: " << transfer_id);
                    } else {
                        LOG_MAIN_ERROR("Failed to initiate file transfer");
                    }
                }
            } else {
                std::cout << "Usage: file_send <peer_hash> <file_path> [remote_name]" << std::endl;
            }
        }
        else if (command == "dir_send") {
            std::string peer_hash, dir_path, remote_name, recursive_str;
            iss >> peer_hash >> dir_path >> remote_name >> recursive_str;
            
            if (!peer_hash.empty() && !dir_path.empty()) {
                if (!client.is_file_transfer_available()) {
                    LOG_MAIN_ERROR("File transfer not available");
                } else {
                    bool recursive = (recursive_str.empty() || recursive_str == "true" || recursive_str == "1");
                    LOG_MAIN_INFO("Sending directory '" << dir_path << "' to peer " << peer_hash 
                                 << (remote_name.empty() ? "" : " as '" + remote_name + "'")
                                 << " (recursive: " << (recursive ? "yes" : "no") << ")");
                    std::string transfer_id = client.send_directory(peer_hash, dir_path, remote_name, recursive);
                    if (!transfer_id.empty()) {
                        LOG_MAIN_INFO("Directory transfer initiated with ID: " << transfer_id);
                    } else {
                        LOG_MAIN_ERROR("Failed to initiate directory transfer");
                    }
                }
            } else {
                std::cout << "Usage: dir_send <peer_hash> <dir_path> [remote_name] [recursive]" << std::endl;
            }
        }
        else if (command == "file_request") {
            std::string peer_hash, remote_path, local_path;
            iss >> peer_hash >> remote_path >> local_path;
            
            if (!peer_hash.empty() && !remote_path.empty() && !local_path.empty()) {
                if (!client.is_file_transfer_available()) {
                    LOG_MAIN_ERROR("File transfer not available");
                } else {
                    LOG_MAIN_INFO("Requesting file '" << remote_path << "' from peer " << peer_hash 
                                 << " to save as '" << local_path << "'");
                    std::string transfer_id = client.request_file(peer_hash, remote_path, local_path);
                    if (!transfer_id.empty()) {
                        LOG_MAIN_INFO("File request initiated with ID: " << transfer_id);
                    } else {
                        LOG_MAIN_ERROR("Failed to initiate file request");
                    }
                }
            } else {
                std::cout << "Usage: file_request <peer_hash> <remote_path> <local_path>" << std::endl;
            }
        }
        else if (command == "dir_request") {
            std::string peer_hash, remote_path, local_path, recursive_str;
            iss >> peer_hash >> remote_path >> local_path >> recursive_str;
            
            if (!peer_hash.empty() && !remote_path.empty() && !local_path.empty()) {
                if (!client.is_file_transfer_available()) {
                    LOG_MAIN_ERROR("File transfer not available");
                } else {
                    bool recursive = (recursive_str.empty() || recursive_str == "true" || recursive_str == "1");
                    LOG_MAIN_INFO("Requesting directory '" << remote_path << "' from peer " << peer_hash 
                                 << " to save as '" << local_path << "' (recursive: " << (recursive ? "yes" : "no") << ")");
                    std::string transfer_id = client.request_directory(peer_hash, remote_path, local_path, recursive);
                    if (!transfer_id.empty()) {
                        LOG_MAIN_INFO("Directory request initiated with ID: " << transfer_id);
                    } else {
                        LOG_MAIN_ERROR("Failed to initiate directory request");
                    }
                }
            } else {
                std::cout << "Usage: dir_request <peer_hash> <remote_path> <local_path> [recursive]" << std::endl;
            }
        }
        else if (command == "transfer_list") {
            if (!client.is_file_transfer_available()) {
                LOG_MAIN_ERROR("File transfer not available");
            } else {
                auto active_transfers = client.get_active_file_transfers();
                if (active_transfers.empty()) {
                    std::cout << "No active file transfers." << std::endl;
                } else {
                    std::cout << "Active file transfers:" << std::endl;
                    for (const auto& transfer : active_transfers) {
                        std::cout << "  ID: " << transfer->transfer_id << std::endl;
                        std::cout << "    Peer: " << transfer->peer_id << std::endl;
                        std::cout << "    File: " << transfer->filename << std::endl;
                        std::cout << "    Direction: " << (transfer->direction == librats::FileTransferDirection::SENDING ? "SENDING" : "RECEIVING") << std::endl;
                        std::cout << "    Status: ";
                        switch (transfer->status) {
                            case librats::FileTransferStatus::PENDING: std::cout << "PENDING"; break;
                            case librats::FileTransferStatus::STARTING: std::cout << "STARTING"; break;
                            case librats::FileTransferStatus::IN_PROGRESS: std::cout << "IN_PROGRESS"; break;
                            case librats::FileTransferStatus::PAUSED: std::cout << "PAUSED"; break;
                            case librats::FileTransferStatus::COMPLETED: std::cout << "COMPLETED"; break;
                            case librats::FileTransferStatus::FAILED: std::cout << "FAILED"; break;
                            case librats::FileTransferStatus::CANCELLED: std::cout << "CANCELLED"; break;
                            case librats::FileTransferStatus::RESUMING: std::cout << "RESUMING"; break;
                        }
                        std::cout << std::endl;
                        std::cout << "    Progress: " << transfer->get_completion_percentage() << "% ("
                                 << transfer->bytes_transferred << "/" << transfer->total_bytes << " bytes)" << std::endl;
                        std::cout << "    Rate: " << (transfer->transfer_rate_bps / 1024.0) << " KB/s" << std::endl;
                        std::cout << std::endl;
                    }
                }
            }
        }
        else if (command == "transfer_status") {
            std::string transfer_id;
            iss >> transfer_id;
            if (!transfer_id.empty()) {
                if (!client.is_file_transfer_available()) {
                    LOG_MAIN_ERROR("File transfer not available");
                } else {
                    auto progress = client.get_file_transfer_progress(transfer_id);
                    if (progress) {
                        std::cout << "Transfer " << transfer_id << " status:" << std::endl;
                        std::cout << "  Peer: " << progress->peer_id << std::endl;
                        std::cout << "  File: " << progress->filename << std::endl;
                        std::cout << "  Direction: " << (progress->direction == librats::FileTransferDirection::SENDING ? "SENDING" : "RECEIVING") << std::endl;
                        std::cout << "  Status: ";
                        switch (progress->status) {
                            case librats::FileTransferStatus::PENDING: std::cout << "PENDING"; break;
                            case librats::FileTransferStatus::STARTING: std::cout << "STARTING"; break;
                            case librats::FileTransferStatus::IN_PROGRESS: std::cout << "IN_PROGRESS"; break;
                            case librats::FileTransferStatus::PAUSED: std::cout << "PAUSED"; break;
                            case librats::FileTransferStatus::COMPLETED: std::cout << "COMPLETED"; break;
                            case librats::FileTransferStatus::FAILED: std::cout << "FAILED"; break;
                            case librats::FileTransferStatus::CANCELLED: std::cout << "CANCELLED"; break;
                            case librats::FileTransferStatus::RESUMING: std::cout << "RESUMING"; break;
                        }
                        std::cout << std::endl;
                        std::cout << "  Progress: " << progress->get_completion_percentage() << "%" << std::endl;
                        std::cout << "  Bytes: " << progress->bytes_transferred << "/" << progress->total_bytes << std::endl;
                        std::cout << "  Chunks: " << progress->chunks_completed << "/" << progress->total_chunks << std::endl;
                        std::cout << "  Rate: " << (progress->transfer_rate_bps / 1024.0) << " KB/s" << std::endl;
                        std::cout << "  Average Rate: " << (progress->average_rate_bps / 1024.0) << " KB/s" << std::endl;
                        std::cout << "  Elapsed: " << progress->get_elapsed_time().count() << " ms" << std::endl;
                        if (progress->estimated_time_remaining.count() > 0) {
                            std::cout << "  ETA: " << progress->estimated_time_remaining.count() << " ms" << std::endl;
                        }
                        if (!progress->error_message.empty()) {
                            std::cout << "  Error: " << progress->error_message << std::endl;
                        }
                    } else {
                        LOG_MAIN_ERROR("Transfer " << transfer_id << " not found");
                    }
                }
            } else {
                std::cout << "Usage: transfer_status <transfer_id>" << std::endl;
            }
        }
        else if (command == "transfer_pause") {
            std::string transfer_id;
            iss >> transfer_id;
            if (!transfer_id.empty()) {
                if (!client.is_file_transfer_available()) {
                    LOG_MAIN_ERROR("File transfer not available");
                } else {
                    if (client.pause_file_transfer(transfer_id)) {
                        LOG_MAIN_INFO("Transfer " << transfer_id << " paused");
                    } else {
                        LOG_MAIN_ERROR("Failed to pause transfer " << transfer_id);
                    }
                }
            } else {
                std::cout << "Usage: transfer_pause <transfer_id>" << std::endl;
            }
        }
        else if (command == "transfer_resume") {
            std::string transfer_id;
            iss >> transfer_id;
            if (!transfer_id.empty()) {
                if (!client.is_file_transfer_available()) {
                    LOG_MAIN_ERROR("File transfer not available");
                } else {
                    if (client.resume_file_transfer(transfer_id)) {
                        LOG_MAIN_INFO("Transfer " << transfer_id << " resumed");
                    } else {
                        LOG_MAIN_ERROR("Failed to resume transfer " << transfer_id);
                    }
                }
            } else {
                std::cout << "Usage: transfer_resume <transfer_id>" << std::endl;
            }
        }
        else if (command == "transfer_cancel") {
            std::string transfer_id;
            iss >> transfer_id;
            if (!transfer_id.empty()) {
                if (!client.is_file_transfer_available()) {
                    LOG_MAIN_ERROR("File transfer not available");
                } else {
                    if (client.cancel_file_transfer(transfer_id)) {
                        LOG_MAIN_INFO("Transfer " << transfer_id << " cancelled");
                    } else {
                        LOG_MAIN_ERROR("Failed to cancel transfer " << transfer_id);
                    }
                }
            } else {
                std::cout << "Usage: transfer_cancel <transfer_id>" << std::endl;
            }
        }
        else if (command == "transfer_stats") {
            if (!client.is_file_transfer_available()) {
                LOG_MAIN_ERROR("File transfer not available");
            } else {
                auto stats = client.get_file_transfer_statistics();
                std::cout << "File Transfer Statistics:" << std::endl;
                std::cout << stats.dump(2) << std::endl;
            }
        }
#ifdef RATS_SEARCH_FEATURES
        else if (command == "bittorrent_enable") {
            int bt_port = 6881;
            iss >> bt_port;
            if (bt_port <= 0) bt_port = 6881;
            
            LOG_MAIN_INFO("Enabling BitTorrent on port " << bt_port << "...");
            if (client.enable_bittorrent(bt_port)) {
                LOG_MAIN_INFO("BitTorrent enabled successfully");
            } else {
                LOG_MAIN_ERROR("Failed to enable BitTorrent");
            }
        }
        else if (command == "bittorrent_disable") {
            if (!client.is_bittorrent_enabled()) {
                std::cout << "BitTorrent is not enabled." << std::endl;
            } else {
                LOG_MAIN_INFO("Disabling BitTorrent...");
                client.disable_bittorrent();
                LOG_MAIN_INFO("BitTorrent disabled");
            }
        }
        else if (command == "bittorrent_status") {
            if (client.is_bittorrent_enabled()) {
                size_t torrent_count = client.get_active_torrents_count();
                auto stats = client.get_bittorrent_stats();
                LOG_MAIN_INFO("BitTorrent Status: ENABLED");
                LOG_MAIN_INFO("Active torrents: " << torrent_count);
                LOG_MAIN_INFO("Total downloaded: " << (stats.first / 1024.0 / 1024.0) << " MB");
                LOG_MAIN_INFO("Total uploaded: " << (stats.second / 1024.0 / 1024.0) << " MB");
            } else {
                LOG_MAIN_INFO("BitTorrent Status: DISABLED");
            }
        }
        else if (command == "torrent_add") {
            std::string torrent_file, download_path;
            iss >> torrent_file >> download_path;
            
            if (!torrent_file.empty() && !download_path.empty()) {
                if (!client.is_bittorrent_enabled()) {
                    LOG_MAIN_ERROR("BitTorrent is not enabled. Use 'bittorrent_enable' first.");
                } else {
                    LOG_MAIN_INFO("Adding torrent: " << torrent_file);
                    auto torrent = client.add_torrent(torrent_file, download_path);
                    if (torrent) {
                        LOG_MAIN_INFO("Torrent added successfully");
                    } else {
                        LOG_MAIN_ERROR("Failed to add torrent");
                    }
                }
            } else {
                std::cout << "Usage: torrent_add <torrent_file> <download_path>" << std::endl;
            }
        }
        else if (command == "torrent_add_hash") {
            std::string hash_str, download_path;
            iss >> hash_str >> download_path;
            
            if (!hash_str.empty() && !download_path.empty()) {
                if (!client.is_bittorrent_enabled()) {
                    LOG_MAIN_ERROR("BitTorrent is not enabled. Use 'bittorrent_enable' first.");
                } else if (!client.is_dht_running()) {
                    LOG_MAIN_ERROR("DHT is not running. BitTorrent by hash requires DHT for peer discovery.");
                    LOG_MAIN_INFO("Start DHT with 'dht_start' and try again.");
                } else {
                    LOG_MAIN_INFO("Adding torrent by hash: " << hash_str);
                    LOG_MAIN_INFO("This will use DHT to discover peers and attempt to download metadata...");
                    auto torrent = client.add_torrent_by_hash(hash_str, download_path);
                    if (torrent) {
                        LOG_MAIN_INFO("Torrent added successfully (metadata received)");
                    } else {
                        LOG_MAIN_WARN("Metadata download initiated. DHT peer discovery in progress...");
                        LOG_MAIN_INFO("Note: Full metadata exchange (BEP 9) requires additional implementation.");
                        LOG_MAIN_INFO("      Once you have the .torrent file, use 'torrent_add <file> <path>'");
                    }
                }
            } else {
                std::cout << "Usage: torrent_add_hash <info_hash> <download_path>" << std::endl;
            }
        }
        else if (command == "torrent_metadata") {
            std::string hash_str;
            iss >> hash_str;
            
            if (!hash_str.empty()) {
                if (!client.is_bittorrent_enabled()) {
                    LOG_MAIN_ERROR("BitTorrent is not enabled. Use 'bittorrent_enable' first.");
                } else if (!client.is_dht_running()) {
                    LOG_MAIN_ERROR("DHT is not running. Metadata retrieval requires DHT for peer discovery.");
                    LOG_MAIN_INFO("Start DHT with 'dht_start' and try again.");
                } else {
                    LOG_MAIN_INFO("Retrieving metadata for torrent hash: " << hash_str);
                    LOG_MAIN_INFO("This will use DHT to discover peers and download metadata...");
                    
                    client.get_torrent_metadata(hash_str, 
                        [hash_str](const librats::TorrentInfo& torrent_info, bool success, const std::string& error_message) {
                            if (success) {
                                LOG_MAIN_INFO("=== Torrent Metadata Retrieved Successfully ===");
                                LOG_MAIN_INFO("Name: " << torrent_info.get_name());
                                LOG_MAIN_INFO("Info Hash: " << librats::info_hash_to_hex(torrent_info.get_info_hash()));
                                LOG_MAIN_INFO("Total Size: " << (torrent_info.get_total_length() / 1024.0 / 1024.0) << " MB");
                                LOG_MAIN_INFO("Piece Length: " << torrent_info.get_piece_length() << " bytes");
                                LOG_MAIN_INFO("Number of Pieces: " << torrent_info.get_num_pieces());
                                LOG_MAIN_INFO("Number of Files: " << torrent_info.get_files().size());
                                LOG_MAIN_INFO("Private: " << (torrent_info.is_private() ? "yes" : "no"));
                                
                                const auto& files = torrent_info.get_files();
                                if (files.size() == 1) {
                                    LOG_MAIN_INFO("Single file torrent");
                                } else {
                                    std::cout << "\nFiles in torrent:" << std::endl;
                                    for (const auto& file : files) {
                                        std::cout << "  - " << file.path << " (" << (file.length / 1024.0 / 1024.0) << " MB)" << std::endl;
                                    }
                                }
                                
                                LOG_MAIN_INFO("\nYou can now download this torrent using:");
                                LOG_MAIN_INFO("  torrent_add_hash " << hash_str << " <download_path>");
                            } else {
                                LOG_MAIN_ERROR("Failed to retrieve metadata: " << error_message);
                            }
                        });
                    
                    LOG_MAIN_INFO("Metadata retrieval initiated. Waiting for DHT peer discovery...");
                }
            } else {
                std::cout << "Usage: torrent_metadata <info_hash>" << std::endl;
            }
        }
        else if (command == "torrent_find_peers") {
            std::string hash_str;
            iss >> hash_str;
            
            if (!hash_str.empty()) {
                if (!client.is_dht_running()) {
                    LOG_MAIN_ERROR("DHT is not running. Use 'dht_start' first.");
                } else {
                    LOG_MAIN_INFO("Finding peers for torrent hash: " << hash_str);
                    LOG_MAIN_INFO("Using DHT to discover peers...");
                    
                    try {
                        librats::InfoHash info_hash = librats::hex_to_info_hash(hash_str);
                        
                        if (client.find_peers_by_hash(hash_str, 
                            [hash_str](const std::vector<std::string>& peers) {
                                LOG_MAIN_INFO("Found " << peers.size() << " peers for torrent hash " << hash_str);
                                if (peers.empty()) {
                                    LOG_MAIN_INFO("No peers found. The torrent may not be popular or DHT may need more time.");
                                } else {
                                    std::cout << "Discovered peers:" << std::endl;
                                    for (const auto& peer : peers) {
                                        std::cout << "  " << peer << std::endl;
                                    }
                                    LOG_MAIN_INFO("Note: These peers should have the torrent. You can:");
                                    LOG_MAIN_INFO("  1. Obtain the .torrent file from one of these peers or a tracker");
                                    LOG_MAIN_INFO("  2. Use 'torrent_add <file> <path>' to start downloading");
                                }
                            })) {
                            LOG_MAIN_INFO("DHT peer search initiated");
                        } else {
                            LOG_MAIN_ERROR("Failed to initiate DHT peer search");
                        }
                    } catch (const std::exception& e) {
                        LOG_MAIN_ERROR("Invalid info hash format: " << e.what());
                    }
                }
            } else {
                std::cout << "Usage: torrent_find_peers <info_hash>" << std::endl;
            }
        }
        else if (command == "torrent_list") {
            if (!client.is_bittorrent_enabled()) {
                LOG_MAIN_ERROR("BitTorrent is not enabled");
            } else {
                auto torrents = client.get_all_torrents();
                if (torrents.empty()) {
                    std::cout << "No active torrents." << std::endl;
                } else {
                    std::cout << "Active torrents:" << std::endl;
                    for (const auto& torrent : torrents) {
                        const auto& info = torrent->get_torrent_info();
                        std::cout << "  Info Hash: " << librats::info_hash_to_hex(info.get_info_hash()) << std::endl;
                        std::cout << "    Name: " << info.get_name() << std::endl;
                        std::cout << "    Size: " << (info.get_total_length() / 1024.0 / 1024.0) << " MB" << std::endl;
                        std::cout << "    Downloaded: " << (torrent->get_downloaded_bytes() / 1024.0 / 1024.0) << " MB" << std::endl;
                        std::cout << "    Uploaded: " << (torrent->get_uploaded_bytes() / 1024.0 / 1024.0) << " MB" << std::endl;
                        std::cout << "    Progress: " << torrent->get_progress_percentage() << "%" << std::endl;
                        std::cout << "    Peers: " << torrent->get_peer_count() << std::endl;
                        std::cout << "    Status: ";
                        if (torrent->is_complete()) {
                            std::cout << "COMPLETE";
                        } else if (torrent->is_paused()) {
                            std::cout << "PAUSED";
                        } else if (torrent->is_running()) {
                            std::cout << "DOWNLOADING";
                        } else {
                            std::cout << "STOPPED";
                        }
                        std::cout << std::endl << std::endl;
                    }
                }
            }
        }
        else if (command == "torrent_remove") {
            std::string hash_str;
            iss >> hash_str;
            
            if (!hash_str.empty()) {
                if (!client.is_bittorrent_enabled()) {
                    LOG_MAIN_ERROR("BitTorrent is not enabled");
                } else {
                    try {
                        librats::InfoHash info_hash = librats::hex_to_info_hash(hash_str);
                        if (client.remove_torrent(info_hash)) {
                            LOG_MAIN_INFO("Torrent removed successfully");
                        } else {
                            LOG_MAIN_ERROR("Failed to remove torrent (not found or error)");
                        }
                    } catch (const std::exception& e) {
                        LOG_MAIN_ERROR("Invalid info hash format: " << e.what());
                    }
                }
            } else {
                std::cout << "Usage: torrent_remove <info_hash>" << std::endl;
            }
        }
        else if (command == "torrent_info") {
            std::string hash_str;
            iss >> hash_str;
            
            if (!hash_str.empty()) {
                if (!client.is_bittorrent_enabled()) {
                    LOG_MAIN_ERROR("BitTorrent is not enabled");
                } else {
                    try {
                        librats::InfoHash info_hash = librats::hex_to_info_hash(hash_str);
                        auto torrent = client.get_torrent(info_hash);
                        if (torrent) {
                            const auto& info = torrent->get_torrent_info();
                            std::cout << "Torrent Information:" << std::endl;
                            std::cout << "  Info Hash: " << librats::info_hash_to_hex(info.get_info_hash()) << std::endl;
                            std::cout << "  Name: " << info.get_name() << std::endl;
                            std::cout << "  Total Size: " << (info.get_total_length() / 1024.0 / 1024.0) << " MB" << std::endl;
                            std::cout << "  Piece Length: " << info.get_piece_length() << " bytes" << std::endl;
                            std::cout << "  Piece Count: " << info.get_num_pieces() << std::endl;
                            std::cout << "  Downloaded: " << (torrent->get_downloaded_bytes() / 1024.0 / 1024.0) << " MB" << std::endl;
                            std::cout << "  Uploaded: " << (torrent->get_uploaded_bytes() / 1024.0 / 1024.0) << " MB" << std::endl;
                            std::cout << "  Progress: " << torrent->get_progress_percentage() << "%" << std::endl;
                            std::cout << "  Completed Pieces: " << torrent->get_completed_pieces() << "/" << info.get_num_pieces() << std::endl;
                            std::cout << "  Connected Peers: " << torrent->get_peer_count() << std::endl;
                            std::cout << "  Status: ";
                            if (torrent->is_complete()) {
                                std::cout << "COMPLETE";
                            } else if (torrent->is_paused()) {
                                std::cout << "PAUSED";
                            } else if (torrent->is_running()) {
                                std::cout << "DOWNLOADING";
                            } else {
                                std::cout << "STOPPED";
                            }
                            std::cout << std::endl;
                            
                            // Show file list
                            const auto& files = info.get_files();
                            if (files.size() > 1) {
                                std::cout << "  Files:" << std::endl;
                                for (const auto& file : files) {
                                    std::cout << "    - " << file.path << " (" << (file.length / 1024.0 / 1024.0) << " MB)" << std::endl;
                                }
                            }
                        } else {
                            LOG_MAIN_ERROR("Torrent not found");
                        }
                    } catch (const std::exception& e) {
                        LOG_MAIN_ERROR("Invalid info hash format: " << e.what());
                    }
                }
            } else {
                std::cout << "Usage: torrent_info <info_hash>" << std::endl;
            }
        }
        else if (command == "torrent_pause") {
            std::string hash_str;
            iss >> hash_str;
            
            if (!hash_str.empty()) {
                if (!client.is_bittorrent_enabled()) {
                    LOG_MAIN_ERROR("BitTorrent is not enabled");
                } else {
                    try {
                        librats::InfoHash info_hash = librats::hex_to_info_hash(hash_str);
                        auto torrent = client.get_torrent(info_hash);
                        if (torrent) {
                            torrent->pause();
                            LOG_MAIN_INFO("Torrent paused");
                        } else {
                            LOG_MAIN_ERROR("Torrent not found");
                        }
                    } catch (const std::exception& e) {
                        LOG_MAIN_ERROR("Invalid info hash format: " << e.what());
                    }
                }
            } else {
                std::cout << "Usage: torrent_pause <info_hash>" << std::endl;
            }
        }
        else if (command == "torrent_resume") {
            std::string hash_str;
            iss >> hash_str;
            
            if (!hash_str.empty()) {
                if (!client.is_bittorrent_enabled()) {
                    LOG_MAIN_ERROR("BitTorrent is not enabled");
                } else {
                    try {
                        librats::InfoHash info_hash = librats::hex_to_info_hash(hash_str);
                        auto torrent = client.get_torrent(info_hash);
                        if (torrent) {
                            torrent->resume();
                            LOG_MAIN_INFO("Torrent resumed");
                        } else {
                            LOG_MAIN_ERROR("Torrent not found");
                        }
                    } catch (const std::exception& e) {
                        LOG_MAIN_ERROR("Invalid info hash format: " << e.what());
                    }
                }
            } else {
                std::cout << "Usage: torrent_resume <info_hash>" << std::endl;
            }
        }
        else if (command == "torrent_peers") {
            std::string hash_str;
            iss >> hash_str;
            
            if (!hash_str.empty()) {
                if (!client.is_bittorrent_enabled()) {
                    LOG_MAIN_ERROR("BitTorrent is not enabled");
                } else {
                    try {
                        librats::InfoHash info_hash = librats::hex_to_info_hash(hash_str);
                        auto torrent = client.get_torrent(info_hash);
                        if (torrent) {
                            auto peers = torrent->get_connected_peers();
                            if (peers.empty()) {
                                std::cout << "No connected peers for this torrent." << std::endl;
                            } else {
                                std::cout << "Connected peers (" << peers.size() << "):" << std::endl;
                                for (const auto& peer : peers) {
                                    std::cout << "  " << peer.ip << ":" << peer.port << std::endl;
                                }
                            }
                        } else {
                            LOG_MAIN_ERROR("Torrent not found");
                        }
                    } catch (const std::exception& e) {
                        LOG_MAIN_ERROR("Invalid info hash format: " << e.what());
                    }
                }
            } else {
                std::cout << "Usage: torrent_peers <info_hash>" << std::endl;
            }
        }
        else if (command == "bittorrent_stats") {
            if (!client.is_bittorrent_enabled()) {
                LOG_MAIN_ERROR("BitTorrent is not enabled");
            } else {
                auto stats = client.get_bittorrent_stats();
                size_t torrent_count = client.get_active_torrents_count();
                
                std::cout << "BitTorrent Statistics:" << std::endl;
                std::cout << "  Active Torrents: " << torrent_count << std::endl;
                std::cout << "  Total Downloaded: " << (stats.first / 1024.0 / 1024.0) << " MB" << std::endl;
                std::cout << "  Total Uploaded: " << (stats.second / 1024.0 / 1024.0) << " MB" << std::endl;
                std::cout << "  Share Ratio: " << (stats.first > 0 ? (double)stats.second / stats.first : 0.0) << std::endl;
            }
        }
#endif // RATS_SEARCH_FEATURES
#ifdef RATS_STORAGE
        else if (command == "storage_put") {
            std::string key, value;
            iss >> key;
            std::getline(iss, value);
            if (!value.empty()) {
                value = value.substr(1); // Remove leading space
            }
            
            if (!key.empty() && !value.empty()) {
                if (!client.is_storage_available()) {
                    LOG_MAIN_ERROR("Storage is not available");
                } else {
                    if (client.storage_put(key, value)) {
                        LOG_MAIN_INFO("Stored key '" << key << "' with value '" << value << "'");
                    } else {
                        LOG_MAIN_ERROR("Failed to store key '" << key << "'");
                    }
                }
            } else {
                std::cout << "Usage: storage_put <key> <value>" << std::endl;
            }
        }
        else if (command == "storage_get") {
            std::string key;
            iss >> key;
            
            if (!key.empty()) {
                if (!client.is_storage_available()) {
                    LOG_MAIN_ERROR("Storage is not available");
                } else {
                    auto value = client.storage_get_string(key);
                    if (value) {
                        std::cout << "Value: " << *value << std::endl;
                    } else {
                        // Try JSON in case it's stored as JSON
                        auto json_value = client.storage_get_json(key);
                        if (json_value) {
                            std::cout << "Value (JSON): " << json_value->dump(2) << std::endl;
                        } else {
                            // Try int
                            auto int_value = client.storage_get_int(key);
                            if (int_value) {
                                std::cout << "Value (int): " << *int_value << std::endl;
                            } else {
                                // Try double
                                auto double_value = client.storage_get_double(key);
                                if (double_value) {
                                    std::cout << "Value (double): " << *double_value << std::endl;
                                } else {
                                    LOG_MAIN_ERROR("Key '" << key << "' not found or has unsupported type");
                                }
                            }
                        }
                    }
                }
            } else {
                std::cout << "Usage: storage_get <key>" << std::endl;
            }
        }
        else if (command == "storage_delete") {
            std::string key;
            iss >> key;
            
            if (!key.empty()) {
                if (!client.is_storage_available()) {
                    LOG_MAIN_ERROR("Storage is not available");
                } else {
                    if (client.storage_delete(key)) {
                        LOG_MAIN_INFO("Deleted key '" << key << "'");
                    } else {
                        LOG_MAIN_ERROR("Key '" << key << "' not found");
                    }
                }
            } else {
                std::cout << "Usage: storage_delete <key>" << std::endl;
            }
        }
        else if (command == "storage_has") {
            std::string key;
            iss >> key;
            
            if (!key.empty()) {
                if (!client.is_storage_available()) {
                    LOG_MAIN_ERROR("Storage is not available");
                } else {
                    bool exists = client.storage_has(key);
                    std::cout << "Key '" << key << "': " << (exists ? "exists" : "does not exist") << std::endl;
                }
            } else {
                std::cout << "Usage: storage_has <key>" << std::endl;
            }
        }
        else if (command == "storage_list") {
            std::string prefix;
            iss >> prefix;
            
            if (!client.is_storage_available()) {
                LOG_MAIN_ERROR("Storage is not available");
            } else {
                std::vector<std::string> keys;
                if (prefix.empty()) {
                    keys = client.storage_keys();
                } else {
                    keys = client.storage_keys_with_prefix(prefix);
                }
                
                if (keys.empty()) {
                    std::cout << "No keys found" << (prefix.empty() ? "" : " with prefix '" + prefix + "'") << std::endl;
                } else {
                    std::cout << "Keys (" << keys.size() << "):" << std::endl;
                    for (const auto& key : keys) {
                        std::cout << "  " << key << std::endl;
                    }
                }
            }
        }
        else if (command == "storage_stats") {
            if (!client.is_storage_available()) {
                LOG_MAIN_ERROR("Storage is not available");
            } else {
                auto stats = client.get_storage_statistics();
                std::cout << "Storage Statistics:" << std::endl;
                std::cout << stats.dump(2) << std::endl;
            }
        }
        else if (command == "storage_sync") {
            if (!client.is_storage_available()) {
                LOG_MAIN_ERROR("Storage is not available");
            } else {
                if (client.storage_request_sync()) {
                    LOG_MAIN_INFO("Storage sync request sent to peers");
                } else {
                    LOG_MAIN_ERROR("Failed to send storage sync request");
                }
            }
        }
        else if (command == "storage_status") {
            if (!client.is_storage_available()) {
                LOG_MAIN_ERROR("Storage is not available");
            } else {
                bool synced = client.is_storage_synced();
                size_t count = client.storage_size();
                LOG_MAIN_INFO("Storage Status:");
                LOG_MAIN_INFO("  Synced: " << (synced ? "yes" : "no"));
                LOG_MAIN_INFO("  Entries: " << count);
            }
        }
        else if (command == "storage_clear") {
            if (!client.is_storage_available()) {
                LOG_MAIN_ERROR("Storage is not available");
            } else {
                std::cout << "Are you sure you want to clear all storage? (yes/no): ";
                std::string confirm;
                std::getline(std::cin, confirm);
                if (confirm == "yes") {
                    client.get_storage_manager().clear();
                    LOG_MAIN_INFO("Storage cleared");
                } else {
                    std::cout << "Operation cancelled." << std::endl;
                }
            }
        }
#endif // RATS_STORAGE
        else {
            std::cout << "Unknown command: " << command << std::endl;
            std::cout << "Type 'help' for available commands." << std::endl;
        }
        
        // Always show prompt after each command
        std::cout << "rats> ";
        std::cout.flush();
    }
    
    // Clean shutdown
    LOG_MAIN_INFO("Stopping DHT peer discovery...");
    client.stop_dht_discovery();
    
    LOG_MAIN_INFO("Stopping mDNS local network discovery...");
    client.stop_mdns_discovery();
    
    client.stop();
    LOG_MAIN_INFO("RatsClient stopped. Goodbye!");
    
    return 0;
} 