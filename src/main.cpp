#include "librats.h"
#include "network_utils.h"
#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <sstream>
#include <algorithm>

// Main module logging macros
#define LOG_MAIN_DEBUG(message) LOG_DEBUG("main", message)
#define LOG_MAIN_INFO(message)  LOG_INFO("main", message)
#define LOG_MAIN_WARN(message)  LOG_WARN("main", message)
#define LOG_MAIN_ERROR(message) LOG_ERROR("main", message)

void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " <listen_port> [peer_host] [peer_port]\n";
    std::cout << "  listen_port: Port to listen on for incoming connections\n";
    std::cout << "  peer_host:   Optional hostname/IP to connect to as peer\n";
    std::cout << "  peer_port:   Optional port of peer to connect to\n";
    std::cout << "\nExample:\n";
    std::cout << "  " << program_name << " 8080              # Listen on port 8080\n";
    std::cout << "  " << program_name << " 8081 localhost 8080  # Listen on 8081 and connect to 8080\n";
}

void print_help() {
    std::cout << "Available commands:" << std::endl;
    std::cout << "  help              - Show this help message" << std::endl;
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
    std::cout << "  netutils [hostname] - Test network utilities" << std::endl;
    std::cout << "  netutils6 [hostname] - Test IPv6 network utilities" << std::endl;
    std::cout << "  dht_test <ip> <port> - Test DHT protocol with specific peer" << std::endl;
    std::cout << "  test_ipv6 <host> <port> - Test IPv6 connectivity" << std::endl;
    std::cout << "  quit              - Exit the program" << std::endl;
}

int main(int argc, char* argv[]) {
    // Enable debug level logging
    librats::Logger::getInstance().set_log_level(librats::LogLevel::DEBUG);
    
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    int listen_port = std::stoi(argv[1]);
    std::string peer_host = "";
    int peer_port = 0;
    
    if (argc >= 4) {
        peer_host = argv[2];
        peer_port = std::stoi(argv[3]);
    }
    
    LOG_MAIN_INFO("=== RatsClient Demo ===");
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
    
    client.set_data_callback([](socket_t socket, const std::string& peer_hash_id, const std::string& data) {
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
    print_help();
    
    // Add initial prompt
    std::cout << "\nType your command: ";
    std::cout.flush();
    
    // Main command loop
    std::string input;
    while (client.is_running()) {
        std::getline(std::cin, input);
        
        if (input.empty()) {
            std::cout << "Type your command: ";
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
                int sent = client.broadcast_to_peers(message);
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
                if (client.send_to_peer_by_hash(hash_id, message)) {
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
        else if (command == "connect6") {
            std::string host;
            int port;
            iss >> host >> port;
            if (!host.empty() && port > 0) {
                LOG_MAIN_INFO("Connecting to " << host << ":" << port << " using IPv6...");
                
                // Test IPv6 connection using low-level API
                socket_t test_socket = librats::create_tcp_client_v6(host, port);
                if (test_socket != INVALID_SOCKET_VALUE) {
                    LOG_MAIN_INFO("IPv6 connection successful!");
                    librats::close_socket(test_socket);
                    
                    // Now try to connect using the high-level client
                    if (client.connect_to_peer(host, port)) {
                        LOG_MAIN_INFO("RatsClient connected successfully!");
                    } else {
                        LOG_MAIN_ERROR("Failed to connect RatsClient");
                    }
                } else {
                    LOG_MAIN_ERROR("Failed to connect using IPv6");
                }
            } else {
                std::cout << "Usage: connect6 <host> <port>" << std::endl;
            }
        }
        else if (command == "connect_dual") {
            std::string host;
            int port;
            iss >> host >> port;
            if (!host.empty() && port > 0) {
                LOG_MAIN_INFO("Connecting to " << host << ":" << port << " using dual stack...");
                
                // Test dual stack connection using low-level API
                socket_t test_socket = librats::create_tcp_client_dual(host, port);
                if (test_socket != INVALID_SOCKET_VALUE) {
                    LOG_MAIN_INFO("Dual stack connection successful!");
                    librats::close_socket(test_socket);
                    
                    // Now try to connect using the high-level client
                    if (client.connect_to_peer(host, port)) {
                        LOG_MAIN_INFO("RatsClient connected successfully!");
                    } else {
                        LOG_MAIN_ERROR("Failed to connect RatsClient");
                    }
                } else {
                    LOG_MAIN_ERROR("Failed to connect using dual stack");
                }
            } else {
                std::cout << "Usage: connect_dual <host> <port>" << std::endl;
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
        else if (command == "netutils") {
            std::string hostname;
            iss >> hostname;
            if (hostname.empty()) {
                librats::network_utils::demo_network_utils();
            } else {
                librats::network_utils::demo_network_utils(hostname);
            }
        }
        else if (command == "netutils6") {
            std::string hostname;
            iss >> hostname;
            if (hostname.empty()) {
                hostname = "google.com";
            }
            
            LOG_MAIN_INFO("=== IPv6 Network Utils Test ===");
            LOG_MAIN_INFO("Testing IPv6 functionality with: " << hostname);
            
            // Test IPv6 validation
            std::string test_ipv6 = "2001:db8::1";
            LOG_MAIN_INFO("'" << test_ipv6 << "' is valid IPv6: " << (librats::network_utils::is_valid_ipv6(test_ipv6) ? "yes" : "no"));
            
            // Test IPv6 hostname resolution
            std::string resolved_ipv6 = librats::network_utils::resolve_hostname_v6(hostname);
            if (!resolved_ipv6.empty()) {
                LOG_MAIN_INFO("Resolved '" << hostname << "' to IPv6: " << resolved_ipv6);
            } else {
                LOG_MAIN_ERROR("Failed to resolve '" << hostname << "' to IPv6");
            }
            
            // Test getting all IPv6 addresses
            auto all_ipv6_addresses = librats::network_utils::resolve_all_addresses_v6(hostname);
            LOG_MAIN_INFO("Found " << all_ipv6_addresses.size() << " IPv6 addresses:");
            for (size_t i = 0; i < all_ipv6_addresses.size(); ++i) {
                LOG_MAIN_INFO("  [" << i << "] " << all_ipv6_addresses[i]);
            }
            
            // Test dual stack resolution
            auto dual_addresses = librats::network_utils::resolve_all_addresses_dual(hostname);
            LOG_MAIN_INFO("Found " << dual_addresses.size() << " addresses (dual stack):");
            for (size_t i = 0; i < dual_addresses.size(); ++i) {
                LOG_MAIN_INFO("  [" << i << "] " << dual_addresses[i]);
            }
            
            LOG_MAIN_INFO("=== IPv6 Test Complete ===");
        }
        else if (command == "test_ipv6") {
            std::string host;
            int port;
            iss >> host >> port;
            if (!host.empty() && port > 0) {
                LOG_MAIN_INFO("=== IPv6 Connectivity Test ===");
                LOG_MAIN_INFO("Testing IPv6 connectivity to " << host << ":" << port);
                
                // Test IPv6 TCP client
                LOG_MAIN_INFO("Testing IPv6 TCP client...");
                socket_t tcp_socket = librats::create_tcp_client_v6(host, port);
                if (tcp_socket != INVALID_SOCKET_VALUE) {
                    LOG_MAIN_INFO("IPv6 TCP connection successful!");
                    librats::close_socket(tcp_socket);
                } else {
                    LOG_MAIN_ERROR("IPv6 TCP connection failed");
                }
                
                // Test dual stack TCP client
                LOG_MAIN_INFO("Testing dual stack TCP client...");
                socket_t dual_socket = librats::create_tcp_client_dual(host, port);
                if (dual_socket != INVALID_SOCKET_VALUE) {
                    LOG_MAIN_INFO("Dual stack TCP connection successful!");
                    librats::close_socket(dual_socket);
                } else {
                    LOG_MAIN_ERROR("Dual stack TCP connection failed");
                }
                
                // Test IPv6 UDP socket
                LOG_MAIN_INFO("Testing IPv6 UDP socket...");
                udp_socket_t udp_socket = librats::create_udp_socket_v6(0);
                if (librats::is_valid_udp_socket(udp_socket)) {
                    LOG_MAIN_INFO("IPv6 UDP socket creation successful!");
                    librats::close_udp_socket(udp_socket);
                } else {
                    LOG_MAIN_ERROR("IPv6 UDP socket creation failed");
                }
                
                // Test dual stack UDP socket
                LOG_MAIN_INFO("Testing dual stack UDP socket...");
                udp_socket_t dual_udp_socket = librats::create_udp_socket_dual(0);
                if (librats::is_valid_udp_socket(dual_udp_socket)) {
                    LOG_MAIN_INFO("Dual stack UDP socket creation successful!");
                    librats::close_udp_socket(dual_udp_socket);
                } else {
                    LOG_MAIN_ERROR("Dual stack UDP socket creation failed");
                }
                
                LOG_MAIN_INFO("=== IPv6 Test Complete ===");
            } else {
                std::cout << "Usage: test_ipv6 <host> <port>" << std::endl;
            }
        }
        else if (command == "dht_test") {
            std::string target_ip;
            int target_port;
            iss >> target_ip >> target_port;
            if (!target_ip.empty() && target_port > 0) {
                LOG_MAIN_INFO("Testing DHT protocol with " << target_ip << ":" << target_port);
                
                // Create test DHT client
                librats::DhtClient test_dht(8882);  // Use different port for testing
                if (test_dht.start()) {
                    LOG_MAIN_INFO("Test DHT started on port 8882");
                    
                    // Test bootstrap with the target
                    std::vector<librats::UdpPeer> test_nodes = {{target_ip, static_cast<uint16_t>(target_port)}};
                    test_dht.bootstrap(test_nodes);
                    
                    // Wait a bit for responses
                    std::this_thread::sleep_for(std::chrono::seconds(2));
                    
                    LOG_MAIN_INFO("Test DHT routing table size: " << test_dht.get_routing_table_size());
                    test_dht.stop();
                } else {
                    LOG_MAIN_ERROR("Failed to start test DHT");
                }
            } else {
                std::cout << "Usage: dht_test <ip> <port>" << std::endl;
            }
        }
        else {
            std::cout << "Unknown command: " << command << std::endl;
            std::cout << "Type 'help' for available commands." << std::endl;
        }
        
        // Always show prompt after each command
        std::cout << "Type your command: ";
        std::cout.flush();
    }
    
    // Clean shutdown
    LOG_MAIN_INFO("Stopping DHT peer discovery...");
    client.stop_dht_discovery();
    
    client.stop();
    LOG_MAIN_INFO("RatsClient stopped. Goodbye!");
    
    return 0;
} 