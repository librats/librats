#include "librats.h"
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
    std::cout << "\nAvailable commands:\n";
    std::cout << "  help        - Show this help message\n";
    std::cout << "  peers       - Show number of connected peers\n";
    std::cout << "  broadcast <message> - Send message to all peers\n";
    std::cout << "  connect <host> <port> - Connect to a new peer\n";
    std::cout << "  send <hash_id> <message> - Send message to specific peer by hash ID\n";
    std::cout << "  list        - List all connected peers with their hash IDs\n";
    std::cout << "  quit        - Exit the program\n";
    std::cout << "Type your command: ";
}

int main(int argc, char* argv[]) {
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
        
        std::cout << "Type your command: ";
        std::flush(std::cout);
    });
    
    client.set_data_callback([](socket_t socket, const std::string& peer_hash_id, const std::string& data) {
        LOG_MAIN_INFO("Message from peer " << peer_hash_id << ": " << data);
        std::cout << "Type your command: ";
        std::flush(std::cout);
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
        
        std::cout << "Type your command: ";
        std::flush(std::cout);
    });
    
    // Start the client
    if (!client.start()) {
        LOG_MAIN_ERROR("Failed to start RatsClient on port " << listen_port);
        return 1;
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
    print_help();
    
    // Main command loop
    std::string input;
    while (client.is_running()) {
        std::getline(std::cin, input);
        
        if (input.empty()) {
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
            std::cout << "Type your command: ";
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
            std::cout << "Type your command: ";
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
            std::cout << "Type your command: ";
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
            std::cout << "Type your command: ";
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
            std::cout << "Type your command: ";
        }
        else {
            std::cout << "Unknown command: " << command << std::endl;
            std::cout << "Type 'help' for available commands." << std::endl;
            std::cout << "Type your command: ";
        }
    }
    
    // Clean shutdown
    client.stop();
    LOG_MAIN_INFO("RatsClient stopped. Goodbye!");
    
    return 0;
} 