#include "librats.h"
#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <sstream>

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
    
    std::cout << "=== RatsClient Demo ===" << std::endl;
    std::cout << "Starting RatsClient on port " << listen_port << std::endl;
    
    // Create and configure the RatsClient
    librats::RatsClient client(listen_port);
    
    // Set up callbacks
    client.set_connection_callback([](socket_t socket, const std::string& info) {
        std::cout << "\n[CONNECTION] New peer connected: " << info << " (socket: " << socket << ")" << std::endl;
        std::cout << "Type your command: ";
        std::flush(std::cout);
    });
    
    client.set_data_callback([](socket_t socket, const std::string& data) {
        std::cout << "\n[MESSAGE] From socket " << socket << ": " << data << std::endl;
        std::cout << "Type your command: ";
        std::flush(std::cout);
    });
    
    client.set_disconnect_callback([](socket_t socket) {
        std::cout << "\n[DISCONNECT] Peer disconnected (socket: " << socket << ")" << std::endl;
        std::cout << "Type your command: ";
        std::flush(std::cout);
    });
    
    // Start the client
    if (!client.start()) {
        std::cerr << "Failed to start RatsClient on port " << listen_port << std::endl;
        return 1;
    }
    
    // Connect to peer if specified
    if (!peer_host.empty() && peer_port > 0) {
        std::cout << "Connecting to peer " << peer_host << ":" << peer_port << "..." << std::endl;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        if (client.connect_to_peer(peer_host, peer_port)) {
            std::cout << "Successfully connected to peer!" << std::endl;
        } else {
            std::cout << "Failed to connect to peer, but continuing..." << std::endl;
        }
    }
    
    std::cout << "RatsClient is running. Current peers: " << client.get_peer_count() << std::endl;
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
            std::cout << "Shutting down..." << std::endl;
            break;
        }
        else if (command == "help") {
            print_help();
        }
        else if (command == "peers") {
            std::cout << "Connected peers: " << client.get_peer_count() << std::endl;
            std::cout << "Type your command: ";
        }
        else if (command == "broadcast") {
            std::string message;
            std::getline(iss, message);
            if (!message.empty()) {
                message = message.substr(1); // Remove leading space
                int sent = client.broadcast_to_peers(message);
                std::cout << "Broadcasted message to " << sent << " peers" << std::endl;
            } else {
                std::cout << "Usage: broadcast <message>" << std::endl;
            }
            std::cout << "Type your command: ";
        }
        else if (command == "connect") {
            std::string host;
            int port;
            iss >> host >> port;
            if (!host.empty() && port > 0) {
                std::cout << "Connecting to " << host << ":" << port << "..." << std::endl;
                if (client.connect_to_peer(host, port)) {
                    std::cout << "Successfully connected!" << std::endl;
                } else {
                    std::cout << "Failed to connect to peer" << std::endl;
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
    std::cout << "RatsClient stopped. Goodbye!" << std::endl;
    
    return 0;
} 