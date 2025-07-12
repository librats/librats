# LibRats - TCP Network Library

A simple C++ library for TCP networking with cross-platform support (Windows and Unix-like systems). Features both low-level socket operations and high-level RatsClient functionality for peer-to-peer communication with unique hash ID system.

## Features

- **TCP Client**: Connect to remote servers
- **TCP Server**: Accept client connections and handle communication  
- **RatsClient**: Run both client and server simultaneously for peer-to-peer communication
- **Unique Peer IDs**: Each peer gets a unique hash ID for identification
- **Cross-platform**: Works on Windows and Unix-like systems
- **Thread-safe**: Multi-threaded design with proper synchronization
- **Simple API**: Easy-to-use functions for network operations

## Project Structure

```
librats/
├── CMakeLists.txt          # Main CMake configuration
├── src/
│   ├── network.h           # Low-level networking header
│   ├── network.cpp         # Low-level networking implementation
│   ├── librats.h           # High-level RatsClient header
│   ├── librats.cpp         # High-level RatsClient implementation
│   ├── main.cpp            # Main executable with CLI interface
│   └── logger.h            # Logging utilities
└── README.md              # This file
```

## Building the Project

### Prerequisites
- CMake 3.10 or higher
- C++17 compatible compiler (GCC, Clang, MSVC)

### Build Steps

1. **Create build directory:**
   ```bash
   mkdir build
   cd build
   ```

2. **Configure with CMake:**
   ```bash
   cmake ..
   ```

3. **Build the project:**
   ```bash
   cmake --build .
   ```

### Output
- Library: `build/lib/librats.a` (or `.lib` on Windows)
- Main executable: `build/bin/librats` (or `librats.exe` on Windows)

## Usage

### High-Level RatsClient API (Recommended)

The RatsClient class provides peer-to-peer functionality where each instance can both accept incoming connections and connect to other peers. Each peer is assigned a unique hash ID for identification.

```cpp
#include "src/librats.h"
using namespace librats;

// Initialize networking
init_networking();

// Create a RatsClient that listens on port 8080
RatsClient client(8080);

// Set up callbacks with hash ID support
client.set_connection_callback([](socket_t socket, const std::string& peer_hash_id) {
    std::cout << "New peer connected: " << peer_hash_id << " (socket: " << socket << ")" << std::endl;
});

client.set_data_callback([&client](socket_t socket, const std::string& peer_hash_id, const std::string& data) {
    std::cout << "Received from peer " << peer_hash_id << ": " << data << std::endl;
    client.send_to_peer(socket, "Echo: " + data);
});

client.set_disconnect_callback([](socket_t socket, const std::string& peer_hash_id) {
    std::cout << "Peer disconnected: " << peer_hash_id << std::endl;
});

// Start the client (begins listening)
client.start();

// Connect to another peer
client.connect_to_peer("127.0.0.1", 8081);

// Send data to all peers
client.broadcast_to_peers("Hello everyone!");

// Send data to specific peer by hash ID
std::string target_hash = "1a2b3c4d5e6f7890_12345_987654321_a1b2c3d4e5f6a7b8";
client.send_to_peer_by_hash(target_hash, "Direct message");

// Get peer information
std::string hash_id = client.get_peer_hash_id(socket);
socket_t peer_socket = client.get_peer_socket(hash_id);

// Cleanup
client.stop();
cleanup_networking();
```

### Peer Hash ID System

Each peer connection is assigned a unique hash ID that consists of:
- High-resolution timestamp (nanoseconds)
- Socket handle
- Connection information hash
- Random 8-byte component

Example hash ID format: `1a2b3c4d5e6f7890_12345_987654321_a1b2c3d4e5f6a7b8`

### Helper Functions

For simple use cases, use the helper functions:

```cpp
// Run a basic demo
run_rats_client_demo(8080);

// Run demo and connect to peer
run_rats_client_demo(8081, "127.0.0.1", 8080);

// Create and start a client
auto client = create_rats_client(8080);
```

### Low-Level Socket API

For direct socket control, use the low-level API:

```cpp
#include "src/network.h"
using namespace librats;

// Initialize networking (required on Windows)
init_networking();

// Create TCP server
socket_t server = create_tcp_server(8080);
socket_t client = accept_client(server);

// Create TCP client
socket_t client_socket = create_tcp_client("127.0.0.1", 8080);

// Send/receive data
send_data(socket, "Hello World!");
std::string data = receive_data(socket);

// Cleanup
close_socket(socket);
cleanup_networking();
```

### Running the Main Program

The main program provides an interactive CLI interface:

```bash
# Run with port only (listen mode)
./build/bin/librats 8080

# Run and connect to peer
./build/bin/librats 8081 localhost 8080
```

#### Available Commands:
- `help` - Show available commands
- `peers` - Show number of connected peers
- `list` - List all connected peers with their hash IDs
- `broadcast <message>` - Send message to all peers
- `send <hash_id> <message>` - Send message to specific peer
- `connect <host> <port>` - Connect to a new peer
- `quit` - Exit the program

## RatsClient API Reference

### RatsClient Class
- `RatsClient(int listen_port)`: Constructor
- `bool start()`: Start listening for connections
- `void stop()`: Stop the client and close all connections
- `bool connect_to_peer(const std::string& host, int port)`: Connect to another peer
- `bool send_to_peer(socket_t socket, const std::string& data)`: Send data to specific peer
- `bool send_to_peer_by_hash(const std::string& peer_hash_id, const std::string& data)`: Send data using hash ID
- `int broadcast_to_peers(const std::string& data)`: Send data to all peers
- `void disconnect_peer(socket_t socket)`: Disconnect from specific peer
- `void disconnect_peer_by_hash(const std::string& peer_hash_id)`: Disconnect using hash ID
- `int get_peer_count()`: Get number of connected peers
- `bool is_running()`: Check if client is running
- `std::string get_peer_hash_id(socket_t socket)`: Get hash ID for socket
- `socket_t get_peer_socket(const std::string& peer_hash_id)`: Get socket for hash ID

### Callback Functions
- `ConnectionCallback`: `void(socket_t socket, const std::string& peer_hash_id)`
- `DataCallback`: `void(socket_t socket, const std::string& peer_hash_id, const std::string& data)`
- `DisconnectCallback`: `void(socket_t socket, const std::string& peer_hash_id)`

### Callback Setters
- `set_connection_callback(ConnectionCallback)`: Called when new peer connects
- `set_data_callback(DataCallback)`: Called when data is received
- `set_disconnect_callback(DisconnectCallback)`: Called when peer disconnects

### Helper Functions
- `std::unique_ptr<RatsClient> create_rats_client(int listen_port)`: Create and start client
- `void run_rats_client_demo(int listen_port, const std::string& peer_host = "", int peer_port = 0)`: Run demo

## Low-Level API Reference

### Initialization
- `bool init_networking()`: Initialize networking (required on Windows)
- `void cleanup_networking()`: Cleanup networking resources

### TCP Server Functions
- `socket_t create_tcp_server(int port, int backlog = 5)`: Create and bind TCP server
- `socket_t accept_client(socket_t server_socket)`: Accept client connection

### TCP Client Functions
- `socket_t create_tcp_client(const std::string& host, int port)`: Connect to TCP server

### Data Transfer
- `int send_data(socket_t socket, const std::string& data)`: Send data through socket
- `std::string receive_data(socket_t socket, size_t buffer_size = 1024)`: Receive data from socket

### Socket Management
- `void close_socket(socket_t socket)`: Close socket
- `bool is_valid_socket(socket_t socket)`: Check if socket is valid

## Example Usage Scenarios

### Scenario 1: Simple Chat Application
```cpp
RatsClient client(8080);
client.set_data_callback([&](socket_t socket, const std::string& peer_hash_id, const std::string& data) {
    std::cout << "[" << peer_hash_id.substr(0, 8) << "]: " << data << std::endl;
});
client.start();
```

### Scenario 2: Peer-to-Peer File Sharing
```cpp
RatsClient client(8080);
client.set_connection_callback([](socket_t socket, const std::string& peer_hash_id) {
    std::cout << "New peer joined: " << peer_hash_id << std::endl;
});
client.set_data_callback([&](socket_t socket, const std::string& peer_hash_id, const std::string& data) {
    if (data.starts_with("REQUEST_FILE:")) {
        std::string filename = data.substr(13);
        // Send file to specific peer
        client.send_to_peer_by_hash(peer_hash_id, "FILE_DATA:" + load_file(filename));
    }
});
```

### Scenario 3: Distributed System Node
```cpp
RatsClient node(8080);
std::set<std::string> known_peers;

node.set_connection_callback([&](socket_t socket, const std::string& peer_hash_id) {
    known_peers.insert(peer_hash_id);
    // Broadcast node list to all peers
    node.broadcast_to_peers("NODE_LIST:" + join_peers(known_peers));
});
```

## Platform Notes

### Windows
- Automatically links with `ws2_32.lib`
- Uses WinSock2 API
- Requires `init_networking()` call before use

### Unix-like Systems
- Uses standard POSIX socket API
- Links with pthread library for threading
- `init_networking()` is optional but recommended for consistency

## Threading

The RatsClient uses multiple threads:
- **Server thread**: Handles incoming connections
- **Client threads**: Handle individual peer connections
- **Main thread**: Application logic and user interaction

All threading is handled internally with proper synchronization using mutexes.

## Hash ID Benefits

- **Unique identification**: Each peer has a guaranteed unique identifier
- **Persistent tracking**: Hash IDs can be logged and tracked across sessions
- **Security**: Hash IDs don't reveal internal socket information
- **Flexibility**: Work with either socket handles or hash IDs
- **Debugging**: Easier to trace peer connections in logs

## License

This project is provided as-is for educational purposes. 