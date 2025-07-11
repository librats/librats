# LibRats - TCP Network Library

A simple C++ library for TCP networking with cross-platform support (Windows and Unix-like systems). Features both low-level socket operations and high-level RatsClient functionality for peer-to-peer communication.

## Features

- **TCP Client**: Connect to remote servers
- **TCP Server**: Accept client connections and handle communication  
- **RatsClient**: Run both client and server simultaneously for peer-to-peer communication
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
│   └── librats.cpp         # High-level RatsClient implementation
├── example.cpp             # Example usage
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
- Example executable: `build/bin/example` (or `example.exe` on Windows)

## Usage

### High-Level RatsClient API (Recommended)

The RatsClient class provides peer-to-peer functionality where each instance can both accept incoming connections and connect to other peers.

```cpp
#include "src/librats.h"
using namespace librats;

// Initialize networking
init_networking();

// Create a RatsClient that listens on port 8080
RatsClient client(8080);

// Set up callbacks
client.set_connection_callback([](socket_t socket, const std::string& info) {
    std::cout << "New peer connected: " << info << std::endl;
});

client.set_data_callback([&client](socket_t socket, const std::string& data) {
    std::cout << "Received: " << data << std::endl;
    client.send_to_peer(socket, "Echo: " + data);
});

// Start the client (begins listening)
client.start();

// Connect to another peer
client.connect_to_peer("127.0.0.1", 8081);

// Send data to all peers
client.broadcast_to_peers("Hello everyone!");

// Cleanup
client.stop();
cleanup_networking();
```

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

### Running the Example

The example provides multiple modes:

1. **Single RatsClient**: Run as listener only
2. **RatsClient with peer**: Connect to another peer
3. **Helper function demo**: Use convenience functions
4. **Dual RatsClients**: Run two clients simultaneously

```bash
# Run the example
./build/bin/example

# Follow the prompts to choose mode (1-4)
```

## RatsClient API Reference

### RatsClient Class
- `RatsClient(int listen_port)`: Constructor
- `bool start()`: Start listening for connections
- `void stop()`: Stop the client and close all connections
- `bool connect_to_peer(const std::string& host, int port)`: Connect to another peer
- `bool send_to_peer(socket_t socket, const std::string& data)`: Send data to specific peer
- `int broadcast_to_peers(const std::string& data)`: Send data to all peers
- `void disconnect_peer(socket_t socket)`: Disconnect from specific peer
- `int get_peer_count()`: Get number of connected peers
- `bool is_running()`: Check if client is running

### Callback Functions
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

All threading is handled internally with proper synchronization.

## License

This project is provided as-is for educational purposes. 