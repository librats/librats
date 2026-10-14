# Contributing to librats 🐀

Thank you for your interest in contributing to librats! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Code Style Guidelines](#code-style-guidelines)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Reporting Issues](#reporting-issues)
- [Project Structure](#project-structure)
- [Language Bindings](#language-bindings)
- [Documentation](#documentation)

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment. We expect all contributors to:

- Be respectful and inclusive in all interactions
- Accept constructive criticism gracefully
- Focus on what's best for the community and the project
- Show empathy towards other community members

## Getting Started

### Prerequisites

Before contributing, ensure you have:

- **CMake 3.14+** installed
- **C++17 compatible compiler**:
  - GCC 7+ (Linux, MinGW)
  - Clang 5+ (macOS, Linux)
  - MSVC 2017+ (Windows)
- **Git** for version control
- **GoogleTest** (automatically downloaded during build)

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/librats.git
   cd librats
   ```
3. Add the upstream repository:
   ```bash
   git remote add upstream https://github.com/DEgITx/librats.git
   ```

## Development Setup

### Building the Project

```bash
# Create build directory
mkdir build && cd build

# Configure with tests enabled
cmake .. -DCMAKE_BUILD_TYPE=Debug -DRATS_BUILD_TESTS=ON

# Build
cmake --build . --parallel

# Run tests
ctest --output-on-failure
```

### Build Options

| Option | Default | Description |
|--------|---------|-------------|
| `RATS_BUILD_TESTS` | `ON` | Build unit tests |
| `RATS_BUILD_CLIENT` | `ON` | Build the `rats-client` reference application |
| `RATS_BUILD_EXAMPLES` | `OFF` | Build the `examples/` programs |
| `RATS_ENABLE_ASAN` | `OFF` | Enable AddressSanitizer |
| `RATS_ENABLE_TSAN` | `OFF` | Enable ThreadSanitizer (mutually exclusive with ASAN) |
| `RATS_BINDINGS` | `ON` | Enable C API bindings |
| `RATS_INSTALL` | `ON` | Generate install/export targets (`find_package(rats)`) |
| `RATS_CROSSCOMPILING` | `OFF` | Force cross-compilation flags |
| `RATS_SHARED_LIBRARY` | `OFF` | Build as shared library |
| `RATS_STATIC_LIBRARY` | `ON` | Build as static library |
| `RATS_SEARCH_FEATURES` | `OFF` | Enable BitTorrent features |
| `RATS_STORAGE` | `OFF` | Enable the distributed key-value storage subsystem |

### Debug Build with AddressSanitizer

For debugging memory issues:

```bash
cmake .. -DCMAKE_BUILD_TYPE=Debug -DRATS_ENABLE_ASAN=ON
cmake --build .
```

## Code Style Guidelines

### General Principles

1. **Consistency**: Follow the existing code style in the codebase
2. **Readability**: Write clear, self-documenting code
3. **Simplicity**: Prefer simple solutions over complex ones
4. **DRY**: Don't repeat yourself - extract common patterns

### C++ Style Guide

#### Naming Conventions

```cpp
// Classes and Structs: PascalCase
class Node { };
struct NodeConfig { };

// Functions and Methods: snake_case
bool connect(const Address& addr);
bool is_running() const;

// Variables: snake_case
int listen_port_;           // Member variables end with underscore
std::string peer_id;        // Local variables without underscore

// Constants: kCamelCase for constexpr
constexpr uint32_t kMaxBlockSize = 64u * 1024 * 1024;

// Enums: enum class with PascalCase enumerators
enum class CloseReason { LocalClose, PeerClosed, HandshakeFailed };

// Namespaces: lowercase — everything lives under librats,
// with librats::dht, librats::bittorrent, … nested inside it
namespace librats { }
```

#### Header Files

```cpp
#pragma once  // Use pragma once for header guards

#include "librats/core/address.h"  // librats includes first — always the full
#include "librats/node/config.h"    // "librats/..." path, even for a sibling
#include <system_header>            // System includes second
#include <third_party_header>       // Third-party includes last

namespace librats {

/**
 * Brief description of the class
 */
class MyClass {
public:
    // Public interface first
    MyClass();
    ~MyClass();
    
    void public_method();
    
private:
    // Private implementation
    int private_member_;
};

} // namespace librats
```

#### Documentation

Use Doxygen-style comments for public APIs:

```cpp
/**
 * Dial a peer. Non-blocking and thread-safe: the work is posted to the
 * owning reactor, and the outcome arrives via on_peer_connected().
 *
 * @param host Target host/IP address
 * @param port Target port
 */
void connect(const std::string& host, uint16_t port);
```

#### Error Handling

- Use return values for expected error conditions
- Use exceptions only for exceptional circumstances
- Always log errors with meaningful context

```cpp
if (!socket_valid) {
    LOG_ERROR("socket", "Failed to create socket: " << error_message);
    return false;
}
```

#### Thread Safety

- Document thread safety guarantees
- Use `mutable std::mutex` for const methods that need locking
- Use RAII lock guards (`std::lock_guard`, `std::unique_lock`)
- **Do not add locks to the per-connection path.** A `Connection` is owned by
  exactly one `Reactor` and touched only by that reactor's thread, so it holds
  no locks and no atomics — that shared-nothing rule is the core invariant.
  Post work to the owning reactor instead, and offload heavy work to your
  subsystem's own thread. See [ARCHITECTURE.md](ARCHITECTURE.md) for the
  threading model.
- All event callbacks (`on_peer_connected`, message handlers, …) run on a
  reactor thread — register them before `start()` and keep them non-blocking

### File Organization

- One class per file (except for closely related small classes)
- Header files in `src/librats/` with `.h` extension
- Implementation files in `src/librats/` with `.cpp` extension
- Test files in `tests/` with `test_` prefix

## Testing

### Running Tests

```bash
# Run all tests
cd build
ctest --output-on-failure

# Run specific test
./bin/librats_tests --gtest_filter=SocketTest.*

# Run with verbose output
./bin/librats_tests --gtest_filter=* --gtest_print_time=1
```

### Writing Tests

We use GoogleTest for unit testing. Place tests in `tests/test_<module>.cpp`:

```cpp
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "librats/<subdir>/your_module.h"

using namespace librats;

class YourModuleTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Setup code
    }
    
    void TearDown() override {
        // Cleanup code
    }
};

TEST_F(YourModuleTest, DescriptiveTestName) {
    // Arrange
    YourClass instance;
    
    // Act
    auto result = instance.some_method();
    
    // Assert
    EXPECT_TRUE(result);
    EXPECT_EQ(instance.get_value(), expected_value);
}
```

### Test Coverage Requirements

- All new public APIs must have tests
- Bug fixes should include regression tests
- Aim for meaningful tests, not just coverage numbers
- Test edge cases and error conditions

### Cross-Platform Testing

Tests run automatically on:
- Ubuntu (latest)
- Windows (latest)
- macOS (latest)

Ensure your changes work on all platforms by checking CI results.

## Pull Request Process

### Before Submitting

1. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Keep changes focused**: One logical change per PR

3. **Update documentation**: If you change APIs, update docs

4. **Add tests**: Cover your changes with tests

5. **Run tests locally**:
   ```bash
   cd build
   ctest --output-on-failure
   ```

6. **Check for compiler warnings**: Build with `-Wall -Wextra`

### Submitting a PR

1. **Push your branch**:
   ```bash
   git push origin feature/your-feature-name
   ```

2. **Create Pull Request** on GitHub

3. **Describe in the PR**:
   - Clear description of changes
   - Related issue numbers
   - Testing performed
   - Breaking changes (if any)

4. **Wait for CI**: All checks must pass

5. **Address review feedback**: Make requested changes

### PR Review Criteria

- [ ] Code follows style guidelines
- [ ] Tests pass on all platforms
- [ ] New features have tests
- [ ] Documentation is updated
- [ ] No unnecessary changes
- [ ] Commit messages are clear

### Commit Messages

Use clear, descriptive commit messages:

```
<type>: <short summary>

<detailed description if needed>

<reference to issues>
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Adding or updating tests
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `chore`: Maintenance tasks

Example:
```
feat: add UDP hole punching support

Implement coordinated UDP hole punching for NAT traversal.
This enables direct connections through restrictive NATs.

Closes #123
```

## Reporting Issues

### Bug Reports

Include the following information:

1. **Environment**:
   - Operating system and version
   - Compiler and version
   - librats version or commit hash

2. **Steps to reproduce**: Minimal code example if possible

3. **Expected behavior**: What should happen

4. **Actual behavior**: What actually happens

5. **Logs**: Relevant log output with timestamps

### Feature Requests

Describe:
- The problem you're trying to solve
- Your proposed solution
- Alternative solutions you've considered
- Any breaking changes required

## Project Structure

The include root is `src/`, and everything the library ships lives one level
down in `src/librats/` — so the tree in the repository mirrors the installed
`<prefix>/include/librats/` exactly, and both resolve `librats/node/node.h`
the same way.

```
librats/
├── src/                        # Include root — nothing lives here directly
│   ├── librats/                # Everything installed, mirrors include/librats/
│   │   ├── core/              # Sockets, buffers, IOPoller, MPSC/timer queues,
│   │   │                      #   EventBus, ServiceRegistry
│   │   ├── wire/              # Two-level framing + MessageRouter
│   │   ├── transport/         # ReactorPool, Reactor, Connection, TCP/UDP links
│   │   ├── security/          # Identity, Handshaker/Session, Noise & plaintext
│   │   ├── peer/              # Self-certifying PeerId, PeerTable, Peer handle
│   │   ├── node/              # Node facade, NodeContext, PeerNetwork, dialer
│   │   ├── subsystems/        # The opt-in plugins (PubSub, FileTransfer, …)
│   │   ├── dht/               # Kademlia + KRPC
│   │   ├── mdns/              # Multicast DNS
│   │   ├── nat/               # STUN, UPnP, NAT-PMP
│   │   ├── crypto/            # curve25519 / chacha / poly1305 / blake2 / sha
│   │   │                      #   + the Noise framework
│   │   ├── bittorrent/        # BitTorrent (gated by RATS_SEARCH_FEATURES)
│   │   ├── storage/           # Distributed KV store (gated by RATS_STORAGE)
│   │   ├── bindings/          # rats.{h,cpp} — the C ABI all FFI bindings use
│   │   └── util/              # Logger, JSON, filesystem, OS helpers
│   └── main.cpp                # rats-client reference app — not library code
├── tests/                      # Unit tests
│   ├── test_main.cpp          # Test runner
│   ├── test_socket.cpp        # Socket tests
│   └── ...
├── examples/                   # Focused, self-contained example programs
├── bench/                      # Benchmark suites (see bench/README.md)
├── docs/                       # Doxygen config output + the project website
├── ports/librats/              # vcpkg port (portfile.cmake, vcpkg.json)
├── nodejs/                     # Node.js bindings
├── python/                     # Python bindings
├── android/                    # Android integration (JNI + Java API)
├── react-native/               # React Native package (Nitro Modules, C++)
├── ios/                        # iOS XCFramework build of the core
├── .github/workflows/          # CI configuration
├── CMakeLists.txt             # Build configuration
└── README.md                  # Project documentation
```

### Key Components

| Component | Files | Description |
|-----------|-------|-------------|
| Core | `node/node.{cpp,h}` | The `Node` facade — the public entry point |
| Networking | `core/socket.{cpp,h}` | Cross-platform socket abstraction |
| Transport | `transport/connection.{cpp,h}`, `transport/reactor.{cpp,h}` | Per-peer state machine + reactor threads |
| Discovery | `dht/dht.{cpp,h}`, `mdns/mdns.{cpp,h}` | Peer discovery mechanisms |
| NAT | `nat/stun.{cpp,h}`, `nat/port_mapping.h`, `nat/upnp.{cpp,h}`, `nat/natpmp.{cpp,h}` | STUN client and UPnP / NAT-PMP port mapping |
| NAT traversal | `subsystems/hole_punch.{cpp,h}`, `subsystems/relay.{cpp,h}`, `transport/relay_link.{cpp,h}` | UDP hole punching and relayed circuits |
| Security | `crypto/noise.{cpp,h}`, `security/noise_security.{cpp,h}` | End-to-end encryption |
| Messaging | `subsystems/pubsub.{cpp,h}` | GossipSub pub-sub |
| Transfer | `subsystems/file_transfer.{cpp,h}` | File/directory transfer |
| C ABI | `bindings/rats.{cpp,h}` | The C API every language binding builds on |

Paths are relative to `src/librats/`.

## Language Bindings

### Adding New Bindings

When contributing language bindings:

1. **Use the C API** (`src/librats/bindings/rats.h`, included as
   `<librats/bindings/rats.h>`) as the foundation. When you add a public C++
   capability that should be reachable from other languages, surface it there
   first — typically as a `rats_enable_*` call made before `rats_start` — and
   keep the language wrappers in sync.
2. **Follow language conventions** for the target language
3. **Provide examples** showing common use cases
4. **Document installation** and usage
5. **Add CI testing** for the binding

### Existing Bindings

- **Node.js**: `nodejs/` - Native addon with TypeScript support
- **Python**: `python/` - ctypes-based wrapper
- **Android/Java**: `android/` - JNI integration
- **iOS**: `ios/` - XCFramework of the core; Swift imports the C API directly
- **React Native**: `react-native/` - Nitro module over the C++ API (not the C API)
- **React Native**: `react-native/` - one C++ Nitro Modules `HybridObject` shared by iOS and Android
- **iOS**: `ios/` - `XCFramework` build of the core; Swift imports the C ABI directly

## Documentation

### Types of Documentation

1. **API Documentation**: Doxygen comments in headers
2. **Usage Examples**: In `README.md` and the runnable programs in `examples/`
3. **Architecture**: `ARCHITECTURE.md` — the layers, the subsystem contract, the threading model

### Writing Documentation

- Use clear, concise language
- Include code examples that can be copy-pasted
- Keep examples up-to-date with code changes
- Use proper markdown formatting

### Building Documentation

```bash
# API documentation (requires Doxygen)
doxygen Doxyfile
```

## Questions?

If you have questions about contributing:

1. Check existing issues and discussions
2. Open a new issue with the `question` label
3. Read `README.md` and `ARCHITECTURE.md`

Thank you for contributing to librats! 🐀

