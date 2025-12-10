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

- **CMake 3.10+** installed
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
| `RATS_BUILD_EXAMPLES` | `ON` | Build example applications |
| `RATS_ENABLE_ASAN` | `OFF` | Enable AddressSanitizer |
| `RATS_BINDINGS` | `ON` | Enable C API bindings |
| `RATS_SHARED_LIBRARY` | `OFF` | Build as shared library |
| `RATS_STATIC_LIBRARY` | `ON` | Build as static library |
| `RATS_SEARCH_FEATURES` | `OFF` | Enable BitTorrent features |

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
class RatsClient { };
struct NatTraversalConfig { };

// Functions and Methods: snake_case
void connect_to_peer();
bool is_running() const;

// Variables: snake_case
int listen_port_;           // Member variables end with underscore
std::string peer_id;        // Local variables without underscore

// Constants and Enums: SCREAMING_SNAKE_CASE or PascalCase
static constexpr int MAX_PEERS = 100;
enum class ConnectionStrategy { DIRECT_ONLY, AUTO_ADAPTIVE };

// Namespaces: lowercase
namespace librats { }
```

#### Header Files

```cpp
#pragma once  // Use pragma once for header guards

#include "local_header.h"      // Local includes first
#include <system_header>        // System includes second
#include <third_party_header>   // Third-party includes last

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
 * Connect to a peer with automatic NAT traversal
 * @param host Target host/IP address
 * @param port Target port
 * @param strategy Connection strategy to use
 * @return true if connection initiated successfully
 */
bool connect_to_peer(const std::string& host, int port, 
                    ConnectionStrategy strategy = ConnectionStrategy::AUTO_ADAPTIVE);
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
- Follow the mutex locking order documented in `librats.h`
- Use RAII lock guards (`std::lock_guard`, `std::unique_lock`)

### File Organization

- One class per file (except for closely related small classes)
- Header files in `src/` with `.h` extension
- Implementation files in `src/` with `.cpp` extension
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
#include "your_module.h"

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

3. **Fill out the PR template** with:
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

```
librats/
├── src/                    # Core C++ source files
│   ├── librats.h          # Main public API header
│   ├── librats.cpp        # Core implementation
│   ├── librats_c.h        # C API bindings
│   ├── socket.cpp/h       # Socket abstraction
│   ├── dht.cpp/h          # DHT implementation
│   ├── stun.cpp/h         # STUN client
│   ├── ice.cpp/h          # ICE implementation
│   ├── mdns.cpp/h         # mDNS discovery
│   ├── noise.cpp/h        # Noise Protocol encryption
│   ├── gossipsub.cpp/h    # GossipSub pub-sub
│   ├── file_transfer.cpp/h # File transfer
│   └── ...
├── tests/                  # Unit tests
│   ├── test_main.cpp      # Test runner
│   ├── test_socket.cpp    # Socket tests
│   └── ...
├── docs/                   # Documentation
├── nodejs/                 # Node.js bindings
├── python/                 # Python bindings
├── android/                # Android integration
├── .github/workflows/      # CI configuration
├── CMakeLists.txt         # Build configuration
└── README.md              # Project documentation
```

### Key Components

| Component | Files | Description |
|-----------|-------|-------------|
| Core | `librats.cpp/h` | Main RatsClient implementation |
| Networking | `socket.cpp/h` | Cross-platform socket abstraction |
| Discovery | `dht.cpp/h`, `mdns.cpp/h` | Peer discovery mechanisms |
| NAT | `stun.cpp/h`, `ice.cpp/h` | NAT traversal |
| Security | `noise.cpp/h` | End-to-end encryption |
| Messaging | `gossipsub.cpp/h` | Pub-sub protocol |
| Transfer | `file_transfer.cpp/h` | File/directory transfer |

## Language Bindings

### Adding New Bindings

When contributing language bindings:

1. **Use the C API** (`librats_c.h`) as the foundation
2. **Follow language conventions** for the target language
3. **Provide examples** showing common use cases
4. **Document installation** and usage
5. **Add CI testing** for the binding

### Existing Bindings

- **Node.js**: `nodejs/` - Native addon with TypeScript support
- **Python**: `python/` - ctypes-based wrapper
- **Android/Java**: `android/` - JNI integration

## Documentation

### Types of Documentation

1. **API Documentation**: Doxygen comments in headers
2. **Usage Examples**: In `README.md` and `docs/`
3. **Tutorials**: Step-by-step guides in `docs/`

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
3. Read the documentation in `docs/`

Thank you for contributing to librats! 🐀

---

*This contributing guide is adapted from open source best practices and customized for the librats project.*

