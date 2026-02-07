#pragma once

/**
 * @file io_poller.h
 * @brief Platform-optimal I/O multiplexing abstraction
 * 
 * Provides a unified interface over platform-specific I/O multiplexers:
 * - Linux:       epoll   (O(1) per event, scales to millions of fds)
 * - macOS/BSD:   kqueue  (O(1) per event, scales to millions of fds)
 * - Windows:     IOCP    (true async completion ports, O(1) per event)
 * 
 * Usage:
 *   auto poller = IOPoller::create();
 *   poller->add(fd, PollIn);
 *   
 *   PollResult results[64];
 *   int n = poller->wait(results, 64, 100);  // 100ms timeout
 *   for (int i = 0; i < n; i++) {
 *       if (results[i].events & PollIn) handle_read(results[i].fd);
 *       if (results[i].events & PollOut) handle_write(results[i].fd);
 *   }
 */

#include "socket.h"

#include <memory>
#include <cstdint>

namespace librats {

//=============================================================================
// Poll Event Flags
//=============================================================================

/**
 * @brief I/O event flags for polling
 */
enum PollFlags : uint32_t {
    PollNone = 0,
    PollIn   = 1 << 0,  ///< Socket is readable (data available or connection accepted)
    PollOut  = 1 << 1,  ///< Socket is writable (can send or connect completed)
    PollErr  = 1 << 2,  ///< Error condition on socket
    PollHup  = 1 << 3,  ///< Hang up / peer disconnected
};

inline uint32_t operator|(PollFlags a, PollFlags b) {
    return static_cast<uint32_t>(a) | static_cast<uint32_t>(b);
}

//=============================================================================
// Poll Result
//=============================================================================

/**
 * @brief Result entry from a poll wait
 */
struct PollResult {
    socket_t fd;        ///< The socket that has events
    uint32_t events;    ///< Bitmask of PollFlags that occurred
};

//=============================================================================
// IOPoller Abstract Interface
//=============================================================================

/**
 * @brief Abstract I/O multiplexer
 * 
 * Thread-safety:
 * - add/modify/remove: Safe to call from any thread (epoll_ctl is thread-safe,
 *   kqueue changes are atomic, WSAPoll rebuilds on wait).
 * - wait: Should be called from a single I/O thread.
 * - add/modify/remove can be called concurrently with wait().
 */
class IOPoller {
public:
    virtual ~IOPoller() = default;
    
    /**
     * @brief Create the platform-optimal poller instance
     * 
     * Returns:
     * - EpollPoller on Linux
     * - KqueuePoller on macOS/FreeBSD
     * - IocpPoller on Windows (I/O Completion Ports)
     */
    static std::unique_ptr<IOPoller> create();
    
    /**
     * @brief Add a socket to the poll set
     * 
     * @param fd Socket to monitor
     * @param events Bitmask of PollFlags to watch for
     * @return true on success
     */
    virtual bool add(socket_t fd, uint32_t events) = 0;
    
    /**
     * @brief Modify the event mask for a monitored socket
     * 
     * @param fd Socket already in the poll set
     * @param events New bitmask of PollFlags
     * @return true on success
     */
    virtual bool modify(socket_t fd, uint32_t events) = 0;
    
    /**
     * @brief Remove a socket from the poll set
     * 
     * @param fd Socket to remove
     * @return true on success (false if fd was not registered)
     */
    virtual bool remove(socket_t fd) = 0;
    
    /**
     * @brief Wait for I/O events
     * 
     * Blocks until events occur or timeout expires.
     * 
     * @param results Array to fill with ready socket events
     * @param max_results Maximum entries in results array
     * @param timeout_ms Timeout in milliseconds (-1 = block forever, 0 = non-blocking)
     * @return Number of ready descriptors (0 on timeout, -1 on error)
     */
    virtual int wait(PollResult* results, int max_results, int timeout_ms) = 0;
    
    /**
     * @brief Get the backend name (for logging/diagnostics)
     */
    virtual const char* name() const = 0;
    
    // Non-copyable
    IOPoller() = default;
    IOPoller(const IOPoller&) = delete;
    IOPoller& operator=(const IOPoller&) = delete;
};

} // namespace librats
