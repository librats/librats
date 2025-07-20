#pragma once

#include "logger.h"
#include <thread>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <string>

namespace librats {

/**
 * ThreadManager provides thread management capabilities for classes that need
 * to manage multiple background threads with graceful shutdown coordination.
 */
class ThreadManager {
public:
    ThreadManager();
    virtual ~ThreadManager();

    // Thread management methods
    /**
     * Add a managed thread with a descriptive name
     * @param t Thread to be managed (moved)
     * @param name Descriptive name for logging purposes
     */
    void add_managed_thread(std::thread&& t, const std::string& name);

    /**
     * Clean up threads that have finished execution
     */
    void cleanup_finished_threads();

    /**
     * Signal all threads to shutdown and notify waiting threads
     */
    void shutdown_all_threads();

    /**
     * Join all active threads and wait for them to finish
     */
    void join_all_active_threads();

    /**
     * Get the current number of active threads
     * @return Number of active threads
     */
    size_t get_active_thread_count() const;

protected:
    // Protected members that derived classes can use for thread coordination
    
    /**
     * Condition variable for coordinating thread shutdown
     * Threads should wait on this and check running flags
     */
    std::condition_variable shutdown_cv_;
    
    /**
     * Mutex for the shutdown condition variable
     */
    std::mutex shutdown_mutex_;

    /**
     * Notify all waiting threads to wake up (typically for shutdown)
     */
    void notify_shutdown();

private:
    // Thread storage and synchronization
    std::vector<std::thread> active_threads_;
    mutable std::mutex active_threads_mutex_;

    // Prevent copying
    ThreadManager(const ThreadManager&) = delete;
    ThreadManager& operator=(const ThreadManager&) = delete;
};

} // namespace librats

