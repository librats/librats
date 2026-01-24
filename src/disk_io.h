#pragma once

#include <string>
#include <vector>
#include <queue>
#include <deque>
#include <functional>
#include <mutex>
#include <thread>
#include <atomic>
#include <condition_variable>
#include <memory>

namespace librats {

// Forward declaration
class DiskIOThreadPool;

//=============================================================================
// Disk Job Types
//=============================================================================

enum class DiskJobType {
    WRITE_BLOCK,    // Write a block to disk
    READ_PIECE,     // Read an entire piece from disk
    HASH_PIECE,     // Read piece from disk and compute hash
    FLUSH           // Ensure all pending writes are complete
};

// Job priority (lower = higher priority)
enum class DiskJobPriority {
    HIGH = 0,       // Critical operations (e.g., flush, urgent reads)
    NORMAL = 1,     // Standard operations
    LOW = 2         // Background operations (e.g., hash verification)
};

// Completion callback types
using WriteCompleteCallback = std::function<void(bool success)>;
using ReadCompleteCallback = std::function<void(bool success, const std::vector<uint8_t>& data)>;
using HashCompleteCallback = std::function<void(bool success, const std::string& hash)>;
using FlushCompleteCallback = std::function<void(bool success)>;

//=============================================================================
// File Mapping Structure (for multi-file torrents)
//=============================================================================

struct FileMappingInfo {
    std::string path;       // File path relative to download directory
    uint64_t length;        // Total file length
    uint64_t torrent_offset; // Offset within the torrent's data stream
};

//=============================================================================
// Disk Job Structure
//=============================================================================

struct DiskJob {
    DiskJobType type;
    DiskJobPriority priority;
    
    // Job identification
    uint32_t piece_index;
    uint32_t block_index;
    uint32_t offset;         // Offset within piece
    
    // File mapping info
    std::string download_path;
    std::vector<FileMappingInfo> file_mappings;  // Full file mapping info including lengths
    
    // Data for write operations
    std::vector<uint8_t> data;
    
    // Piece info for read/hash operations
    uint32_t piece_length;
    uint64_t piece_offset_in_torrent;  // Absolute offset in torrent (uint64 to support large torrents >4GB)
    
    // Callbacks (only one is set based on job type)
    WriteCompleteCallback write_callback;
    ReadCompleteCallback read_callback;
    HashCompleteCallback hash_callback;
    FlushCompleteCallback flush_callback;
    
    DiskJob() : type(DiskJobType::WRITE_BLOCK), priority(DiskJobPriority::NORMAL),
                piece_index(0), block_index(0), 
                offset(0), piece_length(0), piece_offset_in_torrent(0) {}
    
    // For priority queue ordering
    bool operator<(const DiskJob& other) const {
        return static_cast<int>(priority) > static_cast<int>(other.priority);
    }
};

//=============================================================================
// DiskIOThreadPool Configuration
//=============================================================================

struct DiskIOConfig {
    int num_write_threads = 1;      // Number of threads for write operations
    int num_read_threads = 2;       // Number of threads for read/hash operations
    int max_pending_jobs = 1000;    // Maximum pending jobs before blocking
    bool enable_coalescing = true;  // Coalesce adjacent write operations
    
    DiskIOConfig() = default;
};

//=============================================================================
// DiskIOThreadPool - Multi-threaded disk I/O handler
//=============================================================================

class DiskIOThreadPool {
public:
    explicit DiskIOThreadPool(const DiskIOConfig& config = DiskIOConfig());
    ~DiskIOThreadPool();
    
    // Start/stop the thread pool
    bool start();
    void stop();
    bool is_running() const { return running_.load(); }
    
    // Configuration
    void set_num_write_threads(int count);
    void set_num_read_threads(int count);
    int get_num_write_threads() const { return num_write_threads_.load(); }
    int get_num_read_threads() const { return num_read_threads_.load(); }
    
    // Queue a write operation (writes block immediately to disk)
    void async_write_block(
        const std::string& download_path,
        const std::vector<FileMappingInfo>& files,
        uint32_t piece_index,
        uint32_t piece_length_standard,  // Standard piece length from torrent
        uint32_t block_offset,           // Offset within piece
        const std::vector<uint8_t>& data,
        WriteCompleteCallback callback,
        DiskJobPriority priority = DiskJobPriority::NORMAL
    );
    
    // Queue a piece read operation (reads entire piece from disk)
    void async_read_piece(
        const std::string& download_path,
        const std::vector<FileMappingInfo>& files,
        uint32_t piece_index,
        uint32_t piece_length_standard,
        uint32_t actual_piece_length,    // May be smaller for last piece
        ReadCompleteCallback callback,
        DiskJobPriority priority = DiskJobPriority::NORMAL
    );
    
    // Queue a piece hash operation (reads piece and computes SHA1)
    void async_hash_piece(
        const std::string& download_path,
        const std::vector<FileMappingInfo>& files,
        uint32_t piece_index,
        uint32_t piece_length_standard,
        uint32_t actual_piece_length,
        HashCompleteCallback callback,
        DiskJobPriority priority = DiskJobPriority::LOW
    );
    
    // Queue a flush operation (ensures all pending writes are complete)
    void async_flush(FlushCompleteCallback callback);
    
    // Statistics
    size_t get_pending_write_jobs() const;
    size_t get_pending_read_jobs() const;
    size_t get_total_pending_jobs() const;
    uint64_t get_total_bytes_written() const { return total_bytes_written_.load(); }
    uint64_t get_total_bytes_read() const { return total_bytes_read_.load(); }
    uint64_t get_jobs_completed() const { return jobs_completed_.load(); }
    
private:
    DiskIOConfig config_;
    std::atomic<bool> running_;
    
    // Thread counts (can be adjusted at runtime)
    std::atomic<int> num_write_threads_;
    std::atomic<int> num_read_threads_;
    
    // Worker threads
    std::vector<std::thread> write_threads_;
    std::vector<std::thread> read_threads_;
    
    // Separate job queues for writes and reads (with priority)
    std::priority_queue<DiskJob> write_queue_;
    std::priority_queue<DiskJob> read_queue_;
    
    mutable std::mutex write_mutex_;
    mutable std::mutex read_mutex_;
    std::condition_variable write_cv_;
    std::condition_variable read_cv_;
    
    // Statistics
    std::atomic<uint64_t> total_bytes_written_;
    std::atomic<uint64_t> total_bytes_read_;
    std::atomic<uint64_t> jobs_completed_;
    
    // Worker thread functions
    void write_worker_loop();
    void read_worker_loop();
    
    // Execute individual job types
    void execute_write_block(const DiskJob& job);
    void execute_read_piece(const DiskJob& job);
    void execute_hash_piece(const DiskJob& job);
    void execute_flush(const DiskJob& job);
    
    // Helper: Map torrent offset to file(s)
    // Returns list of (file_path, file_offset, length) tuples for the given range
    static std::vector<std::tuple<std::string, uint64_t, size_t>> map_to_files(
        const std::string& download_path,
        const std::vector<FileMappingInfo>& files,
        uint64_t torrent_offset,
        size_t length
    );
    
    // Helper: Start/stop worker threads
    void start_write_threads(int count);
    void start_read_threads(int count);
    void stop_write_threads();
    void stop_read_threads();
};

//=============================================================================
// Legacy compatibility - DiskIOThread using thread pool internally
//=============================================================================

class DiskIOThread {
public:
    DiskIOThread();
    ~DiskIOThread();
    
    // Start/stop the disk I/O thread
    bool start();
    void stop();
    bool is_running() const;
    
    // Queue a write operation (writes block immediately to disk)
    void async_write_block(
        const std::string& download_path,
        const std::vector<FileMappingInfo>& files,
        uint32_t piece_index,
        uint32_t piece_length_standard,
        uint32_t block_offset,
        const std::vector<uint8_t>& data,
        WriteCompleteCallback callback
    );
    
    // Queue a piece read operation (reads entire piece from disk)
    void async_read_piece(
        const std::string& download_path,
        const std::vector<FileMappingInfo>& files,
        uint32_t piece_index,
        uint32_t piece_length_standard,
        uint32_t actual_piece_length,
        ReadCompleteCallback callback
    );
    
    // Queue a piece hash operation (reads piece and computes SHA1)
    void async_hash_piece(
        const std::string& download_path,
        const std::vector<FileMappingInfo>& files,
        uint32_t piece_index,
        uint32_t piece_length_standard,
        uint32_t actual_piece_length,
        HashCompleteCallback callback
    );
    
    // Queue a flush operation (ensures all pending writes are complete)
    void async_flush(FlushCompleteCallback callback);
    
    // Statistics
    size_t get_pending_jobs() const;
    uint64_t get_total_bytes_written() const;
    uint64_t get_total_bytes_read() const;
    
private:
    std::unique_ptr<DiskIOThreadPool> pool_;
};

//=============================================================================
// Global DiskIO instance (singleton pattern)
//=============================================================================

class DiskIO {
public:
    static DiskIOThreadPool& instance();
    
    // Configure the singleton (must be called before first instance() call)
    static void configure(const DiskIOConfig& config);
    
    // Non-copyable
    DiskIO(const DiskIO&) = delete;
    DiskIO& operator=(const DiskIO&) = delete;
    
private:
    DiskIO() = default;
    static std::unique_ptr<DiskIOThreadPool> instance_;
    static std::once_flag init_flag_;
    static DiskIOConfig config_;
};

} // namespace librats
