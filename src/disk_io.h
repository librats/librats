#pragma once

#include <string>
#include <vector>
#include <queue>
#include <functional>
#include <mutex>
#include <thread>
#include <atomic>
#include <condition_variable>
#include <memory>

namespace librats {

// Forward declaration
class DiskIOThread;

//=============================================================================
// Disk Job Types
//=============================================================================

enum class DiskJobType {
    WRITE_BLOCK,    // Write a block to disk
    READ_PIECE,     // Read an entire piece from disk
    HASH_PIECE,     // Read piece from disk and compute hash
    FLUSH           // Ensure all pending writes are complete
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
    uint32_t piece_offset_in_torrent;  // Absolute offset in torrent
    
    // Callbacks (only one is set based on job type)
    WriteCompleteCallback write_callback;
    ReadCompleteCallback read_callback;
    HashCompleteCallback hash_callback;
    FlushCompleteCallback flush_callback;
    
    DiskJob() : type(DiskJobType::WRITE_BLOCK), piece_index(0), block_index(0), 
                offset(0), piece_length(0), piece_offset_in_torrent(0) {}
};

//=============================================================================
// DiskIOThread - Handles all disk I/O asynchronously
//=============================================================================

class DiskIOThread {
public:
    DiskIOThread();
    ~DiskIOThread();
    
    // Start/stop the disk I/O thread
    bool start();
    void stop();
    bool is_running() const { return running_.load(); }
    
    // Queue a write operation (writes block immediately to disk)
    void async_write_block(
        const std::string& download_path,
        const std::vector<FileMappingInfo>& files,
        uint32_t piece_index,
        uint32_t piece_length_standard,  // Standard piece length from torrent
        uint32_t block_offset,           // Offset within piece
        const std::vector<uint8_t>& data,
        WriteCompleteCallback callback
    );
    
    // Queue a piece read operation (reads entire piece from disk)
    void async_read_piece(
        const std::string& download_path,
        const std::vector<FileMappingInfo>& files,
        uint32_t piece_index,
        uint32_t piece_length_standard,
        uint32_t actual_piece_length,    // May be smaller for last piece
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
    uint64_t get_total_bytes_written() const { return total_bytes_written_.load(); }
    uint64_t get_total_bytes_read() const { return total_bytes_read_.load(); }
    
private:
    std::atomic<bool> running_;
    std::thread worker_thread_;
    
    // Job queue
    std::queue<DiskJob> job_queue_;
    mutable std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    
    // Statistics
    std::atomic<uint64_t> total_bytes_written_;
    std::atomic<uint64_t> total_bytes_read_;
    
    // Worker thread function
    void worker_loop();
    
    // Execute individual job types
    void execute_write_block(const DiskJob& job);
    void execute_read_piece(const DiskJob& job);
    void execute_hash_piece(const DiskJob& job);
    void execute_flush(const DiskJob& job);
    
    // Helper: Map torrent offset to file(s)
    // Returns list of (file_path, file_offset, length) tuples for the given range
    std::vector<std::tuple<std::string, uint64_t, size_t>> map_to_files(
        const std::string& download_path,
        const std::vector<FileMappingInfo>& files,
        uint64_t torrent_offset,
        size_t length
    );
};

//=============================================================================
// Global DiskIO instance (singleton pattern)
//=============================================================================

class DiskIO {
public:
    static DiskIOThread& instance();
    
    // Non-copyable
    DiskIO(const DiskIO&) = delete;
    DiskIO& operator=(const DiskIO&) = delete;
    
private:
    DiskIO() = default;
    static std::unique_ptr<DiskIOThread> instance_;
    static std::once_flag init_flag_;
};

} // namespace librats
