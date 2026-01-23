#include "disk_io.h"
#include "fs.h"
#include "sha1.h"
#include "logger.h"
#include <algorithm>

#define LOG_DISK_DEBUG(message) LOG_DEBUG("disk_io", message)
#define LOG_DISK_INFO(message)  LOG_INFO("disk_io", message)
#define LOG_DISK_WARN(message)  LOG_WARN("disk_io", message)
#define LOG_DISK_ERROR(message) LOG_ERROR("disk_io", message)

namespace librats {

//=============================================================================
// DiskIOThread Implementation
//=============================================================================

DiskIOThread::DiskIOThread()
    : running_(false), total_bytes_written_(0), total_bytes_read_(0) {
}

DiskIOThread::~DiskIOThread() {
    stop();
}

bool DiskIOThread::start() {
    if (running_.load()) {
        return true;
    }
    
    running_.store(true);
    worker_thread_ = std::thread(&DiskIOThread::worker_loop, this);
    
    LOG_DISK_INFO("Disk I/O thread started");
    return true;
}

void DiskIOThread::stop() {
    if (!running_.load()) {
        return;
    }
    
    running_.store(false);
    
    // Wake up worker thread
    queue_cv_.notify_all();
    
    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
    
    LOG_DISK_INFO("Disk I/O thread stopped");
}

void DiskIOThread::async_write_block(
    const std::string& download_path,
    const std::vector<FileMappingInfo>& files,
    uint32_t piece_index,
    uint32_t piece_length_standard,
    uint32_t block_offset,
    const std::vector<uint8_t>& data,
    WriteCompleteCallback callback)
{
    DiskJob job;
    job.type = DiskJobType::WRITE_BLOCK;
    job.piece_index = piece_index;
    job.offset = block_offset;
    job.download_path = download_path;
    job.data = data;  // Copy the data
    job.piece_length = piece_length_standard;
    job.piece_offset_in_torrent = static_cast<uint32_t>(
        static_cast<uint64_t>(piece_index) * piece_length_standard
    );
    job.write_callback = callback;
    
    // Store file mappings with full info
    job.file_mappings = files;
    
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        job_queue_.push(std::move(job));
    }
    queue_cv_.notify_one();
    
    LOG_DISK_DEBUG("Queued write block: piece " << piece_index << " offset " << block_offset 
                   << " size " << data.size());
}

void DiskIOThread::async_read_piece(
    const std::string& download_path,
    const std::vector<FileMappingInfo>& files,
    uint32_t piece_index,
    uint32_t piece_length_standard,
    uint32_t actual_piece_length,
    ReadCompleteCallback callback)
{
    DiskJob job;
    job.type = DiskJobType::READ_PIECE;
    job.piece_index = piece_index;
    job.download_path = download_path;
    job.piece_length = actual_piece_length;
    job.piece_offset_in_torrent = static_cast<uint32_t>(
        static_cast<uint64_t>(piece_index) * piece_length_standard
    );
    job.read_callback = callback;
    
    // Store file mappings with full info
    job.file_mappings = files;
    
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        job_queue_.push(std::move(job));
    }
    queue_cv_.notify_one();
    
    LOG_DISK_DEBUG("Queued read piece: piece " << piece_index << " length " << actual_piece_length);
}

void DiskIOThread::async_hash_piece(
    const std::string& download_path,
    const std::vector<FileMappingInfo>& files,
    uint32_t piece_index,
    uint32_t piece_length_standard,
    uint32_t actual_piece_length,
    HashCompleteCallback callback)
{
    DiskJob job;
    job.type = DiskJobType::HASH_PIECE;
    job.piece_index = piece_index;
    job.download_path = download_path;
    job.piece_length = actual_piece_length;
    job.piece_offset_in_torrent = static_cast<uint32_t>(
        static_cast<uint64_t>(piece_index) * piece_length_standard
    );
    job.hash_callback = callback;
    
    // Store file mappings with full info
    job.file_mappings = files;
    
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        job_queue_.push(std::move(job));
    }
    queue_cv_.notify_one();
    
    LOG_DISK_DEBUG("Queued hash piece: piece " << piece_index << " length " << actual_piece_length);
}

void DiskIOThread::async_flush(FlushCompleteCallback callback) {
    DiskJob job;
    job.type = DiskJobType::FLUSH;
    job.flush_callback = callback;
    
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        job_queue_.push(std::move(job));
    }
    queue_cv_.notify_one();
    
    LOG_DISK_DEBUG("Queued flush operation");
}

size_t DiskIOThread::get_pending_jobs() const {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    return job_queue_.size();
}

void DiskIOThread::worker_loop() {
    LOG_DISK_INFO("Disk I/O worker loop started");
    
    while (running_.load()) {
        DiskJob job;
        
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            
            // Wait for a job or shutdown
            queue_cv_.wait(lock, [this] {
                return !job_queue_.empty() || !running_.load();
            });
            
            if (!running_.load() && job_queue_.empty()) {
                break;
            }
            
            if (!job_queue_.empty()) {
                job = std::move(job_queue_.front());
                job_queue_.pop();
            } else {
                continue;
            }
        }
        
        // Execute the job outside the lock
        switch (job.type) {
            case DiskJobType::WRITE_BLOCK:
                execute_write_block(job);
                break;
            case DiskJobType::READ_PIECE:
                execute_read_piece(job);
                break;
            case DiskJobType::HASH_PIECE:
                execute_hash_piece(job);
                break;
            case DiskJobType::FLUSH:
                execute_flush(job);
                break;
        }
    }
    
    LOG_DISK_INFO("Disk I/O worker loop ended");
}

std::vector<std::tuple<std::string, uint64_t, size_t>> DiskIOThread::map_to_files(
    const std::string& download_path,
    const std::vector<FileMappingInfo>& files,
    uint64_t torrent_offset,
    size_t length)
{
    std::vector<std::tuple<std::string, uint64_t, size_t>> result;
    
    size_t remaining = length;
    uint64_t current_offset = torrent_offset;
    
    for (const auto& file : files) {
        if (remaining == 0) break;
        
        uint64_t file_end = file.torrent_offset + file.length;
        
        // Check if we've passed this file entirely
        if (current_offset >= file_end) {
            continue;
        }
        
        // Check if we haven't reached this file yet
        if (current_offset + remaining <= file.torrent_offset) {
            break;
        }
        
        // Calculate overlap with this file
        uint64_t read_start_in_torrent = std::max(current_offset, file.torrent_offset);
        uint64_t read_end_in_torrent = std::min(current_offset + remaining, file_end);
        size_t read_length = static_cast<size_t>(read_end_in_torrent - read_start_in_torrent);
        
        if (read_length == 0) continue;
        
        // Calculate file offset
        uint64_t file_offset = read_start_in_torrent - file.torrent_offset;
        
        // Construct full file path
        std::string file_path = download_path + "/" + file.path;
        
        result.emplace_back(file_path, file_offset, read_length);
        
        // Advance
        current_offset = read_end_in_torrent;
        remaining -= read_length;
    }
    
    return result;
}

void DiskIOThread::execute_write_block(const DiskJob& job) {
    bool success = true;
    
    // Calculate absolute torrent offset for this block
    uint64_t torrent_offset = static_cast<uint64_t>(job.piece_offset_in_torrent) + job.offset;
    
    // Map to file(s) using the complete file mapping info
    auto mappings = map_to_files(job.download_path, job.file_mappings, torrent_offset, job.data.size());
    
    size_t data_offset = 0;
    for (const auto& [file_path, file_offset, write_length] : mappings) {
        if (!write_file_chunk(file_path.c_str(), file_offset, 
                             job.data.data() + data_offset, write_length)) {
            LOG_DISK_ERROR("Failed to write block to file: " << file_path);
            success = false;
            break;
        }
        data_offset += write_length;
    }
    
    if (success) {
        total_bytes_written_ += job.data.size();
        LOG_DISK_DEBUG("Write complete: piece " << job.piece_index << " offset " << job.offset);
    }
    
    if (job.write_callback) {
        job.write_callback(success);
    }
}

void DiskIOThread::execute_read_piece(const DiskJob& job) {
    std::vector<uint8_t> data(job.piece_length);
    bool success = true;
    
    // Calculate absolute torrent offset for this piece
    uint64_t torrent_offset = job.piece_offset_in_torrent;
    
    // Map to file(s) using the complete file mapping info
    auto mappings = map_to_files(job.download_path, job.file_mappings, torrent_offset, job.piece_length);
    
    size_t data_offset = 0;
    for (const auto& [file_path, file_offset, read_length] : mappings) {
        if (!read_file_chunk(file_path.c_str(), file_offset, 
                            data.data() + data_offset, read_length)) {
            LOG_DISK_ERROR("Failed to read piece from file: " << file_path);
            success = false;
            break;
        }
        data_offset += read_length;
    }
    
    if (success) {
        total_bytes_read_ += job.piece_length;
        LOG_DISK_DEBUG("Read complete: piece " << job.piece_index);
    }
    
    if (job.read_callback) {
        job.read_callback(success, success ? data : std::vector<uint8_t>());
    }
}

void DiskIOThread::execute_hash_piece(const DiskJob& job) {
    std::vector<uint8_t> data(job.piece_length);
    bool success = true;
    
    // Calculate absolute torrent offset for this piece
    uint64_t torrent_offset = job.piece_offset_in_torrent;
    
    // Map to file(s) using the complete file mapping info
    auto mappings = map_to_files(job.download_path, job.file_mappings, torrent_offset, job.piece_length);
    
    size_t data_offset = 0;
    for (const auto& [file_path, file_offset, read_length] : mappings) {
        if (!read_file_chunk(file_path.c_str(), file_offset, 
                            data.data() + data_offset, read_length)) {
            LOG_DISK_ERROR("Failed to read piece for hashing from file: " << file_path);
            success = false;
            break;
        }
        data_offset += read_length;
    }
    
    std::string hash;
    if (success) {
        // Calculate SHA1 hash
        hash = SHA1::hash_bytes(data);
        total_bytes_read_ += job.piece_length;
        LOG_DISK_DEBUG("Hash complete: piece " << job.piece_index << " hash " << hash.substr(0, 8) << "...");
    }
    
    if (job.hash_callback) {
        job.hash_callback(success, hash);
    }
}

void DiskIOThread::execute_flush(const DiskJob& job) {
    // On most systems, writes are already flushed when write_file_chunk returns
    // For additional safety, we could call fsync() here, but it's costly
    
    LOG_DISK_DEBUG("Flush complete");
    
    if (job.flush_callback) {
        job.flush_callback(true);
    }
}

//=============================================================================
// DiskIO Singleton Implementation
//=============================================================================

std::unique_ptr<DiskIOThread> DiskIO::instance_;
std::once_flag DiskIO::init_flag_;

DiskIOThread& DiskIO::instance() {
    std::call_once(init_flag_, []() {
        instance_ = std::make_unique<DiskIOThread>();
        instance_->start();
    });
    return *instance_;
}

} // namespace librats
