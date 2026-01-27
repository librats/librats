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
// DiskIOThreadPool Implementation
//=============================================================================

DiskIOThreadPool::DiskIOThreadPool(const DiskIOConfig& config)
    : config_(config)
    , running_(false)
    , num_write_threads_(config.num_write_threads)
    , num_read_threads_(config.num_read_threads)
    , total_bytes_written_(0)
    , total_bytes_read_(0)
    , jobs_completed_(0)
    , under_pressure_(false) {
}

DiskIOThreadPool::~DiskIOThreadPool() {
    stop();
}

bool DiskIOThreadPool::start() {
    if (running_.load()) {
        return true;
    }
    
    running_.store(true);
    
    // Start worker threads
    start_write_threads(num_write_threads_.load());
    start_read_threads(num_read_threads_.load());
    
    LOG_DISK_INFO("Disk I/O thread pool started with " 
                  << num_write_threads_.load() << " write threads and "
                  << num_read_threads_.load() << " read threads");
    return true;
}

void DiskIOThreadPool::stop() {
    if (!running_.load()) {
        return;
    }
    
    running_.store(false);
    
    // Wake up all waiting threads
    write_cv_.notify_all();
    read_cv_.notify_all();
    
    // Wait for all threads to finish
    stop_write_threads();
    stop_read_threads();
    
    LOG_DISK_INFO("Disk I/O thread pool stopped. Total jobs completed: " << jobs_completed_.load());
}

void DiskIOThreadPool::set_num_write_threads(int count) {
    if (count < 1) count = 1;
    int old_count = num_write_threads_.exchange(count);
    
    if (!running_.load()) return;
    
    if (count > old_count) {
        // Start additional threads
        start_write_threads(count - old_count);
    }
    // Note: Reducing threads happens naturally when threads check the count
}

void DiskIOThreadPool::set_num_read_threads(int count) {
    if (count < 1) count = 1;
    int old_count = num_read_threads_.exchange(count);
    
    if (!running_.load()) return;
    
    if (count > old_count) {
        // Start additional threads
        start_read_threads(count - old_count);
    }
}

void DiskIOThreadPool::start_write_threads(int count) {
    std::lock_guard<std::mutex> lock(write_mutex_);
    for (int i = 0; i < count; ++i) {
        write_threads_.emplace_back(&DiskIOThreadPool::write_worker_loop, this);
    }
}

void DiskIOThreadPool::start_read_threads(int count) {
    std::lock_guard<std::mutex> lock(read_mutex_);
    for (int i = 0; i < count; ++i) {
        read_threads_.emplace_back(&DiskIOThreadPool::read_worker_loop, this);
    }
}

void DiskIOThreadPool::stop_write_threads() {
    for (auto& t : write_threads_) {
        if (t.joinable()) {
            t.join();
        }
    }
    write_threads_.clear();
}

void DiskIOThreadPool::stop_read_threads() {
    for (auto& t : read_threads_) {
        if (t.joinable()) {
            t.join();
        }
    }
    read_threads_.clear();
}

//=============================================================================
// Async Job Submission
//=============================================================================

void DiskIOThreadPool::async_write_block(
    const std::string& download_path,
    const std::vector<FileMappingInfo>& files,
    uint32_t piece_index,
    uint32_t piece_length_standard,
    uint32_t block_offset,
    const std::vector<uint8_t>& data,
    WriteCompleteCallback callback,
    DiskJobPriority priority)
{
    DiskJob job;
    job.type = DiskJobType::WRITE_BLOCK;
    job.priority = priority;
    job.piece_index = piece_index;
    job.offset = block_offset;
    job.download_path = download_path;
    job.data = data;  // Copy the data
    job.piece_length = piece_length_standard;
    job.piece_offset_in_torrent = static_cast<uint64_t>(piece_index) * piece_length_standard;
    job.write_callback = callback;
    job.file_mappings = files;
    
    {
        std::lock_guard<std::mutex> lock(write_mutex_);
        write_queue_.push(std::move(job));
    }
    write_cv_.notify_one();
    
    LOG_DISK_DEBUG("Queued write block: piece " << piece_index << " offset " << block_offset 
                   << " size " << data.size());
}

void DiskIOThreadPool::async_read_piece(
    const std::string& download_path,
    const std::vector<FileMappingInfo>& files,
    uint32_t piece_index,
    uint32_t piece_length_standard,
    uint32_t actual_piece_length,
    ReadCompleteCallback callback,
    DiskJobPriority priority)
{
    DiskJob job;
    job.type = DiskJobType::READ_PIECE;
    job.priority = priority;
    job.piece_index = piece_index;
    job.download_path = download_path;
    job.piece_length = actual_piece_length;
    job.piece_offset_in_torrent = static_cast<uint64_t>(piece_index) * piece_length_standard;
    job.read_callback = callback;
    job.file_mappings = files;
    
    {
        std::lock_guard<std::mutex> lock(read_mutex_);
        read_queue_.push(std::move(job));
    }
    read_cv_.notify_one();
    
    LOG_DISK_DEBUG("Queued read piece: piece " << piece_index << " length " << actual_piece_length);
}

void DiskIOThreadPool::async_hash_piece(
    const std::string& download_path,
    const std::vector<FileMappingInfo>& files,
    uint32_t piece_index,
    uint32_t piece_length_standard,
    uint32_t actual_piece_length,
    HashCompleteCallback callback,
    DiskJobPriority priority)
{
    DiskJob job;
    job.type = DiskJobType::HASH_PIECE;
    job.priority = priority;
    job.piece_index = piece_index;
    job.download_path = download_path;
    job.piece_length = actual_piece_length;
    job.piece_offset_in_torrent = static_cast<uint64_t>(piece_index) * piece_length_standard;
    job.hash_callback = callback;
    job.file_mappings = files;
    
    {
        std::lock_guard<std::mutex> lock(read_mutex_);
        read_queue_.push(std::move(job));
    }
    read_cv_.notify_one();
    
    LOG_DISK_DEBUG("Queued hash piece: piece " << piece_index << " length " << actual_piece_length);
}

void DiskIOThreadPool::async_flush(FlushCompleteCallback callback) {
    // Flush goes to write queue with high priority
    DiskJob job;
    job.type = DiskJobType::FLUSH;
    job.priority = DiskJobPriority::HIGH;
    job.flush_callback = callback;
    
    {
        std::lock_guard<std::mutex> lock(write_mutex_);
        write_queue_.push(std::move(job));
    }
    write_cv_.notify_one();
    
    LOG_DISK_DEBUG("Queued flush operation");
}

//=============================================================================
// Statistics
//=============================================================================

size_t DiskIOThreadPool::get_pending_write_jobs() const {
    std::lock_guard<std::mutex> lock(write_mutex_);
    return write_queue_.size();
}

size_t DiskIOThreadPool::get_pending_read_jobs() const {
    std::lock_guard<std::mutex> lock(read_mutex_);
    return read_queue_.size();
}

size_t DiskIOThreadPool::get_total_pending_jobs() const {
    return get_pending_write_jobs() + get_pending_read_jobs();
}

//=============================================================================
// Backpressure Control
//=============================================================================

bool DiskIOThreadPool::can_accept_write() const {
    size_t pending = get_pending_write_jobs();
    size_t high_mark = static_cast<size_t>(config_.max_pending_jobs * config_.high_watermark_percent / 100);
    size_t low_mark = static_cast<size_t>(config_.max_pending_jobs * config_.low_watermark_percent / 100);
    
    // Hysteresis: once under pressure, stay under pressure until below low watermark
    if (under_pressure_.load()) {
        if (pending <= low_mark) {
            under_pressure_.store(false);
            LOG_DISK_DEBUG("Disk I/O backpressure released, pending jobs: " << pending);
            return true;
        }
        return false;
    } else {
        if (pending >= high_mark) {
            under_pressure_.store(true);
            LOG_DISK_DEBUG("Disk I/O under backpressure, pending jobs: " << pending);
            return false;
        }
        return true;
    }
}

//=============================================================================
// Worker Loops
//=============================================================================

void DiskIOThreadPool::write_worker_loop() {
    LOG_DISK_DEBUG("Write worker thread started");
    
    while (running_.load()) {
        DiskJob job;
        
        {
            std::unique_lock<std::mutex> lock(write_mutex_);
            
            // Wait for a job or shutdown
            write_cv_.wait(lock, [this] {
                return !write_queue_.empty() || !running_.load();
            });
            
            if (!running_.load() && write_queue_.empty()) {
                break;
            }
            
            if (!write_queue_.empty()) {
                job = std::move(const_cast<DiskJob&>(write_queue_.top()));
                write_queue_.pop();
            } else {
                continue;
            }
        }
        
        // Execute the job outside the lock
        switch (job.type) {
            case DiskJobType::WRITE_BLOCK:
                execute_write_block(job);
                break;
            case DiskJobType::FLUSH:
                execute_flush(job);
                break;
            default:
                LOG_DISK_WARN("Invalid job type in write queue: " << static_cast<int>(job.type));
                break;
        }
        
        jobs_completed_++;
    }
    
    LOG_DISK_DEBUG("Write worker thread ended");
}

void DiskIOThreadPool::read_worker_loop() {
    LOG_DISK_DEBUG("Read worker thread started");
    
    while (running_.load()) {
        DiskJob job;
        
        {
            std::unique_lock<std::mutex> lock(read_mutex_);
            
            // Wait for a job or shutdown
            read_cv_.wait(lock, [this] {
                return !read_queue_.empty() || !running_.load();
            });
            
            if (!running_.load() && read_queue_.empty()) {
                break;
            }
            
            if (!read_queue_.empty()) {
                job = std::move(const_cast<DiskJob&>(read_queue_.top()));
                read_queue_.pop();
            } else {
                continue;
            }
        }
        
        // Execute the job outside the lock
        switch (job.type) {
            case DiskJobType::READ_PIECE:
                execute_read_piece(job);
                break;
            case DiskJobType::HASH_PIECE:
                execute_hash_piece(job);
                break;
            default:
                LOG_DISK_WARN("Invalid job type in read queue: " << static_cast<int>(job.type));
                break;
        }
        
        jobs_completed_++;
    }
    
    LOG_DISK_DEBUG("Read worker thread ended");
}

//=============================================================================
// File Mapping Helper
//=============================================================================

std::vector<std::tuple<std::string, uint64_t, size_t>> DiskIOThreadPool::map_to_files(
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
        uint64_t read_start_in_torrent = (std::max)(current_offset, file.torrent_offset);
        uint64_t read_end_in_torrent = (std::min)(current_offset + remaining, file_end);
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

//=============================================================================
// Job Execution
//=============================================================================

void DiskIOThreadPool::execute_write_block(const DiskJob& job) {
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

void DiskIOThreadPool::execute_read_piece(const DiskJob& job) {
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

void DiskIOThreadPool::execute_hash_piece(const DiskJob& job) {
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

void DiskIOThreadPool::execute_flush(const DiskJob& job) {
    // On most systems, writes are already flushed when write_file_chunk returns
    // For additional safety, we could call fsync() here, but it's costly
    
    LOG_DISK_DEBUG("Flush complete");
    
    if (job.flush_callback) {
        job.flush_callback(true);
    }
}

//=============================================================================
// Legacy DiskIOThread Implementation (wrapper around DiskIOThreadPool)
//=============================================================================

DiskIOThread::DiskIOThread()
    : pool_(std::make_unique<DiskIOThreadPool>()) {
}

DiskIOThread::~DiskIOThread() {
    stop();
}

bool DiskIOThread::start() {
    return pool_->start();
}

void DiskIOThread::stop() {
    pool_->stop();
}

bool DiskIOThread::is_running() const {
    return pool_->is_running();
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
    pool_->async_write_block(download_path, files, piece_index, piece_length_standard,
                             block_offset, data, callback);
}

void DiskIOThread::async_read_piece(
    const std::string& download_path,
    const std::vector<FileMappingInfo>& files,
    uint32_t piece_index,
    uint32_t piece_length_standard,
    uint32_t actual_piece_length,
    ReadCompleteCallback callback)
{
    pool_->async_read_piece(download_path, files, piece_index, piece_length_standard,
                            actual_piece_length, callback);
}

void DiskIOThread::async_hash_piece(
    const std::string& download_path,
    const std::vector<FileMappingInfo>& files,
    uint32_t piece_index,
    uint32_t piece_length_standard,
    uint32_t actual_piece_length,
    HashCompleteCallback callback)
{
    pool_->async_hash_piece(download_path, files, piece_index, piece_length_standard,
                            actual_piece_length, callback);
}

void DiskIOThread::async_flush(FlushCompleteCallback callback) {
    pool_->async_flush(callback);
}

size_t DiskIOThread::get_pending_jobs() const {
    return pool_->get_total_pending_jobs();
}

uint64_t DiskIOThread::get_total_bytes_written() const {
    return pool_->get_total_bytes_written();
}

uint64_t DiskIOThread::get_total_bytes_read() const {
    return pool_->get_total_bytes_read();
}

//=============================================================================
// DiskIO Singleton Implementation
//=============================================================================

std::unique_ptr<DiskIOThreadPool> DiskIO::instance_;
std::once_flag DiskIO::init_flag_;
DiskIOConfig DiskIO::config_;

void DiskIO::configure(const DiskIOConfig& config) {
    config_ = config;
}

DiskIOThreadPool& DiskIO::instance() {
    std::call_once(init_flag_, []() {
        instance_ = std::make_unique<DiskIOThreadPool>(config_);
        instance_->start();
    });
    return *instance_;
}

} // namespace librats
