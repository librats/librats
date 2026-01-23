#include <gtest/gtest.h>
#include "disk_io.h"
#include "fs.h"
#include "sha1.h"
#include <thread>
#include <chrono>
#include <atomic>
#include <random>

using namespace librats;

class DiskIOTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create test directory
        test_dir_ = "test_disk_io_temp";
        create_directories(test_dir_.c_str());
        
        // Ensure DiskIO is started
        DiskIO::instance().start();
    }
    
    void TearDown() override {
        // Clean up test files
        cleanup_test_directory();
    }
    
    void cleanup_test_directory() {
        // List and delete all files in test directory
        std::vector<DirectoryEntry> entries;
        if (list_directory(test_dir_.c_str(), entries)) {
            for (const auto& entry : entries) {
                if (entry.is_directory) {
                    // Recursively delete subdirectories (simple version)
                    delete_directory(entry.path.c_str());
                } else {
                    delete_file(entry.path.c_str());
                }
            }
        }
        delete_directory(test_dir_.c_str());
    }
    
    std::string test_dir_;
};

// Test basic DiskIOThread creation and start/stop
TEST_F(DiskIOTest, ThreadStartStop) {
    DiskIOThread disk_io;
    
    EXPECT_FALSE(disk_io.is_running());
    
    EXPECT_TRUE(disk_io.start());
    EXPECT_TRUE(disk_io.is_running());
    
    // Starting again should be fine
    EXPECT_TRUE(disk_io.start());
    EXPECT_TRUE(disk_io.is_running());
    
    disk_io.stop();
    EXPECT_FALSE(disk_io.is_running());
    
    // Stopping again should be fine
    disk_io.stop();
    EXPECT_FALSE(disk_io.is_running());
}

// Test singleton instance
TEST_F(DiskIOTest, SingletonInstance) {
    DiskIOThread& instance1 = DiskIO::instance();
    DiskIOThread& instance2 = DiskIO::instance();
    
    EXPECT_EQ(&instance1, &instance2);
    EXPECT_TRUE(instance1.is_running());
}

// Test async block write
TEST_F(DiskIOTest, AsyncWriteBlock) {
    std::string file_path = test_dir_ + "/test_write.bin";
    
    // Pre-create file with size
    ASSERT_TRUE(create_file_with_size(file_path.c_str(), 1024));
    
    // Prepare test data
    std::vector<uint8_t> data(256);
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<uint8_t>(i);
    }
    
    // Create file mapping
    std::vector<FileMappingInfo> mappings;
    FileMappingInfo mapping;
    mapping.path = "test_write.bin";
    mapping.length = 1024;
    mapping.torrent_offset = 0;
    mappings.push_back(mapping);
    
    std::atomic<bool> callback_called(false);
    std::atomic<bool> write_success(false);
    
    DiskIO::instance().async_write_block(
        test_dir_,
        mappings,
        0,      // piece_index
        1024,   // piece_length_standard
        0,      // block_offset
        data,
        [&](bool success) {
            write_success = success;
            callback_called = true;
        }
    );
    
    // Wait for callback
    auto start = std::chrono::steady_clock::now();
    while (!callback_called && 
           std::chrono::steady_clock::now() - start < std::chrono::seconds(5)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    EXPECT_TRUE(callback_called);
    EXPECT_TRUE(write_success);
    
    // Verify data was written
    std::vector<uint8_t> read_buffer(256);
    EXPECT_TRUE(read_file_chunk(file_path.c_str(), 0, read_buffer.data(), read_buffer.size()));
    EXPECT_EQ(data, read_buffer);
}

// Test async piece read
TEST_F(DiskIOTest, AsyncReadPiece) {
    std::string file_path = test_dir_ + "/test_read.bin";
    
    // Create test data and write to file
    std::vector<uint8_t> original_data(512);
    for (size_t i = 0; i < original_data.size(); ++i) {
        original_data[i] = static_cast<uint8_t>((i * 7) % 256);
    }
    ASSERT_TRUE(create_file_binary(file_path.c_str(), original_data.data(), original_data.size()));
    
    // Create file mapping
    std::vector<FileMappingInfo> mappings;
    FileMappingInfo mapping;
    mapping.path = "test_read.bin";
    mapping.length = 512;
    mapping.torrent_offset = 0;
    mappings.push_back(mapping);
    
    std::atomic<bool> callback_called(false);
    std::atomic<bool> read_success(false);
    std::vector<uint8_t> read_data;
    std::mutex data_mutex;
    
    DiskIO::instance().async_read_piece(
        test_dir_,
        mappings,
        0,      // piece_index
        512,    // piece_length_standard
        512,    // actual_piece_length
        [&](bool success, const std::vector<uint8_t>& data) {
            std::lock_guard<std::mutex> lock(data_mutex);
            read_success = success;
            read_data = data;
            callback_called = true;
        }
    );
    
    // Wait for callback
    auto start = std::chrono::steady_clock::now();
    while (!callback_called && 
           std::chrono::steady_clock::now() - start < std::chrono::seconds(5)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    EXPECT_TRUE(callback_called);
    EXPECT_TRUE(read_success);
    
    std::lock_guard<std::mutex> lock(data_mutex);
    EXPECT_EQ(original_data, read_data);
}

// Test async hash piece
TEST_F(DiskIOTest, AsyncHashPiece) {
    std::string file_path = test_dir_ + "/test_hash.bin";
    
    // Create test data - "Hello, World!" repeated
    std::string content = "Hello, World!";
    std::vector<uint8_t> data(content.begin(), content.end());
    ASSERT_TRUE(create_file_binary(file_path.c_str(), data.data(), data.size()));
    
    // Create file mapping
    std::vector<FileMappingInfo> mappings;
    FileMappingInfo mapping;
    mapping.path = "test_hash.bin";
    mapping.length = data.size();
    mapping.torrent_offset = 0;
    mappings.push_back(mapping);
    
    std::atomic<bool> callback_called(false);
    std::atomic<bool> hash_success(false);
    std::string calculated_hash;
    std::mutex hash_mutex;
    
    DiskIO::instance().async_hash_piece(
        test_dir_,
        mappings,
        0,                              // piece_index
        static_cast<uint32_t>(data.size()),  // piece_length_standard
        static_cast<uint32_t>(data.size()),  // actual_piece_length
        [&](bool success, const std::string& hash) {
            std::lock_guard<std::mutex> lock(hash_mutex);
            hash_success = success;
            calculated_hash = hash;
            callback_called = true;
        }
    );
    
    // Wait for callback
    auto start = std::chrono::steady_clock::now();
    while (!callback_called && 
           std::chrono::steady_clock::now() - start < std::chrono::seconds(5)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    EXPECT_TRUE(callback_called);
    EXPECT_TRUE(hash_success);
    
    std::lock_guard<std::mutex> lock(hash_mutex);
    // SHA1 of "Hello, World!" is "0a0a9f2a6772942557ab5355d76af442f8f65e01"
    EXPECT_EQ(calculated_hash, "0a0a9f2a6772942557ab5355d76af442f8f65e01");
}

// Test multi-file piece write (piece spans multiple files)
TEST_F(DiskIOTest, MultiFilePieceWrite) {
    // Create two files
    std::string file1_path = test_dir_ + "/file1.bin";
    std::string file2_path = test_dir_ + "/file2.bin";
    
    ASSERT_TRUE(create_file_with_size(file1_path.c_str(), 100));
    ASSERT_TRUE(create_file_with_size(file2_path.c_str(), 100));
    
    // Create file mappings - file1 at offset 0, file2 at offset 100
    std::vector<FileMappingInfo> mappings;
    
    FileMappingInfo mapping1;
    mapping1.path = "file1.bin";
    mapping1.length = 100;
    mapping1.torrent_offset = 0;
    mappings.push_back(mapping1);
    
    FileMappingInfo mapping2;
    mapping2.path = "file2.bin";
    mapping2.length = 100;
    mapping2.torrent_offset = 100;
    mappings.push_back(mapping2);
    
    // Write a block that spans both files (offset 50, length 100 => 50 in file1, 50 in file2)
    std::vector<uint8_t> data(100);
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<uint8_t>(0xAA + i);
    }
    
    std::atomic<bool> callback_called(false);
    std::atomic<bool> write_success(false);
    
    DiskIO::instance().async_write_block(
        test_dir_,
        mappings,
        0,      // piece_index
        200,    // piece_length_standard (total torrent size)
        50,     // block_offset (starts at byte 50)
        data,
        [&](bool success) {
            write_success = success;
            callback_called = true;
        }
    );
    
    // Wait for callback
    auto start = std::chrono::steady_clock::now();
    while (!callback_called && 
           std::chrono::steady_clock::now() - start < std::chrono::seconds(5)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    EXPECT_TRUE(callback_called);
    EXPECT_TRUE(write_success);
    
    // Verify data in both files
    std::vector<uint8_t> buffer1(50);
    std::vector<uint8_t> buffer2(50);
    
    EXPECT_TRUE(read_file_chunk(file1_path.c_str(), 50, buffer1.data(), 50));
    EXPECT_TRUE(read_file_chunk(file2_path.c_str(), 0, buffer2.data(), 50));
    
    // Check file1 got first 50 bytes
    for (size_t i = 0; i < 50; ++i) {
        EXPECT_EQ(buffer1[i], static_cast<uint8_t>(0xAA + i));
    }
    
    // Check file2 got last 50 bytes
    for (size_t i = 0; i < 50; ++i) {
        EXPECT_EQ(buffer2[i], static_cast<uint8_t>(0xAA + 50 + i));
    }
}

// Test flush operation
TEST_F(DiskIOTest, AsyncFlush) {
    std::atomic<bool> callback_called(false);
    std::atomic<bool> flush_success(false);
    
    DiskIO::instance().async_flush([&](bool success) {
        flush_success = success;
        callback_called = true;
    });
    
    // Wait for callback
    auto start = std::chrono::steady_clock::now();
    while (!callback_called && 
           std::chrono::steady_clock::now() - start < std::chrono::seconds(5)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    EXPECT_TRUE(callback_called);
    EXPECT_TRUE(flush_success);
}

// Test pending jobs count
TEST_F(DiskIOTest, PendingJobsCount) {
    DiskIOThread disk_io;
    disk_io.start();
    
    EXPECT_EQ(disk_io.get_pending_jobs(), 0);
    
    // Queue several jobs
    std::atomic<int> completed_jobs(0);
    const int num_jobs = 5;
    
    for (int i = 0; i < num_jobs; ++i) {
        disk_io.async_flush([&](bool) {
            completed_jobs++;
        });
    }
    
    // Wait for all jobs to complete
    auto start = std::chrono::steady_clock::now();
    while (completed_jobs < num_jobs && 
           std::chrono::steady_clock::now() - start < std::chrono::seconds(5)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    EXPECT_EQ(completed_jobs, num_jobs);
    
    // After completion, pending jobs should be 0
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_EQ(disk_io.get_pending_jobs(), 0);
    
    disk_io.stop();
}

// Test statistics tracking
TEST_F(DiskIOTest, StatisticsTracking) {
    std::string file_path = test_dir_ + "/test_stats.bin";
    
    // Create file
    ASSERT_TRUE(create_file_with_size(file_path.c_str(), 256));
    
    std::vector<FileMappingInfo> mappings;
    FileMappingInfo mapping;
    mapping.path = "test_stats.bin";
    mapping.length = 256;
    mapping.torrent_offset = 0;
    mappings.push_back(mapping);
    
    // Write some data
    std::vector<uint8_t> data(128, 0x55);
    std::atomic<bool> write_done(false);
    
    uint64_t bytes_before_write = DiskIO::instance().get_total_bytes_written();
    
    DiskIO::instance().async_write_block(
        test_dir_,
        mappings,
        0, 256, 0, data,
        [&](bool) { write_done = true; }
    );
    
    // Wait for write
    auto start = std::chrono::steady_clock::now();
    while (!write_done && 
           std::chrono::steady_clock::now() - start < std::chrono::seconds(5)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    uint64_t bytes_after_write = DiskIO::instance().get_total_bytes_written();
    EXPECT_GE(bytes_after_write - bytes_before_write, 128);
    
    // Now read the piece
    std::atomic<bool> read_done(false);
    uint64_t bytes_before_read = DiskIO::instance().get_total_bytes_read();
    
    DiskIO::instance().async_read_piece(
        test_dir_,
        mappings,
        0, 128, 128,
        [&](bool, const std::vector<uint8_t>&) { read_done = true; }
    );
    
    // Wait for read
    start = std::chrono::steady_clock::now();
    while (!read_done && 
           std::chrono::steady_clock::now() - start < std::chrono::seconds(5)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    uint64_t bytes_after_read = DiskIO::instance().get_total_bytes_read();
    EXPECT_GE(bytes_after_read - bytes_before_read, 128);
}

// Test write to non-existent directory (should create file)
TEST_F(DiskIOTest, WriteCreatesFile) {
    std::string subdir = test_dir_ + "/subdir";
    std::string file_path = subdir + "/new_file.bin";
    
    // Create subdirectory
    ASSERT_TRUE(create_directories(subdir.c_str()));
    
    // Prepare data
    std::vector<uint8_t> data(64, 0xBB);
    
    std::vector<FileMappingInfo> mappings;
    FileMappingInfo mapping;
    mapping.path = "subdir/new_file.bin";
    mapping.length = 64;
    mapping.torrent_offset = 0;
    mappings.push_back(mapping);
    
    std::atomic<bool> callback_called(false);
    std::atomic<bool> write_success(false);
    
    DiskIO::instance().async_write_block(
        test_dir_,
        mappings,
        0, 64, 0, data,
        [&](bool success) {
            write_success = success;
            callback_called = true;
        }
    );
    
    // Wait for callback
    auto start = std::chrono::steady_clock::now();
    while (!callback_called && 
           std::chrono::steady_clock::now() - start < std::chrono::seconds(5)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    EXPECT_TRUE(callback_called);
    EXPECT_TRUE(write_success);
    EXPECT_TRUE(file_exists(file_path.c_str()));
}

// Test concurrent writes
TEST_F(DiskIOTest, ConcurrentWrites) {
    const int num_files = 10;
    const int data_size = 256;
    
    // Create files
    for (int i = 0; i < num_files; ++i) {
        std::string file_path = test_dir_ + "/concurrent_" + std::to_string(i) + ".bin";
        ASSERT_TRUE(create_file_with_size(file_path.c_str(), data_size));
    }
    
    std::atomic<int> completed_writes(0);
    std::vector<bool> write_results(num_files, false);
    std::mutex results_mutex;
    
    // Queue concurrent writes
    for (int i = 0; i < num_files; ++i) {
        std::vector<FileMappingInfo> mappings;
        FileMappingInfo mapping;
        mapping.path = "concurrent_" + std::to_string(i) + ".bin";
        mapping.length = data_size;
        mapping.torrent_offset = 0;
        mappings.push_back(mapping);
        
        std::vector<uint8_t> data(data_size, static_cast<uint8_t>(i));
        
        DiskIO::instance().async_write_block(
            test_dir_,
            mappings,
            0, data_size, 0, data,
            [&, i](bool success) {
                std::lock_guard<std::mutex> lock(results_mutex);
                write_results[i] = success;
                completed_writes++;
            }
        );
    }
    
    // Wait for all writes
    auto start = std::chrono::steady_clock::now();
    while (completed_writes < num_files && 
           std::chrono::steady_clock::now() - start < std::chrono::seconds(10)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    EXPECT_EQ(completed_writes, num_files);
    
    // Verify all writes succeeded
    std::lock_guard<std::mutex> lock(results_mutex);
    for (int i = 0; i < num_files; ++i) {
        EXPECT_TRUE(write_results[i]) << "Write " << i << " failed";
    }
    
    // Verify data integrity
    for (int i = 0; i < num_files; ++i) {
        std::string file_path = test_dir_ + "/concurrent_" + std::to_string(i) + ".bin";
        std::vector<uint8_t> buffer(data_size);
        EXPECT_TRUE(read_file_chunk(file_path.c_str(), 0, buffer.data(), data_size));
        
        for (int j = 0; j < data_size; ++j) {
            EXPECT_EQ(buffer[j], static_cast<uint8_t>(i)) 
                << "Data mismatch in file " << i << " at byte " << j;
        }
    }
}

// Test large piece handling
TEST_F(DiskIOTest, LargePieceWrite) {
    std::string file_path = test_dir_ + "/large_file.bin";
    const size_t piece_size = 1024 * 1024;  // 1MB
    
    ASSERT_TRUE(create_file_with_size(file_path.c_str(), piece_size));
    
    std::vector<FileMappingInfo> mappings;
    FileMappingInfo mapping;
    mapping.path = "large_file.bin";
    mapping.length = piece_size;
    mapping.torrent_offset = 0;
    mappings.push_back(mapping);
    
    // Create random data
    std::vector<uint8_t> data(piece_size);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (size_t i = 0; i < piece_size; ++i) {
        data[i] = static_cast<uint8_t>(dis(gen));
    }
    
    std::atomic<bool> write_done(false);
    std::atomic<bool> write_success(false);
    
    DiskIO::instance().async_write_block(
        test_dir_,
        mappings,
        0, static_cast<uint32_t>(piece_size), 0, data,
        [&](bool success) {
            write_success = success;
            write_done = true;
        }
    );
    
    // Wait for write (may take longer for large file)
    auto start = std::chrono::steady_clock::now();
    while (!write_done && 
           std::chrono::steady_clock::now() - start < std::chrono::seconds(30)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    
    EXPECT_TRUE(write_done);
    EXPECT_TRUE(write_success);
    
    // Verify by hashing
    std::atomic<bool> hash_done(false);
    std::string calculated_hash;
    std::mutex hash_mutex;
    
    DiskIO::instance().async_hash_piece(
        test_dir_,
        mappings,
        0, static_cast<uint32_t>(piece_size), static_cast<uint32_t>(piece_size),
        [&](bool success, const std::string& hash) {
            std::lock_guard<std::mutex> lock(hash_mutex);
            if (success) {
                calculated_hash = hash;
            }
            hash_done = true;
        }
    );
    
    start = std::chrono::steady_clock::now();
    while (!hash_done && 
           std::chrono::steady_clock::now() - start < std::chrono::seconds(30)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    
    EXPECT_TRUE(hash_done);
    
    // Calculate expected hash
    std::string expected_hash = SHA1::hash_bytes(data);
    
    std::lock_guard<std::mutex> lock(hash_mutex);
    EXPECT_EQ(calculated_hash, expected_hash);
}
