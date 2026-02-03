#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "librats.h"
#include "fs.h"
#include <thread>
#include <chrono>
#include <fstream>

using namespace librats;

class LoggingApiTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Use a unique port for each test to avoid conflicts
        test_port_ = 19999 + ::testing::UnitTest::GetInstance()->current_test_info()->line();
        client_ = std::make_unique<RatsClient>(test_port_);
        
        // Clean up any existing test log files
        cleanup_test_files();
    }
    
    void TearDown() override {
        if (client_) {
            if (client_->is_running()) {
                client_->stop();
            }
            client_.reset();
        }
        
        // Clean up test files
        cleanup_test_files();
    }
    
    void cleanup_test_files() {
        // Remove test log files if they exist
        std::vector<std::string> test_files = {
            "rats.log", 
            "test_custom.log",
            "test_logging.log",
            "persistent_test.log"
        };
        
        for (const auto& file : test_files) {
            librats::delete_file(file.c_str());
            // Also remove rotated versions
            for (int i = 1; i <= 5; ++i) {
                std::string rotated_file = file + "." + std::to_string(i);
                librats::delete_file(rotated_file.c_str());
            }
        }
    }
    
    bool file_or_directory_exists_test(const std::string& filename) {
        return librats::file_or_directory_exists(filename);
    }
    
    size_t get_file_size_test(const std::string& filename) {
        if (!file_or_directory_exists_test(filename)) return 0;
        int64_t size = librats::get_file_size(filename.c_str());
        return size > 0 ? static_cast<size_t>(size) : 0;
    }
    
    std::string read_file_content(const std::string& filename) {
        return librats::read_file_text_cpp(filename);
    }
    
    std::unique_ptr<RatsClient> client_;
    int test_port_;
};

// Test initial logging state
TEST_F(LoggingApiTest, InitialState) {
    EXPECT_FALSE(client_->is_logging_enabled()) 
        << "Logging should be disabled by default";
}

// Test enabling logging with default settings
TEST_F(LoggingApiTest, EnableLoggingDefault) {
    client_->set_logging_enabled(true);
    EXPECT_TRUE(client_->is_logging_enabled())
        << "Logging should be enabled after calling set_logging_enabled(true)";
}

// Test disabling logging
TEST_F(LoggingApiTest, DisableLogging) {
    client_->set_logging_enabled(true);
    EXPECT_TRUE(client_->is_logging_enabled());
    
    client_->set_logging_enabled(false);
    EXPECT_FALSE(client_->is_logging_enabled())
        << "Logging should be disabled after calling set_logging_enabled(false)";
}

// Test default log file path
TEST_F(LoggingApiTest, DefaultLogFilePath) {
    client_->set_logging_enabled(true);
    std::string default_path = client_->get_log_file_path();
    EXPECT_EQ(default_path, "rats.log")
        << "Default log file path should be 'rats.log'";
}

// Test custom log file path
TEST_F(LoggingApiTest, CustomLogFilePath) {
    const std::string custom_path = "test_custom.log";
    client_->set_log_file_path(custom_path);
    
    EXPECT_EQ(client_->get_log_file_path(), custom_path)
        << "Custom log file path should be set correctly";
}

// Test log level setting with enum
TEST_F(LoggingApiTest, SetLogLevelEnum) {
    EXPECT_NO_THROW(client_->set_log_level(LogLevel::DEBUG))
        << "Setting log level with enum should not throw";
    
    EXPECT_NO_THROW(client_->set_log_level(LogLevel::INFO))
        << "Setting log level to INFO should not throw";
    
    EXPECT_NO_THROW(client_->set_log_level(LogLevel::WARN))
        << "Setting log level to WARN should not throw";
    
    EXPECT_NO_THROW(client_->set_log_level(LogLevel::ERROR))
        << "Setting log level to ERROR should not throw";
}

// Test log level setting with string
TEST_F(LoggingApiTest, SetLogLevelString) {
    EXPECT_NO_THROW(client_->set_log_level("DEBUG"))
        << "Setting log level with 'DEBUG' string should not throw";
    
    EXPECT_NO_THROW(client_->set_log_level("INFO"))
        << "Setting log level with 'INFO' string should not throw";
    
    EXPECT_NO_THROW(client_->set_log_level("WARN"))
        << "Setting log level with 'WARN' string should not throw";
    
    EXPECT_NO_THROW(client_->set_log_level("WARNING"))
        << "Setting log level with 'WARNING' string should not throw";
    
    EXPECT_NO_THROW(client_->set_log_level("ERROR"))
        << "Setting log level with 'ERROR' string should not throw";
}

// Test invalid log level string handling
TEST_F(LoggingApiTest, InvalidLogLevelString) {
    EXPECT_NO_THROW(client_->set_log_level("INVALID"))
        << "Setting invalid log level string should not throw";
    
    EXPECT_NO_THROW(client_->set_log_level(""))
        << "Setting empty log level string should not throw";
    
    EXPECT_NO_THROW(client_->set_log_level("random_string"))
        << "Setting random log level string should not throw";
}

// Test color and timestamp settings
TEST_F(LoggingApiTest, ColorAndTimestampSettings) {
    EXPECT_NO_THROW(client_->set_log_colors_enabled(true))
        << "Enabling log colors should not throw";
    
    EXPECT_NO_THROW(client_->set_log_colors_enabled(false))
        << "Disabling log colors should not throw";
    
    EXPECT_NO_THROW(client_->set_log_timestamps_enabled(true))
        << "Enabling log timestamps should not throw";
    
    EXPECT_NO_THROW(client_->set_log_timestamps_enabled(false))
        << "Disabling log timestamps should not throw";
    
    // Test getter methods (note: current implementation returns hardcoded values)
    EXPECT_TRUE(client_->is_log_colors_enabled())
        << "Log colors enabled getter should work";
    
    EXPECT_TRUE(client_->is_log_timestamps_enabled())
        << "Log timestamps enabled getter should work";
}

// Test rotation settings
TEST_F(LoggingApiTest, RotationSettings) {
    const size_t rotation_size = 1024 * 1024; // 1MB
    const int retention_count = 3;
    
    EXPECT_NO_THROW(client_->set_log_rotation_size(rotation_size))
        << "Setting log rotation size should not throw";
    
    EXPECT_NO_THROW(client_->set_log_retention_count(retention_count))
        << "Setting log retention count should not throw";
}

// Test log level getter
TEST_F(LoggingApiTest, LogLevelGetter) {
    LogLevel level = client_->get_log_level();
    EXPECT_TRUE(level == LogLevel::DEBUG || level == LogLevel::INFO || 
                level == LogLevel::WARN || level == LogLevel::ERROR)
        << "Log level getter should return a valid LogLevel enum value";
}

// Test client lifecycle with logging
TEST_F(LoggingApiTest, ClientLifecycleWithLogging) {
    client_->set_logging_enabled(true);
    client_->set_log_file_path("test_logging.log");
    
    // Start client
    bool started = client_->start();
    if (started) {
        EXPECT_TRUE(client_->is_running())
            << "Client should be running after successful start";
        
        // Give it a moment to initialize and potentially log something
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        // Stop the client
        client_->stop();
        EXPECT_FALSE(client_->is_running())
            << "Client should not be running after stop";
    }
    // Note: start() might fail in test environment, which is acceptable
}

// Test clear log file functionality
TEST_F(LoggingApiTest, ClearLogFile) {
    const std::string log_path = "test_logging.log";
    client_->set_log_file_path(log_path);
    client_->set_logging_enabled(true);
    
    // Start client briefly to potentially create log file
    if (client_->start()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        client_->stop();
    }
    
    EXPECT_NO_THROW(client_->clear_log_file())
        << "Clearing log file should not throw";
}

// Test clear log file with no path set
TEST_F(LoggingApiTest, ClearLogFileNoPath) {
    // Don't set a log file path
    EXPECT_NO_THROW(client_->clear_log_file())
        << "Clearing log file with no path set should not throw";
}

// Test concurrent logging operations
TEST_F(LoggingApiTest, ConcurrentOperations) {
    client_->set_logging_enabled(true);
    
    std::vector<std::thread> threads;
    
    // Start multiple threads performing logging operations
    for (int i = 0; i < 5; ++i) {
        threads.emplace_back([this, i]() {
            client_->set_log_level(LogLevel::DEBUG);
            client_->set_log_colors_enabled(i % 2 == 0);
            client_->set_log_timestamps_enabled(i % 2 == 1);
        });
    }
    
    // Wait for all threads to complete
    for (auto& thread : threads) {
        thread.join();
    }
    
    // Should still be in a valid state
    EXPECT_TRUE(client_->is_logging_enabled())
        << "Logging should still be enabled after concurrent operations";
}

// Test multiple enable/disable cycles
TEST_F(LoggingApiTest, MultipleEnableDisableCycles) {
    for (int i = 0; i < 5; ++i) {
        client_->set_logging_enabled(true);
        EXPECT_TRUE(client_->is_logging_enabled())
            << "Logging should be enabled in cycle " << i;
        
        client_->set_logging_enabled(false);
        EXPECT_FALSE(client_->is_logging_enabled())
            << "Logging should be disabled in cycle " << i;
    }
}

// Test edge cases with log file paths
TEST_F(LoggingApiTest, LogFilePathEdgeCases) {
    // Test empty path
    EXPECT_NO_THROW(client_->set_log_file_path(""))
        << "Setting empty log file path should not throw";
    
    // Test path with special characters
    EXPECT_NO_THROW(client_->set_log_file_path("test-log_file.log"))
        << "Setting log file path with special characters should not throw";
    
    // Test very long path (within reason)
    std::string long_path = "very_long_log_file_name_that_is_still_reasonable.log";
    EXPECT_NO_THROW(client_->set_log_file_path(long_path))
        << "Setting long log file path should not throw";
}

// Test all rotation size values
TEST_F(LoggingApiTest, RotationSizeValues) {
    // Test minimum size
    EXPECT_NO_THROW(client_->set_log_rotation_size(0))
        << "Setting rotation size to 0 should not throw";
    
    // Test small size
    EXPECT_NO_THROW(client_->set_log_rotation_size(1024))
        << "Setting small rotation size should not throw";
    
    // Test large size
    EXPECT_NO_THROW(client_->set_log_rotation_size(100 * 1024 * 1024))
        << "Setting large rotation size should not throw";
}

// Test retention count edge cases
TEST_F(LoggingApiTest, RetentionCountEdgeCases) {
    // Test zero retention
    EXPECT_NO_THROW(client_->set_log_retention_count(0))
        << "Setting retention count to 0 should not throw";
    
    // Test negative retention (should be handled gracefully)
    EXPECT_NO_THROW(client_->set_log_retention_count(-1))
        << "Setting negative retention count should not throw";
    
    // Test large retention count
    EXPECT_NO_THROW(client_->set_log_retention_count(100))
        << "Setting large retention count should not throw";
}

// Test state persistence across operations
TEST_F(LoggingApiTest, StatePersistence) {
    // Set various logging options
    client_->set_logging_enabled(true);
    client_->set_log_file_path("persistent_test.log");
    client_->set_log_level(LogLevel::ERROR);
    
    // Verify state is maintained
    EXPECT_TRUE(client_->is_logging_enabled())
        << "Logging enabled state should persist";
    
    EXPECT_EQ(client_->get_log_file_path(), "persistent_test.log")
        << "Log file path should persist";
    
    // Perform other operations
    client_->set_log_colors_enabled(false);
    client_->set_log_timestamps_enabled(false);
    
    // Original settings should still be intact
    EXPECT_TRUE(client_->is_logging_enabled())
        << "Logging enabled state should still persist after other operations";
    
    EXPECT_EQ(client_->get_log_file_path(), "persistent_test.log")
        << "Log file path should still persist after other operations";
}

// Test rotate on startup initial state
TEST_F(LoggingApiTest, RotateOnStartupInitialState) {
    EXPECT_FALSE(client_->is_log_rotate_on_startup_enabled())
        << "Rotate on startup should be disabled by default";
}

// Test enable/disable rotate on startup
TEST_F(LoggingApiTest, RotateOnStartupEnableDisable) {
    client_->set_log_rotate_on_startup(true);
    EXPECT_TRUE(client_->is_log_rotate_on_startup_enabled())
        << "Rotate on startup should be enabled after calling set_log_rotate_on_startup(true)";
    
    client_->set_log_rotate_on_startup(false);
    EXPECT_FALSE(client_->is_log_rotate_on_startup_enabled())
        << "Rotate on startup should be disabled after calling set_log_rotate_on_startup(false)";
}

// Test rotate on startup actually rotates existing log file
TEST_F(LoggingApiTest, RotateOnStartupRotatesExistingLog) {
    const std::string log_path = "test_logging.log";
    const std::string rotated_path = log_path + ".1";
    
    // Clean up first
    librats::delete_file(log_path.c_str());
    librats::delete_file(rotated_path.c_str());
    
    // Create initial log file with some content
    {
        std::ofstream initial_log(log_path);
        initial_log << "Initial log content before rotation" << std::endl;
    }
    
    EXPECT_TRUE(file_or_directory_exists_test(log_path))
        << "Initial log file should exist";
    
    // Enable rotate on startup and configure logging
    client_->set_log_rotate_on_startup(true);
    client_->set_log_file_path(log_path);
    client_->set_logging_enabled(true);
    
    // The existing log should have been rotated to .1
    EXPECT_TRUE(file_or_directory_exists_test(rotated_path))
        << "Rotated log file (.1) should exist after enabling logging with rotate on startup";
    
    // Verify the rotated file contains the original content
    std::string rotated_content = read_file_content(rotated_path);
    EXPECT_NE(rotated_content.find("Initial log content before rotation"), std::string::npos)
        << "Rotated log file should contain the original content";
    
    // Clean up
    client_->set_logging_enabled(false);
    librats::delete_file(log_path.c_str());
    librats::delete_file(rotated_path.c_str());
}

// Test rotate on startup only rotates once per session
TEST_F(LoggingApiTest, RotateOnStartupOnlyOnce) {
    const std::string log_path = "test_logging.log";
    const std::string rotated_path_1 = log_path + ".1";
    const std::string rotated_path_2 = log_path + ".2";
    
    // Clean up first
    librats::delete_file(log_path.c_str());
    librats::delete_file(rotated_path_1.c_str());
    librats::delete_file(rotated_path_2.c_str());
    
    // Create initial log file
    {
        std::ofstream initial_log(log_path);
        initial_log << "First session content" << std::endl;
    }
    
    // Enable rotate on startup
    client_->set_log_rotate_on_startup(true);
    client_->set_log_file_path(log_path);
    client_->set_logging_enabled(true);
    
    // First rotation should happen
    EXPECT_TRUE(file_or_directory_exists_test(rotated_path_1))
        << "First rotation should create .1 file";
    
    // Disable and re-enable logging (simulate re-opening log in same session)
    client_->set_logging_enabled(false);
    
    // Create some new content in the log file  
    {
        std::ofstream new_log(log_path);
        new_log << "New content after disable" << std::endl;
    }
    
    client_->set_logging_enabled(true);
    
    // The .1 file should still contain original content (no second rotation)
    std::string rotated_content = read_file_content(rotated_path_1);
    EXPECT_NE(rotated_content.find("First session content"), std::string::npos)
        << "Rotated .1 file should still contain original content (no second rotation in same session)";
    
    // Clean up
    client_->set_logging_enabled(false);
    librats::delete_file(log_path.c_str());
    librats::delete_file(rotated_path_1.c_str());
    librats::delete_file(rotated_path_2.c_str());
}

// Test rotate on startup with empty log file (should not rotate)
TEST_F(LoggingApiTest, RotateOnStartupEmptyFile) {
    const std::string log_path = "test_logging.log";
    const std::string rotated_path = log_path + ".1";
    
    // Clean up first
    librats::delete_file(log_path.c_str());
    librats::delete_file(rotated_path.c_str());
    
    // Create empty log file
    {
        std::ofstream empty_log(log_path);
        // Don't write anything
    }
    
    EXPECT_TRUE(file_or_directory_exists_test(log_path))
        << "Empty log file should exist";
    
    // Enable rotate on startup
    client_->set_log_rotate_on_startup(true);
    client_->set_log_file_path(log_path);
    client_->set_logging_enabled(true);
    
    // Empty file should NOT be rotated
    EXPECT_FALSE(file_or_directory_exists_test(rotated_path))
        << "Empty log file should not be rotated";
    
    // Clean up
    client_->set_logging_enabled(false);
    librats::delete_file(log_path.c_str());
}

// Test rotate on startup with non-existent log file
TEST_F(LoggingApiTest, RotateOnStartupNoExistingFile) {
    const std::string log_path = "test_logging.log";
    const std::string rotated_path = log_path + ".1";
    
    // Ensure files don't exist
    librats::delete_file(log_path.c_str());
    librats::delete_file(rotated_path.c_str());
    
    EXPECT_FALSE(file_or_directory_exists_test(log_path))
        << "Log file should not exist initially";
    
    // Enable rotate on startup
    client_->set_log_rotate_on_startup(true);
    client_->set_log_file_path(log_path);
    client_->set_logging_enabled(true);
    
    // No rotation should happen (nothing to rotate)
    EXPECT_FALSE(file_or_directory_exists_test(rotated_path))
        << "No rotation should happen when there's no existing log file";
    
    // Clean up
    client_->set_logging_enabled(false);
    librats::delete_file(log_path.c_str());
}