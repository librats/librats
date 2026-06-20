#include <gtest/gtest.h>

#include "util/logger.h"

#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>

using namespace librats;

namespace {

std::string read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

// The Logger is a process-global singleton, so every test snapshots nothing and
// instead resets it to documented defaults in TearDown, and routes output to a
// private file (console off) so assertions are deterministic and quiet.
class LoggingTest : public ::testing::Test {
protected:
    Logger& log = Logger::getInstance();
    const std::string path = "test_logging_out.log";

    void SetUp() override {
        remove_logs();
        log.set_console_logging_enabled(false);
        log.set_timestamps_enabled(true);
        log.set_log_rotation_size(10 * 1024 * 1024);
        log.set_log_retention_count(5);
        log.set_rotate_on_startup(false);
        log.set_log_level(LogLevel::DEBUG);
    }

    void TearDown() override {
        log.set_file_logging_enabled(false);  // close the handle before deleting
        log.set_log_file_path("");
        log.set_log_level(LogLevel::INFO);
        log.set_console_logging_enabled(true);
        log.set_rotate_on_startup(false);
        log.set_log_rotation_size(10 * 1024 * 1024);
        log.set_log_retention_count(5);
        remove_logs();
    }

    void remove_logs() {
        std::remove(path.c_str());
        for (int i = 1; i <= 6; ++i) std::remove((path + "." + std::to_string(i)).c_str());
    }

    void enable_file() {
        log.set_log_file_path(path);
        log.set_file_logging_enabled(true);
    }
};

} // namespace

// The minimum level actually filters: messages below it never reach the sink.
TEST_F(LoggingTest, LevelFilteringDropsLowerLevels) {
    log.set_log_level(LogLevel::WARN);
    enable_file();

    LOG_DEBUG("filt", "debug-line");
    LOG_INFO("filt", "info-line");
    LOG_WARN("filt", "warn-line");
    LOG_ERROR("filt", "error-line");
    log.set_file_logging_enabled(false);  // flush + close

    const std::string out = read_file(path);
    EXPECT_FALSE(contains(out, "debug-line")) << "DEBUG leaked past WARN threshold";
    EXPECT_FALSE(contains(out, "info-line"))  << "INFO leaked past WARN threshold";
    EXPECT_TRUE(contains(out, "warn-line"));
    EXPECT_TRUE(contains(out, "error-line"));
}

// The file path round-trips through the getter and output is actually written.
TEST_F(LoggingTest, FilePathSetGetAndWrites) {
    log.set_log_file_path(path);
    EXPECT_EQ(log.get_log_file_path(), path);
    log.set_file_logging_enabled(true);
    EXPECT_TRUE(log.is_file_logging_enabled());

    LOG_INFO("netmon", "started up");
    log.set_file_logging_enabled(false);

    const std::string out = read_file(path);
    EXPECT_TRUE(contains(out, "netmon"));      // module tag present
    EXPECT_TRUE(contains(out, "started up"));  // message present
}

// File lines carry a timestamp + level + module tag, and never ANSI colour codes.
TEST_F(LoggingTest, FileLineFormat) {
    enable_file();
    LOG_WARN("fmt", "shape-check");
    log.set_file_logging_enabled(false);

    const std::string out = read_file(path);
    ASSERT_FALSE(out.empty());
    EXPECT_TRUE(contains(out, "[WARN ]"));        // padded level tag
    EXPECT_TRUE(contains(out, "[fmt]"));          // module tag
    EXPECT_TRUE(contains(out, "shape-check"));
    EXPECT_TRUE(contains(out, "[20"));            // a 20xx timestamp (file lines always stamp)
    EXPECT_EQ(out.find('\033'), std::string::npos) << "ANSI colour codes must not reach the file";
}

// Crossing the rotation size threshold rolls the active file over to ".1".
TEST_F(LoggingTest, SizeBasedRotation) {
    log.set_log_rotation_size(1024);   // tiny, so a handful of lines trips it
    log.set_log_retention_count(3);
    enable_file();

    const std::string filler(200, 'x');
    for (int i = 0; i < 40; ++i) LOG_ERROR("rot", filler << " " << i);
    log.set_file_logging_enabled(false);

    EXPECT_TRUE(std::ifstream(path + ".1").good()) << "no rotated .1 file was produced";
}

// rotate_on_startup is off by default and reflects its setter.
TEST_F(LoggingTest, RotateOnStartupToggle) {
    EXPECT_FALSE(log.is_rotate_on_startup_enabled());
    log.set_rotate_on_startup(true);
    EXPECT_TRUE(log.is_rotate_on_startup_enabled());
    log.set_rotate_on_startup(false);
    EXPECT_FALSE(log.is_rotate_on_startup_enabled());
}

// With rotate_on_startup enabled, opening over a non-empty existing log preserves
// the old content as ".1" before the fresh session begins.
TEST_F(LoggingTest, RotateOnStartupRotatesExistingLog) {
    // Seed a non-empty log file at the path.
    { std::ofstream seed(path, std::ios::binary); seed << "previous session line\n"; }
    ASSERT_TRUE(std::ifstream(path).good());

    log.set_rotate_on_startup(true);
    enable_file();  // opening triggers the startup rotation
    LOG_INFO("startup", "fresh session");
    log.set_file_logging_enabled(false);

    EXPECT_TRUE(std::ifstream(path + ".1").good()) << "existing log was not rotated to .1";
    EXPECT_TRUE(contains(read_file(path + ".1"), "previous session line"));
    EXPECT_TRUE(contains(read_file(path), "fresh session"));  // new file holds the new line
}
