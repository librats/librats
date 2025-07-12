#pragma once

#include <string>
#include <iostream>
#include <mutex>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <cstdint>

#ifdef _WIN32
    #include <windows.h>
    #include <io.h>
    #define isatty _isatty
    #define fileno _fileno
    // Undefine Windows ERROR macro to avoid conflicts with our enum
    #ifdef ERROR
        #undef ERROR
    #endif
#else
    #include <unistd.h>
#endif

namespace librats {

enum class LogLevel {
    DEBUG = 0,
    INFO = 1,
    WARN = 2,
    ERROR = 3
};

class Logger {
public:
    // Singleton pattern
    static Logger& getInstance() {
        static Logger instance;
        return instance;
    }
    
    // Delete copy constructor and assignment operator
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
    
    // Set the minimum log level
    void set_log_level(LogLevel level) {
        std::lock_guard<std::mutex> lock(mutex_);
        min_level_ = level;
    }
    
    // Enable/disable colors
    void set_colors_enabled(bool enabled) {
        std::lock_guard<std::mutex> lock(mutex_);
        colors_enabled_ = enabled;
    }
    
    // Enable/disable timestamps
    void set_timestamps_enabled(bool enabled) {
        std::lock_guard<std::mutex> lock(mutex_);
        timestamps_enabled_ = enabled;
    }
    
    // Main logging function
    void log(LogLevel level, const std::string& module, const std::string& message) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        if (level < min_level_) {
            return;
        }
        
        std::ostringstream oss;
        
        // Add timestamp if enabled
        if (timestamps_enabled_) {
            auto now = std::chrono::system_clock::now();
            auto time_t = std::chrono::system_clock::to_time_t(now);
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                now.time_since_epoch()) % 1000;
            
            oss << "[" << std::put_time(std::localtime(&time_t), "%H:%M:%S");
            oss << "." << std::setfill('0') << std::setw(3) << ms.count() << "] ";
        }
        
        // Add colored log level
        if (colors_enabled_ && is_terminal_) {
            oss << get_color_code(level) << "[" << get_level_string(level) << "]" << get_reset_code();
        } else {
            oss << "[" << get_level_string(level) << "]";
        }
        
        // Add colored module tag
        if (!module.empty()) {
            if (colors_enabled_ && is_terminal_) {
                oss << " " << get_module_color(module) << "[" << module << "]" << get_reset_code();
            } else {
                oss << " [" << module << "]";
            }
        }
        
        // Add message
        oss << " " << message << std::endl;
        
        // Output to appropriate stream
        if (level >= LogLevel::ERROR) {
            std::cerr << oss.str();
            std::cerr.flush();
        } else {
            std::cout << oss.str();
            std::cout.flush();
        }
    }

private:
    Logger() : min_level_(LogLevel::INFO), colors_enabled_(true), timestamps_enabled_(true) {
        // Check if we're outputting to a terminal
        is_terminal_ = isatty(fileno(stdout));
        
        // On Windows, enable ANSI color codes
#ifdef _WIN32
        if (is_terminal_) {
            HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
            DWORD dwMode = 0;
            GetConsoleMode(hOut, &dwMode);
            dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            SetConsoleMode(hOut, dwMode);
        }
#endif
    }
    
    std::string get_level_string(LogLevel level) {
        switch (level) {
            case LogLevel::DEBUG: return "DEBUG";
            case LogLevel::INFO:  return "INFO ";
            case LogLevel::WARN:  return "WARN ";
            case LogLevel::ERROR: return "ERROR";
            default: return "UNKNOWN";
        }
    }
    
    std::string get_color_code(LogLevel level) {
        if (!colors_enabled_ || !is_terminal_) return "";
        
        switch (level) {
            case LogLevel::DEBUG: return "\033[36m";  // Cyan
            case LogLevel::INFO:  return "\033[32m";  // Green
            case LogLevel::WARN:  return "\033[33m";  // Yellow
            case LogLevel::ERROR: return "\033[31m";  // Red
            default: return "";
        }
    }
    
    std::string get_module_color(const std::string& module) {
        if (!colors_enabled_ || !is_terminal_) return "";
        
        // Generate hash for module name
        uint32_t hash = hash_string(module);
        
        // Map hash to a predefined set of nice, readable colors
        const char* colors[] = {
            "\033[35m",  // Magenta
            "\033[36m",  // Cyan
            "\033[94m",  // Bright Blue
            "\033[95m",  // Bright Magenta
            "\033[96m",  // Bright Cyan
            "\033[93m",  // Bright Yellow
            "\033[91m",  // Bright Red
            "\033[92m",  // Bright Green
            "\033[90m",  // Bright Black (Gray)
            "\033[37m",  // White
            "\033[34m",  // Blue
            "\033[33m",  // Yellow
            "\033[31m",  // Red
            "\033[32m",  // Green
            "\033[97m",  // Bright White
            "\033[38;5;208m", // Orange
            "\033[38;5;165m", // Pink
            "\033[38;5;141m", // Purple
            "\033[38;5;51m",  // Bright Turquoise
            "\033[38;5;226m", // Bright Yellow
            "\033[38;5;46m",  // Bright Green
            "\033[38;5;196m", // Bright Red
            "\033[38;5;21m",  // Bright Blue
            "\033[38;5;129m"  // Bright Purple
        };
        
        size_t color_count = sizeof(colors) / sizeof(colors[0]);
        return colors[hash % color_count];
    }
    
    // Simple hash function for strings
    uint32_t hash_string(const std::string& str) {
        uint32_t hash = 5381;
        for (char c : str) {
            hash = ((hash << 5) + hash) + c; // hash * 33 + c
        }
        return hash;
    }
    
    std::string get_reset_code() {
        if (!colors_enabled_ || !is_terminal_) return "";
        return "\033[0m";
    }
    
    std::mutex mutex_;
    LogLevel min_level_;
    bool colors_enabled_;
    bool timestamps_enabled_;
    bool is_terminal_;
};

} // namespace librats

// Convenience macros for easy logging
#define LOG_DEBUG(module, message) \
    do { \
        std::ostringstream oss; \
        oss << message; \
        librats::Logger::getInstance().log(librats::LogLevel::DEBUG, module, oss.str()); \
    } while(0)

#define LOG_INFO(module, message) \
    do { \
        std::ostringstream oss; \
        oss << message; \
        librats::Logger::getInstance().log(librats::LogLevel::INFO, module, oss.str()); \
    } while(0)

#define LOG_WARN(module, message) \
    do { \
        std::ostringstream oss; \
        oss << message; \
        librats::Logger::getInstance().log(librats::LogLevel::WARN, module, oss.str()); \
    } while(0)

#define LOG_ERROR(module, message) \
    do { \
        std::ostringstream oss; \
        oss << message; \
        librats::Logger::getInstance().log(librats::LogLevel::ERROR, module, oss.str()); \
    } while(0)

 