#pragma once

#include <string>
#include <iostream>
#include <mutex>
#include <sstream>
#include <chrono>
#include <iomanip>

#ifdef _WIN32
    #include <windows.h>
    #include <io.h>
    #define isatty _isatty
    #define fileno _fileno
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
                oss << " " << get_module_color() << "[" << module << "]" << get_reset_code();
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
    
    std::string get_module_color() {
        if (!colors_enabled_ || !is_terminal_) return "";
        return "\033[35m";  // Magenta
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

// Module-specific macros for common modules
#define LOG_NETWORK_DEBUG(message) LOG_DEBUG("NETWORK", message)
#define LOG_NETWORK_INFO(message)  LOG_INFO("NETWORK", message)
#define LOG_NETWORK_WARN(message)  LOG_WARN("NETWORK", message)
#define LOG_NETWORK_ERROR(message) LOG_ERROR("NETWORK", message)

#define LOG_CLIENT_DEBUG(message) LOG_DEBUG("CLIENT", message)
#define LOG_CLIENT_INFO(message)  LOG_INFO("CLIENT", message)
#define LOG_CLIENT_WARN(message)  LOG_WARN("CLIENT", message)
#define LOG_CLIENT_ERROR(message) LOG_ERROR("CLIENT", message)

#define LOG_SERVER_DEBUG(message) LOG_DEBUG("SERVER", message)
#define LOG_SERVER_INFO(message)  LOG_INFO("SERVER", message)
#define LOG_SERVER_WARN(message)  LOG_WARN("SERVER", message)
#define LOG_SERVER_ERROR(message) LOG_ERROR("SERVER", message)

#define LOG_MAIN_DEBUG(message) LOG_DEBUG("MAIN", message)
#define LOG_MAIN_INFO(message)  LOG_INFO("MAIN", message)
#define LOG_MAIN_WARN(message)  LOG_WARN("MAIN", message)
#define LOG_MAIN_ERROR(message) LOG_ERROR("MAIN", message) 