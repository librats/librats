/**
 * @file librats_log_macros.h
 * @brief Shared logging macros for all librats_*.cpp files.
 *
 * In TESTING builds the macros embed the `this` pointer so that
 * log lines from different RatsClient instances can be distinguished.
 */

#ifndef LIBRATS_LOG_MACROS_H
#define LIBRATS_LOG_MACROS_H

#include "logger.h"

#ifdef TESTING
#define LOG_CLIENT_DEBUG(message) LOG_DEBUG("client", "[pointer: " << this << "] " << message)
#define LOG_CLIENT_INFO(message)  LOG_INFO("client", "[pointer: " << this << "] " << message)
#define LOG_CLIENT_WARN(message)  LOG_WARN("client", "[pointer: " << this << "] " << message)
#define LOG_CLIENT_ERROR(message) LOG_ERROR("client", "[pointer: " << this << "] " << message)

#define LOG_SERVER_DEBUG(message) LOG_DEBUG("server", "[pointer: " << this << "] " << message)
#define LOG_SERVER_INFO(message)  LOG_INFO("server", "[pointer: " << this << "] " << message)
#define LOG_SERVER_WARN(message)  LOG_WARN("server", "[pointer: " << this << "] " << message)
#define LOG_SERVER_ERROR(message) LOG_ERROR("server", "[pointer: " << this << "] " << message)
#else
#define LOG_CLIENT_DEBUG(message) LOG_DEBUG("client", message)
#define LOG_CLIENT_INFO(message)  LOG_INFO("client", message)
#define LOG_CLIENT_WARN(message)  LOG_WARN("client", message)
#define LOG_CLIENT_ERROR(message) LOG_ERROR("client", message)

#define LOG_SERVER_DEBUG(message) LOG_DEBUG("server", message)
#define LOG_SERVER_INFO(message)  LOG_INFO("server", message)
#define LOG_SERVER_WARN(message)  LOG_WARN("server", message)
#define LOG_SERVER_ERROR(message) LOG_ERROR("server", message)
#endif

#endif // LIBRATS_LOG_MACROS_H
