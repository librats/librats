#pragma once

/**
 * @file log.h
 * @brief Small logging helpers for the mDNS module.
 *
 * Formatting sugar on top of util/logger.h — nothing more. mDNS logs under the "mdns"
 * tag so it gets its own stable colour and is easy to grep.
 *
 * This lives apart from mdns.h on purpose. mdns.h is reachable from a public header
 * (subsystems/mdns_discovery.h), and util/logger.h defines unprefixed macros —
 * LOG_DEBUG/LOG_INFO/LOG_WARN/LOG_ERROR, plus isatty/fileno on Windows — that would
 * then land in every consumer translation unit. Keep the logging include on the .cpp
 * side, exactly as src/dht/log.h and src/bittorrent/log.h do.
 */

#include "librats/util/logger.h"

#define LOG_MDNS_DEBUG(message) LOG_DEBUG("mdns", message)
#define LOG_MDNS_INFO(message)  LOG_INFO("mdns", message)
#define LOG_MDNS_WARN(message)  LOG_WARN("mdns", message)
#define LOG_MDNS_ERROR(message) LOG_ERROR("mdns", message)
