#pragma once

/**
 * @file rats_extend.h
 * @brief The C ABI extended from C++: a library's own subsystem on a C caller's node.
 *
 * A library built on librats in C++ that offers a C API of its own (ratcast's media
 * layer, say) runs as a Subsystem, as discovery or file transfer do. Its C caller
 * holds a `rats_t`, not a Node, so the library attaches through this — and the
 * caller keeps everything else rats.h offers on the same node: discovery, NAT
 * traversal, relays, its own channels.
 *
 * C++ only: nothing here crosses into C, so it is no part of rats.h.
 */

#include "librats/bindings/rats.h"
#include "librats/node/peer_network.h"  // Subsystem
#include "librats/util/rats_export.h"

#include <memory>

/** Attach `subsystem` to the node behind `node` under `name`, as the rats_enable_*()
 *  calls attach theirs: before rats_start(), owned by the node from then on,
 *  stopped by rats_stop() and destroyed by rats_destroy(). `name` keeps one per
 *  node: RATS_ERR_DECLINED if a subsystem is attached under it already;
 *  RATS_ERR_ALREADY_STARTED once the node has started; RATS_ERR_INVALID_ARG for
 *  a NULL or empty name or no subsystem. Whatever fails, `subsystem` is destroyed. */
RATS_API rats_error_t rats_attach_subsystem(rats_t node, const char* name,
                                            std::unique_ptr<librats::Subsystem> subsystem);
