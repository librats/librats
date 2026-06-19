#pragma once

/**
 * @file rats_node.h
 * @brief C ABI for the redesigned Node — the foundation for all language bindings.
 *
 * Opaque-pointer style. A `rats_node_t` wraps a C++ Node. Strings returned by the
 * library (e.g. peer ids) are heap-allocated and must be released with
 * rats_node_string_free(). Peer ids are 64-char lowercase hex of the peer's
 * self-certifying PeerId.
 *
 * Threading: callbacks fire on an internal reactor thread — do not block in them.
 * Register callbacks and subsystems BEFORE rats_node_start().
 *
 * (Named rats_node_* to coexist with the legacy rats_* C API during the rewrite;
 * it becomes the canonical C API once the legacy client is removed.)
 */

#include "util/rats_export.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void* rats_node_t;

typedef enum {
    RATS_SECURITY_NOISE     = 0,  /* Noise XX, encrypted + authenticated (default) */
    RATS_SECURITY_PLAINTEXT = 1   /* unencrypted, ids exchanged in the clear */
} rats_security_t;

/* — construction / lifecycle — */

/** Create a listening node (Noise, binds 127.0.0.1, ephemeral if port 0). */
RATS_API rats_node_t rats_node_create(uint16_t listen_port);

/** Create with full control. enable_listen=0 makes a dial-only node. */
RATS_API rats_node_t rats_node_create_ex(uint16_t listen_port, int enable_listen,
                                         const char* bind_address, rats_security_t security);

RATS_API void     rats_node_destroy(rats_node_t node);
RATS_API int      rats_node_start(rats_node_t node);   /* 1 on success, 0 on failure */
RATS_API void     rats_node_stop(rats_node_t node);
RATS_API uint16_t rats_node_listen_port(rats_node_t node);

/** Our self-certifying peer id as hex. Caller frees with rats_node_string_free(). */
RATS_API char*    rats_node_local_id(rats_node_t node);

/* — connections — */

RATS_API void   rats_node_connect(rats_node_t node, const char* host, uint16_t port);
RATS_API size_t rats_node_peer_count(rats_node_t node);

/** Cap on established peers (0 = unlimited). Guards inbound; our dials are honored.
 *  May be set before or after start(). */
RATS_API void   rats_node_set_max_peers(rats_node_t node, size_t max_peers);
RATS_API size_t rats_node_max_peers(rats_node_t node);

/* — messaging (named application channel, raw bytes) — */

RATS_API void rats_node_send(rats_node_t node, const char* peer_id_hex,
                             const char* channel, const void* data, size_t len);
RATS_API void rats_node_broadcast(rats_node_t node, const char* channel,
                                  const void* data, size_t len);

/* — callbacks (register before start; invoked on a reactor thread) — */

typedef void (*rats_peer_cb)(void* user, const char* peer_id_hex);
typedef void (*rats_message_cb)(void* user, const char* peer_id_hex, const void* data, size_t len);

RATS_API void rats_node_on_peer_connected(rats_node_t node, rats_peer_cb cb, void* user);
RATS_API void rats_node_on_peer_disconnected(rats_node_t node, rats_peer_cb cb, void* user);
RATS_API void rats_node_on_message(rats_node_t node, const char* channel, rats_message_cb cb, void* user);

/* — optional discovery subsystems (call before start) — */

/** DHT discovery. dht_port 0 = ephemeral; discovery_key namespaces the app (NULL → default). */
RATS_API void rats_node_enable_dht(rats_node_t node, uint16_t dht_port, const char* discovery_key);
/** Local-network mDNS discovery. */
RATS_API void rats_node_enable_mdns(rats_node_t node);
/** Automatic NAT port forwarding for the listen port (UPnP IGD + NAT-PMP).
 *  Pass non-zero to enable each backend; both run in parallel. */
RATS_API void rats_node_enable_port_mapping(rats_node_t node, int enable_upnp, int enable_natpmp);

/* — utility — */

RATS_API void rats_node_string_free(char* str);

#ifdef __cplusplus
}
#endif
