#pragma once

/**
 * @file rats.h
 * @brief The canonical C ABI over Node — the foundation for all language bindings.
 *
 * Opaque-pointer style. A `rats_t` wraps a C++ Node. Strings returned by the
 * library (e.g. peer ids) are heap-allocated and must be released with
 * rats_string_free(). Peer ids are 64-char lowercase hex of the peer's
 * self-certifying PeerId.
 *
 * Threading: callbacks fire on an internal reactor thread — do not block in them.
 * Register callbacks and subsystems BEFORE rats_start().
 */

#include "util/rats_export.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void* rats_t;

typedef enum {
    RATS_SECURITY_NOISE     = 0,  /* Noise XX, encrypted + authenticated (default) */
    RATS_SECURITY_PLAINTEXT = 1   /* unencrypted, ids exchanged in the clear */
} rats_security_t;

/* — construction / lifecycle — */

/** Create a listening node (Noise, binds 127.0.0.1, ephemeral if port 0). */
RATS_API rats_t rats_create(uint16_t listen_port);

/** Create with full control. enable_listen=0 makes a dial-only node. */
RATS_API rats_t rats_create_ex(uint16_t listen_port, int enable_listen,
                                         const char* bind_address, rats_security_t security);

RATS_API void     rats_destroy(rats_t node);
RATS_API int      rats_start(rats_t node);   /* 1 on success, 0 on failure */
RATS_API void     rats_stop(rats_t node);
RATS_API uint16_t rats_listen_port(rats_t node);

/** Our self-certifying peer id as hex. Caller frees with rats_string_free(). */
RATS_API char*    rats_local_id(rats_t node);

/* — connections — */

RATS_API void   rats_connect(rats_t node, const char* host, uint16_t port);
RATS_API size_t rats_peer_count(rats_t node);

/** Cap on established peers (0 = unlimited). Guards inbound; our dials are honored.
 *  May be set before or after start(). */
RATS_API void   rats_set_max_peers(rats_t node, size_t max_peers);
RATS_API size_t rats_max_peers(rats_t node);

/* — messaging (named application channel, raw bytes) — */

RATS_API void rats_send(rats_t node, const char* peer_id_hex,
                             const char* channel, const void* data, size_t len);
RATS_API void rats_broadcast(rats_t node, const char* channel,
                                  const void* data, size_t len);

/* — callbacks (register before start; invoked on a reactor thread) — */

typedef void (*rats_peer_cb)(void* user, const char* peer_id_hex);
typedef void (*rats_message_cb)(void* user, const char* peer_id_hex, const void* data, size_t len);

RATS_API void rats_on_peer_connected(rats_t node, rats_peer_cb cb, void* user);
RATS_API void rats_on_peer_disconnected(rats_t node, rats_peer_cb cb, void* user);
RATS_API void rats_on_message(rats_t node, const char* channel, rats_message_cb cb, void* user);

/* — optional discovery subsystems (call before start) — */

/** DHT discovery. dht_port 0 = ephemeral; discovery_key namespaces the app (NULL → default). */
RATS_API void rats_enable_dht(rats_t node, uint16_t dht_port, const char* discovery_key);
/** Local-network mDNS discovery. */
RATS_API void rats_enable_mdns(rats_t node);
/** Automatic NAT port forwarding for the listen port (UPnP IGD + NAT-PMP).
 *  Pass non-zero to enable each backend; both run in parallel. */
RATS_API void rats_enable_port_mapping(rats_t node, int enable_upnp, int enable_natpmp);

/* — peer enumeration — */

/** Hex ids of currently-connected peers. Writes the count to *count and returns a
 *  heap array of `count` heap strings; free the whole thing with rats_free_peer_ids().
 *  Returns NULL (and *count = 0) when there are no peers. */
RATS_API char** rats_peer_ids(rats_t node, size_t* count);
RATS_API void   rats_free_peer_ids(char** ids, size_t count);

/* — pub/sub (topic-based, raw bytes; subscribe before start) — */

typedef void (*rats_topic_cb)(void* user, const char* peer_id_hex,
                              const char* topic, const void* data, size_t len);

/** Subscribe to `topic`; matching messages invoke `cb` on a reactor thread. */
RATS_API void rats_subscribe(rats_t node, const char* topic, rats_topic_cb cb, void* user);
RATS_API void rats_unsubscribe(rats_t node, const char* topic);
/** Publish `data` on `topic` to every subscribed peer (and local subscribers). */
RATS_API void rats_publish(rats_t node, const char* topic, const void* data, size_t len);

/* — typed JSON messaging (named message type; payload is JSON text) — */

typedef void (*rats_typed_cb)(void* user, const char* peer_id_hex, const char* json);

/** Register a handler for messages of `type`. `json` is compact JSON text owned by
 *  the library (valid only for the duration of the call). Additive: multiple
 *  handlers may coexist. The sender id is the authenticated handshake PeerId. */
RATS_API void rats_on(rats_t node, const char* type, rats_typed_cb cb, void* user);
RATS_API void rats_off(rats_t node, const char* type);
/** Send/broadcast a typed message. `json` must be valid JSON text (invalid → no-op). */
RATS_API void rats_send_typed(rats_t node, const char* peer_id_hex, const char* type, const char* json);
RATS_API void rats_broadcast_typed(rats_t node, const char* type, const char* json);

/* — file transfer (push model; enable + register callbacks before start) — */

typedef void (*rats_file_offer_cb)(void* user, const char* peer_id_hex, uint64_t transfer_id,
                                   const char* name, uint64_t size, int is_directory);
typedef void (*rats_file_progress_cb)(void* user, uint64_t transfer_id, const char* peer_id_hex,
                                      uint64_t bytes_transferred, uint64_t total_bytes, int status);
typedef void (*rats_file_complete_cb)(void* user, uint64_t transfer_id, int success, const char* path);

/** Enable the file-transfer subsystem. `temp_dir` holds in-progress downloads
 *  (NULL → current directory). Call before start(). */
RATS_API void rats_enable_file_transfer(rats_t node, const char* temp_dir);

RATS_API void rats_on_file_offer(rats_t node, rats_file_offer_cb cb, void* user);
RATS_API void rats_on_file_progress(rats_t node, rats_file_progress_cb cb, void* user);
RATS_API void rats_on_file_complete(rats_t node, rats_file_complete_cb cb, void* user);

/** Offer a file / directory tree to a peer. Returns the transfer id (0 on failure). */
RATS_API uint64_t rats_send_file(rats_t node, const char* peer_id_hex, const char* path);
RATS_API uint64_t rats_send_directory(rats_t node, const char* peer_id_hex, const char* dir_path);

/** Respond to an offer. For a single file, dest_path is the file path; for a
 *  directory, the destination directory. (peer_id, transfer_id) names the offer. */
RATS_API void rats_accept_file(rats_t node, const char* peer_id_hex, uint64_t transfer_id, const char* dest_path);
RATS_API void rats_reject_file(rats_t node, const char* peer_id_hex, uint64_t transfer_id);

/** Control a live transfer (either side). Returns 1 if the transfer was found. */
RATS_API int rats_cancel_file(rats_t node, const char* peer_id_hex, uint64_t transfer_id);
RATS_API int rats_pause_file(rats_t node, const char* peer_id_hex, uint64_t transfer_id);
RATS_API int rats_resume_file(rats_t node, const char* peer_id_hex, uint64_t transfer_id);

/* — liveness (RTT probing) — */

/** Enable periodic ping/pong RTT probing of every peer. Call before start(). */
RATS_API void rats_enable_ping(rats_t node);
/** Last measured round-trip time to a peer in milliseconds, or -1 if unknown
 *  (ping not enabled, or no pong received yet). */
RATS_API int64_t rats_peer_rtt_ms(rats_t node, const char* peer_id_hex);

/* — logging (process-global; no node required) — */

typedef enum {
    RATS_LOG_DEBUG = 0,
    RATS_LOG_INFO  = 1,
    RATS_LOG_WARN  = 2,
    RATS_LOG_ERROR = 3
} rats_log_level_t;

RATS_API void rats_set_log_level(rats_log_level_t level);
/** Mirror logs to `path` (NULL/empty disables file logging). */
RATS_API void rats_set_log_file(const char* path);

/* — utility — */

RATS_API void rats_string_free(char* str);

#ifdef __cplusplus
}
#endif
