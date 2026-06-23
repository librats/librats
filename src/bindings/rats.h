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
 * Error model: fallible operations return a `rats_error_t` (RATS_OK == 0 on
 * success). Pure getters return their value directly. Use rats_error_str() for a
 * static human-readable name. Delivery of messages is asynchronous and
 * best-effort: a RATS_OK from rats_send()/rats_publish() means the request was
 * accepted and queued, not that a peer received it.
 *
 * Subsystems are explicit and opt-in: discovery, pub/sub, typed messaging, file
 * transfer and ping must each be turned on with the matching rats_enable_*()
 * BEFORE rats_start(). Calling a subsystem function before its enable returns
 * RATS_ERR_NOT_ENABLED; calling an enable after start returns
 * RATS_ERR_ALREADY_STARTED.
 *
 * Threading: callbacks fire on an internal reactor thread — do not block in them.
 * Register callbacks and enable subsystems BEFORE rats_start().
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

/* Result of a fallible operation. RATS_OK is 0; any non-zero value is an error.
 * NOTE: this inverts the truthiness of the old int-returning calls — test against
 * RATS_OK, not against zero/non-zero, e.g. `if (rats_start(n) != RATS_OK) …`. */
typedef enum {
    RATS_OK                  = 0,
    RATS_ERR_INVALID_ARG     = 1,  /* null/malformed argument (bad peer id, null ptr, bad json) */
    RATS_ERR_NOT_STARTED     = 2,  /* operation requires a started node */
    RATS_ERR_ALREADY_STARTED = 3,  /* enable/attach called after rats_start() */
    RATS_ERR_NOT_ENABLED     = 4,  /* subsystem not enabled — call the matching rats_enable_* */
    RATS_ERR_NO_SUCH_PEER    = 5,  /* peer not connected, or transfer id not found */
    RATS_ERR_BIND            = 6,  /* listen/bind failed during rats_start() */
    RATS_ERR_INTERNAL        = 7
} rats_error_t;

/** Static human-readable name of an error code (do not free). */
RATS_API const char* rats_error_str(rats_error_t err);

/* — construction / lifecycle — */

/** Full node configuration. Obtain a sane-defaults instance with
 *  rats_config_default(), set the fields you care about, then pass it to
 *  rats_create_config(). Zero-initialising this struct yourself is NOT safe
 *  (enable_listen would be 0 → a dial-only node); always start from the default.
 *  String fields are borrowed only for the duration of the create call; NULL on
 *  any of them selects the library default shown below. */
typedef struct {
    uint16_t        listen_port;      /* inbound port; 0 = ephemeral */
    int             enable_listen;    /* 0 = dial-only node (no listener) */
    const char*     bind_address;     /* NULL → "::" dual-stack wildcard */
    rats_security_t security;         /* RATS_SECURITY_NOISE / _PLAINTEXT */
    const char*     data_dir;         /* persistent state dir; NULL/"" → ephemeral identity each run */
    const char*     protocol;         /* handshake app id (e.g. "myapp/1.0"); NULL → "librats/1.0" */
    size_t          max_peers;        /* established-peer cap; 0 = unlimited */
} rats_config_t;

/** A config pre-filled with the library defaults (listening, Noise, ephemeral
 *  identity, unlimited peers). Mutate the returned struct and pass to
 *  rats_create_config(). */
RATS_API rats_config_t rats_config_default(void);

/** Create a node from a full config (NULL → all defaults). When data_dir is set,
 *  the identity persists across restarts and subsystems (DHT routing table,
 *  reconnection store) co-locate their state there. */
RATS_API rats_t rats_create_config(const rats_config_t* config);

/** Create a listening node (Noise, dual-stack, ephemeral identity, port 0 = ephemeral). */
RATS_API rats_t rats_create(uint16_t listen_port);

/** Create with basic control. enable_listen=0 makes a dial-only node. For
 *  data_dir / protocol identity / max_peers use rats_create_config(). */
RATS_API rats_t rats_create_ex(uint16_t listen_port, int enable_listen,
                                         const char* bind_address, rats_security_t security);

RATS_API void         rats_destroy(rats_t node);
RATS_API rats_error_t rats_start(rats_t node);   /* RATS_OK / RATS_ERR_ALREADY_STARTED / RATS_ERR_BIND */
RATS_API void         rats_stop(rats_t node);
RATS_API uint16_t     rats_listen_port(rats_t node);

/** Our self-certifying peer id as hex. Caller frees with rats_string_free(). */
RATS_API char*    rats_local_id(rats_t node);

/** Application protocol identity bound into the handshake (see rats_config_t).
 *  Two nodes whose protocol differs cannot complete a handshake. Caller frees
 *  the returned string with rats_string_free(). */
RATS_API char*    rats_protocol(rats_t node);

/* — connections — */

RATS_API rats_error_t rats_connect(rats_t node, const char* host, uint16_t port);
RATS_API size_t       rats_peer_count(rats_t node);

/** Cap on established peers (0 = unlimited). Guards inbound; our dials are honored.
 *  May be set before or after start(). */
RATS_API void   rats_set_max_peers(rats_t node, size_t max_peers);
RATS_API size_t rats_max_peers(rats_t node);

/* — messaging (named application channel, raw bytes) — */

RATS_API rats_error_t rats_send(rats_t node, const char* peer_id_hex,
                                          const char* channel, const void* data, size_t len);
RATS_API rats_error_t rats_broadcast(rats_t node, const char* channel,
                                               const void* data, size_t len);

/* — callbacks (register before start; invoked on a reactor thread) — */

typedef void (*rats_peer_cb)(void* user, const char* peer_id_hex);
typedef void (*rats_message_cb)(void* user, const char* peer_id_hex, const void* data, size_t len);

RATS_API rats_error_t rats_on_peer_connected(rats_t node, rats_peer_cb cb, void* user);
RATS_API rats_error_t rats_on_peer_disconnected(rats_t node, rats_peer_cb cb, void* user);
RATS_API rats_error_t rats_on(rats_t node, const char* channel, rats_message_cb cb, void* user);

/* — optional subsystems (enable before start) — */

/** DHT discovery. dht_port 0 = ephemeral; discovery_key namespaces the app (NULL → default). */
RATS_API rats_error_t rats_enable_dht(rats_t node, uint16_t dht_port, const char* discovery_key);
/** Local-network mDNS discovery. */
RATS_API rats_error_t rats_enable_mdns(rats_t node);
/** Automatic NAT port forwarding for the listen port (UPnP IGD + NAT-PMP).
 *  Pass non-zero to enable each backend; both run in parallel. */
RATS_API rats_error_t rats_enable_port_mapping(rats_t node, int enable_upnp, int enable_natpmp);

/* — peer enumeration — */

/** Hex ids of currently-connected peers. Writes the count to *count and returns a
 *  heap array of `count` heap strings; free the whole thing with rats_free_peer_ids().
 *  Returns NULL (and *count = 0) when there are no peers. */
RATS_API char** rats_peer_ids(rats_t node, size_t* count);
RATS_API void   rats_free_peer_ids(char** ids, size_t count);

/* — pub/sub (topic-based, raw bytes; enable + subscribe before start) — */

typedef void (*rats_topic_cb)(void* user, const char* peer_id_hex,
                              const char* topic, const void* data, size_t len);

/** Enable the pub/sub (GossipSub) subsystem. Call before start(). */
RATS_API rats_error_t rats_enable_pubsub(rats_t node);
/** Subscribe to `topic`; matching messages invoke `cb` on a reactor thread. */
RATS_API rats_error_t rats_subscribe(rats_t node, const char* topic, rats_topic_cb cb, void* user);
RATS_API rats_error_t rats_unsubscribe(rats_t node, const char* topic);
/** Publish `data` on `topic` to every subscribed peer (and local subscribers). */
RATS_API rats_error_t rats_publish(rats_t node, const char* topic, const void* data, size_t len);

/* — typed JSON messaging (named message type; payload is JSON text) — */

typedef void (*rats_json_cb)(void* user, const char* peer_id_hex, const char* json);

/** Enable the JSON-messaging subsystem (the C view of MessageJson). Call before start(). */
RATS_API rats_error_t rats_enable_json(rats_t node);
/** Register a handler for JSON messages of `type`. `json` is compact JSON text owned
 *  by the library (valid only for the duration of the call). Additive: multiple
 *  handlers may coexist. The sender id is the authenticated handshake PeerId. */
RATS_API rats_error_t rats_on_json(rats_t node, const char* type, rats_json_cb cb, void* user);
/** Like rats_on_json, but the handler is removed right after it fires once. */
RATS_API rats_error_t rats_once_json(rats_t node, const char* type, rats_json_cb cb, void* user);
RATS_API rats_error_t rats_off_json(rats_t node, const char* type);
/** Send/broadcast a JSON message. `json` must be valid JSON text (invalid → RATS_ERR_INVALID_ARG). */
RATS_API rats_error_t rats_send_json(rats_t node, const char* peer_id_hex, const char* type, const char* json);
RATS_API rats_error_t rats_broadcast_json(rats_t node, const char* type, const char* json);

/* — file transfer (push model; enable + register callbacks before start) — */

typedef void (*rats_file_offer_cb)(void* user, const char* peer_id_hex, uint64_t transfer_id,
                                   const char* name, uint64_t size, int is_directory);
typedef void (*rats_file_progress_cb)(void* user, uint64_t transfer_id, const char* peer_id_hex,
                                      uint64_t bytes_transferred, uint64_t total_bytes, int status);
typedef void (*rats_file_complete_cb)(void* user, uint64_t transfer_id, int success, const char* path);

/** Enable the file-transfer subsystem. `temp_dir` holds in-progress downloads
 *  (NULL → current directory). Call before start(). */
RATS_API rats_error_t rats_enable_file_transfer(rats_t node, const char* temp_dir);

RATS_API rats_error_t rats_on_file_offer(rats_t node, rats_file_offer_cb cb, void* user);
RATS_API rats_error_t rats_on_file_progress(rats_t node, rats_file_progress_cb cb, void* user);
RATS_API rats_error_t rats_on_file_complete(rats_t node, rats_file_complete_cb cb, void* user);

/** Offer a file / directory tree to a peer. Returns the transfer id (0 on failure,
 *  e.g. file transfer not enabled or bad peer id). */
RATS_API uint64_t rats_send_file(rats_t node, const char* peer_id_hex, const char* path);
RATS_API uint64_t rats_send_directory(rats_t node, const char* peer_id_hex, const char* dir_path);

/** Respond to an offer. For a single file, dest_path is the file path; for a
 *  directory, the destination directory. (peer_id, transfer_id) names the offer. */
RATS_API rats_error_t rats_accept_file(rats_t node, const char* peer_id_hex, uint64_t transfer_id, const char* dest_path);
RATS_API rats_error_t rats_reject_file(rats_t node, const char* peer_id_hex, uint64_t transfer_id);

/** Control a live transfer (either side). RATS_OK if the transfer was found and
 *  the action applied; RATS_ERR_NO_SUCH_PEER if no matching transfer. */
RATS_API rats_error_t rats_cancel_file(rats_t node, const char* peer_id_hex, uint64_t transfer_id);
RATS_API rats_error_t rats_pause_file(rats_t node, const char* peer_id_hex, uint64_t transfer_id);
RATS_API rats_error_t rats_resume_file(rats_t node, const char* peer_id_hex, uint64_t transfer_id);

/* — liveness (RTT probing) — */

/** Enable periodic ping/pong RTT probing of every peer. Call before start(). */
RATS_API rats_error_t rats_enable_ping(rats_t node);
/** Last measured round-trip time to a peer in milliseconds, or -1 if unknown
 *  (ping not enabled, or no pong received yet). */
RATS_API int64_t rats_peer_rtt_ms(rats_t node, const char* peer_id_hex);

/* — automatic reconnection — */

/** Enable the reconnection subsystem: re-dials dropped peers with exponential
 *  backoff. Dialed peers are remembered automatically; when the node has a
 *  data_dir, targets persist to "<data_dir>/peers.txt" across restarts. Call
 *  before start(). A bare node never reconnects on its own. */
RATS_API rats_error_t rats_enable_reconnect(rats_t node);
/** Add an address to keep connected (re-dialed on drop). Persisted if a store is
 *  configured. May be called before or after start(). */
RATS_API rats_error_t rats_add_reconnect(rats_t node, const char* host, uint16_t port);
/** Stop reconnecting to an address and drop it from the store. */
RATS_API rats_error_t rats_remove_reconnect(rats_t node, const char* host, uint16_t port);

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

/* — library info (process-global; no node required) — */

/** Library version as a static string, e.g. "1.2.3" (do not free). */
RATS_API const char* rats_version_string(void);
/** Library version components. Any out-pointer may be NULL. */
RATS_API void        rats_version(int* major, int* minor, int* patch, int* build);
/** Git describe of the build, e.g. "v1.2.3-4-gabcdef" (static; do not free). */
RATS_API const char* rats_git_describe(void);
/** Packed ABI id as (major<<16)|(minor<<8)|patch — MAJOR bumps on breaking
 *  changes, MINOR on additive ones. */
RATS_API uint32_t    rats_abi(void);

/* — utility — */

RATS_API void rats_string_free(char* str);

#ifdef __cplusplus
}
#endif
