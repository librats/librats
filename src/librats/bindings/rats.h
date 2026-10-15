#pragma once

/**
 * @file rats.h
 * @brief The C ABI over Node — what every language binding is built on.
 *
 * A `rats_t` is an opaque handle to one node. Peer ids cross the ABI as 64-char
 * lowercase hex of the peer's self-certifying PeerId.
 *
 * Configuration: `rats_config_t` is zero-initialisable — every field's zero is
 * the library default — so `rats_config_t cfg = {0};` (or a designated
 * initialiser naming only what you change) is a complete config, and
 * rats_create(NULL) is a node with all defaults.
 *
 * Errors: a fallible call returns `rats_error_t`, RATS_OK (0) on success;
 * rats_error_str() names a code. Sending is asynchronous: RATS_OK from
 * rats_send()/rats_publish() means the message was queued, not that it arrived.
 *
 * Subsystems are opt-in. Discovery, NAT traversal, pub/sub, JSON messaging, file
 * transfer, ping and reconnection each need their rats_enable_*() BEFORE
 * rats_start(). Using one that was not enabled returns RATS_ERR_NOT_ENABLED;
 * enabling after start returns RATS_ERR_ALREADY_STARTED.
 *
 * Threading: every call may be made from any thread. Callbacks run on an
 * internal reactor thread — keep them short and never block in them. Register
 * them before rats_start(); the node-level ones refuse afterwards
 * (RATS_ERR_ALREADY_STARTED). Strings and structs handed to a callback are valid
 * only for the duration of the call.
 *
 * Memory: the string arrays rats_peer_ids() and rats_observed_addresses()
 * return are released with rats_strings_free(). Every `const char*` the library
 * returns is its own and must not be freed.
 */

#include "librats/util/rats_export.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* C lets an enum hold any int, and a binding passes whatever int it has. C++
 * gives an enum without a fixed underlying type only the range of its
 * enumerators, so there loading another value — the very one a check exists to
 * refuse — would be undefined. In C++ these enums are therefore int-based: the
 * same size and calling convention as in C. */
#ifdef __cplusplus
#define RATS_ENUM_BASE : int
#else
#define RATS_ENUM_BASE
#endif

typedef struct rats_node* rats_t;

/* ─── Results ─────────────────────────────────────────────────────────────── */

typedef enum RATS_ENUM_BASE {
    RATS_OK                  = 0,
    RATS_ERR_INVALID_ARG     = 1,  /* NULL or malformed argument (bad peer id, bad JSON, …) */
    RATS_ERR_NOT_STARTED     = 2,  /* the call needs a started node */
    RATS_ERR_ALREADY_STARTED = 3,  /* only allowed before rats_start() */
    RATS_ERR_NOT_ENABLED     = 4,  /* the subsystem was not enabled with its rats_enable_*() */
    RATS_ERR_NO_SUCH_PEER    = 5,  /* the peer is not connected */
    RATS_ERR_NOT_FOUND       = 6,  /* no such transfer (or other named object) */
    RATS_ERR_DECLINED        = 7,  /* nothing to do or nothing to try with: the peer is
                                    * already connected, an attempt is already running
                                    * or cooling down, or no peer can help */
    RATS_ERR_BIND            = 8,  /* rats_start() could not open its sockets */
    RATS_ERR_INTERNAL        = 9
} rats_error_t;

/** Static name of an error code, e.g. "RATS_ERR_NO_SUCH_PEER" (never NULL). */
RATS_API const char* rats_error_str(rats_error_t err);

/* ─── Enumerations ────────────────────────────────────────────────────────── */

typedef enum RATS_ENUM_BASE {
    RATS_SECURITY_NOISE     = 0,  /* Noise XX: encrypted and authenticated (default) */
    RATS_SECURITY_PLAINTEXT = 1   /* no encryption; ids exchanged in the clear */
} rats_security_t;

/* Which wire a peer connection runs on. UDP and TCP carry the same protocol
 * under the same encrypted handshake. */
typedef enum RATS_ENUM_BASE {
    RATS_TRANSPORT_UDP   = 0,  /* the library's own transport on one shared UDP socket */
    RATS_TRANSPORT_TCP   = 1,  /* one kernel socket per peer */
    /* Carried through another peer's connection (rats_enable_relay). Only ever
     * reported, never chosen: a relay is not something a dial can try. */
    RATS_TRANSPORT_RELAY = 2
} rats_transport_t;

/* Bitmask of transports (rats_config_t::transports, rats_transports(),
 * rats_peer_info_t::transports). */
#define RATS_TRANSPORT_MASK_TCP 0x1u
#define RATS_TRANSPORT_MASK_UDP 0x2u

/* Congestion controller of every UDP connection. TCP is the kernel's and
 * ignores it. */
typedef enum RATS_ENUM_BASE {
    RATS_CONGESTION_BBR  = 0,  /* BBRv3 (default): holds its rate through loss that is
                                * not congestion (Wi-Fi, mobile, long paths) */
    RATS_CONGESTION_RENO = 1   /* NewReno with HyStart++: backs off on every loss */
} rats_congestion_t;

typedef enum RATS_ENUM_BASE {
    RATS_DIRECTION_OUTBOUND = 0,  /* we dialed it */
    RATS_DIRECTION_INBOUND  = 1   /* it dialed us */
} rats_direction_t;

/* Why a peer connection ended (rats_on_peer_disconnected). */
typedef enum RATS_ENUM_BASE {
    RATS_CLOSE_LOCAL            = 0,  /* we disconnected it */
    RATS_CLOSE_PEER_CLOSED      = 1,  /* the peer closed cleanly */
    RATS_CLOSE_PEER_RESET       = 2,  /* connection reset / socket error */
    RATS_CLOSE_CONNECT_FAILED   = 3,  /* the dial never completed */
    RATS_CLOSE_HANDSHAKE_FAILED = 4,  /* secure handshake failed or timed out */
    RATS_CLOSE_PROTOCOL_ERROR   = 5,  /* malformed frame or decryption failure */
    /* We kept sending while the peer's queue was already past its limit. The one
     * reason the application causes and can prevent: stop when rats_send() is
     * followed by rats_peer_writable() == 0 and resume on rats_on_peer_writable().
     * It never means one message was too big — a message of any size is queued. */
    RATS_CLOSE_SLOW_CONSUMER    = 6,
    RATS_CLOSE_SHUTDOWN         = 7,  /* the node is stopping */
    RATS_CLOSE_DUPLICATE        = 8,  /* replaced by another connection to the same peer */
    RATS_CLOSE_PEER_LIMIT       = 9,  /* inbound refused: max_peers reached */
    RATS_CLOSE_IDLE_TIMEOUT     = 10, /* a UDP connection went silent */
    RATS_CLOSE_DIAL_SUPERSEDED  = 11  /* a dial racing over the other transport won */
} rats_close_reason_t;

/** Static name of a close reason, e.g. "RATS_CLOSE_SLOW_CONSUMER" (never NULL). */
RATS_API const char* rats_close_reason_str(rats_close_reason_t reason);

/* What the mesh has shown about this node's own NAT (rats_nat_mapping). */
typedef enum RATS_ENUM_BASE {
    RATS_NAT_UNKNOWN              = 0,  /* not enough independent observations yet */
    RATS_NAT_OPEN                 = 1,  /* no NAT in the path */
    RATS_NAT_ENDPOINT_INDEPENDENT = 2,  /* one external port for every peer: punchable */
    RATS_NAT_ENDPOINT_DEPENDENT   = 3   /* a new mapping per peer (symmetric): not punchable */
} rats_nat_mapping_t;

typedef enum RATS_ENUM_BASE {
    RATS_LOG_DEBUG = 0,
    RATS_LOG_INFO  = 1,
    RATS_LOG_WARN  = 2,
    RATS_LOG_ERROR = 3
} rats_log_level_t;

/* ─── Configuration and lifecycle ─────────────────────────────────────────── */

/* transport_fallback_ms value that never races the second transport. */
#define RATS_FALLBACK_NEVER 0xFFFFFFFFu

/* Node configuration. Zero in any field is the default named beside it. Strings
 * are copied by rats_create(); they need not outlive the call. */
typedef struct {
    /* — identity — */
    const char*     protocol;   /* app id bound into the handshake, e.g. "myapp/1.0";
                                 * peers with a different one cannot connect.
                                 * NULL → "librats/1.0" */
    const char*     data_dir;   /* persistent state (identity.key, DHT routing table,
                                 * reconnect store). NULL → a new identity every run */
    rats_security_t security;   /* RATS_SECURITY_NOISE */

    /* — listening — */
    uint16_t        listen_port;   /* shared by both transports; 0 → ephemeral */
    const char*     bind_address;  /* NULL → "::", dual-stack on every interface */
    int             dial_only;     /* non-zero: no listener, outbound connections only */
    size_t          max_peers;     /* cap on established peers, enforced on inbound;
                                    * 0 → unlimited */

    /* — transports — */
    uint32_t         transports;            /* RATS_TRANSPORT_MASK_* to run; 0 → both */
    rats_transport_t preferred_transport;   /* tried first by a dial; RATS_TRANSPORT_UDP */
    uint32_t         transport_fallback_ms; /* the preferred transport dials alone this
                                             * long before the other is raced; 0 → 1200,
                                             * RATS_FALLBACK_NEVER → never */

    /* — sending — */
    size_t   send_queue_limit;  /* bytes a peer's queue may hold before a sender that
                                 * keeps going has it dropped (RATS_CLOSE_SLOW_CONSUMER);
                                 * rats_peer_writable() turns 0 at a quarter of it.
                                 * Not a message size limit. 0 → 8 MiB */
    uint32_t path_sample_ms;    /* how often each peer's path is sampled for
                                 * rats_path_stats(); 0 → only while a
                                 * rats_on_peer_path() callback is registered, every 100 ms */

    /* — UDP transport — */
    rats_congestion_t congestion_control;  /* RATS_CONGESTION_BBR */
    size_t udp_receive_window;   /* ceiling one connection's flow-control window grows
                                  * to (it starts at 1 MiB); throughput is bounded by
                                  * window / round trip. 0 → 16 MiB */
    size_t udp_receive_budget;   /* bytes all connections together may hold out of
                                  * order. 0 → 64 MiB */
    int    disable_udp_offload;  /* non-zero: no kernel segmentation offload
                                  * (UDP_SEGMENT/GRO, USO/URO), for comparison or a
                                  * host where it misbehaves */

    /* — runtime — */
    size_t reactor_threads;          /* I/O threads; 0 → 1, enough for thousands of peers */
    int    disable_network_monitor;  /* non-zero: do not watch the host for interface and
                                      * address changes (saves one mostly idle thread) */
} rats_config_t;

/** Create a node. `config` may be NULL for all defaults. Returns NULL when the
 *  config is invalid: no transport, an out-of-range enum, or TCP preferred while
 *  turned off. With a data_dir the identity is loaded from it, or created and
 *  saved there. No socket is opened until rats_start(). */
RATS_API rats_t rats_create(const rats_config_t* config);

/** Stop the node if running and free it. The handle is invalid afterwards. */
RATS_API void rats_destroy(rats_t node);

/** Open the sockets, start the I/O threads and every enabled subsystem.
 *  RATS_ERR_ALREADY_STARTED, or RATS_ERR_BIND if the listen port is taken. */
RATS_API rats_error_t rats_start(rats_t node);

/** Close every connection and stop. Idempotent. */
RATS_API void rats_stop(rats_t node);

/* ─── This node ───────────────────────────────────────────────────────────── */

/** Our peer id as hex. Owned by the node, valid until rats_destroy(). */
RATS_API const char* rats_local_id(rats_t node);

/** The protocol bound into the handshake. Owned by the node, valid until
 *  rats_destroy(). */
RATS_API const char* rats_protocol(rats_t node);

/** The bound listen port (the real one when 0 was asked for); 0 before start. */
RATS_API uint16_t rats_listen_port(rats_t node);

/** Transports actually running, as RATS_TRANSPORT_MASK_* bits. Can be narrower
 *  than the config asked for: a UDP socket that cannot be bound leaves the node
 *  TCP-only rather than failing to start. 0 when not running. */
RATS_API uint32_t rats_transports(rats_t node);

/** What the mesh has shown about this node's NAT, from where UDP peers report
 *  seeing its socket. */
RATS_API rats_nat_mapping_t rats_nat_mapping(rats_t node);

/** Our own addresses as peers report seeing us ("ip:port", our listen port).
 *  Returns an array of *count strings, NULL when there are none; release with
 *  rats_strings_free(). */
RATS_API char** rats_observed_addresses(rats_t node, size_t* count);

/* ─── Peers ───────────────────────────────────────────────────────────────── */

/** Dial host:port (a literal or a hostname). Non-blocking: success arrives as
 *  rats_on_peer_connected, failure as rats_on_dial_failed. */
RATS_API rats_error_t rats_connect(rats_t node, const char* host, uint16_t port);

/** Close the connection to a peer. RATS_ERR_NO_SUCH_PEER if it is not connected. */
RATS_API rats_error_t rats_disconnect(rats_t node, const char* peer_id);

RATS_API size_t rats_peer_count(rats_t node);

/** Ids of the connected peers: an array of *count strings, NULL when there are
 *  none. Release with rats_strings_free(). */
RATS_API char** rats_peer_ids(rats_t node, size_t* count);

typedef struct {
    rats_transport_t transport;   /* the wire this connection runs on */
    uint32_t         transports;  /* RATS_TRANSPORT_MASK_* the peer says it accepts;
                                   * 0 → it did not say */
    rats_direction_t direction;
    char             address[64]; /* where the peer can be dialed, "ip:port" or
                                   * "[ip]:port"; "" until known */
} rats_peer_info_t;

/** Fill `out` for a connected peer. RATS_ERR_NO_SUCH_PEER if not connected. */
RATS_API rats_error_t rats_peer_info(rats_t node, const char* peer_id, rats_peer_info_t* out);

/** Cap on established peers (0 = unlimited). Can be changed while running. */
RATS_API void   rats_set_max_peers(rats_t node, size_t max_peers);
RATS_API size_t rats_max_peers(rats_t node);

/* ─── Messaging ───────────────────────────────────────────────────────────── */

/* Limits of a live message (lifetime_ms > 0). A longer lifetime is cut to the
 * maximum; a larger payload is refused. */
#define RATS_LIVE_MAX_LIFETIME_MS 30000u
#define RATS_LIVE_MAX_PAYLOAD     (4u * 1024u * 1024u)

/** Queue bytes for one peer on a named channel. RATS_ERR_NO_SUCH_PEER if the
 *  peer is not connected.
 *
 *  lifetime_ms 0 is reliable: the message arrives, in order with everything else
 *  this node sends on its channels. Non-zero makes it a live message, worth
 *  delivering only within that many ms of this call: repaired while it can still
 *  arrive in time, dropped whole once it cannot, never delivered partly or twice,
 *  and ordered with nothing (number them if order matters). Made for audio and
 *  video frames. The receiver needs nothing special — it arrives at rats_on()
 *  like any message.
 *
 *  If you send in bulk, ask rats_peer_writable() after each send: that is the
 *  only warning before the peer is dropped as a slow consumer. */
RATS_API rats_error_t rats_send(rats_t node, const char* peer_id, const char* channel,
                                const void* data, size_t len, uint32_t lifetime_ms);

/** rats_send() to every connected peer. */
RATS_API rats_error_t rats_broadcast(rats_t node, const char* channel, const void* data,
                                     size_t len, uint32_t lifetime_ms);

/** 1 while the peer's send queue has room, 0 when it does not or the peer is not
 *  connected. 0 means stop: what you sent was queued, but keep adding and the
 *  peer is dropped with RATS_CLOSE_SLOW_CONSUMER. Resume on
 *  rats_on_peer_writable(), or poll this from a thread of your own. It counts
 *  bytes just handed to rats_send() too, so asking right after a send is exact. */
RATS_API int rats_peer_writable(rats_t node, const char* peer_id);

/* What the transport knows about the path to one peer, for a sender that sizes
 * its output to the path (a live encoder). Rates are bits per second. A new
 * message waits behind queued_bytes; queued_bytes * 8 / bandwidth_bps is that
 * wait in seconds. Over TCP the path figures are the kernel's and exist on Linux
 * only; elsewhere, and over a relay, only queued_bytes and the live counters are
 * filled. */
typedef struct {
    uint64_t bandwidth_bps;      /* the congestion controller's estimate; 0 = none yet */
    int      app_limited;        /* 1: the sender was not filling the path, so the
                                  * estimate is a floor, not the path's capacity */
    uint64_t pacing_bps;         /* current release rate; 0 = unpaced */
    uint32_t srtt_us;            /* smoothed round trip */
    uint32_t min_rtt_us;         /* lowest round trip seen: the path without queues */
    uint64_t queued_bytes;       /* accepted for the peer, not yet sent */
    uint64_t bytes_in_flight;    /* sent, not yet acknowledged */
    double   loss;               /* share of bytes lost over the last interval, 0..1 */
    uint64_t bytes_delivered;    /* acknowledged since the connection opened */
    uint64_t bytes_lost;         /* declared lost since the connection opened */
    uint64_t live_sent;          /* live messages sent since the connection opened */
    uint64_t live_expired;       /* of those, dropped because their lifetime ran out */
    uint64_t live_repair_bytes;  /* forward-error-correction bytes sent with live
                                  * messages on a lossy path, on top of the source's own */
} rats_path_stats_t;

/** The latest path sample for a peer. RATS_ERR_NO_SUCH_PEER if the peer is not
 *  connected or nothing was sampled yet (sampling runs only with path_sample_ms
 *  set or a rats_on_peer_path() callback registered). */
RATS_API rats_error_t rats_path_stats(rats_t node, const char* peer_id, rats_path_stats_t* out);

/* ─── Callbacks (register before rats_start; run on a reactor thread) ────── */

typedef void (*rats_peer_cb)(void* user, const char* peer_id);
typedef void (*rats_disconnect_cb)(void* user, const char* peer_id, rats_close_reason_t reason);
typedef void (*rats_dial_failed_cb)(void* user, const char* address);
typedef void (*rats_message_cb)(void* user, const char* peer_id, const void* data, size_t len);
typedef void (*rats_path_cb)(void* user, const char* peer_id, const rats_path_stats_t* stats);

/* Each registration adds a handler; several may coexist. */
RATS_API rats_error_t rats_on_peer_connected(rats_t node, rats_peer_cb cb, void* user);
RATS_API rats_error_t rats_on_peer_disconnected(rats_t node, rats_disconnect_cb cb, void* user);
/** A dial to a numeric address failed over every transport tried — one made by
 *  rats_connect() or by a discovery subsystem. `address` is "ip:port"; a dial by
 *  hostname is not reported. */
RATS_API rats_error_t rats_on_dial_failed(rats_t node, rats_dial_failed_cb cb, void* user);
/** A peer whose queue had filled has drained back under its mark. */
RATS_API rats_error_t rats_on_peer_writable(rats_t node, rats_peer_cb cb, void* user);
/** A path sample of every connected peer, every path_sample_ms (100 ms if 0).
 *  Registering one turns sampling on. Runs once per peer per interval. */
RATS_API rats_error_t rats_on_peer_path(rats_t node, rats_path_cb cb, void* user);
/** Messages arriving on a named channel. */
RATS_API rats_error_t rats_on(rats_t node, const char* channel, rats_message_cb cb, void* user);

/* ─── Discovery (enable before start) ─────────────────────────────────────── */

/** Mainline DHT: announce and search a key, dialing the peers found. dht_port 0
 *  is ephemeral. discovery_key NULL → the node's protocol, so only nodes that
 *  could handshake find each other. */
RATS_API rats_error_t rats_enable_dht(rats_t node, uint16_t dht_port, const char* discovery_key);

/** mDNS discovery on the local network. */
RATS_API rats_error_t rats_enable_mdns(rats_t node);

/** Peer exchange: connected peers trade the addresses of peers they hold, so a
 *  node needs one contact to find the rest of the mesh. */
RATS_API rats_error_t rats_enable_peer_exchange(rats_t node);

/* ─── NAT traversal (enable before start) ─────────────────────────────────── */

/** Ask the router to forward the listen port, over UPnP IGD and/or NAT-PMP
 *  (non-zero enables each; both run in parallel). */
RATS_API rats_error_t rats_enable_port_mapping(rats_t node, int upnp, int natpmp);

/** UDP hole punching: reach a peer behind a NAT by having a peer both sides
 *  share arrange for the two to dial each other at the same moment. Every node
 *  involved needs it enabled. `serve_rendezvous` non-zero also passes other
 *  peers' rendezvous along — a few dozen bytes per punch; a mesh where nobody
 *  does this cannot punch. */
RATS_API rats_error_t rats_enable_hole_punch(rats_t node, int serve_rendezvous);

/** Start punching to a peer. Success arrives as rats_on_peer_connected.
 *  RATS_ERR_DECLINED: already connected, already punching, or no external
 *  endpoint of our own known yet (that takes at least one UDP peer). */
RATS_API rats_error_t rats_punch_peer(rats_t node, const char* peer_id);

/** Relaying: reach a peer nothing else can, through a node both ends are
 *  connected to. Encryption stays end to end; rats_peer_info() reports
 *  RATS_TRANSPORT_RELAY. `serve` non-zero also carries OTHER peers'
 *  connections, which costs this node their bandwidth (each circuit is capped
 *  by bytes, time and count). With hole punching enabled too, a punch that
 *  cannot work falls back to a relay by itself, and a relayed peer is upgraded
 *  to a direct connection when a punch later succeeds. */
RATS_API rats_error_t rats_enable_relay(rats_t node, int serve);

/** Start a relayed connection to a peer. Success arrives as
 *  rats_on_peer_connected. RATS_ERR_DECLINED: already connected, already
 *  trying or cooling down, or no connected peer could carry it. */
RATS_API rats_error_t rats_connect_via_relay(rats_t node, const char* peer_id);

/* ─── Pub/sub (GossipSub) ─────────────────────────────────────────────────── */

typedef void (*rats_topic_cb)(void* user, const char* peer_id, const char* topic,
                              const void* data, size_t len);

/** Enable before start. */
RATS_API rats_error_t rats_enable_pubsub(rats_t node);
/** Subscribe to a topic; one handler per topic, a second subscribe replaces it. */
RATS_API rats_error_t rats_subscribe(rats_t node, const char* topic, rats_topic_cb cb, void* user);
RATS_API rats_error_t rats_unsubscribe(rats_t node, const char* topic);
/** Publish to every subscriber of the topic. */
RATS_API rats_error_t rats_publish(rats_t node, const char* topic, const void* data, size_t len);

/* ─── JSON messaging (typed messages carrying a JSON document) ───────────── */

/* `json` is compact JSON text. The sender id is the one authenticated by the
 * handshake. */
typedef void (*rats_json_cb)(void* user, const char* peer_id, const char* json);

/** Enable before start. */
RATS_API rats_error_t rats_enable_json(rats_t node);
/** Add a handler for messages of `type`. May be called while running. */
RATS_API rats_error_t rats_on_json(rats_t node, const char* type, rats_json_cb cb, void* user);
/** Like rats_on_json(); the handler is removed after its first message. */
RATS_API rats_error_t rats_once_json(rats_t node, const char* type, rats_json_cb cb, void* user);
/** Remove every handler of `type`. */
RATS_API rats_error_t rats_off_json(rats_t node, const char* type);
/** `json` must be valid JSON text (else RATS_ERR_INVALID_ARG). */
RATS_API rats_error_t rats_send_json(rats_t node, const char* peer_id, const char* type,
                                     const char* json);
RATS_API rats_error_t rats_broadcast_json(rats_t node, const char* type, const char* json);

/* ─── File transfer (push: the sender offers, the receiver accepts) ──────── */

typedef enum RATS_ENUM_BASE {
    RATS_FILE_PENDING   = 0,  /* offered, not answered yet */
    RATS_FILE_ACTIVE    = 1,
    RATS_FILE_PAUSED    = 2,
    RATS_FILE_COMPLETED = 3,
    RATS_FILE_FAILED    = 4,
    RATS_FILE_CANCELLED = 5
} rats_file_status_t;

typedef struct {
    uint64_t            transfer_id;
    const char*         peer_id;
    rats_direction_t    direction;          /* OUTBOUND = we send, INBOUND = we receive */
    rats_file_status_t  status;
    uint64_t            bytes_transferred;
    uint64_t            total_bytes;
    uint32_t            files_completed;
    uint32_t            total_files;
    double              rate_bytes_per_sec; /* recent, smoothed */
} rats_file_progress_t;

typedef void (*rats_file_offer_cb)(void* user, const char* peer_id, uint64_t transfer_id,
                                   const char* name, uint64_t size, int is_directory);
typedef void (*rats_file_progress_cb)(void* user, const rats_file_progress_t* progress);
typedef void (*rats_file_complete_cb)(void* user, const char* peer_id, uint64_t transfer_id,
                                      int success, const char* path);

/** Enable before start. `temp_dir` holds partial downloads (NULL → "."). */
RATS_API rats_error_t rats_enable_file_transfer(rats_t node, const char* temp_dir);

/* One handler each, set before start; a second call replaces the first. */
RATS_API rats_error_t rats_on_file_offer(rats_t node, rats_file_offer_cb cb, void* user);
RATS_API rats_error_t rats_on_file_progress(rats_t node, rats_file_progress_cb cb, void* user);
RATS_API rats_error_t rats_on_file_complete(rats_t node, rats_file_complete_cb cb, void* user);

/** Offer a file or a directory tree to a connected peer; the transfer id is
 *  written to *transfer_id (which may be NULL). RATS_ERR_NO_SUCH_PEER if the peer
 *  is not connected, RATS_ERR_NOT_FOUND if the path cannot be read. */
RATS_API rats_error_t rats_send_file(rats_t node, const char* peer_id, const char* path,
                                     uint64_t* transfer_id);
RATS_API rats_error_t rats_send_directory(rats_t node, const char* peer_id, const char* path,
                                          uint64_t* transfer_id);

/** Answer an offer. dest_path is the file to write for a file, the directory to
 *  fill for a directory. */
RATS_API rats_error_t rats_accept_file(rats_t node, const char* peer_id, uint64_t transfer_id,
                                       const char* dest_path);
RATS_API rats_error_t rats_reject_file(rats_t node, const char* peer_id, uint64_t transfer_id);

/** Control a running transfer from either side. RATS_ERR_NOT_FOUND if there is
 *  no such transfer. */
RATS_API rats_error_t rats_cancel_file(rats_t node, const char* peer_id, uint64_t transfer_id);
RATS_API rats_error_t rats_pause_file(rats_t node, const char* peer_id, uint64_t transfer_id);
RATS_API rats_error_t rats_resume_file(rats_t node, const char* peer_id, uint64_t transfer_id);

/* ─── Ping (round-trip probing of every peer) ─────────────────────────────── */

/** Enable before start. */
RATS_API rats_error_t rats_enable_ping(rats_t node);
/** Last measured round trip to a peer in ms; -1 if unknown (ping not enabled,
 *  no answer yet). */
RATS_API int64_t rats_peer_rtt_ms(rats_t node, const char* peer_id);

/* ─── Reconnection ────────────────────────────────────────────────────────── */

/** Re-dial dropped peers with exponential backoff. Every address dialed is
 *  remembered; with a data_dir the list survives restarts (peers.json). Enable
 *  before start — a node without it never redials on its own. */
RATS_API rats_error_t rats_enable_reconnect(rats_t node);
/** Keep an address connected. May be called while running. */
RATS_API rats_error_t rats_add_reconnect(rats_t node, const char* host, uint16_t port);
/** Stop keeping an address connected and forget it. */
RATS_API rats_error_t rats_remove_reconnect(rats_t node, const char* host, uint16_t port);

/* ─── BitTorrent ──────────────────────────────────────────────────────────────
 * Available only in builds with RATS_SEARCH_FEATURES; elsewhere every call
 * returns RATS_ERR_NOT_ENABLED. The client runs its own sockets; enable the DHT
 * first and it shares the node's. */

typedef enum RATS_ENUM_BASE {
    RATS_BT_ENC_ENABLED  = 0,  /* obfuscate (MSE/PE) first, fall back to plaintext (default) */
    RATS_BT_ENC_FORCED   = 1,  /* obfuscated connections only */
    RATS_BT_ENC_DISABLED = 2   /* plaintext only */
} rats_bt_encryption_t;

/* Zero in any field is the default named beside it. */
typedef struct {
    uint16_t             listen_port;          /* 0 → ephemeral */
    const char*          download_path;        /* NULL → "." */
    rats_bt_encryption_t outgoing_encryption;  /* RATS_BT_ENC_ENABLED */
    rats_bt_encryption_t incoming_encryption;  /* RATS_BT_ENC_ENABLED */
    int                  disable_outgoing_utp; /* non-zero: dial over TCP only */
    int                  disable_incoming_utp; /* non-zero: never answer uTP */
} rats_bt_config_t;

/** Enable before start. `config` may be NULL for the defaults. */
RATS_API rats_error_t rats_enable_bittorrent(rats_t node, const rats_bt_config_t* config);
/** Start a download from a magnet link (metadata is fetched from peers). */
RATS_API rats_error_t rats_bt_add_magnet(rats_t node, const char* magnet_uri, const char* save_path);
/** Start a download from a .torrent file. */
RATS_API rats_error_t rats_bt_add_torrent_file(rats_t node, const char* torrent_path,
                                               const char* save_path);
/** Remove a torrent by its 40-char hex info-hash. Downloaded files are kept. */
RATS_API rats_error_t rats_bt_remove_torrent(rats_t node, const char* info_hash_hex);

/* ─── Process-wide ────────────────────────────────────────────────────────── */

RATS_API void rats_set_log_level(rats_log_level_t level);
/** Also write logs to `path`; NULL or "" stops file logging. */
RATS_API void rats_set_log_file(const char* path);

/** Library version with the build number, e.g. "2.3.7.884". */
RATS_API const char* rats_version_string(void);
/** Version components; any pointer may be NULL. */
RATS_API void        rats_version(int* major, int* minor, int* patch, int* build);
/** `git describe` of the build, e.g. "v1.2.3-4-gabcdef". */
RATS_API const char* rats_git_describe(void);
/** (major << 16) | (minor << 8) | patch. */
RATS_API uint32_t    rats_abi(void);

/** Free an array from rats_peer_ids() / rats_observed_addresses(). NULL is a no-op. */
RATS_API void rats_strings_free(char** strings, size_t count);

#undef RATS_ENUM_BASE

#ifdef __cplusplus
}
#endif
