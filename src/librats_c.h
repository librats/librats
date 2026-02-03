#pragma once

#include "rats_export.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque handle to a RatsClient instance
typedef void* rats_client_t;

// Memory helpers for returned strings
RATS_API void rats_string_free(const char* str);

// Version / ABI
RATS_API const char* rats_get_version_string(void);
RATS_API void rats_get_version(int* major, int* minor, int* patch, int* build);
RATS_API const char* rats_get_git_describe(void);
RATS_API uint32_t rats_get_abi(void);

// Client lifecycle
RATS_API rats_client_t rats_create(int listen_port);
RATS_API void rats_destroy(rats_client_t client);
RATS_API int rats_start(rats_client_t client);
RATS_API void rats_stop(rats_client_t client);

// Basic operations
RATS_API int rats_connect(rats_client_t client, const char* host, int port);
RATS_API int rats_get_listen_port(rats_client_t client);
RATS_API int rats_broadcast_string(rats_client_t client, const char* message);
RATS_API int rats_send_string(rats_client_t client, const char* peer_id, const char* message);

// Info
RATS_API int rats_get_peer_count(rats_client_t client);
RATS_API char* rats_get_our_peer_id(rats_client_t client); // caller must free with rats_string_free
RATS_API char* rats_get_connection_statistics_json(rats_client_t client); // caller must free with rats_string_free
RATS_API char** rats_get_validated_peer_ids(rats_client_t client, int* count); // caller must free array and strings
RATS_API char** rats_get_peer_ids(rats_client_t client, int* count); // caller must free array and strings
RATS_API char* rats_get_peer_info_json(rats_client_t client, const char* peer_id); // caller must free

// Logging controls (optional helpers)
RATS_API void rats_set_console_logging_enabled(int enabled);
RATS_API int rats_is_console_logging_enabled(void);
RATS_API void rats_set_logging_enabled(int enabled);
RATS_API void rats_set_log_level(const char* level_str); // "DEBUG", "INFO", "WARN", "ERROR"
RATS_API void rats_set_log_file_path(rats_client_t client, const char* file_path);
RATS_API char* rats_get_log_file_path(rats_client_t client); // caller must free
RATS_API void rats_set_log_colors_enabled(rats_client_t client, int enabled);
RATS_API int rats_is_log_colors_enabled(rats_client_t client);
RATS_API void rats_set_log_timestamps_enabled(rats_client_t client, int enabled);
RATS_API int rats_is_log_timestamps_enabled(rats_client_t client);
RATS_API void rats_set_log_rotation_size(rats_client_t client, size_t max_size_bytes);
RATS_API void rats_set_log_retention_count(rats_client_t client, int count);
RATS_API void rats_set_log_rotate_on_startup(rats_client_t client, int enabled);
RATS_API int rats_is_log_rotate_on_startup_enabled(rats_client_t client);
RATS_API void rats_clear_log_file(rats_client_t client);

// Error codes
typedef enum {
    RATS_SUCCESS = 0,
    RATS_ERROR_INVALID_HANDLE = -1,
    RATS_ERROR_INVALID_PARAMETER = -2,
    RATS_ERROR_NOT_RUNNING = -3,
    RATS_ERROR_OPERATION_FAILED = -4,
    RATS_ERROR_PEER_NOT_FOUND = -5,
    RATS_ERROR_MEMORY_ALLOCATION = -6,
    RATS_ERROR_JSON_PARSE = -7
} rats_error_t;

// C callbacks
typedef void (*rats_connection_cb)(void* user_data, const char* peer_id);
typedef void (*rats_string_cb)(void* user_data, const char* peer_id, const char* message);
typedef void (*rats_binary_cb)(void* user_data, const char* peer_id, const void* data, size_t size);
typedef void (*rats_json_cb)(void* user_data, const char* peer_id, const char* json_str);
typedef void (*rats_disconnect_cb)(void* user_data, const char* peer_id);
typedef void (*rats_peer_discovered_cb)(void* user_data, const char* host, int port, const char* service_name);
typedef void (*rats_message_cb)(void* user_data, const char* peer_id, const char* message_data);
typedef void (*rats_peers_found_cb)(void* user_data, const char** peer_addresses, int count);

// Peer configuration
RATS_API rats_error_t rats_set_max_peers(rats_client_t client, int max_peers);
RATS_API int rats_get_max_peers(rats_client_t client);
RATS_API int rats_is_peer_limit_reached(rats_client_t client);

// Connection methods
RATS_API rats_error_t rats_disconnect_peer_by_id(rats_client_t client, const char* peer_id);

// Binary data operations
RATS_API rats_error_t rats_send_binary(rats_client_t client, const char* peer_id, 
                                          const void* data, size_t size);
RATS_API int rats_broadcast_binary(rats_client_t client, const void* data, size_t size);

// JSON operations
RATS_API rats_error_t rats_send_json(rats_client_t client, const char* peer_id, const char* json_str);
RATS_API int rats_broadcast_json(rats_client_t client, const char* json_str);

// DHT Discovery
RATS_API rats_error_t rats_start_dht_discovery(rats_client_t client, int dht_port);
RATS_API void rats_stop_dht_discovery(rats_client_t client);
RATS_API int rats_is_dht_running(rats_client_t client);
RATS_API rats_error_t rats_announce_for_hash(rats_client_t client, const char* content_hash, int port,
                                               rats_peers_found_cb callback, void* user_data);
RATS_API size_t rats_get_dht_routing_table_size(rats_client_t client);

// Automatic discovery
RATS_API void rats_start_automatic_peer_discovery(rats_client_t client);
RATS_API void rats_stop_automatic_peer_discovery(rats_client_t client);
RATS_API int rats_is_automatic_discovery_running(rats_client_t client);
RATS_API char* rats_get_discovery_hash(rats_client_t client); // caller must free
RATS_API char* rats_get_rats_peer_discovery_hash(void); // caller must free - static method

// mDNS Discovery  
RATS_API rats_error_t rats_start_mdns_discovery(rats_client_t client, const char* service_name);
RATS_API void rats_stop_mdns_discovery(rats_client_t client);
RATS_API int rats_is_mdns_running(rats_client_t client);
RATS_API rats_error_t rats_query_mdns_services(rats_client_t client);

// Encryption
RATS_API rats_error_t rats_set_encryption_enabled(rats_client_t client, int enabled);
RATS_API int rats_is_encryption_enabled(rats_client_t client);

// Protocol configuration
RATS_API rats_error_t rats_set_protocol_name(rats_client_t client, const char* protocol_name);
RATS_API rats_error_t rats_set_protocol_version(rats_client_t client, const char* protocol_version);
RATS_API char* rats_get_protocol_name(rats_client_t client); // caller must free
RATS_API char* rats_get_protocol_version(rats_client_t client); // caller must free

// Message Exchange API
RATS_API rats_error_t rats_on_message(rats_client_t client, const char* message_type, 
                                         rats_message_cb callback, void* user_data);
RATS_API rats_error_t rats_send_message(rats_client_t client, const char* peer_id, 
                                           const char* message_type, const char* data);
RATS_API rats_error_t rats_broadcast_message(rats_client_t client, const char* message_type, 
                                                const char* data);

// File Transfer
RATS_API char* rats_send_file(rats_client_t client, const char* peer_id, 
                                 const char* file_path, const char* remote_filename); // returns transfer_id, caller must free
RATS_API char* rats_send_directory(rats_client_t client, const char* peer_id, const char* directory_path, const char* remote_directory_name, int recursive); // returns transfer_id, caller must free
RATS_API char* rats_request_file(rats_client_t client, const char* peer_id, const char* remote_file_path, const char* local_path); // returns transfer_id, caller must free
RATS_API char* rats_request_directory(rats_client_t client, const char* peer_id, const char* remote_directory_path, const char* local_directory_path, int recursive); // returns transfer_id, caller must free
RATS_API rats_error_t rats_accept_file_transfer(rats_client_t client, const char* transfer_id, 
                                                   const char* local_path);
RATS_API rats_error_t rats_reject_file_transfer(rats_client_t client, const char* transfer_id, 
                                                   const char* reason);
RATS_API rats_error_t rats_cancel_file_transfer(rats_client_t client, const char* transfer_id);
RATS_API rats_error_t rats_accept_directory_transfer(rats_client_t client, const char* transfer_id, const char* local_path);
RATS_API rats_error_t rats_reject_directory_transfer(rats_client_t client, const char* transfer_id, const char* reason);
RATS_API rats_error_t rats_pause_file_transfer(rats_client_t client, const char* transfer_id);
RATS_API rats_error_t rats_resume_file_transfer(rats_client_t client, const char* transfer_id);
RATS_API char* rats_get_file_transfer_progress_json(rats_client_t client, const char* transfer_id); // caller must free
RATS_API char* rats_get_file_transfer_statistics_json(rats_client_t client); // caller must free

// File transfer callbacks
typedef void (*rats_file_request_cb)(void* user_data, const char* peer_id, const char* transfer_id, const char* remote_path, const char* filename);
typedef void (*rats_directory_request_cb)(void* user_data, const char* peer_id, const char* transfer_id, const char* remote_path, const char* directory_name);
typedef void (*rats_directory_progress_cb)(void* user_data, const char* transfer_id, int files_completed, int total_files, const char* current_file);
typedef void (*rats_file_progress_cb)(void* user_data, const char* transfer_id, int progress_percent, const char* status);

// Additional file transfer callbacks
RATS_API void rats_set_file_request_callback(rats_client_t client, rats_file_request_cb cb, void* user_data);
RATS_API void rats_set_directory_request_callback(rats_client_t client, rats_directory_request_cb cb, void* user_data);
RATS_API void rats_set_file_progress_callback(rats_client_t client, rats_file_progress_cb cb, void* user_data);
RATS_API void rats_set_directory_progress_callback(rats_client_t client, rats_directory_progress_cb cb, void* user_data);

// Enhanced callbacks
RATS_API void rats_set_connection_callback(rats_client_t client, rats_connection_cb cb, void* user_data);
RATS_API void rats_set_string_callback(rats_client_t client, rats_string_cb cb, void* user_data);
RATS_API void rats_set_binary_callback(rats_client_t client, rats_binary_cb cb, void* user_data);
RATS_API void rats_set_json_callback(rats_client_t client, rats_json_cb cb, void* user_data);
RATS_API void rats_set_disconnect_callback(rats_client_t client, rats_disconnect_cb cb, void* user_data);
RATS_API void rats_set_peer_discovered_callback(rats_client_t client, rats_peer_discovered_cb cb, void* user_data);

// GossipSub functionality
RATS_API int rats_is_gossipsub_available(rats_client_t client);
RATS_API int rats_is_gossipsub_running(rats_client_t client);
RATS_API rats_error_t rats_subscribe_to_topic(rats_client_t client, const char* topic);
RATS_API rats_error_t rats_unsubscribe_from_topic(rats_client_t client, const char* topic);
RATS_API int rats_is_subscribed_to_topic(rats_client_t client, const char* topic);
RATS_API char** rats_get_subscribed_topics(rats_client_t client, int* count); // caller must free array and strings
RATS_API rats_error_t rats_publish_to_topic(rats_client_t client, const char* topic, const char* message);
RATS_API rats_error_t rats_publish_json_to_topic(rats_client_t client, const char* topic, const char* json_str);
RATS_API char** rats_get_topic_peers(rats_client_t client, const char* topic, int* count); // caller must free array and strings
RATS_API char** rats_get_topic_mesh_peers(rats_client_t client, const char* topic, int* count); // caller must free array and strings
RATS_API char* rats_get_gossipsub_statistics_json(rats_client_t client); // caller must free

// GossipSub callbacks
typedef void (*rats_topic_message_cb)(void* user_data, const char* peer_id, const char* topic, const char* message);
typedef void (*rats_topic_json_message_cb)(void* user_data, const char* peer_id, const char* topic, const char* json_str);
typedef void (*rats_topic_peer_joined_cb)(void* user_data, const char* peer_id, const char* topic);
typedef void (*rats_topic_peer_left_cb)(void* user_data, const char* peer_id, const char* topic);

RATS_API void rats_set_topic_message_callback(rats_client_t client, const char* topic, rats_topic_message_cb cb, void* user_data);
RATS_API void rats_set_topic_json_message_callback(rats_client_t client, const char* topic, rats_topic_json_message_cb cb, void* user_data);
RATS_API void rats_set_topic_peer_joined_callback(rats_client_t client, const char* topic, rats_topic_peer_joined_cb cb, void* user_data);
RATS_API void rats_set_topic_peer_left_callback(rats_client_t client, const char* topic, rats_topic_peer_left_cb cb, void* user_data);
RATS_API void rats_clear_topic_callbacks(rats_client_t client, const char* topic);

// Address blocking
RATS_API void rats_add_ignored_address(rats_client_t client, const char* ip_address);

// Configuration persistence
RATS_API rats_error_t rats_load_configuration(rats_client_t client);
RATS_API rats_error_t rats_save_configuration(rats_client_t client);
RATS_API rats_error_t rats_set_data_directory(rats_client_t client, const char* directory_path);
RATS_API char* rats_get_data_directory(rats_client_t client); // caller must free
RATS_API int rats_load_and_reconnect_peers(rats_client_t client);
RATS_API int rats_load_historical_peers(rats_client_t client);
RATS_API int rats_save_historical_peers(rats_client_t client);
RATS_API void rats_clear_historical_peers(rats_client_t client);
RATS_API char** rats_get_historical_peer_ids(rats_client_t client, int* count); // caller must free array and strings

// ===================== ENHANCED ENCRYPTION API =====================

// Initialize encryption system
RATS_API rats_error_t rats_initialize_encryption(rats_client_t client, int enable);

// Check if a specific peer connection is encrypted
RATS_API int rats_is_peer_encrypted(rats_client_t client, const char* peer_id);

// Set custom Noise Protocol static keypair (32-byte private key as hex string)
RATS_API rats_error_t rats_set_noise_static_keypair(rats_client_t client, const char* private_key_hex);

// Get our Noise Protocol static public key (returns 64-char hex string, caller must free)
RATS_API char* rats_get_noise_static_public_key(rats_client_t client);

// Get remote peer's Noise static public key (returns 64-char hex string, caller must free)
RATS_API char* rats_get_peer_noise_public_key(rats_client_t client, const char* peer_id);

// Get handshake hash for channel binding (returns 64-char hex string, caller must free)
RATS_API char* rats_get_peer_handshake_hash(rats_client_t client, const char* peer_id);

// ===================== ICE (NAT TRAVERSAL) API =====================

// ICE connection states
typedef enum {
    RATS_ICE_STATE_NEW = 0,
    RATS_ICE_STATE_GATHERING = 1,
    RATS_ICE_STATE_CHECKING = 2,
    RATS_ICE_STATE_CONNECTED = 3,
    RATS_ICE_STATE_COMPLETED = 4,
    RATS_ICE_STATE_FAILED = 5,
    RATS_ICE_STATE_DISCONNECTED = 6,
    RATS_ICE_STATE_CLOSED = 7
} rats_ice_connection_state_t;

// ICE gathering states
typedef enum {
    RATS_ICE_GATHERING_NEW = 0,
    RATS_ICE_GATHERING_GATHERING = 1,
    RATS_ICE_GATHERING_COMPLETE = 2
} rats_ice_gathering_state_t;

// ICE candidate types
typedef enum {
    RATS_ICE_CANDIDATE_HOST = 0,
    RATS_ICE_CANDIDATE_SRFLX = 1,
    RATS_ICE_CANDIDATE_PRFLX = 2,
    RATS_ICE_CANDIDATE_RELAY = 3
} rats_ice_candidate_type_t;

// ICE callbacks
typedef void (*rats_ice_candidates_cb)(void* user_data, const char* candidates_json);
typedef void (*rats_ice_new_candidate_cb)(void* user_data, const char* candidate_sdp);
typedef void (*rats_ice_gathering_state_cb)(void* user_data, rats_ice_gathering_state_t state);
typedef void (*rats_ice_connection_state_cb)(void* user_data, rats_ice_connection_state_t state);
typedef void (*rats_ice_selected_pair_cb)(void* user_data, const char* local_candidate_json, const char* remote_candidate_json);

// Check if ICE is available
RATS_API int rats_is_ice_available(rats_client_t client);

// Server configuration
RATS_API void rats_add_stun_server(rats_client_t client, const char* host, uint16_t port);
RATS_API void rats_add_turn_server(rats_client_t client, const char* host, uint16_t port,
                                    const char* username, const char* password);
RATS_API void rats_clear_ice_servers(rats_client_t client);

// Candidate gathering
RATS_API int rats_gather_ice_candidates(rats_client_t client);
RATS_API char* rats_get_ice_candidates_json(rats_client_t client); // caller must free
RATS_API int rats_is_ice_gathering_complete(rats_client_t client);

// Public address discovery
RATS_API char* rats_get_public_address(rats_client_t client); // returns "ip:port" string, caller must free
RATS_API char* rats_discover_public_address(rats_client_t client, const char* stun_server, 
                                             uint16_t port, int timeout_ms); // caller must free

// Remote candidates
RATS_API void rats_add_remote_ice_candidate(rats_client_t client, const char* candidate_sdp);
RATS_API void rats_add_remote_ice_candidates_from_sdp(rats_client_t client, 
                                                       const char** sdp_lines, int count);
RATS_API void rats_end_of_remote_ice_candidates(rats_client_t client);

// Connectivity
RATS_API void rats_start_ice_checks(rats_client_t client);
RATS_API rats_ice_connection_state_t rats_get_ice_connection_state(rats_client_t client);
RATS_API rats_ice_gathering_state_t rats_get_ice_gathering_state(rats_client_t client);
RATS_API int rats_is_ice_connected(rats_client_t client);
RATS_API char* rats_get_ice_selected_pair_json(rats_client_t client); // caller must free

// ICE callbacks
RATS_API void rats_set_ice_candidates_gathered_callback(rats_client_t client, 
                                                         rats_ice_candidates_cb cb, void* user_data);
RATS_API void rats_set_ice_new_candidate_callback(rats_client_t client,
                                                   rats_ice_new_candidate_cb cb, void* user_data);
RATS_API void rats_set_ice_gathering_state_callback(rats_client_t client,
                                                     rats_ice_gathering_state_cb cb, void* user_data);
RATS_API void rats_set_ice_connection_state_callback(rats_client_t client,
                                                      rats_ice_connection_state_cb cb, void* user_data);
RATS_API void rats_set_ice_selected_pair_callback(rats_client_t client,
                                                   rats_ice_selected_pair_cb cb, void* user_data);

// ICE lifecycle
RATS_API void rats_close_ice(rats_client_t client);
RATS_API void rats_restart_ice(rats_client_t client);

#ifdef __cplusplus
} // extern "C"
#endif


