#pragma once

#ifdef _WIN32
  #if defined(RATS_BUILDING_DLL)
    #define RATS_C_API __declspec(dllexport)
  #elif defined(RATS_USING_DLL)
    #define RATS_C_API __declspec(dllimport)
  #else
    #define RATS_C_API
  #endif
#else
  #if __GNUC__ >= 4
    #define RATS_C_API __attribute__((visibility("default")))
  #else
    #define RATS_C_API
  #endif
#endif

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque handle to a RatsClient instance
typedef void* rats_client_t;

// Memory helpers for returned strings
RATS_C_API void rats_string_free(const char* str);

// Version / ABI
RATS_C_API const char* rats_get_version_string(void);
RATS_C_API void rats_get_version(int* major, int* minor, int* patch, int* build);
RATS_C_API const char* rats_get_git_describe(void);
RATS_C_API uint32_t rats_get_abi(void);

// Client lifecycle
RATS_C_API rats_client_t rats_create(int listen_port);
RATS_C_API void rats_destroy(rats_client_t client);
RATS_C_API int rats_start(rats_client_t client);
RATS_C_API void rats_stop(rats_client_t client);

// Basic operations
RATS_C_API int rats_connect(rats_client_t client, const char* host, int port);
RATS_C_API int rats_broadcast_string(rats_client_t client, const char* message);
RATS_C_API int rats_send_string(rats_client_t client, const char* peer_id, const char* message);

// Info
RATS_C_API int rats_get_peer_count(rats_client_t client);
RATS_C_API char* rats_get_our_peer_id(rats_client_t client); // caller must free with rats_string_free
RATS_C_API char* rats_get_connection_statistics_json(rats_client_t client); // caller must free with rats_string_free

// Logging controls (optional helpers)
RATS_C_API void rats_set_logging_enabled(int enabled);
RATS_C_API void rats_set_log_level(const char* level_str); // "DEBUG", "INFO", "WARN", "ERROR"

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

// Connection strategy enum
typedef enum {
    RATS_STRATEGY_DIRECT_ONLY = 0,
    RATS_STRATEGY_STUN_ASSISTED = 1,
    RATS_STRATEGY_ICE_FULL = 2,
    RATS_STRATEGY_TURN_RELAY = 3,
    RATS_STRATEGY_AUTO_ADAPTIVE = 4
} rats_connection_strategy_t;

// C callbacks
typedef void (*rats_connection_cb)(void* user_data, const char* peer_id);
typedef void (*rats_string_cb)(void* user_data, const char* peer_id, const char* message);
typedef void (*rats_binary_cb)(void* user_data, const char* peer_id, const void* data, size_t size);
typedef void (*rats_json_cb)(void* user_data, const char* peer_id, const char* json_str);
typedef void (*rats_disconnect_cb)(void* user_data, const char* peer_id);
typedef void (*rats_peer_discovered_cb)(void* user_data, const char* host, int port, const char* service_name);
typedef void (*rats_message_cb)(void* user_data, const char* peer_id, const char* message_data);
typedef void (*rats_file_progress_cb)(void* user_data, const char* transfer_id, int progress_percent, const char* status);

// Peer configuration
RATS_C_API rats_error_t rats_set_max_peers(rats_client_t client, int max_peers);
RATS_C_API int rats_get_max_peers(rats_client_t client);
RATS_C_API int rats_is_peer_limit_reached(rats_client_t client);

// Advanced connection methods
RATS_C_API rats_error_t rats_connect_with_strategy(rats_client_t client, const char* host, int port, 
                                                    rats_connection_strategy_t strategy);
RATS_C_API rats_error_t rats_disconnect_peer_by_id(rats_client_t client, const char* peer_id);

// Binary data operations
RATS_C_API rats_error_t rats_send_binary(rats_client_t client, const char* peer_id, 
                                          const void* data, size_t size);
RATS_C_API int rats_broadcast_binary(rats_client_t client, const void* data, size_t size);

// JSON operations
RATS_C_API rats_error_t rats_send_json(rats_client_t client, const char* peer_id, const char* json_str);
RATS_C_API int rats_broadcast_json(rats_client_t client, const char* json_str);

// DHT Discovery
RATS_C_API rats_error_t rats_start_dht_discovery(rats_client_t client, int dht_port);
RATS_C_API void rats_stop_dht_discovery(rats_client_t client);
RATS_C_API int rats_is_dht_running(rats_client_t client);
RATS_C_API rats_error_t rats_announce_for_hash(rats_client_t client, const char* content_hash, int port);
RATS_C_API size_t rats_get_dht_routing_table_size(rats_client_t client);

// mDNS Discovery  
RATS_C_API rats_error_t rats_start_mdns_discovery(rats_client_t client, const char* service_name);
RATS_C_API void rats_stop_mdns_discovery(rats_client_t client);
RATS_C_API int rats_is_mdns_running(rats_client_t client);
RATS_C_API rats_error_t rats_query_mdns_services(rats_client_t client);

// Encryption
RATS_C_API rats_error_t rats_set_encryption_enabled(rats_client_t client, int enabled);
RATS_C_API int rats_is_encryption_enabled(rats_client_t client);
RATS_C_API char* rats_get_encryption_key(rats_client_t client); // caller must free
RATS_C_API rats_error_t rats_set_encryption_key(rats_client_t client, const char* key_hex);
RATS_C_API char* rats_generate_encryption_key(rats_client_t client); // caller must free

// Protocol configuration
RATS_C_API rats_error_t rats_set_protocol_name(rats_client_t client, const char* protocol_name);
RATS_C_API rats_error_t rats_set_protocol_version(rats_client_t client, const char* protocol_version);
RATS_C_API char* rats_get_protocol_name(rats_client_t client); // caller must free
RATS_C_API char* rats_get_protocol_version(rats_client_t client); // caller must free

// Message Exchange API
RATS_C_API rats_error_t rats_on_message(rats_client_t client, const char* message_type, 
                                         rats_message_cb callback, void* user_data);
RATS_C_API rats_error_t rats_send_message(rats_client_t client, const char* peer_id, 
                                           const char* message_type, const char* data);
RATS_C_API rats_error_t rats_broadcast_message(rats_client_t client, const char* message_type, 
                                                const char* data);

// File Transfer
RATS_C_API char* rats_send_file(rats_client_t client, const char* peer_id, 
                                 const char* file_path, const char* remote_filename); // returns transfer_id, caller must free
RATS_C_API rats_error_t rats_accept_file_transfer(rats_client_t client, const char* transfer_id, 
                                                   const char* local_path);
RATS_C_API rats_error_t rats_reject_file_transfer(rats_client_t client, const char* transfer_id, 
                                                   const char* reason);
RATS_C_API rats_error_t rats_cancel_file_transfer(rats_client_t client, const char* transfer_id);

// Enhanced callbacks
RATS_C_API void rats_set_connection_callback(rats_client_t client, rats_connection_cb cb, void* user_data);
RATS_C_API void rats_set_string_callback(rats_client_t client, rats_string_cb cb, void* user_data);
RATS_C_API void rats_set_binary_callback(rats_client_t client, rats_binary_cb cb, void* user_data);
RATS_C_API void rats_set_json_callback(rats_client_t client, rats_json_cb cb, void* user_data);
RATS_C_API void rats_set_disconnect_callback(rats_client_t client, rats_disconnect_cb cb, void* user_data);
RATS_C_API void rats_set_peer_discovered_callback(rats_client_t client, rats_peer_discovered_cb cb, void* user_data);
RATS_C_API void rats_set_file_progress_callback(rats_client_t client, rats_file_progress_cb cb, void* user_data);

// Peer information
RATS_C_API char** rats_get_peer_ids(rats_client_t client, int* count); // caller must free array and strings
RATS_C_API char* rats_get_peer_info_json(rats_client_t client, const char* peer_id); // caller must free

#ifdef __cplusplus
} // extern "C"
#endif


