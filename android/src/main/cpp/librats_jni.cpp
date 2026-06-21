// JNI bridge for the librats C ABI (src/bindings/rats.h).
//
// Each Java RatsClient owns a native rats_t. Callbacks registered with the C
// API take a `void* user`; we pass a JNI global ref to the Java callback object
// there, and the C bridge functions below attach the calling reactor thread to
// the JVM, invoke the matching Java method, then leave the thread attached
// (the reactor reuses its threads; a registered detach-on-exit hook cleans up).
//
// All global refs created for callbacks are tracked per-node so they can be
// released in nativeDestroy.

#include <jni.h>
#include <string>
#include <vector>
#include <mutex>
#include <unordered_map>
#include <android/log.h>

#include "bindings/rats.h"

#define LOG_TAG "LibRatsJNI"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static JavaVM* g_jvm = nullptr;

// Per-node bookkeeping: every global ref handed to the C API as `user` so we
// can release them when the node is destroyed.
static std::mutex g_refs_mutex;
static std::unordered_map<rats_t, std::vector<jobject>> g_node_refs;

// ---- thread attach helpers --------------------------------------------------

// Detach the reactor thread from the JVM when it exits. The reactor keeps a
// small pool of long-lived threads, so attaching once per thread and detaching
// on thread death avoids a leak without re-attaching on every callback.
static pthread_key_t g_detach_key;
static pthread_once_t g_detach_once = PTHREAD_ONCE_INIT;

static void detach_current_thread(void* /*unused*/) {
    if (g_jvm) g_jvm->DetachCurrentThread();
}

static void make_detach_key() {
    pthread_key_create(&g_detach_key, detach_current_thread);
}

static JNIEnv* getEnv() {
    JNIEnv* env = nullptr;
    if (!g_jvm) return nullptr;
    jint rc = g_jvm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6);
    if (rc == JNI_OK) return env;
    if (rc == JNI_EDETACHED) {
        if (g_jvm->AttachCurrentThread(&env, nullptr) != JNI_OK) {
            LOGE("AttachCurrentThread failed");
            return nullptr;
        }
        pthread_once(&g_detach_once, make_detach_key);
        // Register the detach hook for this thread (value is non-null sentinel).
        pthread_setspecific(g_detach_key, reinterpret_cast<void*>(1));
        return env;
    }
    LOGE("GetEnv failed: %d", rc);
    return nullptr;
}

static jstring toJString(JNIEnv* env, const char* str) {
    if (!str) return nullptr;
    return env->NewStringUTF(str);
}

static std::string toCString(JNIEnv* env, jstring jstr) {
    if (!jstr) return std::string();
    const char* chars = env->GetStringUTFChars(jstr, nullptr);
    std::string result(chars ? chars : "");
    if (chars) env->ReleaseStringUTFChars(jstr, chars);
    return result;
}

static jbyteArray toByteArray(JNIEnv* env, const void* data, size_t len) {
    jbyteArray arr = env->NewByteArray(static_cast<jsize>(len));
    if (arr && len > 0) {
        env->SetByteArrayRegion(arr, 0, static_cast<jsize>(len),
                                static_cast<const jbyte*>(data));
    }
    return arr;
}

// Register a global ref for later cleanup, keyed by node. Returns the ref.
static jobject trackRef(JNIEnv* env, rats_t node, jobject local) {
    if (!local) return nullptr;
    jobject global = env->NewGlobalRef(local);
    std::lock_guard<std::mutex> lock(g_refs_mutex);
    g_node_refs[node].push_back(global);
    return global;
}

static void releaseRefs(JNIEnv* env, rats_t node) {
    std::vector<jobject> refs;
    {
        std::lock_guard<std::mutex> lock(g_refs_mutex);
        auto it = g_node_refs.find(node);
        if (it != g_node_refs.end()) {
            refs.swap(it->second);
            g_node_refs.erase(it);
        }
    }
    for (jobject ref : refs) env->DeleteGlobalRef(ref);
}

// ---- C -> Java callback bridges --------------------------------------------

static void peer_connected_bridge(void* user, const char* peer_id_hex) {
    JNIEnv* env = getEnv();
    if (!env) return;
    jobject obj = static_cast<jobject>(user);
    jclass cls = env->GetObjectClass(obj);
    jmethodID m = env->GetMethodID(cls, "onConnected", "(Ljava/lang/String;)V");
    jstring jid = toJString(env, peer_id_hex);
    env->CallVoidMethod(obj, m, jid);
    env->DeleteLocalRef(jid);
    env->DeleteLocalRef(cls);
}

static void peer_disconnected_bridge(void* user, const char* peer_id_hex) {
    JNIEnv* env = getEnv();
    if (!env) return;
    jobject obj = static_cast<jobject>(user);
    jclass cls = env->GetObjectClass(obj);
    jmethodID m = env->GetMethodID(cls, "onDisconnected", "(Ljava/lang/String;)V");
    jstring jid = toJString(env, peer_id_hex);
    env->CallVoidMethod(obj, m, jid);
    env->DeleteLocalRef(jid);
    env->DeleteLocalRef(cls);
}

static void message_bridge(void* user, const char* peer_id_hex, const void* data, size_t len) {
    JNIEnv* env = getEnv();
    if (!env) return;
    jobject obj = static_cast<jobject>(user);
    jclass cls = env->GetObjectClass(obj);
    jmethodID m = env->GetMethodID(cls, "onMessage", "(Ljava/lang/String;[B)V");
    jstring jid = toJString(env, peer_id_hex);
    jbyteArray jdata = toByteArray(env, data, len);
    env->CallVoidMethod(obj, m, jid, jdata);
    env->DeleteLocalRef(jid);
    env->DeleteLocalRef(jdata);
    env->DeleteLocalRef(cls);
}

static void topic_bridge(void* user, const char* peer_id_hex, const char* topic,
                         const void* data, size_t len) {
    JNIEnv* env = getEnv();
    if (!env) return;
    jobject obj = static_cast<jobject>(user);
    jclass cls = env->GetObjectClass(obj);
    jmethodID m = env->GetMethodID(cls, "onTopicMessage",
                                   "(Ljava/lang/String;Ljava/lang/String;[B)V");
    jstring jid = toJString(env, peer_id_hex);
    jstring jtopic = toJString(env, topic);
    jbyteArray jdata = toByteArray(env, data, len);
    env->CallVoidMethod(obj, m, jid, jtopic, jdata);
    env->DeleteLocalRef(jid);
    env->DeleteLocalRef(jtopic);
    env->DeleteLocalRef(jdata);
    env->DeleteLocalRef(cls);
}

static void json_bridge(void* user, const char* peer_id_hex, const char* json) {
    JNIEnv* env = getEnv();
    if (!env) return;
    jobject obj = static_cast<jobject>(user);
    jclass cls = env->GetObjectClass(obj);
    jmethodID m = env->GetMethodID(cls, "onJsonMessage",
                                   "(Ljava/lang/String;Ljava/lang/String;)V");
    jstring jid = toJString(env, peer_id_hex);
    jstring jjson = toJString(env, json);
    env->CallVoidMethod(obj, m, jid, jjson);
    env->DeleteLocalRef(jid);
    env->DeleteLocalRef(jjson);
    env->DeleteLocalRef(cls);
}

static void file_offer_bridge(void* user, const char* peer_id_hex, uint64_t transfer_id,
                              const char* name, uint64_t size, int is_directory) {
    JNIEnv* env = getEnv();
    if (!env) return;
    jobject obj = static_cast<jobject>(user);
    jclass cls = env->GetObjectClass(obj);
    jmethodID m = env->GetMethodID(cls, "onFileOffer",
                                   "(Ljava/lang/String;JLjava/lang/String;JZ)V");
    jstring jid = toJString(env, peer_id_hex);
    jstring jname = toJString(env, name);
    env->CallVoidMethod(obj, m, jid, static_cast<jlong>(transfer_id), jname,
                        static_cast<jlong>(size), is_directory ? JNI_TRUE : JNI_FALSE);
    env->DeleteLocalRef(jid);
    env->DeleteLocalRef(jname);
    env->DeleteLocalRef(cls);
}

static void file_progress_bridge(void* user, uint64_t transfer_id, const char* peer_id_hex,
                                 uint64_t bytes_transferred, uint64_t total_bytes, int status) {
    JNIEnv* env = getEnv();
    if (!env) return;
    jobject obj = static_cast<jobject>(user);
    jclass cls = env->GetObjectClass(obj);
    jmethodID m = env->GetMethodID(cls, "onFileProgress", "(JLjava/lang/String;JJI)V");
    jstring jid = toJString(env, peer_id_hex);
    env->CallVoidMethod(obj, m, static_cast<jlong>(transfer_id), jid,
                        static_cast<jlong>(bytes_transferred),
                        static_cast<jlong>(total_bytes), status);
    env->DeleteLocalRef(jid);
    env->DeleteLocalRef(cls);
}

static void file_complete_bridge(void* user, uint64_t transfer_id, int success, const char* path) {
    JNIEnv* env = getEnv();
    if (!env) return;
    jobject obj = static_cast<jobject>(user);
    jclass cls = env->GetObjectClass(obj);
    jmethodID m = env->GetMethodID(cls, "onFileComplete", "(JZLjava/lang/String;)V");
    jstring jpath = toJString(env, path);
    env->CallVoidMethod(obj, m, static_cast<jlong>(transfer_id),
                        success ? JNI_TRUE : JNI_FALSE, jpath);
    env->DeleteLocalRef(jpath);
    env->DeleteLocalRef(cls);
}

// ---- JNI exports ------------------------------------------------------------

extern "C" {

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* /*reserved*/) {
    g_jvm = vm;
    LOGD("librats JNI loaded");
    return JNI_VERSION_1_6;
}

static inline rats_t node_of(jlong ptr) {
    return reinterpret_cast<rats_t>(ptr);
}

// ---- lifecycle ----

JNIEXPORT jlong JNICALL
Java_com_librats_RatsClient_nativeCreate(JNIEnv*, jobject, jint listen_port) {
    return reinterpret_cast<jlong>(rats_create(static_cast<uint16_t>(listen_port)));
}

JNIEXPORT jlong JNICALL
Java_com_librats_RatsClient_nativeCreateConfig(JNIEnv* env, jobject, jint listen_port,
        jboolean enable_listen, jstring bind_address, jint security, jstring data_dir,
        jstring protocol_name, jstring protocol_version, jlong max_peers) {
    rats_config_t cfg = rats_config_default();
    cfg.listen_port = static_cast<uint16_t>(listen_port);
    cfg.enable_listen = enable_listen ? 1 : 0;
    cfg.security = static_cast<rats_security_t>(security);
    cfg.max_peers = static_cast<size_t>(max_peers);

    std::string bind = toCString(env, bind_address);
    std::string ddir = toCString(env, data_dir);
    std::string pname = toCString(env, protocol_name);
    std::string pver = toCString(env, protocol_version);
    cfg.bind_address = bind_address ? bind.c_str() : nullptr;
    cfg.data_dir = data_dir ? ddir.c_str() : nullptr;
    cfg.protocol_name = protocol_name ? pname.c_str() : nullptr;
    cfg.protocol_version = protocol_version ? pver.c_str() : nullptr;

    return reinterpret_cast<jlong>(rats_create_config(&cfg));
}

JNIEXPORT void JNICALL
Java_com_librats_RatsClient_nativeDestroy(JNIEnv* env, jobject, jlong ptr) {
    rats_t node = node_of(ptr);
    if (!node) return;
    rats_destroy(node);
    releaseRefs(env, node);
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsClient_nativeStart(JNIEnv*, jobject, jlong ptr) {
    return rats_start(node_of(ptr));
}

JNIEXPORT void JNICALL
Java_com_librats_RatsClient_nativeStop(JNIEnv*, jobject, jlong ptr) {
    rats_stop(node_of(ptr));
}

// ---- identity / info ----

JNIEXPORT jint JNICALL
Java_com_librats_RatsClient_nativeListenPort(JNIEnv*, jobject, jlong ptr) {
    return rats_listen_port(node_of(ptr));
}

JNIEXPORT jstring JNICALL
Java_com_librats_RatsClient_nativeLocalId(JNIEnv* env, jobject, jlong ptr) {
    char* id = rats_local_id(node_of(ptr));
    jstring result = toJString(env, id);
    if (id) rats_string_free(id);
    return result;
}

JNIEXPORT jstring JNICALL
Java_com_librats_RatsClient_nativeProtocolName(JNIEnv* env, jobject, jlong ptr) {
    char* s = rats_protocol_name(node_of(ptr));
    jstring result = toJString(env, s);
    if (s) rats_string_free(s);
    return result;
}

JNIEXPORT jstring JNICALL
Java_com_librats_RatsClient_nativeProtocolVersion(JNIEnv* env, jobject, jlong ptr) {
    char* s = rats_protocol_version(node_of(ptr));
    jstring result = toJString(env, s);
    if (s) rats_string_free(s);
    return result;
}

// ---- connections ----

JNIEXPORT jint JNICALL
Java_com_librats_RatsClient_nativeConnect(JNIEnv* env, jobject, jlong ptr, jstring host, jint port) {
    std::string h = toCString(env, host);
    return rats_connect(node_of(ptr), h.c_str(), static_cast<uint16_t>(port));
}

JNIEXPORT jlong JNICALL
Java_com_librats_RatsClient_nativePeerCount(JNIEnv*, jobject, jlong ptr) {
    return static_cast<jlong>(rats_peer_count(node_of(ptr)));
}

JNIEXPORT jobjectArray JNICALL
Java_com_librats_RatsClient_nativePeerIds(JNIEnv* env, jobject, jlong ptr) {
    size_t count = 0;
    char** ids = rats_peer_ids(node_of(ptr), &count);
    jclass strClass = env->FindClass("java/lang/String");
    jobjectArray result = env->NewObjectArray(static_cast<jsize>(count), strClass, nullptr);
    for (size_t i = 0; i < count; ++i) {
        jstring js = toJString(env, ids[i]);
        env->SetObjectArrayElement(result, static_cast<jsize>(i), js);
        env->DeleteLocalRef(js);
    }
    if (ids) rats_free_peer_ids(ids, count);
    env->DeleteLocalRef(strClass);
    return result;
}

JNIEXPORT void JNICALL
Java_com_librats_RatsClient_nativeSetMaxPeers(JNIEnv*, jobject, jlong ptr, jlong max_peers) {
    rats_set_max_peers(node_of(ptr), static_cast<size_t>(max_peers));
}

JNIEXPORT jlong JNICALL
Java_com_librats_RatsClient_nativeMaxPeers(JNIEnv*, jobject, jlong ptr) {
    return static_cast<jlong>(rats_max_peers(node_of(ptr)));
}

// ---- messaging ----

JNIEXPORT jint JNICALL
Java_com_librats_RatsClient_nativeSend(JNIEnv* env, jobject, jlong ptr, jstring peer_id,
                                       jstring channel, jbyteArray data) {
    std::string pid = toCString(env, peer_id);
    std::string ch = toCString(env, channel);
    jbyte* bytes = data ? env->GetByteArrayElements(data, nullptr) : nullptr;
    jsize len = data ? env->GetArrayLength(data) : 0;
    rats_error_t rc = rats_send(node_of(ptr), pid.c_str(), ch.c_str(), bytes, len);
    if (bytes) env->ReleaseByteArrayElements(data, bytes, JNI_ABORT);
    return rc;
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsClient_nativeBroadcast(JNIEnv* env, jobject, jlong ptr, jstring channel,
                                            jbyteArray data) {
    std::string ch = toCString(env, channel);
    jbyte* bytes = data ? env->GetByteArrayElements(data, nullptr) : nullptr;
    jsize len = data ? env->GetArrayLength(data) : 0;
    rats_error_t rc = rats_broadcast(node_of(ptr), ch.c_str(), bytes, len);
    if (bytes) env->ReleaseByteArrayElements(data, bytes, JNI_ABORT);
    return rc;
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsClient_nativeOn(JNIEnv* env, jobject, jlong ptr, jstring channel,
                                     jobject callback) {
    rats_t node = node_of(ptr);
    std::string ch = toCString(env, channel);
    jobject ref = trackRef(env, node, callback);
    return rats_on(node, ch.c_str(), message_bridge, ref);
}

// ---- peer callbacks ----

JNIEXPORT jint JNICALL
Java_com_librats_RatsClient_nativeOnPeerConnected(JNIEnv* env, jobject, jlong ptr, jobject cb) {
    rats_t node = node_of(ptr);
    jobject ref = trackRef(env, node, cb);
    return rats_on_peer_connected(node, peer_connected_bridge, ref);
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsClient_nativeOnPeerDisconnected(JNIEnv* env, jobject, jlong ptr, jobject cb) {
    rats_t node = node_of(ptr);
    jobject ref = trackRef(env, node, cb);
    return rats_on_peer_disconnected(node, peer_disconnected_bridge, ref);
}

// ---- discovery / NAT ----

JNIEXPORT jint JNICALL
Java_com_librats_RatsClient_nativeEnableDht(JNIEnv* env, jobject, jlong ptr, jint dht_port,
                                            jstring discovery_key) {
    std::string key = toCString(env, discovery_key);
    return rats_enable_dht(node_of(ptr), static_cast<uint16_t>(dht_port),
                           discovery_key ? key.c_str() : nullptr);
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsClient_nativeEnableMdns(JNIEnv*, jobject, jlong ptr) {
    return rats_enable_mdns(node_of(ptr));
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsClient_nativeEnablePortMapping(JNIEnv*, jobject, jlong ptr,
                                                    jboolean upnp, jboolean natpmp) {
    return rats_enable_port_mapping(node_of(ptr), upnp ? 1 : 0, natpmp ? 1 : 0);
}

// ---- pub/sub ----

JNIEXPORT jint JNICALL
Java_com_librats_RatsClient_nativeEnablePubsub(JNIEnv*, jobject, jlong ptr) {
    return rats_enable_pubsub(node_of(ptr));
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsClient_nativeSubscribe(JNIEnv* env, jobject, jlong ptr, jstring topic,
                                            jobject cb) {
    rats_t node = node_of(ptr);
    std::string t = toCString(env, topic);
    jobject ref = trackRef(env, node, cb);
    return rats_subscribe(node, t.c_str(), topic_bridge, ref);
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsClient_nativeUnsubscribe(JNIEnv* env, jobject, jlong ptr, jstring topic) {
    std::string t = toCString(env, topic);
    return rats_unsubscribe(node_of(ptr), t.c_str());
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsClient_nativePublish(JNIEnv* env, jobject, jlong ptr, jstring topic,
                                          jbyteArray data) {
    std::string t = toCString(env, topic);
    jbyte* bytes = data ? env->GetByteArrayElements(data, nullptr) : nullptr;
    jsize len = data ? env->GetArrayLength(data) : 0;
    rats_error_t rc = rats_publish(node_of(ptr), t.c_str(), bytes, len);
    if (bytes) env->ReleaseByteArrayElements(data, bytes, JNI_ABORT);
    return rc;
}

// ---- typed JSON ----

JNIEXPORT jint JNICALL
Java_com_librats_RatsClient_nativeEnableJson(JNIEnv*, jobject, jlong ptr) {
    return rats_enable_json(node_of(ptr));
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsClient_nativeOnJson(JNIEnv* env, jobject, jlong ptr, jstring type, jobject cb) {
    rats_t node = node_of(ptr);
    std::string t = toCString(env, type);
    jobject ref = trackRef(env, node, cb);
    return rats_on_json(node, t.c_str(), json_bridge, ref);
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsClient_nativeOnceJson(JNIEnv* env, jobject, jlong ptr, jstring type, jobject cb) {
    rats_t node = node_of(ptr);
    std::string t = toCString(env, type);
    jobject ref = trackRef(env, node, cb);
    return rats_once_json(node, t.c_str(), json_bridge, ref);
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsClient_nativeOffJson(JNIEnv* env, jobject, jlong ptr, jstring type) {
    std::string t = toCString(env, type);
    return rats_off_json(node_of(ptr), t.c_str());
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsClient_nativeSendJson(JNIEnv* env, jobject, jlong ptr, jstring peer_id,
                                           jstring type, jstring json) {
    std::string pid = toCString(env, peer_id);
    std::string t = toCString(env, type);
    std::string j = toCString(env, json);
    return rats_send_json(node_of(ptr), pid.c_str(), t.c_str(), j.c_str());
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsClient_nativeBroadcastJson(JNIEnv* env, jobject, jlong ptr, jstring type,
                                                jstring json) {
    std::string t = toCString(env, type);
    std::string j = toCString(env, json);
    return rats_broadcast_json(node_of(ptr), t.c_str(), j.c_str());
}

// ---- file transfer ----

JNIEXPORT jint JNICALL
Java_com_librats_RatsClient_nativeEnableFileTransfer(JNIEnv* env, jobject, jlong ptr,
                                                     jstring temp_dir) {
    std::string td = toCString(env, temp_dir);
    return rats_enable_file_transfer(node_of(ptr), temp_dir ? td.c_str() : nullptr);
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsClient_nativeOnFileOffer(JNIEnv* env, jobject, jlong ptr, jobject cb) {
    rats_t node = node_of(ptr);
    jobject ref = trackRef(env, node, cb);
    return rats_on_file_offer(node, file_offer_bridge, ref);
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsClient_nativeOnFileProgress(JNIEnv* env, jobject, jlong ptr, jobject cb) {
    rats_t node = node_of(ptr);
    jobject ref = trackRef(env, node, cb);
    return rats_on_file_progress(node, file_progress_bridge, ref);
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsClient_nativeOnFileComplete(JNIEnv* env, jobject, jlong ptr, jobject cb) {
    rats_t node = node_of(ptr);
    jobject ref = trackRef(env, node, cb);
    return rats_on_file_complete(node, file_complete_bridge, ref);
}

JNIEXPORT jlong JNICALL
Java_com_librats_RatsClient_nativeSendFile(JNIEnv* env, jobject, jlong ptr, jstring peer_id,
                                           jstring path) {
    std::string pid = toCString(env, peer_id);
    std::string p = toCString(env, path);
    return static_cast<jlong>(rats_send_file(node_of(ptr), pid.c_str(), p.c_str()));
}

JNIEXPORT jlong JNICALL
Java_com_librats_RatsClient_nativeSendDirectory(JNIEnv* env, jobject, jlong ptr, jstring peer_id,
                                                jstring dir_path) {
    std::string pid = toCString(env, peer_id);
    std::string p = toCString(env, dir_path);
    return static_cast<jlong>(rats_send_directory(node_of(ptr), pid.c_str(), p.c_str()));
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsClient_nativeAcceptFile(JNIEnv* env, jobject, jlong ptr, jstring peer_id,
                                             jlong transfer_id, jstring dest_path) {
    std::string pid = toCString(env, peer_id);
    std::string dp = toCString(env, dest_path);
    return rats_accept_file(node_of(ptr), pid.c_str(),
                            static_cast<uint64_t>(transfer_id), dp.c_str());
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsClient_nativeRejectFile(JNIEnv* env, jobject, jlong ptr, jstring peer_id,
                                             jlong transfer_id) {
    std::string pid = toCString(env, peer_id);
    return rats_reject_file(node_of(ptr), pid.c_str(), static_cast<uint64_t>(transfer_id));
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsClient_nativeCancelFile(JNIEnv* env, jobject, jlong ptr, jstring peer_id,
                                             jlong transfer_id) {
    std::string pid = toCString(env, peer_id);
    return rats_cancel_file(node_of(ptr), pid.c_str(), static_cast<uint64_t>(transfer_id));
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsClient_nativePauseFile(JNIEnv* env, jobject, jlong ptr, jstring peer_id,
                                            jlong transfer_id) {
    std::string pid = toCString(env, peer_id);
    return rats_pause_file(node_of(ptr), pid.c_str(), static_cast<uint64_t>(transfer_id));
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsClient_nativeResumeFile(JNIEnv* env, jobject, jlong ptr, jstring peer_id,
                                             jlong transfer_id) {
    std::string pid = toCString(env, peer_id);
    return rats_resume_file(node_of(ptr), pid.c_str(), static_cast<uint64_t>(transfer_id));
}

// ---- liveness ----

JNIEXPORT jint JNICALL
Java_com_librats_RatsClient_nativeEnablePing(JNIEnv*, jobject, jlong ptr) {
    return rats_enable_ping(node_of(ptr));
}

JNIEXPORT jlong JNICALL
Java_com_librats_RatsClient_nativePeerRttMs(JNIEnv* env, jobject, jlong ptr, jstring peer_id) {
    std::string pid = toCString(env, peer_id);
    return static_cast<jlong>(rats_peer_rtt_ms(node_of(ptr), pid.c_str()));
}

// ---- reconnection ----

JNIEXPORT jint JNICALL
Java_com_librats_RatsClient_nativeEnableReconnect(JNIEnv*, jobject, jlong ptr) {
    return rats_enable_reconnect(node_of(ptr));
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsClient_nativeAddReconnect(JNIEnv* env, jobject, jlong ptr, jstring host,
                                               jint port) {
    std::string h = toCString(env, host);
    return rats_add_reconnect(node_of(ptr), h.c_str(), static_cast<uint16_t>(port));
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsClient_nativeRemoveReconnect(JNIEnv* env, jobject, jlong ptr, jstring host,
                                                  jint port) {
    std::string h = toCString(env, host);
    return rats_remove_reconnect(node_of(ptr), h.c_str(), static_cast<uint16_t>(port));
}

// ---- static: logging ----

JNIEXPORT void JNICALL
Java_com_librats_RatsClient_nativeSetLogLevel(JNIEnv*, jclass, jint level) {
    rats_set_log_level(static_cast<rats_log_level_t>(level));
}

JNIEXPORT void JNICALL
Java_com_librats_RatsClient_nativeSetLogFile(JNIEnv* env, jclass, jstring path) {
    std::string p = toCString(env, path);
    rats_set_log_file(path ? p.c_str() : nullptr);
}

// ---- static: library info ----

JNIEXPORT jstring JNICALL
Java_com_librats_RatsClient_nativeVersionString(JNIEnv* env, jclass) {
    return toJString(env, rats_version_string());
}

JNIEXPORT jintArray JNICALL
Java_com_librats_RatsClient_nativeVersion(JNIEnv* env, jclass) {
    int major = 0, minor = 0, patch = 0, build = 0;
    rats_version(&major, &minor, &patch, &build);
    jintArray result = env->NewIntArray(4);
    jint values[4] = {major, minor, patch, build};
    env->SetIntArrayRegion(result, 0, 4, values);
    return result;
}

JNIEXPORT jstring JNICALL
Java_com_librats_RatsClient_nativeGitDescribe(JNIEnv* env, jclass) {
    return toJString(env, rats_git_describe());
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsClient_nativeAbi(JNIEnv*, jclass) {
    return static_cast<jint>(rats_abi());
}

JNIEXPORT jstring JNICALL
Java_com_librats_RatsClient_nativeErrorStr(JNIEnv* env, jclass, jint error) {
    return toJString(env, rats_error_str(static_cast<rats_error_t>(error)));
}

} // extern "C"
