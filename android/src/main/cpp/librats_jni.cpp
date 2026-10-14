// JNI bridge from com.librats.RatsNode to the librats C ABI
// (src/librats/bindings/rats.h).
//
// Each RatsNode holds a rats_t as a jlong. A Java callback is handed to the C API
// as a JNI global ref in the `void* user` slot; the refs are tracked per node and
// released after rats_destroy(), when no reactor thread can call them any more.
//
// Classes, methods and fields are looked up once, in JNI_OnLoad. That is not only
// a saving: callbacks run on reactor threads attached from native code, and
// FindClass on such a thread searches the system class loader, which cannot see
// com.librats classes at all.
//
// Strings cross as UTF-8 through String(byte[], "UTF-8") and getBytes("UTF-8"),
// not New/GetStringUTFChars: those speak "modified UTF-8", which encodes NUL and
// any character outside the BMP differently from the real UTF-8 the library
// speaks (a JSON document with an emoji in it, say).

#include <jni.h>
#include <pthread.h>
#include <android/log.h>

#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <librats/bindings/rats.h>

#define LOG_TAG "LibRatsJNI"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace {

JavaVM* g_vm = nullptr;

// ─── cached classes, methods, fields ────────────────────────────────────────

struct {
    jclass    string_cls;
    jmethodID string_from_bytes;   // String(byte[], String charsetName)
    jmethodID string_get_bytes;    // byte[] String.getBytes(String charsetName)
    jstring   utf8;                // "UTF-8"

    jclass    path_stats_cls;
    jmethodID path_stats_ctor;
    jclass    peer_info_cls;
    jmethodID peer_info_ctor;
    jclass    progress_cls;
    jmethodID progress_ctor;
    jclass    close_reason_cls;
    jmethodID close_reason_from_value;

    jmethodID on_peer;             // PeerCallback.onPeer
    jmethodID on_peer_disconnected;
    jmethodID on_dial_failed;
    jmethodID on_peer_path;
    jmethodID on_message;
    jmethodID on_topic_message;
    jmethodID on_json_message;
    jmethodID on_file_offer;
    jmethodID on_file_progress;
    jmethodID on_file_complete;

    struct {
        jfieldID protocol, data_dir, security, listen_port, bind_address, dial_only,
                 max_peers, transports, preferred_transport, transport_fallback_ms,
                 send_queue_limit, path_sample_ms, congestion_control,
                 udp_receive_window, udp_receive_budget, udp_offload, reactor_threads,
                 network_monitor;
    } config;
} J;

// Look up everything once. Any miss is a Java/native mismatch, and failing the
// library load says so far more clearly than a crash in some later callback.
bool cache_ids(JNIEnv* env) {
    bool ok = true;
    auto cls = [&](const char* name) -> jclass {
        jclass local = env->FindClass(name);
        if (!local) { LOGE("missing class %s", name); ok = false; env->ExceptionClear(); return nullptr; }
        auto global = static_cast<jclass>(env->NewGlobalRef(local));
        env->DeleteLocalRef(local);
        return global;
    };
    auto method = [&](jclass c, const char* name, const char* sig) -> jmethodID {
        if (!c) return nullptr;
        jmethodID m = env->GetMethodID(c, name, sig);
        if (!m) { LOGE("missing method %s%s", name, sig); ok = false; env->ExceptionClear(); }
        return m;
    };
    auto field = [&](jclass c, const char* name, const char* sig) -> jfieldID {
        if (!c) return nullptr;
        jfieldID f = env->GetFieldID(c, name, sig);
        if (!f) { LOGE("missing field %s %s", name, sig); ok = false; env->ExceptionClear(); }
        return f;
    };
    // Interfaces are only needed for their method ids; a method id taken from an
    // interface is valid on any object implementing it, lambdas included.
    auto callback = [&](const char* iface, const char* name, const char* sig) -> jmethodID {
        jclass local = env->FindClass(iface);
        if (!local) { LOGE("missing class %s", iface); ok = false; env->ExceptionClear(); return nullptr; }
        jmethodID m = method(local, name, sig);
        env->DeleteLocalRef(local);
        return m;
    };

    J.string_cls        = cls("java/lang/String");
    J.string_from_bytes = method(J.string_cls, "<init>", "([BLjava/lang/String;)V");
    J.string_get_bytes  = method(J.string_cls, "getBytes", "(Ljava/lang/String;)[B");
    jstring utf8 = env->NewStringUTF("UTF-8");
    J.utf8 = static_cast<jstring>(env->NewGlobalRef(utf8));
    env->DeleteLocalRef(utf8);

    J.path_stats_cls  = cls("com/librats/PathStats");
    J.path_stats_ctor = method(J.path_stats_cls, "<init>", "(JZJIIJJDJJJJJ)V");
    J.peer_info_cls   = cls("com/librats/PeerInfo");
    J.peer_info_ctor  = method(J.peer_info_cls, "<init>", "(IIILjava/lang/String;)V");
    J.progress_cls    = cls("com/librats/FileTransferProgress");
    J.progress_ctor   = method(J.progress_cls, "<init>", "(JLjava/lang/String;IIJJIID)V");
    J.close_reason_cls = cls("com/librats/CloseReason");
    if (J.close_reason_cls) {
        J.close_reason_from_value = env->GetStaticMethodID(
            J.close_reason_cls, "fromValue", "(I)Lcom/librats/CloseReason;");
        if (!J.close_reason_from_value) { LOGE("missing CloseReason.fromValue"); ok = false; env->ExceptionClear(); }
    }

    J.on_peer = callback("com/librats/PeerCallback", "onPeer", "(Ljava/lang/String;)V");
    J.on_peer_disconnected = callback("com/librats/PeerDisconnectCallback", "onPeerDisconnected",
                                      "(Ljava/lang/String;Lcom/librats/CloseReason;)V");
    J.on_dial_failed = callback("com/librats/DialFailedCallback", "onDialFailed", "(Ljava/lang/String;)V");
    J.on_peer_path = callback("com/librats/PathCallback", "onPeerPath",
                              "(Ljava/lang/String;Lcom/librats/PathStats;)V");
    J.on_message = callback("com/librats/MessageCallback", "onMessage", "(Ljava/lang/String;[B)V");
    J.on_topic_message = callback("com/librats/TopicCallback", "onTopicMessage",
                                  "(Ljava/lang/String;Ljava/lang/String;[B)V");
    J.on_json_message = callback("com/librats/JsonCallback", "onJsonMessage",
                                 "(Ljava/lang/String;Ljava/lang/String;)V");
    J.on_file_offer = callback("com/librats/FileOfferCallback", "onFileOffer",
                               "(Ljava/lang/String;JLjava/lang/String;JZ)V");
    J.on_file_progress = callback("com/librats/FileProgressCallback", "onFileProgress",
                                  "(Lcom/librats/FileTransferProgress;)V");
    J.on_file_complete = callback("com/librats/FileCompleteCallback", "onFileComplete",
                                  "(Ljava/lang/String;JZLjava/lang/String;)V");

    jclass config = env->FindClass("com/librats/RatsNode$Config");
    if (!config) { LOGE("missing class RatsNode$Config"); env->ExceptionClear(); return false; }
    J.config.protocol              = field(config, "protocol", "Ljava/lang/String;");
    J.config.data_dir              = field(config, "dataDir", "Ljava/lang/String;");
    J.config.security              = field(config, "security", "I");
    J.config.listen_port           = field(config, "listenPort", "I");
    J.config.bind_address          = field(config, "bindAddress", "Ljava/lang/String;");
    J.config.dial_only             = field(config, "dialOnly", "Z");
    J.config.max_peers             = field(config, "maxPeers", "J");
    J.config.transports            = field(config, "transports", "I");
    J.config.preferred_transport   = field(config, "preferredTransport", "I");
    J.config.transport_fallback_ms = field(config, "transportFallbackMs", "I");
    J.config.send_queue_limit      = field(config, "sendQueueLimit", "J");
    J.config.path_sample_ms        = field(config, "pathSampleMs", "I");
    J.config.congestion_control    = field(config, "congestionControl", "I");
    J.config.udp_receive_window    = field(config, "udpReceiveWindow", "J");
    J.config.udp_receive_budget    = field(config, "udpReceiveBudget", "J");
    J.config.udp_offload           = field(config, "udpOffload", "Z");
    J.config.reactor_threads       = field(config, "reactorThreads", "I");
    J.config.network_monitor       = field(config, "networkMonitor", "Z");
    env->DeleteLocalRef(config);
    return ok;
}

// ─── threads ────────────────────────────────────────────────────────────────

// Reactor threads are long-lived: attach once, and detach when the thread exits.
pthread_key_t  g_detach_key;
pthread_once_t g_detach_once = PTHREAD_ONCE_INIT;

void detach_thread(void*) {
    if (g_vm) g_vm->DetachCurrentThread();
}

void make_detach_key() {
    pthread_key_create(&g_detach_key, detach_thread);
}

// The JNIEnv of the calling thread, attaching it if it is a library thread.
JNIEnv* env_for_callback() {
    JNIEnv* env = nullptr;
    if (!g_vm) return nullptr;
    const jint rc = g_vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6);
    if (rc == JNI_OK) return env;
    if (rc != JNI_EDETACHED) return nullptr;
    JavaVMAttachArgs args{JNI_VERSION_1_6, const_cast<char*>("librats"), nullptr};
    if (g_vm->AttachCurrentThread(&env, &args) != JNI_OK) {
        LOGE("AttachCurrentThread failed");
        return nullptr;
    }
    pthread_once(&g_detach_once, make_detach_key);
    pthread_setspecific(g_detach_key, reinterpret_cast<void*>(1));   // non-null: run the destructor
    return env;
}

// A callback has nowhere to return an exception to, and a pending one would break
// the next JNI call on the thread: log it and clear it.
void clear_callback_exception(JNIEnv* env, const char* where) {
    if (!env->ExceptionCheck()) return;
    LOGE("exception thrown from a %s callback", where);
    env->ExceptionDescribe();
    env->ExceptionClear();
}

// ─── strings and bytes ──────────────────────────────────────────────────────

// A UTF-8 C string as a Java String; null for null.
jstring to_jstring(JNIEnv* env, const char* s) {
    if (!s) return nullptr;
    const jsize len = static_cast<jsize>(std::char_traits<char>::length(s));
    jbyteArray bytes = env->NewByteArray(len);
    if (!bytes) return nullptr;
    env->SetByteArrayRegion(bytes, 0, len, reinterpret_cast<const jbyte*>(s));
    auto str = static_cast<jstring>(env->NewObject(J.string_cls, J.string_from_bytes, bytes, J.utf8));
    env->DeleteLocalRef(bytes);
    return str;
}

// A Java String as UTF-8, remembering whether it was null so that the C API can
// tell a missing argument from an empty one.
class Utf8 {
public:
    Utf8(JNIEnv* env, jstring s) : null_(s == nullptr) {
        if (null_) return;
        auto bytes = static_cast<jbyteArray>(env->CallObjectMethod(s, J.string_get_bytes, J.utf8));
        if (!bytes) return;   // exception pending; the caller's return value is moot
        const jsize len = env->GetArrayLength(bytes);
        value_.resize(static_cast<size_t>(len));
        if (len > 0) env->GetByteArrayRegion(bytes, 0, len, reinterpret_cast<jbyte*>(&value_[0]));
        env->DeleteLocalRef(bytes);
    }
    const char* get() const { return null_ ? nullptr : value_.c_str(); }

private:
    bool        null_;
    std::string value_;
};

// A byte[] pinned or copied for the duration of one C call; released without
// copying back.
class Bytes {
public:
    Bytes(JNIEnv* env, jbyteArray array) : env_(env), array_(array) {
        if (!array) return;
        data_ = env->GetByteArrayElements(array, nullptr);
        len_  = static_cast<size_t>(env->GetArrayLength(array));
    }
    ~Bytes() {
        if (data_) env_->ReleaseByteArrayElements(array_, data_, JNI_ABORT);
    }
    Bytes(const Bytes&) = delete;
    Bytes& operator=(const Bytes&) = delete;

    const void* data() const { return data_; }
    size_t      size() const { return len_; }

private:
    JNIEnv*    env_;
    jbyteArray array_;
    jbyte*     data_ = nullptr;
    size_t     len_  = 0;
};

jbyteArray to_jbytes(JNIEnv* env, const void* data, size_t len) {
    jbyteArray array = env->NewByteArray(static_cast<jsize>(len));
    if (array && len > 0)
        env->SetByteArrayRegion(array, 0, static_cast<jsize>(len), static_cast<const jbyte*>(data));
    return array;
}

// A C string array (rats_peer_ids / rats_observed_addresses) as String[], freeing it.
jobjectArray to_jstrings(JNIEnv* env, char** strings, size_t count) {
    jobjectArray out = env->NewObjectArray(static_cast<jsize>(count), J.string_cls, nullptr);
    for (size_t i = 0; out && i < count; ++i) {
        jstring s = to_jstring(env, strings[i]);
        env->SetObjectArrayElement(out, static_cast<jsize>(i), s);
        env->DeleteLocalRef(s);
    }
    rats_strings_free(strings, count);
    return out;
}

// ─── value objects ──────────────────────────────────────────────────────────

jobject to_jpath_stats(JNIEnv* env, const rats_path_stats_t& s) {
    return env->NewObject(J.path_stats_cls, J.path_stats_ctor,
                          static_cast<jlong>(s.bandwidth_bps),
                          s.app_limited ? JNI_TRUE : JNI_FALSE,
                          static_cast<jlong>(s.pacing_bps),
                          static_cast<jint>(s.srtt_us),
                          static_cast<jint>(s.min_rtt_us),
                          static_cast<jlong>(s.queued_bytes),
                          static_cast<jlong>(s.bytes_in_flight),
                          static_cast<jdouble>(s.loss),
                          static_cast<jlong>(s.bytes_delivered),
                          static_cast<jlong>(s.bytes_lost),
                          static_cast<jlong>(s.live_sent),
                          static_cast<jlong>(s.live_expired),
                          static_cast<jlong>(s.live_repair_bytes));
}

jobject to_jpeer_info(JNIEnv* env, const rats_peer_info_t& info) {
    jstring address = to_jstring(env, info.address);
    jobject out = env->NewObject(J.peer_info_cls, J.peer_info_ctor,
                                 static_cast<jint>(info.transport),
                                 static_cast<jint>(info.transports),
                                 static_cast<jint>(info.direction),
                                 address);
    env->DeleteLocalRef(address);
    return out;
}

jobject to_jprogress(JNIEnv* env, const rats_file_progress_t& p) {
    jstring peer = to_jstring(env, p.peer_id);
    jobject out = env->NewObject(J.progress_cls, J.progress_ctor,
                                 static_cast<jlong>(p.transfer_id),
                                 peer,
                                 static_cast<jint>(p.direction),
                                 static_cast<jint>(p.status),
                                 static_cast<jlong>(p.bytes_transferred),
                                 static_cast<jlong>(p.total_bytes),
                                 static_cast<jint>(p.files_completed),
                                 static_cast<jint>(p.total_files),
                                 static_cast<jdouble>(p.rate_bytes_per_sec));
    env->DeleteLocalRef(peer);
    return out;
}

// ─── callback refs ──────────────────────────────────────────────────────────

std::mutex                                      g_refs_mutex;
std::unordered_map<rats_t, std::vector<jobject>> g_refs;

// Register a callback with the C API. The global ref is kept for the node's
// lifetime when the registration succeeds and dropped at once when it does not.
template <class Register>
jint register_callback(JNIEnv* env, rats_t node, jobject callback, Register reg) {
    if (!callback) return RATS_ERR_INVALID_ARG;
    jobject ref = env->NewGlobalRef(callback);
    const rats_error_t rc = reg(static_cast<void*>(ref));
    if (rc != RATS_OK) {
        env->DeleteGlobalRef(ref);
        return rc;
    }
    std::lock_guard<std::mutex> lock(g_refs_mutex);
    g_refs[node].push_back(ref);
    return RATS_OK;
}

// Only after rats_destroy(): no thread can be inside one of these any more.
void release_callbacks(JNIEnv* env, rats_t node) {
    std::vector<jobject> refs;
    {
        std::lock_guard<std::mutex> lock(g_refs_mutex);
        auto it = g_refs.find(node);
        if (it == g_refs.end()) return;
        refs.swap(it->second);
        g_refs.erase(it);
    }
    for (jobject ref : refs) env->DeleteGlobalRef(ref);
}

// ─── C → Java ───────────────────────────────────────────────────────────────

void peer_bridge(void* user, const char* peer_id) {
    JNIEnv* env = env_for_callback();
    if (!env) return;
    jstring id = to_jstring(env, peer_id);
    env->CallVoidMethod(static_cast<jobject>(user), J.on_peer, id);
    clear_callback_exception(env, "peer");
    env->DeleteLocalRef(id);
}

void disconnect_bridge(void* user, const char* peer_id, rats_close_reason_t reason) {
    JNIEnv* env = env_for_callback();
    if (!env) return;
    jstring id = to_jstring(env, peer_id);
    jobject why = env->CallStaticObjectMethod(J.close_reason_cls, J.close_reason_from_value,
                                              static_cast<jint>(reason));
    env->CallVoidMethod(static_cast<jobject>(user), J.on_peer_disconnected, id, why);
    clear_callback_exception(env, "peer-disconnected");
    env->DeleteLocalRef(why);
    env->DeleteLocalRef(id);
}

void dial_failed_bridge(void* user, const char* address) {
    JNIEnv* env = env_for_callback();
    if (!env) return;
    jstring addr = to_jstring(env, address);
    env->CallVoidMethod(static_cast<jobject>(user), J.on_dial_failed, addr);
    clear_callback_exception(env, "dial-failed");
    env->DeleteLocalRef(addr);
}

void path_bridge(void* user, const char* peer_id, const rats_path_stats_t* stats) {
    JNIEnv* env = env_for_callback();
    if (!env || !stats) return;
    jstring id = to_jstring(env, peer_id);
    jobject jstats = to_jpath_stats(env, *stats);
    env->CallVoidMethod(static_cast<jobject>(user), J.on_peer_path, id, jstats);
    clear_callback_exception(env, "peer-path");
    env->DeleteLocalRef(jstats);
    env->DeleteLocalRef(id);
}

void message_bridge(void* user, const char* peer_id, const void* data, size_t len) {
    JNIEnv* env = env_for_callback();
    if (!env) return;
    jstring id = to_jstring(env, peer_id);
    jbyteArray bytes = to_jbytes(env, data, len);
    env->CallVoidMethod(static_cast<jobject>(user), J.on_message, id, bytes);
    clear_callback_exception(env, "message");
    env->DeleteLocalRef(bytes);
    env->DeleteLocalRef(id);
}

void topic_bridge(void* user, const char* peer_id, const char* topic, const void* data, size_t len) {
    JNIEnv* env = env_for_callback();
    if (!env) return;
    jstring id = to_jstring(env, peer_id);
    jstring jtopic = to_jstring(env, topic);
    jbyteArray bytes = to_jbytes(env, data, len);
    env->CallVoidMethod(static_cast<jobject>(user), J.on_topic_message, id, jtopic, bytes);
    clear_callback_exception(env, "topic");
    env->DeleteLocalRef(bytes);
    env->DeleteLocalRef(jtopic);
    env->DeleteLocalRef(id);
}

void json_bridge(void* user, const char* peer_id, const char* json) {
    JNIEnv* env = env_for_callback();
    if (!env) return;
    jstring id = to_jstring(env, peer_id);
    jstring text = to_jstring(env, json);
    env->CallVoidMethod(static_cast<jobject>(user), J.on_json_message, id, text);
    clear_callback_exception(env, "JSON");
    env->DeleteLocalRef(text);
    env->DeleteLocalRef(id);
}

void file_offer_bridge(void* user, const char* peer_id, uint64_t transfer_id, const char* name,
                       uint64_t size, int is_directory) {
    JNIEnv* env = env_for_callback();
    if (!env) return;
    jstring id = to_jstring(env, peer_id);
    jstring jname = to_jstring(env, name);
    env->CallVoidMethod(static_cast<jobject>(user), J.on_file_offer, id,
                        static_cast<jlong>(transfer_id), jname, static_cast<jlong>(size),
                        is_directory ? JNI_TRUE : JNI_FALSE);
    clear_callback_exception(env, "file-offer");
    env->DeleteLocalRef(jname);
    env->DeleteLocalRef(id);
}

void file_progress_bridge(void* user, const rats_file_progress_t* progress) {
    JNIEnv* env = env_for_callback();
    if (!env || !progress) return;
    jobject jprogress = to_jprogress(env, *progress);
    env->CallVoidMethod(static_cast<jobject>(user), J.on_file_progress, jprogress);
    clear_callback_exception(env, "file-progress");
    env->DeleteLocalRef(jprogress);
}

void file_complete_bridge(void* user, const char* peer_id, uint64_t transfer_id, int success,
                          const char* path) {
    JNIEnv* env = env_for_callback();
    if (!env) return;
    jstring id = to_jstring(env, peer_id);
    jstring jpath = to_jstring(env, path);
    env->CallVoidMethod(static_cast<jobject>(user), J.on_file_complete, id,
                        static_cast<jlong>(transfer_id), success ? JNI_TRUE : JNI_FALSE, jpath);
    clear_callback_exception(env, "file-complete");
    env->DeleteLocalRef(jpath);
    env->DeleteLocalRef(id);
}

inline rats_t node_of(jlong ptr) { return reinterpret_cast<rats_t>(ptr); }

} // namespace

// ─── JNI exports ────────────────────────────────────────────────────────────

extern "C" {

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    g_vm = vm;
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    if (!cache_ids(env)) {
        LOGE("librats_jni does not match the com.librats Java classes");
        return JNI_ERR;
    }
    return JNI_VERSION_1_6;
}

// ---- construction and lifecycle ----

JNIEXPORT jlong JNICALL
Java_com_librats_RatsNode_nativeCreate(JNIEnv* env, jclass, jobject config) {
    rats_config_t cfg{};   // zero is the default in every field
    Utf8 protocol(env, static_cast<jstring>(env->GetObjectField(config, J.config.protocol)));
    Utf8 data_dir(env, static_cast<jstring>(env->GetObjectField(config, J.config.data_dir)));
    Utf8 bind(env, static_cast<jstring>(env->GetObjectField(config, J.config.bind_address)));
    if (env->ExceptionCheck()) return 0;

    cfg.protocol     = protocol.get();
    cfg.data_dir     = data_dir.get();
    cfg.security     = static_cast<rats_security_t>(env->GetIntField(config, J.config.security));
    cfg.listen_port  = static_cast<uint16_t>(env->GetIntField(config, J.config.listen_port));
    cfg.bind_address = bind.get();
    cfg.dial_only    = env->GetBooleanField(config, J.config.dial_only) ? 1 : 0;
    cfg.max_peers    = static_cast<size_t>(env->GetLongField(config, J.config.max_peers));
    cfg.transports   = static_cast<uint32_t>(env->GetIntField(config, J.config.transports));
    cfg.preferred_transport =
        static_cast<rats_transport_t>(env->GetIntField(config, J.config.preferred_transport));
    // Config.FALLBACK_NEVER is -1, which is RATS_FALLBACK_NEVER as a uint32.
    cfg.transport_fallback_ms =
        static_cast<uint32_t>(env->GetIntField(config, J.config.transport_fallback_ms));
    cfg.send_queue_limit = static_cast<size_t>(env->GetLongField(config, J.config.send_queue_limit));
    cfg.path_sample_ms   = static_cast<uint32_t>(env->GetIntField(config, J.config.path_sample_ms));
    cfg.congestion_control =
        static_cast<rats_congestion_t>(env->GetIntField(config, J.config.congestion_control));
    cfg.udp_receive_window  = static_cast<size_t>(env->GetLongField(config, J.config.udp_receive_window));
    cfg.udp_receive_budget  = static_cast<size_t>(env->GetLongField(config, J.config.udp_receive_budget));
    cfg.disable_udp_offload = env->GetBooleanField(config, J.config.udp_offload) ? 0 : 1;
    cfg.reactor_threads     = static_cast<size_t>(env->GetIntField(config, J.config.reactor_threads));
    cfg.disable_network_monitor = env->GetBooleanField(config, J.config.network_monitor) ? 0 : 1;

    return reinterpret_cast<jlong>(rats_create(&cfg));
}

JNIEXPORT void JNICALL
Java_com_librats_RatsNode_nativeDestroy(JNIEnv* env, jclass, jlong ptr) {
    rats_t node = node_of(ptr);
    rats_destroy(node);              // joins every thread that could call back
    release_callbacks(env, node);
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativeStart(JNIEnv*, jclass, jlong ptr) {
    return rats_start(node_of(ptr));
}

JNIEXPORT void JNICALL
Java_com_librats_RatsNode_nativeStop(JNIEnv*, jclass, jlong ptr) {
    rats_stop(node_of(ptr));
}

// ---- this node ----

JNIEXPORT jstring JNICALL
Java_com_librats_RatsNode_nativeLocalId(JNIEnv* env, jclass, jlong ptr) {
    return to_jstring(env, rats_local_id(node_of(ptr)));
}

JNIEXPORT jstring JNICALL
Java_com_librats_RatsNode_nativeProtocol(JNIEnv* env, jclass, jlong ptr) {
    return to_jstring(env, rats_protocol(node_of(ptr)));
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativeListenPort(JNIEnv*, jclass, jlong ptr) {
    return rats_listen_port(node_of(ptr));
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativeTransports(JNIEnv*, jclass, jlong ptr) {
    return static_cast<jint>(rats_transports(node_of(ptr)));
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativeNatMapping(JNIEnv*, jclass, jlong ptr) {
    return rats_nat_mapping(node_of(ptr));
}

JNIEXPORT jobjectArray JNICALL
Java_com_librats_RatsNode_nativeObservedAddresses(JNIEnv* env, jclass, jlong ptr) {
    size_t count = 0;
    char** addresses = rats_observed_addresses(node_of(ptr), &count);
    return to_jstrings(env, addresses, count);
}

// ---- peers ----

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativeConnect(JNIEnv* env, jclass, jlong ptr, jstring host, jint port) {
    Utf8 h(env, host);
    return rats_connect(node_of(ptr), h.get(), static_cast<uint16_t>(port));
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativeDisconnect(JNIEnv* env, jclass, jlong ptr, jstring peer_id) {
    Utf8 id(env, peer_id);
    return rats_disconnect(node_of(ptr), id.get());
}

JNIEXPORT jlong JNICALL
Java_com_librats_RatsNode_nativePeerCount(JNIEnv*, jclass, jlong ptr) {
    return static_cast<jlong>(rats_peer_count(node_of(ptr)));
}

JNIEXPORT jobjectArray JNICALL
Java_com_librats_RatsNode_nativePeerIds(JNIEnv* env, jclass, jlong ptr) {
    size_t count = 0;
    char** ids = rats_peer_ids(node_of(ptr), &count);
    return to_jstrings(env, ids, count);
}

// Returns the rats_error_t; on RATS_OK out[0] holds the PeerInfo.
JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativePeerInfo(JNIEnv* env, jclass, jlong ptr, jstring peer_id,
                                         jobjectArray out) {
    Utf8 id(env, peer_id);
    rats_peer_info_t info{};
    const rats_error_t rc = rats_peer_info(node_of(ptr), id.get(), &info);
    if (rc != RATS_OK) return rc;
    jobject jinfo = to_jpeer_info(env, info);
    if (!jinfo) return RATS_ERR_INTERNAL;
    env->SetObjectArrayElement(out, 0, jinfo);
    env->DeleteLocalRef(jinfo);
    return RATS_OK;
}

JNIEXPORT void JNICALL
Java_com_librats_RatsNode_nativeSetMaxPeers(JNIEnv*, jclass, jlong ptr, jlong max_peers) {
    rats_set_max_peers(node_of(ptr), static_cast<size_t>(max_peers));
}

JNIEXPORT jlong JNICALL
Java_com_librats_RatsNode_nativeMaxPeers(JNIEnv*, jclass, jlong ptr) {
    return static_cast<jlong>(rats_max_peers(node_of(ptr)));
}

// ---- messaging ----

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativeSend(JNIEnv* env, jclass, jlong ptr, jstring peer_id,
                                     jstring channel, jbyteArray data, jint lifetime_ms) {
    Utf8 id(env, peer_id);
    Utf8 ch(env, channel);
    Bytes bytes(env, data);
    return rats_send(node_of(ptr), id.get(), ch.get(), bytes.data(), bytes.size(),
                     static_cast<uint32_t>(lifetime_ms));   // >= 0, checked in Java
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativeBroadcast(JNIEnv* env, jclass, jlong ptr, jstring channel,
                                          jbyteArray data, jint lifetime_ms) {
    Utf8 ch(env, channel);
    Bytes bytes(env, data);
    return rats_broadcast(node_of(ptr), ch.get(), bytes.data(), bytes.size(),
                          static_cast<uint32_t>(lifetime_ms));
}

JNIEXPORT jboolean JNICALL
Java_com_librats_RatsNode_nativePeerWritable(JNIEnv* env, jclass, jlong ptr, jstring peer_id) {
    Utf8 id(env, peer_id);
    return rats_peer_writable(node_of(ptr), id.get()) ? JNI_TRUE : JNI_FALSE;
}

// Returns the rats_error_t; on RATS_OK out[0] holds the PathStats.
JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativePathStats(JNIEnv* env, jclass, jlong ptr, jstring peer_id,
                                          jobjectArray out) {
    Utf8 id(env, peer_id);
    rats_path_stats_t stats{};
    const rats_error_t rc = rats_path_stats(node_of(ptr), id.get(), &stats);
    if (rc != RATS_OK) return rc;
    jobject jstats = to_jpath_stats(env, stats);
    if (!jstats) return RATS_ERR_INTERNAL;
    env->SetObjectArrayElement(out, 0, jstats);
    env->DeleteLocalRef(jstats);
    return RATS_OK;
}

// ---- callbacks ----

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativeOn(JNIEnv* env, jclass, jlong ptr, jstring channel, jobject cb) {
    rats_t node = node_of(ptr);
    Utf8 ch(env, channel);
    return register_callback(env, node, cb, [&](void* user) {
        return rats_on(node, ch.get(), message_bridge, user);
    });
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativeOnPeerConnected(JNIEnv* env, jclass, jlong ptr, jobject cb) {
    rats_t node = node_of(ptr);
    return register_callback(env, node, cb, [&](void* user) {
        return rats_on_peer_connected(node, peer_bridge, user);
    });
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativeOnPeerDisconnected(JNIEnv* env, jclass, jlong ptr, jobject cb) {
    rats_t node = node_of(ptr);
    return register_callback(env, node, cb, [&](void* user) {
        return rats_on_peer_disconnected(node, disconnect_bridge, user);
    });
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativeOnDialFailed(JNIEnv* env, jclass, jlong ptr, jobject cb) {
    rats_t node = node_of(ptr);
    return register_callback(env, node, cb, [&](void* user) {
        return rats_on_dial_failed(node, dial_failed_bridge, user);
    });
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativeOnPeerWritable(JNIEnv* env, jclass, jlong ptr, jobject cb) {
    rats_t node = node_of(ptr);
    return register_callback(env, node, cb, [&](void* user) {
        return rats_on_peer_writable(node, peer_bridge, user);
    });
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativeOnPeerPath(JNIEnv* env, jclass, jlong ptr, jobject cb) {
    rats_t node = node_of(ptr);
    return register_callback(env, node, cb, [&](void* user) {
        return rats_on_peer_path(node, path_bridge, user);
    });
}

// ---- discovery ----

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativeEnableDht(JNIEnv* env, jclass, jlong ptr, jint dht_port,
                                          jstring discovery_key) {
    Utf8 key(env, discovery_key);
    return rats_enable_dht(node_of(ptr), static_cast<uint16_t>(dht_port), key.get());
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativeEnableMdns(JNIEnv*, jclass, jlong ptr) {
    return rats_enable_mdns(node_of(ptr));
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativeEnablePeerExchange(JNIEnv*, jclass, jlong ptr) {
    return rats_enable_peer_exchange(node_of(ptr));
}

// ---- NAT traversal ----

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativeEnablePortMapping(JNIEnv*, jclass, jlong ptr, jboolean upnp,
                                                  jboolean natpmp) {
    return rats_enable_port_mapping(node_of(ptr), upnp ? 1 : 0, natpmp ? 1 : 0);
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativeEnableHolePunch(JNIEnv*, jclass, jlong ptr, jboolean serve_rendezvous) {
    return rats_enable_hole_punch(node_of(ptr), serve_rendezvous ? 1 : 0);
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativePunchPeer(JNIEnv* env, jclass, jlong ptr, jstring peer_id) {
    Utf8 id(env, peer_id);
    return rats_punch_peer(node_of(ptr), id.get());
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativeEnableRelay(JNIEnv*, jclass, jlong ptr, jboolean serve) {
    return rats_enable_relay(node_of(ptr), serve ? 1 : 0);
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativeConnectViaRelay(JNIEnv* env, jclass, jlong ptr, jstring peer_id) {
    Utf8 id(env, peer_id);
    return rats_connect_via_relay(node_of(ptr), id.get());
}

// ---- pub/sub ----

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativeEnablePubsub(JNIEnv*, jclass, jlong ptr) {
    return rats_enable_pubsub(node_of(ptr));
}

// A re-subscribe replaces the C handler but this ref stays with the node until
// it is destroyed: the old handler may be running on a reactor thread right now.
JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativeSubscribe(JNIEnv* env, jclass, jlong ptr, jstring topic, jobject cb) {
    rats_t node = node_of(ptr);
    Utf8 t(env, topic);
    return register_callback(env, node, cb, [&](void* user) {
        return rats_subscribe(node, t.get(), topic_bridge, user);
    });
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativeUnsubscribe(JNIEnv* env, jclass, jlong ptr, jstring topic) {
    Utf8 t(env, topic);
    return rats_unsubscribe(node_of(ptr), t.get());
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativePublish(JNIEnv* env, jclass, jlong ptr, jstring topic,
                                        jbyteArray data) {
    Utf8 t(env, topic);
    Bytes bytes(env, data);
    return rats_publish(node_of(ptr), t.get(), bytes.data(), bytes.size());
}

// ---- JSON messaging ----

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativeEnableJson(JNIEnv*, jclass, jlong ptr) {
    return rats_enable_json(node_of(ptr));
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativeOnJson(JNIEnv* env, jclass, jlong ptr, jstring type, jobject cb) {
    rats_t node = node_of(ptr);
    Utf8 t(env, type);
    return register_callback(env, node, cb, [&](void* user) {
        return rats_on_json(node, t.get(), json_bridge, user);
    });
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativeOnceJson(JNIEnv* env, jclass, jlong ptr, jstring type, jobject cb) {
    rats_t node = node_of(ptr);
    Utf8 t(env, type);
    return register_callback(env, node, cb, [&](void* user) {
        return rats_once_json(node, t.get(), json_bridge, user);
    });
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativeOffJson(JNIEnv* env, jclass, jlong ptr, jstring type) {
    Utf8 t(env, type);
    return rats_off_json(node_of(ptr), t.get());
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativeSendJson(JNIEnv* env, jclass, jlong ptr, jstring peer_id,
                                         jstring type, jstring json) {
    Utf8 id(env, peer_id);
    Utf8 t(env, type);
    Utf8 j(env, json);
    return rats_send_json(node_of(ptr), id.get(), t.get(), j.get());
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativeBroadcastJson(JNIEnv* env, jclass, jlong ptr, jstring type,
                                              jstring json) {
    Utf8 t(env, type);
    Utf8 j(env, json);
    return rats_broadcast_json(node_of(ptr), t.get(), j.get());
}

// ---- file transfer ----

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativeEnableFileTransfer(JNIEnv* env, jclass, jlong ptr, jstring temp_dir) {
    Utf8 dir(env, temp_dir);
    return rats_enable_file_transfer(node_of(ptr), dir.get());
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativeOnFileOffer(JNIEnv* env, jclass, jlong ptr, jobject cb) {
    rats_t node = node_of(ptr);
    return register_callback(env, node, cb, [&](void* user) {
        return rats_on_file_offer(node, file_offer_bridge, user);
    });
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativeOnFileProgress(JNIEnv* env, jclass, jlong ptr, jobject cb) {
    rats_t node = node_of(ptr);
    return register_callback(env, node, cb, [&](void* user) {
        return rats_on_file_progress(node, file_progress_bridge, user);
    });
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativeOnFileComplete(JNIEnv* env, jclass, jlong ptr, jobject cb) {
    rats_t node = node_of(ptr);
    return register_callback(env, node, cb, [&](void* user) {
        return rats_on_file_complete(node, file_complete_bridge, user);
    });
}

// The transfer id comes back through a long[1]; the return is the error code.
static jint offer_result(JNIEnv* env, rats_error_t err, uint64_t transfer_id, jlongArray out) {
    if (err == RATS_OK && out && env->GetArrayLength(out) > 0) {
        const jlong id = static_cast<jlong>(transfer_id);
        env->SetLongArrayRegion(out, 0, 1, &id);
    }
    return err;
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativeSendFile(JNIEnv* env, jclass, jlong ptr, jstring peer_id, jstring path,
                                         jlongArray transfer_id) {
    Utf8 id(env, peer_id);
    Utf8 p(env, path);
    uint64_t tid = 0;
    return offer_result(env, rats_send_file(node_of(ptr), id.get(), p.get(), &tid), tid, transfer_id);
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativeSendDirectory(JNIEnv* env, jclass, jlong ptr, jstring peer_id,
                                              jstring path, jlongArray transfer_id) {
    Utf8 id(env, peer_id);
    Utf8 p(env, path);
    uint64_t tid = 0;
    return offer_result(env, rats_send_directory(node_of(ptr), id.get(), p.get(), &tid), tid, transfer_id);
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativeAcceptFile(JNIEnv* env, jclass, jlong ptr, jstring peer_id,
                                           jlong transfer_id, jstring dest_path) {
    Utf8 id(env, peer_id);
    Utf8 dest(env, dest_path);
    return rats_accept_file(node_of(ptr), id.get(), static_cast<uint64_t>(transfer_id), dest.get());
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativeRejectFile(JNIEnv* env, jclass, jlong ptr, jstring peer_id,
                                           jlong transfer_id) {
    Utf8 id(env, peer_id);
    return rats_reject_file(node_of(ptr), id.get(), static_cast<uint64_t>(transfer_id));
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativeCancelFile(JNIEnv* env, jclass, jlong ptr, jstring peer_id,
                                           jlong transfer_id) {
    Utf8 id(env, peer_id);
    return rats_cancel_file(node_of(ptr), id.get(), static_cast<uint64_t>(transfer_id));
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativePauseFile(JNIEnv* env, jclass, jlong ptr, jstring peer_id,
                                          jlong transfer_id) {
    Utf8 id(env, peer_id);
    return rats_pause_file(node_of(ptr), id.get(), static_cast<uint64_t>(transfer_id));
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativeResumeFile(JNIEnv* env, jclass, jlong ptr, jstring peer_id,
                                           jlong transfer_id) {
    Utf8 id(env, peer_id);
    return rats_resume_file(node_of(ptr), id.get(), static_cast<uint64_t>(transfer_id));
}

// ---- ping and reconnection ----

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativeEnablePing(JNIEnv*, jclass, jlong ptr) {
    return rats_enable_ping(node_of(ptr));
}

JNIEXPORT jlong JNICALL
Java_com_librats_RatsNode_nativePeerRttMs(JNIEnv* env, jclass, jlong ptr, jstring peer_id) {
    Utf8 id(env, peer_id);
    return static_cast<jlong>(rats_peer_rtt_ms(node_of(ptr), id.get()));
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativeEnableReconnect(JNIEnv*, jclass, jlong ptr) {
    return rats_enable_reconnect(node_of(ptr));
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativeAddReconnect(JNIEnv* env, jclass, jlong ptr, jstring host, jint port) {
    Utf8 h(env, host);
    return rats_add_reconnect(node_of(ptr), h.get(), static_cast<uint16_t>(port));
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativeRemoveReconnect(JNIEnv* env, jclass, jlong ptr, jstring host,
                                                jint port) {
    Utf8 h(env, host);
    return rats_remove_reconnect(node_of(ptr), h.get(), static_cast<uint16_t>(port));
}

// ---- process-wide ----

JNIEXPORT void JNICALL
Java_com_librats_RatsNode_nativeSetLogLevel(JNIEnv*, jclass, jint level) {
    rats_set_log_level(static_cast<rats_log_level_t>(level));
}

JNIEXPORT void JNICALL
Java_com_librats_RatsNode_nativeSetLogFile(JNIEnv* env, jclass, jstring path) {
    Utf8 p(env, path);
    rats_set_log_file(p.get());
}

JNIEXPORT jstring JNICALL
Java_com_librats_RatsNode_nativeVersionString(JNIEnv* env, jclass) {
    return to_jstring(env, rats_version_string());
}

JNIEXPORT jintArray JNICALL
Java_com_librats_RatsNode_nativeVersion(JNIEnv* env, jclass) {
    int major = 0, minor = 0, patch = 0, build = 0;
    rats_version(&major, &minor, &patch, &build);
    const jint values[4] = {major, minor, patch, build};
    jintArray out = env->NewIntArray(4);
    if (out) env->SetIntArrayRegion(out, 0, 4, values);
    return out;
}

JNIEXPORT jstring JNICALL
Java_com_librats_RatsNode_nativeGitDescribe(JNIEnv* env, jclass) {
    return to_jstring(env, rats_git_describe());
}

JNIEXPORT jint JNICALL
Java_com_librats_RatsNode_nativeAbi(JNIEnv*, jclass) {
    return static_cast<jint>(rats_abi());
}

} // extern "C"
