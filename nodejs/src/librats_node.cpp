/**
 * librats Node.js addon: an N-API wrapper over the C ABI in
 * src/librats/bindings/rats.h.
 *
 * Enumerations cross into JS as lowercase strings ("udp", "slow-consumer", …)
 * and failures as an Error whose `code` is the C error name without its
 * RATS_ERR_ prefix ("NOT_ENABLED", "NO_SUCH_PEER", …).
 *
 * librats calls back on its own reactor threads. Every callback registration
 * owns a Napi::ThreadSafeFunction that carries the call over to the JS thread;
 * all of them live until the node is destroyed, because librats keeps the
 * `user` pointer it was given for as long as the node exists.
 */

#include <napi.h>
#include <librats/bindings/rats.h>

#include <cmath>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

namespace {

// ── errors ──────────────────────────────────────────────────────────────────

void throw_code(Napi::Env env, const std::string& code, const std::string& detail = "") {
    Napi::Error err = Napi::Error::New(env, "librats: " + code + (detail.empty() ? "" : " (" + detail + ")"));
    err.Set("code", Napi::String::New(env, code));
    err.ThrowAsJavaScriptException();
}

// Throw for anything but RATS_OK. Returns true when it threw.
bool throw_on_error(Napi::Env env, rats_error_t err) {
    if (err == RATS_OK) return false;
    std::string name = rats_error_str(err);
    const std::string prefix = "RATS_ERR_";
    if (name.compare(0, prefix.size(), prefix) == 0) name.erase(0, prefix.size());
    throw_code(env, name);
    return true;
}

void throw_type(Napi::Env env, const std::string& what) {
    Napi::TypeError::New(env, what).ThrowAsJavaScriptException();
}

// ── enumerations as strings ─────────────────────────────────────────────────

const char* transport_name(rats_transport_t t) {
    switch (t) {
        case RATS_TRANSPORT_UDP:   return "udp";
        case RATS_TRANSPORT_TCP:   return "tcp";
        case RATS_TRANSPORT_RELAY: return "relay";
    }
    return "unknown";
}

const char* close_reason_name(rats_close_reason_t r) {
    switch (r) {
        case RATS_CLOSE_LOCAL:            return "local";
        case RATS_CLOSE_PEER_CLOSED:      return "peer-closed";
        case RATS_CLOSE_PEER_RESET:       return "peer-reset";
        case RATS_CLOSE_CONNECT_FAILED:   return "connect-failed";
        case RATS_CLOSE_HANDSHAKE_FAILED: return "handshake-failed";
        case RATS_CLOSE_PROTOCOL_ERROR:   return "protocol-error";
        case RATS_CLOSE_SLOW_CONSUMER:    return "slow-consumer";
        case RATS_CLOSE_SHUTDOWN:         return "shutdown";
        case RATS_CLOSE_DUPLICATE:        return "duplicate";
        case RATS_CLOSE_PEER_LIMIT:       return "peer-limit";
        case RATS_CLOSE_IDLE_TIMEOUT:     return "idle-timeout";
        case RATS_CLOSE_DIAL_SUPERSEDED:  return "dial-superseded";
    }
    return "unknown";
}

const char* nat_name(rats_nat_mapping_t m) {
    switch (m) {
        case RATS_NAT_UNKNOWN:              return "unknown";
        case RATS_NAT_OPEN:                 return "open";
        case RATS_NAT_ENDPOINT_INDEPENDENT: return "endpoint-independent";
        case RATS_NAT_ENDPOINT_DEPENDENT:   return "endpoint-dependent";
    }
    return "unknown";
}

const char* direction_name(rats_direction_t d) {
    return d == RATS_DIRECTION_INBOUND ? "inbound" : "outbound";
}

const char* file_status_name(rats_file_status_t s) {
    switch (s) {
        case RATS_FILE_PENDING:   return "pending";
        case RATS_FILE_ACTIVE:    return "active";
        case RATS_FILE_PAUSED:    return "paused";
        case RATS_FILE_COMPLETED: return "completed";
        case RATS_FILE_FAILED:    return "failed";
        case RATS_FILE_CANCELLED: return "cancelled";
    }
    return "unknown";
}

Napi::Array transport_mask_to_js(Napi::Env env, uint32_t mask) {
    Napi::Array out = Napi::Array::New(env);
    uint32_t i = 0;
    if (mask & RATS_TRANSPORT_MASK_UDP) out[i++] = Napi::String::New(env, "udp");
    if (mask & RATS_TRANSPORT_MASK_TCP) out[i++] = Napi::String::New(env, "tcp");
    return out;
}

Napi::Array strings_to_js(Napi::Env env, char** strings, size_t count) {
    Napi::Array out = Napi::Array::New(env, count);
    for (size_t i = 0; i < count; ++i) out[static_cast<uint32_t>(i)] = Napi::String::New(env, strings[i]);
    rats_strings_free(strings, count);
    return out;
}

// ── argument helpers ────────────────────────────────────────────────────────

bool arg_string(const Napi::CallbackInfo& info, size_t i, const char* name, std::string& out) {
    if (info.Length() <= i || !info[i].IsString()) {
        throw_type(info.Env(), std::string("Expected ") + name + " (string)");
        return false;
    }
    out = info[i].As<Napi::String>().Utf8Value();
    return true;
}

bool arg_function(const Napi::CallbackInfo& info, size_t i, Napi::Function& out) {
    if (info.Length() <= i || !info[i].IsFunction()) {
        throw_type(info.Env(), "Expected a callback function");
        return false;
    }
    out = info[i].As<Napi::Function>();
    return true;
}

// An integer in [0, max]; `required` false accepts a missing/undefined argument
// as `fallback`.
bool arg_uint(const Napi::CallbackInfo& info, size_t i, const char* name, double max,
              double& out, bool required = true, double fallback = 0) {
    if (info.Length() <= i || info[i].IsUndefined()) {
        if (required) {
            throw_type(info.Env(), std::string("Expected ") + name + " (number)");
            return false;
        }
        out = fallback;
        return true;
    }
    const double v = info[i].IsNumber() ? info[i].As<Napi::Number>().DoubleValue() : -1;
    if (!(v >= 0 && v <= max) || v != std::floor(v)) {
        Napi::RangeError::New(info.Env(), std::string(name) + " must be an integer in [0, " +
                                              std::to_string(static_cast<uint64_t>(max)) + "]")
            .ThrowAsJavaScriptException();
        return false;
    }
    out = v;
    return true;
}

bool arg_port(const Napi::CallbackInfo& info, size_t i, uint16_t& out, bool required = true) {
    double v = 0;
    if (!arg_uint(info, i, "port", 65535, v, required)) return false;
    out = static_cast<uint16_t>(v);
    return true;
}

bool arg_bool(const Napi::CallbackInfo& info, size_t i, bool fallback) {
    if (info.Length() <= i || info[i].IsUndefined()) return fallback;
    return info[i].ToBoolean().Value();
}

// A string or Buffer as bytes.
bool arg_bytes(const Napi::CallbackInfo& info, size_t i, std::vector<uint8_t>& out) {
    if (info.Length() > i && info[i].IsBuffer()) {
        auto buf = info[i].As<Napi::Buffer<uint8_t>>();
        out.assign(buf.Data(), buf.Data() + buf.Length());
        return true;
    }
    if (info.Length() > i && info[i].IsString()) {
        const std::string s = info[i].As<Napi::String>().Utf8Value();
        out.assign(s.begin(), s.end());
        return true;
    }
    throw_type(info.Env(), "Expected data (string or Buffer)");
    return false;
}

// ── config ──────────────────────────────────────────────────────────────────

// Strings the config points at, kept alive until rats_create() has copied them.
struct ConfigStrings {
    std::string protocol, data_dir, bind_address;
};

bool cfg_number(Napi::Env env, const Napi::Object& cfg, const char* key, double max, double& out) {
    const Napi::Value v = cfg.Get(key);
    if (v.IsUndefined()) return false;
    const double d = v.IsNumber() ? v.As<Napi::Number>().DoubleValue() : -1;
    if (!(d >= 0 && d <= max) || d != std::floor(d)) {
        Napi::RangeError::New(env, std::string("config.") + key + " must be a non-negative integer")
            .ThrowAsJavaScriptException();
        return false;
    }
    out = d;
    return true;
}

bool cfg_string(Napi::Env env, const Napi::Object& cfg, const char* key, std::string& out,
                bool& present) {
    present = false;
    const Napi::Value v = cfg.Get(key);
    if (v.IsUndefined()) return true;
    if (!v.IsString()) {
        throw_type(env, std::string("config.") + key + " must be a string");
        return false;
    }
    out = v.As<Napi::String>().Utf8Value();
    present = true;
    return true;
}

// Map one of a fixed set of strings to its value; `key` names the field in errors.
template <class T>
bool cfg_choice(Napi::Env env, const Napi::Object& cfg, const char* key,
                std::initializer_list<std::pair<const char*, T>> choices, T& out) {
    const Napi::Value v = cfg.Get(key);
    if (v.IsUndefined()) return true;
    if (v.IsString()) {
        const std::string s = v.As<Napi::String>().Utf8Value();
        for (const auto& c : choices)
            if (s == c.first) { out = c.second; return true; }
    }
    std::string allowed;
    for (const auto& c : choices) allowed += std::string(allowed.empty() ? "" : ", ") + "'" + c.first + "'";
    throw_type(env, std::string("config.") + key + " must be one of " + allowed);
    return false;
}

// Fill a zeroed rats_config_t (zero is the default in every field) from a JS
// object. Returns false with a JS exception pending on a malformed field.
bool to_config(Napi::Env env, const Napi::Object& cfg, rats_config_t& c, ConfigStrings& s) {
    bool present = false;
    double n = 0;

    if (!cfg_string(env, cfg, "protocol", s.protocol, present)) return false;
    if (present) c.protocol = s.protocol.c_str();
    if (!cfg_string(env, cfg, "dataDir", s.data_dir, present)) return false;
    if (present) c.data_dir = s.data_dir.c_str();
    if (!cfg_choice<rats_security_t>(env, cfg, "security",
            {{"noise", RATS_SECURITY_NOISE}, {"plaintext", RATS_SECURITY_PLAINTEXT}}, c.security))
        return false;

    if (cfg_number(env, cfg, "listenPort", 65535, n)) c.listen_port = static_cast<uint16_t>(n);
    if (env.IsExceptionPending()) return false;
    if (!cfg_string(env, cfg, "bindAddress", s.bind_address, present)) return false;
    if (present) c.bind_address = s.bind_address.c_str();
    c.dial_only = cfg.Get("dialOnly").ToBoolean().Value() ? 1 : 0;
    if (cfg_number(env, cfg, "maxPeers", 9007199254740991.0, n)) c.max_peers = static_cast<size_t>(n);
    if (env.IsExceptionPending()) return false;

    const Napi::Value transports = cfg.Get("transports");
    if (!transports.IsUndefined()) {
        if (!transports.IsArray()) {
            throw_type(env, "config.transports must be an array of 'udp' / 'tcp'");
            return false;
        }
        const Napi::Array list = transports.As<Napi::Array>();
        uint32_t mask = 0;
        for (uint32_t i = 0; i < list.Length(); ++i) {
            const Napi::Value item = list.Get(i);
            const std::string t = item.IsString() ? item.As<Napi::String>().Utf8Value() : "";
            if (t == "udp")      mask |= RATS_TRANSPORT_MASK_UDP;
            else if (t == "tcp") mask |= RATS_TRANSPORT_MASK_TCP;
            else {
                throw_type(env, "config.transports must be an array of 'udp' / 'tcp'");
                return false;
            }
        }
        if (mask == 0) {
            throw_type(env, "config.transports must name at least one transport");
            return false;
        }
        c.transports = mask;
    }
    if (!cfg_choice<rats_transport_t>(env, cfg, "preferredTransport",
            {{"udp", RATS_TRANSPORT_UDP}, {"tcp", RATS_TRANSPORT_TCP}}, c.preferred_transport))
        return false;

    const Napi::Value fallback = cfg.Get("transportFallbackMs");
    if (!fallback.IsUndefined()) {
        const double d = fallback.IsNumber() ? fallback.As<Napi::Number>().DoubleValue() : -1;
        if (std::isinf(d) && d > 0) {
            c.transport_fallback_ms = RATS_FALLBACK_NEVER;
        } else if (d >= 1 && d < 4294967295.0 && d == std::floor(d)) {
            c.transport_fallback_ms = static_cast<uint32_t>(d);
        } else {
            Napi::RangeError::New(env, "config.transportFallbackMs must be a positive integer or Infinity")
                .ThrowAsJavaScriptException();
            return false;
        }
    }

    if (cfg_number(env, cfg, "sendQueueLimit", 9007199254740991.0, n)) c.send_queue_limit = static_cast<size_t>(n);
    if (cfg_number(env, cfg, "pathSampleMs", 4294967295.0, n)) c.path_sample_ms = static_cast<uint32_t>(n);
    if (env.IsExceptionPending()) return false;

    if (!cfg_choice<rats_congestion_t>(env, cfg, "congestionControl",
            {{"bbr", RATS_CONGESTION_BBR}, {"reno", RATS_CONGESTION_RENO}}, c.congestion_control))
        return false;
    if (cfg_number(env, cfg, "udpReceiveWindow", 9007199254740991.0, n)) c.udp_receive_window = static_cast<size_t>(n);
    if (cfg_number(env, cfg, "udpReceiveBudget", 9007199254740991.0, n)) c.udp_receive_budget = static_cast<size_t>(n);
    if (cfg_number(env, cfg, "reactorThreads", 1024, n)) c.reactor_threads = static_cast<size_t>(n);
    if (env.IsExceptionPending()) return false;

    // Both default to on; only an explicit false turns them off.
    const Napi::Value offload = cfg.Get("udpOffload");
    c.disable_udp_offload = (!offload.IsUndefined() && !offload.ToBoolean().Value()) ? 1 : 0;
    const Napi::Value monitor = cfg.Get("networkMonitor");
    c.disable_network_monitor = (!monitor.IsUndefined() && !monitor.ToBoolean().Value()) ? 1 : 0;
    return true;
}

// ── JS objects built from C structs ─────────────────────────────────────────

Napi::Object path_stats_to_js(Napi::Env env, const rats_path_stats_t& s) {
    // uint64 counters become Numbers, exact up to 2^53.
    Napi::Object o = Napi::Object::New(env);
    o.Set("bandwidthBps",    Napi::Number::New(env, static_cast<double>(s.bandwidth_bps)));
    o.Set("appLimited",      Napi::Boolean::New(env, s.app_limited != 0));
    o.Set("pacingBps",       Napi::Number::New(env, static_cast<double>(s.pacing_bps)));
    o.Set("srttUs",          Napi::Number::New(env, s.srtt_us));
    o.Set("minRttUs",        Napi::Number::New(env, s.min_rtt_us));
    o.Set("queuedBytes",     Napi::Number::New(env, static_cast<double>(s.queued_bytes)));
    o.Set("bytesInFlight",   Napi::Number::New(env, static_cast<double>(s.bytes_in_flight)));
    o.Set("loss",            Napi::Number::New(env, s.loss));
    o.Set("bytesDelivered",  Napi::Number::New(env, static_cast<double>(s.bytes_delivered)));
    o.Set("bytesLost",       Napi::Number::New(env, static_cast<double>(s.bytes_lost)));
    o.Set("liveSent",        Napi::Number::New(env, static_cast<double>(s.live_sent)));
    o.Set("liveExpired",     Napi::Number::New(env, static_cast<double>(s.live_expired)));
    o.Set("liveRepairBytes", Napi::Number::New(env, static_cast<double>(s.live_repair_bytes)));
    return o;
}

// The copyable part of rats_file_progress_t (its peer_id pointer is valid only
// during the C callback).
struct FileProgress {
    rats_file_progress_t c;
    std::string          peer;
};

Napi::Object file_progress_to_js(Napi::Env env, const FileProgress& p) {
    Napi::Object o = Napi::Object::New(env);
    o.Set("transferId",       Napi::Number::New(env, static_cast<double>(p.c.transfer_id)));
    o.Set("peerId",           Napi::String::New(env, p.peer));
    o.Set("direction",        Napi::String::New(env, direction_name(p.c.direction)));
    o.Set("status",           Napi::String::New(env, file_status_name(p.c.status)));
    o.Set("bytesTransferred", Napi::Number::New(env, static_cast<double>(p.c.bytes_transferred)));
    o.Set("totalBytes",       Napi::Number::New(env, static_cast<double>(p.c.total_bytes)));
    o.Set("filesCompleted",   Napi::Number::New(env, p.c.files_completed));
    o.Set("totalFiles",       Napi::Number::New(env, p.c.total_files));
    o.Set("rateBytesPerSec",  Napi::Number::New(env, p.c.rate_bytes_per_sec));
    return o;
}

std::string str_or_empty(const char* s) { return s ? s : ""; }

std::vector<uint8_t> copy_bytes(const void* data, size_t len) {
    const auto* p = static_cast<const uint8_t*>(data);
    return std::vector<uint8_t>(p, p + len);
}

} // namespace

// One registered JS callback: the thread-safe function librats' threads call
// through. Released only when the node is gone, since librats holds the pointer
// to this as its `user` argument until then.
struct Callback {
    Napi::ThreadSafeFunction tsfn;
};

class RatsNode : public Napi::ObjectWrap<RatsNode> {
public:
    static Napi::Object Init(Napi::Env env, Napi::Object exports);
    explicit RatsNode(const Napi::CallbackInfo& info);
    ~RatsNode() override { Teardown(); }

private:
    rats_t node_ = nullptr;
    std::vector<std::unique_ptr<Callback>> callbacks_;

    // A new callback slot for `fn`. Undone by drop_last() when librats refuses it.
    Callback* add_callback(Napi::Env env, const Napi::Function& fn, const char* name) {
        auto cb = std::make_unique<Callback>();
        cb->tsfn = Napi::ThreadSafeFunction::New(env, fn, name, 0, 1);
        callbacks_.push_back(std::move(cb));
        return callbacks_.back().get();
    }
    void drop_last() {
        callbacks_.back()->tsfn.Release();
        callbacks_.pop_back();
    }
    // Register through librats; on refusal undo the slot and throw.
    void registered(Napi::Env env, rats_error_t err) {
        if (err != RATS_OK) {
            drop_last();
            throw_on_error(env, err);
        }
    }
    bool require_node(const Napi::CallbackInfo& info) {
        if (node_) return true;
        throw_code(info.Env(), "DESTROYED");
        return false;
    }

    // Destroy the node first — that joins the reactor threads, so nothing calls
    // back afterwards — then let the thread-safe functions go. Idempotent.
    void Teardown() {
        if (node_) {
            rats_destroy(node_);
            node_ = nullptr;
        }
        for (auto& cb : callbacks_) cb->tsfn.Release();
        callbacks_.clear();
    }

    // lifecycle and this node
    void Start(const Napi::CallbackInfo& info);
    void Stop(const Napi::CallbackInfo& info);
    void Destroy(const Napi::CallbackInfo& info);
    Napi::Value LocalId(const Napi::CallbackInfo& info);
    Napi::Value Protocol(const Napi::CallbackInfo& info);
    Napi::Value ListenPort(const Napi::CallbackInfo& info);
    Napi::Value Transports(const Napi::CallbackInfo& info);
    Napi::Value NatMapping(const Napi::CallbackInfo& info);
    Napi::Value ObservedAddresses(const Napi::CallbackInfo& info);

    // peers
    void Connect(const Napi::CallbackInfo& info);
    Napi::Value Disconnect(const Napi::CallbackInfo& info);
    Napi::Value PeerCount(const Napi::CallbackInfo& info);
    Napi::Value PeerIds(const Napi::CallbackInfo& info);
    Napi::Value PeerInfo(const Napi::CallbackInfo& info);
    Napi::Value MaxPeers(const Napi::CallbackInfo& info);
    void SetMaxPeers(const Napi::CallbackInfo& info);

    // messaging
    void Send(const Napi::CallbackInfo& info);
    void Broadcast(const Napi::CallbackInfo& info);
    Napi::Value PeerWritable(const Napi::CallbackInfo& info);
    Napi::Value PathStats(const Napi::CallbackInfo& info);

    // callbacks
    void OnPeerConnected(const Napi::CallbackInfo& info);
    void OnPeerDisconnected(const Napi::CallbackInfo& info);
    void OnDialFailed(const Napi::CallbackInfo& info);
    void OnPeerWritable(const Napi::CallbackInfo& info);
    void OnPeerPath(const Napi::CallbackInfo& info);
    void On(const Napi::CallbackInfo& info);
    void OnPeerEvent(const Napi::CallbackInfo& info, const char* name,
                     rats_error_t (*reg)(rats_t, rats_peer_cb, void*));

    // discovery and NAT traversal
    void EnableDht(const Napi::CallbackInfo& info);
    void EnableMdns(const Napi::CallbackInfo& info);
    void EnablePeerExchange(const Napi::CallbackInfo& info);
    void EnablePortMapping(const Napi::CallbackInfo& info);
    void EnableHolePunch(const Napi::CallbackInfo& info);
    Napi::Value PunchPeer(const Napi::CallbackInfo& info);
    void EnableRelay(const Napi::CallbackInfo& info);
    Napi::Value ConnectViaRelay(const Napi::CallbackInfo& info);

    // pub/sub
    void EnablePubsub(const Napi::CallbackInfo& info);
    void Subscribe(const Napi::CallbackInfo& info);
    void Unsubscribe(const Napi::CallbackInfo& info);
    void Publish(const Napi::CallbackInfo& info);

    // JSON messaging
    void EnableJson(const Napi::CallbackInfo& info);
    void OnJson(const Napi::CallbackInfo& info) { JsonHandler(info, false); }
    void OnceJson(const Napi::CallbackInfo& info) { JsonHandler(info, true); }
    void JsonHandler(const Napi::CallbackInfo& info, bool once);
    void OffJson(const Napi::CallbackInfo& info);
    void SendJson(const Napi::CallbackInfo& info);
    void BroadcastJson(const Napi::CallbackInfo& info);

    // file transfer
    void EnableFileTransfer(const Napi::CallbackInfo& info);
    void OnFileOffer(const Napi::CallbackInfo& info);
    void OnFileProgress(const Napi::CallbackInfo& info);
    void OnFileComplete(const Napi::CallbackInfo& info);
    Napi::Value SendFile(const Napi::CallbackInfo& info);
    Napi::Value SendDirectory(const Napi::CallbackInfo& info);
    void AcceptFile(const Napi::CallbackInfo& info);
    void RejectFile(const Napi::CallbackInfo& info);
    Napi::Value CancelFile(const Napi::CallbackInfo& info);
    Napi::Value PauseFile(const Napi::CallbackInfo& info);
    Napi::Value ResumeFile(const Napi::CallbackInfo& info);
    Napi::Value ControlFile(const Napi::CallbackInfo& info,
                            rats_error_t (*op)(rats_t, const char*, uint64_t));

    // ping and reconnection
    void EnablePing(const Napi::CallbackInfo& info);
    Napi::Value PeerRttMs(const Napi::CallbackInfo& info);
    void EnableReconnect(const Napi::CallbackInfo& info);
    void AddReconnect(const Napi::CallbackInfo& info);
    void RemoveReconnect(const Napi::CallbackInfo& info);
};

// ─── lifecycle and this node ────────────────────────────────────────────────

RatsNode::RatsNode(const Napi::CallbackInfo& info) : Napi::ObjectWrap<RatsNode>(info) {
    Napi::Env env = info.Env();
    rats_config_t c{};
    ConfigStrings strings;
    if (info.Length() >= 1 && !info[0].IsUndefined()) {
        if (!info[0].IsObject() || info[0].IsArray()) {
            throw_type(env, "Expected a config object");
            return;
        }
        if (!to_config(env, info[0].As<Napi::Object>(), c, strings)) return;
    }
    node_ = rats_create(&c);
    if (!node_) {
        throw_code(env, "INVALID_CONFIG",
                   "no transport left to run, or a preferredTransport that is turned off");
    }
}

void RatsNode::Start(const Napi::CallbackInfo& info) {
    if (!require_node(info)) return;
    throw_on_error(info.Env(), rats_start(node_));
}

void RatsNode::Stop(const Napi::CallbackInfo&) {
    if (node_) rats_stop(node_);
}

void RatsNode::Destroy(const Napi::CallbackInfo&) { Teardown(); }

Napi::Value RatsNode::LocalId(const Napi::CallbackInfo& info) {
    if (!require_node(info)) return info.Env().Undefined();
    return Napi::String::New(info.Env(), rats_local_id(node_));
}

Napi::Value RatsNode::Protocol(const Napi::CallbackInfo& info) {
    if (!require_node(info)) return info.Env().Undefined();
    return Napi::String::New(info.Env(), rats_protocol(node_));
}

Napi::Value RatsNode::ListenPort(const Napi::CallbackInfo& info) {
    if (!require_node(info)) return info.Env().Undefined();
    return Napi::Number::New(info.Env(), rats_listen_port(node_));
}

Napi::Value RatsNode::Transports(const Napi::CallbackInfo& info) {
    if (!require_node(info)) return info.Env().Undefined();
    return transport_mask_to_js(info.Env(), rats_transports(node_));
}

Napi::Value RatsNode::NatMapping(const Napi::CallbackInfo& info) {
    if (!require_node(info)) return info.Env().Undefined();
    return Napi::String::New(info.Env(), nat_name(rats_nat_mapping(node_)));
}

Napi::Value RatsNode::ObservedAddresses(const Napi::CallbackInfo& info) {
    if (!require_node(info)) return info.Env().Undefined();
    size_t count = 0;
    char** addresses = rats_observed_addresses(node_, &count);
    return strings_to_js(info.Env(), addresses, count);
}

// ─── peers ──────────────────────────────────────────────────────────────────

void RatsNode::Connect(const Napi::CallbackInfo& info) {
    if (!require_node(info)) return;
    std::string host;
    uint16_t port = 0;
    if (!arg_string(info, 0, "host", host) || !arg_port(info, 1, port)) return;
    throw_on_error(info.Env(), rats_connect(node_, host.c_str(), port));
}

Napi::Value RatsNode::Disconnect(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (!require_node(info)) return env.Undefined();
    std::string peer;
    if (!arg_string(info, 0, "peerId", peer)) return env.Undefined();
    const rats_error_t err = rats_disconnect(node_, peer.c_str());
    if (err == RATS_ERR_NO_SUCH_PEER) return Napi::Boolean::New(env, false);
    if (throw_on_error(env, err)) return env.Undefined();
    return Napi::Boolean::New(env, true);
}

Napi::Value RatsNode::PeerCount(const Napi::CallbackInfo& info) {
    if (!require_node(info)) return info.Env().Undefined();
    return Napi::Number::New(info.Env(), static_cast<double>(rats_peer_count(node_)));
}

Napi::Value RatsNode::PeerIds(const Napi::CallbackInfo& info) {
    if (!require_node(info)) return info.Env().Undefined();
    size_t count = 0;
    char** ids = rats_peer_ids(node_, &count);
    return strings_to_js(info.Env(), ids, count);
}

Napi::Value RatsNode::PeerInfo(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (!require_node(info)) return env.Undefined();
    std::string peer;
    if (!arg_string(info, 0, "peerId", peer)) return env.Undefined();
    rats_peer_info_t p{};
    const rats_error_t err = rats_peer_info(node_, peer.c_str(), &p);
    if (err == RATS_ERR_NO_SUCH_PEER) return env.Null();
    if (throw_on_error(env, err)) return env.Undefined();
    Napi::Object o = Napi::Object::New(env);
    o.Set("transport",  Napi::String::New(env, transport_name(p.transport)));
    o.Set("transports", transport_mask_to_js(env, p.transports));
    o.Set("direction",  Napi::String::New(env, direction_name(p.direction)));
    o.Set("address",    p.address[0] ? Napi::Value(Napi::String::New(env, p.address)) : env.Null());
    return o;
}

Napi::Value RatsNode::MaxPeers(const Napi::CallbackInfo& info) {
    if (!require_node(info)) return info.Env().Undefined();
    return Napi::Number::New(info.Env(), static_cast<double>(rats_max_peers(node_)));
}

void RatsNode::SetMaxPeers(const Napi::CallbackInfo& info) {
    if (!require_node(info)) return;
    double n = 0;
    if (!arg_uint(info, 0, "maxPeers", 9007199254740991.0, n)) return;
    rats_set_max_peers(node_, static_cast<size_t>(n));
}

// ─── messaging ──────────────────────────────────────────────────────────────

void RatsNode::Send(const Napi::CallbackInfo& info) {
    if (!require_node(info)) return;
    std::string peer, channel;
    std::vector<uint8_t> data;
    double lifetime = 0;
    if (!arg_string(info, 0, "peerId", peer) || !arg_string(info, 1, "channel", channel) ||
        !arg_bytes(info, 2, data) ||
        !arg_uint(info, 3, "lifetimeMs", 4294967295.0, lifetime, /*required=*/false))
        return;
    throw_on_error(info.Env(), rats_send(node_, peer.c_str(), channel.c_str(), data.data(),
                                         data.size(), static_cast<uint32_t>(lifetime)));
}

void RatsNode::Broadcast(const Napi::CallbackInfo& info) {
    if (!require_node(info)) return;
    std::string channel;
    std::vector<uint8_t> data;
    double lifetime = 0;
    if (!arg_string(info, 0, "channel", channel) || !arg_bytes(info, 1, data) ||
        !arg_uint(info, 2, "lifetimeMs", 4294967295.0, lifetime, /*required=*/false))
        return;
    throw_on_error(info.Env(), rats_broadcast(node_, channel.c_str(), data.data(), data.size(),
                                              static_cast<uint32_t>(lifetime)));
}

Napi::Value RatsNode::PeerWritable(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (!require_node(info)) return env.Undefined();
    std::string peer;
    if (!arg_string(info, 0, "peerId", peer)) return env.Undefined();
    return Napi::Boolean::New(env, rats_peer_writable(node_, peer.c_str()) != 0);
}

Napi::Value RatsNode::PathStats(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (!require_node(info)) return env.Undefined();
    std::string peer;
    if (!arg_string(info, 0, "peerId", peer)) return env.Undefined();
    rats_path_stats_t s{};
    const rats_error_t err = rats_path_stats(node_, peer.c_str(), &s);
    if (err == RATS_ERR_NO_SUCH_PEER) return env.Null();
    if (throw_on_error(env, err)) return env.Undefined();
    return path_stats_to_js(env, s);
}

// ─── callbacks ──────────────────────────────────────────────────────────────

void RatsNode::OnPeerEvent(const Napi::CallbackInfo& info, const char* name,
                           rats_error_t (*reg)(rats_t, rats_peer_cb, void*)) {
    if (!require_node(info)) return;
    Napi::Function fn;
    if (!arg_function(info, 0, fn)) return;
    Callback* cb = add_callback(info.Env(), fn, name);
    registered(info.Env(), reg(node_, [](void* user, const char* peer_id) {
        std::string peer = str_or_empty(peer_id);
        static_cast<Callback*>(user)->tsfn.BlockingCall([peer](Napi::Env env, Napi::Function js) {
            js.Call({Napi::String::New(env, peer)});
        });
    }, cb));
}

void RatsNode::OnPeerConnected(const Napi::CallbackInfo& info) {
    OnPeerEvent(info, "onPeerConnected", rats_on_peer_connected);
}

void RatsNode::OnPeerWritable(const Napi::CallbackInfo& info) {
    OnPeerEvent(info, "onPeerWritable", rats_on_peer_writable);
}

void RatsNode::OnPeerDisconnected(const Napi::CallbackInfo& info) {
    if (!require_node(info)) return;
    Napi::Function fn;
    if (!arg_function(info, 0, fn)) return;
    Callback* cb = add_callback(info.Env(), fn, "onPeerDisconnected");
    registered(info.Env(), rats_on_peer_disconnected(node_,
        [](void* user, const char* peer_id, rats_close_reason_t reason) {
            std::string peer = str_or_empty(peer_id);
            const char* why = close_reason_name(reason);
            static_cast<Callback*>(user)->tsfn.BlockingCall([peer, why](Napi::Env env, Napi::Function js) {
                js.Call({Napi::String::New(env, peer), Napi::String::New(env, why)});
            });
        }, cb));
}

void RatsNode::OnDialFailed(const Napi::CallbackInfo& info) {
    if (!require_node(info)) return;
    Napi::Function fn;
    if (!arg_function(info, 0, fn)) return;
    Callback* cb = add_callback(info.Env(), fn, "onDialFailed");
    registered(info.Env(), rats_on_dial_failed(node_, [](void* user, const char* address) {
        std::string a = str_or_empty(address);
        static_cast<Callback*>(user)->tsfn.BlockingCall([a](Napi::Env env, Napi::Function js) {
            js.Call({Napi::String::New(env, a)});
        });
    }, cb));
}

void RatsNode::OnPeerPath(const Napi::CallbackInfo& info) {
    if (!require_node(info)) return;
    Napi::Function fn;
    if (!arg_function(info, 0, fn)) return;
    Callback* cb = add_callback(info.Env(), fn, "onPeerPath");
    registered(info.Env(), rats_on_peer_path(node_,
        [](void* user, const char* peer_id, const rats_path_stats_t* stats) {
            std::string peer = str_or_empty(peer_id);
            const rats_path_stats_t s = stats ? *stats : rats_path_stats_t{};
            static_cast<Callback*>(user)->tsfn.BlockingCall([peer, s](Napi::Env env, Napi::Function js) {
                js.Call({Napi::String::New(env, peer), path_stats_to_js(env, s)});
            });
        }, cb));
}

void RatsNode::On(const Napi::CallbackInfo& info) {
    if (!require_node(info)) return;
    std::string channel;
    Napi::Function fn;
    if (!arg_string(info, 0, "channel", channel) || !arg_function(info, 1, fn)) return;
    Callback* cb = add_callback(info.Env(), fn, "on");
    registered(info.Env(), rats_on(node_, channel.c_str(),
        [](void* user, const char* peer_id, const void* data, size_t len) {
            std::string peer = str_or_empty(peer_id);
            auto bytes = copy_bytes(data, len);
            static_cast<Callback*>(user)->tsfn.BlockingCall(
                [peer, bytes = std::move(bytes)](Napi::Env env, Napi::Function js) {
                    js.Call({Napi::String::New(env, peer),
                             Napi::Buffer<uint8_t>::Copy(env, bytes.data(), bytes.size())});
                });
        }, cb));
}

// ─── discovery and NAT traversal ────────────────────────────────────────────

void RatsNode::EnableDht(const Napi::CallbackInfo& info) {
    if (!require_node(info)) return;
    uint16_t port = 0;
    if (!arg_port(info, 0, port, /*required=*/false)) return;
    std::string key;
    const char* key_ptr = nullptr;
    if (info.Length() >= 2 && !info[1].IsUndefined()) {
        if (!arg_string(info, 1, "discoveryKey", key)) return;
        key_ptr = key.c_str();
    }
    throw_on_error(info.Env(), rats_enable_dht(node_, port, key_ptr));
}

void RatsNode::EnableMdns(const Napi::CallbackInfo& info) {
    if (!require_node(info)) return;
    throw_on_error(info.Env(), rats_enable_mdns(node_));
}

void RatsNode::EnablePeerExchange(const Napi::CallbackInfo& info) {
    if (!require_node(info)) return;
    throw_on_error(info.Env(), rats_enable_peer_exchange(node_));
}

void RatsNode::EnablePortMapping(const Napi::CallbackInfo& info) {
    if (!require_node(info)) return;
    throw_on_error(info.Env(), rats_enable_port_mapping(node_, arg_bool(info, 0, true) ? 1 : 0,
                                                        arg_bool(info, 1, true) ? 1 : 0));
}

void RatsNode::EnableHolePunch(const Napi::CallbackInfo& info) {
    if (!require_node(info)) return;
    throw_on_error(info.Env(), rats_enable_hole_punch(node_, arg_bool(info, 0, true) ? 1 : 0));
}

// true: an attempt started; false: declined (nothing to do or to try with).
static Napi::Value attempt_result(Napi::Env env, rats_error_t err) {
    if (err == RATS_ERR_DECLINED) return Napi::Boolean::New(env, false);
    if (throw_on_error(env, err)) return env.Undefined();
    return Napi::Boolean::New(env, true);
}

Napi::Value RatsNode::PunchPeer(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (!require_node(info)) return env.Undefined();
    std::string peer;
    if (!arg_string(info, 0, "peerId", peer)) return env.Undefined();
    return attempt_result(env, rats_punch_peer(node_, peer.c_str()));
}

void RatsNode::EnableRelay(const Napi::CallbackInfo& info) {
    if (!require_node(info)) return;
    throw_on_error(info.Env(), rats_enable_relay(node_, arg_bool(info, 0, false) ? 1 : 0));
}

Napi::Value RatsNode::ConnectViaRelay(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (!require_node(info)) return env.Undefined();
    std::string peer;
    if (!arg_string(info, 0, "peerId", peer)) return env.Undefined();
    return attempt_result(env, rats_connect_via_relay(node_, peer.c_str()));
}

// ─── pub/sub ────────────────────────────────────────────────────────────────

void RatsNode::EnablePubsub(const Napi::CallbackInfo& info) {
    if (!require_node(info)) return;
    throw_on_error(info.Env(), rats_enable_pubsub(node_));
}

void RatsNode::Subscribe(const Napi::CallbackInfo& info) {
    if (!require_node(info)) return;
    std::string topic;
    Napi::Function fn;
    if (!arg_string(info, 0, "topic", topic) || !arg_function(info, 1, fn)) return;
    Callback* cb = add_callback(info.Env(), fn, "subscribe");
    registered(info.Env(), rats_subscribe(node_, topic.c_str(),
        [](void* user, const char* peer_id, const char* t, const void* data, size_t len) {
            std::string peer = str_or_empty(peer_id);
            std::string topic = str_or_empty(t);
            auto bytes = copy_bytes(data, len);
            static_cast<Callback*>(user)->tsfn.BlockingCall(
                [peer, topic, bytes = std::move(bytes)](Napi::Env env, Napi::Function js) {
                    js.Call({Napi::String::New(env, peer), Napi::String::New(env, topic),
                             Napi::Buffer<uint8_t>::Copy(env, bytes.data(), bytes.size())});
                });
        }, cb));
}

void RatsNode::Unsubscribe(const Napi::CallbackInfo& info) {
    if (!require_node(info)) return;
    std::string topic;
    if (!arg_string(info, 0, "topic", topic)) return;
    throw_on_error(info.Env(), rats_unsubscribe(node_, topic.c_str()));
}

void RatsNode::Publish(const Napi::CallbackInfo& info) {
    if (!require_node(info)) return;
    std::string topic;
    std::vector<uint8_t> data;
    if (!arg_string(info, 0, "topic", topic) || !arg_bytes(info, 1, data)) return;
    throw_on_error(info.Env(), rats_publish(node_, topic.c_str(), data.data(), data.size()));
}

// ─── JSON messaging (JSON text here; index.js converts to and from values) ──

void RatsNode::EnableJson(const Napi::CallbackInfo& info) {
    if (!require_node(info)) return;
    throw_on_error(info.Env(), rats_enable_json(node_));
}

void RatsNode::JsonHandler(const Napi::CallbackInfo& info, bool once) {
    if (!require_node(info)) return;
    std::string type;
    Napi::Function fn;
    if (!arg_string(info, 0, "type", type) || !arg_function(info, 1, fn)) return;
    Callback* cb = add_callback(info.Env(), fn, once ? "onceJson" : "onJson");
    const rats_json_cb trampoline = [](void* user, const char* peer_id, const char* json) {
        std::string peer = str_or_empty(peer_id);
        std::string text = str_or_empty(json);
        static_cast<Callback*>(user)->tsfn.BlockingCall([peer, text](Napi::Env env, Napi::Function js) {
            js.Call({Napi::String::New(env, peer), Napi::String::New(env, text)});
        });
    };
    registered(info.Env(), once ? rats_once_json(node_, type.c_str(), trampoline, cb)
                                : rats_on_json(node_, type.c_str(), trampoline, cb));
}

void RatsNode::OffJson(const Napi::CallbackInfo& info) {
    if (!require_node(info)) return;
    std::string type;
    if (!arg_string(info, 0, "type", type)) return;
    throw_on_error(info.Env(), rats_off_json(node_, type.c_str()));
}

void RatsNode::SendJson(const Napi::CallbackInfo& info) {
    if (!require_node(info)) return;
    std::string peer, type, json;
    if (!arg_string(info, 0, "peerId", peer) || !arg_string(info, 1, "type", type) ||
        !arg_string(info, 2, "json", json))
        return;
    throw_on_error(info.Env(), rats_send_json(node_, peer.c_str(), type.c_str(), json.c_str()));
}

void RatsNode::BroadcastJson(const Napi::CallbackInfo& info) {
    if (!require_node(info)) return;
    std::string type, json;
    if (!arg_string(info, 0, "type", type) || !arg_string(info, 1, "json", json)) return;
    throw_on_error(info.Env(), rats_broadcast_json(node_, type.c_str(), json.c_str()));
}

// ─── file transfer ──────────────────────────────────────────────────────────

void RatsNode::EnableFileTransfer(const Napi::CallbackInfo& info) {
    if (!require_node(info)) return;
    std::string dir;
    const char* dir_ptr = nullptr;
    if (info.Length() >= 1 && !info[0].IsUndefined()) {
        if (!arg_string(info, 0, "tempDir", dir)) return;
        dir_ptr = dir.c_str();
    }
    throw_on_error(info.Env(), rats_enable_file_transfer(node_, dir_ptr));
}

void RatsNode::OnFileOffer(const Napi::CallbackInfo& info) {
    if (!require_node(info)) return;
    Napi::Function fn;
    if (!arg_function(info, 0, fn)) return;
    Callback* cb = add_callback(info.Env(), fn, "onFileOffer");
    registered(info.Env(), rats_on_file_offer(node_,
        [](void* user, const char* peer_id, uint64_t transfer_id, const char* name, uint64_t size,
           int is_directory) {
            std::string peer = str_or_empty(peer_id);
            std::string n = str_or_empty(name);
            const bool dir = is_directory != 0;
            static_cast<Callback*>(user)->tsfn.BlockingCall(
                [peer, transfer_id, n, size, dir](Napi::Env env, Napi::Function js) {
                    js.Call({Napi::String::New(env, peer),
                             Napi::Number::New(env, static_cast<double>(transfer_id)),
                             Napi::String::New(env, n),
                             Napi::Number::New(env, static_cast<double>(size)),
                             Napi::Boolean::New(env, dir)});
                });
        }, cb));
}

void RatsNode::OnFileProgress(const Napi::CallbackInfo& info) {
    if (!require_node(info)) return;
    Napi::Function fn;
    if (!arg_function(info, 0, fn)) return;
    Callback* cb = add_callback(info.Env(), fn, "onFileProgress");
    registered(info.Env(), rats_on_file_progress(node_,
        [](void* user, const rats_file_progress_t* progress) {
            if (!progress) return;
            FileProgress p{*progress, str_or_empty(progress->peer_id)};
            p.c.peer_id = nullptr;   // valid only for this call; the copy is in p.peer
            static_cast<Callback*>(user)->tsfn.BlockingCall([p](Napi::Env env, Napi::Function js) {
                js.Call({file_progress_to_js(env, p)});
            });
        }, cb));
}

void RatsNode::OnFileComplete(const Napi::CallbackInfo& info) {
    if (!require_node(info)) return;
    Napi::Function fn;
    if (!arg_function(info, 0, fn)) return;
    Callback* cb = add_callback(info.Env(), fn, "onFileComplete");
    registered(info.Env(), rats_on_file_complete(node_,
        [](void* user, const char* peer_id, uint64_t transfer_id, int success, const char* path) {
            std::string peer = str_or_empty(peer_id);
            std::string p = str_or_empty(path);
            const bool ok = success != 0;
            static_cast<Callback*>(user)->tsfn.BlockingCall(
                [peer, transfer_id, ok, p](Napi::Env env, Napi::Function js) {
                    js.Call({Napi::String::New(env, peer),
                             Napi::Number::New(env, static_cast<double>(transfer_id)),
                             Napi::Boolean::New(env, ok),
                             Napi::String::New(env, p)});
                });
        }, cb));
}

Napi::Value RatsNode::SendFile(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (!require_node(info)) return env.Undefined();
    std::string peer, path;
    if (!arg_string(info, 0, "peerId", peer) || !arg_string(info, 1, "path", path)) return env.Undefined();
    uint64_t id = 0;
    if (throw_on_error(env, rats_send_file(node_, peer.c_str(), path.c_str(), &id))) return env.Undefined();
    return Napi::Number::New(env, static_cast<double>(id));
}

Napi::Value RatsNode::SendDirectory(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (!require_node(info)) return env.Undefined();
    std::string peer, path;
    if (!arg_string(info, 0, "peerId", peer) || !arg_string(info, 1, "path", path)) return env.Undefined();
    uint64_t id = 0;
    if (throw_on_error(env, rats_send_directory(node_, peer.c_str(), path.c_str(), &id))) return env.Undefined();
    return Napi::Number::New(env, static_cast<double>(id));
}

static bool arg_transfer(const Napi::CallbackInfo& info, std::string& peer, uint64_t& id) {
    double v = 0;
    if (!arg_string(info, 0, "peerId", peer) ||
        !arg_uint(info, 1, "transferId", 9007199254740991.0, v))
        return false;
    id = static_cast<uint64_t>(v);
    return true;
}

void RatsNode::AcceptFile(const Napi::CallbackInfo& info) {
    if (!require_node(info)) return;
    std::string peer, dest;
    uint64_t id = 0;
    if (!arg_transfer(info, peer, id) || !arg_string(info, 2, "destPath", dest)) return;
    throw_on_error(info.Env(), rats_accept_file(node_, peer.c_str(), id, dest.c_str()));
}

void RatsNode::RejectFile(const Napi::CallbackInfo& info) {
    if (!require_node(info)) return;
    std::string peer;
    uint64_t id = 0;
    if (!arg_transfer(info, peer, id)) return;
    throw_on_error(info.Env(), rats_reject_file(node_, peer.c_str(), id));
}

// true: applied; false: no such transfer.
Napi::Value RatsNode::ControlFile(const Napi::CallbackInfo& info,
                                  rats_error_t (*op)(rats_t, const char*, uint64_t)) {
    Napi::Env env = info.Env();
    if (!require_node(info)) return env.Undefined();
    std::string peer;
    uint64_t id = 0;
    if (!arg_transfer(info, peer, id)) return env.Undefined();
    const rats_error_t err = op(node_, peer.c_str(), id);
    if (err == RATS_ERR_NOT_FOUND) return Napi::Boolean::New(env, false);
    if (throw_on_error(env, err)) return env.Undefined();
    return Napi::Boolean::New(env, true);
}

Napi::Value RatsNode::CancelFile(const Napi::CallbackInfo& info) { return ControlFile(info, rats_cancel_file); }
Napi::Value RatsNode::PauseFile(const Napi::CallbackInfo& info) { return ControlFile(info, rats_pause_file); }
Napi::Value RatsNode::ResumeFile(const Napi::CallbackInfo& info) { return ControlFile(info, rats_resume_file); }

// ─── ping and reconnection ──────────────────────────────────────────────────

void RatsNode::EnablePing(const Napi::CallbackInfo& info) {
    if (!require_node(info)) return;
    throw_on_error(info.Env(), rats_enable_ping(node_));
}

Napi::Value RatsNode::PeerRttMs(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (!require_node(info)) return env.Undefined();
    std::string peer;
    if (!arg_string(info, 0, "peerId", peer)) return env.Undefined();
    const int64_t rtt = rats_peer_rtt_ms(node_, peer.c_str());
    if (rtt < 0) return env.Null();
    return Napi::Number::New(env, static_cast<double>(rtt));
}

void RatsNode::EnableReconnect(const Napi::CallbackInfo& info) {
    if (!require_node(info)) return;
    throw_on_error(info.Env(), rats_enable_reconnect(node_));
}

void RatsNode::AddReconnect(const Napi::CallbackInfo& info) {
    if (!require_node(info)) return;
    std::string host;
    uint16_t port = 0;
    if (!arg_string(info, 0, "host", host) || !arg_port(info, 1, port)) return;
    throw_on_error(info.Env(), rats_add_reconnect(node_, host.c_str(), port));
}

void RatsNode::RemoveReconnect(const Napi::CallbackInfo& info) {
    if (!require_node(info)) return;
    std::string host;
    uint16_t port = 0;
    if (!arg_string(info, 0, "host", host) || !arg_port(info, 1, port)) return;
    throw_on_error(info.Env(), rats_remove_reconnect(node_, host.c_str(), port));
}

// ─── registration ───────────────────────────────────────────────────────────

Napi::Object RatsNode::Init(Napi::Env env, Napi::Object exports) {
    Napi::Function func = DefineClass(env, "RatsNode", {
        InstanceMethod("start", &RatsNode::Start),
        InstanceMethod("stop", &RatsNode::Stop),
        InstanceMethod("destroy", &RatsNode::Destroy),
        InstanceMethod("localId", &RatsNode::LocalId),
        InstanceMethod("protocol", &RatsNode::Protocol),
        InstanceMethod("listenPort", &RatsNode::ListenPort),
        InstanceMethod("transports", &RatsNode::Transports),
        InstanceMethod("natMapping", &RatsNode::NatMapping),
        InstanceMethod("observedAddresses", &RatsNode::ObservedAddresses),

        InstanceMethod("connect", &RatsNode::Connect),
        InstanceMethod("disconnect", &RatsNode::Disconnect),
        InstanceMethod("peerCount", &RatsNode::PeerCount),
        InstanceMethod("peerIds", &RatsNode::PeerIds),
        InstanceMethod("peerInfo", &RatsNode::PeerInfo),
        InstanceMethod("maxPeers", &RatsNode::MaxPeers),
        InstanceMethod("setMaxPeers", &RatsNode::SetMaxPeers),

        InstanceMethod("send", &RatsNode::Send),
        InstanceMethod("broadcast", &RatsNode::Broadcast),
        InstanceMethod("peerWritable", &RatsNode::PeerWritable),
        InstanceMethod("pathStats", &RatsNode::PathStats),

        InstanceMethod("onPeerConnected", &RatsNode::OnPeerConnected),
        InstanceMethod("onPeerDisconnected", &RatsNode::OnPeerDisconnected),
        InstanceMethod("onDialFailed", &RatsNode::OnDialFailed),
        InstanceMethod("onPeerWritable", &RatsNode::OnPeerWritable),
        InstanceMethod("onPeerPath", &RatsNode::OnPeerPath),
        InstanceMethod("on", &RatsNode::On),

        InstanceMethod("enableDht", &RatsNode::EnableDht),
        InstanceMethod("enableMdns", &RatsNode::EnableMdns),
        InstanceMethod("enablePeerExchange", &RatsNode::EnablePeerExchange),
        InstanceMethod("enablePortMapping", &RatsNode::EnablePortMapping),
        InstanceMethod("enableHolePunch", &RatsNode::EnableHolePunch),
        InstanceMethod("punchPeer", &RatsNode::PunchPeer),
        InstanceMethod("enableRelay", &RatsNode::EnableRelay),
        InstanceMethod("connectViaRelay", &RatsNode::ConnectViaRelay),

        InstanceMethod("enablePubsub", &RatsNode::EnablePubsub),
        InstanceMethod("subscribe", &RatsNode::Subscribe),
        InstanceMethod("unsubscribe", &RatsNode::Unsubscribe),
        InstanceMethod("publish", &RatsNode::Publish),

        InstanceMethod("enableJson", &RatsNode::EnableJson),
        InstanceMethod("onJson", &RatsNode::OnJson),
        InstanceMethod("onceJson", &RatsNode::OnceJson),
        InstanceMethod("offJson", &RatsNode::OffJson),
        InstanceMethod("sendJson", &RatsNode::SendJson),
        InstanceMethod("broadcastJson", &RatsNode::BroadcastJson),

        InstanceMethod("enableFileTransfer", &RatsNode::EnableFileTransfer),
        InstanceMethod("onFileOffer", &RatsNode::OnFileOffer),
        InstanceMethod("onFileProgress", &RatsNode::OnFileProgress),
        InstanceMethod("onFileComplete", &RatsNode::OnFileComplete),
        InstanceMethod("sendFile", &RatsNode::SendFile),
        InstanceMethod("sendDirectory", &RatsNode::SendDirectory),
        InstanceMethod("acceptFile", &RatsNode::AcceptFile),
        InstanceMethod("rejectFile", &RatsNode::RejectFile),
        InstanceMethod("cancelFile", &RatsNode::CancelFile),
        InstanceMethod("pauseFile", &RatsNode::PauseFile),
        InstanceMethod("resumeFile", &RatsNode::ResumeFile),

        InstanceMethod("enablePing", &RatsNode::EnablePing),
        InstanceMethod("peerRttMs", &RatsNode::PeerRttMs),
        InstanceMethod("enableReconnect", &RatsNode::EnableReconnect),
        InstanceMethod("addReconnect", &RatsNode::AddReconnect),
        InstanceMethod("removeReconnect", &RatsNode::RemoveReconnect),
    });
    exports.Set("RatsNode", func);
    return exports;
}

// ─── process-wide ───────────────────────────────────────────────────────────

static Napi::Value Version(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    int major = 0, minor = 0, patch = 0, build = 0;
    rats_version(&major, &minor, &patch, &build);
    Napi::Object v = Napi::Object::New(env);
    v.Set("string",      Napi::String::New(env, rats_version_string()));
    v.Set("major",       Napi::Number::New(env, major));
    v.Set("minor",       Napi::Number::New(env, minor));
    v.Set("patch",       Napi::Number::New(env, patch));
    v.Set("build",       Napi::Number::New(env, build));
    v.Set("gitDescribe", Napi::String::New(env, rats_git_describe()));
    v.Set("abi",         Napi::Number::New(env, rats_abi()));
    return v;
}

static Napi::Value SetLogLevel(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    const std::string level = info.Length() >= 1 && info[0].IsString()
                                  ? info[0].As<Napi::String>().Utf8Value() : "";
    if (level == "debug")      rats_set_log_level(RATS_LOG_DEBUG);
    else if (level == "info")  rats_set_log_level(RATS_LOG_INFO);
    else if (level == "warn")  rats_set_log_level(RATS_LOG_WARN);
    else if (level == "error") rats_set_log_level(RATS_LOG_ERROR);
    else throw_type(env, "Expected log level 'debug', 'info', 'warn' or 'error'");
    return env.Undefined();
}

static Napi::Value SetLogFile(const Napi::CallbackInfo& info) {
    if (info.Length() >= 1 && info[0].IsString()) {
        const std::string path = info[0].As<Napi::String>().Utf8Value();
        rats_set_log_file(path.c_str());
    } else {
        rats_set_log_file(nullptr);
    }
    return info.Env().Undefined();
}

static Napi::Object Init(Napi::Env env, Napi::Object exports) {
    RatsNode::Init(env, exports);
    exports.Set("version", Napi::Function::New(env, Version));
    exports.Set("setLogLevel", Napi::Function::New(env, SetLogLevel));
    exports.Set("setLogFile", Napi::Function::New(env, SetLogFile));
    exports.Set("LIVE_MAX_LIFETIME_MS", Napi::Number::New(env, RATS_LIVE_MAX_LIFETIME_MS));
    exports.Set("LIVE_MAX_PAYLOAD", Napi::Number::New(env, RATS_LIVE_MAX_PAYLOAD));
    return exports;
}

NODE_API_MODULE(librats, Init)
