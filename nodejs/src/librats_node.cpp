/**
 * LibRats Node.js native addon.
 *
 * N-API wrapper over the canonical C ABI in src/bindings/rats.h. Callbacks fire
 * on librats' internal reactor thread, so every native callback marshals into
 * the JS thread with a Napi::ThreadSafeFunction (TSFN). Per-channel / per-topic
 * / per-json-type handlers are kept in maps owned by the RatsNode instance and
 * torn down on destruction.
 *
 * Contract reminder (enforced by the C core, surfaced here as thrown errors):
 *   - Register callbacks and enable subsystems BEFORE start().
 *   - Calling an enable after start() -> RATS_ERR_ALREADY_STARTED.
 *   - Calling a subsystem op before its enable -> RATS_ERR_NOT_ENABLED.
 */

#include <napi.h>
#include <cstring>
#include <memory>
#include <string>
#include <vector>
#include <librats/bindings/rats.h>

using namespace Napi;

namespace {

// Translate a rats_error_t into a JS exception when it is not RATS_OK.
// Returns true if an error was thrown (caller should bail out / return).
bool throw_on_error(Napi::Env env, rats_error_t err) {
    if (err == RATS_OK) return false;
    Napi::Error::New(env, std::string("librats: ") + rats_error_str(err))
        .ThrowAsJavaScriptException();
    return true;
}

// Every instance method funnels through this: the C ABI does not null-check its
// handle, and destroy() legitimately leaves us without one. The variadic
// argument is the value to return — empty for a void method.
#define RATS_REQUIRE_NODE(...)                                            \
    do {                                                                  \
        if (!node_) {                                                     \
            Napi::Error::New(info.Env(), "librats: node has been destroyed") \
                .ThrowAsJavaScriptException();                            \
            return __VA_ARGS__;                                           \
        }                                                                 \
    } while (0)

} // namespace

// ---------------------------------------------------------------------------
// Per-callback context. Each registration owns a TSFN plus a back-pointer used
// only for cleanup bookkeeping. The trampoline (the C function we hand to
// librats) receives the context as `user`.
// ---------------------------------------------------------------------------

struct CbContext {
    Napi::ThreadSafeFunction tsfn;
    bool acquired = false;

    void init(Napi::Env env, const Napi::Function& fn, const char* name) {
        release();
        tsfn = Napi::ThreadSafeFunction::New(env, fn, name, 0, 1);
        acquired = true;
    }
    void release() {
        if (acquired) {
            tsfn.Release();
            acquired = false;
        }
    }
};

class RatsNode : public Napi::ObjectWrap<RatsNode> {
public:
    static Napi::Object Init(Napi::Env env, Napi::Object exports);
    RatsNode(const Napi::CallbackInfo& info);
    ~RatsNode();

private:
    rats_t node_ = nullptr;

    // Single-slot callbacks (peer connect/disconnect, file offer/progress/complete).
    std::unique_ptr<CbContext> on_connected_;
    std::unique_ptr<CbContext> on_disconnected_;
    std::unique_ptr<CbContext> on_writable_;
    std::unique_ptr<CbContext> on_file_offer_;
    std::unique_ptr<CbContext> on_file_progress_;
    std::unique_ptr<CbContext> on_file_complete_;

    // Multi-slot callbacks keyed by channel / topic / json type. We keep them
    // alive for the lifetime of the client; the trampolines look up nothing —
    // each registration has its own CbContext handed to librats as `user`.
    std::vector<std::unique_ptr<CbContext>> handlers_;

    CbContext* new_handler() {
        handlers_.push_back(std::make_unique<CbContext>());
        return handlers_.back().get();
    }

    // Release TSFNs + the native node. Idempotent; used by ~RatsNode and destroy().
    void Teardown();

    // ---- lifecycle / core ----
    void Start(const Napi::CallbackInfo& info);
    void Stop(const Napi::CallbackInfo& info);
    void Destroy(const Napi::CallbackInfo& info);
    Napi::Value GetListenPort(const Napi::CallbackInfo& info);
    Napi::Value GetLocalId(const Napi::CallbackInfo& info);
    Napi::Value GetProtocol(const Napi::CallbackInfo& info);
    Napi::Value GetTransports(const Napi::CallbackInfo& info);

    // ---- connections ----
    Napi::Value Connect(const Napi::CallbackInfo& info);
    Napi::Value GetPeerCount(const Napi::CallbackInfo& info);
    Napi::Value GetPeerIds(const Napi::CallbackInfo& info);
    void SetMaxPeers(const Napi::CallbackInfo& info);
    Napi::Value GetMaxPeers(const Napi::CallbackInfo& info);
    Napi::Value GetPeerTransport(const Napi::CallbackInfo& info);
    Napi::Value GetPeerTransports(const Napi::CallbackInfo& info);

    // ---- raw channel messaging ----
    Napi::Value Send(const Napi::CallbackInfo& info);
    Napi::Value Broadcast(const Napi::CallbackInfo& info);
    Napi::Value PeerWritable(const Napi::CallbackInfo& info);
    void On(const Napi::CallbackInfo& info);

    // ---- peer events ----
    void OnPeerConnected(const Napi::CallbackInfo& info);
    void OnPeerDisconnected(const Napi::CallbackInfo& info);
    void OnPeerWritable(const Napi::CallbackInfo& info);

    // ---- discovery / NAT ----
    void EnableDht(const Napi::CallbackInfo& info);
    void EnableMdns(const Napi::CallbackInfo& info);
    void EnablePortMapping(const Napi::CallbackInfo& info);
    void EnableHolePunch(const Napi::CallbackInfo& info);
    Napi::Value PunchPeer(const Napi::CallbackInfo& info);
    void EnableRelay(const Napi::CallbackInfo& info);
    Napi::Value ConnectViaRelay(const Napi::CallbackInfo& info);
    Napi::Value GetNatMapping(const Napi::CallbackInfo& info);

    // ---- pub/sub ----
    void EnablePubsub(const Napi::CallbackInfo& info);
    void Subscribe(const Napi::CallbackInfo& info);
    void Unsubscribe(const Napi::CallbackInfo& info);
    Napi::Value Publish(const Napi::CallbackInfo& info);

    // ---- typed JSON ----
    void EnableJson(const Napi::CallbackInfo& info);
    void OnJson(const Napi::CallbackInfo& info);
    void OnceJson(const Napi::CallbackInfo& info);
    void OffJson(const Napi::CallbackInfo& info);
    Napi::Value SendJson(const Napi::CallbackInfo& info);
    Napi::Value BroadcastJson(const Napi::CallbackInfo& info);
    void OnJsonImpl(const Napi::CallbackInfo& info, bool once);

    // ---- file transfer ----
    void EnableFileTransfer(const Napi::CallbackInfo& info);
    void OnFileOffer(const Napi::CallbackInfo& info);
    void OnFileProgress(const Napi::CallbackInfo& info);
    void OnFileComplete(const Napi::CallbackInfo& info);
    Napi::Value SendFile(const Napi::CallbackInfo& info);
    Napi::Value SendDirectory(const Napi::CallbackInfo& info);
    Napi::Value AcceptFile(const Napi::CallbackInfo& info);
    Napi::Value RejectFile(const Napi::CallbackInfo& info);
    Napi::Value CancelFile(const Napi::CallbackInfo& info);
    Napi::Value PauseFile(const Napi::CallbackInfo& info);
    Napi::Value ResumeFile(const Napi::CallbackInfo& info);

    // ---- ping / reconnect ----
    void EnablePing(const Napi::CallbackInfo& info);
    Napi::Value GetPeerRttMs(const Napi::CallbackInfo& info);
    void EnableReconnect(const Napi::CallbackInfo& info);
    Napi::Value AddReconnect(const Napi::CallbackInfo& info);
    Napi::Value RemoveReconnect(const Napi::CallbackInfo& info);
};

// ---------------------------------------------------------------------------
// Construction / lifecycle
// ---------------------------------------------------------------------------

RatsNode::RatsNode(const Napi::CallbackInfo& info)
    : Napi::ObjectWrap<RatsNode>(info) {
    Napi::Env env = info.Env();

    // Two construction forms:
    //   new RatsNode(port)         -> rats_create(port)
    //   new RatsNode({ ...config }) -> rats_create_config(&cfg)
    if (info.Length() >= 1 && info[0].IsObject() && !info[0].IsBuffer()) {
        Napi::Object cfg = info[0].As<Napi::Object>();
        rats_config_t c = rats_config_default();

        // Hold string storage alive until rats_create_config() returns (the
        // struct borrows the pointers only for the duration of the call).
        std::string bind_addr, data_dir, protocol;

        if (cfg.Has("listenPort"))
            c.listen_port = static_cast<uint16_t>(cfg.Get("listenPort").As<Napi::Number>().Uint32Value());
        if (cfg.Has("enableListen"))
            c.enable_listen = cfg.Get("enableListen").As<Napi::Boolean>().Value() ? 1 : 0;
        if (cfg.Has("bindAddress") && cfg.Get("bindAddress").IsString()) {
            bind_addr = cfg.Get("bindAddress").As<Napi::String>().Utf8Value();
            c.bind_address = bind_addr.c_str();
        }
        if (cfg.Has("security"))
            c.security = static_cast<rats_security_t>(cfg.Get("security").As<Napi::Number>().Int32Value());
        if (cfg.Has("dataDir") && cfg.Get("dataDir").IsString()) {
            data_dir = cfg.Get("dataDir").As<Napi::String>().Utf8Value();
            c.data_dir = data_dir.c_str();
        }
        if (cfg.Has("protocol") && cfg.Get("protocol").IsString()) {
            protocol = cfg.Get("protocol").As<Napi::String>().Utf8Value();
            c.protocol = protocol.c_str();
        }
        if (cfg.Has("maxPeers"))
            c.max_peers = static_cast<size_t>(cfg.Get("maxPeers").As<Napi::Number>().Int64Value());

        // Transports. Both are on by default and share one port; preferredTransport
        // decides which a dial tries first (UDP), transportFallbackMs how long
        // before the other is raced alongside it.
        if (cfg.Has("enableTcp"))
            c.enable_tcp = cfg.Get("enableTcp").As<Napi::Boolean>().Value() ? 1 : 0;
        if (cfg.Has("enableUdp"))
            c.enable_udp = cfg.Get("enableUdp").As<Napi::Boolean>().Value() ? 1 : 0;
        if (cfg.Has("preferredTransport"))
            c.preferred_transport = static_cast<rats_transport_t>(
                cfg.Get("preferredTransport").As<Napi::Number>().Int32Value());
        if (cfg.Has("transportFallbackMs"))
            c.transport_fallback_ms =
                cfg.Get("transportFallbackMs").As<Napi::Number>().Uint32Value();

        // Bytes a peer may have queued before an app that keeps sending anyway has
        // it dropped as a slow consumer. A quarter of it is where peerWritable()
        // starts saying false, so lowering it makes backpressure felt sooner.
        if (cfg.Has("sendQueueLimit"))
            c.send_queue_limit =
                static_cast<size_t>(cfg.Get("sendQueueLimit").As<Napi::Number>().Int64Value());

        node_ = rats_create_config(&c);
    } else {
        int port = 0;
        if (info.Length() >= 1 && info[0].IsNumber()) {
            port = info[0].As<Napi::Number>().Int32Value();
            if (port < 0 || port > 65535) {
                Napi::RangeError::New(env, "Port number must be between 0 and 65535")
                    .ThrowAsJavaScriptException();
                return;
            }
        } else if (info.Length() >= 1) {
            Napi::TypeError::New(env, "Expected a port number or a config object")
                .ThrowAsJavaScriptException();
            return;
        }
        node_ = rats_create(static_cast<uint16_t>(port));
    }

    if (!node_) {
        Napi::Error::New(env, "Failed to create RatsNode").ThrowAsJavaScriptException();
        return;
    }
}

RatsNode::~RatsNode() {
    Teardown();
}

// Release all TSFNs first so no JS callback can be invoked during/after
// destruction, then destroy the native node. Idempotent.
void RatsNode::Teardown() {
    if (on_connected_) on_connected_->release();
    if (on_disconnected_) on_disconnected_->release();
    if (on_writable_) on_writable_->release();
    if (on_file_offer_) on_file_offer_->release();
    if (on_file_progress_) on_file_progress_->release();
    if (on_file_complete_) on_file_complete_->release();
    for (auto& h : handlers_) h->release();

    if (node_) {
        rats_destroy(node_);
        node_ = nullptr;
    }
}

void RatsNode::Start(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE();
    throw_on_error(info.Env(), rats_start(node_));
}

void RatsNode::Stop(const Napi::CallbackInfo& info) {
    if (node_) rats_stop(node_);
}

// Explicit release. After this the instance is inert; further calls are no-ops
// or throw, and the GC has nothing left to free.
void RatsNode::Destroy(const Napi::CallbackInfo& info) {
    Teardown();
}

Napi::Value RatsNode::GetListenPort(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE(info.Env().Undefined());
    return Napi::Number::New(info.Env(), rats_listen_port(node_));
}

Napi::Value RatsNode::GetLocalId(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE(info.Env().Undefined());
    Napi::Env env = info.Env();
    char* id = rats_local_id(node_);
    if (!id) return env.Null();
    Napi::String result = Napi::String::New(env, id);
    rats_string_free(id);
    return result;
}

Napi::Value RatsNode::GetProtocol(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE(info.Env().Undefined());
    Napi::Env env = info.Env();
    char* s = rats_protocol(node_);
    if (!s) return env.Null();
    Napi::String result = Napi::String::New(env, s);
    rats_string_free(s);
    return result;
}

// Transports actually running, as a RATS_TRANSPORT_MASK_* bitmask. May be
// narrower than the config asked for; 0 before start() and after stop().
Napi::Value RatsNode::GetTransports(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE(info.Env().Undefined());
    return Napi::Number::New(info.Env(), rats_transports(node_));
}

// ---------------------------------------------------------------------------
// Connections
// ---------------------------------------------------------------------------

Napi::Value RatsNode::Connect(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE(info.Env().Undefined());
    Napi::Env env = info.Env();
    if (info.Length() < 2 || !info[0].IsString() || !info[1].IsNumber()) {
        Napi::TypeError::New(env, "Expected host (string) and port (number)")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }
    std::string host = info[0].As<Napi::String>().Utf8Value();
    uint16_t port = static_cast<uint16_t>(info[1].As<Napi::Number>().Uint32Value());
    throw_on_error(env, rats_connect(node_, host.c_str(), port));
    return env.Undefined();
}

Napi::Value RatsNode::GetPeerCount(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE(info.Env().Undefined());
    return Napi::Number::New(info.Env(), static_cast<double>(rats_peer_count(node_)));
}

Napi::Value RatsNode::GetPeerIds(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE(info.Env().Undefined());
    Napi::Env env = info.Env();
    size_t count = 0;
    char** ids = rats_peer_ids(node_, &count);
    Napi::Array result = Napi::Array::New(env, count);
    if (ids) {
        for (size_t i = 0; i < count; i++) {
            result[static_cast<uint32_t>(i)] = Napi::String::New(env, ids[i]);
        }
        rats_free_peer_ids(ids, count);
    }
    return result;
}

void RatsNode::SetMaxPeers(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE();
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsNumber()) {
        Napi::TypeError::New(env, "Expected maxPeers (number)").ThrowAsJavaScriptException();
        return;
    }
    rats_set_max_peers(node_, static_cast<size_t>(info[0].As<Napi::Number>().Int64Value()));
}

Napi::Value RatsNode::GetMaxPeers(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE(info.Env().Undefined());
    return Napi::Number::New(info.Env(), static_cast<double>(rats_max_peers(node_)));
}

// Which transport a connected peer's link runs on; null if not connected.
Napi::Value RatsNode::GetPeerTransport(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE(info.Env().Undefined());
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "Expected peerId (string)").ThrowAsJavaScriptException();
        return env.Undefined();
    }
    std::string peer = info[0].As<Napi::String>().Utf8Value();
    int t = rats_peer_transport(node_, peer.c_str());
    if (t < 0) return env.Null();
    return Napi::Number::New(env, t);
}

// Transports a connected peer advertised, as a bitmask; null if not connected.
// 0 means the peer did not say (an older build) — "no information", not "none".
Napi::Value RatsNode::GetPeerTransports(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE(info.Env().Undefined());
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "Expected peerId (string)").ThrowAsJavaScriptException();
        return env.Undefined();
    }
    std::string peer = info[0].As<Napi::String>().Utf8Value();
    int t = rats_peer_transports(node_, peer.c_str());
    if (t < 0) return env.Null();
    return Napi::Number::New(env, t);
}

// ---------------------------------------------------------------------------
// Raw channel messaging
// ---------------------------------------------------------------------------

// Coerce a JS string or Buffer argument into a contiguous byte vector.
static bool to_bytes(Napi::Env env, const Napi::Value& v, std::vector<uint8_t>& out) {
    if (v.IsBuffer()) {
        Napi::Buffer<uint8_t> buf = v.As<Napi::Buffer<uint8_t>>();
        out.assign(buf.Data(), buf.Data() + buf.Length());
        return true;
    }
    if (v.IsString()) {
        std::string s = v.As<Napi::String>().Utf8Value();
        out.assign(s.begin(), s.end());
        return true;
    }
    Napi::TypeError::New(env, "Expected data (string or Buffer)").ThrowAsJavaScriptException();
    return false;
}

Napi::Value RatsNode::Send(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE(info.Env().Undefined());
    Napi::Env env = info.Env();
    if (info.Length() < 3 || !info[0].IsString() || !info[1].IsString()) {
        Napi::TypeError::New(env, "Expected peerId (string), channel (string), data")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }
    std::string peer = info[0].As<Napi::String>().Utf8Value();
    std::string channel = info[1].As<Napi::String>().Utf8Value();
    std::vector<uint8_t> data;
    if (!to_bytes(env, info[2], data)) return env.Undefined();
    throw_on_error(env, rats_send(node_, peer.c_str(), channel.c_str(), data.data(), data.size()));
    return env.Undefined();
}

// send() only says the message was queued. This is how a JS caller learns it is
// outrunning the link — before the peer is dropped for it.
Napi::Value RatsNode::PeerWritable(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE(info.Env().Undefined());
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "Expected peerId (string)").ThrowAsJavaScriptException();
        return env.Undefined();
    }
    std::string peer = info[0].As<Napi::String>().Utf8Value();
    return Napi::Boolean::New(env, rats_peer_writable(node_, peer.c_str()) != 0);
}

Napi::Value RatsNode::Broadcast(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE(info.Env().Undefined());
    Napi::Env env = info.Env();
    if (info.Length() < 2 || !info[0].IsString()) {
        Napi::TypeError::New(env, "Expected channel (string) and data")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }
    std::string channel = info[0].As<Napi::String>().Utf8Value();
    std::vector<uint8_t> data;
    if (!to_bytes(env, info[1], data)) return env.Undefined();
    throw_on_error(env, rats_broadcast(node_, channel.c_str(), data.data(), data.size()));
    return env.Undefined();
}

// rats_message_cb(user, peer_id_hex, data, len) -> JS (peerId, Buffer)
void RatsNode::On(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE();
    Napi::Env env = info.Env();
    if (info.Length() < 2 || !info[0].IsString() || !info[1].IsFunction()) {
        Napi::TypeError::New(env, "Expected channel (string) and callback (function)")
            .ThrowAsJavaScriptException();
        return;
    }
    std::string channel = info[0].As<Napi::String>().Utf8Value();
    CbContext* ctx = new_handler();
    ctx->init(env, info[1].As<Napi::Function>(), "on_message");

    auto trampoline = [](void* user, const char* peer_id, const void* data, size_t len) {
        auto* c = static_cast<CbContext*>(user);
        std::string peer = peer_id ? peer_id : "";
        std::vector<uint8_t> bytes(static_cast<const uint8_t*>(data),
                                   static_cast<const uint8_t*>(data) + len);
        c->tsfn.BlockingCall([peer, bytes](Napi::Env env, Napi::Function js) {
            js.Call({Napi::String::New(env, peer),
                     Napi::Buffer<uint8_t>::Copy(env, bytes.data(), bytes.size())});
        });
    };
    throw_on_error(env, rats_on(node_, channel.c_str(), trampoline, ctx));
}

// ---------------------------------------------------------------------------
// Peer events
// ---------------------------------------------------------------------------

void RatsNode::OnPeerConnected(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE();
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsFunction()) {
        Napi::TypeError::New(env, "Expected callback function").ThrowAsJavaScriptException();
        return;
    }
    on_connected_ = std::make_unique<CbContext>();
    on_connected_->init(env, info[0].As<Napi::Function>(), "on_peer_connected");
    auto trampoline = [](void* user, const char* peer_id) {
        auto* c = static_cast<CbContext*>(user);
        std::string peer = peer_id ? peer_id : "";
        c->tsfn.BlockingCall([peer](Napi::Env env, Napi::Function js) {
            js.Call({Napi::String::New(env, peer)});
        });
    };
    throw_on_error(env, rats_on_peer_connected(node_, trampoline, on_connected_.get()));
}

void RatsNode::OnPeerDisconnected(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE();
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsFunction()) {
        Napi::TypeError::New(env, "Expected callback function").ThrowAsJavaScriptException();
        return;
    }
    on_disconnected_ = std::make_unique<CbContext>();
    on_disconnected_->init(env, info[0].As<Napi::Function>(), "on_peer_disconnected");
    // Second argument is why the peer went: "RATS_CLOSE_SLOW_CONSUMER" is the one
    // an application can act on (it was sending faster than the link drained).
    // Callbacks that only declare (peerId) are unaffected.
    auto trampoline = [](void* user, const char* peer_id, rats_close_reason_t reason) {
        auto* c = static_cast<CbContext*>(user);
        std::string peer = peer_id ? peer_id : "";
        std::string why  = rats_close_reason_str(reason);
        c->tsfn.BlockingCall([peer, why](Napi::Env env, Napi::Function js) {
            js.Call({Napi::String::New(env, peer), Napi::String::New(env, why)});
        });
    };
    throw_on_error(env, rats_on_peer_disconnected(node_, trampoline, on_disconnected_.get()));
}

void RatsNode::OnPeerWritable(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE();
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsFunction()) {
        Napi::TypeError::New(env, "Expected callback function").ThrowAsJavaScriptException();
        return;
    }
    on_writable_ = std::make_unique<CbContext>();
    on_writable_->init(env, info[0].As<Napi::Function>(), "on_peer_writable");
    auto trampoline = [](void* user, const char* peer_id) {
        auto* c = static_cast<CbContext*>(user);
        std::string peer = peer_id ? peer_id : "";
        c->tsfn.BlockingCall([peer](Napi::Env env, Napi::Function js) {
            js.Call({Napi::String::New(env, peer)});
        });
    };
    throw_on_error(env, rats_on_peer_writable(node_, trampoline, on_writable_.get()));
}

// ---------------------------------------------------------------------------
// Discovery / NAT
// ---------------------------------------------------------------------------

void RatsNode::EnableDht(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE();
    Napi::Env env = info.Env();
    uint16_t dht_port = 0;
    std::string key;
    const char* key_ptr = nullptr;
    if (info.Length() >= 1 && info[0].IsNumber())
        dht_port = static_cast<uint16_t>(info[0].As<Napi::Number>().Uint32Value());
    if (info.Length() >= 2 && info[1].IsString()) {
        key = info[1].As<Napi::String>().Utf8Value();
        key_ptr = key.c_str();
    }
    throw_on_error(env, rats_enable_dht(node_, dht_port, key_ptr));
}

void RatsNode::EnableMdns(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE();
    throw_on_error(info.Env(), rats_enable_mdns(node_));
}

void RatsNode::EnablePortMapping(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE();
    int upnp = 1, natpmp = 1;
    if (info.Length() >= 1 && info[0].IsBoolean()) upnp = info[0].As<Napi::Boolean>().Value() ? 1 : 0;
    if (info.Length() >= 2 && info[1].IsBoolean()) natpmp = info[1].As<Napi::Boolean>().Value() ? 1 : 0;
    throw_on_error(info.Env(), rats_enable_port_mapping(node_, upnp, natpmp));
}

// Hole punching. serveAsRelay (default true) also carries other peers'
// rendezvous — a mesh in which nobody relays cannot punch at all.
void RatsNode::EnableHolePunch(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE();
    int relay = 1;
    if (info.Length() >= 1 && info[0].IsBoolean()) relay = info[0].As<Napi::Boolean>().Value() ? 1 : 0;
    throw_on_error(info.Env(), rats_enable_hole_punch(node_, relay));
}

// Start a punch to a peer. Non-blocking: success arrives as onPeerConnected.
Napi::Value RatsNode::PunchPeer(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE(info.Env().Undefined());
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "Expected peerId (string)").ThrowAsJavaScriptException();
        return env.Undefined();
    }
    std::string peer = info[0].As<Napi::String>().Utf8Value();
    throw_on_error(env, rats_punch_peer(node_, peer.c_str()));
    return env.Undefined();
}

// Relaying. serveAsRelay (default false) also carries OTHER peers' connections,
// which spends real bandwidth — so it is opted into rather than assumed.
void RatsNode::EnableRelay(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE();
    int serve = 0;
    if (info.Length() >= 1 && info[0].IsBoolean()) serve = info[0].As<Napi::Boolean>().Value() ? 1 : 0;
    throw_on_error(info.Env(), rats_enable_relay(node_, serve));
}

// Reach a peer through a relay. Non-blocking: success arrives as onPeerConnected.
Napi::Value RatsNode::ConnectViaRelay(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE(info.Env().Undefined());
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "Expected peerId (string)").ThrowAsJavaScriptException();
        return env.Undefined();
    }
    std::string peer = info[0].As<Napi::String>().Utf8Value();
    throw_on_error(env, rats_connect_via_relay(node_, peer.c_str()));
    return env.Undefined();
}

// What the mesh has shown about this node's own NAT (a RATS_NAT_* value).
Napi::Value RatsNode::GetNatMapping(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE(info.Env().Undefined());
    return Napi::Number::New(info.Env(), rats_nat_mapping(node_));
}

// ---------------------------------------------------------------------------
// Pub/sub
// ---------------------------------------------------------------------------

void RatsNode::EnablePubsub(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE();
    throw_on_error(info.Env(), rats_enable_pubsub(node_));
}

// rats_topic_cb(user, peer_id_hex, topic, data, len) -> JS (peerId, topic, Buffer)
void RatsNode::Subscribe(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE();
    Napi::Env env = info.Env();
    if (info.Length() < 2 || !info[0].IsString() || !info[1].IsFunction()) {
        Napi::TypeError::New(env, "Expected topic (string) and callback (function)")
            .ThrowAsJavaScriptException();
        return;
    }
    std::string topic = info[0].As<Napi::String>().Utf8Value();
    CbContext* ctx = new_handler();
    ctx->init(env, info[1].As<Napi::Function>(), "on_topic");
    auto trampoline = [](void* user, const char* peer_id, const char* topic,
                         const void* data, size_t len) {
        auto* c = static_cast<CbContext*>(user);
        std::string peer = peer_id ? peer_id : "";
        std::string t = topic ? topic : "";
        std::vector<uint8_t> bytes(static_cast<const uint8_t*>(data),
                                   static_cast<const uint8_t*>(data) + len);
        c->tsfn.BlockingCall([peer, t, bytes](Napi::Env env, Napi::Function js) {
            js.Call({Napi::String::New(env, peer),
                     Napi::String::New(env, t),
                     Napi::Buffer<uint8_t>::Copy(env, bytes.data(), bytes.size())});
        });
    };
    throw_on_error(env, rats_subscribe(node_, topic.c_str(), trampoline, ctx));
}

void RatsNode::Unsubscribe(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE();
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "Expected topic (string)").ThrowAsJavaScriptException();
        return;
    }
    std::string topic = info[0].As<Napi::String>().Utf8Value();
    throw_on_error(env, rats_unsubscribe(node_, topic.c_str()));
}

Napi::Value RatsNode::Publish(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE(info.Env().Undefined());
    Napi::Env env = info.Env();
    if (info.Length() < 2 || !info[0].IsString()) {
        Napi::TypeError::New(env, "Expected topic (string) and data")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }
    std::string topic = info[0].As<Napi::String>().Utf8Value();
    std::vector<uint8_t> data;
    if (!to_bytes(env, info[1], data)) return env.Undefined();
    throw_on_error(env, rats_publish(node_, topic.c_str(), data.data(), data.size()));
    return env.Undefined();
}

// ---------------------------------------------------------------------------
// Typed JSON
// ---------------------------------------------------------------------------

void RatsNode::EnableJson(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE();
    throw_on_error(info.Env(), rats_enable_json(node_));
}

void RatsNode::OnJsonImpl(const Napi::CallbackInfo& info, bool once) {
    Napi::Env env = info.Env();
    if (info.Length() < 2 || !info[0].IsString() || !info[1].IsFunction()) {
        Napi::TypeError::New(env, "Expected type (string) and callback (function)")
            .ThrowAsJavaScriptException();
        return;
    }
    std::string type = info[0].As<Napi::String>().Utf8Value();
    CbContext* ctx = new_handler();
    ctx->init(env, info[1].As<Napi::Function>(), "on_json");
    auto trampoline = [](void* user, const char* peer_id, const char* json) {
        auto* c = static_cast<CbContext*>(user);
        std::string peer = peer_id ? peer_id : "";
        std::string j = json ? json : "";
        c->tsfn.BlockingCall([peer, j](Napi::Env env, Napi::Function js) {
            js.Call({Napi::String::New(env, peer), Napi::String::New(env, j)});
        });
    };
    if (once)
        throw_on_error(env, rats_once_json(node_, type.c_str(), trampoline, ctx));
    else
        throw_on_error(env, rats_on_json(node_, type.c_str(), trampoline, ctx));
}

void RatsNode::OnJson(const Napi::CallbackInfo& info) { OnJsonImpl(info, false); }
void RatsNode::OnceJson(const Napi::CallbackInfo& info) { OnJsonImpl(info, true); }

void RatsNode::OffJson(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE();
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "Expected type (string)").ThrowAsJavaScriptException();
        return;
    }
    std::string type = info[0].As<Napi::String>().Utf8Value();
    throw_on_error(env, rats_off_json(node_, type.c_str()));
}

Napi::Value RatsNode::SendJson(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE(info.Env().Undefined());
    Napi::Env env = info.Env();
    if (info.Length() < 3 || !info[0].IsString() || !info[1].IsString() || !info[2].IsString()) {
        Napi::TypeError::New(env, "Expected peerId (string), type (string), json (string)")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }
    std::string peer = info[0].As<Napi::String>().Utf8Value();
    std::string type = info[1].As<Napi::String>().Utf8Value();
    std::string json = info[2].As<Napi::String>().Utf8Value();
    throw_on_error(env, rats_send_json(node_, peer.c_str(), type.c_str(), json.c_str()));
    return env.Undefined();
}

Napi::Value RatsNode::BroadcastJson(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE(info.Env().Undefined());
    Napi::Env env = info.Env();
    if (info.Length() < 2 || !info[0].IsString() || !info[1].IsString()) {
        Napi::TypeError::New(env, "Expected type (string) and json (string)")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }
    std::string type = info[0].As<Napi::String>().Utf8Value();
    std::string json = info[1].As<Napi::String>().Utf8Value();
    throw_on_error(env, rats_broadcast_json(node_, type.c_str(), json.c_str()));
    return env.Undefined();
}

// ---------------------------------------------------------------------------
// File transfer
// ---------------------------------------------------------------------------

void RatsNode::EnableFileTransfer(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE();
    Napi::Env env = info.Env();
    std::string tmp;
    const char* tmp_ptr = nullptr;
    if (info.Length() >= 1 && info[0].IsString()) {
        tmp = info[0].As<Napi::String>().Utf8Value();
        tmp_ptr = tmp.c_str();
    }
    throw_on_error(env, rats_enable_file_transfer(node_, tmp_ptr));
}

// rats_file_offer_cb(user, peer_id, transfer_id, name, size, is_directory)
void RatsNode::OnFileOffer(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE();
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsFunction()) {
        Napi::TypeError::New(env, "Expected callback function").ThrowAsJavaScriptException();
        return;
    }
    on_file_offer_ = std::make_unique<CbContext>();
    on_file_offer_->init(env, info[0].As<Napi::Function>(), "on_file_offer");
    auto trampoline = [](void* user, const char* peer_id, uint64_t transfer_id,
                         const char* name, uint64_t size, int is_directory) {
        auto* c = static_cast<CbContext*>(user);
        std::string peer = peer_id ? peer_id : "";
        std::string n = name ? name : "";
        bool isdir = is_directory != 0;
        c->tsfn.BlockingCall([peer, transfer_id, n, size, isdir](Napi::Env env, Napi::Function js) {
            js.Call({Napi::String::New(env, peer),
                     Napi::Number::New(env, static_cast<double>(transfer_id)),
                     Napi::String::New(env, n),
                     Napi::Number::New(env, static_cast<double>(size)),
                     Napi::Boolean::New(env, isdir)});
        });
    };
    throw_on_error(env, rats_on_file_offer(node_, trampoline, on_file_offer_.get()));
}

// rats_file_progress_cb(user, transfer_id, peer_id, bytes_transferred, total_bytes, status)
void RatsNode::OnFileProgress(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE();
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsFunction()) {
        Napi::TypeError::New(env, "Expected callback function").ThrowAsJavaScriptException();
        return;
    }
    on_file_progress_ = std::make_unique<CbContext>();
    on_file_progress_->init(env, info[0].As<Napi::Function>(), "on_file_progress");
    auto trampoline = [](void* user, uint64_t transfer_id, const char* peer_id,
                         uint64_t bytes_transferred, uint64_t total_bytes, int status) {
        auto* c = static_cast<CbContext*>(user);
        std::string peer = peer_id ? peer_id : "";
        c->tsfn.BlockingCall([transfer_id, peer, bytes_transferred, total_bytes, status]
                             (Napi::Env env, Napi::Function js) {
            js.Call({Napi::Number::New(env, static_cast<double>(transfer_id)),
                     Napi::String::New(env, peer),
                     Napi::Number::New(env, static_cast<double>(bytes_transferred)),
                     Napi::Number::New(env, static_cast<double>(total_bytes)),
                     Napi::Number::New(env, status)});
        });
    };
    throw_on_error(env, rats_on_file_progress(node_, trampoline, on_file_progress_.get()));
}

// rats_file_complete_cb(user, transfer_id, peer_id_hex, success, path)
void RatsNode::OnFileComplete(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE();
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsFunction()) {
        Napi::TypeError::New(env, "Expected callback function").ThrowAsJavaScriptException();
        return;
    }
    on_file_complete_ = std::make_unique<CbContext>();
    on_file_complete_->init(env, info[0].As<Napi::Function>(), "on_file_complete");
    auto trampoline = [](void* user, uint64_t transfer_id, const char* peer_id_hex, int success,
                         const char* path) {
        auto* c = static_cast<CbContext*>(user);
        std::string p = path ? path : "";
        std::string peer = peer_id_hex ? peer_id_hex : "";
        bool ok = success != 0;
        c->tsfn.BlockingCall([transfer_id, peer, ok, p](Napi::Env env, Napi::Function js) {
            js.Call({Napi::Number::New(env, static_cast<double>(transfer_id)),
                     Napi::String::New(env, peer),
                     Napi::Boolean::New(env, ok),
                     Napi::String::New(env, p)});
        });
    };
    throw_on_error(env, rats_on_file_complete(node_, trampoline, on_file_complete_.get()));
}

Napi::Value RatsNode::SendFile(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE(info.Env().Undefined());
    Napi::Env env = info.Env();
    if (info.Length() < 2 || !info[0].IsString() || !info[1].IsString()) {
        Napi::TypeError::New(env, "Expected peerId (string) and path (string)")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }
    std::string peer = info[0].As<Napi::String>().Utf8Value();
    std::string path = info[1].As<Napi::String>().Utf8Value();
    uint64_t id = rats_send_file(node_, peer.c_str(), path.c_str());
    return Napi::Number::New(env, static_cast<double>(id));
}

Napi::Value RatsNode::SendDirectory(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE(info.Env().Undefined());
    Napi::Env env = info.Env();
    if (info.Length() < 2 || !info[0].IsString() || !info[1].IsString()) {
        Napi::TypeError::New(env, "Expected peerId (string) and dirPath (string)")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }
    std::string peer = info[0].As<Napi::String>().Utf8Value();
    std::string path = info[1].As<Napi::String>().Utf8Value();
    uint64_t id = rats_send_directory(node_, peer.c_str(), path.c_str());
    return Napi::Number::New(env, static_cast<double>(id));
}

// Shared decoder for the (peerId, transferId[, dest]) control calls.
static bool parse_xfer_args(const Napi::CallbackInfo& info, std::string& peer,
                            uint64_t& transfer_id) {
    Napi::Env env = info.Env();
    if (info.Length() < 2 || !info[0].IsString() || !info[1].IsNumber()) {
        Napi::TypeError::New(env, "Expected peerId (string) and transferId (number)")
            .ThrowAsJavaScriptException();
        return false;
    }
    peer = info[0].As<Napi::String>().Utf8Value();
    transfer_id = static_cast<uint64_t>(info[1].As<Napi::Number>().Int64Value());
    return true;
}

Napi::Value RatsNode::AcceptFile(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE(info.Env().Undefined());
    Napi::Env env = info.Env();
    std::string peer; uint64_t id;
    if (!parse_xfer_args(info, peer, id)) return env.Undefined();
    if (info.Length() < 3 || !info[2].IsString()) {
        Napi::TypeError::New(env, "Expected destPath (string)").ThrowAsJavaScriptException();
        return env.Undefined();
    }
    std::string dest = info[2].As<Napi::String>().Utf8Value();
    throw_on_error(env, rats_accept_file(node_, peer.c_str(), id, dest.c_str()));
    return env.Undefined();
}

Napi::Value RatsNode::RejectFile(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE(info.Env().Undefined());
    Napi::Env env = info.Env();
    std::string peer; uint64_t id;
    if (!parse_xfer_args(info, peer, id)) return env.Undefined();
    throw_on_error(env, rats_reject_file(node_, peer.c_str(), id));
    return env.Undefined();
}

Napi::Value RatsNode::CancelFile(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE(info.Env().Undefined());
    Napi::Env env = info.Env();
    std::string peer; uint64_t id;
    if (!parse_xfer_args(info, peer, id)) return env.Undefined();
    throw_on_error(env, rats_cancel_file(node_, peer.c_str(), id));
    return env.Undefined();
}

Napi::Value RatsNode::PauseFile(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE(info.Env().Undefined());
    Napi::Env env = info.Env();
    std::string peer; uint64_t id;
    if (!parse_xfer_args(info, peer, id)) return env.Undefined();
    throw_on_error(env, rats_pause_file(node_, peer.c_str(), id));
    return env.Undefined();
}

Napi::Value RatsNode::ResumeFile(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE(info.Env().Undefined());
    Napi::Env env = info.Env();
    std::string peer; uint64_t id;
    if (!parse_xfer_args(info, peer, id)) return env.Undefined();
    throw_on_error(env, rats_resume_file(node_, peer.c_str(), id));
    return env.Undefined();
}

// ---------------------------------------------------------------------------
// Ping / reconnect
// ---------------------------------------------------------------------------

void RatsNode::EnablePing(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE();
    throw_on_error(info.Env(), rats_enable_ping(node_));
}

Napi::Value RatsNode::GetPeerRttMs(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE(info.Env().Undefined());
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "Expected peerId (string)").ThrowAsJavaScriptException();
        return env.Undefined();
    }
    std::string peer = info[0].As<Napi::String>().Utf8Value();
    int64_t rtt = rats_peer_rtt_ms(node_, peer.c_str());
    return Napi::Number::New(env, static_cast<double>(rtt));
}

void RatsNode::EnableReconnect(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE();
    throw_on_error(info.Env(), rats_enable_reconnect(node_));
}

Napi::Value RatsNode::AddReconnect(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE(info.Env().Undefined());
    Napi::Env env = info.Env();
    if (info.Length() < 2 || !info[0].IsString() || !info[1].IsNumber()) {
        Napi::TypeError::New(env, "Expected host (string) and port (number)")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }
    std::string host = info[0].As<Napi::String>().Utf8Value();
    uint16_t port = static_cast<uint16_t>(info[1].As<Napi::Number>().Uint32Value());
    throw_on_error(env, rats_add_reconnect(node_, host.c_str(), port));
    return env.Undefined();
}

Napi::Value RatsNode::RemoveReconnect(const Napi::CallbackInfo& info) {
    RATS_REQUIRE_NODE(info.Env().Undefined());
    Napi::Env env = info.Env();
    if (info.Length() < 2 || !info[0].IsString() || !info[1].IsNumber()) {
        Napi::TypeError::New(env, "Expected host (string) and port (number)")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }
    std::string host = info[0].As<Napi::String>().Utf8Value();
    uint16_t port = static_cast<uint16_t>(info[1].As<Napi::Number>().Uint32Value());
    throw_on_error(env, rats_remove_reconnect(node_, host.c_str(), port));
    return env.Undefined();
}

// ---------------------------------------------------------------------------
// Class registration
// ---------------------------------------------------------------------------

Napi::Object RatsNode::Init(Napi::Env env, Napi::Object exports) {
    Napi::Function func = DefineClass(env, "RatsNode", {
        // lifecycle / core
        InstanceMethod("start", &RatsNode::Start),
        InstanceMethod("stop", &RatsNode::Stop),
        InstanceMethod("destroy", &RatsNode::Destroy),
        InstanceMethod("listenPort", &RatsNode::GetListenPort),
        InstanceMethod("localId", &RatsNode::GetLocalId),
        InstanceMethod("protocol", &RatsNode::GetProtocol),
        InstanceMethod("transports", &RatsNode::GetTransports),
        // connections
        InstanceMethod("connect", &RatsNode::Connect),
        InstanceMethod("peerCount", &RatsNode::GetPeerCount),
        InstanceMethod("peerIds", &RatsNode::GetPeerIds),
        InstanceMethod("setMaxPeers", &RatsNode::SetMaxPeers),
        InstanceMethod("maxPeers", &RatsNode::GetMaxPeers),
        InstanceMethod("peerTransport", &RatsNode::GetPeerTransport),
        InstanceMethod("peerTransports", &RatsNode::GetPeerTransports),
        // raw channel messaging
        InstanceMethod("send", &RatsNode::Send),
        InstanceMethod("broadcast", &RatsNode::Broadcast),
        InstanceMethod("peerWritable", &RatsNode::PeerWritable),
        InstanceMethod("on", &RatsNode::On),
        // peer events
        InstanceMethod("onPeerConnected", &RatsNode::OnPeerConnected),
        InstanceMethod("onPeerDisconnected", &RatsNode::OnPeerDisconnected),
        InstanceMethod("onPeerWritable", &RatsNode::OnPeerWritable),
        // discovery / NAT
        InstanceMethod("enableDht", &RatsNode::EnableDht),
        InstanceMethod("enableMdns", &RatsNode::EnableMdns),
        InstanceMethod("enablePortMapping", &RatsNode::EnablePortMapping),
        InstanceMethod("enableHolePunch", &RatsNode::EnableHolePunch),
        InstanceMethod("punchPeer", &RatsNode::PunchPeer),
        InstanceMethod("enableRelay", &RatsNode::EnableRelay),
        InstanceMethod("connectViaRelay", &RatsNode::ConnectViaRelay),
        InstanceMethod("natMapping", &RatsNode::GetNatMapping),
        // pub/sub
        InstanceMethod("enablePubsub", &RatsNode::EnablePubsub),
        InstanceMethod("subscribe", &RatsNode::Subscribe),
        InstanceMethod("unsubscribe", &RatsNode::Unsubscribe),
        InstanceMethod("publish", &RatsNode::Publish),
        // typed JSON
        InstanceMethod("enableJson", &RatsNode::EnableJson),
        InstanceMethod("onJson", &RatsNode::OnJson),
        InstanceMethod("onceJson", &RatsNode::OnceJson),
        InstanceMethod("offJson", &RatsNode::OffJson),
        InstanceMethod("sendJson", &RatsNode::SendJson),
        InstanceMethod("broadcastJson", &RatsNode::BroadcastJson),
        // file transfer
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
        // ping / reconnect
        InstanceMethod("enablePing", &RatsNode::EnablePing),
        InstanceMethod("peerRttMs", &RatsNode::GetPeerRttMs),
        InstanceMethod("enableReconnect", &RatsNode::EnableReconnect),
        InstanceMethod("addReconnect", &RatsNode::AddReconnect),
        InstanceMethod("removeReconnect", &RatsNode::RemoveReconnect),
    });

    exports.Set("RatsNode", func);
    return exports;
}

// ---------------------------------------------------------------------------
// Module-level functions (process-global; no node required)
// ---------------------------------------------------------------------------

Napi::Value GetVersionString(const Napi::CallbackInfo& info) {
    return Napi::String::New(info.Env(), rats_version_string());
}

Napi::Value GetVersion(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    int major = 0, minor = 0, patch = 0, build = 0;
    rats_version(&major, &minor, &patch, &build);
    Napi::Object version = Napi::Object::New(env);
    version.Set("major", Napi::Number::New(env, major));
    version.Set("minor", Napi::Number::New(env, minor));
    version.Set("patch", Napi::Number::New(env, patch));
    version.Set("build", Napi::Number::New(env, build));
    return version;
}

Napi::Value GetGitDescribe(const Napi::CallbackInfo& info) {
    return Napi::String::New(info.Env(), rats_git_describe());
}

Napi::Value GetAbi(const Napi::CallbackInfo& info) {
    return Napi::Number::New(info.Env(), rats_abi());
}

Napi::Value SetLogLevel(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsNumber()) {
        Napi::TypeError::New(env, "Expected log level (number)").ThrowAsJavaScriptException();
        return env.Undefined();
    }
    rats_set_log_level(static_cast<rats_log_level_t>(info[0].As<Napi::Number>().Int32Value()));
    return env.Undefined();
}

Napi::Value SetLogFile(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() >= 1 && info[0].IsString()) {
        std::string path = info[0].As<Napi::String>().Utf8Value();
        rats_set_log_file(path.c_str());
    } else {
        rats_set_log_file(nullptr); // NULL/empty disables file logging
    }
    return env.Undefined();
}

// Constants exposed to JS (security + log levels + error codes).
Napi::Object InitConstants(Napi::Env env) {
    Napi::Object constants = Napi::Object::New(env);

    Napi::Object security = Napi::Object::New(env);
    security.Set("NOISE", Napi::Number::New(env, RATS_SECURITY_NOISE));
    security.Set("PLAINTEXT", Napi::Number::New(env, RATS_SECURITY_PLAINTEXT));
    constants.Set("SECURITY", security);

    Napi::Object transport = Napi::Object::New(env);
    transport.Set("TCP", Napi::Number::New(env, RATS_TRANSPORT_TCP));
    transport.Set("UDP", Napi::Number::New(env, RATS_TRANSPORT_UDP));
    constants.Set("TRANSPORT", transport);

    Napi::Object transportMask = Napi::Object::New(env);
    transportMask.Set("TCP", Napi::Number::New(env, RATS_TRANSPORT_MASK_TCP));
    transportMask.Set("UDP", Napi::Number::New(env, RATS_TRANSPORT_MASK_UDP));
    constants.Set("TRANSPORT_MASK", transportMask);

    Napi::Object nat = Napi::Object::New(env);
    nat.Set("UNKNOWN", Napi::Number::New(env, RATS_NAT_UNKNOWN));
    nat.Set("OPEN", Napi::Number::New(env, RATS_NAT_OPEN));
    nat.Set("ENDPOINT_INDEPENDENT", Napi::Number::New(env, RATS_NAT_ENDPOINT_INDEPENDENT));
    nat.Set("ENDPOINT_DEPENDENT", Napi::Number::New(env, RATS_NAT_ENDPOINT_DEPENDENT));
    constants.Set("NAT_MAPPING", nat);

    Napi::Object logLevels = Napi::Object::New(env);
    logLevels.Set("DEBUG", Napi::Number::New(env, RATS_LOG_DEBUG));
    logLevels.Set("INFO", Napi::Number::New(env, RATS_LOG_INFO));
    logLevels.Set("WARN", Napi::Number::New(env, RATS_LOG_WARN));
    logLevels.Set("ERROR", Napi::Number::New(env, RATS_LOG_ERROR));
    constants.Set("LOG_LEVELS", logLevels);

    Napi::Object errors = Napi::Object::New(env);
    errors.Set("OK", Napi::Number::New(env, RATS_OK));
    errors.Set("INVALID_ARG", Napi::Number::New(env, RATS_ERR_INVALID_ARG));
    errors.Set("NOT_STARTED", Napi::Number::New(env, RATS_ERR_NOT_STARTED));
    errors.Set("ALREADY_STARTED", Napi::Number::New(env, RATS_ERR_ALREADY_STARTED));
    errors.Set("NOT_ENABLED", Napi::Number::New(env, RATS_ERR_NOT_ENABLED));
    errors.Set("NO_SUCH_PEER", Napi::Number::New(env, RATS_ERR_NO_SUCH_PEER));
    errors.Set("BIND", Napi::Number::New(env, RATS_ERR_BIND));
    errors.Set("INTERNAL", Napi::Number::New(env, RATS_ERR_INTERNAL));
    constants.Set("ERRORS", errors);

    return constants;
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    RatsNode::Init(env, exports);

    exports.Set("getVersionString", Napi::Function::New(env, GetVersionString));
    exports.Set("getVersion", Napi::Function::New(env, GetVersion));
    exports.Set("getGitDescribe", Napi::Function::New(env, GetGitDescribe));
    exports.Set("getAbi", Napi::Function::New(env, GetAbi));
    exports.Set("setLogLevel", Napi::Function::New(env, SetLogLevel));
    exports.Set("setLogFile", Napi::Function::New(env, SetLogFile));
    exports.Set("constants", InitConstants(env));

    return exports;
}

NODE_API_MODULE(librats, Init)
