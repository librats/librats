/**
 * LibRats Node.js native addon.
 *
 * N-API wrapper over the canonical C ABI in src/bindings/rats.h. Callbacks fire
 * on librats' internal reactor thread, so every native callback marshals into
 * the JS thread with a Napi::ThreadSafeFunction (TSFN). Per-channel / per-topic
 * / per-json-type handlers are kept in maps owned by the RatsClient instance and
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
#include "bindings/rats.h"

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

class RatsClient : public Napi::ObjectWrap<RatsClient> {
public:
    static Napi::Object Init(Napi::Env env, Napi::Object exports);
    RatsClient(const Napi::CallbackInfo& info);
    ~RatsClient();

private:
    rats_t node_ = nullptr;

    // Single-slot callbacks (peer connect/disconnect, file offer/progress/complete).
    std::unique_ptr<CbContext> on_connected_;
    std::unique_ptr<CbContext> on_disconnected_;
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

    // ---- lifecycle / core ----
    Napi::Value Start(const Napi::CallbackInfo& info);
    void Stop(const Napi::CallbackInfo& info);
    Napi::Value GetListenPort(const Napi::CallbackInfo& info);
    Napi::Value GetOurPeerId(const Napi::CallbackInfo& info);
    Napi::Value GetProtocol(const Napi::CallbackInfo& info);

    // ---- connections ----
    Napi::Value Connect(const Napi::CallbackInfo& info);
    Napi::Value GetPeerCount(const Napi::CallbackInfo& info);
    Napi::Value GetPeerIds(const Napi::CallbackInfo& info);
    void SetMaxPeers(const Napi::CallbackInfo& info);
    Napi::Value GetMaxPeers(const Napi::CallbackInfo& info);

    // ---- raw channel messaging ----
    Napi::Value Send(const Napi::CallbackInfo& info);
    Napi::Value Broadcast(const Napi::CallbackInfo& info);
    void On(const Napi::CallbackInfo& info);

    // ---- peer events ----
    void OnPeerConnected(const Napi::CallbackInfo& info);
    void OnPeerDisconnected(const Napi::CallbackInfo& info);

    // ---- discovery / NAT ----
    void EnableDht(const Napi::CallbackInfo& info);
    void EnableMdns(const Napi::CallbackInfo& info);
    void EnablePortMapping(const Napi::CallbackInfo& info);

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

RatsClient::RatsClient(const Napi::CallbackInfo& info)
    : Napi::ObjectWrap<RatsClient>(info) {
    Napi::Env env = info.Env();

    // Two construction forms:
    //   new RatsClient(port)         -> rats_create(port)
    //   new RatsClient({ ...config }) -> rats_create_config(&cfg)
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
        Napi::Error::New(env, "Failed to create RatsClient").ThrowAsJavaScriptException();
        return;
    }
}

RatsClient::~RatsClient() {
    // Release all TSFNs first so no JS callback can be invoked during/after
    // destruction, then destroy the native node.
    if (on_connected_) on_connected_->release();
    if (on_disconnected_) on_disconnected_->release();
    if (on_file_offer_) on_file_offer_->release();
    if (on_file_progress_) on_file_progress_->release();
    if (on_file_complete_) on_file_complete_->release();
    for (auto& h : handlers_) h->release();

    if (node_) {
        rats_destroy(node_);
        node_ = nullptr;
    }
}

Napi::Value RatsClient::Start(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    rats_error_t err = rats_start(node_);
    if (throw_on_error(env, err)) return env.Undefined();
    return env.Undefined();
}

void RatsClient::Stop(const Napi::CallbackInfo& info) {
    rats_stop(node_);
}

Napi::Value RatsClient::GetListenPort(const Napi::CallbackInfo& info) {
    return Napi::Number::New(info.Env(), rats_listen_port(node_));
}

Napi::Value RatsClient::GetOurPeerId(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    char* id = rats_local_id(node_);
    if (!id) return env.Null();
    Napi::String result = Napi::String::New(env, id);
    rats_string_free(id);
    return result;
}

Napi::Value RatsClient::GetProtocol(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    char* s = rats_protocol(node_);
    if (!s) return env.Null();
    Napi::String result = Napi::String::New(env, s);
    rats_string_free(s);
    return result;
}

// ---------------------------------------------------------------------------
// Connections
// ---------------------------------------------------------------------------

Napi::Value RatsClient::Connect(const Napi::CallbackInfo& info) {
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

Napi::Value RatsClient::GetPeerCount(const Napi::CallbackInfo& info) {
    return Napi::Number::New(info.Env(), static_cast<double>(rats_peer_count(node_)));
}

Napi::Value RatsClient::GetPeerIds(const Napi::CallbackInfo& info) {
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

void RatsClient::SetMaxPeers(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsNumber()) {
        Napi::TypeError::New(env, "Expected maxPeers (number)").ThrowAsJavaScriptException();
        return;
    }
    rats_set_max_peers(node_, static_cast<size_t>(info[0].As<Napi::Number>().Int64Value()));
}

Napi::Value RatsClient::GetMaxPeers(const Napi::CallbackInfo& info) {
    return Napi::Number::New(info.Env(), static_cast<double>(rats_max_peers(node_)));
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

Napi::Value RatsClient::Send(const Napi::CallbackInfo& info) {
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

Napi::Value RatsClient::Broadcast(const Napi::CallbackInfo& info) {
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
void RatsClient::On(const Napi::CallbackInfo& info) {
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

void RatsClient::OnPeerConnected(const Napi::CallbackInfo& info) {
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

void RatsClient::OnPeerDisconnected(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsFunction()) {
        Napi::TypeError::New(env, "Expected callback function").ThrowAsJavaScriptException();
        return;
    }
    on_disconnected_ = std::make_unique<CbContext>();
    on_disconnected_->init(env, info[0].As<Napi::Function>(), "on_peer_disconnected");
    auto trampoline = [](void* user, const char* peer_id) {
        auto* c = static_cast<CbContext*>(user);
        std::string peer = peer_id ? peer_id : "";
        c->tsfn.BlockingCall([peer](Napi::Env env, Napi::Function js) {
            js.Call({Napi::String::New(env, peer)});
        });
    };
    throw_on_error(env, rats_on_peer_disconnected(node_, trampoline, on_disconnected_.get()));
}

// ---------------------------------------------------------------------------
// Discovery / NAT
// ---------------------------------------------------------------------------

void RatsClient::EnableDht(const Napi::CallbackInfo& info) {
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

void RatsClient::EnableMdns(const Napi::CallbackInfo& info) {
    throw_on_error(info.Env(), rats_enable_mdns(node_));
}

void RatsClient::EnablePortMapping(const Napi::CallbackInfo& info) {
    int upnp = 1, natpmp = 1;
    if (info.Length() >= 1 && info[0].IsBoolean()) upnp = info[0].As<Napi::Boolean>().Value() ? 1 : 0;
    if (info.Length() >= 2 && info[1].IsBoolean()) natpmp = info[1].As<Napi::Boolean>().Value() ? 1 : 0;
    throw_on_error(info.Env(), rats_enable_port_mapping(node_, upnp, natpmp));
}

// ---------------------------------------------------------------------------
// Pub/sub
// ---------------------------------------------------------------------------

void RatsClient::EnablePubsub(const Napi::CallbackInfo& info) {
    throw_on_error(info.Env(), rats_enable_pubsub(node_));
}

// rats_topic_cb(user, peer_id_hex, topic, data, len) -> JS (peerId, topic, Buffer)
void RatsClient::Subscribe(const Napi::CallbackInfo& info) {
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

void RatsClient::Unsubscribe(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "Expected topic (string)").ThrowAsJavaScriptException();
        return;
    }
    std::string topic = info[0].As<Napi::String>().Utf8Value();
    throw_on_error(env, rats_unsubscribe(node_, topic.c_str()));
}

Napi::Value RatsClient::Publish(const Napi::CallbackInfo& info) {
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

void RatsClient::EnableJson(const Napi::CallbackInfo& info) {
    throw_on_error(info.Env(), rats_enable_json(node_));
}

void RatsClient::OnJsonImpl(const Napi::CallbackInfo& info, bool once) {
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

void RatsClient::OnJson(const Napi::CallbackInfo& info) { OnJsonImpl(info, false); }
void RatsClient::OnceJson(const Napi::CallbackInfo& info) { OnJsonImpl(info, true); }

void RatsClient::OffJson(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "Expected type (string)").ThrowAsJavaScriptException();
        return;
    }
    std::string type = info[0].As<Napi::String>().Utf8Value();
    throw_on_error(env, rats_off_json(node_, type.c_str()));
}

Napi::Value RatsClient::SendJson(const Napi::CallbackInfo& info) {
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

Napi::Value RatsClient::BroadcastJson(const Napi::CallbackInfo& info) {
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

void RatsClient::EnableFileTransfer(const Napi::CallbackInfo& info) {
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
void RatsClient::OnFileOffer(const Napi::CallbackInfo& info) {
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
void RatsClient::OnFileProgress(const Napi::CallbackInfo& info) {
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

// rats_file_complete_cb(user, transfer_id, success, path)
void RatsClient::OnFileComplete(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsFunction()) {
        Napi::TypeError::New(env, "Expected callback function").ThrowAsJavaScriptException();
        return;
    }
    on_file_complete_ = std::make_unique<CbContext>();
    on_file_complete_->init(env, info[0].As<Napi::Function>(), "on_file_complete");
    auto trampoline = [](void* user, uint64_t transfer_id, int success, const char* path) {
        auto* c = static_cast<CbContext*>(user);
        std::string p = path ? path : "";
        bool ok = success != 0;
        c->tsfn.BlockingCall([transfer_id, ok, p](Napi::Env env, Napi::Function js) {
            js.Call({Napi::Number::New(env, static_cast<double>(transfer_id)),
                     Napi::Boolean::New(env, ok),
                     Napi::String::New(env, p)});
        });
    };
    throw_on_error(env, rats_on_file_complete(node_, trampoline, on_file_complete_.get()));
}

Napi::Value RatsClient::SendFile(const Napi::CallbackInfo& info) {
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

Napi::Value RatsClient::SendDirectory(const Napi::CallbackInfo& info) {
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

Napi::Value RatsClient::AcceptFile(const Napi::CallbackInfo& info) {
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

Napi::Value RatsClient::RejectFile(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string peer; uint64_t id;
    if (!parse_xfer_args(info, peer, id)) return env.Undefined();
    throw_on_error(env, rats_reject_file(node_, peer.c_str(), id));
    return env.Undefined();
}

Napi::Value RatsClient::CancelFile(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string peer; uint64_t id;
    if (!parse_xfer_args(info, peer, id)) return env.Undefined();
    throw_on_error(env, rats_cancel_file(node_, peer.c_str(), id));
    return env.Undefined();
}

Napi::Value RatsClient::PauseFile(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string peer; uint64_t id;
    if (!parse_xfer_args(info, peer, id)) return env.Undefined();
    throw_on_error(env, rats_pause_file(node_, peer.c_str(), id));
    return env.Undefined();
}

Napi::Value RatsClient::ResumeFile(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::string peer; uint64_t id;
    if (!parse_xfer_args(info, peer, id)) return env.Undefined();
    throw_on_error(env, rats_resume_file(node_, peer.c_str(), id));
    return env.Undefined();
}

// ---------------------------------------------------------------------------
// Ping / reconnect
// ---------------------------------------------------------------------------

void RatsClient::EnablePing(const Napi::CallbackInfo& info) {
    throw_on_error(info.Env(), rats_enable_ping(node_));
}

Napi::Value RatsClient::GetPeerRttMs(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "Expected peerId (string)").ThrowAsJavaScriptException();
        return env.Undefined();
    }
    std::string peer = info[0].As<Napi::String>().Utf8Value();
    int64_t rtt = rats_peer_rtt_ms(node_, peer.c_str());
    return Napi::Number::New(env, static_cast<double>(rtt));
}

void RatsClient::EnableReconnect(const Napi::CallbackInfo& info) {
    throw_on_error(info.Env(), rats_enable_reconnect(node_));
}

Napi::Value RatsClient::AddReconnect(const Napi::CallbackInfo& info) {
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

Napi::Value RatsClient::RemoveReconnect(const Napi::CallbackInfo& info) {
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

Napi::Object RatsClient::Init(Napi::Env env, Napi::Object exports) {
    Napi::Function func = DefineClass(env, "RatsClient", {
        // lifecycle / core
        InstanceMethod("start", &RatsClient::Start),
        InstanceMethod("stop", &RatsClient::Stop),
        InstanceMethod("getListenPort", &RatsClient::GetListenPort),
        InstanceMethod("getOurPeerId", &RatsClient::GetOurPeerId),
        InstanceMethod("getProtocol", &RatsClient::GetProtocol),
        // connections
        InstanceMethod("connect", &RatsClient::Connect),
        InstanceMethod("getPeerCount", &RatsClient::GetPeerCount),
        InstanceMethod("getPeerIds", &RatsClient::GetPeerIds),
        InstanceMethod("setMaxPeers", &RatsClient::SetMaxPeers),
        InstanceMethod("getMaxPeers", &RatsClient::GetMaxPeers),
        // raw channel messaging
        InstanceMethod("send", &RatsClient::Send),
        InstanceMethod("broadcast", &RatsClient::Broadcast),
        InstanceMethod("on", &RatsClient::On),
        // peer events
        InstanceMethod("onPeerConnected", &RatsClient::OnPeerConnected),
        InstanceMethod("onPeerDisconnected", &RatsClient::OnPeerDisconnected),
        // discovery / NAT
        InstanceMethod("enableDht", &RatsClient::EnableDht),
        InstanceMethod("enableMdns", &RatsClient::EnableMdns),
        InstanceMethod("enablePortMapping", &RatsClient::EnablePortMapping),
        // pub/sub
        InstanceMethod("enablePubsub", &RatsClient::EnablePubsub),
        InstanceMethod("subscribe", &RatsClient::Subscribe),
        InstanceMethod("unsubscribe", &RatsClient::Unsubscribe),
        InstanceMethod("publish", &RatsClient::Publish),
        // typed JSON
        InstanceMethod("enableJson", &RatsClient::EnableJson),
        InstanceMethod("onJson", &RatsClient::OnJson),
        InstanceMethod("onceJson", &RatsClient::OnceJson),
        InstanceMethod("offJson", &RatsClient::OffJson),
        InstanceMethod("sendJson", &RatsClient::SendJson),
        InstanceMethod("broadcastJson", &RatsClient::BroadcastJson),
        // file transfer
        InstanceMethod("enableFileTransfer", &RatsClient::EnableFileTransfer),
        InstanceMethod("onFileOffer", &RatsClient::OnFileOffer),
        InstanceMethod("onFileProgress", &RatsClient::OnFileProgress),
        InstanceMethod("onFileComplete", &RatsClient::OnFileComplete),
        InstanceMethod("sendFile", &RatsClient::SendFile),
        InstanceMethod("sendDirectory", &RatsClient::SendDirectory),
        InstanceMethod("acceptFile", &RatsClient::AcceptFile),
        InstanceMethod("rejectFile", &RatsClient::RejectFile),
        InstanceMethod("cancelFile", &RatsClient::CancelFile),
        InstanceMethod("pauseFile", &RatsClient::PauseFile),
        InstanceMethod("resumeFile", &RatsClient::ResumeFile),
        // ping / reconnect
        InstanceMethod("enablePing", &RatsClient::EnablePing),
        InstanceMethod("getPeerRttMs", &RatsClient::GetPeerRttMs),
        InstanceMethod("enableReconnect", &RatsClient::EnableReconnect),
        InstanceMethod("addReconnect", &RatsClient::AddReconnect),
        InstanceMethod("removeReconnect", &RatsClient::RemoveReconnect),
    });

    exports.Set("RatsClient", func);
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
    RatsClient::Init(env, exports);

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
