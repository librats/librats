#pragma once

/**
 * @file message_json.h
 * @brief Typed JSON message exchange over PeerNetwork.
 *
 * A familiar `on`/`once`/`off` + `send` messaging API as a Subsystem: an
 * application names a message *type* (a string) and exchanges librats::Json
 * payloads with peers, without caring about framing or channels. Attach it like
 * any subsystem; reach it later via node.json() (or subsystem<MessageJson>()):
 *
 *   node.add_subsystem(std::make_unique<MessageJson>());
 *   node.json()->on("chat", [](const PeerId& from, const json& j){ ... });
 *   node.start();
 *   node.json()->send(peer_id, "chat", json{{"text","hi"}});
 *
 * Two deliberate properties:
 *   - the sender is the *authenticated* PeerId from the handshake, not a
 *     self-reported field in the payload (which could be spoofed);
 *   - no JSON envelope on the wire — just [type][payload], encrypted by the
 *     transport like everything else.
 *
 * Wire format (MessageType::Typed payload):
 *   [type_len:u16][type bytes][json payload bytes]   (json as compact text)
 *
 * Handlers run on a reactor thread; do not block in them. Registration is
 * thread-safe and may happen before or after start().
 */

#include "node/peer_network.h"
#include "peer/peer.h"
#include "peer/peer_id.h"
#include "core/bytes.h"
#include "util/json.h"

#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace librats {

class MessageJson final : public Subsystem {
public:
    using Handler      = std::function<void(const PeerId& from, const librats::Json& data)>;
    using SendCallback = std::function<void(bool ok, const std::string& error)>;

    /// Register a handler for `type`. Additive: multiple handlers may coexist and
    /// all fire (in registration order) for each received message of that type.
    void on(const std::string& type, Handler handler);

    /// Like on(), but the handler is removed right after it fires once.
    void once(const std::string& type, Handler handler);

    /// Remove every handler registered for `type`.
    void off(const std::string& type);

    /// Broadcast `data` of `type` to all connected peers. `cb`, if given, reports
    /// whether there was at least one peer to send to.
    void send(const std::string& type, const librats::Json& data, SendCallback cb = nullptr);

    /// Send `data` of `type` to one peer. `cb`, if given, reports success or the
    /// reason it could not be sent (e.g. the peer is not connected).
    void send(const PeerId& to, const std::string& type, const librats::Json& data,
              SendCallback cb = nullptr);

    // Subsystem — no background thread; purely event-driven.
    void attach(NodeContext& ctx) override;
    void start() override {}
    void stop() override {}

private:
    void on_typed(const PeerId& from, ByteView payload);
    static Bytes encode(const std::string& type, const librats::Json& data);

    struct Entry {
        Handler handler;
        bool    once;
    };

    PeerNetwork* network_ = nullptr;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::vector<Entry>> handlers_;
};

} // namespace librats
