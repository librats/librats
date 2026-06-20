#include <gtest/gtest.h>

#include "bindings/rats.h"

#include <atomic>
#include <chrono>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace std::chrono_literals;

namespace {

template <typename Pred>
bool wait_for(Pred pred, std::chrono::milliseconds timeout = 10s) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(1ms);
    }
    return pred();
}

struct EchoCtx { rats_t node; };
void echo_cb(void* user, const char* peer_id, const void* data, size_t len) {
    auto* ctx = static_cast<EchoCtx*>(user);
    rats_send(ctx->node, peer_id, "chat", data, len);  // bounce back to sender
}

struct CollectCtx {
    std::atomic<int> peers{0};
    std::mutex mu;
    std::string got;
};
void peer_cb(void* user, const char*) { static_cast<CollectCtx*>(user)->peers++; }
void collect_cb(void* user, const char*, const void* data, size_t len) {
    auto* ctx = static_cast<CollectCtx*>(user);
    std::lock_guard<std::mutex> lock(ctx->mu);
    ctx->got.assign(static_cast<const char*>(data), len);
}

} // namespace

// Drive two nodes entirely through the C ABI: connect, send on a channel, echo.
TEST(NodeCApiTest, ConnectSendAndEcho) {
    rats_t server = rats_create(0);  // listening, ephemeral
    rats_t client = rats_create_ex(0, /*enable_listen=*/0, "127.0.0.1", RATS_SECURITY_NOISE);
    ASSERT_NE(server, nullptr);
    ASSERT_NE(client, nullptr);

    EchoCtx echo{server};
    CollectCtx client_ctx;
    rats_on_message(server, "chat", echo_cb, &echo);
    rats_on_peer_connected(client, peer_cb, &client_ctx);
    rats_on_message(client, "chat", collect_cb, &client_ctx);

    ASSERT_EQ(rats_start(server), RATS_OK);
    ASSERT_EQ(rats_start(client), RATS_OK);

    rats_connect(client, "127.0.0.1", rats_listen_port(server));
    ASSERT_TRUE(wait_for([&] { return rats_peer_count(client) == 1; }));
    EXPECT_EQ(client_ctx.peers.load(), 1);

    char* server_id = rats_local_id(server);
    ASSERT_NE(server_id, nullptr);
    EXPECT_EQ(std::strlen(server_id), 64u);

    const char* msg = "hello capi";
    rats_send(client, server_id, "chat", msg, std::strlen(msg));

    ASSERT_TRUE(wait_for([&] { std::lock_guard<std::mutex> l(client_ctx.mu); return client_ctx.got == msg; }))
        << "no echo via C API";

    rats_string_free(server_id);
    rats_stop(client);
    rats_stop(server);
    rats_destroy(client);
    rats_destroy(server);
}

// local_id is stable and distinct per node; lifecycle is clean.
TEST(NodeCApiTest, LocalIdAndLifecycle) {
    rats_t a = rats_create(0);
    rats_t b = rats_create(0);

    char* ida = rats_local_id(a);
    char* idb = rats_local_id(b);
    ASSERT_NE(ida, nullptr);
    ASSERT_NE(idb, nullptr);
    EXPECT_STRNE(ida, idb);

    EXPECT_EQ(rats_start(a), RATS_OK);
    EXPECT_NE(rats_listen_port(a), 0);
    rats_stop(a);

    rats_string_free(ida);
    rats_string_free(idb);
    rats_destroy(a);
    rats_destroy(b);
}

namespace {
struct TopicCtx {
    std::mutex mu;
    std::string topic, data;
};
void topic_cb(void* user, const char*, const char* topic, const void* data, size_t len) {
    auto* ctx = static_cast<TopicCtx*>(user);
    std::lock_guard<std::mutex> lock(ctx->mu);
    ctx->topic = topic;
    ctx->data.assign(static_cast<const char*>(data), len);
}
struct TypedCtx {
    std::mutex mu;
    std::string json;
};
void typed_cb(void* user, const char*, const char* json) {
    auto* ctx = static_cast<TypedCtx*>(user);
    std::lock_guard<std::mutex> lock(ctx->mu);
    ctx->json = json;
}
} // namespace

// Connect two nodes, then exercise pub/sub and typed JSON messaging via the C ABI.
TEST(NodeCApiTest, PubSubAndTypedMessaging) {
    rats_t server = rats_create(0);
    rats_t client = rats_create_ex(0, /*enable_listen=*/0, "127.0.0.1", RATS_SECURITY_NOISE);
    ASSERT_NE(server, nullptr);
    ASSERT_NE(client, nullptr);

    // Subsystems must be configured before start(). Both nodes subscribe / register
    // so each has the subsystem attached; we then assert on one direction.
    TopicCtx topic_ctx, client_topic_ctx;
    TypedCtx typed_ctx, server_typed_ctx;
    ASSERT_EQ(rats_enable_pubsub(server), RATS_OK);
    ASSERT_EQ(rats_enable_pubsub(client), RATS_OK);
    ASSERT_EQ(rats_enable_messaging(server), RATS_OK);
    ASSERT_EQ(rats_enable_messaging(client), RATS_OK);
    rats_subscribe(server, "news", topic_cb, &topic_ctx);
    rats_subscribe(client, "news", topic_cb, &client_topic_ctx);
    rats_on(client, "greet", typed_cb, &typed_ctx);
    rats_on(server, "greet", typed_cb, &server_typed_ctx);

    ASSERT_EQ(rats_start(server), RATS_OK);
    ASSERT_EQ(rats_start(client), RATS_OK);

    rats_connect(client, "127.0.0.1", rats_listen_port(server));
    ASSERT_TRUE(wait_for([&] { return rats_peer_count(server) == 1 && rats_peer_count(client) == 1; }));

    // peer enumeration: the client should list exactly the server's id.
    char* server_id = rats_local_id(server);
    size_t n = 0;
    char** ids = rats_peer_ids(client, &n);
    ASSERT_EQ(n, 1u);
    ASSERT_NE(ids, nullptr);
    EXPECT_STREQ(ids[0], server_id);
    rats_free_peer_ids(ids, n);

    // pub/sub: client publishes once the server's subscription has propagated.
    const char* payload = "breaking";
    ASSERT_TRUE(wait_for([&] {
        rats_publish(client, "news", payload, std::strlen(payload));
        std::lock_guard<std::mutex> l(topic_ctx.mu);
        return topic_ctx.data == payload;
    })) << "pub/sub message not delivered";
    {
        std::lock_guard<std::mutex> l(topic_ctx.mu);
        EXPECT_EQ(topic_ctx.topic, "news");
    }

    // typed JSON messaging: server → client.
    char* client_id = rats_local_id(client);
    ASSERT_TRUE(wait_for([&] {
        rats_send_typed(server, client_id, "greet", "{\"text\":\"hi\"}");
        std::lock_guard<std::mutex> l(typed_ctx.mu);
        return typed_ctx.json.find("\"text\"") != std::string::npos;
    })) << "typed message not delivered";

    rats_string_free(server_id);
    rats_string_free(client_id);
    rats_stop(client);
    rats_stop(server);
    rats_destroy(client);
    rats_destroy(server);
}

// max_peers is settable/readable via the ABI and actually caps inbound peers.
TEST(NodeCApiTest, MaxPeersCapsInbound) {
    rats_t server = rats_create(0);
    rats_t a = rats_create_ex(0, 0, "127.0.0.1", RATS_SECURITY_NOISE);
    rats_t b = rats_create_ex(0, 0, "127.0.0.1", RATS_SECURITY_NOISE);

    rats_set_max_peers(server, 1);
    EXPECT_EQ(rats_max_peers(server), 1u);

    ASSERT_EQ(rats_start(server), RATS_OK);
    ASSERT_EQ(rats_start(a), RATS_OK);
    ASSERT_EQ(rats_start(b), RATS_OK);

    uint16_t port = rats_listen_port(server);
    rats_connect(a, "127.0.0.1", port);
    ASSERT_TRUE(wait_for([&] { return rats_peer_count(server) == 1; }));

    rats_connect(b, "127.0.0.1", port);            // refused: server already at its cap
    std::this_thread::sleep_for(700ms);
    EXPECT_EQ(rats_peer_count(server), 1u);

    rats_stop(a); rats_stop(b); rats_stop(server);
    rats_destroy(a); rats_destroy(b); rats_destroy(server);
}

// The disconnect callback fires (with the peer id) when a peer drops.
TEST(NodeCApiTest, DisconnectCallbackFires) {
    rats_t server = rats_create(0);
    rats_t client = rats_create_ex(0, 0, "127.0.0.1", RATS_SECURITY_NOISE);

    std::atomic<int> disconnects{0};
    rats_on_peer_disconnected(server, [](void* u, const char* id) {
        if (id && std::strlen(id) == 64) static_cast<std::atomic<int>*>(u)->fetch_add(1);
    }, &disconnects);

    ASSERT_EQ(rats_start(server), RATS_OK);
    ASSERT_EQ(rats_start(client), RATS_OK);
    rats_connect(client, "127.0.0.1", rats_listen_port(server));
    ASSERT_TRUE(wait_for([&] { return rats_peer_count(server) == 1; }));

    rats_stop(client);  // drops the connection
    ASSERT_TRUE(wait_for([&] { return disconnects.load() == 1; }));
    EXPECT_EQ(rats_peer_count(server), 0u);

    rats_stop(server);
    rats_destroy(client);
    rats_destroy(server);
}

namespace {
struct BinCtx { std::mutex mu; std::vector<uint8_t> got; };
void bin_collect_cb(void* user, const char*, const void* data, size_t len) {
    auto* ctx = static_cast<BinCtx*>(user);
    std::lock_guard<std::mutex> l(ctx->mu);
    const auto* p = static_cast<const uint8_t*>(data);
    ctx->got.assign(p, p + len);
}
} // namespace

// rats_send carries (void*, len) faithfully — a payload with embedded NUL bytes
// round-trips intact, proving the channel is length-framed, not NUL-terminated.
TEST(NodeCApiTest, BinaryPayloadWithNuls) {
    rats_t server = rats_create(0);
    rats_t client = rats_create_ex(0, 0, "127.0.0.1", RATS_SECURITY_NOISE);

    BinCtx ctx;
    rats_on_message(server, "bin", bin_collect_cb, &ctx);

    ASSERT_EQ(rats_start(server), RATS_OK);
    ASSERT_EQ(rats_start(client), RATS_OK);
    rats_connect(client, "127.0.0.1", rats_listen_port(server));
    ASSERT_TRUE(wait_for([&] { return rats_peer_count(client) == 1; }));

    const uint8_t payload[] = {0x00, 0x01, 0xFF, 0x00, 0x42};
    char* server_id = rats_local_id(server);
    rats_send(client, server_id, "bin", payload, sizeof(payload));

    ASSERT_TRUE(wait_for([&] { std::lock_guard<std::mutex> l(ctx.mu); return ctx.got.size() == sizeof(payload); }));
    {
        std::lock_guard<std::mutex> l(ctx.mu);
        EXPECT_EQ(std::memcmp(ctx.got.data(), payload, sizeof(payload)), 0);
    }

    rats_string_free(server_id);
    rats_stop(client); rats_stop(server);
    rats_destroy(client); rats_destroy(server);
}

// File-transfer negative/control paths: bad inputs return 0 / are no-ops, never crash.
TEST(NodeCApiTest, FileTransferNegativePaths) {
    rats_t node = rats_create(0);
    rats_enable_file_transfer(node, ".");
    ASSERT_EQ(rats_start(node), RATS_OK);

    char* self = rats_local_id(node);  // a valid 64-hex id (but no transfer exists for it)

    EXPECT_EQ(rats_send_file(node, "not-a-valid-hex-id", "whatever.bin"), 0u);   // bad hex
    EXPECT_EQ(rats_send_file(node, self, "no_such_file_98765.bin"), 0u);          // missing path
    EXPECT_EQ(rats_send_directory(node, self, "no_such_dir_98765"), 0u);          // missing dir
    EXPECT_EQ(rats_cancel_file(node, self, 999999u), RATS_ERR_NO_SUCH_PEER);       // unknown transfer
    EXPECT_EQ(rats_pause_file(node, self, 999999u), RATS_ERR_NO_SUCH_PEER);
    EXPECT_EQ(rats_resume_file(node, self, 999999u), RATS_ERR_NO_SUCH_PEER);
    EXPECT_NO_THROW(rats_accept_file(node, self, 999999u, "dest.bin"));           // no-op, no crash
    EXPECT_NO_THROW(rats_reject_file(node, self, 999999u));

    rats_string_free(self);
    rats_stop(node);
    rats_destroy(node);
}

// rats_broadcast (raw) and rats_broadcast_typed (JSON) both reach a connected peer.
TEST(NodeCApiTest, BroadcastRawAndTyped) {
    rats_t server = rats_create(0);
    rats_t client = rats_create_ex(0, 0, "127.0.0.1", RATS_SECURITY_NOISE);

    CollectCtx raw_ctx;
    TypedCtx typed_ctx, server_typed_ctx;
    ASSERT_EQ(rats_enable_messaging(client), RATS_OK);
    ASSERT_EQ(rats_enable_messaging(server), RATS_OK);
    rats_on_message(client, "raw", collect_cb, &raw_ctx);
    rats_on(client, "ev", typed_cb, &typed_ctx);
    // The server must own a MessageExchange before start() to broadcast typed
    // messages (subsystems attach pre-start), so register a handler on it too.
    rats_on(server, "ev", typed_cb, &server_typed_ctx);

    ASSERT_EQ(rats_start(server), RATS_OK);
    ASSERT_EQ(rats_start(client), RATS_OK);
    rats_connect(client, "127.0.0.1", rats_listen_port(server));
    ASSERT_TRUE(wait_for([&] { return rats_peer_count(server) == 1 && rats_peer_count(client) == 1; }));

    const char* raw = "via-broadcast";
    ASSERT_TRUE(wait_for([&] {
        rats_broadcast(server, "raw", raw, std::strlen(raw));
        std::lock_guard<std::mutex> l(raw_ctx.mu);
        return raw_ctx.got == raw;
    })) << "raw broadcast not delivered";

    ASSERT_TRUE(wait_for([&] {
        rats_broadcast_typed(server, "ev", "{\"k\":99}");
        std::lock_guard<std::mutex> l(typed_ctx.mu);
        return typed_ctx.json.find("\"k\"") != std::string::npos;
    })) << "typed broadcast not delivered";

    rats_stop(client); rats_stop(server);
    rats_destroy(client); rats_destroy(server);
}
