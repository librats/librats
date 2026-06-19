#include <gtest/gtest.h>

#include "bindings/rats_node.h"

#include <atomic>
#include <chrono>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>

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

struct EchoCtx { rats_node_t node; };
void echo_cb(void* user, const char* peer_id, const void* data, size_t len) {
    auto* ctx = static_cast<EchoCtx*>(user);
    rats_node_send(ctx->node, peer_id, "chat", data, len);  // bounce back to sender
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
    rats_node_t server = rats_node_create(0);  // listening, ephemeral
    rats_node_t client = rats_node_create_ex(0, /*enable_listen=*/0, "127.0.0.1", RATS_SECURITY_NOISE);
    ASSERT_NE(server, nullptr);
    ASSERT_NE(client, nullptr);

    EchoCtx echo{server};
    CollectCtx client_ctx;
    rats_node_on_message(server, "chat", echo_cb, &echo);
    rats_node_on_peer_connected(client, peer_cb, &client_ctx);
    rats_node_on_message(client, "chat", collect_cb, &client_ctx);

    ASSERT_EQ(rats_node_start(server), 1);
    ASSERT_EQ(rats_node_start(client), 1);

    rats_node_connect(client, "127.0.0.1", rats_node_listen_port(server));
    ASSERT_TRUE(wait_for([&] { return rats_node_peer_count(client) == 1; }));
    EXPECT_EQ(client_ctx.peers.load(), 1);

    char* server_id = rats_node_local_id(server);
    ASSERT_NE(server_id, nullptr);
    EXPECT_EQ(std::strlen(server_id), 64u);

    const char* msg = "hello capi";
    rats_node_send(client, server_id, "chat", msg, std::strlen(msg));

    ASSERT_TRUE(wait_for([&] { std::lock_guard<std::mutex> l(client_ctx.mu); return client_ctx.got == msg; }))
        << "no echo via C API";

    rats_node_string_free(server_id);
    rats_node_stop(client);
    rats_node_stop(server);
    rats_node_destroy(client);
    rats_node_destroy(server);
}

// local_id is stable and distinct per node; lifecycle is clean.
TEST(NodeCApiTest, LocalIdAndLifecycle) {
    rats_node_t a = rats_node_create(0);
    rats_node_t b = rats_node_create(0);

    char* ida = rats_node_local_id(a);
    char* idb = rats_node_local_id(b);
    ASSERT_NE(ida, nullptr);
    ASSERT_NE(idb, nullptr);
    EXPECT_STRNE(ida, idb);

    EXPECT_EQ(rats_node_start(a), 1);
    EXPECT_NE(rats_node_listen_port(a), 0);
    rats_node_stop(a);

    rats_node_string_free(ida);
    rats_node_string_free(idb);
    rats_node_destroy(a);
    rats_node_destroy(b);
}
