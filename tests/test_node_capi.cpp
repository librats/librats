#include <gtest/gtest.h>

#include "librats/bindings/rats.h"

#include <atomic>
#include <chrono>
#include <cstring>
#include <filesystem>
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

// A listening node on loopback.
rats_t make_server() {
    rats_config_t cfg{};
    cfg.bind_address = "127.0.0.1";
    return rats_create(&cfg);
}

// A dial-only node.
rats_t make_client() {
    rats_config_t cfg{};
    cfg.dial_only = 1;
    return rats_create(&cfg);
}

// Start both, connect client → server and wait until each side holds the other.
void connect_pair(rats_t client, rats_t server) {
    ASSERT_EQ(rats_start(server), RATS_OK);
    ASSERT_EQ(rats_start(client), RATS_OK);
    ASSERT_EQ(rats_connect(client, "127.0.0.1", rats_listen_port(server)), RATS_OK);
    ASSERT_TRUE(wait_for([&] { return rats_peer_count(client) == 1 && rats_peer_count(server) == 1; }));
}

struct EchoCtx { rats_t node; };
void echo_cb(void* user, const char* peer_id, const void* data, size_t len) {
    auto* ctx = static_cast<EchoCtx*>(user);
    rats_send(ctx->node, peer_id, "chat", data, len, 0);  // bounce back to sender
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

struct BinCtx { std::mutex mu; std::vector<uint8_t> got; };
void bin_collect_cb(void* user, const char*, const void* data, size_t len) {
    auto* ctx = static_cast<BinCtx*>(user);
    std::lock_guard<std::mutex> l(ctx->mu);
    const auto* p = static_cast<const uint8_t*>(data);
    ctx->got.assign(p, p + len);
}

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

struct JsonCtx {
    std::mutex mu;
    std::string json;
};
void json_cb(void* user, const char*, const char* json) {
    auto* ctx = static_cast<JsonCtx*>(user);
    std::lock_guard<std::mutex> lock(ctx->mu);
    ctx->json = json;
}

} // namespace

// ─── configuration ──────────────────────────────────────────────────────────

// Zero is the default in every field, so a zeroed struct and NULL are the same
// complete config: listening, both transports, UDP preferred.
TEST(NodeCApiTest, AZeroedConfigIsTheDefaultConfig) {
    rats_config_t cfg;
    std::memset(&cfg, 0, sizeof(cfg));
    for (const rats_config_t* c : {static_cast<const rats_config_t*>(&cfg),
                                   static_cast<const rats_config_t*>(nullptr)}) {
        rats_t node = rats_create(c);
        ASSERT_NE(node, nullptr);
        EXPECT_EQ(rats_transports(node), 0u) << "nothing runs before start";
        ASSERT_EQ(rats_start(node), RATS_OK);
        EXPECT_NE(rats_listen_port(node), 0);
        EXPECT_EQ(rats_transports(node), RATS_TRANSPORT_MASK_TCP | RATS_TRANSPORT_MASK_UDP);
        EXPECT_STREQ(rats_protocol(node), "librats/1.0");
        rats_stop(node);
        EXPECT_EQ(rats_transports(node), 0u);
        rats_destroy(node);
    }
}

// A config no node can run with is refused at create, not discovered later from
// a node that never connects.
TEST(NodeCApiTest, AnImpossibleConfigIsRefused) {
    rats_config_t cfg{};
    cfg.transports = 0x4;   // no such transport
    EXPECT_EQ(rats_create(&cfg), nullptr);

    cfg = rats_config_t{};
    cfg.preferred_transport = RATS_TRANSPORT_RELAY;   // a relay is never dialed
    EXPECT_EQ(rats_create(&cfg), nullptr);

    cfg = rats_config_t{};
    cfg.transports          = RATS_TRANSPORT_MASK_UDP;
    cfg.preferred_transport = RATS_TRANSPORT_TCP;     // asks for a transport it turned off
    EXPECT_EQ(rats_create(&cfg), nullptr);

    cfg = rats_config_t{};
    cfg.security = static_cast<rats_security_t>(7);
    EXPECT_EQ(rats_create(&cfg), nullptr);

    cfg = rats_config_t{};
    cfg.congestion_control = static_cast<rats_congestion_t>(7);
    EXPECT_EQ(rats_create(&cfg), nullptr);

    // The default preference follows the transports: TCP-only is not a contradiction.
    cfg = rats_config_t{};
    cfg.transports = RATS_TRANSPORT_MASK_TCP;
    rats_t node = rats_create(&cfg);
    ASSERT_NE(node, nullptr);
    ASSERT_EQ(rats_start(node), RATS_OK);
    EXPECT_EQ(rats_transports(node), RATS_TRANSPORT_MASK_TCP);
    rats_destroy(node);   // destroy stops a running node
}

// data_dir makes the identity survive a restart; protocol reaches the node.
TEST(NodeCApiTest, ConfigDataDirPersistsIdentity) {
    const std::filesystem::path dir =
        std::filesystem::temp_directory_path() / "librats_capi_identity_test";
    std::filesystem::remove_all(dir);

    rats_config_t cfg{};
    const std::string dir_str = dir.string();
    cfg.data_dir = dir_str.c_str();
    cfg.protocol = "capi-test/2.0";

    rats_t a = rats_create(&cfg);
    ASSERT_NE(a, nullptr);
    const std::string first = rats_local_id(a);
    EXPECT_EQ(first.size(), 64u);
    EXPECT_STREQ(rats_protocol(a), "capi-test/2.0");
    rats_destroy(a);

    rats_t b = rats_create(&cfg);
    ASSERT_NE(b, nullptr);
    EXPECT_EQ(std::string(rats_local_id(b)), first) << "identity not persisted via data_dir";
    rats_destroy(b);

    std::filesystem::remove_all(dir);
}

// The UDP knobs are ordinary config fields: two nodes squeezed to Reno, a small
// window and budget, no offload and two reactor threads still talk — slower,
// never wrong.
TEST(NodeCApiTest, UdpTuningIsConfigurable) {
    rats_config_t cfg{};
    cfg.bind_address            = "127.0.0.1";
    cfg.transports              = RATS_TRANSPORT_MASK_UDP;
    cfg.congestion_control      = RATS_CONGESTION_RENO;
    cfg.udp_receive_window      = 64 * 1024;
    cfg.udp_receive_budget      = 256 * 1024;
    cfg.disable_udp_offload     = 1;
    cfg.reactor_threads         = 2;
    cfg.disable_network_monitor = 1;
    rats_t server = rats_create(&cfg);
    rats_t client = rats_create(&cfg);
    ASSERT_NE(server, nullptr);
    ASSERT_NE(client, nullptr);

    BinCtx ctx;
    ASSERT_EQ(rats_on(server, "rw", bin_collect_cb, &ctx), RATS_OK);
    connect_pair(client, server);

    const char* server_id = rats_local_id(server);
    rats_peer_info_t info{};
    ASSERT_EQ(rats_peer_info(client, server_id, &info), RATS_OK);
    EXPECT_EQ(info.transport, RATS_TRANSPORT_UDP);

    std::vector<uint8_t> payload(2 * 1024 * 1024);
    for (size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<uint8_t>(i * 131);
    ASSERT_EQ(rats_send(client, server_id, "rw", payload.data(), payload.size(), 0), RATS_OK);
    ASSERT_TRUE(wait_for([&] { std::lock_guard<std::mutex> l(ctx.mu); return ctx.got.size() == payload.size(); }));
    {
        std::lock_guard<std::mutex> l(ctx.mu);
        EXPECT_EQ(ctx.got, payload);
    }

    rats_destroy(client); rats_destroy(server);
}

// ─── lifecycle and peers ────────────────────────────────────────────────────

TEST(NodeCApiTest, LifecycleRules) {
    rats_t a = make_server();
    rats_t b = make_server();
    EXPECT_EQ(std::strlen(rats_local_id(a)), 64u);
    EXPECT_STRNE(rats_local_id(a), rats_local_id(b));

    // Dialing needs a running node; registering node callbacks needs one that is not.
    EXPECT_EQ(rats_connect(a, "127.0.0.1", 1), RATS_ERR_NOT_STARTED);
    EXPECT_EQ(rats_on_peer_connected(a, nullptr, nullptr), RATS_ERR_INVALID_ARG);

    ASSERT_EQ(rats_start(a), RATS_OK);
    EXPECT_EQ(rats_start(a), RATS_ERR_ALREADY_STARTED);
    EXPECT_NE(rats_listen_port(a), 0);
    EXPECT_EQ(rats_on_peer_connected(a, [](void*, const char*) {}, nullptr), RATS_ERR_ALREADY_STARTED);
    EXPECT_EQ(rats_on(a, "x", [](void*, const char*, const void*, size_t) {}, nullptr),
              RATS_ERR_ALREADY_STARTED);
    EXPECT_EQ(rats_enable_ping(a), RATS_ERR_ALREADY_STARTED);
    EXPECT_EQ(rats_connect(a, nullptr, 1), RATS_ERR_INVALID_ARG);

    rats_stop(a);
    rats_stop(a);   // idempotent
    rats_destroy(a);
    rats_destroy(b);
}

TEST(NodeCApiTest, ConnectSendAndEcho) {
    rats_t server = make_server();
    rats_t client = make_client();

    EchoCtx echo{server};
    CollectCtx client_ctx;
    ASSERT_EQ(rats_on(server, "chat", echo_cb, &echo), RATS_OK);
    ASSERT_EQ(rats_on_peer_connected(client, peer_cb, &client_ctx), RATS_OK);
    ASSERT_EQ(rats_on(client, "chat", collect_cb, &client_ctx), RATS_OK);

    connect_pair(client, server);
    // The peer table flips just before the connected callbacks run.
    ASSERT_TRUE(wait_for([&] { return client_ctx.peers.load() == 1; }));

    const char* msg = "hello capi";
    ASSERT_EQ(rats_send(client, rats_local_id(server), "chat", msg, std::strlen(msg), 0), RATS_OK);
    ASSERT_TRUE(wait_for([&] { std::lock_guard<std::mutex> l(client_ctx.mu); return client_ctx.got == msg; }))
        << "no echo via C API";

    EXPECT_EQ(rats_send(client, rats_local_id(client), "chat", msg, 1, 0), RATS_ERR_NO_SUCH_PEER);
    EXPECT_EQ(rats_send(client, "not-hex", "chat", msg, 1, 0), RATS_ERR_INVALID_ARG);

    rats_destroy(client); rats_destroy(server);
}

// Everything the C API says about one peer: ids, wire, direction, address — and
// that it can be told to go.
TEST(NodeCApiTest, PeerEnumerationInfoAndDisconnect) {
    rats_t server = make_server();
    rats_t client = make_client();

    std::atomic<int> reason{-1};
    ASSERT_EQ(rats_on_peer_disconnected(server, [](void* u, const char*, rats_close_reason_t why) {
        static_cast<std::atomic<int>*>(u)->store(static_cast<int>(why));
    }, &reason), RATS_OK);
    connect_pair(client, server);

    size_t n = 0;
    char** ids = rats_peer_ids(client, &n);
    ASSERT_EQ(n, 1u);
    ASSERT_NE(ids, nullptr);
    EXPECT_STREQ(ids[0], rats_local_id(server));
    rats_strings_free(ids, n);

    rats_peer_info_t info{};
    ASSERT_EQ(rats_peer_info(client, rats_local_id(server), &info), RATS_OK);
    EXPECT_EQ(info.direction, RATS_DIRECTION_OUTBOUND);
    EXPECT_EQ(info.transport, RATS_TRANSPORT_UDP) << "UDP is the default first choice";
    const std::string port = ":" + std::to_string(rats_listen_port(server));
    EXPECT_NE(std::string(info.address).find(port), std::string::npos) << info.address;
    ASSERT_TRUE(wait_for([&] {
        return rats_peer_info(client, rats_local_id(server), &info) == RATS_OK &&
               info.transports == (RATS_TRANSPORT_MASK_TCP | RATS_TRANSPORT_MASK_UDP);
    })) << "the server's identify never said what it accepts";

    ASSERT_EQ(rats_peer_info(server, rats_local_id(client), &info), RATS_OK);
    EXPECT_EQ(info.direction, RATS_DIRECTION_INBOUND);
    EXPECT_EQ(rats_peer_info(server, rats_local_id(server), &info), RATS_ERR_NO_SUCH_PEER);
    EXPECT_EQ(rats_peer_info(server, rats_local_id(client), nullptr), RATS_ERR_INVALID_ARG);

    ASSERT_EQ(rats_disconnect(client, rats_local_id(server)), RATS_OK);
    ASSERT_TRUE(wait_for([&] { return rats_peer_count(client) == 0 && reason.load() != -1; }));
    EXPECT_NE(reason.load(), static_cast<int>(RATS_CLOSE_SLOW_CONSUMER));
    EXPECT_STRNE(rats_close_reason_str(static_cast<rats_close_reason_t>(reason.load())),
                 "RATS_CLOSE_UNKNOWN");
    EXPECT_EQ(rats_disconnect(client, rats_local_id(server)), RATS_ERR_NO_SUCH_PEER);
    EXPECT_EQ(rats_peer_ids(client, &n), nullptr);
    EXPECT_EQ(n, 0u);

    rats_destroy(client); rats_destroy(server);
}

// A dial nothing answers reports its address once every transport has given up.
TEST(NodeCApiTest, DialFailedNamesTheAddress) {
    rats_t closed = make_server();
    ASSERT_EQ(rats_start(closed), RATS_OK);
    const uint16_t port = rats_listen_port(closed);
    rats_destroy(closed);   // nothing listens on the port any more

    rats_t client = make_client();
    struct Ctx { std::mutex mu; std::string address; } ctx;
    ASSERT_EQ(rats_on_dial_failed(client, [](void* u, const char* address) {
        auto* c = static_cast<Ctx*>(u);
        std::lock_guard<std::mutex> l(c->mu);
        c->address = address;
    }, &ctx), RATS_OK);
    ASSERT_EQ(rats_start(client), RATS_OK);
    ASSERT_EQ(rats_connect(client, "127.0.0.1", port), RATS_OK);
    ASSERT_TRUE(wait_for([&] { std::lock_guard<std::mutex> l(ctx.mu); return !ctx.address.empty(); }, 15s));
    {
        std::lock_guard<std::mutex> l(ctx.mu);
        EXPECT_EQ(ctx.address, "127.0.0.1:" + std::to_string(port));
    }
    rats_destroy(client);
}

TEST(NodeCApiTest, MaxPeersCapsInbound) {
    rats_t server = make_server();
    rats_t a = make_client();
    rats_t b = make_client();

    rats_set_max_peers(server, 1);
    EXPECT_EQ(rats_max_peers(server), 1u);

    ASSERT_EQ(rats_start(server), RATS_OK);
    ASSERT_EQ(rats_start(a), RATS_OK);
    ASSERT_EQ(rats_start(b), RATS_OK);

    const uint16_t port = rats_listen_port(server);
    rats_connect(a, "127.0.0.1", port);
    ASSERT_TRUE(wait_for([&] { return rats_peer_count(server) == 1; }));

    rats_connect(b, "127.0.0.1", port);   // refused: the server is at its cap
    std::this_thread::sleep_for(700ms);
    EXPECT_EQ(rats_peer_count(server), 1u);

    rats_destroy(a); rats_destroy(b); rats_destroy(server);
}

// ─── messaging ──────────────────────────────────────────────────────────────

// The payload is length-framed, not NUL-terminated.
TEST(NodeCApiTest, BinaryPayloadWithNuls) {
    rats_t server = make_server();
    rats_t client = make_client();
    BinCtx ctx;
    ASSERT_EQ(rats_on(server, "bin", bin_collect_cb, &ctx), RATS_OK);
    connect_pair(client, server);

    const uint8_t payload[] = {0x00, 0x01, 0xFF, 0x00, 0x42};
    ASSERT_EQ(rats_send(client, rats_local_id(server), "bin", payload, sizeof(payload), 0), RATS_OK);
    ASSERT_TRUE(wait_for([&] { std::lock_guard<std::mutex> l(ctx.mu); return ctx.got.size() == sizeof(payload); }));
    {
        std::lock_guard<std::mutex> l(ctx.mu);
        EXPECT_EQ(std::memcmp(ctx.got.data(), payload, sizeof(payload)), 0);
    }
    rats_destroy(client); rats_destroy(server);
}

// Backpressure is the one signal an application has before a peer is dropped for
// sending too fast; every binding gets it from here.
TEST(NodeCApiTest, PeerWritableAndTheWritableCallback) {
    rats_config_t cfg{};
    cfg.dial_only        = 1;
    cfg.send_queue_limit = 256 * 1024;   // ⇒ 64 KiB before "no room"
    rats_t server = make_server();
    rats_t client = rats_create(&cfg);

    struct Ctx { std::atomic<int> openings{0}; std::atomic<int> lost{0}; } ctx;
    rats_on_peer_writable(client, [](void* u, const char*) {
        static_cast<Ctx*>(u)->openings.fetch_add(1);
    }, &ctx);
    rats_on_peer_disconnected(client, [](void* u, const char*, rats_close_reason_t) {
        static_cast<Ctx*>(u)->lost.fetch_add(1);
    }, &ctx);
    connect_pair(client, server);

    const char* server_id = rats_local_id(server);
    EXPECT_EQ(rats_peer_writable(client, server_id), 1) << "an idle peer reported no room";
    EXPECT_EQ(rats_peer_writable(client, "not-a-peer-id"), 0);

    const std::vector<uint8_t> chunk(32 * 1024, 'c');
    bool told_to_stop = false;
    int  openings_before = 0;
    for (int i = 0; i < 64 && !told_to_stop; ++i) {
        ASSERT_EQ(rats_send(client, server_id, "bulk", chunk.data(), chunk.size(), 0), RATS_OK);
        openings_before = ctx.openings.load();
        told_to_stop = rats_peer_writable(client, server_id) == 0;
    }
    EXPECT_TRUE(told_to_stop) << "the queue never reported filling up";

    // Only an opening after the stop counts: on a fast link the reactor can drain
    // the queue below the mark and back over it while the loop is still filling,
    // which fires the callback for an opening the next send has already closed.
    // And one opening is not yet the last: sends handed over before the stop may
    // still be reaching the reactor, refilling the queue once more after it fired.
    ASSERT_TRUE(wait_for([&] {
        return ctx.openings.load() > openings_before && rats_peer_writable(client, server_id) == 1;
    }, 30s)) << "the queue filled and nothing ever said it had drained";
    EXPECT_EQ(ctx.lost.load(), 0) << "a sender that heeded the answer lost its peer anyway";

    rats_destroy(client); rats_destroy(server);
}

// Path samples reach an application both ways: the callback that turns sampling
// on, and the getter that answers from any thread.
TEST(NodeCApiTest, PathStatsReachAnApplication) {
    rats_t server = make_server();
    rats_t client = make_client();

    std::atomic<int> samples{0};
    ASSERT_EQ(rats_on_peer_path(client, [](void* u, const char* id, const rats_path_stats_t* st) {
        if (id && st && st->srtt_us > 0) static_cast<std::atomic<int>*>(u)->fetch_add(1);
    }, &samples), RATS_OK);
    EXPECT_EQ(rats_on_peer_path(client, nullptr, nullptr), RATS_ERR_INVALID_ARG);
    connect_pair(client, server);

    const char* server_id = rats_local_id(server);
    const std::vector<uint8_t> chunk(32 * 1024, 'p');
    for (int i = 0; i < 16; ++i) rats_send(client, server_id, "bulk", chunk.data(), chunk.size(), 0);

    ASSERT_TRUE(wait_for([&] { return samples.load() >= 2; })) << "no samples reached the callback";
    rats_path_stats_t st{};
    ASSERT_EQ(rats_path_stats(client, server_id, &st), RATS_OK);
    EXPECT_GT(st.srtt_us, 0u);
    EXPECT_GT(st.bandwidth_bps, 0u);
    EXPECT_EQ(rats_path_stats(client, "not-a-peer-id", &st), RATS_ERR_INVALID_ARG);
    EXPECT_EQ(rats_path_stats(client, server_id, nullptr), RATS_ERR_INVALID_ARG);
    EXPECT_EQ(rats_path_stats(server, rats_local_id(client), &st), RATS_ERR_NO_SUCH_PEER)
        << "the server never asked for samples";

    rats_destroy(client); rats_destroy(server);
}

// A lifetime makes a message live: it arrives at the same callback, the path stats
// count it, and a payload past what a live message may carry is refused.
TEST(NodeCApiTest, ALiveMessageArrivesAtTheChannelCallback) {
    rats_config_t cfg{};
    cfg.dial_only      = 1;
    cfg.path_sample_ms = 20;
    rats_t server = make_server();
    rats_t client = rats_create(&cfg);
    BinCtx ctx;
    ASSERT_EQ(rats_on(server, "video", bin_collect_cb, &ctx), RATS_OK);
    connect_pair(client, server);

    const char* server_id = rats_local_id(server);
    const std::vector<uint8_t> frame(20000, 'k');
    ASSERT_EQ(rats_send(client, server_id, "video", frame.data(), frame.size(), 500), RATS_OK);
    ASSERT_TRUE(wait_for([&] { std::lock_guard<std::mutex> l(ctx.mu); return ctx.got == frame; }))
        << "the live message never reached the callback";

    const std::vector<uint8_t> too_big(RATS_LIVE_MAX_PAYLOAD + 1, 'x');
    EXPECT_EQ(rats_send(client, server_id, "video", too_big.data(), too_big.size(), 500), RATS_ERR_INVALID_ARG);
    EXPECT_EQ(rats_broadcast(client, "video", too_big.data(), too_big.size(), 500), RATS_ERR_INVALID_ARG);

    rats_path_stats_t st{};
    EXPECT_TRUE(wait_for([&] {
        return rats_path_stats(client, server_id, &st) == RATS_OK && st.live_sent == 1;
    })) << "the live message was not counted";
    EXPECT_EQ(st.live_expired, 0u);

    rats_destroy(client); rats_destroy(server);
}

// ─── subsystems ─────────────────────────────────────────────────────────────

TEST(NodeCApiTest, PubSubAndJsonMessaging) {
    rats_t server = make_server();
    rats_t client = make_client();

    EXPECT_EQ(rats_publish(client, "news", "x", 1), RATS_ERR_NOT_ENABLED);
    TopicCtx topic_ctx, client_topic_ctx;
    JsonCtx json_ctx, server_json_ctx;
    for (rats_t n : {server, client}) {
        ASSERT_EQ(rats_enable_pubsub(n), RATS_OK);
        ASSERT_EQ(rats_enable_json(n), RATS_OK);
    }
    ASSERT_EQ(rats_subscribe(server, "news", topic_cb, &topic_ctx), RATS_OK);
    ASSERT_EQ(rats_subscribe(client, "news", topic_cb, &client_topic_ctx), RATS_OK);
    ASSERT_EQ(rats_on_json(client, "greet", json_cb, &json_ctx), RATS_OK);
    ASSERT_EQ(rats_on_json(server, "greet", json_cb, &server_json_ctx), RATS_OK);
    connect_pair(client, server);

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

    const char* client_id = rats_local_id(client);
    EXPECT_EQ(rats_send_json(server, client_id, "greet", "{not json"), RATS_ERR_INVALID_ARG);
    ASSERT_TRUE(wait_for([&] {
        rats_send_json(server, client_id, "greet", "{\"text\":\"hi\"}");
        std::lock_guard<std::mutex> l(json_ctx.mu);
        return json_ctx.json.find("\"text\"") != std::string::npos;
    })) << "JSON message not delivered";

    rats_destroy(client); rats_destroy(server);
}

TEST(NodeCApiTest, OnceJsonFiresOnce) {
    rats_t server = make_server();
    rats_t client = make_client();

    std::atomic<int> hits{0};
    ASSERT_EQ(rats_enable_json(server), RATS_OK);
    ASSERT_EQ(rats_enable_json(client), RATS_OK);
    ASSERT_EQ(rats_once_json(client, "ping", [](void* u, const char*, const char*) {
        static_cast<std::atomic<int>*>(u)->fetch_add(1);
    }, &hits), RATS_OK);
    connect_pair(client, server);

    for (int i = 0; i < 3; ++i) rats_send_json(server, rats_local_id(client), "ping", "{}");
    ASSERT_TRUE(wait_for([&] { return hits.load() >= 1; }));
    std::this_thread::sleep_for(300ms);
    EXPECT_EQ(hits.load(), 1) << "once handler fired more than once";

    rats_destroy(client); rats_destroy(server);
}

TEST(NodeCApiTest, BroadcastRawAndJson) {
    rats_t server = make_server();
    rats_t client = make_client();

    CollectCtx raw_ctx;
    JsonCtx json_ctx;
    ASSERT_EQ(rats_enable_json(client), RATS_OK);
    ASSERT_EQ(rats_enable_json(server), RATS_OK);
    ASSERT_EQ(rats_on(client, "raw", collect_cb, &raw_ctx), RATS_OK);
    ASSERT_EQ(rats_on_json(client, "ev", json_cb, &json_ctx), RATS_OK);
    connect_pair(client, server);

    const char* raw = "via-broadcast";
    ASSERT_TRUE(wait_for([&] {
        rats_broadcast(server, "raw", raw, std::strlen(raw), 0);
        std::lock_guard<std::mutex> l(raw_ctx.mu);
        return raw_ctx.got == raw;
    })) << "raw broadcast not delivered";

    ASSERT_TRUE(wait_for([&] {
        rats_broadcast_json(server, "ev", "{\"k\":99}");
        std::lock_guard<std::mutex> l(json_ctx.mu);
        return json_ctx.json.find("\"k\"") != std::string::npos;
    })) << "JSON broadcast not delivered";

    rats_destroy(client); rats_destroy(server);
}

// An added target is dialed by the subsystem, without a rats_connect.
TEST(NodeCApiTest, ReconnectDialsTarget) {
    rats_t server = make_server();
    rats_t client = make_client();

    EXPECT_EQ(rats_add_reconnect(client, "127.0.0.1", 1234), RATS_ERR_NOT_ENABLED);
    ASSERT_EQ(rats_enable_reconnect(client), RATS_OK);
    EXPECT_EQ(rats_enable_reconnect(client), RATS_OK);   // idempotent

    ASSERT_EQ(rats_start(server), RATS_OK);
    ASSERT_EQ(rats_start(client), RATS_OK);
    EXPECT_EQ(rats_enable_reconnect(server), RATS_ERR_ALREADY_STARTED);

    ASSERT_EQ(rats_add_reconnect(client, "127.0.0.1", rats_listen_port(server)), RATS_OK);
    ASSERT_TRUE(wait_for([&] { return rats_peer_count(client) == 1; }, 15s))
        << "reconnect did not dial the added target";
    EXPECT_EQ(rats_remove_reconnect(client, "127.0.0.1", rats_listen_port(server)), RATS_OK);

    rats_destroy(client); rats_destroy(server);
}

// Bad inputs return 0 or an error, never crash; an unknown transfer is NOT_FOUND.
TEST(NodeCApiTest, FileTransferNegativePaths) {
    rats_t node = make_server();
    EXPECT_EQ(rats_cancel_file(node, rats_local_id(node), 1), RATS_ERR_NOT_ENABLED);
    ASSERT_EQ(rats_enable_file_transfer(node, "."), RATS_OK);
    ASSERT_EQ(rats_on_file_progress(node, [](void*, const rats_file_progress_t*) {}, nullptr), RATS_OK);
    ASSERT_EQ(rats_start(node), RATS_OK);
    EXPECT_EQ(rats_on_file_offer(node, [](void*, const char*, uint64_t, const char*, uint64_t, int) {},
                                 nullptr), RATS_ERR_ALREADY_STARTED);

    const char* self = rats_local_id(node);   // valid hex, but no transfer exists for it
    uint64_t tid = 7;
    EXPECT_EQ(rats_send_file(node, "not-a-valid-hex-id", "whatever.bin", &tid), RATS_ERR_INVALID_ARG);
    EXPECT_EQ(tid, 0u);
    EXPECT_EQ(rats_send_file(node, self, "whatever.bin", &tid), RATS_ERR_NO_SUCH_PEER);
    EXPECT_EQ(rats_send_directory(node, self, "no_such_dir_98765", nullptr), RATS_ERR_NO_SUCH_PEER);
    EXPECT_EQ(rats_cancel_file(node, self, 999999u), RATS_ERR_NOT_FOUND);
    EXPECT_EQ(rats_pause_file(node, self, 999999u), RATS_ERR_NOT_FOUND);
    EXPECT_EQ(rats_resume_file(node, self, 999999u), RATS_ERR_NOT_FOUND);
    EXPECT_EQ(rats_accept_file(node, self, 999999u, "dest.bin"), RATS_OK);   // nothing to accept: no-op
    EXPECT_EQ(rats_reject_file(node, self, 999999u), RATS_OK);

    rats_destroy(node);
}

// A real offer: a path that cannot be read is NOT_FOUND, a readable one gets an id
// and the receiver hears of it.
TEST(NodeCApiTest, FileOfferReachesThePeer) {
    rats_t server = make_server();
    rats_t client = make_client();
    std::atomic<uint64_t> offered{0};
    for (rats_t n : {server, client}) ASSERT_EQ(rats_enable_file_transfer(n, "."), RATS_OK);
    ASSERT_EQ(rats_on_file_offer(server, [](void* u, const char*, uint64_t id, const char*, uint64_t, int) {
        static_cast<std::atomic<uint64_t>*>(u)->store(id);
    }, &offered), RATS_OK);
    connect_pair(client, server);

    const auto file = std::filesystem::temp_directory_path() / "librats_capi_offer.bin";
    { FILE* f = std::fopen(file.string().c_str(), "wb"); ASSERT_NE(f, nullptr); std::fputs("x", f); std::fclose(f); }

    const char* server_id = rats_local_id(server);
    uint64_t tid = 0;
    EXPECT_EQ(rats_send_file(client, server_id, "no_such_file_98765.bin", &tid), RATS_ERR_NOT_FOUND);
    ASSERT_EQ(rats_send_file(client, server_id, file.string().c_str(), &tid), RATS_OK);
    EXPECT_NE(tid, 0u);
    EXPECT_TRUE(wait_for([&] { return offered.load() == tid; })) << "the offer never arrived";
    EXPECT_EQ(rats_cancel_file(client, server_id, tid), RATS_OK);

    rats_destroy(client); rats_destroy(server);
    std::filesystem::remove(file);
}

// One contact is enough: b learns of a from the hub it shares with it, and dials.
TEST(NodeCApiTest, PeerExchangeIntroducesPeers) {
    rats_t hub = make_server();
    rats_t a   = make_server();
    rats_t b   = make_server();
    for (rats_t n : {hub, a, b}) {
        ASSERT_EQ(rats_enable_peer_exchange(n), RATS_OK);
        ASSERT_EQ(rats_start(n), RATS_OK);
    }
    rats_connect(a, "127.0.0.1", rats_listen_port(hub));
    ASSERT_TRUE(wait_for([&] { return rats_peer_count(hub) == 1; }));
    rats_connect(b, "127.0.0.1", rats_listen_port(hub));

    EXPECT_TRUE(wait_for([&] { return rats_peer_count(a) == 2 && rats_peer_count(b) == 2; }, 15s))
        << "peer exchange never introduced a and b";

    rats_destroy(a); rats_destroy(b); rats_destroy(hub);
}

// Hole punching is reachable end to end from the C ABI: enable, read the NAT
// classification, punch.
TEST(NodeCApiTest, HolePunchIsReachableFromTheCApi) {
    rats_t hub = make_server();
    rats_t a   = make_server();
    rats_t b   = make_server();

    EXPECT_EQ(rats_punch_peer(a, "00"), RATS_ERR_INVALID_ARG);
    EXPECT_EQ(rats_punch_peer(a, rats_local_id(b)), RATS_ERR_NOT_ENABLED);

    ASSERT_EQ(rats_enable_hole_punch(hub, /*serve_rendezvous=*/1), RATS_OK);
    ASSERT_EQ(rats_enable_hole_punch(a, 0), RATS_OK);
    ASSERT_EQ(rats_enable_hole_punch(b, 0), RATS_OK);
    EXPECT_EQ(rats_enable_hole_punch(a, 0), RATS_OK);   // idempotent

    for (rats_t n : {hub, a, b}) ASSERT_EQ(rats_start(n), RATS_OK);
    EXPECT_EQ(rats_enable_hole_punch(a, 0), RATS_ERR_ALREADY_STARTED);

    rats_connect(a, "127.0.0.1", rats_listen_port(hub));
    rats_connect(b, "127.0.0.1", rats_listen_port(hub));
    ASSERT_TRUE(wait_for([&] { return rats_peer_count(hub) == 2; }));

    // No NAT on loopback; either way an external endpoint was learned, which is
    // what a punch needs.
    ASSERT_TRUE(wait_for([&] { return rats_nat_mapping(a) == RATS_NAT_OPEN; }))
        << "the node never classified its own path";
    size_t n = 0;
    char** seen = rats_observed_addresses(a, &n);
    EXPECT_GE(n, 1u) << "no peer reported where it sees us";
    rats_strings_free(seen, n);

    const char* b_id = rats_local_id(b);
    EXPECT_EQ(rats_punch_peer(a, b_id), RATS_OK);
    EXPECT_TRUE(wait_for([&] { return rats_peer_count(a) == 2 && rats_peer_count(b) == 2; }, 15s))
        << "the punch never produced a direct link";
    EXPECT_EQ(rats_punch_peer(a, b_id), RATS_ERR_DECLINED) << "already connected";

    rats_destroy(a); rats_destroy(b); rats_destroy(hub);
}

// Relaying likewise — and the one thing that tells a relayed peer apart is
// reported through rats_peer_info.
TEST(NodeCApiTest, RelayingIsReachableFromTheCApi) {
    rats_t hub = make_server();
    rats_t a   = make_server();
    rats_t b   = make_server();

    EXPECT_EQ(rats_connect_via_relay(a, rats_local_id(b)), RATS_ERR_NOT_ENABLED);

    ASSERT_EQ(rats_enable_relay(hub, /*serve=*/1), RATS_OK);
    ASSERT_EQ(rats_enable_relay(a, 0), RATS_OK);
    ASSERT_EQ(rats_enable_relay(b, 0), RATS_OK);
    EXPECT_EQ(rats_enable_relay(a, 0), RATS_OK);   // idempotent

    for (rats_t n : {hub, a, b}) ASSERT_EQ(rats_start(n), RATS_OK);
    EXPECT_EQ(rats_enable_relay(a, 0), RATS_ERR_ALREADY_STARTED);

    rats_connect(a, "127.0.0.1", rats_listen_port(hub));
    rats_connect(b, "127.0.0.1", rats_listen_port(hub));
    ASSERT_TRUE(wait_for([&] { return rats_peer_count(hub) == 2; }));

    const char* b_id = rats_local_id(b);
    EXPECT_EQ(rats_connect_via_relay(a, "not-a-peer-id"), RATS_ERR_INVALID_ARG);
    EXPECT_EQ(rats_connect_via_relay(a, b_id), RATS_OK);
    ASSERT_TRUE(wait_for([&] { return rats_peer_count(a) == 2 && rats_peer_count(b) == 2; }, 20s))
        << "the relay never produced a connection";

    rats_peer_info_t info{};
    ASSERT_EQ(rats_peer_info(a, b_id, &info), RATS_OK);
    EXPECT_EQ(info.transport, RATS_TRANSPORT_RELAY);
    EXPECT_EQ(rats_connect_via_relay(a, b_id), RATS_ERR_DECLINED) << "already connected";

    rats_destroy(a); rats_destroy(b); rats_destroy(hub);
}

#ifndef RATS_SEARCH_FEATURES
TEST(NodeCApiTest, BitTorrentIsUnavailableWithoutTheFeature) {
    rats_t node = make_server();
    EXPECT_EQ(rats_enable_bittorrent(node, nullptr), RATS_ERR_NOT_ENABLED);
    EXPECT_EQ(rats_bt_add_magnet(node, "magnet:?xt=urn:btih:00", nullptr), RATS_ERR_NOT_ENABLED);
    rats_destroy(node);
}
#endif

// ─── process-wide ───────────────────────────────────────────────────────────

TEST(NodeCApiTest, NamesAndVersion) {
    EXPECT_STREQ(rats_error_str(RATS_ERR_DECLINED), "RATS_ERR_DECLINED");
    EXPECT_STREQ(rats_error_str(static_cast<rats_error_t>(99)), "RATS_ERR_UNKNOWN");
    EXPECT_STREQ(rats_close_reason_str(RATS_CLOSE_DIAL_SUPERSEDED), "RATS_CLOSE_DIAL_SUPERSEDED");

    int major = -1, minor = -1, patch = -1;
    rats_version(&major, &minor, &patch, nullptr);
    EXPECT_GE(major, 0);
    EXPECT_EQ(rats_abi(), (static_cast<uint32_t>(major) << 16) | (static_cast<uint32_t>(minor) << 8) |
                              static_cast<uint32_t>(patch));
    EXPECT_NE(rats_version_string(), nullptr);
    rats_strings_free(nullptr, 0);
}
