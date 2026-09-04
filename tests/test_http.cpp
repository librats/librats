/**
 * @file test_http.cpp
 * @brief Tests for the blocking HTTP client (librats/util/http.h).
 *
 * The case that motivated this file: a device answers our request in full and
 * then simply keeps the connection open, ignoring "Connection: close". Every test
 * server here that "holds" does exactly that — a client that ends a response by
 * waiting for EOF parks forever on it, which is what happened to UPnP discovery
 * against a cast box on the LAN.
 */

#include <gtest/gtest.h>

#include "librats/core/socket.h"
#include "librats/core/wakeup_pipe.h"
#include "librats/util/http.h"

#include <atomic>
#include <chrono>
#include <functional>
#include <string>
#include <thread>

using namespace librats;
using namespace std::chrono_literals;

namespace {

using Clock = std::chrono::steady_clock;

int elapsed_ms(Clock::time_point start) {
    return static_cast<int>(
        std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - start).count());
}

/// Single-shot HTTP server on 127.0.0.1. The handler gets the accepted socket and
/// a stop flag it can spin on to keep the connection open for the whole test.
class FakeHttpServer {
public:
    using Handler = std::function<void(socket_t client, const std::atomic<bool>& stopping)>;

    explicit FakeHttpServer(Handler handler) {
        listener_ = create_tcp_server(0, 4, "127.0.0.1", AddressFamily::IPv4);
        EXPECT_TRUE(is_valid_socket(listener_));
        port_ = get_bound_port(listener_);
        thread_ = std::thread([this, handler = std::move(handler)] {
            socket_t client = accept_client(listener_);
            if (!is_valid_socket(client)) return;
            if (!stopping_.load()) handler(client, stopping_);
            close_socket(client);
        });
    }

    ~FakeHttpServer() {
        stopping_.store(true);
        // Unblock a still-pending accept() with a throwaway connection, so the
        // join below cannot outlive a test that never connected.
        socket_t poke = create_tcp_client("127.0.0.1", port_, 500);
        if (is_valid_socket(poke)) close_socket(poke);
        if (thread_.joinable()) thread_.join();
        close_socket(listener_);
    }

    FakeHttpServer(const FakeHttpServer&) = delete;
    FakeHttpServer& operator=(const FakeHttpServer&) = delete;

    std::uint16_t port() const { return static_cast<std::uint16_t>(port_); }

private:
    socket_t          listener_ = RATS_INVALID_SOCKET;
    int               port_ = 0;
    std::atomic<bool> stopping_{false};
    std::thread       thread_;
};

/// Read the client's request up to the blank line (bounded, so a broken client
/// cannot wedge the server thread either).
void read_request(socket_t client) {
    std::string raw;
    while (raw.find("\r\n\r\n") == std::string::npos) {
        TcpRecvStatus status = TcpRecvStatus::Data;
        auto chunk = receive_tcp_data(client, 2048, 2000, RATS_INVALID_SOCKET, &status);
        if (status != TcpRecvStatus::Data) return;
        raw.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
    }
}

void spin_until_stopped(const std::atomic<bool>& stopping) {
    while (!stopping.load()) std::this_thread::sleep_for(10ms);
}

/// Answer with @p response, then hold the connection open — the keep-alive server
/// that never sends EOF.
FakeHttpServer::Handler responder_holding_open(std::string response) {
    return [response = std::move(response)](socket_t client, const std::atomic<bool>& stopping) {
        read_request(client);
        send_tcp_string(client, response);
        spin_until_stopped(stopping);
    };
}

/// Answer with @p response and hang up, the way a well-behaved HTTP/1.0 server does.
FakeHttpServer::Handler responder_closing(std::string response) {
    return [response = std::move(response)](socket_t client, const std::atomic<bool>&) {
        read_request(client);
        send_tcp_string(client, response);
    };
}

/// Accept, read the request, then say nothing at all.
FakeHttpServer::Handler silent_server() {
    return [](socket_t client, const std::atomic<bool>& stopping) {
        read_request(client);
        spin_until_stopped(stopping);
    };
}

http::Options fast_options() {
    http::Options opt;
    opt.connect_timeout_ms = 2000;
    opt.read_timeout_ms = 500;
    opt.total_timeout_ms = 3000;
    return opt;
}

bool get_from(const FakeHttpServer& server, const http::Options& opt, http::Response& out,
              const std::string& path = "/") {
    return http::get("http://127.0.0.1:" + std::to_string(server.port()) + path, opt, out);
}

class HttpTest : public ::testing::Test {
protected:
    void SetUp() override { ASSERT_TRUE(init_socket_library()); }
    void TearDown() override { cleanup_socket_library(); }
};

} // namespace

// ── URL parsing ────────────────────────────────────────────────────────────

TEST_F(HttpTest, ParseUrlBasics) {
    http::Url u;

    ASSERT_TRUE(http::parse_url("http://192.168.1.1:5000/rootDesc.xml", u));
    EXPECT_EQ(u.scheme, "http");
    EXPECT_EQ(u.host, "192.168.1.1");
    EXPECT_EQ(u.port, 5000);
    EXPECT_EQ(u.path, "/rootDesc.xml");

    ASSERT_TRUE(http::parse_url("http://tracker.example.com/announce?x=1", u));
    EXPECT_EQ(u.port, 80);
    EXPECT_EQ(u.path, "/announce?x=1");

    ASSERT_TRUE(http::parse_url("HTTP://10.0.0.1", u));
    EXPECT_EQ(u.scheme, "http");
    EXPECT_EQ(u.path, "/");

    // https parses (the scheme is reported, not judged) but has no default of ours.
    ASSERT_TRUE(http::parse_url("https://example.com/x", u));
    EXPECT_EQ(u.port, 443);

    // Bracketed IPv6 literal, with and without a port.
    ASSERT_TRUE(http::parse_url("http://[fe80::1]:8080/desc", u));
    EXPECT_EQ(u.host, "fe80::1");
    EXPECT_EQ(u.port, 8080);
    ASSERT_TRUE(http::parse_url("http://[::1]/", u));
    EXPECT_EQ(u.host, "::1");
    EXPECT_EQ(u.port, 80);
}

TEST_F(HttpTest, ParseUrlRejectsMalformed) {
    http::Url u;
    EXPECT_FALSE(http::parse_url("not a url", u));
    EXPECT_FALSE(http::parse_url("://host/x", u));
    EXPECT_FALSE(http::parse_url("http:///just-a-path", u));
    EXPECT_FALSE(http::parse_url("http://host:notaport/x", u));
    EXPECT_FALSE(http::parse_url("http://host:99999/x", u));
    EXPECT_FALSE(http::parse_url("http://[fe80::1/x", u));
}

TEST_F(HttpTest, GetRefusesHttpsBecauseThereIsNoTls) {
    http::Response resp;
    EXPECT_FALSE(http::get("https://example.com/", fast_options(), resp));
}

// ── The regression: a server that answers and never closes ─────────────────

TEST_F(HttpTest, KeepAliveContentLengthDoesNotHang) {
    const std::string body = "<root><device>cast box</device></root>";
    FakeHttpServer server(responder_holding_open(
        "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: " +
        std::to_string(body.size()) + "\r\n\r\n" + body));

    // Deliberately generous limits: the response must end because the message says
    // so, not because a timeout rescued us.
    http::Options opt = fast_options();
    opt.read_timeout_ms = 30000;
    opt.total_timeout_ms = 30000;

    const auto start = Clock::now();
    http::Response resp;
    ASSERT_TRUE(get_from(server, opt, resp));
    EXPECT_EQ(resp.status, 200);
    EXPECT_EQ(resp.body, body);
    EXPECT_FALSE(resp.truncated);
    EXPECT_LT(elapsed_ms(start), 2000) << "the request waited for an EOF that never comes";
}

TEST_F(HttpTest, BodilessStatusDoesNotWaitForClose) {
    FakeHttpServer server(responder_holding_open("HTTP/1.1 204 No Content\r\n\r\n"));

    http::Options opt = fast_options();
    opt.read_timeout_ms = 30000;
    opt.total_timeout_ms = 30000;

    const auto start = Clock::now();
    http::Response resp;
    ASSERT_TRUE(get_from(server, opt, resp));
    EXPECT_EQ(resp.status, 204);
    EXPECT_TRUE(resp.body.empty());
    EXPECT_LT(elapsed_ms(start), 2000);
}

TEST_F(HttpTest, ChunkedBodyDoesNotWaitForClose) {
    FakeHttpServer server(responder_holding_open(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        "5\r\nhello\r\n"
        "6;ext=1\r\n world\r\n"
        "0\r\n\r\n"));

    http::Options opt = fast_options();
    opt.read_timeout_ms = 30000;
    opt.total_timeout_ms = 30000;

    const auto start = Clock::now();
    http::Response resp;
    ASSERT_TRUE(get_from(server, opt, resp));
    EXPECT_EQ(resp.status, 200);
    EXPECT_EQ(resp.body, "hello world");
    EXPECT_FALSE(resp.truncated);
    EXPECT_LT(elapsed_ms(start), 2000);
}

// ── Length-less bodies still work the old way ──────────────────────────────

TEST_F(HttpTest, ReadsToEofWhenNoLengthIsGiven) {
    FakeHttpServer server(responder_closing("HTTP/1.1 200 OK\r\n\r\nd8:intervali1800ee"));

    http::Response resp;
    ASSERT_TRUE(get_from(server, fast_options(), resp));
    EXPECT_EQ(resp.status, 200);
    EXPECT_EQ(resp.body, "d8:intervali1800ee");
    EXPECT_FALSE(resp.truncated);
}

TEST_F(HttpTest, LengthlessBodyEndsAtTheIdleTimeout) {
    // No length and no close: all we can do is keep what arrived and flag it.
    FakeHttpServer server(responder_holding_open("HTTP/1.1 200 OK\r\n\r\npartial"));

    const auto start = Clock::now();
    http::Response resp;
    ASSERT_TRUE(get_from(server, fast_options(), resp));
    EXPECT_EQ(resp.body, "partial");
    EXPECT_TRUE(resp.truncated);
    EXPECT_LT(elapsed_ms(start), 3000);
}

TEST_F(HttpTest, ReportsNonOkStatus) {
    FakeHttpServer server(responder_closing(
        "HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\n\r\nnah"));

    http::Response resp;
    ASSERT_TRUE(get_from(server, fast_options(), resp));
    EXPECT_EQ(resp.status, 404);
    EXPECT_EQ(resp.body, "nah");
}

// ── Bounds: a peer cannot stall us or grow us without limit ────────────────

TEST_F(HttpTest, SilentServerTimesOutInsteadOfBlocking) {
    FakeHttpServer server(silent_server());

    const auto start = Clock::now();
    http::Response resp;
    EXPECT_FALSE(get_from(server, fast_options(), resp));
    const int took = elapsed_ms(start);
    EXPECT_GE(took, 400) << "returned before the read timeout could have expired";
    EXPECT_LT(took, 3000);
}

TEST_F(HttpTest, TotalBudgetCapsADribblingServer) {
    // One byte per 100 ms, forever: every single read succeeds, so only the total
    // budget can end this.
    FakeHttpServer server([](socket_t client, const std::atomic<bool>& stopping) {
        read_request(client);
        send_tcp_string(client, "HTTP/1.1 200 OK\r\n");
        while (!stopping.load()) {
            if (send_tcp_string(client, "X") < 0) return;
            std::this_thread::sleep_for(100ms);
        }
    });

    http::Options opt = fast_options();
    opt.read_timeout_ms = 5000;   // never trips: bytes keep arriving
    opt.total_timeout_ms = 1000;

    const auto start = Clock::now();
    http::Response resp;
    EXPECT_FALSE(get_from(server, opt, resp)) << "headers never completed";
    EXPECT_LT(elapsed_ms(start), 3000);
}

TEST_F(HttpTest, BodyCapTruncatesInsteadOfGrowing) {
    const std::string body(4096, 'A');
    FakeHttpServer server(responder_closing(
        "HTTP/1.1 200 OK\r\nContent-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body));

    http::Options opt = fast_options();
    opt.max_body_bytes = 100;

    http::Response resp;
    ASSERT_TRUE(get_from(server, opt, resp));
    EXPECT_EQ(resp.body.size(), 100u);
    EXPECT_TRUE(resp.truncated);
}

TEST_F(HttpTest, CancelPredicateAbortsTheWait) {
    FakeHttpServer server(silent_server());

    http::Options opt = fast_options();
    opt.read_timeout_ms = 20000;
    opt.total_timeout_ms = 20000;
    const auto start = Clock::now();
    opt.cancelled = [start] { return elapsed_ms(start) > 200; };

    http::Response resp;
    EXPECT_FALSE(get_from(server, opt, resp));
    EXPECT_LT(elapsed_ms(start), 3000) << "cancellation was not polled during the read";
}

TEST_F(HttpTest, InterruptFdAbortsTheWait) {
    FakeHttpServer server(silent_server());

    WakeupPipe wakeup;
    if (!is_valid_socket(wakeup.fd())) GTEST_SKIP() << "wakeup pipe unavailable on this host";

    http::Options opt = fast_options();
    opt.read_timeout_ms = 20000;
    opt.total_timeout_ms = 20000;
    opt.interrupt_fd = wakeup.fd();

    std::thread waker([&wakeup] {
        std::this_thread::sleep_for(200ms);
        wakeup.signal();
    });

    const auto start = Clock::now();
    http::Response resp;
    EXPECT_FALSE(get_from(server, opt, resp));
    EXPECT_LT(elapsed_ms(start), 3000) << "a signalled wakeup pipe did not break the read";
    waker.join();
}

TEST_F(HttpTest, GarbageResponseIsRejected) {
    FakeHttpServer server(responder_closing("this is not http at all\r\n\r\nbody"));

    http::Response resp;
    EXPECT_FALSE(get_from(server, fast_options(), resp));
}
