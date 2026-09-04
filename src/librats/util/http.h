#pragma once

/**
 * @file http.h
 * @brief Minimal blocking HTTP/1.1 client used by UPnP discovery and BitTorrent
 *        tracker announces.
 *
 * Deliberately tiny: one request per connection, no TLS, no redirects, no
 * connection reuse. What it does provide is the part a hand-rolled "recv until
 * the socket closes" loop always gets wrong — knowing when the response has
 * *ended*, and never waiting for that forever:
 *
 *  - The body length comes from the message (Content-Length or chunked framing),
 *    not from the peer closing the connection. A server that ignores our
 *    `Connection: close` and keeps the socket open — routine for embedded HTTP
 *    stacks on smart TVs, printers and cast devices — is answered and released
 *    immediately instead of parking the calling thread forever.
 *  - Every wait is bounded three ways: a connect timeout, an idle timeout between
 *    reads, and a budget for the whole response. A peer that dribbles one byte per
 *    idle period cannot outlast the budget.
 *  - The wait can be aborted early, either by a socket that becomes readable on
 *    shutdown (@ref Options::interrupt_fd, e.g. a WakeupPipe) or by a polled
 *    predicate (@ref Options::cancelled).
 *  - The body is capped, so a hostile or broken server cannot grow the process
 *    until it dies.
 *
 * Calls block, so they belong on a worker thread — never on a reactor thread.
 */

#include "librats/core/socket.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

namespace librats {
namespace http {

/// Pieces of an absolute URL: "scheme://host[:port][/path]".
struct Url {
    std::string   scheme;        ///< lowercased, without "://" (e.g. "http")
    std::string   host;          ///< hostname or IP literal, IPv6 without brackets
    std::uint16_t port = 0;      ///< explicit port, else the scheme default (80/443)
    std::string   path = "/";    ///< path + query, always starting with '/'
};

/// Parse an absolute URL. Accepts a bracketed IPv6 host ("http://[::1]:8080/x").
/// Returns false when the scheme or host is missing, or the port is not a number.
/// The scheme is reported, never judged: callers decide what they can speak.
bool parse_url(const std::string& url, Url& out);

/// One request. `extra_headers` lines must each end with CRLF; Host, Connection
/// and (when a body is present) Content-Length are added by the client.
struct Request {
    std::string   host;
    std::uint16_t port = 80;
    std::string   method = "GET";
    std::string   path = "/";
    std::string   extra_headers;
    std::string   body;
};

/// Timeouts, caps and abort hooks. The defaults suit a LAN device.
struct Options {
    /// Time allowed for the TCP connect.
    int connect_timeout_ms = 10000;
    /// Longest silence tolerated between two reads. 0 disables the idle limit,
    /// leaving only @ref total_timeout_ms.
    int read_timeout_ms = 5000;
    /// Budget for receiving the whole response, measured from the moment the
    /// request was sent (so the worst case is connect_timeout_ms + this). 0
    /// disables the budget, leaving only @ref read_timeout_ms.
    int total_timeout_ms = 15000;
    /// Hard cap on the body kept. Past it the read stops and the response is
    /// flagged @ref Response::truncated rather than growing without bound.
    std::size_t max_body_bytes = 256 * 1024;
    /// Socket watched alongside the connection; when it becomes readable the
    /// request is abandoned at once (a WakeupPipe signalled on shutdown).
    socket_t interrupt_fd = RATS_INVALID_SOCKET;
    /// Polled between reads; returning true abandons the request within roughly
    /// one 200 ms slice. Empty predicate never cancels.
    std::function<bool()> cancelled;
};

struct Response {
    int         status = 0;      ///< HTTP status code from the status line
    std::string body;
    /// The body is known to be incomplete: the cap cut it off, or the peer went
    /// quiet / hung up before delivering everything it promised. The status line
    /// and headers were still valid, so the request itself counts as answered.
    bool        truncated = false;
};

/// Perform one request. Returns true when a well-formed status line came back
/// (inspect @ref Response::status for the outcome), false when the exchange
/// failed outright: connect refused, send error, malformed response, or an abort
/// via interrupt_fd / cancelled.
bool request(const Request& req, const Options& opt, Response& out);

/// Convenience GET of an absolute "http://…" URL. Returns false for a URL that
/// cannot be parsed or is not http (there is no TLS here — an https URL is
/// refused rather than spoken in the clear).
bool get(const std::string& url, const Options& opt, Response& out);

} // namespace http
} // namespace librats
