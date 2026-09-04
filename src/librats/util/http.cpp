/**
 * @file http.cpp
 * @brief Minimal blocking HTTP/1.1 client implementation.
 */

#include "librats/util/http.h"
#include "librats/util/logger.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <sstream>

#define LOG_HTTP_DEBUG(message) LOG_DEBUG("http", message)

namespace librats {
namespace http {

namespace {

using Clock = std::chrono::steady_clock;

/// One recv per call; responses we care about are a few KiB.
constexpr std::size_t kReadChunk = 4096;
/// Status line + headers may not exceed this. A peer that streams headers forever
/// is as effective a denial of service as one that streams a body forever.
constexpr std::size_t kMaxHeaderBytes = 32 * 1024;
/// Longest a single wait may run while a cancel predicate is installed, so a
/// cancellation is noticed promptly rather than after the whole timeout.
constexpr int kCancelSliceMs = 200;

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return s;
}

std::string trim(const std::string& s) {
    const std::size_t b = s.find_first_not_of(" \t");
    if (b == std::string::npos) return "";
    const std::size_t e = s.find_last_not_of(" \t");
    return s.substr(b, e - b + 1);
}

/// Why a read stopped short. Only Timeout is recoverable — it means the peer went
/// quiet, which for a length-less body is simply how it ends.
enum class Stop { None, Timeout, Cancelled, Error };

/// Accumulating reader: pulls bytes off the socket into one growing buffer, with
/// every wait bounded by the idle timeout, the total budget and the abort hooks.
class Reader {
public:
    Reader(socket_t sock, const Options& opt)
        : sock_(sock), opt_(opt),
          total_deadline_(opt.total_timeout_ms > 0
                              ? Clock::now() + std::chrono::milliseconds(opt.total_timeout_ms)
                              : Clock::time_point::max()) {}

    enum class Fill { Appended, Eof, Aborted };

    /// Wait for and append at least one byte. Aborted sets @ref stop().
    Fill fill();

    const std::string& buf() const { return buf_; }
    Stop stop() const { return stop_; }

private:
    socket_t          sock_;
    const Options&    opt_;
    Clock::time_point total_deadline_;
    std::string       buf_;
    Stop              stop_ = Stop::None;
};

Reader::Fill Reader::fill() {
    const Clock::time_point idle_deadline =
        opt_.read_timeout_ms > 0 ? Clock::now() + std::chrono::milliseconds(opt_.read_timeout_ms)
                                 : Clock::time_point::max();

    for (;;) {
        if (opt_.cancelled && opt_.cancelled()) { stop_ = Stop::Cancelled; return Fill::Aborted; }

        const Clock::time_point deadline = (std::min)(idle_deadline, total_deadline_);
        int wait;
        if (deadline == Clock::time_point::max()) {
            wait = -1;  // both limits disabled: block until something happens
        } else {
            const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                                  deadline - Clock::now()).count();
            if (left <= 0) { stop_ = Stop::Timeout; return Fill::Aborted; }
            wait = static_cast<int>(std::min<long long>(left, 3600LL * 1000));
        }
        // Slice the wait so a pending cancellation is seen without waiting it out.
        if (opt_.cancelled) wait = (wait < 0) ? kCancelSliceMs : (std::min)(wait, kCancelSliceMs);

        TcpRecvStatus status = TcpRecvStatus::Data;
        const auto chunk = receive_tcp_data(sock_, kReadChunk, wait, opt_.interrupt_fd, &status);
        switch (status) {
            case TcpRecvStatus::Data:
                buf_.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
                return Fill::Appended;
            case TcpRecvStatus::Closed:
                return Fill::Eof;
            case TcpRecvStatus::Interrupted:
                stop_ = Stop::Cancelled;
                return Fill::Aborted;
            case TcpRecvStatus::Error:
                stop_ = Stop::Error;
                return Fill::Aborted;
            case TcpRecvStatus::Timeout:
                break;  // a slice expired — the loop re-checks both deadlines
        }
    }
}

struct Head {
    int       status = 0;
    long long content_length = -1;  ///< -1 when the header is absent
    bool      chunked = false;
};

/// Parse the status line and the headers we act on. Returns false for anything
/// that is not recognisably an HTTP response.
bool parse_head(const std::string& raw, std::size_t header_end, Head& out) {
    std::size_t eol = raw.find("\r\n");
    if (eol == std::string::npos || eol > header_end) return false;

    const std::string status_line = raw.substr(0, eol);
    if (status_line.compare(0, 5, "HTTP/") != 0) return false;
    const std::size_t sp = status_line.find(' ');
    if (sp == std::string::npos) return false;
    out.status = std::atoi(status_line.c_str() + sp + 1);
    if (out.status < 100 || out.status > 599) return false;

    for (std::size_t pos = eol + 2; pos < header_end;) {
        std::size_t line_end = raw.find("\r\n", pos);
        if (line_end == std::string::npos || line_end > header_end) line_end = header_end;
        const std::size_t colon = raw.find(':', pos);
        if (colon != std::string::npos && colon < line_end) {
            const std::string name  = to_lower(trim(raw.substr(pos, colon - pos)));
            const std::string value = trim(raw.substr(colon + 1, line_end - colon - 1));
            if (name == "content-length" && out.content_length < 0) {
                if (!value.empty() && value.find_first_not_of("0123456789") == std::string::npos) {
                    out.content_length = std::strtoll(value.c_str(), nullptr, 10);
                }
            } else if (name == "transfer-encoding") {
                if (to_lower(value).find("chunked") != std::string::npos) out.chunked = true;
            }
        }
        pos = line_end + 2;
    }
    return true;
}

/// Parse a chunk-size line: hex digits, optionally followed by ";extension".
bool parse_chunk_size(const std::string& line, unsigned long long& out) {
    std::string text = trim(line.substr(0, line.find(';')));
    if (text.empty() || text.size() > 16) return false;
    for (char c : text) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
    }
    out = std::strtoull(text.c_str(), nullptr, 16);
    return true;
}

/// Body of known length: stop at exactly that many bytes. This is what keeps a
/// keep-alive server (one that ignores "Connection: close") from parking us.
bool read_counted(Reader& r, std::size_t start, unsigned long long length,
                  const Options& opt, Response& out) {
    const std::size_t want =
        static_cast<std::size_t>(std::min<unsigned long long>(length, opt.max_body_bytes));
    if (length > want) out.truncated = true;

    while (r.buf().size() - start < want) {
        const Reader::Fill f = r.fill();
        if (f == Reader::Fill::Appended) continue;
        // Short of what was promised. The status line was valid, so report the
        // partial body rather than throwing the whole exchange away — unless the
        // caller asked us to stop or the socket died.
        if (f == Reader::Fill::Aborted && r.stop() != Stop::Timeout) return false;
        out.truncated = true;
        break;
    }

    out.body.assign(r.buf(), start, (std::min)(want, r.buf().size() - start));
    return true;
}

/// Body delimited by connection close (HTTP/1.0 style, or a 1.1 response with no
/// length at all). Bounded by the cap and by the timeouts.
bool read_to_eof(Reader& r, std::size_t start, const Options& opt, Response& out) {
    for (;;) {
        if (r.buf().size() - start >= opt.max_body_bytes) { out.truncated = true; break; }
        const Reader::Fill f = r.fill();
        if (f == Reader::Fill::Appended) continue;
        if (f == Reader::Fill::Eof) break;
        if (r.stop() != Stop::Timeout) return false;
        out.truncated = true;
        break;
    }
    out.body.assign(r.buf(), start, (std::min)(r.buf().size() - start, opt.max_body_bytes));
    return true;
}

/// Chunked transfer coding (RFC 7230 §4.1). Trailers after the final chunk are
/// read by nobody here, so the response ends at the zero-length chunk.
bool read_chunked(Reader& r, std::size_t pos, const Options& opt, Response& out) {
    for (;;) {
        std::size_t eol;
        while ((eol = r.buf().find("\r\n", pos)) == std::string::npos) {
            // The framing itself is incomplete — nothing here can be salvaged.
            if (r.fill() != Reader::Fill::Appended) return false;
        }

        unsigned long long size = 0;
        if (!parse_chunk_size(r.buf().substr(pos, eol - pos), size)) return false;
        pos = eol + 2;
        if (size == 0) return true;

        if (out.body.size() + size > opt.max_body_bytes) { out.truncated = true; return true; }

        while (r.buf().size() < pos + static_cast<std::size_t>(size) + 2) {
            const Reader::Fill f = r.fill();
            if (f == Reader::Fill::Appended) continue;
            if (f == Reader::Fill::Aborted && r.stop() != Stop::Timeout) return false;
            // Truncated mid-chunk: keep whatever of it did arrive.
            const std::size_t available = r.buf().size() - pos;
            out.body.append(r.buf(), pos, std::min<std::size_t>(available, size));
            out.truncated = true;
            return true;
        }

        out.body.append(r.buf(), pos, static_cast<std::size_t>(size));
        pos += static_cast<std::size_t>(size) + 2;
    }
}

bool read_response(socket_t sock, const std::string& method, const Options& opt, Response& out) {
    Reader r(sock, opt);

    std::size_t header_end;
    for (;;) {
        header_end = r.buf().find("\r\n\r\n");
        if (header_end != std::string::npos) break;
        if (r.buf().size() > kMaxHeaderBytes) {
            LOG_HTTP_DEBUG("response headers exceed " << kMaxHeaderBytes << " bytes");
            return false;
        }
        if (r.fill() != Reader::Fill::Appended) {
            LOG_HTTP_DEBUG("no complete response headers (" << r.buf().size() << " bytes read)");
            return false;
        }
    }

    Head head;
    if (!parse_head(r.buf(), header_end, head)) {
        LOG_HTTP_DEBUG("malformed HTTP response");
        return false;
    }
    out.status = head.status;

    const std::size_t body_start = header_end + 4;
    // Responses that carry no body however the headers read (RFC 7230 §3.3.3).
    if (method == "HEAD" || head.status == 204 || head.status == 304 ||
        (head.status >= 100 && head.status < 200)) {
        return true;
    }

    if (head.chunked) return read_chunked(r, body_start, opt, out);
    if (head.content_length >= 0)
        return read_counted(r, body_start, static_cast<unsigned long long>(head.content_length),
                            opt, out);
    return read_to_eof(r, body_start, opt, out);
}

/// Host header value: an IPv6 literal has to go back in brackets, and the default
/// port is left implicit (a few embedded servers match it literally).
std::string host_header(const std::string& host, std::uint16_t port) {
    std::string value = host.find(':') != std::string::npos ? "[" + host + "]" : host;
    if (port != 80) value += ":" + std::to_string(port);
    return value;
}

} // namespace

bool parse_url(const std::string& url, Url& out) {
    const std::size_t sep = url.find("://");
    if (sep == std::string::npos || sep == 0) return false;

    out = Url{};
    out.scheme = to_lower(url.substr(0, sep));

    const std::size_t host_start = sep + 3;
    const std::size_t path_start = url.find('/', host_start);
    std::string authority = (path_start == std::string::npos)
                                ? url.substr(host_start)
                                : url.substr(host_start, path_start - host_start);
    out.path = (path_start == std::string::npos) ? "/" : url.substr(path_start);

    // Drop any "user:password@" — we never authenticate, but the host still parses.
    if (const std::size_t at = authority.rfind('@'); at != std::string::npos) {
        authority = authority.substr(at + 1);
    }

    std::string port_text;
    if (!authority.empty() && authority.front() == '[') {  // [IPv6]:port
        const std::size_t close = authority.find(']');
        if (close == std::string::npos) return false;
        out.host = authority.substr(1, close - 1);
        if (close + 1 < authority.size()) {
            if (authority[close + 1] != ':') return false;
            port_text = authority.substr(close + 2);
        }
    } else if (const std::size_t colon = authority.find(':'); colon != std::string::npos) {
        out.host = authority.substr(0, colon);
        port_text = authority.substr(colon + 1);
    } else {
        out.host = authority;
    }
    if (out.host.empty()) return false;

    out.port = (out.scheme == "https") ? 443 : 80;
    if (!port_text.empty()) {
        if (port_text.find_first_not_of("0123456789") != std::string::npos) return false;
        const unsigned long value = std::strtoul(port_text.c_str(), nullptr, 10);
        if (value == 0 || value > 65535) return false;
        out.port = static_cast<std::uint16_t>(value);
    }
    return true;
}

bool request(const Request& req, const Options& opt, Response& out) {
    out = Response{};

    socket_t sock = create_tcp_client(req.host, req.port, opt.connect_timeout_ms);
    if (!is_valid_socket(sock)) {
        LOG_HTTP_DEBUG("connect to " << req.host << ":" << req.port << " failed");
        return false;
    }

    std::ostringstream wire;
    wire << req.method << " " << (req.path.empty() ? "/" : req.path) << " HTTP/1.1\r\n"
         << "Host: " << host_header(req.host, req.port) << "\r\n"
         << "Connection: close\r\n"
         << req.extra_headers;
    if (!req.body.empty()) {
        wire << "Content-Length: " << req.body.size() << "\r\n";
    }
    wire << "\r\n" << req.body;

    if (send_tcp_string(sock, wire.str()) < 0) {
        LOG_HTTP_DEBUG("failed to send request to " << req.host << ":" << req.port);
        close_socket(sock);
        return false;
    }

    const bool ok = read_response(sock, req.method, opt, out);
    close_socket(sock);
    return ok;
}

bool get(const std::string& url, const Options& opt, Response& out) {
    Url parsed;
    if (!parse_url(url, parsed)) {
        LOG_HTTP_DEBUG("unparsable URL: " << url);
        return false;
    }
    if (parsed.scheme != "http") {
        LOG_HTTP_DEBUG("unsupported scheme '" << parsed.scheme << "' (no TLS here)");
        return false;
    }

    Request req;
    req.host = parsed.host;
    req.port = parsed.port;
    req.path = parsed.path;
    req.extra_headers = "User-Agent: librats\r\nAccept: */*\r\n";
    return request(req, opt, out);
}

} // namespace http
} // namespace librats
