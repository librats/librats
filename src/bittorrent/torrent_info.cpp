#include "bittorrent/torrent_info.h"

#include "bittorrent/bencode.h"
#include "bittorrent/magnet_uri.h"
#include "crypto/sha1.h"
#include "util/fs.h"

#include <cctype>
#include <cstddef>
#include <cstring>

namespace librats::bittorrent {

namespace {

// ----------------------------------------------------------------------------
// Minimal bencode byte-span scanner.
//
// We must hash the *original* bytes of the `info` value (re-encoding the parsed
// structure could reorder dict keys and change the hash). The eager BencodeValue
// decoder discards positions, so this scanner walks the raw buffer to locate the
// info value's byte range without building a tree.
// ----------------------------------------------------------------------------

/// Read a bencoded byte string at @p pos, advancing @p pos past it.
bool read_bstring(const std::uint8_t* d, std::size_t n, std::size_t& pos, std::string& out) {
    std::size_t colon = pos;
    while (colon < n && d[colon] != ':') {
        if (d[colon] < '0' || d[colon] > '9') return false;
        ++colon;
    }
    if (colon >= n || colon == pos) return false;
    std::uint64_t len = 0;
    for (std::size_t i = pos; i < colon; ++i) {
        len = len * 10 + std::uint64_t(d[i] - '0');
        if (len > n) return false;  // can't be longer than the whole buffer
    }
    const std::size_t start = colon + 1;
    if (start + len > n) return false;
    out.assign(reinterpret_cast<const char*>(d + start), len);
    pos = start + len;
    return true;
}

/// Advance @p pos past exactly one bencoded value (int / string / list / dict).
bool skip_value(const std::uint8_t* d, std::size_t n, std::size_t& pos) {
    if (pos >= n) return false;
    const char c = char(d[pos]);
    if (c == 'i') {
        std::size_t e = pos + 1;
        while (e < n && d[e] != 'e') ++e;
        if (e >= n) return false;
        pos = e + 1;
        return true;
    }
    if (c == 'l' || c == 'd') {
        ++pos;
        while (pos < n && d[pos] != 'e') {
            if (!skip_value(d, n, pos)) return false;
        }
        if (pos >= n) return false;
        ++pos;  // consume 'e'
        return true;
    }
    if (c >= '0' && c <= '9') {
        std::string tmp;
        return read_bstring(d, n, pos, tmp);
    }
    return false;
}

/// Locate the byte range [start, end) of the top-level dict's `info` value.
std::optional<std::pair<std::size_t, std::size_t>> find_info_span(const Bytes& buf) {
    const std::uint8_t* d = buf.data();
    const std::size_t   n = buf.size();
    if (n == 0 || d[0] != 'd') return std::nullopt;

    std::size_t pos = 1;
    while (pos < n && d[pos] != 'e') {
        std::string key;
        if (!read_bstring(d, n, pos, key)) return std::nullopt;
        const std::size_t value_start = pos;
        if (!skip_value(d, n, pos)) return std::nullopt;
        if (key == "info") return std::make_pair(value_start, pos);
    }
    return std::nullopt;
}

// ---- safe bencode accessors (the BencodeValue accessors throw on mismatch) ----

const librats::BencodeValue* find(const librats::BencodeValue& dict, const char* key) {
    return dict.find(key);
}

const std::string* find_string(const librats::BencodeValue& dict, const char* key) {
    const auto* v = find(dict, key);
    return (v && v->is_string()) ? &v->as_string() : nullptr;
}

std::optional<std::int64_t> find_int(const librats::BencodeValue& dict, const char* key) {
    const auto* v = find(dict, key);
    if (v && v->is_integer()) return v->as_integer();
    return std::nullopt;
}

/// A path component is safe if it is non-empty, not "." / ".." and free of
/// separators / NULs — guarding the disk layer against traversal.
bool safe_component(const std::string& c) {
    if (c.empty() || c == "." || c == "..") return false;
    return c.find('/') == std::string::npos && c.find('\\') == std::string::npos
        && c.find('\0') == std::string::npos;
}

} // namespace

bool TorrentInfo::parse_info_dict(const librats::BencodeValue& info, TorrentParseError* err) {
    auto fail = [&](const char* m) { if (err) err->message = m; return false; };

    const std::string* name = find_string(info, "name");
    const auto piece_length  = find_int(info, "piece length");
    const std::string* pieces = find_string(info, "pieces");
    if (!name || !piece_length || !pieces) return fail("info dict missing name/piece length/pieces");
    if (*piece_length <= 0 || *piece_length > (1 << 30)) return fail("invalid piece length");
    if (pieces->size() % kInfoHashSize != 0) return fail("pieces string not a multiple of 20");
    if (!safe_component(*name)) return fail("unsafe torrent name");

    FileStorage files;
    files.set_piece_length(std::uint32_t(*piece_length));
    files.set_name(*name);

    if (const auto* file_list = find(info, "files"); file_list && file_list->is_list()) {
        // Multi-file: each entry has a length and a path component list.
        for (const auto& entry : file_list->as_list()) {
            const auto length = find_int(entry, "length");
            const auto* path  = find(entry, "path");
            if (!length || *length < 0 || !path || !path->is_list()) return fail("bad file entry");
            std::string rel = *name;
            for (const auto& comp : path->as_list()) {
                if (!comp.is_string() || !safe_component(comp.as_string())) return fail("unsafe file path");
                rel += '/';
                rel += comp.as_string();
            }
            if (!files.add_file(std::move(rel), *length)) return fail("file size overflow");
        }
    } else {
        // Single-file: the info dict itself carries the length.
        const auto length = find_int(info, "length");
        if (!length || *length < 0) return fail("single-file torrent missing length");
        if (!files.add_file(*name, *length)) return fail("file size overflow");
    }

    // The piece-hash count must match the file layout exactly.
    if (pieces->size() / kInfoHashSize != files.num_pieces()) return fail("piece count mismatch");

    files_        = std::move(files);
    name_         = *name;
    piece_hashes_.assign(pieces->begin(), pieces->end());
    is_private_   = find_int(info, "private").value_or(0) == 1;
    has_metadata_ = true;
    return true;
}

std::optional<TorrentInfo> TorrentInfo::from_info_dict(const Bytes& info_dict_bytes,
                                                       const InfoHash& expected,
                                                       TorrentParseError* err) {
    try {
        librats::BencodeValue info = librats::BencodeDecoder::decode(info_dict_bytes);
        TorrentInfo ti;
        if (!ti.parse_info_dict(info, err)) return std::nullopt;
        ti.info_dict_bytes_ = info_dict_bytes;
        ti.info_hash_       = SHA1::hash_raw(info_dict_bytes.data(), info_dict_bytes.size());
        if (!is_all_zero(expected) && ti.info_hash_ != expected) {
            if (err) err->message = "info-hash mismatch";
            return std::nullopt;
        }
        return ti;
    } catch (const std::exception& e) {
        if (err) err->message = e.what();
        return std::nullopt;
    }
}

std::optional<TorrentInfo> TorrentInfo::from_bytes(const Bytes& data, TorrentParseError* err) {
    try {
        librats::BencodeValue root = librats::BencodeDecoder::decode(data);
        if (!root.is_dict()) { if (err) err->message = "torrent is not a dict"; return std::nullopt; }

        const auto span = find_info_span(data);
        const auto* info = find(root, "info");
        if (!span || !info) { if (err) err->message = "missing info dict"; return std::nullopt; }

        TorrentInfo ti;
        if (!ti.parse_info_dict(*info, err)) return std::nullopt;

        ti.info_dict_bytes_.assign(data.begin() + std::ptrdiff_t(span->first),
                                   data.begin() + std::ptrdiff_t(span->second));
        ti.info_hash_ = SHA1::hash_raw(ti.info_dict_bytes_.data(), ti.info_dict_bytes_.size());

        // Optional top-level fields.
        if (const auto* a = find_string(root, "announce")) ti.announce_ = *a;
        if (const auto* c = find_string(root, "comment")) ti.comment_ = *c;
        if (const auto* cb = find_string(root, "created by")) ti.created_by_ = *cb;
        if (auto cd = find_int(root, "creation date")) ti.creation_date_ = *cd;

        if (const auto* al = find(root, "announce-list"); al && al->is_list()) {
            for (const auto& tier : al->as_list()) {
                if (!tier.is_list()) continue;
                TrackerTier t;
                for (const auto& url : tier.as_list())
                    if (url.is_string()) t.push_back(url.as_string());
                if (!t.empty()) ti.announce_list_.push_back(std::move(t));
            }
        }

        if (const auto* ul = find(root, "url-list")) {  // web seeds (BEP 19)
            if (ul->is_string()) ti.web_seeds_.push_back(ul->as_string());
            else if (ul->is_list())
                for (const auto& u : ul->as_list())
                    if (u.is_string()) ti.web_seeds_.push_back(u.as_string());
        }

        if (const auto* nodes = find(root, "nodes"); nodes && nodes->is_list()) {
            for (const auto& node : nodes->as_list()) {
                if (!node.is_list() || node.as_list().size() != 2) continue;
                const auto& pair = node.as_list();
                if (pair[0].is_string() && pair[1].is_integer())
                    ti.dht_nodes_.push_back(DhtNode{pair[0].as_string(),
                                                    std::uint16_t(pair[1].as_integer())});
            }
        }

        return ti;
    } catch (const std::exception& e) {
        if (err) err->message = e.what();
        return std::nullopt;
    }
}

std::optional<TorrentInfo> TorrentInfo::from_file(const std::string& path, TorrentParseError* err) {
    std::size_t size = 0;
    void* buf = read_file_binary(path.c_str(), &size);
    if (!buf) { if (err) err->message = "cannot read file"; return std::nullopt; }
    Bytes data(static_cast<std::uint8_t*>(buf), static_cast<std::uint8_t*>(buf) + size);
    free_file_buffer(buf);
    return from_bytes(data, err);
}

std::optional<TorrentInfo> TorrentInfo::from_magnet(const std::string& uri, TorrentParseError* err) {
    auto magnet = MagnetUri::parse(uri);
    if (!magnet) { if (err) err->message = "invalid magnet uri"; return std::nullopt; }

    TorrentInfo ti;
    ti.info_hash_    = magnet->info_hash;
    ti.name_         = magnet->display_name;
    ti.web_seeds_    = magnet->web_seeds;
    ti.has_metadata_ = false;  // file list & piece hashes still need fetching
    for (const auto& tr : magnet->trackers) ti.announce_list_.push_back({tr});
    if (!ti.announce_list_.empty() && !ti.announce_list_.front().empty())
        ti.announce_ = ti.announce_list_.front().front();
    return ti;
}

bool TorrentInfo::set_metadata(const Bytes& info_dict_bytes) {
    auto completed = from_info_dict(info_dict_bytes, info_hash_, nullptr);
    if (!completed) return false;
    // Preserve discovery fields learned from the magnet; adopt the parsed payload.
    files_           = std::move(completed->files_);
    piece_hashes_    = std::move(completed->piece_hashes_);
    info_dict_bytes_ = std::move(completed->info_dict_bytes_);
    is_private_      = completed->is_private_;
    if (name_.empty()) name_ = completed->name_;
    has_metadata_    = true;
    return true;
}

std::array<std::uint8_t, 20> TorrentInfo::piece_hash(std::uint32_t index) const {
    std::array<std::uint8_t, 20> out{};
    const std::size_t off = std::size_t(index) * kInfoHashSize;
    if (off + kInfoHashSize <= piece_hashes_.size())
        std::memcpy(out.data(), piece_hashes_.data() + off, kInfoHashSize);
    return out;
}

std::vector<std::string> TorrentInfo::all_trackers() const {
    std::vector<std::string> all;
    if (!announce_.empty()) all.push_back(announce_);
    for (const auto& tier : announce_list_)
        for (const auto& url : tier)
            if (url != announce_) all.push_back(url);
    return all;
}

std::string TorrentInfo::to_magnet_uri(bool include_trackers) const {
    std::string uri = "magnet:?xt=urn:btih:" + to_hex(info_hash_);
    if (!name_.empty()) {
        uri += "&dn=";
        // Percent-encode anything that isn't an unreserved URI character.
        for (unsigned char c : name_) {
            if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
                uri += char(c);
            } else {
                static const char hex[] = "0123456789ABCDEF";
                uri += '%';
                uri += hex[c >> 4];
                uri += hex[c & 0x0F];
            }
        }
    }
    if (include_trackers)
        for (const auto& tr : all_trackers()) uri += "&tr=" + tr;
    return uri;
}

} // namespace librats::bittorrent
