#include "bittorrent/torrent_creator.h"

#include "bittorrent/bencode.h"
#include "bittorrent/file_storage.h"
#include "crypto/sha1.h"
#include "util/fs.h"

#include <ctime>

namespace librats::bittorrent {

namespace {

struct SourceFile {
    std::vector<std::string> components;  ///< path relative to the torrent root
    std::int64_t             size = 0;
    std::string              disk_path;   ///< where to read the bytes from
};

/// Recursively collect the regular files under @p dir, accumulating the path
/// components relative to the torrent root.
void scan_directory(const std::string& dir, std::vector<std::string> prefix,
                    std::vector<SourceFile>& out) {
    std::vector<DirectoryEntry> entries;
    if (!list_directory(dir.c_str(), entries)) return;
    for (const auto& e : entries) {
        if (e.name == "." || e.name == "..") continue;
        std::vector<std::string> comps = prefix;
        comps.push_back(e.name);
        const std::string child = combine_paths(dir, e.name);
        if (e.is_directory) scan_directory(child, std::move(comps), out);
        else out.push_back(SourceFile{std::move(comps), std::int64_t(get_file_size(child.c_str())), child});
    }
}

} // namespace

std::optional<TorrentInfo> TorrentCreator::create_from_path(const std::string& path, std::string* error,
                                                            const PieceHashProgress& on_progress) {
    auto fail = [&](const char* m) -> std::optional<TorrentInfo> { if (error) *error = m; return std::nullopt; };

    const std::string root_name = name_.empty() ? get_filename_from_path(path) : name_;
    if (root_name.empty()) return fail("empty torrent name");

    // Gather the source files and lay them out (the layout also drives reading).
    std::vector<SourceFile> sources;
    bool single_file = false;
    if (is_directory(path.c_str())) {
        scan_directory(path, {}, sources);
    } else if (is_file(path.c_str())) {
        single_file = true;
        sources.push_back(SourceFile{{root_name}, std::int64_t(get_file_size(path.c_str())), path});
    } else {
        return fail("path is neither a file nor a directory");
    }
    if (sources.empty()) return fail("no files to add");

    FileStorage layout;
    layout.set_piece_length(piece_length_);
    layout.set_name(root_name);
    std::vector<std::string> disk_paths;
    for (const auto& s : sources) {
        std::string rel = root_name;
        if (!single_file)
            for (const auto& c : s.components) { rel += '/'; rel += c; }
        if (!layout.add_file(rel, s.size)) return fail("file size overflow");
        disk_paths.push_back(s.disk_path);
    }

    // Hash every piece by reading the bytes it spans across the source files.
    const std::uint32_t total_pieces = layout.num_pieces();
    std::string pieces;
    pieces.reserve(std::size_t(total_pieces) * 20);
    for (std::uint32_t p = 0; p < total_pieces; ++p) {
        Bytes buf;
        buf.reserve(layout.piece_size(p));
        for (const auto& slice : layout.map_block(p, 0, layout.piece_size(p))) {
            Bytes chunk(std::size_t(slice.size));
            if (!read_file_chunk(disk_paths[slice.file_index], std::uint64_t(slice.offset),
                                 chunk.data(), chunk.size()))
                return fail("failed to read source file");
            buf.insert(buf.end(), chunk.begin(), chunk.end());
        }
        auto h = SHA1::hash_raw(buf.data(), buf.size());
        pieces.append(reinterpret_cast<const char*>(h.data()), 20);
        if (on_progress) on_progress(p + 1, total_pieces);
    }

    // Build the info dictionary.
    librats::BencodeValue info = librats::BencodeValue::create_dict();
    info["name"]         = librats::BencodeValue(root_name);
    info["piece length"] = librats::BencodeValue(std::int64_t(piece_length_));
    info["pieces"]       = librats::BencodeValue(pieces);
    if (private_) info["private"] = librats::BencodeValue(std::int64_t(1));
    if (single_file) {
        info["length"] = librats::BencodeValue(std::int64_t(sources[0].size));
    } else {
        librats::BencodeValue files = librats::BencodeValue::create_list();
        for (const auto& s : sources) {
            librats::BencodeValue f = librats::BencodeValue::create_dict();
            f["length"] = librats::BencodeValue(std::int64_t(s.size));
            librats::BencodeValue comps = librats::BencodeValue::create_list();
            for (const auto& c : s.components) comps.push_back(librats::BencodeValue(c));
            f["path"] = comps;
            files.push_back(f);
        }
        info["files"] = files;
    }

    // Wrap into a full .torrent with the optional top-level fields.
    librats::BencodeValue root = librats::BencodeValue::create_dict();
    if (!trackers_.empty()) {
        root["announce"] = librats::BencodeValue(trackers_.front());
        librats::BencodeValue tier = librats::BencodeValue::create_list();
        for (const auto& t : trackers_) tier.push_back(librats::BencodeValue(t));
        librats::BencodeValue al = librats::BencodeValue::create_list();
        al.push_back(tier);
        root["announce-list"] = al;
    }
    if (!comment_.empty())    root["comment"]    = librats::BencodeValue(comment_);
    if (!created_by_.empty()) root["created by"] = librats::BencodeValue(created_by_);
    root["creation date"] = librats::BencodeValue(std::int64_t(std::time(nullptr)));
    root["info"]          = info;

    torrent_bytes_ = root.encode();
    return TorrentInfo::from_bytes(torrent_bytes_);
}

} // namespace librats::bittorrent
