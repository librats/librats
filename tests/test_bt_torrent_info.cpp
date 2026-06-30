#include <gtest/gtest.h>

#include "bittorrent/torrent_info.h"
#include "bittorrent/bencode.h"
#include "crypto/sha1.h"

#include <string>

using namespace librats::bittorrent;
using librats::BencodeValue;

namespace {

// Wrap an exactly-encoded info dict into a .torrent byte stream. We embed the
// provided info bytes verbatim (rather than re-encoding through a parent map),
// so SHA1(info_bytes) is, by construction, the info-hash the parser must report.
librats::Bytes make_torrent(const librats::Bytes& info_bytes, const std::string& announce) {
    librats::Bytes out;
    auto put = [&](const std::string& s) { out.insert(out.end(), s.begin(), s.end()); };
    put("d");
    put("8:announce");
    put(std::to_string(announce.size()) + ":" + announce);
    put("4:info");
    out.insert(out.end(), info_bytes.begin(), info_bytes.end());
    put("e");
    return out;
}

librats::Bytes single_file_info(const std::string& name, std::int64_t length,
                                std::uint32_t piece_length, std::uint32_t num_pieces) {
    BencodeValue info = BencodeValue::create_dict();
    info["name"]         = BencodeValue(name);
    info["length"]       = BencodeValue(std::int64_t(length));
    info["piece length"] = BencodeValue(std::int64_t(piece_length));
    info["pieces"]       = BencodeValue(std::string(std::size_t(num_pieces) * 20, '\0'));
    return info.encode();
}

} // namespace

TEST(BtTorrentInfo, Sha1RawMatchesKnown) {
    // Cross-check the raw-digest SHA-1 used for info-hashes against a known vector.
    auto d = librats::SHA1::hash_raw(reinterpret_cast<const std::uint8_t*>("abc"), 3);
    EXPECT_EQ(to_hex(d), "a9993e364706816aba3e25717850c26c9cd0d89d");
}

TEST(BtTorrentInfo, ParseSingleFile) {
    librats::Bytes info = single_file_info("hello.txt", 2500, 1024, 3);
    auto expected = librats::SHA1::hash_raw(info.data(), info.size());
    librats::Bytes torrent = make_torrent(info, "http://tracker.example/announce");

    auto ti = TorrentInfo::from_bytes(torrent);
    ASSERT_TRUE(ti.has_value());
    EXPECT_TRUE(ti->is_valid());
    EXPECT_TRUE(ti->has_metadata());
    EXPECT_EQ(ti->info_hash(), expected);
    EXPECT_EQ(ti->name(), "hello.txt");
    EXPECT_EQ(ti->total_size(), 2500);
    EXPECT_EQ(ti->num_files(), 1u);
    EXPECT_EQ(ti->num_pieces(), 3u);
    EXPECT_EQ(ti->piece_length(), 1024u);
    EXPECT_EQ(ti->announce(), "http://tracker.example/announce");
    EXPECT_EQ(ti->files().file_at(0).path, "hello.txt");
}

TEST(BtTorrentInfo, ParseMultiFile) {
    BencodeValue info = BencodeValue::create_dict();
    info["name"]         = BencodeValue(std::string("mydir"));
    info["piece length"] = BencodeValue(std::int64_t(1024));
    info["pieces"]       = BencodeValue(std::string(20, '\0'));  // 300 bytes => 1 piece

    BencodeValue files = BencodeValue::create_list();
    {
        BencodeValue f = BencodeValue::create_dict();
        f["length"] = BencodeValue(std::int64_t(100));
        BencodeValue path = BencodeValue::create_list();
        path.push_back(BencodeValue(std::string("a.txt")));
        f["path"] = path;
        files.push_back(f);
    }
    {
        BencodeValue f = BencodeValue::create_dict();
        f["length"] = BencodeValue(std::int64_t(200));
        BencodeValue path = BencodeValue::create_list();
        path.push_back(BencodeValue(std::string("sub")));
        path.push_back(BencodeValue(std::string("b.txt")));
        f["path"] = path;
        files.push_back(f);
    }
    info["files"] = files;

    librats::Bytes info_bytes = info.encode();
    auto expected = librats::SHA1::hash_raw(info_bytes.data(), info_bytes.size());
    auto ti = TorrentInfo::from_bytes(make_torrent(info_bytes, "udp://t/announce"));

    ASSERT_TRUE(ti.has_value());
    EXPECT_EQ(ti->info_hash(), expected);
    EXPECT_EQ(ti->name(), "mydir");
    EXPECT_EQ(ti->num_files(), 2u);
    EXPECT_EQ(ti->total_size(), 300);
    EXPECT_EQ(ti->num_pieces(), 1u);
    // Paths are prefixed with the torrent (directory) name.
    EXPECT_EQ(ti->files().file_at(0).path, "mydir/a.txt");
    EXPECT_EQ(ti->files().file_at(1).path, "mydir/sub/b.txt");
}

TEST(BtTorrentInfo, PieceHashExtraction) {
    BencodeValue info = BencodeValue::create_dict();
    info["name"]         = BencodeValue(std::string("f"));
    info["length"]       = BencodeValue(std::int64_t(2048));
    info["piece length"] = BencodeValue(std::int64_t(1024));
    std::string pieces(40, '\0');
    pieces[0]  = 0x11;   // first byte of piece 0's hash
    pieces[20] = 0x22;   // first byte of piece 1's hash
    info["pieces"] = BencodeValue(pieces);

    auto ti = TorrentInfo::from_bytes(make_torrent(info.encode(), "http://t/a"));
    ASSERT_TRUE(ti.has_value());
    EXPECT_EQ(ti->piece_hash(0)[0], 0x11);
    EXPECT_EQ(ti->piece_hash(1)[0], 0x22);
    EXPECT_EQ(ti->piece_hash(99), (std::array<std::uint8_t, 20>{}));  // out of range => zeros
}

TEST(BtTorrentInfo, FromInfoDictVerifiesHash) {
    librats::Bytes info = single_file_info("x", 10, 16384, 1);
    auto good = librats::SHA1::hash_raw(info.data(), info.size());

    auto ok = TorrentInfo::from_info_dict(info, good);
    ASSERT_TRUE(ok.has_value());
    EXPECT_EQ(ok->info_hash(), good);

    InfoHash wrong = good;
    wrong[0] ^= 0xFF;
    EXPECT_FALSE(TorrentInfo::from_info_dict(info, wrong).has_value());

    // A zero "expected" means "don't check".
    EXPECT_TRUE(TorrentInfo::from_info_dict(info, InfoHash{}).has_value());
}

TEST(BtTorrentInfo, MagnetThenSetMetadata) {
    librats::Bytes info = single_file_info("movie.mkv", 5000, 2048, 3);
    auto ih = librats::SHA1::hash_raw(info.data(), info.size());

    auto ti = TorrentInfo::from_magnet("magnet:?xt=urn:btih:" + to_hex(ih) + "&dn=movie.mkv");
    ASSERT_TRUE(ti.has_value());
    EXPECT_TRUE(ti->is_valid());
    EXPECT_FALSE(ti->has_metadata());
    EXPECT_EQ(ti->info_hash(), ih);
    EXPECT_EQ(ti->num_files(), 0u);

    ASSERT_TRUE(ti->set_metadata(info));
    EXPECT_TRUE(ti->has_metadata());
    EXPECT_EQ(ti->num_files(), 1u);
    EXPECT_EQ(ti->total_size(), 5000);
    EXPECT_EQ(ti->info_hash(), ih);  // unchanged
}

TEST(BtTorrentInfo, SetMetadataRejectsWrongBytes) {
    librats::Bytes real  = single_file_info("a", 10, 16384, 1);
    librats::Bytes other = single_file_info("b", 99, 16384, 1);
    auto ih = librats::SHA1::hash_raw(real.data(), real.size());

    auto ti = TorrentInfo::from_magnet("magnet:?xt=urn:btih:" + to_hex(ih));
    ASSERT_TRUE(ti.has_value());
    EXPECT_FALSE(ti->set_metadata(other));   // hashes to a different info-hash
    EXPECT_FALSE(ti->has_metadata());
}

TEST(BtTorrentInfo, ToMagnetUri) {
    librats::Bytes info = single_file_info("name", 10, 16384, 1);
    auto ti = TorrentInfo::from_bytes(make_torrent(info, "http://tracker/announce"));
    ASSERT_TRUE(ti.has_value());
    const std::string uri = ti->to_magnet_uri();
    EXPECT_NE(uri.find("magnet:?xt=urn:btih:" + ti->info_hash_hex()), std::string::npos);
    EXPECT_NE(uri.find("tr=http://tracker/announce"), std::string::npos);
}

TEST(BtTorrentInfo, RejectsMalformed) {
    TorrentParseError err;
    EXPECT_FALSE(TorrentInfo::from_bytes(librats::Bytes{'x', 'y', 'z'}, &err).has_value());
    EXPECT_FALSE(err.message.empty());

    // Valid bencode but not a dict.
    EXPECT_FALSE(TorrentInfo::from_bytes(librats::Bytes{'i', '4', 'e'}).has_value());

    // Dict without an info key.
    librats::Bytes no_info = {'d', '1', ':', 'a', '1', ':', 'b', 'e'};
    EXPECT_FALSE(TorrentInfo::from_bytes(no_info).has_value());
}
