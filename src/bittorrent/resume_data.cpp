#include "bittorrent/resume_data.h"

#include "bittorrent/bencode.h"

#include <cstring>

namespace librats::bittorrent {

namespace {
constexpr char kFormatTag[] = "librats resume";

const librats::BencodeValue* find(const librats::BencodeValue& d, const char* key) {
    return d.find(key);
}
} // namespace

Bytes ResumeData::encode() const {
    librats::BencodeValue d = librats::BencodeValue::create_dict();
    d["format"]     = librats::BencodeValue(std::string(kFormatTag));
    d["version"]    = librats::BencodeValue(std::int64_t(1));
    d["info-hash"]  = librats::BencodeValue(std::string(reinterpret_cast<const char*>(info_hash.data()), info_hash.size()));
    d["name"]       = librats::BencodeValue(name);
    d["save-path"]  = librats::BencodeValue(save_path);
    d["num-pieces"] = librats::BencodeValue(std::int64_t(have.size()));
    d["pieces"]     = librats::BencodeValue(std::string(reinterpret_cast<const char*>(have.data()), have.data_size()));
    d["uploaded"]   = librats::BencodeValue(std::int64_t(total_uploaded));
    d["downloaded"] = librats::BencodeValue(std::int64_t(total_downloaded));
    if (!info_dict.empty())
        d["info"] = librats::BencodeValue(std::string(reinterpret_cast<const char*>(info_dict.data()), info_dict.size()));
    return d.encode();
}

std::optional<ResumeData> ResumeData::decode(const Bytes& data) {
    try {
        librats::BencodeValue d = librats::BencodeDecoder::decode(data.data(), data.size());
        if (!d.is_dict()) return std::nullopt;
        const auto* fmt = find(d, "format");
        if (!fmt || !fmt->is_string() || fmt->as_string() != kFormatTag) return std::nullopt;

        ResumeData rd;
        if (const auto* ih = find(d, "info-hash"); ih && ih->is_string() && ih->as_string().size() == 20)
            std::memcpy(rd.info_hash.data(), ih->as_string().data(), 20);
        if (const auto* n = find(d, "name"); n && n->is_string()) rd.name = n->as_string();
        if (const auto* sp = find(d, "save-path"); sp && sp->is_string()) rd.save_path = sp->as_string();
        if (const auto* up = find(d, "uploaded"); up && up->is_integer()) rd.total_uploaded = std::uint64_t(up->as_integer());
        if (const auto* dn = find(d, "downloaded"); dn && dn->is_integer()) rd.total_downloaded = std::uint64_t(dn->as_integer());

        std::size_t num_pieces = 0;
        if (const auto* np = find(d, "num-pieces"); np && np->is_integer() && np->as_integer() >= 0)
            num_pieces = std::size_t(np->as_integer());
        if (const auto* p = find(d, "pieces"); p && p->is_string())
            rd.have.assign(reinterpret_cast<const std::uint8_t*>(p->as_string().data()),
                           p->as_string().size(), num_pieces);

        if (const auto* info = find(d, "info"); info && info->is_string())
            rd.info_dict.assign(info->as_string().begin(), info->as_string().end());

        return rd;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

} // namespace librats::bittorrent
