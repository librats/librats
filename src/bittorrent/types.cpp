#include "bittorrent/types.h"

#include <cstdio>
#include <cstring>
#include <random>

namespace librats::bittorrent {

// =============================================================================
// Hex / identity helpers
// =============================================================================

std::string to_hex(const std::uint8_t* data, std::size_t len) {
    static const char digits[] = "0123456789abcdef";
    std::string out;
    out.resize(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        out[i * 2]     = digits[data[i] >> 4];
        out[i * 2 + 1] = digits[data[i] & 0x0F];
    }
    return out;
}

std::optional<InfoHash> info_hash_from_hex(const std::string& hex) {
    if (hex.size() != kInfoHashSize * 2) return std::nullopt;

    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };

    InfoHash out{};
    for (std::size_t i = 0; i < kInfoHashSize; ++i) {
        const int hi = nibble(hex[i * 2]);
        const int lo = nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        out[i] = std::uint8_t(hi << 4 | lo);
    }
    return out;
}

bool is_all_zero(const std::array<std::uint8_t, 20>& id) noexcept {
    for (std::uint8_t b : id) if (b != 0) return false;
    return true;
}

PeerId generate_peer_id(const std::string& client_prefix) {
    PeerId id{};
    const std::size_t prefix_len = std::min(client_prefix.size(), kPeerIdSize);
    for (std::size_t i = 0; i < prefix_len; ++i) id[i] = std::uint8_t(client_prefix[i]);

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(0, 255);
    for (std::size_t i = prefix_len; i < kPeerIdSize; ++i) id[i] = std::uint8_t(dist(gen));

    return id;
}

// =============================================================================
// Client identification (BEP 20)
//
// Ported from the prior librats implementation: recognises the Azureus,
// Shadow and Mainline encodings plus a long table of non-standard clients.
// =============================================================================

namespace {

int decode_version_digit(std::uint8_t c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'Z') return c - 'A' + 10;
    if (c >= 'a' && c <= 'z') return c - 'a' + 10;
    return 0;
}

const char* lookup_az_client(const char* code) {
    struct Entry { const char* code; const char* name; };
    static const Entry entries[] = {
        {"7T","aTorrent"},{"AB","AnyEvent BitTorrent"},{"AG","Ares"},{"AR","Arctic Torrent"},
        {"AT","Artemis"},{"AV","Avicora"},{"AX","BitPump"},{"AZ","Azureus"},{"A~","Ares"},
        {"BB","BitBuddy"},{"BC","BitComet"},{"BE","baretorrent"},{"BF","Bitflu"},{"BG","BTG"},
        {"BI","BiglyBT"},{"BL","BitBlinder"},{"BP","BitTorrent Pro"},{"BR","BitRocket"},
        {"BS","BTSlave"},{"BT","BitTorrent"},{"BU","BigUp"},{"BW","BitWombat"},{"BX","BittorrentX"},
        {"CD","Enhanced CTorrent"},{"CT","CTorrent"},{"DE","Deluge"},{"DP","Propagate Data Client"},
        {"EB","EBit"},{"ES","electric sheep"},{"FC","FileCroc"},{"FT","FoxTorrent"},{"FW","FrostWire"},
        {"FX","Freebox BitTorrent"},{"GS","GSTorrent"},{"HK","Hekate"},{"HL","Halite"},{"HN","Hydranode"},
        {"IL","iLivid"},{"KC","Koinonein"},{"KG","KGet"},{"KT","KTorrent"},{"LC","LeechCraft"},
        {"LH","LH-ABC"},{"LK","Linkage"},{"LP","lphant"},{"LR","librats"},{"LT","libtorrent"},
        {"LW","Limewire"},{"ML","MLDonkey"},{"MO","Mono Torrent"},{"MP","MooPolice"},{"MR","Miro"},
        {"MT","Moonlight Torrent"},{"NX","Net Transport"},{"OS","OneSwarm"},{"OT","OmegaTorrent"},
        {"PD","Pando"},{"QD","QQDownload"},{"QT","Qt 4"},{"RT","Retriever"},{"RZ","RezTorrent"},
        {"SB","Swiftbit"},{"SD","Xunlei"},{"SK","spark"},{"SN","ShareNet"},{"SS","SwarmScope"},
        {"ST","SymTorrent"},{"SZ","Shareaza"},{"S~","Shareaza (beta)"},{"TB","Torch"},{"TL","Tribler"},
        {"TN","Torrent.NET"},{"TR","Transmission"},{"TS","TorrentStorm"},{"TT","TuoTu"},{"UL","uLeecher"},
        {"UM","uTorrent Mac"},{"UT","uTorrent"},{"VG","Vagaa"},{"WT","BitLet"},{"WY","FireTorrent"},
        {"XF","Xfplay"},{"XL","Xunlei"},{"XS","XSwifter"},{"XT","XanTorrent"},{"XX","Xtorrent"},
        {"ZO","Zona"},{"ZT","ZipTorrent"},{"lt","rTorrent"},{"pX","pHoeniX"},{"qB","qBittorrent"},
        {"st","SharkTorrent"},
    };
    for (const auto& e : entries) {
        if (e.code[0] == code[0] && e.code[1] == code[1]) return e.name;
    }
    return nullptr;
}

const char* lookup_generic_client(const std::uint8_t* id) {
    struct Entry { int offset; const char* pattern; const char* name; };
    static const Entry entries[] = {
        {0,"Deadman Walking-","Deadman"},{5,"Azureus","Azureus 2.0.3.2"},{0,"DansClient","XanTorrent"},
        {4,"btfans","SimpleBT"},{0,"PRC.P---","Bittorrent Plus! II"},{0,"P87.P---","Bittorrent Plus!"},
        {0,"S587Plus","Bittorrent Plus!"},{0,"martini","Martini Man"},{0,"Plus---","Bittorrent Plus"},
        {0,"turbobt","TurboBT"},{0,"a00---0","Swarmy"},{0,"a02---0","Swarmy"},{0,"T00---0","Teeweety"},
        {0,"BTDWV-","Deadman Walking"},{2,"BS","BitSpirit"},{0,"-SP","BitSpirit 3.6"},{0,"Pando-","Pando"},
        {0,"LIME","LimeWire"},{0,"btuga","BTugaXP"},{0,"oernu","BTugaXP"},{0,"Mbrst","Burst!"},
        {0,"PEERAPP","PeerApp"},{0,"Plus","Plus!"},{0,"-Qt-","Qt"},{0,"exbc","BitComet"},
        {0,"DNA","BitTorrent DNA"},{0,"-G3","G3 Torrent"},{0,"-FG","FlashGet"},{0,"-ML","MLdonkey"},
        {0,"-MG","Media Get"},{0,"XBT","XBT"},{0,"OP","Opera"},{2,"RS","Rufus"},{0,"AZ2500BT","BitTyrant"},
        {0,"btpd/","BitTorrent Protocol Daemon"},{0,"TIX","Tixati"},{0,"QVOD","Qvod"},
    };
    for (const auto& e : entries) {
        const std::size_t len = std::strlen(e.pattern);
        if (std::size_t(e.offset) + len <= kPeerIdSize &&
            std::memcmp(id + e.offset, e.pattern, len) == 0) {
            return e.name;
        }
    }
    return nullptr;
}

} // namespace

std::string identify_client(const PeerId& id) {
    if (is_all_zero(id)) return "Unknown";

    if (const char* generic = lookup_generic_client(id.data())) return generic;

    // Bits on Wheels special case: "-BOW...-"
    if (id[0] == '-' && id[1] == 'B' && id[2] == 'O' && id[3] == 'W' && id[7] == '-') {
        return "Bits on Wheels " + std::string(reinterpret_cast<const char*>(id.data()) + 4, 3);
    }

    // Azureus-style: -XX1234-
    if (id[0] == '-' && id[7] == '-' &&
        id[3] >= '0' && id[4] >= '0' && id[5] >= '0' && id[6] >= '0') {
        const char code[3] = {char(id[1]), char(id[2]), '\0'};
        const int v1 = decode_version_digit(id[3]);
        const int v2 = decode_version_digit(id[4]);
        const int v3 = decode_version_digit(id[5]);
        const int v4 = decode_version_digit(id[6]);

        const char* name = lookup_az_client(code);
        std::string client = name ? name : std::string("Unknown (") + code + ")";
        std::string version = std::to_string(v1) + "." + std::to_string(v2) + "." + std::to_string(v3);
        if (v4 != 0) version += "." + std::to_string(v4);
        return client + " " + version;
    }

    // Shadow-style: X + 3 version chars + "--", and Mainline-style: M1-2-3--
    if ((id[0] >= 'A' && id[0] <= 'Z') || (id[0] >= 'a' && id[0] <= 'z')) {
        if (id[4] == '-' && id[5] == '-' && id[1] >= '0' && id[2] >= '0' && id[3] >= '0') {
            const char* name = nullptr;
            switch (char(id[0])) {
                case 'A': name = "ABC"; break;
                case 'M': name = "Mainline"; break;
                case 'O': name = "Osprey Permaseed"; break;
                case 'Q': name = "BTQueue"; break;
                case 'R': name = "Tribler"; break;
                case 'S': name = "Shadow"; break;
                case 'T': name = "BitTornado"; break;
                case 'U': name = "UPnP"; break;
                default: break;
            }
            if (name) {
                return std::string(name) + " " + std::to_string(decode_version_digit(id[1])) + "." +
                       std::to_string(decode_version_digit(id[2])) + "." +
                       std::to_string(decode_version_digit(id[3]));
            }
        }

        char ids[21];
        std::memcpy(ids, id.data(), 20);
        ids[20] = '\0';
        char name_ch = '\0';
        int v1 = 0, v2 = 0, v3 = 0;
        if (std::sscanf(ids, "%c%3d-%3d-%3d--", &name_ch, &v1, &v2, &v3) == 4 && name_ch == 'M') {
            return "Mainline " + std::to_string(v1) + "." + std::to_string(v2) + "." + std::to_string(v3);
        }
    }

    bool first_12_zero = true;
    for (int i = 0; i < 12; ++i) if (id[i] != 0) { first_12_zero = false; break; }
    if (first_12_zero) {
        if (id[12] == 0x97) return "Experimental 3.2.1b2";
        if (id[12] == 0x00) return "Experimental 3.1";
        return "Generic";
    }

    std::string unknown("Unknown [");
    for (std::uint8_t c : id) unknown += (c >= 32 && c < 127) ? char(c) : '.';
    unknown += "]";
    return unknown;
}

} // namespace librats::bittorrent
