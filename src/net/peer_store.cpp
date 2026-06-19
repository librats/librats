#include "net/peer_store.h"
#include "util/fs.h"

#include <sstream>

namespace librats {

void PeerStore::load() {
    const std::string text = read_file_text_cpp(path_);
    if (text.empty()) return;

    std::lock_guard<std::mutex> lock(mutex_);
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
        if (line.empty()) continue;
        auto addr = Address::parse(line);
        if (!addr) continue;
        bool exists = false;
        for (const auto& a : addresses_) if (a == *addr) { exists = true; break; }
        if (!exists) addresses_.push_back(*addr);
    }
}

void PeerStore::save() const {
    std::string text;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& a : addresses_) text += a.to_string() + "\n";
    }
    create_file(path_.c_str(), text.c_str());
}

bool PeerStore::add(const Address& address) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& a : addresses_) if (a == address) return false;
    addresses_.push_back(address);
    return true;
}

std::vector<Address> PeerStore::all() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return addresses_;
}

size_t PeerStore::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return addresses_.size();
}

} // namespace librats
