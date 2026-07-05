#include "core/address.h"
#include "core/endpoint_parse.h"

#include <cassert>

namespace librats {

Address::Address(std::string_view numeric_ip, uint16_t port) : port(port) {
    if (auto a = IpAddress::parse(numeric_ip)) {
        ip = *a;
    } else {
        // A hostname or garbage reached the numeric-only Address constructor. In
        // release builds we leave ip unspecified (is_valid() will report false);
        // in debug we trip so the offending call site is caught early.
        assert(false && "Address(string, port): not a numeric IP literal — use HostEndpoint");
    }
}

std::optional<Address> Address::parse(std::string_view text) {
    const auto hp = split_host_port(text);
    if (!hp) return std::nullopt;
    // Address is strictly numeric: a hostname host reaches here only as a parse
    // failure, which is exactly the rejection we want (that input is a HostEndpoint).
    auto addr = IpAddress::parse(hp->first);
    if (!addr) return std::nullopt;
    return Address{*addr, hp->second};
}

std::string Address::to_string() const {
    std::string s = ip.to_string();
    if (ip.is_v6()) return "[" + s + "]:" + std::to_string(port);
    return s + ":" + std::to_string(port);
}

} // namespace librats
