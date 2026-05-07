#include "librats.h"

#include <cstdio>

int main() {
    librats::RatsClient client(/*listen_port=*/0);
    std::printf("librats peer id: %s\n", client.get_our_peer_id().c_str());
    return 0;
}
