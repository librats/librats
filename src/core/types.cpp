#include "core/types.h"

namespace librats {

const char* to_string(ConnState s) noexcept {
    switch (s) {
        case ConnState::Connecting:  return "Connecting";
        case ConnState::Handshaking: return "Handshaking";
        case ConnState::Established: return "Established";
        case ConnState::Closing:     return "Closing";
        case ConnState::Closed:      return "Closed";
    }
    return "?";
}

const char* to_string(CloseReason r) noexcept {
    switch (r) {
        case CloseReason::LocalClose:      return "LocalClose";
        case CloseReason::PeerClosed:      return "PeerClosed";
        case CloseReason::PeerReset:       return "PeerReset";
        case CloseReason::ConnectFailed:   return "ConnectFailed";
        case CloseReason::HandshakeFailed: return "HandshakeFailed";
        case CloseReason::ProtocolError:   return "ProtocolError";
        case CloseReason::SlowConsumer:    return "SlowConsumer";
        case CloseReason::ReactorShutdown: return "ReactorShutdown";
        case CloseReason::DuplicateConn:   return "DuplicateConn";
        case CloseReason::PeerLimit:       return "PeerLimit";
    }
    return "?";
}

} // namespace librats
