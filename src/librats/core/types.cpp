#include "librats/core/types.h"

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
        case CloseReason::IdleTimeout:     return "IdleTimeout";
        case CloseReason::DialSuperseded:  return "DialSuperseded";
    }
    return "?";
}

const char* to_string(TransportKind t) noexcept {
    switch (t) {
        case TransportKind::Tcp:   return "tcp";
        case TransportKind::Udp:   return "udp";
        case TransportKind::Relay: return "relay";
    }
    return "?";
}

} // namespace librats
