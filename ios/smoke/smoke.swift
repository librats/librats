// Smoke test for the iOS binding: two librats nodes inside one process complete a
// Noise handshake over the loopback and echo a message back, driven entirely from
// Swift through the C ABI.
//
// It exists to prove three things the compiler alone cannot:
//   1. `import LibRats` resolves — the module map reaches the C ABI with no shim;
//   2. Swift closures convert to the ABI's C callbacks and fire on reactor threads;
//   3. the transport, the Noise handshake and the reactor actually run under the
//      iOS sandbox, rather than merely compiling for it.
//
// Built and run by ios/run-smoke.sh on a simulator.

import Foundation
import LibRats

// Callbacks arrive on a reactor thread, so everything they touch is behind a lock.
final class Harness {
    private let lock = NSLock()
    private var _received: String?

    let node: rats_t
    let connected = DispatchSemaphore(value: 0)
    let echoed = DispatchSemaphore(value: 0)

    init(node: rats_t) { self.node = node }

    var received: String? {
        lock.lock(); defer { lock.unlock() }
        return _received
    }

    func store(_ text: String) {
        lock.lock(); _received = text; lock.unlock()
    }

    /// The `void* user` handed to every C callback. Unretained: the Harness
    /// outlives the node it belongs to in this test, so there is nothing to own.
    var opaque: UnsafeMutableRawPointer { Unmanaged.passUnretained(self).toOpaque() }

    static func from(_ user: UnsafeMutableRawPointer?) -> Harness? {
        guard let user = user else { return nil }
        return Unmanaged<Harness>.fromOpaque(user).takeUnretainedValue()
    }
}

func fail(_ message: String) -> Never {
    print("FAIL: \(message)")
    exit(1)
}

func check(_ err: rats_error_t, _ what: String) {
    guard err == RATS_OK else {
        fail("\(what): \(String(cString: rats_error_str(err)))")
    }
}

// --- nodes -----------------------------------------------------------------
// Port 0 is ephemeral, so the test never collides with whatever else is running.
guard let serverNode = rats_create(0) else { fail("rats_create(server) returned null") }
// enable_listen = 0 — a dial-only client, the normal shape for a mobile peer.
guard let clientNode = rats_create_ex(0, 0, nil, RATS_SECURITY_NOISE) else {
    fail("rats_create_ex(client) returned null")
}

let server = Harness(node: serverNode)
let client = Harness(node: clientNode)

// --- handlers (must be registered before start) -----------------------------

// The server echoes whatever lands on "chat" straight back to its sender. The
// peer id it replies to comes from the callback, so no lookup is needed.
check(rats_on(serverNode, "chat", { user, peerId, data, len in
    guard let h = Harness.from(user), let peerId = peerId, let data = data else { return }
    _ = rats_send(h.node, peerId, "chat", data, len)
}, server.opaque), "rats_on(server)")

check(rats_on(clientNode, "chat", { user, _, data, len in
    guard let h = Harness.from(user), let data = data else { return }
    h.store(String(decoding: Data(bytes: data, count: len), as: UTF8.self))
    h.echoed.signal()
}, client.opaque), "rats_on(client)")

check(rats_on_peer_connected(clientNode, { user, _ in
    Harness.from(user)?.connected.signal()
}, client.opaque), "rats_on_peer_connected(client)")

// --- run -------------------------------------------------------------------
check(rats_start(serverNode), "rats_start(server)")
check(rats_start(clientNode), "rats_start(client)")

let port = rats_listen_port(serverNode)
guard port != 0 else { fail("server bound no port") }

// Strings the library returns are heap-allocated and owned by the caller.
let serverId: String = {
    guard let id = rats_local_id(serverNode) else { fail("rats_local_id returned null") }
    defer { rats_string_free(id) }
    return String(cString: id)
}()

print("server \(serverId.prefix(16))… listening on \(port)")
print("transports: server=\(rats_transports(serverNode)) client=\(rats_transports(clientNode))")

check(rats_connect(clientNode, "127.0.0.1", port), "rats_connect")

guard client.connected.wait(timeout: .now() + 15) == .success else {
    fail("no handshake within 15s (transports=\(rats_transports(clientNode)))")
}
print("handshake complete")

let message = "hello from swift on ios"
check(rats_send(clientNode, serverId, "chat", Array(message.utf8), message.utf8.count),
      "rats_send")

guard client.echoed.wait(timeout: .now() + 15) == .success else {
    fail("no echo within 15s")
}
guard client.received == message else {
    fail("echo mismatch: got \(client.received ?? "nil")")
}
print("echo verified: \"\(client.received!)\"")

rats_stop(clientNode)
rats_stop(serverNode)
rats_destroy(clientNode)
rats_destroy(serverNode)

print("PASS")
