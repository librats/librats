"""
Integration tests for the librats Python bindings (new C ABI).

Require the librats shared library to be built and importable. Not run as part
of this change.
"""

import os
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from librats_py import RatsClient, RatsError, Security
    LIBRATS_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Could not import librats_py: {e}")
    LIBRATS_AVAILABLE = False


@unittest.skipIf(not LIBRATS_AVAILABLE, "librats_py not available")
class TestIntegration(unittest.TestCase):
    def setUp(self):
        self.clients = []
        self.messages = []
        self.connections = []
        self.lock = threading.Lock()

    def tearDown(self):
        for c in self.clients:
            try:
                c.stop()
            except Exception:
                pass
        self.clients.clear()

    def make_client(self, port=0, **kw):
        c = RatsClient(port, **kw)
        self.clients.append(c)
        return c

    def test_two_clients_channel_message(self):
        a = self.make_client(0)
        b = self.make_client(0)

        a.on_peer_connected(lambda pid: self.connections.append(("a", pid)))

        def on_msg(peer_id, data):
            with self.lock:
                self.messages.append((peer_id, data))

        a.on("chat", on_msg)

        a.start()
        b.start()
        time.sleep(0.3)

        b.connect("127.0.0.1", a.listen_port)
        time.sleep(1.0)

        self.assertGreater(a.peer_count(), 0)
        self.assertGreater(b.peer_count(), 0)

        b.broadcast("chat", b"hello from b")
        time.sleep(0.5)

        with self.lock:
            self.assertTrue(any(d == b"hello from b" for _, d in self.messages))

    def test_pubsub(self):
        a = self.make_client(0)
        b = self.make_client(0)

        received = []
        a.enable_pubsub()
        a.subscribe("room", lambda pid, topic, data: received.append(data))
        b.enable_pubsub()
        b.subscribe("room", lambda pid, topic, data: None)

        a.start()
        b.start()
        time.sleep(0.3)
        b.connect("127.0.0.1", a.listen_port)
        time.sleep(1.0)

        b.publish("room", b"broadcast payload")
        time.sleep(0.5)
        self.assertTrue(any(d == b"broadcast payload" for d in received))

    def test_typed_json(self):
        a = self.make_client(0)
        b = self.make_client(0)

        got = []
        a.enable_json()
        a.on_json("greeting", lambda pid, payload: got.append(payload))
        b.enable_json()

        a.start()
        b.start()
        time.sleep(0.3)
        b.connect("127.0.0.1", a.listen_port)
        time.sleep(1.0)

        b.broadcast_json("greeting", {"hi": "there", "n": 7})
        time.sleep(0.5)
        self.assertTrue(any(p.get("hi") == "there" for p in got))

    def test_file_transfer(self):
        import tempfile
        a = self.make_client(0)
        b = self.make_client(0)

        a.enable_file_transfer()
        b.enable_file_transfer()

        completed = []
        dest_dir = tempfile.mkdtemp()

        def on_offer(peer_id, transfer_id, name, size, is_dir):
            a.accept_file(peer_id, transfer_id, os.path.join(dest_dir, name))

        a.on_file_offer(on_offer)
        a.on_file_complete(lambda tid, ok, path: completed.append((ok, path)))

        a.start()
        b.start()
        time.sleep(0.3)
        b.connect("127.0.0.1", a.listen_port)
        time.sleep(1.0)

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write("payload")
            src = f.name
        try:
            a_id = a.local_id
            tid = b.send_file(a_id, src)
            self.assertIsInstance(tid, int)
            self.assertNotEqual(tid, 0)
            time.sleep(1.0)
        finally:
            os.unlink(src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
