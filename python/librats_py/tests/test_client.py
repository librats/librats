"""
Unit tests for :class:`RatsNode` against the librats C ABI.

They need the native shared library built and loadable; the whole module skips
itself when it is not.
"""

import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from librats_py import (
        RatsNode, RatsError, LogLevel, Security, TransportMask, NatMapping,
        version, version_info, abi, git_describe, set_log_level, set_log_file,
    )
    from librats_py.exceptions import (
        RatsNotEnabledError, RatsAlreadyStartedError,
    )
except ImportError as e:  # native lib not built yet
    print(f"Warning: could not import librats_py: {e}")
    RatsNode = None


@unittest.skipIf(RatsNode is None, "librats_py not available")
class TestRatsNode(unittest.TestCase):
    def setUp(self):
        self.node = None
        self.events = []
        self.lock = threading.Lock()

    def tearDown(self):
        if self.node:
            self.node.destroy()

    def recorder(self, tag):
        def cb(*args):
            with self.lock:
                self.events.append((tag, args))
        return cb

    # ---- construction ----

    def test_create(self):
        self.node = RatsNode(0)
        self.assertIsNotNone(self.node)

    def test_create_with_config(self):
        self.node = RatsNode(
            0, security=Security.PLAINTEXT, protocol="myapp/2.0", max_peers=10)
        self.assertEqual(self.node.protocol, "myapp/2.0")
        self.assertEqual(self.node.max_peers, 10)

    def test_context_manager_releases_the_node(self):
        with RatsNode(0) as node:
            self.assertFalse(node.is_running())
            node.start()
        with self.assertRaises(RatsError):
            node.listen_port

    # ---- lifecycle ----

    def test_start_stop(self):
        self.node = RatsNode(0)
        self.assertFalse(self.node.is_running())
        self.node.start()
        self.assertTrue(self.node.is_running())
        self.node.stop()
        self.assertFalse(self.node.is_running())

    def test_destroy_is_idempotent_and_leaves_the_node_inert(self):
        node = RatsNode(0)
        node.destroy()
        node.destroy()
        with self.assertRaises(RatsError):
            node.local_id

    # ---- identity / info ----

    def test_local_id_is_hex(self):
        self.node = RatsNode(0)
        local_id = self.node.local_id
        self.assertIsInstance(local_id, str)
        self.assertEqual(len(local_id), 64)
        int(local_id, 16)  # raises if not hex

    def test_transports_reported_after_start(self):
        self.node = RatsNode(0)
        self.assertEqual(self.node.transports, 0)
        self.node.start()
        self.assertTrue(self.node.transports & (TransportMask.TCP | TransportMask.UDP))

    def test_peer_count_zero(self):
        self.node = RatsNode(0)
        self.assertEqual(self.node.peer_count, 0)
        self.assertEqual(self.node.peer_ids, [])

    def test_max_peers_is_settable(self):
        self.node = RatsNode(0)
        self.node.max_peers = 20
        self.assertEqual(self.node.max_peers, 20)

    def test_transport_of_unconnected_peer_is_none(self):
        self.node = RatsNode(0)
        self.node.start()
        self.assertIsNone(self.node.peer_transport("0" * 64))
        self.assertIsNone(self.node.peer_transports("0" * 64))

    # ---- the before-start contract ----

    def test_register_callbacks_before_start(self):
        self.node = RatsNode(0)
        self.node.on_peer_connected(self.recorder("connected"))
        self.node.on_peer_disconnected(self.recorder("disconnected"))
        self.node.on("chat", self.recorder("msg"))
        self.node.start()

    def test_enable_subsystems_before_start(self):
        self.node = RatsNode(0)
        self.node.enable_pubsub()
        self.node.enable_json()
        self.node.enable_file_transfer()
        self.node.enable_ping()
        self.node.enable_reconnect()
        self.node.enable_mdns()
        self.node.enable_hole_punch()
        self.node.start()
        self.assertEqual(self.node.nat_mapping, NatMapping.UNKNOWN)

    def test_subsystem_before_enable_raises(self):
        self.node = RatsNode(0)
        self.node.start()
        with self.assertRaises(RatsNotEnabledError):
            self.node.publish("topic", b"data")

    def test_enable_after_start_raises(self):
        self.node = RatsNode(0)
        self.node.start()
        with self.assertRaises(RatsAlreadyStartedError):
            self.node.enable_pubsub()


@unittest.skipIf(RatsNode is None, "librats_py not available")
class TestModuleHelpers(unittest.TestCase):
    def test_library_info(self):
        self.assertIsInstance(version(), str)
        self.assertIsInstance(git_describe(), str)
        self.assertIsInstance(abi(), int)
        self.assertGreaterEqual(version_info().major, 0)

    def test_logging(self):
        set_log_level(LogLevel.INFO)
        set_log_level(LogLevel.DEBUG)
        set_log_file(None)


class TestEnumsAndExceptions(unittest.TestCase):
    def test_log_level(self):
        from librats_py import LogLevel
        self.assertEqual((LogLevel.DEBUG, LogLevel.INFO, LogLevel.WARN, LogLevel.ERROR),
                         (0, 1, 2, 3))

    def test_transport_masks(self):
        from librats_py import Transport, TransportMask
        self.assertEqual((Transport.TCP, Transport.UDP), (0, 1))
        self.assertEqual((TransportMask.TCP, TransportMask.UDP), (0x1, 0x2))

    def test_nat_mapping(self):
        from librats_py import NatMapping
        self.assertEqual(NatMapping.UNKNOWN, 0)
        self.assertEqual(NatMapping.ENDPOINT_DEPENDENT, 3)

    def test_error_codes(self):
        from librats_py import ErrorCode
        self.assertEqual(ErrorCode.OK, 0)
        self.assertEqual(ErrorCode.NOT_ENABLED, 4)

    def test_exception_str(self):
        from librats_py import RatsError, ErrorCode
        err = RatsError("boom", ErrorCode.INVALID_ARG)
        self.assertIn("INVALID_ARG", str(err))


if __name__ == "__main__":
    unittest.main()
