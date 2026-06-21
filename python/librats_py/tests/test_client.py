"""
Unit tests for RatsClient against the new librats C ABI.

These are not run as part of this change; they document expected behaviour and
require the native shared library to be built and importable.
"""

import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from librats_py import RatsClient, RatsError, LogLevel, Security
    from librats_py.enums import RatsError as ErrorCode
    from librats_py.exceptions import (
        RatsInvalidArgError, RatsNotEnabledError, RatsAlreadyStartedError,
    )
except ImportError as e:  # native lib not built yet
    print(f"Warning: Could not import librats_py: {e}")
    RatsClient = None


@unittest.skipIf(RatsClient is None, "librats_py not available")
class TestRatsClient(unittest.TestCase):
    def setUp(self):
        self.client = None
        self.events = []
        self.lock = threading.Lock()

    def tearDown(self):
        if self.client:
            try:
                self.client.stop()
            except Exception:
                pass

    def recorder(self, tag):
        def cb(*args):
            with self.lock:
                self.events.append((tag, args))
        return cb

    def test_create(self):
        self.client = RatsClient(0)
        self.assertIsNotNone(self.client)

    def test_create_with_config(self):
        self.client = RatsClient(
            0, security=Security.PLAINTEXT, protocol_name="myapp",
            protocol_version="2.0", max_peers=10)
        self.assertEqual(self.client.protocol_name, "myapp")
        self.assertEqual(self.client.protocol_version, "2.0")
        self.assertEqual(self.client.get_max_peers(), 10)

    def test_context_manager(self):
        with RatsClient(0) as client:
            self.assertFalse(client.is_running())

    def test_start_stop(self):
        self.client = RatsClient(0)
        self.assertFalse(self.client.is_running())
        self.client.start()
        self.assertTrue(self.client.is_running())
        self.client.stop()
        self.assertFalse(self.client.is_running())

    def test_local_id_is_hex(self):
        self.client = RatsClient(0)
        local_id = self.client.local_id
        self.assertIsInstance(local_id, str)
        self.assertEqual(len(local_id), 64)
        int(local_id, 16)  # raises if not hex

    def test_peer_count_zero(self):
        self.client = RatsClient(0)
        self.assertEqual(self.client.peer_count(), 0)
        self.assertEqual(self.client.peer_ids(), [])

    def test_max_peers(self):
        self.client = RatsClient(0)
        self.client.set_max_peers(20)
        self.assertEqual(self.client.get_max_peers(), 20)

    def test_register_callbacks_before_start(self):
        self.client = RatsClient(0)
        self.client.on_peer_connected(self.recorder("connected"))
        self.client.on_peer_disconnected(self.recorder("disconnected"))
        self.client.on("chat", self.recorder("msg"))
        self.client.start()

    def test_enable_subsystems_before_start(self):
        self.client = RatsClient(0)
        self.client.enable_pubsub()
        self.client.enable_json()
        self.client.enable_file_transfer()
        self.client.enable_ping()
        self.client.enable_reconnect()
        self.client.enable_mdns()
        self.client.start()

    def test_subsystem_before_enable_raises(self):
        self.client = RatsClient(0)
        self.client.start()
        with self.assertRaises(RatsNotEnabledError):
            self.client.publish("topic", b"data")

    def test_enable_after_start_raises(self):
        self.client = RatsClient(0)
        self.client.start()
        with self.assertRaises(RatsAlreadyStartedError):
            self.client.enable_pubsub()

    def test_static_info(self):
        self.assertIsInstance(RatsClient.get_version_string(), str)
        self.assertIsInstance(RatsClient.get_abi(), int)
        version = RatsClient.get_version()
        self.assertGreaterEqual(version.major, 0)

    def test_static_logging(self):
        RatsClient.set_log_level(LogLevel.INFO)
        RatsClient.set_log_level(LogLevel.DEBUG)
        RatsClient.set_log_file(None)


class TestEnumsAndExceptions(unittest.TestCase):
    def test_log_level(self):
        from librats_py import LogLevel
        self.assertEqual((LogLevel.DEBUG, LogLevel.INFO, LogLevel.WARN, LogLevel.ERROR),
                         (0, 1, 2, 3))

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
