"""Single-node tests of RatsNode against the librats shared library."""

import pytest

from librats_py import (
    RatsNode, RatsError, RatsInvalidArgError, RatsNotEnabledError, RatsNotStartedError,
    RatsAlreadyStartedError, RatsNotFoundError, RatsDeclinedError, ErrorCode, LogLevel,
    Security, Transport, TransportMask, NatMapping, CloseReason, Direction,
    FALLBACK_NEVER, version, version_info, abi, git_describe, error_str, set_log_level,
    set_log_file,
)

native = pytest.mark.native


@pytest.fixture
def node():
    n = RatsNode(bind_address="127.0.0.1")
    yield n
    n.destroy()


@native
def test_defaults(node):
    assert len(node.local_id) == 64
    int(node.local_id, 16)
    assert node.protocol == "librats/1.0"
    assert node.transports == TransportMask.NONE
    assert node.listen_port == 0
    node.start()
    assert node.running
    assert node.listen_port != 0
    assert node.transports == TransportMask.TCP | TransportMask.UDP
    assert node.peer_count == 0 and node.peer_ids == []
    assert node.nat_mapping == NatMapping.UNKNOWN
    assert node.observed_addresses == []
    node.stop()
    node.stop()
    assert not node.running
    assert node.transports == TransportMask.NONE


@native
def test_config_keywords_reach_the_node():
    with RatsNode(security=Security.PLAINTEXT, protocol="myapp/2.0", max_peers=10,
                  transports=TransportMask.TCP, transport_fallback_ms=FALLBACK_NEVER,
                  udp_offload=False, reactor_threads=2, network_monitor=False) as n:
        assert n.protocol == "myapp/2.0"
        assert n.max_peers == 10
        n.start()
        assert n.transports == TransportMask.TCP


@native
def test_impossible_config_is_refused():
    with pytest.raises(RatsInvalidArgError):
        RatsNode(transports=TransportMask.UDP, preferred_transport=Transport.TCP)
    with pytest.raises(RatsInvalidArgError):
        RatsNode(preferred_transport=Transport.RELAY)


@native
def test_destroyed_node_is_inert():
    with RatsNode() as n:
        n.start()
    with pytest.raises(RatsError):
        n.local_id
    n.destroy()   # idempotent


@native
def test_lifecycle_rules(node):
    with pytest.raises(RatsNotStartedError):
        node.connect("127.0.0.1", 1)
    node.start()
    with pytest.raises(RatsAlreadyStartedError):
        node.start()
    with pytest.raises(RatsAlreadyStartedError):
        node.enable_pubsub()
    with pytest.raises(RatsAlreadyStartedError):
        node.on_peer_connected(lambda peer: None)
    with pytest.raises(RatsNotEnabledError):
        node.publish("topic", b"data")


@native
def test_unknown_peer(node):
    node.start()
    other = "0" * 64
    assert node.peer_info(other) is None
    assert node.path_stats(other) is None
    assert node.peer_writable(other) is False
    assert node.peer_rtt_ms(other) is None
    with pytest.raises(RatsInvalidArgError):
        node.peer_info("not-hex")
    with pytest.raises(RatsError) as e:
        node.send(other, "chat", b"x")
    assert e.value.error_code == ErrorCode.NO_SUCH_PEER


@native
def test_every_subsystem_enables_before_start(node):
    node.enable_dht()
    node.enable_mdns()
    node.enable_peer_exchange()
    node.enable_port_mapping(upnp=False, natpmp=False)
    node.enable_hole_punch()
    node.enable_relay()
    node.enable_pubsub()
    node.enable_json()
    node.enable_file_transfer()
    node.enable_ping()
    node.enable_reconnect()
    node.enable_pubsub()   # idempotent
    node.start()
    with pytest.raises(RatsDeclinedError):
        node.punch_peer("0" * 64)
    with pytest.raises(RatsNotFoundError):
        node.cancel_file(node.local_id, 999999)


@native
def test_max_peers_is_settable(node):
    node.max_peers = 20
    assert node.max_peers == 20


@native
def test_library_info_and_logging():
    assert version()
    assert isinstance(git_describe(), str)
    info = version_info()
    assert abi() == (info.major << 16) | (info.minor << 8) | info.patch
    assert error_str(ErrorCode.DECLINED) == "RATS_ERR_DECLINED"
    set_log_level(LogLevel.WARN)
    set_log_file(None)


def test_enums_mirror_the_c_abi():
    assert (Transport.UDP, Transport.TCP, Transport.RELAY) == (0, 1, 2)
    assert (TransportMask.TCP, TransportMask.UDP) == (0x1, 0x2)
    assert (Direction.OUTBOUND, Direction.INBOUND) == (0, 1)
    assert CloseReason.SLOW_CONSUMER == 6 and CloseReason.DIAL_SUPERSEDED == 11
    assert (ErrorCode.NOT_FOUND, ErrorCode.DECLINED, ErrorCode.BIND, ErrorCode.INTERNAL) == (6, 7, 8, 9)
    assert NatMapping.ENDPOINT_DEPENDENT == 3


def test_exception_carries_its_code():
    assert RatsNotFoundError("x").error_code == ErrorCode.NOT_FOUND
    assert "INVALID_ARG" in str(RatsError("boom", ErrorCode.INVALID_ARG))
