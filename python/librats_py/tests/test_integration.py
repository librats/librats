"""Two and three live nodes over loopback."""

import os
import tempfile
import time

import pytest

from librats_py import (
    RatsNode, RatsNoSuchPeerError, CloseReason, Direction, FileTransferStatus, Transport,
    TransportMask,
)

pytestmark = pytest.mark.native


def wait_for(pred, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(0.01)
    return pred()


@pytest.fixture
def nodes():
    made = []

    def make(**kw):
        kw.setdefault("bind_address", "127.0.0.1")
        n = RatsNode(**kw)
        made.append(n)
        return n

    yield make
    for n in made:
        n.destroy()


def link(client, server):
    server.start()
    client.start()
    client.connect("127.0.0.1", server.listen_port)
    assert wait_for(lambda: client.peer_count == 1 and server.peer_count == 1)


def test_channel_message_info_and_disconnect(nodes):
    server, client = nodes(), nodes(dial_only=True)
    got, gone = [], []
    server.on("chat", lambda peer, data: got.append((peer, data)))
    server.on_peer_disconnected(lambda peer, why: gone.append(why))
    link(client, server)

    sid, cid = server.local_id, client.local_id
    assert client.peer_ids == [sid]
    client.send(sid, "chat", b"hello\x00world")
    assert wait_for(lambda: got == [(cid, b"hello\x00world")])

    info = client.peer_info(sid)
    assert info.direction == Direction.OUTBOUND
    assert info.transport == Transport.UDP
    assert info.address.endswith(f":{server.listen_port}")
    assert wait_for(lambda: client.peer_info(sid).transports
                    == TransportMask.TCP | TransportMask.UDP)
    assert server.peer_info(cid).direction == Direction.INBOUND

    client.disconnect(sid)
    assert wait_for(lambda: client.peer_count == 0 and gone)
    assert isinstance(gone[0], CloseReason) and gone[0] != CloseReason.SLOW_CONSUMER
    with pytest.raises(RatsNoSuchPeerError):
        client.disconnect(sid)


def test_live_message_and_path_stats(nodes):
    server, client = nodes(), nodes(dial_only=True)
    got, samples = [], []
    server.on("video", lambda peer, data: got.append(data))
    client.on_peer_path(lambda peer, stats: samples.append(stats))
    link(client, server)

    frame = b"k" * 20000
    client.send(server.local_id, "video", frame, lifetime_ms=500)
    assert wait_for(lambda: got == [frame])

    def counted():
        stats = client.path_stats(server.local_id)
        return stats is not None and stats.live_sent == 1
    assert wait_for(counted)
    assert wait_for(lambda: len(samples) >= 2)
    assert samples[-1].srtt_us > 0


def test_dial_failed_names_the_address(nodes):
    closed = nodes()
    closed.start()
    port = closed.listen_port
    closed.destroy()

    client = nodes(dial_only=True)
    failed = []
    client.on_dial_failed(failed.append)
    client.start()
    client.connect("127.0.0.1", port)
    assert wait_for(lambda: failed, timeout=15)
    assert failed[0] == f"127.0.0.1:{port}"


def test_pubsub_and_json(nodes):
    a, b = nodes(), nodes()
    received, values = [], []
    for n in (a, b):
        n.enable_pubsub()
        n.enable_json()
    a.subscribe("room", lambda peer, topic, data: received.append((topic, data)))
    b.subscribe("room", lambda peer, topic, data: None)
    a.on_json("greeting", lambda peer, value: values.append(value))
    link(b, a)

    def published():
        b.publish("room", b"payload")
        return ("room", b"payload") in received
    assert wait_for(published)

    b.broadcast_json("greeting", {"hi": "there", "n": 7})
    assert wait_for(lambda: {"hi": "there", "n": 7} in values)


def test_file_transfer(nodes):
    a, b = nodes(), nodes()
    for n in (a, b):
        n.enable_file_transfer()
    dest_dir = tempfile.mkdtemp()
    done, progress = [], []

    a.on_file_offer(lambda peer, tid, name, size, is_dir:
                    a.accept_file(peer, tid, os.path.join(dest_dir, name)))
    a.on_file_progress(progress.append)
    a.on_file_complete(lambda peer, tid, ok, path: done.append((peer, tid, ok, path)))
    link(b, a)

    with tempfile.NamedTemporaryFile("wb", delete=False, suffix=".bin") as f:
        f.write(b"payload" * 1000)
        src = f.name
    try:
        tid = b.send_file(a.local_id, src)
        assert wait_for(lambda: done)
        peer, got_tid, ok, path = done[0]
        assert (peer, got_tid, ok) == (b.local_id, tid, True)
        with open(path, "rb") as f:
            assert f.read() == b"payload" * 1000
        assert any(p.direction == Direction.INBOUND and p.transfer_id == tid for p in progress)
        assert all(isinstance(p.status, FileTransferStatus) for p in progress)
    finally:
        os.unlink(src)


def test_peer_exchange_introduces_peers(nodes):
    hub, a, b = nodes(), nodes(), nodes()
    for n in (hub, a, b):
        n.enable_peer_exchange()
        n.start()
    a.connect("127.0.0.1", hub.listen_port)
    assert wait_for(lambda: hub.peer_count == 1)
    b.connect("127.0.0.1", hub.listen_port)
    assert wait_for(lambda: a.peer_count == 2 and b.peer_count == 2, timeout=15)


def test_relay(nodes):
    hub, a, b = nodes(), nodes(), nodes()
    hub.enable_relay(serve=True)
    a.enable_relay()
    b.enable_relay()
    for n in (hub, a, b):
        n.start()
    a.connect("127.0.0.1", hub.listen_port)
    b.connect("127.0.0.1", hub.listen_port)
    assert wait_for(lambda: hub.peer_count == 2)
    a.connect_via_relay(b.local_id)
    assert wait_for(lambda: a.peer_count == 2 and b.peer_count == 2, timeout=20)
    assert a.peer_info(b.local_id).transport == Transport.RELAY
