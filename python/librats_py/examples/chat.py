#!/usr/bin/env python3
"""
A chat with no server. Everyone who runs it with the same room name is in the
same chat: nodes on one network find each other over mDNS, nodes elsewhere
through the DHT, and /connect dials someone directly.

    python -m librats_py.examples.chat <name> [room] [port]
"""

import sys

from librats_py import RatsNode, RatsError, LogLevel, set_log_level


def short(peer_id: str) -> str:
    return peer_id[:8]


def main() -> None:
    name = sys.argv[1] if len(sys.argv) > 1 else "anon"
    room = sys.argv[2] if len(sys.argv) > 2 else "lobby"
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 0
    set_log_level(LogLevel.ERROR)   # library logs would interleave with the chat

    # The protocol is bound into the handshake: only nodes in the same room can
    # connect, and the DHT, which searches by protocol, looks for exactly them.
    node = RatsNode(port, protocol=f"rats-chat/{room}")
    node.enable_mdns()   # the local network
    node.enable_dht()    # the internet
    node.enable_json()   # messages are {"name": ..., "text": ...} objects

    def on_say(peer_id, msg):
        # Anything can arrive from a peer, so check the shape before using it.
        if not isinstance(msg, dict) or not isinstance(msg.get("text"), str):
            return
        print(f"{str(msg.get('name'))[:32]}: {msg['text']}", flush=True)

    node.on_peer_connected(lambda peer_id: print(f"* {short(peer_id)} joined", flush=True))
    node.on_peer_disconnected(
        lambda peer_id, reason: print(f"* {short(peer_id)} left ({reason.name.lower()})", flush=True))
    node.on_json("say", on_say)

    with node:   # destroys the node on the way out
        node.start()
        print(f'room "{room}", port {node.listen_port}, id {short(node.local_id)}')
        print("/connect <host> <port>, /peers, /quit\n", flush=True)
        try:
            for line in sys.stdin:   # ends on Ctrl+D (Ctrl+Z, Enter on Windows)
                command, *args = line.split() or [""]
                try:
                    if command == "/connect":
                        node.connect(args[0], int(args[1]))
                    elif command == "/peers":
                        print(" ".join(map(short, node.peer_ids)) or "nobody yet")
                    elif command == "/quit":
                        break
                    elif line.strip():
                        node.broadcast_json("say", {"name": name, "text": line.strip()})
                except (RatsError, ValueError, IndexError) as e:
                    print(f"! {e}")
        except KeyboardInterrupt:   # Ctrl+C
            pass


if __name__ == "__main__":
    main()
