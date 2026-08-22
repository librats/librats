#!/usr/bin/env python3
"""
Basic node: peer events and raw-channel messaging.

Everything a node does beyond secure transport is opt-in, and every enable and
every callback goes in BEFORE start().

    python basic_client.py <listen_port>
"""

import sys

from librats_py import RatsNode, RatsError, LogLevel, TransportMask, set_log_level

CHANNEL = "chat"

COMMANDS = """
commands:
  connect <host> <port>  dial a peer
  send <peer_id> <msg>   send on the 'chat' channel to one peer
  broadcast <msg>        send on 'chat' to every peer
  peers                  list connected peers
  quit                   exit
"""


def describe(mask: int) -> str:
    names = [n for n, bit in (("tcp", TransportMask.TCP), ("udp", TransportMask.UDP))
             if mask & bit]
    return "+".join(names) or "none"


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit("usage: python basic_client.py <listen_port>")
    try:
        listen_port = int(sys.argv[1])
    except ValueError:
        sys.exit("port must be a number")

    set_log_level(LogLevel.INFO)

    with RatsNode(listen_port) as node:
        # All of this happens before start().
        node.on_peer_connected(lambda peer: print(f"+ {peer}"))
        node.on_peer_disconnected(lambda peer: print(f"- {peer}"))

        def on_chat(peer_id: str, data: bytes) -> None:
            print(f"\n[{peer_id[:16]}…] {data.decode('utf-8', 'replace')}")
            print("librats> ", end="", flush=True)

        node.on(CHANNEL, on_chat)

        node.start()
        print(f"peer id      {node.local_id}")
        print(f"listening on {node.listen_port}")
        print(f"transports   {describe(node.transports)}")
        print(COMMANDS)

        while True:
            try:
                parts = input("librats> ").strip().split()
            except (EOFError, KeyboardInterrupt):
                break
            if not parts:
                continue
            cmd, *args = parts

            try:
                if cmd in ("quit", "exit"):
                    break
                elif cmd == "connect" and len(args) == 2:
                    node.connect(args[0], int(args[1]))
                    print(f"dialing {args[0]}:{args[1]}…")
                elif cmd == "send" and len(args) >= 2:
                    node.send(args[0], CHANNEL, " ".join(args[1:]).encode())
                elif cmd == "broadcast" and args:
                    node.broadcast(CHANNEL, " ".join(args).encode())
                elif cmd == "peers":
                    print("\n".join(node.peer_ids) or "(none)")
                else:
                    print(f"unknown command: {' '.join(parts)}")
            except RatsError as exc:
                print(f"error: {exc}")

    print("\nstopped")


if __name__ == "__main__":
    main()
