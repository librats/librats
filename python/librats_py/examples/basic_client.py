#!/usr/bin/env python3
"""
Basic librats client example.

Demonstrates peer-to-peer messaging over a named channel using the new C ABI.
Callbacks and subsystems must be registered/enabled before ``start()``.
"""

import sys
from librats_py import RatsClient, RatsError, LogLevel


def main():
    if len(sys.argv) != 2:
        print("Usage: python basic_client.py <listen_port>")
        print("Example: python basic_client.py 8080")
        sys.exit(1)

    try:
        listen_port = int(sys.argv[1])
    except ValueError:
        print("Error: Port must be a number")
        sys.exit(1)

    RatsClient.set_log_level(LogLevel.INFO)

    CHANNEL = "chat"

    with RatsClient(listen_port) as client:
        print(f"Starting librats client on port {listen_port}")

        # Register callbacks BEFORE start().
        client.on_peer_connected(lambda pid: print(f"+ Peer connected: {pid}"))
        client.on_peer_disconnected(lambda pid: print(f"- Peer disconnected: {pid}"))

        def on_chat(peer_id, data):
            print(f"\n[{peer_id[:16]}…] {data.decode('utf-8', 'replace')}")
            print("librats> ", end="", flush=True)

        client.on(CHANNEL, on_chat)

        client.start()
        print("Client started.")
        print(f"Local peer id: {client.local_id}")
        print(f"Listening on port: {client.listen_port}")

        print("\nCommands:")
        print("  connect <host> <port>  - dial a peer")
        print("  send <peer_id> <msg>   - send on the 'chat' channel to a peer")
        print("  broadcast <msg>        - broadcast on 'chat' to all peers")
        print("  peers                  - list connected peers")
        print("  quit                   - exit")
        print()

        while True:
            try:
                parts = input("librats> ").strip().split()
            except (EOFError, KeyboardInterrupt):
                break
            if not parts:
                continue
            cmd = parts[0].lower()

            try:
                if cmd in ("quit", "exit"):
                    break
                elif cmd == "connect" and len(parts) == 3:
                    client.connect(parts[1], int(parts[2]))
                    print(f"Dialing {parts[1]}:{parts[2]}…")
                elif cmd == "send" and len(parts) >= 3:
                    client.send(parts[1], CHANNEL, " ".join(parts[2:]).encode())
                    print("Sent.")
                elif cmd == "broadcast" and len(parts) >= 2:
                    client.broadcast(CHANNEL, " ".join(parts[1:]).encode())
                    print("Broadcasted.")
                elif cmd == "peers":
                    ids = client.peer_ids()
                    print(f"Connected peers ({len(ids)}):")
                    for pid in ids:
                        rtt = ""
                        print(f"  - {pid}{rtt}")
                else:
                    print(f"Unknown/invalid command: {' '.join(parts)}")
            except RatsError as e:
                print(f"Error: {e}")

        print("\nShutting down…")


if __name__ == "__main__":
    main()
