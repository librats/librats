#!/usr/bin/env python3
"""
File transfer example using librats.

Demonstrates the push-model file-transfer subsystem: one peer offers a file,
the other accepts it. The file-transfer subsystem and its callbacks must be
enabled/registered before ``start()``.
"""

import os
import sys

from librats_py import RatsNode, RatsError, LogLevel, FileTransferStatus, set_log_level


class FileTransferExample:
    def __init__(self, listen_port: int, download_dir: str):
        self.listen_port = listen_port
        self.download_dir = download_dir
        os.makedirs(download_dir, exist_ok=True)

        self.node = RatsNode(listen_port)

        # Register callbacks + enable subsystem BEFORE start().
        self.node.on_peer_connected(lambda pid: print(f"+ Peer connected: {pid}"))
        self.node.on_peer_disconnected(
            lambda pid, why: print(f"- Peer disconnected: {pid} ({why})"))

        self.node.enable_file_transfer(temp_dir=download_dir)
        self.node.on_file_offer(self.on_offer)
        self.node.on_file_progress(self.on_progress)
        self.node.on_file_complete(self.on_complete)

    def on_offer(self, peer_id, transfer_id, name, size, is_directory):
        kind = "directory" if is_directory else "file"
        print(f"\nIncoming {kind} offer '{name}' ({size} bytes) "
              f"from {peer_id[:16]}… (transfer {transfer_id})")
        dest = os.path.join(self.download_dir, name)
        # Auto-accept for the demo.
        self.node.accept_file(peer_id, transfer_id, dest)
        print(f"Accepted → {dest}")

    def on_progress(self, transfer_id, peer_id, done, total, status):
        pct = (done * 100 // total) if total else 0
        print(f"  transfer {transfer_id}: {pct}% ({done}/{total}) "
              f"[{FileTransferStatus(status).name}]")

    def on_complete(self, transfer_id, success, path):
        state = "completed" if success else "failed"
        print(f"\nTransfer {transfer_id} {state}: {path}")

    def start(self):
        self.node.start()
        print(f"File transfer client on port {self.listen_port}")
        print(f"Local peer id: {self.node.local_id}")

    def stop(self):
        self.node.stop()

    def run(self):
        print("\nCommands:")
        print("  connect <host> <port>        - dial a peer")
        print("  send <peer_id> <file_path>   - offer a file")
        print("  senddir <peer_id> <dir_path> - offer a directory")
        print("  peers                        - list peers")
        print("  quit                         - exit")
        print()
        while True:
            try:
                parts = input("file-transfer> ").strip().split()
            except (EOFError, KeyboardInterrupt):
                break
            if not parts:
                continue
            cmd = parts[0].lower()
            try:
                if cmd in ("quit", "exit"):
                    break
                elif cmd == "connect" and len(parts) == 3:
                    self.node.connect(parts[1], int(parts[2]))
                    print(f"Dialing {parts[1]}:{parts[2]}…")
                elif cmd == "send" and len(parts) == 3:
                    if not os.path.exists(parts[2]):
                        print("File not found.")
                        continue
                    tid = self.node.send_file(parts[1], parts[2])
                    print(f"Offered file (transfer {tid})")
                elif cmd == "senddir" and len(parts) == 3:
                    tid = self.node.send_directory(parts[1], parts[2])
                    print(f"Offered directory (transfer {tid})")
                elif cmd == "peers":
                    for pid in self.node.peer_ids:
                        print(f"  - {pid}")
                else:
                    print("Unknown/invalid command.")
            except RatsError as e:
                print(f"Error: {e}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python file_transfer.py <listen_port> [download_dir]")
        sys.exit(1)
    try:
        listen_port = int(sys.argv[1])
    except ValueError:
        print("Error: Port must be a number")
        sys.exit(1)
    download_dir = sys.argv[2] if len(sys.argv) > 2 else "./downloads"

    set_log_level(LogLevel.INFO)
    example = FileTransferExample(listen_port, download_dir)
    try:
        example.start()
        example.run()
    finally:
        example.stop()


if __name__ == "__main__":
    main()
