#!/usr/bin/env python3
"""
GossipSub chat room example using librats.

Demonstrates the pub/sub subsystem. The subsystem must be enabled and topics
subscribed before ``start()``.
"""

import json
import sys
from datetime import datetime

from librats_py import RatsClient, RatsError, LogLevel


class GossipSubChat:
    def __init__(self, listen_port: int, username: str, topic: str):
        self.listen_port = listen_port
        self.username = username
        self.topic = topic
        self.client = RatsClient(listen_port)

        # Enable + subscribe BEFORE start().
        self.client.on_peer_connected(lambda pid: self._print(f"+ {pid[:16]}… joined"))
        self.client.on_peer_disconnected(lambda pid: self._print(f"- {pid[:16]}… left"))
        self.client.enable_pubsub()
        self.client.subscribe(topic, self.on_topic_message)

    def _print(self, line):
        print(f"\n{line}")
        print(f"[{self.topic}]> ", end="", flush=True)

    def on_topic_message(self, peer_id, topic, data):
        try:
            msg = json.loads(data.decode('utf-8'))
            if msg.get('type') == 'chat':
                self._print(f"{msg.get('username', '?')}: {msg.get('content', '')}")
                return
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass
        self._print(f"{peer_id[:16]}…: {data!r}")

    def start(self):
        self.client.start()
        print(f"GossipSub chat on port {self.listen_port}")
        print(f"Local peer id: {self.client.local_id}")
        print(f"Username: {self.username}   Topic: {self.topic}")
        self._publish('join', '')

    def stop(self):
        try:
            self._publish('leave', '')
        except RatsError:
            pass
        self.client.stop()

    def _publish(self, kind, content):
        payload = {
            'type': kind,
            'username': self.username,
            'content': content,
            'timestamp': datetime.now().isoformat(),
        }
        self.client.publish(self.topic, json.dumps(payload).encode('utf-8'))

    def run(self):
        print("\nCommands: connect <host> <port> | peers | quit | <message>\n")
        while True:
            try:
                line = input(f"[{self.topic}]> ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if not line:
                continue
            parts = line.split()
            cmd = parts[0].lower()
            try:
                if cmd in ("quit", "exit"):
                    break
                elif cmd == "connect" and len(parts) == 3:
                    self.client.connect(parts[1], int(parts[2]))
                    print(f"Dialing {parts[1]}:{parts[2]}…")
                elif cmd == "peers":
                    for pid in self.client.peer_ids():
                        print(f"  - {pid}")
                else:
                    self._publish('chat', line)
            except RatsError as e:
                print(f"Error: {e}")


def main():
    if len(sys.argv) < 3:
        print("Usage: python gossipsub_chat.py <listen_port> <username> [topic]")
        sys.exit(1)
    try:
        listen_port = int(sys.argv[1])
    except ValueError:
        print("Error: Port must be a number")
        sys.exit(1)
    username = sys.argv[2].strip()
    topic = sys.argv[3] if len(sys.argv) > 3 else "general"
    if not username:
        print("Error: Username cannot be empty")
        sys.exit(1)

    RatsClient.set_log_level(LogLevel.INFO)
    chat = GossipSubChat(listen_port, username, topic)
    try:
        chat.start()
        chat.run()
    finally:
        chat.stop()


if __name__ == "__main__":
    main()
