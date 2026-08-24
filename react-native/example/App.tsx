/**
 * librats React Native example.
 *
 * Runs the same check as the Swift smoke test, but through JS: two nodes are
 * created in-process, one dials the other over the loopback, they complete a
 * Noise handshake, and a message is echoed back. That makes the app
 * self-verifying on a single device — no second phone needed to prove the
 * binding works.
 */
import React, { useCallback, useRef, useState } from 'react';
import {
  ActivityIndicator,
  ScrollView,
  StyleSheet,
  Text,
  TouchableOpacity,
  View,
} from 'react-native';
import {
  SafeAreaProvider,
  SafeAreaView,
} from 'react-native-safe-area-context';
import {
  createNode,
  decodeUtf8,
  encodeUtf8,
  type RatsNode,
} from 'react-native-librats';

type Status = 'idle' | 'running' | 'pass' | 'fail';

const CHANNEL = 'chat';
const MESSAGE = 'hello from react native';

function Demo() {
  const [log, setLog] = useState<string[]>([]);
  const [status, setStatus] = useState<Status>('idle');
  const nodes = useRef<RatsNode[]>([]);

  const append = useCallback((line: string) => {
    setLog(prev => [...prev, line]);
  }, []);

  const stopAll = useCallback(() => {
    for (const node of nodes.current) {
      node.stop();
    }
    nodes.current = [];
  }, []);

  const run = useCallback(async () => {
    stopAll();
    setLog([]);
    setStatus('running');

    try {
      // Configure before attaching listeners: librats fixes configuration when
      // the node is constructed, and expects handlers registered before start().
      const server = createNode({ listenPort: 0, protocol: 'example/1.0' });
      const client = createNode({
        listenPort: 0,
        protocol: 'example/1.0',
        enableListen: false, // dial-only, the usual shape for a mobile peer
      });
      nodes.current = [server, client];

      // The server echoes whatever arrives straight back to the sender.
      server.onMessage(CHANNEL, (peerId, data) => {
        server.send(peerId, CHANNEL, data);
      });

      const echoed = new Promise<string>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('no echo within 15s')), 15000);
        client.onMessage(CHANNEL, (_peerId, data) => {
          clearTimeout(timer);
          resolve(decodeUtf8(data));
        });
      });

      const connected = new Promise<string>((resolve, reject) => {
        const timer = setTimeout(
          () => reject(new Error('no handshake within 15s')),
          15000,
        );
        client.onPeerConnected(peerId => {
          clearTimeout(timer);
          resolve(peerId);
        });
      });

      client.onPeerDisconnected(peerId =>
        append(`client: peer ${peerId.slice(0, 8)} disconnected`),
      );

      if (!server.start()) throw new Error('server failed to start');
      if (!client.start()) throw new Error('client failed to start');

      append(`server id   ${server.localId.slice(0, 16)}...`);
      append(`server port ${server.listenPort}`);
      append(`client id   ${client.localId.slice(0, 16)}...`);

      client.connect('127.0.0.1', server.listenPort);
      append('dialing 127.0.0.1...');

      const peerId = await connected;
      append(`handshake complete with ${peerId.slice(0, 8)}`);
      append(`client peers: ${client.peerCount}`);

      const sent = client.send(peerId, CHANNEL, encodeUtf8(MESSAGE));
      append(`sent (accepted=${sent}): "${MESSAGE}"`);

      const reply = await echoed;
      if (reply !== MESSAGE) {
        throw new Error(`echo mismatch: got "${reply}"`);
      }
      append(`echo verified: "${reply}"`);

      stopAll();
      append('nodes stopped');
      setStatus('pass');
    } catch (error) {
      append(`ERROR: ${error instanceof Error ? error.message : String(error)}`);
      stopAll();
      setStatus('fail');
    }
  }, [append, stopAll]);

  return (
    <SafeAreaView style={styles.screen}>
      <Text style={styles.title}>librats</Text>
      <Text style={styles.subtitle}>
        two nodes, one loopback handshake, one echo
      </Text>

      <TouchableOpacity
        style={[styles.button, status === 'running' && styles.buttonDisabled]}
        onPress={run}
        disabled={status === 'running'}>
        <Text style={styles.buttonText}>
          {status === 'running' ? 'running...' : 'run test'}
        </Text>
      </TouchableOpacity>

      <View style={styles.statusRow}>
        {status === 'running' && <ActivityIndicator />}
        {status === 'pass' && <Text style={styles.pass}>PASS</Text>}
        {status === 'fail' && <Text style={styles.fail}>FAIL</Text>}
      </View>

      <ScrollView style={styles.log} contentContainerStyle={styles.logContent}>
        {log.map((line, i) => (
          <Text key={i} style={styles.logLine}>
            {line}
          </Text>
        ))}
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  screen: { flex: 1, backgroundColor: '#0d1117', padding: 20 },
  title: { fontSize: 32, fontWeight: '700', color: '#e6edf3' },
  subtitle: { fontSize: 14, color: '#8b949e', marginBottom: 24 },
  button: {
    backgroundColor: '#238636',
    paddingVertical: 14,
    borderRadius: 8,
    alignItems: 'center',
  },
  buttonDisabled: { backgroundColor: '#30363d' },
  buttonText: { color: '#fff', fontSize: 16, fontWeight: '600' },
  statusRow: { height: 40, justifyContent: 'center', alignItems: 'center' },
  pass: { color: '#3fb950', fontSize: 20, fontWeight: '700' },
  fail: { color: '#f85149', fontSize: 20, fontWeight: '700' },
  log: { flex: 1, backgroundColor: '#161b22', borderRadius: 8 },
  logContent: { padding: 12 },
  logLine: {
    color: '#c9d1d9',
    fontFamily: 'Menlo',
    fontSize: 12,
    marginBottom: 4,
  },
});

export default function App() {
  return (
    <SafeAreaProvider>
      <Demo />
    </SafeAreaProvider>
  );
}
