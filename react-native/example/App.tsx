/**
 * librats React Native example.
 *
 * Two self-verifying tests, both run with a pair of nodes inside this one
 * process so a single device is enough to prove the binding works:
 *
 *   chat - one node dials the other over the loopback, they complete a Noise
 *          handshake, and a message comes back echoed.
 *   file - one node offers a 512 KiB file, the other accepts it, and the
 *          received bytes are compared against what was sent.
 */
import React, { useCallback, useRef, useState } from 'react';
import {
  ActivityIndicator,
  Platform,
  ScrollView,
  StyleSheet,
  Text,
  TouchableOpacity,
  View,
} from 'react-native';
// Named exports only -- this package has no default export.
import {
  CachesDirectoryPath,
  exists,
  mkdir,
  readFile,
  unlink,
  writeFile,
} from '@dr.pogodin/react-native-fs';
import {
  createNode,
  decodeUtf8,
  encodeUtf8,
  type RatsNode,
} from 'react-native-librats';

type Status = 'idle' | 'running' | 'pass' | 'fail';

const CHANNEL = 'chat';
const MESSAGE = 'hello from react native';

// Comfortably larger than the 256 KiB default progress interval, so the transfer
// produces several progress events rather than completing in one step.
const FILE_BYTES = 512 * 1024;

const CACHE = CachesDirectoryPath;
const TEMP_DIR = `${CACHE}/rats-transfers`;
const SOURCE = `${CACHE}/rats-source.txt`;
const DEST = `${CACHE}/rats-received.txt`;

function timeout(ms: number, what: string): Promise<never> {
  return new Promise((_resolve, reject) =>
    setTimeout(() => reject(new Error(`${what} within ${ms / 1000}s`)), ms),
  );
}

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

  /** A connected sender/receiver pair, with file transfer enabled on both. */
  const connectPair = useCallback(async () => {
    const server = createNode({ listenPort: 0, protocol: 'example/1.0' });
    const client = createNode({
      listenPort: 0,
      protocol: 'example/1.0',
      enableListen: false, // dial-only, the usual shape for a mobile peer
    });
    nodes.current = [server, client];

    // Subsystems are opt-in and must be attached before start().
    await mkdir(TEMP_DIR);
    server.enableFileTransfer({ tempDirectory: TEMP_DIR });
    client.enableFileTransfer({ tempDirectory: TEMP_DIR });

    // Both directions are needed, and they are different ids: each side's
    // onPeerConnected reports *the other* node. Sending to the wrong one is
    // silent -- sendFile still returns a transfer id, because it only checks that
    // the file is readable, not that the peer exists.
    const serverSawClient = new Promise<string>(resolve => {
      server.onPeerConnected(resolve);
    });
    const clientSawServer = new Promise<string>(resolve => {
      client.onPeerConnected(resolve);
    });

    if (!server.start()) throw new Error('server failed to start');
    if (!client.start()) throw new Error('client failed to start');

    client.connect('127.0.0.1', server.listenPort);
    const [clientId, serverId] = await Promise.race([
      Promise.all([serverSawClient, clientSawServer]),
      timeout(15000, 'no handshake'),
    ]);
    return { server, client, clientId, serverId };
  }, []);

  const runChat = useCallback(async () => {
    stopAll();
    setLog([]);
    setStatus('running');
    try {
      const { server, client, serverId } = await connectPair();
      append(`handshake with ${serverId.slice(0, 8)}`);

      server.onMessage(CHANNEL, (from, data) => {
        server.send(from, CHANNEL, data); // echo straight back
      });
      const echoed = new Promise<string>(resolve => {
        client.onMessage(CHANNEL, (_from, data) => resolve(decodeUtf8(data)));
      });

      client.send(serverId, CHANNEL, encodeUtf8(MESSAGE));
      const reply = await Promise.race([echoed, timeout(15000, 'no echo')]);
      if (reply !== MESSAGE) throw new Error(`echo mismatch: "${reply}"`);
      append(`echo verified: "${reply}"`);

      stopAll();
      setStatus('pass');
    } catch (error) {
      append(`ERROR: ${error instanceof Error ? error.message : String(error)}`);
      stopAll();
      setStatus('fail');
    }
  }, [append, connectPair, stopAll]);

  const runFile = useCallback(async () => {
    stopAll();
    setLog([]);
    setStatus('running');
    try {
      // Contents are cheap to verify but not uniform, so a truncated or
      // misordered transfer cannot pass by accident.
      const unit = 'librats-file-transfer-';
      const body = unit
        .repeat(Math.ceil(FILE_BYTES / unit.length))
        .slice(0, FILE_BYTES);
      await writeFile(SOURCE, body, 'utf8');
      if (await exists(DEST)) {
        await unlink(DEST);
      }
      append(`wrote source: ${FILE_BYTES} bytes`);

      const { server, client, clientId } = await connectPair();
      append(`handshake with ${clientId.slice(0, 8)}`);

      // The receiver decides what to do with each offer. Ignoring one would
      // occupy the sender until it times out.
      client.onFileOffer(offer => {
        append(
          `offer: "${offer.name}" ${offer.size} bytes, ` +
            `${offer.files.length} file(s)${offer.isDirectory ? ', directory' : ''}`,
        );
        client.acceptFile(offer.peerId, offer.transferId, DEST);
      });

      let progressEvents = 0;
      client.onFileProgress(p => {
        progressEvents += 1;
        if (progressEvents === 1) {
          append(
            `first progress: ${p.percent.toFixed(0)}% ` +
              `(${p.direction}, ${p.status}) ` +
              `${(p.transferRateBps / 1024).toFixed(0)} KiB/s`,
          );
        }
      });

      const done = new Promise<string>((resolve, reject) => {
        client.onFileComplete((_id, success, path) => {
          if (success) {
            resolve(path);
          } else {
            reject(new Error('transfer reported failure'));
          }
        });
      });

      const transferId = server.sendFile(clientId, SOURCE);
      if (transferId === 0) throw new Error('sendFile rejected the source path');
      append(`sending, transfer id ${transferId}`);

      const path = await Promise.race([
        done,
        timeout(60000, 'transfer incomplete'),
      ]);
      append(`complete: ${path.replace(CACHE, '<cache>')}`);
      append(`progress events: ${progressEvents}`);

      // Verify the bytes actually arrived intact, not just that an event fired.
      const received = await readFile(DEST, 'utf8');
      if (received.length !== body.length) {
        throw new Error(`size mismatch: ${received.length} vs ${body.length}`);
      }
      if (received !== body) throw new Error('content mismatch');
      append(`verified ${received.length} bytes byte-for-byte`);

      const stats = server.transferStats();
      append(
        `sender stats: ${stats.bytesSent} bytes sent, ${stats.completed} completed`,
      );

      stopAll();
      setStatus('pass');
    } catch (error) {
      append(`ERROR: ${error instanceof Error ? error.message : String(error)}`);
      stopAll();
      setStatus('fail');
    }
  }, [append, connectPair, stopAll]);

  const busy = status === 'running';

  return (
    <View style={styles.screen}>
      <Text style={styles.title}>librats</Text>
      <Text style={styles.subtitle}>two nodes, one device</Text>

      <View style={styles.row}>
        <TouchableOpacity
          style={[styles.button, busy && styles.buttonDisabled]}
          onPress={runChat}
          disabled={busy}>
          <Text style={styles.buttonText}>chat test</Text>
        </TouchableOpacity>
        <TouchableOpacity
          style={[styles.button, busy && styles.buttonDisabled]}
          onPress={runFile}
          disabled={busy}>
          <Text style={styles.buttonText}>file test</Text>
        </TouchableOpacity>
      </View>

      <View style={styles.statusRow}>
        {busy && <ActivityIndicator />}
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
    </View>
  );
}

export default function App() {
  return <Demo />;
}

const styles = StyleSheet.create({
  // Explicit top inset instead of a safe-area library: this is a test harness,
  // and one less native dependency is one less thing that can fail to link.
  screen: {
    flex: 1,
    backgroundColor: '#0d1117',
    paddingHorizontal: 20,
    paddingTop: Platform.OS === 'ios' ? 60 : 32,
    paddingBottom: 20,
  },
  title: { fontSize: 32, fontWeight: '700', color: '#e6edf3' },
  subtitle: { fontSize: 14, color: '#8b949e', marginBottom: 20 },
  row: { flexDirection: 'row', gap: 12 },
  button: {
    flex: 1,
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
    fontSize: 11,
    marginBottom: 4,
  },
});
