/**
 * librats React Native example.
 *
 * Three self-verifying tests, each run with a pair of nodes inside this one
 * process so a single device is enough to prove the binding works:
 *
 *   chat   - one node dials the other over the loopback, they complete a Noise
 *            handshake, and a message comes back echoed.
 *   file   - one node offers a 512 KiB file, the other accepts it, and the
 *            received bytes are compared against what was sent.
 *   pubsub - both subscribe to a topic, the mesh forms, one publishes, and the
 *            other receives it (as does the publisher itself).
 */
import React, { useCallback, useRef, useState } from 'react';
import {
  ActivityIndicator,
  Platform,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
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

const TOPIC = 'example/announcements';
const DISCOVERY_KEY = 'librats-rn-example-2dev';
const GOSSIP = 'published over gossipsub';

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

/** Poll until `check` holds. GossipSub forms its mesh on a heartbeat, so the
 *  interesting states here arrive a beat or two after the call that triggers them. */
async function waitUntil(
  check: () => boolean,
  ms: number,
  what: string,
): Promise<void> {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (check()) return;
    await new Promise<void>(resolve => setTimeout(() => resolve(), 100));
  }
  throw new Error(`${what} within ${ms / 1000}s`);
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

  /** A connected pair with file transfer and pub/sub enabled on both.
   *
   *  `setup` runs once both nodes exist and their subsystems are enabled, but
   *  before either one starts -- which is where every on*() registration has to
   *  go. librats stores those handlers without a lock and dispatches them from
   *  reactor threads, so registering on a running node is a data race, and the
   *  binding throws rather than let one happen. subscribe() is the exception:
   *  it takes the PubSub mutex and is safe at any time. */
  const connectPair = useCallback(
    async (setup?: (server: RatsNode, client: RatsNode) => void) => {
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

      // A brisk heartbeat so mesh formation happens in a test-friendly time; the
      // 1000ms default is tuned for real meshes, not for a two-node loopback.
      server.enablePubSub({ heartbeatIntervalMs: 200 });
      client.enablePubSub({ heartbeatIntervalMs: 200 });

      server.enableJsonMessaging();
      client.enableJsonMessaging();

      setup?.(server, client);

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
    },
    [],
  );

  const runChat = useCallback(async () => {
    stopAll();
    setLog([]);
    setStatus('running');
    try {
      // The resolver is captured before connectPair() so the handler can be
      // registered inside setup, while the nodes are still stopped.
      let resolveEcho!: (text: string) => void;
      const echoed = new Promise<string>(resolve => {
        resolveEcho = resolve;
      });

      const { client, serverId } = await connectPair((srv, cli) => {
        srv.onMessage(CHANNEL, (from, data) => {
          srv.send(from, CHANNEL, data); // echo straight back
        });
        cli.onMessage(CHANNEL, (_from, data) => resolveEcho(decodeUtf8(data)));
      });
      append(`handshake with ${serverId.slice(0, 8)}`);

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

      // Settled from inside setup, so the callbacks are registered while the
      // nodes are still stopped.
      let progressEvents = 0;
      let resolveDone!: (path: string) => void;
      let rejectDone!: (error: Error) => void;
      const done = new Promise<string>((resolve, reject) => {
        resolveDone = resolve;
        rejectDone = reject;
      });

      const { server, clientId } = await connectPair((_srv, cli) => {
        // The receiver decides what to do with each offer. Ignoring one would
        // occupy the sender until it times out.
        cli.onFileOffer(offer => {
          append(
            `offer: "${offer.name}" ${offer.size} bytes, ` +
              `${offer.files.length} file(s)${offer.isDirectory ? ', directory' : ''}`,
          );
          cli.acceptFile(offer.peerId, offer.transferId, DEST);
        });

        cli.onFileProgress(p => {
          progressEvents += 1;
          if (progressEvents === 1) {
            append(
              `first progress: ${p.percent.toFixed(0)}% ` +
                `(${p.direction}, ${p.status}) ` +
                `${(p.transferRateBps / 1024).toFixed(0)} KiB/s`,
            );
          }
        });

        cli.onFileComplete((_id, success, path) => {
          if (success) {
            resolveDone(path);
          } else {
            rejectDone(new Error('transfer reported failure'));
          }
        });
      });
      append(`handshake with ${clientId.slice(0, 8)}`);

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

  const runPubSub = useCallback(async () => {
    stopAll();
    setLog([]);
    setStatus('running');
    try {
      const { server, client, clientId } = await connectPair();
      append(`handshake with ${clientId.slice(0, 8)}`);

      // Both sides subscribe, so the publisher pushes along a real mesh rather
      // than the short-lived fanout set used for unsubscribed topics.
      const received = new Promise<string>(resolve => {
        client.subscribe(TOPIC, (_peerId, _topic, data) =>
          resolve(decodeUtf8(data)),
        );
      });
      // A subscribed publisher also hears its own message, tagged with its own
      // peer id -- which is how a chat UI tells its messages apart from a
      // peer's, so it is worth asserting rather than treating as noise.
      const heardSelf = new Promise<string>(resolve => {
        server.subscribe(TOPIC, peerId => resolve(peerId));
      });

      if (!client.isSubscribed(TOPIC)) throw new Error('subscribe did not register');
      append(`subscribed topics: ${client.subscribedTopics().join(', ')}`);

      // SUBSCRIBE is announced asynchronously and GRAFT rides the heartbeat, so
      // publishing straight away would reach nobody.
      await waitUntil(
        () => server.meshPeers(TOPIC).includes(clientId),
        15000,
        'mesh did not form',
      );
      append(
        `mesh formed: ${server.meshPeers(TOPIC).length} peer(s), ` +
          `${server.topicPeers(TOPIC).length} known subscriber(s)`,
      );

      server.publish(TOPIC, encodeUtf8(GOSSIP));
      const got = await Promise.race([received, timeout(15000, 'no gossip')]);
      if (got !== GOSSIP) throw new Error(`payload mismatch: "${got}"`);
      append(`subscriber received: "${got}"`);

      const selfId = await Promise.race([
        heardSelf,
        timeout(15000, 'publisher did not hear itself'),
      ]);
      if (selfId !== server.localId) {
        throw new Error(`self-delivery tagged ${selfId.slice(0, 8)}, not own id`);
      }
      append(`publisher heard itself, tagged ${selfId.slice(0, 8)} (own id)`);

      client.unsubscribe(TOPIC);
      if (client.isSubscribed(TOPIC)) throw new Error('unsubscribe did not take');
      append('unsubscribed');

      stopAll();
      setStatus('pass');
    } catch (error) {
      append(`ERROR: ${error instanceof Error ? error.message : String(error)}`);
      stopAll();
      setStatus('fail');
    }
  }, [append, connectPair, stopAll]);

  // DHT joins a real public network, so unlike the other tests this one depends
  // on internet reachability. It checks that the subsystem comes up and starts
  // bootstrapping -- not that a peer is found, which needs another node
  // announcing the same key and can take minutes.
  const runDht = useCallback(async () => {
    stopAll();
    setLog([]);
    setStatus('running');
    try {
      const node = createNode({ dataDir: TEMP_DIR, protocol: 'example/1.0' });
      nodes.current = [node];

      node.enableDht({
        discoveryKey: 'librats-rn-example',
        searchIntervalMs: 5000,
        announceIntervalMs: 15000,
      });

      // The hash is resolved when the subsystem attaches, which happens inside
      // start() -- so before that it is legitimately all zeros.
      const before = node.dhtStatus();
      append(`before start: running=${before.running} port=${before.port}`);
      if (/[^0]/.test(before.discoveryHash)) {
        throw new Error('hash should still be unresolved before start()');
      }

      if (!node.start()) throw new Error('node failed to start');

      await waitUntil(() => node.dhtStatus().running, 20000, 'DHT did not start');
      const status = node.dhtStatus();
      append(`running on udp ${status.port}${status.portV6 ? ` / v6 ${status.portV6}` : ''}`);

      if (status.discoveryHash.length !== 40) {
        throw new Error(`hash is ${status.discoveryHash.length} chars, expected 40`);
      }
      if (!/[^0]/.test(status.discoveryHash)) {
        throw new Error('hash still unresolved after start()');
      }
      append(`discovery hash: ${status.discoveryHash.slice(0, 16)}...`);

      // STUN or in-DHT voting fills this in; treated as informational because it
      // needs the network to answer.
      const found = await waitUntil(
        () => node.dhtStatus().externalAddress !== '',
        25000,
        'no external address',
      ).then(
        () => true,
        () => false,
      );
      append(
        found
          ? `external address: ${node.dhtStatus().externalAddress}`
          : 'external address not resolved (offline or STUN blocked)',
      );

      append(`peers discovered so far: ${node.peerCount}`);
      stopAll();
      append('stopped');
      setStatus('pass');
    } catch (error) {
      append(`ERROR: ${error instanceof Error ? error.message : String(error)}`);
      stopAll();
      setStatus('fail');
    }
  }, [append, stopAll]);

  // NAT traversal against the real network. Two loopback nodes cannot demonstrate
  // a punch or a relay -- both need peers on opposite sides of a NAT -- so this
  // checks the parts that are observable from one device: that the subsystems
  // attach, that the router is asked for a mapping, and what the mesh reports
  // about our own NAT. The mapping classification is the thing to read before
  // blaming a failed cross-network dial.
  const runNat = useCallback(async () => {
    stopAll();
    setLog([]);
    setStatus('running');
    try {
      const node = createNode({ dataDir: TEMP_DIR, protocol: 'example/1.0' });
      nodes.current = [node];

      node.enablePortMapping({ leaseDurationSeconds: 600 });
      node.enableHolePunch({ attempts: 2 });
      // serve:false is the mobile default -- carrying other peers' traffic costs
      // battery, and a phone is rarely reachable enough to be a useful relay.
      node.enableRelay({ serve: false });

      // natStatus needs no subsystem at all.
      const before = node.natStatus();
      append(`before start: mapping=${before.mapping} observations=${before.observationCount}`);
      if (before.mapping !== 'unknown') {
        throw new Error(`expected unknown before any peer, got ${before.mapping}`);
      }

      if (!node.start()) throw new Error('node failed to start');
      append(`listening on ${node.listenPort}`);

      // UPnP/NAT-PMP probe the gateway in the background; either may be absent.
      const mapped = await waitUntil(
        () => node.portMappingStatus().externalTcpPort !== 0,
        20000,
        'no port mapping',
      ).then(
        () => true,
        () => false,
      );
      const pm = node.portMappingStatus();
      append(
        mapped
          ? `port mapping: tcp ${pm.externalTcpPort} udp ${pm.externalUdpPort}`
          : 'no port mapping (no UPnP/NAT-PMP router, or CGNAT)',
      );

      // Classification needs two independent UDP peers, so on one device it stays
      // unknown -- which is itself the correct answer, not a failure.
      const nat = node.natStatus();
      append(`nat mapping: ${nat.mapping} (${nat.observationCount} observation(s))`);
      append(
        nat.externalEndpoints.length > 0
          ? `external: ${nat.externalEndpoints.join(', ')}`
          : 'no external endpoint observed yet (needs a UDP peer)',
      );

      // Both take a peer id and report whether an attempt could even start. With
      // no peers there is nothing to carry a rendezvous, so false is expected.
      const fakePeer = node.localId;
      append(`punch(self) startable: ${node.punch(fakePeer)}`);
      append(`connectViaRelay(self) startable: ${node.connectViaRelay(fakePeer)}`);

      stopAll();
      append('stopped');
      setStatus('pass');
    } catch (error) {
      append(`ERROR: ${error instanceof Error ? error.message : String(error)}`);
      stopAll();
      setStatus('fail');
    }
  }, [append, stopAll]);

  const runJson = useCallback(async () => {
    stopAll();
    setLog([]);
    setStatus('running');
    try {
      const { server, client, serverId, clientId } = await connectPair();
      append(`handshake with ${serverId.slice(0, 8)}`);

      // Additive, unlike onMessage: both handlers below fire for one message, in
      // registration order.
      const order: string[] = [];
      const both = new Promise<void>(resolve => {
        server.onJson('greet', () => {
          order.push('first');
        });
        server.onJson('greet', (peerId, json) => {
          order.push('second');
          if (peerId !== clientId) {
            throw new Error('sender id is not the authenticated peer');
          }
          const parsed = JSON.parse(json);
          if (parsed.text !== 'hello' || parsed.n !== 42) {
            throw new Error(`payload round-trip wrong: ${json}`);
          }
          resolve();
        });
      });

      const sent = client.sendJson(serverId, 'greet', JSON.stringify({ text: 'hello', n: 42 }));
      append(`sendJson accepted: ${sent}`);
      if (!sent) throw new Error('peer reported not connected');

      await Promise.race([both, timeout(15000, 'no typed message')]);
      append(`handlers fired: ${order.join(', ')} (additive, in order)`);
      if (order.join(',') !== 'first,second') {
        throw new Error(`handler order wrong: ${order.join(',')}`);
      }

      // once() fires one time only, so a second send must not reach it again.
      let onceCount = 0;
      const onceFired = new Promise<void>(resolve => {
        server.onceJson('ping', () => {
          onceCount += 1;
          resolve();
        });
      });
      client.sendJson(serverId, 'ping', '{"i":1}');
      await Promise.race([onceFired, timeout(15000, 'once handler never fired')]);
      client.sendJson(serverId, 'ping', '{"i":2}');
      await new Promise<void>(r => setTimeout(() => r(), 1500));
      if (onceCount !== 1) throw new Error(`once fired ${onceCount} times`);
      append('onceJson fired exactly once');

      // offJson removes every handler for the type.
      server.offJson('greet');
      append('offJson removed the greet handlers');

      // Invalid JSON is rejected at the boundary rather than silently dropped.
      let threw = false;
      try {
        client.sendJson(serverId, 'greet', '{not json');
      } catch {
        threw = true;
      }
      if (!threw) throw new Error('invalid JSON was not rejected');
      append('invalid JSON rejected with an error');

      // Broadcast reports whether there was anyone to send to.
      append(`broadcastJson to ${client.peerCount} peer(s): ${client.broadcastJson('greet', '{}')}`);

      stopAll();
      setStatus('pass');
    } catch (error) {
      append(`ERROR: ${error instanceof Error ? error.message : String(error)}`);
      stopAll();
      setStatus('fail');
    }
  }, [append, connectPair, stopAll]);

  // ── two real devices ──────────────────────────────────────────────────────
  // One device taps "listen"; the other types its address and taps "dial". The
  // dialling side then drives every subsystem across the real network, and both
  // sides report what the mesh says about their NAT -- which only becomes
  // meaningful once a second peer exists.
  const [peerAddr, setPeerAddr] = useState('');
  const peerNode = useRef<RatsNode | null>(null);
  // Both devices run the same responder code, so "echo whatever arrives" makes
  // the two of them volley one message forever. Only the side that did not dial
  // answers; the dialling side just verifies what comes back.
  const didDial = useRef(false);

  const startPeerNode = useCallback(async () => {
    stopAll();
    setLog([]);
    setStatus('running');
    try {
      await mkdir(TEMP_DIR);
      const node = createNode({ dataDir: TEMP_DIR, protocol: 'example/1.0' });
      nodes.current = [node];
      peerNode.current = node;

      node.enableFileTransfer({ tempDirectory: TEMP_DIR });
      node.enablePubSub({ heartbeatIntervalMs: 500 });
      node.enableJsonMessaging();
      node.enableStorage();
      node.enablePortMapping();
      node.enableHolePunch();
      node.enableRelay({ serve: false });
      // Discovery + PEX are what make a cross-network meeting possible: DHT finds
      // peers announcing the same key, PEX gossips addresses onward, and an
      // unreachable discovered peer is handed to HolePunch instead of dropped.
      node.enableDht({ discoveryKey: DISCOVERY_KEY, searchIntervalMs: 10000 });
      node.enablePeerExchange();

      // Every on*() registration has to happen while the node is stopped.
      node.onPeerConnected(id => append(`+ peer ${id.slice(0, 8)}`));
      node.onPeerDisconnected(id => append(`- peer ${id.slice(0, 8)}`));

      // Responder behaviour, so whichever side is dialled can answer.
      node.onMessage(CHANNEL, (from, data) => {
        const text = decodeUtf8(data);
        append(`chat <- ${from.slice(0, 8)}: "${text}"`);
        if (!didDial.current) {
          node.send(from, CHANNEL, encodeUtf8(`${text} (echoed)`));
        }
      });
      node.onFileOffer(offer => {
        append(`file offer "${offer.name}" ${offer.size}B -> accepting`);
        node.acceptFile(offer.peerId, offer.transferId, DEST);
      });
      node.onFileComplete((_id, ok, path) =>
        append(ok ? `file done: ${path.replace(CACHE, '<cache>')}` : 'file FAILED'),
      );
      // Same rule for every responder: reply only when we were dialled.
      node.onJson('greet', (from, json) => {
        append(`json <- ${from.slice(0, 8)}: ${json}`);
        if (!didDial.current) {
          node.sendJson(from, 'greet', JSON.stringify({ ack: true }));
        }
      });
      node.onStorageChange(e =>
        append(`storage ${e.operation} ${e.key} (${e.isRemote ? 'remote' : 'local'})`),
      );

      didDial.current = false;
      if (!node.start()) throw new Error('node failed to start');
      node.subscribe(TOPIC, (from, _t, data) =>
        append(`topic <- ${from.slice(0, 8)}: "${decodeUtf8(data)}"`),
      );

      append(`listening on port ${node.listenPort}`);
      append(`peer id ${node.localId.slice(0, 16)}...`);
      setStatus('idle');
    } catch (error) {
      append(`ERROR: ${error instanceof Error ? error.message : String(error)}`);
      setStatus('fail');
    }
  }, [append, stopAll]);

  /** Drive every subsystem against whichever peer is connected. */
  const exercise = useCallback(
    async (node: RatsNode) => {
      const peerId = node.peerIds()[0]!;
      append(`connected to ${peerId.slice(0, 8)}`);

      node.send(peerId, CHANNEL, encodeUtf8(MESSAGE));
      append('chat -> sent');

      append(
        `json -> sent: ${node.sendJson(peerId, 'greet', JSON.stringify({ from: 'device' }))}`,
      );

      const meshed = await waitUntil(
        () => node.meshPeers(TOPIC).includes(peerId),
        15000,
        'mesh',
      ).then(
        () => true,
        () => false,
      );
      append(`pubsub mesh formed: ${meshed}`);
      if (meshed) node.publish(TOPIC, encodeUtf8(GOSSIP));

      node.putString('device/hello', 'from the dialling side');
      node.putInt('device/counter', 7);
      append(`storage put; ${node.storageCount()} key(s) locally`);

      const body = 'librats-two-device-'.repeat(4096);
      await writeFile(SOURCE, body, 'utf8');
      const tid = node.sendFile(peerId, SOURCE);
      append(`file -> offered ${body.length}B, transfer ${tid}`);

      // Classification needs a real second peer, which we now have.
      await waitUntil(() => node.natStatus().observationCount > 0, 20000, 'nat obs')
        .then(
          () => true,
          () => false,
        );
      const nat = node.natStatus();
      append(
        `nat: ${nat.mapping} (${nat.observationCount} obs) ${nat.externalEndpoints.join(' ')}`,
      );
      const pm = node.portMappingStatus();
      append(
        pm.externalTcpPort
          ? `port map: ${pm.externalIp} tcp ${pm.externalTcpPort} udp ${pm.externalUdpPort}`
          : 'no port mapping (no UPnP router, or CGNAT)',
      );
    },
    [append],
  );

  const dialPeer = useCallback(async () => {
    const node = peerNode.current;
    if (!node) {
      append('tap listen first');
      return;
    }
    setStatus('running');
    try {
      const [host, portText] = peerAddr.trim().split(':');
      const port = Number(portText);
      if (!host || !Number.isInteger(port)) {
        throw new Error(`expected host:port, got "${peerAddr}"`);
      }
      append(`dialing ${host}:${port}...`);
      didDial.current = true;
      node.connect(host, port);
      await waitUntil(() => node.peerCount > 0, 25000, 'no peer connected');
      await exercise(node);
      setStatus('pass');
    } catch (error) {
      append(`ERROR: ${error instanceof Error ? error.message : String(error)}`);
      setStatus('fail');
    }
  }, [append, exercise, peerAddr]);

  /** No address anywhere: DHT announce/search plus PEX have to find the peer. */
  const discoverPeer = useCallback(async () => {
    const node = peerNode.current;
    if (!node) {
      append('tap listen first');
      return;
    }
    setStatus('running');
    try {
      didDial.current = true;
      append('waiting for discovery (DHT + PEX), no address given...');
      const t0 = Date.now();
      await waitUntil(() => node.peerCount > 0, 180000, 'nobody discovered');
      append(`discovered after ${Math.round((Date.now() - t0) / 1000)}s`);
      await exercise(node);
      setStatus('pass');
    } catch (error) {
      const d = node.dhtStatus();
      append(`dht running=${d.running} port=${d.port} ext=${d.externalAddress}`);
      const n = node.natStatus();
      append(`nat ${n.mapping} (${n.observationCount} obs)`);
      append(`ERROR: ${error instanceof Error ? error.message : String(error)}`);
      setStatus('fail');
    }
  }, [append, exercise]);

  const busy = status === 'running';

  return (
    <View style={styles.screen}>
      <Text style={styles.title}>librats</Text>
      <Text style={styles.subtitle}>two nodes, one device</Text>

      <View style={styles.row}>
        <TextInput
          style={styles.input}
          value={peerAddr}
          onChangeText={setPeerAddr}
          placeholder="peer host:port"
          placeholderTextColor="#6e7681"
          autoCapitalize="none"
          autoCorrect={false}
        />
        <TouchableOpacity style={styles.button} onPress={startPeerNode}>
          <Text style={styles.buttonText}>listen</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.button} onPress={dialPeer}>
          <Text style={styles.buttonText}>dial</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.button} onPress={discoverPeer}>
          <Text style={styles.buttonText}>find</Text>
        </TouchableOpacity>
      </View>

      <View style={styles.row}>
        <TouchableOpacity
          style={[styles.button, busy && styles.buttonDisabled]}
          onPress={runChat}
          disabled={busy}>
          <Text style={styles.buttonText}>chat</Text>
        </TouchableOpacity>
        <TouchableOpacity
          style={[styles.button, busy && styles.buttonDisabled]}
          onPress={runFile}
          disabled={busy}>
          <Text style={styles.buttonText}>file</Text>
        </TouchableOpacity>
        <TouchableOpacity
          style={[styles.button, busy && styles.buttonDisabled]}
          onPress={runPubSub}
          disabled={busy}>
          <Text style={styles.buttonText}>pubsub</Text>
        </TouchableOpacity>
        <TouchableOpacity
          style={[styles.button, busy && styles.buttonDisabled]}
          onPress={runDht}
          disabled={busy}>
          <Text style={styles.buttonText}>dht</Text>
        </TouchableOpacity>
        <TouchableOpacity
          style={[styles.button, busy && styles.buttonDisabled]}
          onPress={runNat}
          disabled={busy}>
          <Text style={styles.buttonText}>nat</Text>
        </TouchableOpacity>
        <TouchableOpacity
          style={[styles.button, busy && styles.buttonDisabled]}
          onPress={runJson}
          disabled={busy}>
          <Text style={styles.buttonText}>json</Text>
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
  row: { flexDirection: 'row', gap: 5, marginBottom: 8 },
  input: {
    flex: 2,
    backgroundColor: '#161b22',
    borderRadius: 8,
    paddingHorizontal: 10,
    color: '#e6edf3',
    fontSize: 12,
  },
  button: {
    flex: 1,
    backgroundColor: '#238636',
    paddingVertical: 14,
    borderRadius: 8,
    alignItems: 'center',
  },
  buttonDisabled: { backgroundColor: '#30363d' },
  buttonText: { color: '#fff', fontSize: 11, fontWeight: '600' },
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
