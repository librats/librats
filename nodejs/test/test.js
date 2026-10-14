/**
 * Tests for the librats Node.js bindings: run with `npm test`.
 *
 * Nodes bind 127.0.0.1 on ephemeral ports, so suites can run side by side.
 */

const assert = require('assert');
const { describe, it, beforeEach, afterEach } = require('node:test');

const {
  RatsNode,
  version,
  setLogLevel,
  LIVE_MAX_LIFETIME_MS,
  LIVE_MAX_PAYLOAD,
} = require('../lib/index');

setLogLevel('warn');

const NOBODY = '0'.repeat(64);

function server(extra = {}) {
  return new RatsNode({ bindAddress: '127.0.0.1', ...extra });
}
function client(extra = {}) {
  return new RatsNode({ dialOnly: true, ...extra });
}

// Resolve once `pred()` holds, polling every 10 ms.
function until(pred, timeoutMs = 8000) {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + timeoutMs;
    const tick = () => {
      if (pred()) return resolve();
      if (Date.now() > deadline) return reject(new Error('timed out'));
      setTimeout(tick, 10);
    };
    tick();
  });
}

// Start both and connect a → b; resolves once each side holds the other.
async function connectPair(a, b) {
  a.start();
  b.start();
  a.connect('127.0.0.1', b.listenPort);
  await until(() => a.peerCount === 1 && b.peerCount === 1);
}

describe('librats Node.js bindings', { timeout: 30_000 }, function () {
  describe('library', function () {
    it('reports its version', function () {
      const v = version();
      assert.strictEqual(typeof v.string, 'string');
      assert(v.string.startsWith(`${v.major}.${v.minor}.${v.patch}`), v.string);
      assert.strictEqual(v.abi, (v.major << 16) | (v.minor << 8) | v.patch);
      assert.strictEqual(typeof v.gitDescribe, 'string');
    });

    it('exposes the live message limits', function () {
      assert.strictEqual(LIVE_MAX_LIFETIME_MS, 30000);
      assert.strictEqual(LIVE_MAX_PAYLOAD, 1024 * 1024);
    });

    it('rejects an unknown log level', function () {
      assert.throws(() => setLogLevel('loud'), TypeError);
    });
  });

  describe('configuration', function () {
    it('runs both transports by default', function () {
      const node = new RatsNode();
      try {
        assert.deepStrictEqual(node.transports, [], 'nothing runs before start');
        node.start();
        assert.deepStrictEqual(node.transports, ['udp', 'tcp']);
        assert.strictEqual(node.protocol, 'librats/1.0');
        assert.strictEqual(node.localId.length, 64);
        assert(node.listenPort > 0);
      } finally {
        node.destroy();
      }
    });

    it('takes every field', function () {
      const node = new RatsNode({
        protocol: 'node-test/1',
        security: 'noise',
        bindAddress: '127.0.0.1',
        maxPeers: 4,
        transports: ['tcp'],
        preferredTransport: 'tcp',
        transportFallbackMs: Infinity,
        sendQueueLimit: 1 << 20,
        pathSampleMs: 50,
        congestionControl: 'reno',
        udpReceiveWindow: 1 << 20,
        udpReceiveBudget: 4 << 20,
        udpOffload: false,
        reactorThreads: 2,
        networkMonitor: false,
      });
      try {
        node.start();
        assert.deepStrictEqual(node.transports, ['tcp']);
        assert.strictEqual(node.protocol, 'node-test/1');
        assert.strictEqual(node.maxPeers, 4);
      } finally {
        node.destroy();
      }
    });

    it('refuses malformed fields', function () {
      assert.throws(() => new RatsNode({ security: 'rot13' }), TypeError);
      assert.throws(() => new RatsNode({ transports: ['carrier-pigeon'] }), TypeError);
      assert.throws(() => new RatsNode({ transports: [] }), TypeError);
      assert.throws(() => new RatsNode({ preferredTransport: 'relay' }), TypeError);
      assert.throws(() => new RatsNode({ listenPort: 70000 }), RangeError);
      assert.throws(() => new RatsNode({ transportFallbackMs: 0 }), RangeError);
      assert.throws(() => new RatsNode(42), TypeError);
    });

    it('refuses a config no node can run with', function () {
      assert.throws(() => new RatsNode({ transports: ['udp'], preferredTransport: 'tcp' }),
                    (err) => err.code === 'INVALID_CONFIG');
    });
  });

  describe('lifecycle', function () {
    let node;
    beforeEach(function () { node = server(); });
    afterEach(function () { node.destroy(); });

    it('dials only once started', function () {
      assert.throws(() => node.connect('127.0.0.1', 1), (err) => err.code === 'NOT_STARTED');
    });

    it('refuses callbacks and subsystems after start', function () {
      node.start();
      assert.throws(() => node.start(), (err) => err.code === 'ALREADY_STARTED');
      assert.throws(() => node.onPeerConnected(() => {}), (err) => err.code === 'ALREADY_STARTED');
      assert.throws(() => node.enablePubsub(), (err) => err.code === 'ALREADY_STARTED');
    });

    it('says when a subsystem was not enabled', function () {
      node.start();
      assert.throws(() => node.punchPeer(NOBODY), (err) => err.code === 'NOT_ENABLED');
      assert.throws(() => node.publish('t', 'x'), (err) => err.code === 'NOT_ENABLED');
    });

    it('answers for a peer that is not there', function () {
      node.enablePing();
      node.enableFileTransfer();
      node.start();
      assert.strictEqual(node.peerInfo(NOBODY), null);
      assert.strictEqual(node.pathStats(NOBODY), null);
      assert.strictEqual(node.peerRttMs(NOBODY), null);
      assert.strictEqual(node.disconnect(NOBODY), false);
      assert.strictEqual(node.peerWritable(NOBODY), false);
      assert.strictEqual(node.cancelFile(NOBODY, 12345), false);
      assert.throws(() => node.send(NOBODY, 'c', 'x'), (err) => err.code === 'NO_SUCH_PEER');
      assert.throws(() => node.send('not-hex', 'c', 'x'), (err) => err.code === 'INVALID_ARG');
    });

    it('is inert once destroyed', function () {
      const doomed = server();
      doomed.destroy();
      doomed.destroy();   // idempotent
      assert.throws(() => doomed.listenPort, (err) => err.code === 'DESTROYED');
    });
  });

  describe('two nodes', function () {
    let a, b;
    beforeEach(function () { a = client(); b = server(); });
    afterEach(function () { a.destroy(); b.destroy(); });

    it('carries a channel message and reports the peer', async function () {
      let got = null;
      b.on('chat', (peerId, data) => { got = { peerId, data }; });
      await connectPair(a, b);

      a.send(b.localId, 'chat', Buffer.from([0, 1, 255, 0]));
      await until(() => got !== null);
      assert.strictEqual(got.peerId, a.localId);
      assert.deepStrictEqual([...got.data], [0, 1, 255, 0]);

      assert.deepStrictEqual(a.peerIds, [b.localId]);
      const info = a.peerInfo(b.localId);
      assert.strictEqual(info.direction, 'outbound');
      assert.strictEqual(info.transport, 'udp');
      assert(info.address.endsWith(`:${b.listenPort}`), info.address);
      assert.strictEqual(b.peerInfo(a.localId).direction, 'inbound');
    });

    it('delivers a live message and counts it', async function () {
      let got = 0;
      b.on('video', (peerId, data) => { got = data.length; });
      const a2 = client({ pathSampleMs: 20 });
      try {
        await connectPair(a2, b);
        a2.send(b.localId, 'video', Buffer.alloc(20000, 7), 500);
        await until(() => got === 20000);
        await until(() => (a2.pathStats(b.localId) || {}).liveSent === 1);
        assert.throws(() => a2.send(b.localId, 'video', Buffer.alloc(LIVE_MAX_PAYLOAD + 1), 500),
                      (err) => err.code === 'INVALID_ARG');
      } finally {
        a2.destroy();
      }
    });

    it('round-trips JSON values, strings included', async function () {
      const seen = [];
      a.enableJson();
      b.enableJson();
      b.onJson('greeting', (peerId, value) => seen.push(value));
      await connectPair(a, b);

      a.sendJson(b.localId, 'greeting', { hello: 'world', n: 42 });
      a.sendJson(b.localId, 'greeting', 'just a string');
      await until(() => seen.length === 2);
      assert.deepStrictEqual(seen[0], { hello: 'world', n: 42 });
      assert.strictEqual(seen[1], 'just a string');
      assert.throws(() => a.sendJson(b.localId, 'greeting', undefined), TypeError);
    });

    it('disconnects with a reason', async function () {
      let reason = null;
      b.onPeerDisconnected((peerId, why) => { reason = why; });
      await connectPair(a, b);
      assert.strictEqual(a.disconnect(b.localId), true);
      await until(() => reason !== null && a.peerCount === 0);
      assert.strictEqual(typeof reason, 'string');
      assert.notStrictEqual(reason, 'slow-consumer');
    });

    it('samples the path for a registered handler', async function () {
      let samples = 0;
      a.onPeerPath((peerId, stats) => { if (stats.srttUs > 0) samples++; });
      await connectPair(a, b);
      for (let i = 0; i < 8; i++) a.send(b.localId, 'bulk', Buffer.alloc(32 * 1024));
      await until(() => samples >= 2);
      const stats = a.pathStats(b.localId);
      assert(stats.srttUs > 0);
      assert.strictEqual(typeof stats.appLimited, 'boolean');
    });
  });

  it('names the address of a dial that failed', async function () {
    const closed = server();
    closed.start();
    const port = closed.listenPort;
    closed.destroy();

    const node = client();
    try {
      let failed = null;
      node.onDialFailed((address) => { failed = address; });
      node.start();
      node.connect('127.0.0.1', port);
      await until(() => failed !== null, 15000);
      assert.strictEqual(failed, `127.0.0.1:${port}`);
    } finally {
      node.destroy();
    }
  });
});
