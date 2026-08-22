/**
 * Test suite for the librats Node.js bindings.
 *
 * The contract under test: subsystems and callbacks are registered BEFORE
 * start(), pure getters are properties, and every fallible call throws on a
 * non-OK result rather than returning a code.
 */

const assert = require('assert');
const { describe, it, beforeEach, afterEach } = require('node:test');

const {
  RatsNode,
  Security,
  Transport,
  TransportMask,
  NatMapping,
  LogLevel,
  version,
  versionInfo,
  gitDescribe,
  abi,
} = require('../lib/index');

describe('librats Node.js bindings', { timeout: 10_000 }, function () {

  describe('library info', function () {
    it('returns a version string', function () {
      assert(typeof version() === 'string');
      assert(version().length > 0);
    });

    it('returns version components', function () {
      const v = versionInfo();
      for (const key of ['major', 'minor', 'patch', 'build']) {
        assert(typeof v[key] === 'number', `${key} should be a number`);
      }
    });

    it('returns git describe and abi', function () {
      assert(typeof gitDescribe() === 'string');
      assert(typeof abi() === 'number');
    });
  });

  describe('enums', function () {
    it('mirrors the C ABI values', function () {
      assert.strictEqual(Security.NOISE, 0);
      assert.strictEqual(Security.PLAINTEXT, 1);
      assert.strictEqual(Transport.TCP, 0);
      assert.strictEqual(Transport.UDP, 1);
      assert.strictEqual(TransportMask.TCP, 0x1);
      assert.strictEqual(TransportMask.UDP, 0x2);
      assert.strictEqual(NatMapping.UNKNOWN, 0);
      assert.strictEqual(NatMapping.ENDPOINT_DEPENDENT, 3);
      assert.strictEqual(LogLevel.DEBUG, 0);
      assert.strictEqual(LogLevel.ERROR, 3);
    });
  });

  describe('lifecycle', function () {
    let a, b;

    beforeEach(function () {
      a = new RatsNode(18080);
      b = new RatsNode({ listenPort: 18081, security: Security.NOISE });
    });

    afterEach(function () {
      a.destroy();
      b.destroy();
    });

    it('creates a node from a port and from a config', function () {
      assert(a instanceof RatsNode);
      assert(b instanceof RatsNode);
    });

    it('exposes an identity once started', function () {
      a.start();
      assert.strictEqual(a.localId.length, 64);
      assert(a.listenPort > 0);
      assert(typeof a.protocol === 'string');
    });

    it('reports the transports it actually runs', function () {
      assert.strictEqual(a.transports, 0, 'no transport before start');
      a.start();
      assert(a.transports & (TransportMask.TCP | TransportMask.UDP));
    });

    it('reports peer count and ids', function () {
      a.start();
      assert.strictEqual(a.peerCount, 0);
      assert.deepStrictEqual(a.peerIds, []);
    });

    it('has a settable peer cap', function () {
      a.maxPeers = 50;
      assert.strictEqual(a.maxPeers, 50);
    });

    it('rejects enabling a subsystem after start', function () {
      a.start();
      assert.throws(() => a.enablePubsub(), /ALREADY_STARTED/);
    });

    it('makes a destroyed node inert rather than unsafe', function () {
      const doomed = new RatsNode(0);
      doomed.destroy();
      doomed.destroy(); // idempotent
      assert.throws(() => doomed.listenPort, /destroyed/);
    });
  });

  describe('subsystem setup (before start)', function () {
    let node;

    beforeEach(function () { node = new RatsNode(18082); });
    afterEach(function () { node.destroy(); });

    it('enables discovery and NAT traversal', function () {
      node.enableDht(0, 'test-app');
      node.enableMdns();
      node.enablePortMapping(true, true);
      node.enableHolePunch(true);
      node.start();
      assert.strictEqual(node.natMapping, NatMapping.UNKNOWN);
    });

    it('enables pub/sub and subscribes', function () {
      node.enablePubsub();
      node.subscribe('test-topic', () => {});
      node.start();
      node.publish('test-topic', 'hello');
    });

    it('enables JSON messaging', function () {
      node.enableJson();
      node.onJson('greeting', () => {});
      node.start();
    });

    it('enables ping and reconnect', function () {
      node.enablePing();
      node.enableReconnect();
      node.start();
      assert.strictEqual(node.peerRttMs('0'.repeat(64)), -1);
    });

    it('enables file transfer and registers callbacks', function () {
      node.enableFileTransfer();
      node.onFileOffer(() => {});
      node.onFileProgress(() => {});
      node.onFileComplete(() => {});
      node.start();
    });

    it('reports nothing for an unconnected peer', function () {
      node.start();
      assert.strictEqual(node.peerTransport('0'.repeat(64)), null);
      assert.strictEqual(node.peerTransports('0'.repeat(64)), null);
    });
  });

  describe('peer-to-peer messaging', function () {
    let a, b;

    beforeEach(function () {
      a = new RatsNode(18090);
      b = new RatsNode(18091);
    });

    afterEach(function () {
      a.destroy();
      b.destroy();
    });

    it('delivers a raw channel message', function (t, done) {
      b.on('chat', (peerId, data) => {
        assert.strictEqual(peerId.length, 64);
        assert(Buffer.isBuffer(data));
        assert.strictEqual(data.toString('utf8'), 'hello from a');
        done();
      });
      a.onPeerConnected((peerId) => {
        setTimeout(() => a.send(peerId, 'chat', 'hello from a'), 50);
      });

      a.start();
      b.start();
      setTimeout(() => a.connect('127.0.0.1', 18091), 100);
    });

    it('delivers a typed JSON message as a parsed value', function (t, done) {
      a.enableJson();
      b.enableJson();
      b.onJson('greeting', (peerId, value) => {
        assert.deepStrictEqual(value, { hello: 'world', n: 42 });
        done();
      });
      a.onPeerConnected((peerId) => {
        setTimeout(() => a.sendJson(peerId, 'greeting', { hello: 'world', n: 42 }), 50);
      });

      a.start();
      b.start();
      setTimeout(() => a.connect('127.0.0.1', 18091), 100);
    });
  });

  describe('argument validation', function () {
    it('rejects an out-of-range port', function () {
      assert.throws(() => new RatsNode(-1), RangeError);
    });
  });
});

// Direct execution: minimal smoke test.
if (require.main === module) {
  console.log(`librats ${version()} (${gitDescribe()})`);
  const node = new RatsNode(18099);
  node.start();
  console.log(`peer id ${node.localId} on port ${node.listenPort}`);
  node.destroy();
  console.log('OK');
}
