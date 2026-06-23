const {
  RatsClient,
  Security,
  LogLevel,
  getVersionString,
  getVersion,
  getGitDescribe,
  getAbi,
  constants,
} = require('../lib/index');
const assert = require('assert');
const { describe, it, beforeEach, afterEach } = require('node:test');

/**
 * Test suite for the Node.js librats bindings (new C ABI).
 *
 * Subsystems and callbacks are registered BEFORE start(). Native calls throw on
 * a non-OK result.
 */
describe('LibRats Node.js Bindings', { timeout: 10_000 }, function () {

  describe('Library info', function () {
    it('returns a version string', function () {
      const version = getVersionString();
      assert(typeof version === 'string');
      assert(version.length > 0);
    });

    it('returns version components', function () {
      const v = getVersion();
      assert(typeof v.major === 'number');
      assert(typeof v.minor === 'number');
      assert(typeof v.patch === 'number');
      assert(typeof v.build === 'number');
    });

    it('returns git describe and abi', function () {
      assert(typeof getGitDescribe() === 'string');
      assert(typeof getAbi() === 'number');
    });
  });

  describe('Constants', function () {
    it('exposes security selectors', function () {
      assert.strictEqual(Security.NOISE, 0);
      assert.strictEqual(Security.PLAINTEXT, 1);
      assert.strictEqual(constants.SECURITY.NOISE, 0);
    });

    it('exposes log levels', function () {
      assert.strictEqual(LogLevel.DEBUG, 0);
      assert.strictEqual(LogLevel.ERROR, 3);
    });

    it('exposes error codes', function () {
      assert.strictEqual(constants.ERRORS.OK, 0);
      assert(typeof constants.ERRORS.ALREADY_STARTED === 'number');
    });
  });

  describe('RatsClient lifecycle', function () {
    let client1, client2;

    beforeEach(function () {
      client1 = new RatsClient(18080);
      client2 = new RatsClient({ listenPort: 18081, security: Security.NOISE });
    });

    afterEach(function () {
      if (client1) client1.stop();
      if (client2) client2.stop();
    });

    it('creates instances from a port and a config', function () {
      assert(client1 instanceof RatsClient);
      assert(client2 instanceof RatsClient);
    });

    it('starts and exposes a peer id', function () {
      client1.start();
      const peerId = client1.getOurPeerId();
      assert(typeof peerId === 'string');
      assert(peerId.length === 64);
      assert(client1.getListenPort() > 0);
    });

    it('exposes protocol identity', function () {
      client1.start();
      assert(typeof client1.getProtocol() === 'string');
    });

    it('reports peer count and ids', function () {
      client1.start();
      assert.strictEqual(client1.getPeerCount(), 0);
      assert(Array.isArray(client1.getPeerIds()));
    });

    it('handles max peers', function () {
      client1.setMaxPeers(50);
      assert.strictEqual(client1.getMaxPeers(), 50);
    });

    it('rejects enabling a subsystem after start', function () {
      client1.start();
      assert.throws(() => client1.enablePubsub());
    });
  });

  describe('Subsystem setup (before start)', function () {
    let client;

    beforeEach(function () {
      client = new RatsClient(18082);
    });

    afterEach(function () {
      client.stop();
    });

    it('enables discovery and NAT subsystems', function () {
      client.enableDht(0, 'test-app');
      client.enableMdns();
      client.enablePortMapping(true, true);
      client.start();
    });

    it('enables pub/sub and subscribes', function () {
      client.enablePubsub();
      client.subscribe('test-topic', () => {});
      client.start();
      client.publish('test-topic', 'hello');
    });

    it('enables JSON messaging', function () {
      client.enableJson();
      client.onJson('greeting', () => {});
      client.start();
    });

    it('enables ping and reconnect', function () {
      client.enablePing();
      client.enableReconnect();
      client.start();
      assert.strictEqual(client.getPeerRttMs('0'.repeat(64)), -1);
    });

    it('enables file transfer and registers callbacks', function () {
      client.enableFileTransfer();
      client.onFileOffer(() => {});
      client.onFileProgress(() => {});
      client.onFileComplete(() => {});
      client.start();
    });
  });

  describe('Peer-to-peer messaging', function () {
    let client1, client2;

    beforeEach(function () {
      client1 = new RatsClient(18090);
      client2 = new RatsClient(18091);
    });

    afterEach(function () {
      client1.stop();
      client2.stop();
    });

    it('delivers a raw channel message', function (t, done) {
      client2.on('chat', (peerId, data) => {
        assert(typeof peerId === 'string');
        assert(Buffer.isBuffer(data));
        assert.strictEqual(data.toString('utf8'), 'hello from client1');
        done();
      });
      client1.onPeerConnected((peerId) => {
        setTimeout(() => client1.send(peerId, 'chat', 'hello from client1'), 50);
      });

      client1.start();
      client2.start();
      setTimeout(() => client1.connect('127.0.0.1', 18091), 100);
    });
  });

  describe('Error handling', function () {
    it('rejects an out-of-range port', function () {
      assert.throws(() => new RatsClient(-1));
    });
  });
});

// Direct execution: minimal smoke test.
if (require.main === module) {
  console.log('Running librats Node.js binding smoke test...');
  console.log(`Version: ${getVersionString()}`);
  const client = new RatsClient(18099);
  client.start();
  console.log(`Peer ID: ${client.getOurPeerId()}`);
  console.log(`Listen port: ${client.getListenPort()}`);
  client.stop();
  console.log('OK');
}
