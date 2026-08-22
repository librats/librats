/**
 * Basic node: peer events, raw-channel messaging and typed JSON.
 *
 * Everything a node does beyond secure transport is opt-in, and every enable and
 * every callback goes in BEFORE start().
 *
 *   node basic_client.js [listenPort] [connectHost] [connectPort]
 */

const { RatsNode, TransportMask } = require('../lib/index');

const [portArg, host, peerPortArg] = process.argv.slice(2);
const node = new RatsNode({ listenPort: portArg ? Number(portArg) : 8080 });

// ---- callbacks and subsystems: all before start() ----

node.onPeerConnected((peerId) => {
  console.log(`+ peer ${peerId}`);
  node.send(peerId, 'chat', 'Hello! Welcome to the network.');
});

node.onPeerDisconnected((peerId) => console.log(`- peer ${peerId}`));

// Raw channel: the payload arrives as a Buffer.
node.on('chat', (peerId, data) => {
  console.log(`[chat] ${peerId}: ${data.toString('utf8')}`);
});

// Typed JSON: the payload arrives already parsed.
node.enableJson();
node.onJson('greeting', (peerId, value) => {
  console.log(`[greeting] ${peerId}:`, value);
});

node.start();

console.log(`peer id      ${node.localId}`);
console.log(`listening on ${node.listenPort}`);
console.log(`transports   ${describeTransports(node.transports)}`);

if (host) {
  const peerPort = Number(peerPortArg) || 8081;
  console.log(`dialing ${host}:${peerPort}`);
  node.connect(host, peerPort);
}

// ---- periodic status + broadcast ----

const status = setInterval(() => {
  console.log(`peers: ${node.peerCount}${node.peerIds.length ? ` (${node.peerIds.join(', ')})` : ''}`);
}, 10_000);

const chatter = setInterval(() => {
  if (node.peerCount === 0) return;
  node.broadcast('chat', 'Broadcast message from Node.js!');
  node.broadcastJson('greeting', { from: node.localId, at: Date.now() });
}, 15_000);

process.on('SIGINT', () => {
  clearInterval(status);
  clearInterval(chatter);
  node.stop();
  process.exit(0);
});

console.log('running — Ctrl+C to stop');

function describeTransports(mask) {
  const names = [];
  if (mask & TransportMask.TCP) names.push('tcp');
  if (mask & TransportMask.UDP) names.push('udp');
  return names.join('+') || 'none';
}
