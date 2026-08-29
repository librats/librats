/**
 * Topic-based chat over the pub/sub (GossipSub) subsystem.
 *
 * enablePubsub() and every subscribe() happen BEFORE start() — a topic cannot be
 * subscribed once the node is running.
 *
 *   node gossipsub_chat.js [listenPort] [username] [topic] [connectHost] [connectPort]
 */

const readline = require('readline');
const { RatsNode } = require('../lib/index');

const [portArg, userArg, topicArg, host, peerPortArg] = process.argv.slice(2);
const username = userArg || `user_${Math.random().toString(36).slice(2, 8)}`;
const topic = topicArg || 'lobby';

const node = new RatsNode(portArg ? Number(portArg) : 8080);

node.onPeerConnected((peerId) => console.log(`+ peer ${peerId}`));
node.onPeerDisconnected((peerId, reason) => console.log(`- peer ${peerId} (${reason})`));

node.enablePubsub();
node.subscribe(topic, (peerId, name, data) => {
  const text = data.toString('utf8');
  let msg;
  try {
    msg = JSON.parse(text);
  } catch {
    console.log(`[${name}] (raw) ${peerId}: ${text}`);
    return;
  }
  if (msg.type === 'chat') console.log(`[${name}] ${msg.username}: ${msg.message}`);
  else if (msg.type === 'join') console.log(`[${name}] ${msg.username} joined`);
});

node.start();

console.log(`peer id  ${node.localId}`);
console.log(`username ${username}`);
console.log(`topic    ${topic}`);

if (host) node.connect(host, Number(peerPortArg) || 8081);

publish({ type: 'join' });

// ---- interactive prompt ----

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: 'chat> ',
});

console.log([
  '',
  'commands:',
  '  connect <host> <port>   dial a peer',
  '  peers                   list connected peers',
  '  quit                    exit',
  'anything else is published to the topic.',
  '',
].join('\n'));

rl.prompt();

rl.on('line', (line) => {
  const [command, ...rest] = line.trim().split(/\s+/);
  try {
    switch (command) {
      case '':
        break;
      case 'connect':
        if (rest.length >= 2) node.connect(rest[0], Number(rest[1]));
        else console.log('usage: connect <host> <port>');
        break;
      case 'peers':
        console.log(node.peerIds.join('\n') || '(none)');
        break;
      case 'quit':
      case 'exit':
        rl.close();
        return;
      default:
        say(line.trim());
    }
  } catch (err) {
    console.error(err.message);
  }
  rl.prompt();
});

rl.on('close', () => {
  node.stop();
  process.exit(0);
});

function publish(fields) {
  node.publish(topic, JSON.stringify({ username, at: Date.now(), ...fields }));
}

function say(message) {
  publish({ type: 'chat', message });
  console.log(`[${topic}] ${username}: ${message}`);
}
