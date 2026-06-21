const { RatsClient } = require('../lib/index');

/**
 * Topic-based chat over the pub/sub (GossipSub) subsystem.
 *
 * The pub/sub subsystem and all topic subscriptions are set up BEFORE start().
 * Chat messages are JSON-encoded and published as raw bytes on a topic; every
 * subscriber receives them in the subscribe() callback.
 */
class GossipSubChatExample {
  constructor(port = 8080, username = 'Anonymous', topic = 'lobby') {
    this.client = new RatsClient(port);
    this.username = username;
    this.topic = topic;
    this.setupCallbacks();
  }

  setupCallbacks() {
    this.client.onPeerConnected((peerId) => {
      console.log(`Peer connected: ${peerId}`);
    });
    this.client.onPeerDisconnected((peerId) => {
      console.log(`Peer disconnected: ${peerId}`);
    });

    // Enable pub/sub and subscribe to our chat topic. Both must happen before
    // start(); a topic cannot be (un)subscribed once the node is running.
    this.client.enablePubsub();
    this.client.subscribe(this.topic, (peerId, topic, data) => {
      try {
        const msg = JSON.parse(data.toString('utf8'));
        if (msg.type === 'chat') {
          console.log(`[${topic}] ${msg.username}: ${msg.message}`);
        } else if (msg.type === 'user_info') {
          console.log(`[${topic}] ${msg.username} joined`);
        }
      } catch (e) {
        console.log(`[${topic}] (raw) from ${peerId}: ${data.toString('utf8')}`);
      }
    });
  }

  start() {
    console.log('Starting GossipSub chat client...');
    this.client.start(); // throws on failure
    console.log('Client started.');
    console.log(`Our peer ID: ${this.client.getOurPeerId()}`);
    console.log(`Username: ${this.username}`);
    console.log(`Topic: ${this.topic}`);

    // Announce ourselves to the topic.
    this.publish({ type: 'user_info', username: this.username });
  }

  connectToPeer(host, port) {
    console.log(`Connecting to ${host}:${port}`);
    try {
      this.client.connect(host, port);
      console.log('Connection initiated.');
    } catch (e) {
      console.log(`Failed to initiate connection: ${e.message}`);
    }
  }

  publish(obj) {
    const payload = {
      peerId: this.client.getOurPeerId(),
      timestamp: Date.now(),
      ...obj,
    };
    this.client.publish(this.topic, JSON.stringify(payload));
  }

  sendChatMessage(message) {
    this.publish({ type: 'chat', username: this.username, message });
    console.log(`[${this.topic}] ${this.username}: ${message}`);
  }

  stop() {
    console.log('Stopping chat client...');
    this.client.stop();
  }
}

function setupChatCLI(client) {
  const readline = require('readline');
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: 'chat> ',
  });

  console.log('\nInteractive GossipSub chat');
  console.log('Commands:');
  console.log('  connect <host> <port>   - Connect to a peer');
  console.log('  say <message>           - Publish a message to the topic');
  console.log('  peers                   - List connected peers');
  console.log('  status                  - Show client status');
  console.log('  quit                    - Exit');
  console.log('Type anything else to send it as a chat message.\n');

  rl.prompt();

  rl.on('line', (line) => {
    const args = line.trim().split(' ');
    const command = args[0].toLowerCase();

    try {
      switch (command) {
        case 'connect':
          if (args.length >= 3) client.connectToPeer(args[1], parseInt(args[2]));
          else console.log('Usage: connect <host> <port>');
          break;
        case 'say':
          if (args.length >= 2) client.sendChatMessage(args.slice(1).join(' '));
          else console.log('Usage: say <message>');
          break;
        case 'peers':
          console.log(`Connected peers: ${client.client.getPeerIds().join(', ') || 'None'}`);
          break;
        case 'status':
          console.log(`Peer count: ${client.client.getPeerCount()}, topic: ${client.topic}`);
          break;
        case 'quit':
        case 'exit':
          client.stop();
          process.exit(0);
          break;
        default:
          if (command) client.sendChatMessage(line.trim());
          break;
      }
    } catch (error) {
      console.error('Error:', error.message);
    }
    rl.prompt();
  });

  rl.on('close', () => {
    client.stop();
    process.exit(0);
  });
}

async function main() {
  const args = process.argv.slice(2);
  const port = args[0] ? parseInt(args[0]) : 8080;
  const username = args[1] || `User_${Math.random().toString(36).slice(2, 8)}`;
  const topic = args[2] || 'lobby';

  const client = new GossipSubChatExample(port, username, topic);

  try {
    client.start();

    // Optional bootstrap connection: node gossipsub_chat.js <port> <user> <topic> <host> <connectPort>
    if (args.length >= 5) {
      const host = args[3];
      const peerPort = parseInt(args[4]) || 8081;
      setTimeout(() => client.connectToPeer(host, peerPort), 1000);
    }

    setupChatCLI(client);

    process.on('SIGINT', () => {
      console.log('\nShutting down...');
      client.stop();
      process.exit(0);
    });
  } catch (error) {
    console.error('Error:', error.message);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = GossipSubChatExample;
