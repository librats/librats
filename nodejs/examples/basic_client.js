const { RatsClient, Security } = require('../lib/index');

/**
 * Basic client example: peer events + raw-channel and typed-JSON messaging.
 *
 * Subsystems and callbacks are registered BEFORE start(). Raw messages travel
 * on named channels; typed JSON messages travel by message "type".
 */
class BasicClientExample {
  constructor(port = 8080) {
    // Noise transport (the default) gives encrypted, authenticated channels.
    this.client = new RatsClient({ listenPort: port, security: Security.NOISE });
    this.setupCallbacks();
  }

  setupCallbacks() {
    // Peer lifecycle.
    this.client.onPeerConnected((peerId) => {
      console.log(`Peer connected: ${peerId}`);
      // Greet the new peer on the "chat" channel.
      this.client.send(peerId, 'chat', 'Hello! Welcome to the network.');
    });

    this.client.onPeerDisconnected((peerId) => {
      console.log(`Peer disconnected: ${peerId}`);
    });

    // Raw-channel handler: data arrives as a Buffer.
    this.client.on('chat', (peerId, data) => {
      console.log(`[chat] from ${peerId}: ${data.toString('utf8')}`);
    });

    // Typed JSON requires the JSON subsystem.
    this.client.enableJson();
    this.client.onJson('greeting', (peerId, json) => {
      const data = JSON.parse(json);
      console.log(`[greeting] from ${peerId}:`, data);
    });
  }

  start() {
    console.log('Starting RatsClient...');
    this.client.start(); // throws on failure
    console.log('Client started.');
    console.log(`Our peer ID: ${this.client.getOurPeerId()}`);
    console.log(`Listening on port: ${this.client.getListenPort()}`);
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

  broadcastTestMessages() {
    // Raw broadcast on a channel.
    this.client.broadcast('chat', 'Broadcast message from Node.js!');

    // Typed JSON broadcast.
    const payload = {
      from: this.client.getOurPeerId(),
      timestamp: Date.now(),
      message: 'Hello from Node.js!',
    };
    this.client.broadcastJson('greeting', JSON.stringify(payload));
  }

  printStatus() {
    console.log('\nClient status:');
    console.log(`   Peer count: ${this.client.getPeerCount()}`);
    console.log(`   Our peer ID: ${this.client.getOurPeerId()}`);
    console.log(`   Max peers: ${this.client.getMaxPeers()}`);
    const peerIds = this.client.getPeerIds();
    if (peerIds.length > 0) {
      console.log(`   Connected peers: ${peerIds.join(', ')}`);
    }
    console.log('');
  }

  stop() {
    console.log('Stopping client...');
    this.client.stop();
  }
}

async function main() {
  const args = process.argv.slice(2);
  const port = args[0] ? parseInt(args[0]) : 8080;

  const client = new BasicClientExample(port);

  try {
    client.start();

    const statusInterval = setInterval(() => client.printStatus(), 10000);

    if (args.length >= 2) {
      const host = args[1];
      const peerPort = parseInt(args[2]) || 8081;
      setTimeout(() => client.connectToPeer(host, peerPort), 1000);
    }

    const broadcastInterval = setInterval(() => {
      if (client.client.getPeerCount() > 0) {
        client.broadcastTestMessages();
      }
    }, 15000);

    process.on('SIGINT', () => {
      console.log('\nShutting down...');
      clearInterval(statusInterval);
      clearInterval(broadcastInterval);
      client.stop();
      process.exit(0);
    });

    console.log('Client is running. Press Ctrl+C to stop.');
    console.log('Usage: node basic_client.js [listen_port] [connect_host] [connect_port]');
  } catch (error) {
    console.error('Error:', error.message);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = BasicClientExample;
