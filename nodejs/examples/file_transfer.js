const { RatsClient } = require('../lib/index');
const fs = require('fs');
const path = require('path');

/**
 * File transfer example (push model).
 *
 * The sender offers a file/directory with sendFile()/sendDirectory(); the
 * receiver gets an onFileOffer() callback and accepts with acceptFile() (the
 * (peerId, transferId) pair names the transfer). Progress and completion arrive
 * via onFileProgress()/onFileComplete(). The file-transfer subsystem and its
 * callbacks are registered BEFORE start().
 */
class FileTransferExample {
  constructor(port = 8080) {
    this.client = new RatsClient(port);
    this.transfers = new Map(); // transferId -> metadata
    this.downloadDir = path.join(__dirname, 'transfers', 'downloads');
    fs.mkdirSync(this.downloadDir, { recursive: true });
    this.setupCallbacks();
  }

  setupCallbacks() {
    this.client.onPeerConnected((peerId) => console.log(`Peer connected: ${peerId}`));
    this.client.onPeerDisconnected((peerId) => console.log(`Peer disconnected: ${peerId}`));

    // Enable the subsystem first; temp dir holds in-progress downloads.
    this.client.enableFileTransfer(path.join(__dirname, 'transfers', 'temp'));

    // Incoming offer: auto-accept and save under downloadDir.
    this.client.onFileOffer((peerId, transferId, name, size, isDirectory) => {
      const dest = path.join(this.downloadDir, name);
      console.log(
        `Incoming ${isDirectory ? 'directory' : 'file'} offer "${name}" ` +
        `(${size} bytes) from ${peerId} [transfer ${transferId}]`
      );
      console.log(`Accepting, saving to: ${dest}`);
      this.client.acceptFile(peerId, transferId, dest);
      this.transfers.set(transferId, { type: 'receive', peerId, dest, startTime: Date.now() });
    });

    this.client.onFileProgress((transferId, peerId, bytesTransferred, totalBytes, status) => {
      const pct = totalBytes > 0 ? Math.round((bytesTransferred / totalBytes) * 100) : 0;
      console.log(`Transfer ${transferId}: ${pct}% (${bytesTransferred}/${totalBytes}) status=${status}`);
    });

    this.client.onFileComplete((transferId, success, filePath) => {
      if (success) {
        console.log(`Transfer ${transferId} completed: ${filePath}`);
      } else {
        console.log(`Transfer ${transferId} failed`);
      }
      this.transfers.delete(transferId);
    });
  }

  start() {
    console.log('Starting file transfer client...');
    this.client.start(); // throws on failure
    console.log('Client started.');
    console.log(`Our peer ID: ${this.client.getOurPeerId()}`);
    console.log(`Downloads: ${this.downloadDir}`);
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

  sendFileToPeer(peerId, filePath) {
    if (!fs.existsSync(filePath)) {
      console.log(`File not found: ${filePath}`);
      return 0;
    }
    const transferId = this.client.sendFile(peerId, filePath);
    if (transferId) {
      this.transfers.set(transferId, { type: 'send', peerId, filePath, startTime: Date.now() });
      console.log(`Sending "${filePath}" to ${peerId} [transfer ${transferId}]`);
    } else {
      console.log('Failed to initiate file transfer (subsystem enabled? peer connected?)');
    }
    return transferId;
  }

  sendDirectoryToPeer(peerId, dirPath) {
    if (!fs.existsSync(dirPath)) {
      console.log(`Directory not found: ${dirPath}`);
      return 0;
    }
    const transferId = this.client.sendDirectory(peerId, dirPath);
    if (transferId) {
      this.transfers.set(transferId, { type: 'send_dir', peerId, dirPath, startTime: Date.now() });
      console.log(`Sending directory "${dirPath}" to ${peerId} [transfer ${transferId}]`);
    } else {
      console.log('Failed to initiate directory transfer');
    }
    return transferId;
  }

  stop() {
    console.log('Stopping file transfer client...');
    this.client.stop();
  }
}

function setupInteractiveCLI(client) {
  const readline = require('readline');
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: 'librats> ',
  });

  console.log('\nInteractive file transfer CLI');
  console.log('Commands:');
  console.log('  connect <host> <port>          - Connect to a peer');
  console.log('  send <peerId> <file>           - Send a file to a peer');
  console.log('  senddir <peerId> <dir>         - Send a directory to a peer');
  console.log('  cancel <peerId> <transferId>   - Cancel a transfer');
  console.log('  pause <peerId> <transferId>    - Pause a transfer');
  console.log('  resume <peerId> <transferId>   - Resume a transfer');
  console.log('  peers                          - List connected peers');
  console.log('  quit                           - Exit\n');

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
        case 'send':
          if (args.length >= 3) client.sendFileToPeer(args[1], args[2]);
          else console.log('Usage: send <peerId> <file>');
          break;
        case 'senddir':
          if (args.length >= 3) client.sendDirectoryToPeer(args[1], args[2]);
          else console.log('Usage: senddir <peerId> <dir>');
          break;
        case 'cancel':
          if (args.length >= 3) client.client.cancelFile(args[1], parseInt(args[2]));
          else console.log('Usage: cancel <peerId> <transferId>');
          break;
        case 'pause':
          if (args.length >= 3) client.client.pauseFile(args[1], parseInt(args[2]));
          else console.log('Usage: pause <peerId> <transferId>');
          break;
        case 'resume':
          if (args.length >= 3) client.client.resumeFile(args[1], parseInt(args[2]));
          else console.log('Usage: resume <peerId> <transferId>');
          break;
        case 'peers':
          console.log(`Connected peers: ${client.client.getPeerIds().join(', ') || 'None'}`);
          break;
        case 'quit':
        case 'exit':
          client.stop();
          process.exit(0);
          break;
        default:
          if (command) console.log(`Unknown command: ${command}`);
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

  const client = new FileTransferExample(port);

  try {
    client.start();

    if (args.length >= 2) {
      const host = args[1];
      const peerPort = parseInt(args[2]) || 8081;
      setTimeout(() => client.connectToPeer(host, peerPort), 1000);
    }

    setupInteractiveCLI(client);

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

module.exports = FileTransferExample;
