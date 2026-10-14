/**
 * File transfer (push model).
 *
 * The sender offers with sendFile()/sendDirectory(); the receiver gets an
 * onFileOffer() and answers with acceptFile()/rejectFile() — the
 * (peerId, transferId) pair names the transfer on both sides. Progress and
 * completion arrive on onFileProgress()/onFileComplete().
 *
 * The subsystem and all three callbacks are registered before start().
 *
 *   node file_transfer.js [listenPort] [connectHost] [connectPort]
 */

const fs = require('fs');
const path = require('path');
const readline = require('readline');
const { RatsNode } = require('../lib/index');

const [portArg, host, peerPortArg] = process.argv.slice(2);

const downloadDir = path.join(__dirname, 'transfers', 'downloads');
const tempDir = path.join(__dirname, 'transfers', 'temp');
fs.mkdirSync(downloadDir, { recursive: true });

const node = new RatsNode({ listenPort: portArg ? Number(portArg) : 8080 });

node.onPeerConnected((peerId) => console.log(`+ peer ${peerId}`));
node.onPeerDisconnected((peerId, reason) => console.log(`- peer ${peerId} (${reason})`));

// tempDir holds in-progress downloads; they move to their destination on completion.
node.enableFileTransfer(tempDir);

// Auto-accept every offer into downloadDir. A real app would ask the user here.
node.onFileOffer((peerId, transferId, name, size, isDirectory) => {
  const dest = path.join(downloadDir, name);
  console.log(
    `offer [${transferId}] ${isDirectory ? 'dir' : 'file'} "${name}" ` +
    `(${size} bytes) from ${peerId} -> ${dest}`
  );
  node.acceptFile(peerId, transferId, dest);
});

node.onFileProgress((p) => {
  const pct = p.totalBytes > 0 ? Math.round((p.bytesTransferred / p.totalBytes) * 100) : 0;
  const kib = Math.round(p.rateBytesPerSec / 1024);
  console.log(`[${p.transferId}] ${p.direction} ${p.status} ${pct}% ` +
              `(${p.bytesTransferred}/${p.totalBytes}, ${kib} KiB/s)`);
});

node.onFileComplete((peerId, transferId, success, filePath) => {
  console.log(success ? `[${transferId}] done: ${filePath}` : `[${transferId}] failed`);
});

node.start();

console.log(`peer id   ${node.localId}`);
console.log(`downloads ${downloadDir}`);

if (host) node.connect(host, Number(peerPortArg) || 8081);

// ---- interactive prompt ----

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: 'librats> ',
});

console.log([
  '',
  'commands:',
  '  connect <host> <port>          dial a peer',
  '  send <peerId> <file>           offer a file',
  '  senddir <peerId> <dir>         offer a directory tree',
  '  pause|resume|cancel <peerId> <transferId>',
  '  peers                          list connected peers',
  '  quit                           exit',
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
        need(rest, 2, 'connect <host> <port>') && node.connect(rest[0], Number(rest[1]));
        break;
      case 'send':
        need(rest, 2, 'send <peerId> <file>') && offer('sendFile', rest[0], rest[1]);
        break;
      case 'senddir':
        need(rest, 2, 'senddir <peerId> <dir>') && offer('sendDirectory', rest[0], rest[1]);
        break;
      case 'pause':
      case 'resume':
      case 'cancel':
        if (need(rest, 2, `${command} <peerId> <transferId>`) &&
            !node[`${command}File`](rest[0], Number(rest[1]))) {
          console.log(`no transfer ${rest[1]} with that peer`);
        }
        break;
      case 'peers':
        console.log(node.peerIds.join('\n') || '(none)');
        break;
      case 'quit':
      case 'exit':
        rl.close();
        return;
      default:
        console.log(`unknown command: ${command}`);
    }
  } catch (err) {
    console.error(err.message);
  }
  rl.prompt();
});

rl.on('close', () => node.destroy());

function need(args, count, usage) {
  if (args.length >= count) return true;
  console.log(`usage: ${usage}`);
  return false;
}

function offer(method, peerId, target) {
  if (!fs.existsSync(target)) {
    console.log(`not found: ${target}`);
    return;
  }
  try {
    const transferId = node[method](peerId, target);
    console.log(`offering "${target}" as [${transferId}]`);
  } catch (err) {
    console.log(`offer refused: ${err.code}`);   // NO_SUCH_PEER, NOT_FOUND, …
  }
}
