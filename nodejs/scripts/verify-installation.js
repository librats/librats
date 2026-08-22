#!/usr/bin/env node

/**
 * Installation verification.
 *
 * Loads the built addon and exercises the smallest end-to-end path — create a
 * node, start it, read its identity, stop it — so a broken native build is
 * reported here rather than in the user's first program.
 */

const checks = [];

function check(name, fn) {
  try {
    const detail = fn();
    checks.push({ name, ok: true, detail });
  } catch (err) {
    checks.push({ name, ok: false, detail: err.message });
  }
}

console.log('Verifying librats installation...\n');

let librats;
check('load the module', () => {
  librats = require('../lib/index.js');
  return 'ok';
});

if (librats) {
  check('version info', () => {
    const v = librats.versionInfo();
    return `${librats.version()} (${v.major}.${v.minor}.${v.patch}.${v.build})`;
  });

  check('enums', () => {
    const need = ['Security', 'Transport', 'TransportMask', 'NatMapping', 'LogLevel'];
    const missing = need.filter((k) => typeof librats[k] !== 'object');
    if (missing.length) throw new Error(`missing: ${missing.join(', ')}`);
    return need.join(', ');
  });

  check('create, start and stop a node', () => {
    const node = new librats.RatsNode(0); // ephemeral port — never collides
    try {
      node.start();
      const id = node.localId;
      if (!id || id.length !== 64) throw new Error(`bad peer id: ${id}`);
      const port = node.listenPort;
      if (!port) throw new Error('no listen port');
      if (node.peerCount !== 0) throw new Error('unexpected peers');
      node.stop();
      return `peer ${id.slice(0, 16)}… on port ${port}`;
    } finally {
      node.destroy();
    }
  });
}

for (const { name, ok, detail } of checks) {
  console.log(`${ok ? '✅' : '❌'} ${name}${detail ? ` — ${detail}` : ''}`);
}

const failed = checks.filter((c) => !c.ok);
if (failed.length === 0) {
  console.log('\nAll checks passed. Use it like this:\n');
  console.log("  const { RatsNode } = require('librats');");
  console.log('  const node = new RatsNode(8080);');
  console.log('  node.start();\n');
  process.exit(0);
}

console.log('\nSome checks failed. Try:');
console.log('  1. npm rebuild librats');
console.log('  2. check that CMake and a C++17 compiler are installed');
console.log('  3. re-read the errors above\n');
process.exit(1);
