#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

// Check if we're in a development install (node_modules doesn't contain librats)
const isDev = !__dirname.includes('node_modules');

if (isDev) {
  console.log('\n✨ Development installation detected');
  console.log('   Librats native addon has been built for local development\n');
} else {
  console.log('\n✅ Librats installed successfully!');
  console.log('   Native addon is ready to use\n');
}

// Check if the addon was built successfully
const possiblePaths = [
  path.join(__dirname, '..', 'build', 'Release', 'librats.node'),
  path.join(__dirname, '..', 'build', 'Debug', 'librats.node'),
];

let addonFound = false;
for (const addonPath of possiblePaths) {
  if (fs.existsSync(addonPath)) {
    addonFound = true;
    if (process.env.LIBRATS_DEBUG) {
      console.log(`   Native addon: ${addonPath}`);
    }
    break;
  }
}

if (!addonFound) {
  console.warn('⚠️  Warning: Native addon not found');
  console.warn('   The build may have failed. Try running:');
  console.warn('   npm rebuild librats\n');
}

// Show quick start example
if (!process.env.CI && !process.env.npm_config_global) {
  console.log('Verify installation:');
  console.log('  npm run verify\n');
  console.log('Quick start:');
  console.log('```javascript');
  console.log("const { RatsClient } = require('librats');");
  console.log('const client = new RatsClient(8080);');
  console.log('client.start();');
  console.log('```\n');
  console.log('Documentation: https://github.com/librats/librats/tree/main/nodejs\n');
}

