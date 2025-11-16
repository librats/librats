/**
 * LibRats Node.js Bindings
 * 
 * High-performance peer-to-peer networking library with support for DHT, GossipSub,
 * file transfer, NAT traversal, and more.
 */

const path = require('path');
const fs = require('fs');

// Try to load the native addon from the build directory
let addon;
let addonPath;

// Possible locations for the built addon
const possiblePaths = [
  // Standard node-gyp build location
  path.join(__dirname, '..', 'build', 'Release', 'librats.node'),
  path.join(__dirname, '..', 'build', 'Debug', 'librats.node'),
  // Alternative build locations
  path.join(__dirname, '..', 'build', 'librats.node'),
];

// Try each path
for (const tryPath of possiblePaths) {
  try {
    if (fs.existsSync(tryPath)) {
      addon = require(tryPath);
      addonPath = tryPath;
      break;
    }
  } catch (err) {
    // Continue to next path
  }
}

if (!addon) {
  throw new Error(
    'Could not load librats native addon. ' +
    'Make sure the package is installed correctly and the native library is built. ' +
    'Try running: npm rebuild librats'
  );
}

// Export all native bindings
module.exports = {
  // Main class
  RatsClient: addon.RatsClient,
  
  // Version functions
  getVersionString: addon.getVersionString,
  getVersion: addon.getVersion,
  getGitDescribe: addon.getGitDescribe,
  getAbi: addon.getAbi,
  
  // Constants
  ConnectionStrategy: {
    DIRECT_ONLY: 0,
    STUN_ASSISTED: 1,
    ICE_FULL: 2,
    TURN_RELAY: 3,
    AUTO_ADAPTIVE: 4
  },
  
  ErrorCodes: {
    SUCCESS: 0,
    INVALID_HANDLE: -1,
    INVALID_PARAMETER: -2,
    NOT_RUNNING: -3,
    OPERATION_FAILED: -4,
    PEER_NOT_FOUND: -5,
    MEMORY_ALLOCATION: -6,
    JSON_PARSE: -7
  }
};

// Log successful load for debugging
if (process.env.LIBRATS_DEBUG) {
  console.log(`[librats] Loaded native addon from: ${addonPath}`);
  console.log(`[librats] Version: ${addon.getVersionString()}`);
}

