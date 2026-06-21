#!/usr/bin/env node

/**
 * Installation Verification Script
 * 
 * Checks if librats was installed correctly and all components are working.
 */

const fs = require('fs');
const path = require('path');

console.log('🔍 Verifying librats installation...\n');

let allChecksPassed = true;

// Check 1: Can we load the module?
console.log('1. Loading librats module...');
try {
    const librats = require('../lib/index.js');
    console.log('   ✅ Module loaded successfully\n');
    
    // Check 2: Version info
    console.log('2. Checking version info...');
    try {
        const versionString = librats.getVersionString();
        const version = librats.getVersion();
        console.log(`   ✅ Version: ${versionString}`);
        console.log(`   ✅ Components: ${version.major}.${version.minor}.${version.patch}.${version.build}\n`);
    } catch (err) {
        console.log('   ❌ Failed to get version info:', err.message);
        allChecksPassed = false;
    }
    
    // Check 3: Constants
    console.log('3. Checking constants...');
    try {
        if (typeof librats.Security.NOISE === 'number') {
            console.log('   ✅ Security constants defined');
        }
        if (typeof librats.LogLevel.INFO === 'number') {
            console.log('   ✅ LogLevel constants defined');
        }
        if (typeof librats.constants.ERRORS.OK === 'number') {
            console.log('   ✅ Error-code constants defined\n');
        }
    } catch (err) {
        console.log('   ❌ Constants check failed:', err.message);
        allChecksPassed = false;
    }
    
    // Check 4: Can we create a client?
    console.log('4. Testing client creation...');
    try {
        const RatsClient = librats.RatsClient;
        const testPort = 19999;
        const client = new RatsClient(testPort);
        console.log('   ✅ Client created successfully\n');
        
        // Check 5: Can we start and stop?
        console.log('5. Testing start/stop...');
        try {
            client.start(); // throws on failure
            console.log('   ✅ Client started successfully');

            const peerId = client.getOurPeerId();
            if (peerId && typeof peerId === 'string') {
                console.log(`   ✅ Got peer ID: ${peerId}`);
            }

            const peerCount = client.getPeerCount();
            console.log(`   ✅ Peer count: ${peerCount}`);

            client.stop();
            console.log('   ✅ Client stopped successfully\n');
        } catch (err) {
            console.log('   ❌ Start/stop test failed:', err.message);
            allChecksPassed = false;
        }
    } catch (err) {
        console.log('   ❌ Client creation failed:', err.message);
        allChecksPassed = false;
    }
    
    // Check 6: TypeScript definitions
    console.log('6. Checking TypeScript definitions...');
    const tsDefsPath = path.join(__dirname, '..', 'lib', 'index.d.ts');
    if (fs.existsSync(tsDefsPath)) {
        console.log('   ✅ TypeScript definitions found\n');
    } else {
        console.log('   ⚠️  Warning: TypeScript definitions not found\n');
    }
    
} catch (err) {
    console.log('   ❌ Failed to load module:', err.message);
    console.log('\nError details:');
    console.log(err.stack);
    allChecksPassed = false;
}

// Summary
console.log('━'.repeat(60));
if (allChecksPassed) {
    console.log('✅ All checks passed! Librats is installed correctly.\n');
    console.log('You can now use librats in your project:');
    console.log("  const { RatsClient } = require('librats');");
    console.log('  const client = new RatsClient(8080);');
    console.log('  client.start();\n');
    process.exit(0);
} else {
    console.log('❌ Some checks failed. Installation may be incomplete.\n');
    console.log('Troubleshooting:');
    console.log('  1. Try rebuilding: npm rebuild librats');
    console.log('  2. Check build tools are installed (CMake, C++ compiler)');
    console.log('  3. Check the logs above for specific errors');
    console.log('  4. See: https://github.com/librats/librats/tree/main/nodejs\n');
    process.exit(1);
}

