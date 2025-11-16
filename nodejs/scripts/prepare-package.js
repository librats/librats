#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

/**
 * Prepare package script
 * 
 * This script runs before packing and publishing to ensure the package
 * is ready for distribution. It checks that all necessary files are present.
 */

console.log('Preparing package for distribution...');

const projectRoot = path.resolve(__dirname, '..', '..');
const nodejsRoot = path.resolve(__dirname, '..');

// Critical files that must be included in the package
const criticalFiles = [
    // Node.js binding files
    { path: path.join(nodejsRoot, 'binding.gyp'), desc: 'Node.js binding configuration' },
    { path: path.join(nodejsRoot, 'lib', 'index.js'), desc: 'JavaScript wrapper' },
    { path: path.join(nodejsRoot, 'lib', 'index.d.ts'), desc: 'TypeScript definitions' },
    { path: path.join(nodejsRoot, 'src', 'librats_node.cpp'), desc: 'Node.js binding source' },
    { path: path.join(nodejsRoot, 'scripts', 'build-librats.js'), desc: 'Build script' },
    { path: path.join(nodejsRoot, 'scripts', 'postinstall.js'), desc: 'Post-install script' },
    
    // Librats C++ library files
    { path: path.join(projectRoot, 'CMakeLists.txt'), desc: 'CMake configuration' },
    { path: path.join(projectRoot, 'src', 'librats.cpp'), desc: 'Librats main source' },
    { path: path.join(projectRoot, 'src', 'librats.h'), desc: 'Librats main header' },
    { path: path.join(projectRoot, 'src', 'librats_c.cpp'), desc: 'Librats C API' },
    { path: path.join(projectRoot, 'src', 'librats_c.h'), desc: 'Librats C API header' },
];

let allFilesPresent = true;
let missingFiles = [];

console.log('\nChecking required files:');
for (const file of criticalFiles) {
    if (fs.existsSync(file.path)) {
        console.log(`  ✓ ${file.desc}`);
    } else {
        console.log(`  ✗ ${file.desc} - MISSING`);
        allFilesPresent = false;
        missingFiles.push(file);
    }
}

if (!allFilesPresent) {
    console.error('\n❌ ERROR: Some required files are missing!');
    console.error('\nMissing files:');
    missingFiles.forEach(file => {
        console.error(`  - ${file.path}`);
        console.error(`    (${file.desc})`);
    });
    console.error('\nThe package cannot be published without these files.');
    process.exit(1);
}

// Check that lib directory exists and has content
const libDir = path.join(nodejsRoot, 'lib');
if (!fs.existsSync(libDir)) {
    console.error('\n❌ ERROR: lib directory does not exist!');
    console.error('Create it with the JavaScript wrapper and TypeScript definitions.');
    process.exit(1);
}

// Check that scripts directory exists
const scriptsDir = path.join(nodejsRoot, 'scripts');
if (!fs.existsSync(scriptsDir)) {
    console.error('\n❌ ERROR: scripts directory does not exist!');
    console.error('This directory is required for the build process.');
    process.exit(1);
}

// Count source files
const srcDir = path.join(projectRoot, 'src');
if (fs.existsSync(srcDir)) {
    const sourceFiles = fs.readdirSync(srcDir)
        .filter(f => f.endsWith('.cpp') || f.endsWith('.h'));
    console.log(`\n✓ Found ${sourceFiles.length} source files in src/`);
}

console.log('\n✅ Package is ready for distribution!\n');
console.log('When users install this package via npm:');
console.log('  1. The preinstall script will build the librats C++ library');
console.log('  2. The install script will build the Node.js native addon');
console.log('  3. The postinstall script will verify the installation');
console.log('\nNo manual build steps are required by users!\n');

