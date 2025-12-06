#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

/**
 * Prepare package script
 * 
 * This script runs before packing and publishing to ensure the package
 * is ready for distribution. It copies the native C++ source files into
 * the nodejs package directory so they can be included in the npm package.
 */

console.log('Preparing package for distribution...');

const projectRoot = path.resolve(__dirname, '..', '..');
const nodejsRoot = path.resolve(__dirname, '..');
const nativeSrcDir = path.join(nodejsRoot, 'native-src');

// Helper function to copy a file
function copyFile(src, dest) {
    const destDir = path.dirname(dest);
    if (!fs.existsSync(destDir)) {
        fs.mkdirSync(destDir, { recursive: true });
    }
    fs.copyFileSync(src, dest);
}

// Helper function to copy a directory recursively
function copyDir(src, dest, filter = () => true) {
    if (!fs.existsSync(dest)) {
        fs.mkdirSync(dest, { recursive: true });
    }
    
    const entries = fs.readdirSync(src, { withFileTypes: true });
    for (const entry of entries) {
        const srcPath = path.join(src, entry.name);
        const destPath = path.join(dest, entry.name);
        
        if (entry.isDirectory()) {
            copyDir(srcPath, destPath, filter);
        } else if (filter(entry.name)) {
            copyFile(srcPath, destPath);
        }
    }
}

// Check that we're in the project root with the source files
if (!fs.existsSync(path.join(projectRoot, 'CMakeLists.txt'))) {
    console.error('\n❌ ERROR: Cannot find CMakeLists.txt in project root.');
    console.error('This script must be run from within the librats repository.');
    console.error(`Expected project root: ${projectRoot}`);
    process.exit(1);
}

if (!fs.existsSync(path.join(projectRoot, 'src'))) {
    console.error('\n❌ ERROR: Cannot find src/ directory in project root.');
    console.error('This script must be run from within the librats repository.');
    process.exit(1);
}

// Clean up existing native-src directory
if (fs.existsSync(nativeSrcDir)) {
    console.log('Cleaning existing native-src directory...');
    fs.rmSync(nativeSrcDir, { recursive: true, force: true });
}

console.log('\nCopying native source files to native-src/...');

// Create native-src directory
fs.mkdirSync(nativeSrcDir, { recursive: true });

// Copy CMakeLists.txt
console.log('  Copying CMakeLists.txt...');
copyFile(
    path.join(projectRoot, 'CMakeLists.txt'),
    path.join(nativeSrcDir, 'CMakeLists.txt')
);

// Copy LICENSE
if (fs.existsSync(path.join(projectRoot, 'LICENSE'))) {
    console.log('  Copying LICENSE...');
    copyFile(
        path.join(projectRoot, 'LICENSE'),
        path.join(nativeSrcDir, 'LICENSE')
    );
}

// Copy version.rc.in
if (fs.existsSync(path.join(projectRoot, 'version.rc.in'))) {
    console.log('  Copying version.rc.in...');
    copyFile(
        path.join(projectRoot, 'version.rc.in'),
        path.join(nativeSrcDir, 'version.rc.in')
    );
}

// Copy src/ directory (only .cpp, .h, .hpp, .in files, excluding main.cpp)
console.log('  Copying src/ directory...');
const srcFilter = (name) => {
    if (name === 'main.cpp') return false;
    return name.endsWith('.cpp') || name.endsWith('.h') || 
           name.endsWith('.hpp') || name.endsWith('.in');
};
copyDir(
    path.join(projectRoot, 'src'),
    path.join(nativeSrcDir, 'src'),
    srcFilter
);

// Copy 3rdparty/ directory
if (fs.existsSync(path.join(projectRoot, '3rdparty'))) {
    console.log('  Copying 3rdparty/ directory...');
    copyDir(
        path.join(projectRoot, '3rdparty'),
        path.join(nativeSrcDir, '3rdparty')
    );
}

// Count copied files
let cppCount = 0;
let hCount = 0;
const countFiles = (dir) => {
    if (!fs.existsSync(dir)) return;
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
            countFiles(fullPath);
        } else if (entry.name.endsWith('.cpp')) {
            cppCount++;
        } else if (entry.name.endsWith('.h') || entry.name.endsWith('.hpp')) {
            hCount++;
        }
    }
};
countFiles(nativeSrcDir);

console.log(`\n✓ Copied ${cppCount} source files and ${hCount} header files`);

// Verify critical files in nodejs package
const criticalFiles = [
    { path: path.join(nodejsRoot, 'binding.gyp'), desc: 'Node.js binding configuration' },
    { path: path.join(nodejsRoot, 'lib', 'index.js'), desc: 'JavaScript wrapper' },
    { path: path.join(nodejsRoot, 'lib', 'index.d.ts'), desc: 'TypeScript definitions' },
    { path: path.join(nodejsRoot, 'src', 'librats_node.cpp'), desc: 'Node.js binding source' },
    { path: path.join(nodejsRoot, 'scripts', 'build-librats.js'), desc: 'Build script' },
    { path: path.join(nodejsRoot, 'scripts', 'postinstall.js'), desc: 'Post-install script' },
    { path: path.join(nativeSrcDir, 'CMakeLists.txt'), desc: 'CMake configuration (copied)' },
    { path: path.join(nativeSrcDir, 'src', 'librats.cpp'), desc: 'Librats main source (copied)' },
    { path: path.join(nativeSrcDir, 'src', 'librats.h'), desc: 'Librats main header (copied)' },
    { path: path.join(nativeSrcDir, 'src', 'librats_c.cpp'), desc: 'Librats C API (copied)' },
    { path: path.join(nativeSrcDir, 'src', 'librats_c.h'), desc: 'Librats C API header (copied)' },
];

let allFilesPresent = true;
let missingFiles = [];

console.log('\nVerifying required files:');
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

console.log('\n✅ Package is ready for distribution!\n');
console.log('The native-src/ directory now contains all C++ source files needed to build.');
console.log('\nWhen users install this package via npm:');
console.log('  1. The preinstall script will build the librats C++ library');
console.log('  2. The install script will build the Node.js native addon');
console.log('  3. The postinstall script will verify the installation');
console.log('\nNo manual build steps are required by users!\n');
