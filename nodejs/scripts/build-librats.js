#!/usr/bin/env node

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

// Determine platform
const isWindows = process.platform === 'win32';
const isMac = process.platform === 'darwin';
const isLinux = process.platform === 'linux';

// Paths
const nodejsRoot = path.resolve(__dirname, '..');
const projectRoot = path.resolve(__dirname, '..', '..');
const buildDir = path.resolve(nodejsRoot, 'build-native');  // Build dir inside nodejs/
const srcDir = path.resolve(projectRoot, 'src');
const cmakeLists = path.resolve(projectRoot, 'CMakeLists.txt');

console.log('Building librats native library...');
console.log(`Platform: ${process.platform}`);
console.log(`Project root: ${projectRoot}`);
console.log(`Build directory: ${buildDir}`);

// Check if CMake is installed
try {
    execSync('cmake --version', { stdio: 'pipe' });
    console.log('✓ CMake found');
} catch (error) {
    console.error('\n❌ ERROR: CMake is not installed or not in PATH');
    console.error('\nCMake is required to build librats.');
    console.error('Please install CMake:');
    if (isWindows) {
        console.error('  - Download from: https://cmake.org/download/');
        console.error('  - Or use: winget install Kitware.CMake');
        console.error('  - Or use: choco install cmake');
    } else if (isMac) {
        console.error('  - Use Homebrew: brew install cmake');
        console.error('  - Or download from: https://cmake.org/download/');
    } else if (isLinux) {
        console.error('  - Use: sudo apt install cmake');
        console.error('  - Or: sudo yum install cmake');
        console.error('  - Or download from: https://cmake.org/download/');
    }
    console.error('\nAfter installing CMake, run: npm install\n');
    process.exit(1);
}

// Check if CMakeLists.txt exists
if (!fs.existsSync(cmakeLists)) {
    console.error('ERROR: CMakeLists.txt not found in project root.');
    console.error('Make sure all source files are included in the npm package.');
    process.exit(1);
}

// Check if src directory exists
if (!fs.existsSync(srcDir)) {
    console.error('ERROR: src directory not found.');
    console.error('Make sure all source files are included in the npm package.');
    process.exit(1);
}

// Create build directory if it doesn't exist
if (!fs.existsSync(buildDir)) {
    console.log(`Creating build directory: ${buildDir}`);
    fs.mkdirSync(buildDir, { recursive: true });
}

// Helper function to execute commands
function exec(command, options = {}) {
    console.log(`> ${command}`);
    try {
        execSync(command, {
            cwd: buildDir,
            stdio: 'inherit',
            ...options
        });
    } catch (error) {
        console.error(`Command failed: ${command}`);
        throw error;
    }
}

try {
    // Configure CMake with appropriate options
    console.log('\nConfiguring CMake...');
    
    let cmakeArgs = [
        '-DRATS_BUILD_TESTS=OFF',
        '-DRATS_BUILD_EXAMPLES=OFF',
        '-DRATS_STATIC_LIBRARY=ON',
        '-DRATS_BINDINGS=ON',
        '-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDLL'
    ];

    // Add platform-specific CMake arguments
    if (isWindows) {
        // Try to detect Visual Studio version
        const vsVersions = ['2022', '2019', '2017'];
        let generator = null;
        
        for (const version of vsVersions) {
            try {
                execSync(`where "C:\\Program Files\\Microsoft Visual Studio\\${version}"`, { stdio: 'ignore' });
                generator = `Visual Studio ${version === '2022' ? '17' : version === '2019' ? '16' : '15'} ${version}`;
                break;
            } catch (e) {
                // Try next version
            }
        }
        
        if (generator) {
            cmakeArgs.push(`-G "${generator}"`);
            cmakeArgs.push('-A x64');
        }
    } else if (isMac) {
        // Use Unix Makefiles on macOS
        cmakeArgs.push('-G "Unix Makefiles"');
    } else if (isLinux) {
        // Use Unix Makefiles on Linux
        cmakeArgs.push('-G "Unix Makefiles"');
    }

    const cmakeConfigCmd = `cmake ${cmakeArgs.join(' ')} ../..`;
    exec(cmakeConfigCmd);

    // Build the library
    console.log('\nBuilding librats library...');
    
    if (isWindows) {
        // Build both Debug and Release configurations on Windows
        exec('cmake --build . --config Debug --parallel');
        exec('cmake --build . --config Release --parallel');
        console.log('\nLibrats built successfully (Debug and Release)');
    } else {
        exec('cmake --build . -- -j4');
        console.log('\nLibrats built successfully');
    }

    // Verify the library was built
    const expectedLibPaths = isWindows 
        ? [
            path.join(buildDir, 'lib', 'Debug', 'rats.lib'),
            path.join(buildDir, 'lib', 'Release', 'rats.lib')
        ]
        : [
            path.join(buildDir, 'lib', 'librats.a')
        ];
    
    console.log('\nBuild directory:', buildDir);

    let foundLib = false;
    for (const libPath of expectedLibPaths) {
        if (fs.existsSync(libPath)) {
            console.log(`✓ Found library: ${libPath}`);
            foundLib = true;
        }
    }

    if (!foundLib) {
        console.warn('WARNING: Could not find built library files.');
        console.warn('Expected paths:');
        expectedLibPaths.forEach(p => console.warn(`  - ${p}`));
        console.warn('The build may have failed. Check the output above.');
        // Don't exit with error - let node-gyp try anyway
    }

    console.log('\n✓ Librats build completed successfully!\n');

} catch (error) {
    console.error('\n✗ Failed to build librats library');
    console.error('Error:', error.message);
    
    // Provide helpful error messages
    console.error('\nTroubleshooting:');
    
    if (isWindows) {
        console.error('- Ensure Visual Studio Build Tools or Visual Studio is installed');
        console.error('- Download from: https://visualstudio.microsoft.com/downloads/');
        console.error('- Or run: npm install --global windows-build-tools');
    } else if (isMac) {
        console.error('- Ensure Xcode Command Line Tools are installed');
        console.error('- Run: xcode-select --install');
    } else if (isLinux) {
        console.error('- Ensure build-essential is installed');
        console.error('- Run: sudo apt install build-essential cmake');
    }
    
    console.error('- Ensure CMake is installed and available in PATH');
    console.error('- CMake download: https://cmake.org/download/');
    
    process.exit(1);
}

