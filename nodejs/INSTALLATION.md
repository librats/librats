# Automatic Installation Process for Node.js Package

This document explains how the automatic installation process works for the librats Node.js package.

## Overview

The librats Node.js package has been configured for **transparent, automatic installation** when users install it via npm. No manual build steps are required.

## Installation Flow

When a user runs `npm install librats`, the following happens automatically:

### 1. **preinstall** - Build Native Library (`scripts/build-librats.js`)
   - Checks if CMake is installed
   - Checks if necessary source files are present
   - Creates `nodejs/build-native/` directory for the native library build
   - Runs CMake to configure the build
   - Builds the native librats C++ library (static library)
   - On Windows: Builds both Debug and Release configurations with parallel builds
   - On Linux/macOS: Builds using Unix Makefiles with parallel builds
   - Verifies the library was built successfully

### 2. **install** - Build Node.js Addon (`node-gyp rebuild`)
   - Uses `binding.gyp` to configure the build
   - Links against the librats library built in step 1 (from `nodejs/build-native/`)
   - Builds the native Node.js addon (`librats.node`)
   - Places the addon in `nodejs/build/Release/` or `nodejs/build/Debug/`

### 3. **postinstall** - Verify Installation (`scripts/postinstall.js`)
   - Checks if the native addon was built successfully
   - Displays helpful installation messages
   - Shows quick start example

## Package Structure

```
nodejs/
├── package.json              # Package configuration with install scripts
├── binding.gyp               # Node.js native addon build configuration
├── lib/
│   ├── index.js             # JavaScript wrapper (loads native addon)
│   └── index.d.ts           # TypeScript definitions
├── src/
│   └── librats_node.cpp     # Node.js binding C++ code
├── scripts/
│   ├── build-librats.js     # Builds the native librats library
│   ├── postinstall.js       # Post-installation verification
│   └── prepare-package.js   # Pre-publish checks
├── build-native/             # CMake build directory (created during install)
│   └── lib/                 # Contains librats.a or rats.lib
├── build/                    # node-gyp build directory
│   └── Release/             # Contains librats.node addon
└── examples/
    └── ...                   # Example code

Parent directory (included in package):
../
├── CMakeLists.txt           # CMake configuration for librats
├── src/                     # Librats C++ source files
└── 3rdparty/                # Third-party dependencies
```

## Files Included in npm Package

The `files` field in `package.json` ensures these are included:

```json
{
  "files": [
    "lib/**/*",              // JavaScript wrapper & TypeScript defs
    "src/**/*",              // Node.js binding source
    "scripts/**/*",          // Build scripts
    "binding.gyp",           // Node-gyp configuration
    "README.md",             // Documentation
    "../src/**/*.cpp",       // Librats C++ sources
    "../src/**/*.h",         // Librats headers
    "../src/**/*.in",        // CMake template files
    "../3rdparty/**/*",      // Third-party code
    "../CMakeLists.txt",     // CMake configuration
    "../LICENSE",            // License file
    "!../src/main.cpp"       // Exclude main.cpp (not needed for library)
  ]
}
```

## Prerequisites for Users

Users need these tools installed (automatic detection with helpful errors):

1. **Node.js** (>= 20.0.0)
2. **CMake** (>= 3.10)
3. **C++ Compiler**:
   - Windows: Visual Studio Build Tools 2017+
   - Linux: build-essential (gcc, g++, make)
   - macOS: Xcode Command Line Tools

## Platform-Specific Build Details

### Windows
- Detects Visual Studio version (2022, 2019, or 2017)
- Builds both Debug and Release configurations
- Uses MSVC compiler
- Links against: `ws2_32.lib`, `iphlpapi.lib`, `bcrypt.lib`

### Linux
- Uses Unix Makefiles
- Parallel build with `-j4`
- Links against: `pthread`
- Requires: `build-essential`, `cmake`

### macOS
- Uses Unix Makefiles
- Links against: `pthread`
- Requires: Xcode Command Line Tools

## Error Handling

Each script provides detailed error messages:

- **CMake not found**: Shows installation instructions for the platform
- **Build tools not found**: Links to download pages
- **Source files missing**: Indicates package corruption
- **Build failed**: Shows troubleshooting steps

## Testing the Installation

### Local Development
```bash
cd nodejs
npm install
npm test
```

### Testing as End User
```bash
# In a test directory
npm init -y
npm install /path/to/librats/nodejs
node -e "const {RatsClient} = require('librats'); console.log('Success!');"
```

### Testing from npm (after publishing)
```bash
npm install librats
node -e "const {RatsClient} = require('librats'); console.log('Success!');"
```

## Publishing the Package

Before publishing, ensure:

1. All tests pass: `npm test`
2. Package can be built from scratch: `npm run clean && npm install`
3. Examples work: `node examples/basic_client.js`
4. Version is updated in `package.json`

Then publish:
```bash
npm publish
```

The `prepare` script will verify all required files are present before publishing.

## Debugging Installation Issues

Enable debug output:
```bash
LIBRATS_DEBUG=1 npm install librats
```

This will show:
- Where the native addon was loaded from
- The librats version
- Build progress and paths

## Advantages of This Approach

✅ **Zero Manual Steps**: Users just run `npm install`  
✅ **Cross-Platform**: Automatic detection and configuration  
✅ **No Pre-Built Binaries**: Fresh build for each system (better security)  
✅ **Developer Friendly**: Easy to debug and modify  
✅ **Type Safe**: Full TypeScript support  
✅ **Well Documented**: Clear error messages and troubleshooting  

## Alternative Approaches (Not Used)

1. **Prebuildify/node-pre-gyp**: 
   - Would require maintaining pre-built binaries for many platforms
   - More complex CI/CD setup
   - Security concerns with pre-built binaries

2. **Native Module Wrapper (N-API only)**:
   - Would require rewriting binding layer
   - librats C API is already stable

3. **WASM**:
   - Performance overhead
   - Doesn't support all required system calls

## Maintenance

When adding new features to librats:

1. Update `src/librats_node.cpp` with new bindings
2. Update `lib/index.d.ts` with TypeScript definitions
3. Add examples if needed
4. Update README with new APIs
5. Increment version in `package.json`

The build process automatically handles new source files added to `../src/`.

## Support

For installation issues:
- Check CMake is installed: `cmake --version`
- Check compiler is available: `gcc --version` (Linux/Mac) or `cl` (Windows)
- Ensure Node.js version is >= 20: `node --version`
- Try clean rebuild: `npm run clean && npm install`

For more help, see:
- [Main README](./README.md)
- [Examples](./examples/)
- [GitHub Issues](https://github.com/librats/librats/issues)

