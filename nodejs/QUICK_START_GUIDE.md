# Quick Start Guide - Automatic Installation

## ✨ What Changed

Your librats Node.js package now has **fully automatic installation**!

## 🎯 For End Users (After npm publish)

```bash
# Install from npm - everything builds automatically!
npm install librats

# Verify it works
npm run verify

# Use it in your code
node -e "const {RatsClient, Security} = require('librats'); const c = new RatsClient({listenPort: 8080, security: Security.NOISE}); c.start(); console.log('Ready:', c.getOurPeerId()); c.stop();"
```

That's it! No manual build steps needed.

## 🔧 What Happens Automatically

1. **preinstall** - Builds librats C++ library using CMake
2. **install** - Builds Node.js native addon using node-gyp  
3. **postinstall** - Verifies everything works

## 📋 Prerequisites Users Need

- **Node.js** >= 20.0.0
- **CMake** >= 3.14
- **C++ Compiler** (C++17):
  - Windows: Visual Studio Build Tools 2017+
  - Linux: `sudo apt install build-essential cmake`
  - macOS: `xcode-select --install`

## 🧪 Testing Your Setup

### Test Locally
```bash
cd nodejs
npm install
npm run verify
npm test
```

### Test as Package
```bash
# In a test directory
npm install /path/to/librats/nodejs
npm run verify
```

## 📦 Publishing

```bash
cd nodejs
npm version patch  # or minor, or major
npm publish
```

The `prepare` script automatically validates everything before publishing.

## 🎓 New Scripts Available

- `npm run verify` - Check installation is working
- `npm run build` - Rebuild native addon
- `npm run clean` - Clean build artifacts
- `npm test` - Run tests
- `npm run prepare` - Validate before publishing

## 📚 Documentation

- `README.md` - User-facing documentation
- `INSTALLATION.md` - Detailed installation process
- `SETUP_COMPLETE.md` - Complete setup documentation
- `examples/` - Usage examples

## ✅ Verification Checklist

Before publishing:
- [ ] Test on Windows
- [ ] Test on Linux  
- [ ] Test on macOS
- [ ] `npm run verify` passes
- [ ] `npm test` passes
- [ ] Update version in package.json
- [ ] `npm publish`

## 🚀 Next Steps

1. Test the installation locally: `cd nodejs && npm install`
2. Run verification: `npm run verify`
3. Test examples: `node examples/basic_client.js`
4. Publish when ready: `npm publish`

## 💡 Tips

- Set `LIBRATS_DEBUG=1` for detailed build output
- Users can run `npm run verify` to diagnose issues
- Build scripts provide helpful error messages
- All source files automatically included in package

---

**Your package is ready for transparent npm installation! 🎉**

