const path = require('path');
const { getDefaultConfig, mergeConfig } = require('@react-native/metro-config');

// The module under test lives one directory up and is linked, not installed, so
// Metro has to watch it as source.
const moduleRoot = path.resolve(__dirname, '..');

/**
 * @type {import('@react-native/metro-config').MetroConfig}
 */
const config = {
  watchFolders: [moduleRoot],

  resolver: {
    // The parent package keeps react-native as a devDependency (for JSI headers
    // and typechecking). Metro would otherwise find that second copy through the
    // link and bundle two Reacts, which fails at runtime with hook/renderer
    // errors. Pin resolution to this app's node_modules instead.
    nodeModulesPaths: [path.resolve(__dirname, 'node_modules')],
    blockList: [
      new RegExp(`^${escape(path.join(moduleRoot, 'node_modules'))}\\/.*$`),
    ],
  },
};

// Escape a path for embedding in a RegExp (Windows separators included).
function escape(p) {
  return p.replace(/[/\\^$*+?.()|[\]{}]/g, '\\$&');
}

module.exports = mergeConfig(getDefaultConfig(__dirname), config);
