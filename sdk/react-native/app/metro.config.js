const path = require('path');
const {getDefaultConfig, mergeConfig} = require('@react-native/metro-config');

/**
 * Metro configuration
 * https://reactnative.dev/docs/metro
 *
 * The app imports the typed layer from ../src (the module's own sources, as the Gradle build also compiles the module from source):
 * Metro must watch that folder, and the layer's `react-native` import must resolve to the app's copy, not look for one next to ../src.
 *
 * @type {import('metro-config').MetroConfig}
 */
const config = {
  watchFolders: [path.resolve(__dirname, '..', 'src')],
  resolver: {
    extraNodeModules: new Proxy({}, {get: (_, name) => path.join(__dirname, 'node_modules', String(name))}),
  },
};

module.exports = mergeConfig(getDefaultConfig(__dirname), config);
