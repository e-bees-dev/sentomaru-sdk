// The facade lives in ../src, outside this project: its `@capacitor/core` import must resolve to this app's copy.
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';

export default defineConfig({
  base: './',
  resolve: { alias: { '@capacitor/core': fileURLToPath(new URL('./node_modules/@capacitor/core', import.meta.url)) } },
  server: { fs: { allow: ['..'] } },
});
