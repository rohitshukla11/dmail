import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { nodePolyfills } from 'vite-plugin-node-polyfills'

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    nodePolyfills({
      // Whether to polyfill `global` for Node.js compatibility
      globals: {
        global: true,
        Buffer: true,
      },
      // Polyfills for specific Node.js modules
      protocolImports: true,
    }),
  ],
  define: {
    global: 'globalThis',
  },
})
