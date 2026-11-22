import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { fileURLToPath, URL } from 'node:url'

// Proxy /v1 to the node during development to avoid CORS.
// The node listens on 127.0.0.1:8080 by default (deploy/config/dev.toml, [http] bind).
const target = process.env.VITE_API_TARGET ?? 'http://127.0.0.1:8080'

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  server: {
    // Bind 127.0.0.1 explicitly: by default it only binds [::1], so probing 127.0.0.1 gets
    // connection refused (seen on this machine).
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
    proxy: {
      '/v1': { target, changeOrigin: true },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    // The antd vendor chunk is ~1.3MB (410KB gzipped): it rarely changes, so long-term
    // caching amortises it; the raised limit only silences a noisy warning, it does not
    // hide a problem — reducing first paint would mean per-page dynamic imports.
    chunkSizeWarningLimit: 1500,
    rollupOptions: {
      output: {
        // Split vendors: antd is large and rarely changes, a separate chunk helps long-term caching
        manualChunks: {
          react: ['react', 'react-dom', 'react-router-dom'],
          antd: ['antd', '@ant-design/icons'],
          axios: ['axios'],
        },
      },
    },
  },
})
