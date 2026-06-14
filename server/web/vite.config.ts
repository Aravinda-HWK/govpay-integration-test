import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// During `npm run dev`, API calls are proxied to the Go server on :9091.
// `npm run build` emits to dist/, which the Go server embeds and serves.
export default defineConfig({
  plugins: [react()],
  server: {
    // 5173 is often taken by Docker's proxy on this machine, which breaks the
    // /api proxy (requests get a 404 from Docker instead of the Go backend).
    port: 5180,
    strictPort: true,
    proxy: {
      '/api': 'http://127.0.0.1:9091',
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
})
