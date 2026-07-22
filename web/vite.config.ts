import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Dev-server proxy to the BFF backend - same-origin from the browser's point
// of view (critical: the session/CSRF cookies are SameSite=Strict, so they
// would never be sent to a cross-origin backend during `npm run dev`).
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/v1': 'http://localhost:8000',
      '/.well-known': 'http://localhost:8000',
      '/healthz': 'http://localhost:8000',
      '/readyz': 'http://localhost:8000',
    },
  },
})
