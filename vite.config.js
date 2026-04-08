import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api/claude': {
        target: 'https://api.anthropic.com',
        changeOrigin: true,
        rewrite: (path) => '/v1/messages',
        configure: (proxy) => {
          proxy.on('proxyReq', (proxyReq, req) => {
            // Forward API key from env
            const apiKey = process.env.VITE_ANTHROPIC_API_KEY
            if (apiKey) {
              proxyReq.setHeader('x-api-key', apiKey)
            }
            proxyReq.setHeader('anthropic-version', '2023-06-01')
            proxyReq.setHeader('content-type', 'application/json')
          })
        },
      },
    },
  },
})
