import { fileURLToPath, URL } from 'node:url'
import { defineConfig, type Plugin } from 'vite'
import vue from '@vitejs/plugin-vue'
import { handleMockApi } from './mock-server'

const apiProxyTarget = process.env.VITE_API_PROXY_TARGET

const mockApiPlugin = (): Plugin => ({
  name: 'anet-mock-api-plugin',
  configureServer(server) {
    server.middlewares.use((req, res, next) => {
      if (handleMockApi(req, res)) {
        return
      }
      next()
    })
  },
})

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    vue(),
    ...(!apiProxyTarget ? [mockApiPlugin()] : []),
  ],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  server: {
    host: '0.0.0.0',
    port: 3000,
    strictPort: true,
    allowedHosts: true,
    ...(apiProxyTarget
      ? {
          proxy: {
            '/api': {
              target: apiProxyTarget,
              changeOrigin: true,
            },
          },
        }
      : {}),
  },
})
