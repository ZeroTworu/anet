import { fileURLToPath, URL } from 'node:url'

import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import vueDevTools from 'vite-plugin-vue-devtools'

// Берем таргет из переменных окружения Node при запуске Vite
const apiProxyTarget = process.env.VITE_API_PROXY_TARGET || 'http://localhost:3000'

// В среде AI Studio облачный раннер проксирует порт 3000.
// При локальной разработке у пользователя порт 3000 занят anet-auth, поэтому Vite стартует на стандартном порту 5173.
const isAiStudio = !!process.env.APPLET_ID

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    vue(),
    vueDevTools(),
  ],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url))
    },
  },
  server: {
    ...(isAiStudio
      ? {
          host: '0.0.0.0',
          port: 3000,
          strictPort: true,
          allowedHosts: true,
        }
      : {}),
    proxy: {
      '/api': {
        target: apiProxyTarget,
        changeOrigin: true
      }
    }
  }
})
