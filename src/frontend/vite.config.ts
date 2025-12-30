import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => {
  // Load env from both repo root (./.env) and frontend folder (./src/frontend/.env)
  // Frontend-local values win.
  const repoRoot = path.resolve(__dirname, '..', '..')
  const env = {
    ...loadEnv(mode, repoRoot, ''),
    ...loadEnv(mode, __dirname, ''),
  }

  const backendPort = env.BACKEND_PORT || '8000'
  const proxyTarget = env.VITE_PROXY_TARGET || `http://127.0.0.1:${backendPort}`
  const devPort = Number(env.FRONTEND_PORT || 3000)

  return {
    plugins: [react()],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, './src'),
      },
    },
    server: {
      port: Number.isFinite(devPort) ? devPort : 3000,
      proxy: {
        '/api': {
          target: proxyTarget,
          changeOrigin: true,
        },
      },
    },
  }
})
