import path from 'node:path'

import { defineConfig } from 'vitest/config'

export default defineConfig({
  define: {
    __APP_VERSION__: JSON.stringify('test'),
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['src/test/polyfills.ts'],
    globals: false,
    pool: 'threads',
    poolOptions: {
      threads: {
        minThreads: 1,
        maxThreads: 1,
      },
    },
    testTimeout: 10_000,
    hookTimeout: 10_000,
    css: false,
    include: ['src/**/*.{test,spec}.{ts,tsx}'],
    exclude: ['node_modules/**', 'dist/**', 'coverage/**'],
    typecheck: {
      enabled: true,
      checker: 'tsc',
      tsconfig: path.resolve(__dirname, 'tsconfig.json'),
      include: ['src/**/*.{ts,tsx}'],
    },
  },
})
