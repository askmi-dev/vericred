import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['src/**/*.test.ts', 'tests/**/*.test.ts'],
    hookTimeout: 30000,
    setupFiles: ['./tests/setup.ts'],
    fileParallelism: false,
  },
});
