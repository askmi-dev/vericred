import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    hookTimeout: 30000,
    // CI runs `npm run build` before `npm test`, which compiles test files
    // into dist/ too -- exclude them so they aren't picked up as a second
    // copy of every test alongside the real src/**/*.test.ts files.
    exclude: ['**/node_modules/**', '**/dist/**'],
  },
});
