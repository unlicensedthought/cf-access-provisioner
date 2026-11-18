/**
 * @file vitest.config.ts
 * @description Vitest configuration for the worker. Node env; fetch is
 * mocked per-test via vi.stubGlobal. Tests live under src/__tests__/.
 */

import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    pool: 'forks',
    isolate: true,
    fileParallelism: false,
    maxWorkers: 1,
    include: ['src/__tests__/**/*.test.ts'],
  },
});
