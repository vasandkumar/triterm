import { beforeAll, afterAll } from 'vitest';

// Setup before all tests
beforeAll(() => {
  // Set test environment variables
  process.env.NODE_ENV = 'test';
});

// Cleanup after all tests
afterAll(() => {
  // Clean up resources
});
