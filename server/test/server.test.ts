import { describe, it, expect } from 'vitest';

describe('Server Configuration', () => {
  it('should have test environment set', () => {
    expect(process.env.NODE_ENV).toBe('test');
  });

  it('should default to port 3000', () => {
    const port = parseInt(process.env.PORT || '3000');
    expect(port).toBe(3000);
  });

  it('should not require auth by default', () => {
    const requireAuth = process.env.REQUIRE_AUTH === 'true';
    expect(requireAuth).toBe(false);
  });
});
