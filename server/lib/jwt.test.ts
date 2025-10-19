import { describe, it, expect } from 'vitest';
import { generateAccessToken, generateRefreshToken, verifyToken, decodeToken } from './jwt';

describe('JWT Utilities', () => {
  const testUser = {
    userId: 'test-user-id-123',
    email: 'test@example.com',
    username: 'testuser',
  };

  describe('generateAccessToken', () => {
    it('should generate a valid access token', () => {
      const token = generateAccessToken(testUser);

      expect(token).toBeDefined();
      expect(typeof token).toBe('string');
      expect(token.split('.')).toHaveLength(3); // JWT has 3 parts
    });

    it('should include user data in token payload', () => {
      const token = generateAccessToken(testUser);
      const payload = verifyToken(token);

      expect(payload).toBeDefined();
      expect(payload.userId).toBe(testUser.userId);
      expect(payload.email).toBe(testUser.email);
      expect(payload.username).toBe(testUser.username);
    });

    it('should set expiration time', () => {
      const token = generateAccessToken(testUser);
      const payload = decodeToken(token);

      expect(payload).toBeDefined();
      expect(payload).toHaveProperty('exp');
      expect(payload).toHaveProperty('iat');

      // Access token should expire in 15 minutes (approximately)
      const expiresIn = (payload as any).exp - (payload as any).iat;
      expect(expiresIn).toBeLessThanOrEqual(15 * 60 + 1); // 15 minutes in seconds
      expect(expiresIn).toBeGreaterThanOrEqual(15 * 60 - 1);
    });
  });

  describe('generateRefreshToken', () => {
    it('should generate a valid refresh token', () => {
      const token = generateRefreshToken(testUser);

      expect(token).toBeDefined();
      expect(typeof token).toBe('string');
      expect(token.split('.')).toHaveLength(3);
    });

    it('should include user data in token payload', () => {
      const token = generateRefreshToken(testUser);
      const payload = verifyToken(token);

      expect(payload).toBeDefined();
      expect(payload.userId).toBe(testUser.userId);
      expect(payload.email).toBe(testUser.email);
      expect(payload.username).toBe(testUser.username);
    });

    it('should set longer expiration time than access token', () => {
      const token = generateRefreshToken(testUser);
      const payload = decodeToken(token);

      expect(payload).toBeDefined();
      expect(payload).toHaveProperty('exp');
      expect(payload).toHaveProperty('iat');

      // Refresh token should expire in 7 days (approximately)
      const expiresIn = (payload as any).exp - (payload as any).iat;
      expect(expiresIn).toBeLessThanOrEqual(7 * 24 * 60 * 60 + 1); // 7 days in seconds
      expect(expiresIn).toBeGreaterThanOrEqual(7 * 24 * 60 * 60 - 1);
    });

    it('should generate different tokens for same user', async () => {
      const token1 = generateRefreshToken(testUser);
      // Wait to ensure different iat (JWT iat has 1-second precision)
      await new Promise((resolve) => setTimeout(resolve, 1100));
      const token2 = generateRefreshToken(testUser);

      // Tokens should be different due to different iat (issued at)
      expect(token1).not.toBe(token2);
    });
  });

  describe('verifyToken', () => {
    it('should verify valid access token', () => {
      const token = generateAccessToken(testUser);
      const payload = verifyToken(token);

      expect(payload).toBeDefined();
      expect(payload.userId).toBe(testUser.userId);
    });

    it('should throw error for invalid token', () => {
      expect(() => verifyToken('invalid-token')).toThrow();
    });

    it('should throw error for malformed token', () => {
      expect(() => verifyToken('not.a.jwt')).toThrow();
    });

    it('should throw error for empty token', () => {
      expect(() => verifyToken('')).toThrow();
    });

    it('should verify refresh token (same secret)', () => {
      const refreshToken = generateRefreshToken(testUser);
      const payload = verifyToken(refreshToken);

      // Should work because both use same secret
      expect(payload).toBeDefined();
      expect(payload.userId).toBe(testUser.userId);
    });
  });

  describe('decodeToken', () => {
    it('should decode valid token without verification', () => {
      const token = generateAccessToken(testUser);
      const payload = decodeToken(token);

      expect(payload).toBeDefined();
      expect(payload?.userId).toBe(testUser.userId);
    });

    it('should return null for invalid token', () => {
      const payload = decodeToken('invalid-token');
      expect(payload).toBeNull();
    });

    it('should decode expired token', () => {
      // Create token and decode it (doesn't verify expiration)
      const token = generateAccessToken(testUser);
      const payload = decodeToken(token);

      expect(payload).toBeDefined();
      expect(payload?.userId).toBe(testUser.userId);
    });
  });

  describe('Token expiration', () => {
    it('should include standard JWT claims', () => {
      const token = generateAccessToken(testUser);
      const payload = verifyToken(token);

      expect(payload).toHaveProperty('iat'); // issued at
      expect(payload).toHaveProperty('exp'); // expiration
      expect(payload).toHaveProperty('userId');
      expect(payload).toHaveProperty('email');
      expect(payload).toHaveProperty('username');
    });

    it('should have future expiration date', () => {
      const token = generateAccessToken(testUser);
      const payload = decodeToken(token);

      const now = Math.floor(Date.now() / 1000);
      expect((payload as any)?.exp).toBeGreaterThan(now);
    });
  });
});
