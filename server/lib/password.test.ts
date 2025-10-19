import { describe, it, expect } from 'vitest';
import { hashPassword, comparePassword } from './password';

describe('Password Utilities', () => {
  const testPassword = 'TestPassword123!';

  describe('hashPassword', () => {
    it('should hash a password', async () => {
      const hash = await hashPassword(testPassword);

      expect(hash).toBeDefined();
      expect(typeof hash).toBe('string');
      expect(hash).not.toBe(testPassword);
    });

    it('should generate different hashes for same password', async () => {
      // Due to salt, same password should produce different hashes
      const hash1 = await hashPassword(testPassword);
      const hash2 = await hashPassword(testPassword);

      expect(hash1).not.toBe(hash2);
    });

    it('should generate bcrypt hash format', async () => {
      const hash = await hashPassword(testPassword);

      // Bcrypt hashes start with $2a$, $2b$, or $2y$
      expect(hash).toMatch(/^\$2[aby]\$/);
    });

    it('should use 12 rounds of hashing', async () => {
      const hash = await hashPassword(testPassword);

      // Extract rounds from bcrypt hash (format: $2b$12$...)
      const rounds = hash.split('$')[2];
      expect(rounds).toBe('12');
    });

    it('should handle empty string', async () => {
      const hash = await hashPassword('');

      expect(hash).toBeDefined();
      expect(typeof hash).toBe('string');
    });

    it('should handle very long passwords', async () => {
      const longPassword = 'a'.repeat(100);
      const hash = await hashPassword(longPassword);

      expect(hash).toBeDefined();
      expect(typeof hash).toBe('string');
    });

    it('should handle special characters', async () => {
      const specialPassword = '!@#$%^&*()_+-=[]{}|;:,.<>?/~`';
      const hash = await hashPassword(specialPassword);

      expect(hash).toBeDefined();
      expect(typeof hash).toBe('string');
    });
  });

  describe('comparePassword', () => {
    it('should verify correct password', async () => {
      const hash = await hashPassword(testPassword);
      const isValid = await comparePassword(testPassword, hash);

      expect(isValid).toBe(true);
    });

    it('should reject incorrect password', async () => {
      const hash = await hashPassword(testPassword);
      const isValid = await comparePassword('WrongPassword', hash);

      expect(isValid).toBe(false);
    });

    it('should be case sensitive', async () => {
      const hash = await hashPassword('Password123');
      const isValid = await comparePassword('password123', hash);

      expect(isValid).toBe(false);
    });

    it('should reject similar but different passwords', async () => {
      const hash = await hashPassword('Password123');
      const isValid = await comparePassword('Password124', hash);

      expect(isValid).toBe(false);
    });

    it('should reject empty password against hash', async () => {
      const hash = await hashPassword(testPassword);
      const isValid = await comparePassword('', hash);

      expect(isValid).toBe(false);
    });

    it('should reject password against invalid hash', async () => {
      const isValid = await comparePassword(testPassword, 'invalid-hash');

      expect(isValid).toBe(false);
    });

    it('should handle whitespace correctly', async () => {
      const passwordWithSpace = 'Test Password 123';
      const hash = await hashPassword(passwordWithSpace);

      const isValid1 = await comparePassword(passwordWithSpace, hash);
      const isValid2 = await comparePassword('TestPassword123', hash);

      expect(isValid1).toBe(true);
      expect(isValid2).toBe(false);
    });
  });

  describe('Integration', () => {
    it('should work with hash and verify cycle', async () => {
      const passwords = [
        'SimplePass123',
        'Complex!Pass@123#',
        'with spaces and 123',
        '日本語パスワード123',
        '🔐SecurePass123🔑',
      ];

      for (const password of passwords) {
        const hash = await hashPassword(password);
        const isValid = await comparePassword(password, hash);
        expect(isValid).toBe(true);
      }
    });

    it('should reject after hash with wrong password', async () => {
      const correctPassword = 'CorrectPass123';
      const wrongPassword = 'WrongPass123';

      const hash = await hashPassword(correctPassword);
      const isValid = await comparePassword(wrongPassword, hash);

      expect(isValid).toBe(false);
    });
  });
});
