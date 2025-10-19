import { describe, it, expect } from 'vitest';
import { registerSchema, loginSchema, refreshTokenSchema } from './validation';

describe('Validation Schemas', () => {
  describe('registerSchema', () => {
    const validData = {
      email: 'test@example.com',
      username: 'testuser',
      password: 'TestPass123',
    };

    it('should validate valid registration data', () => {
      const result = registerSchema.safeParse(validData);
      expect(result.success).toBe(true);
    });

    describe('email validation', () => {
      it('should reject invalid email format', () => {
        const result = registerSchema.safeParse({
          ...validData,
          email: 'invalid-email',
        });
        expect(result.success).toBe(false);
      });

      it('should reject missing email', () => {
        const { email, ...dataWithoutEmail } = validData;
        const result = registerSchema.safeParse(dataWithoutEmail);
        expect(result.success).toBe(false);
      });

      it('should accept valid email formats', () => {
        const validEmails = [
          'user@example.com',
          'user.name@example.com',
          'user+tag@example.co.uk',
          'user123@test-domain.com',
        ];

        validEmails.forEach((email) => {
          const result = registerSchema.safeParse({
            ...validData,
            email,
          });
          expect(result.success).toBe(true);
        });
      });
    });

    describe('username validation', () => {
      it('should reject username shorter than 3 characters', () => {
        const result = registerSchema.safeParse({
          ...validData,
          username: 'ab',
        });
        expect(result.success).toBe(false);
      });

      it('should reject username longer than 20 characters', () => {
        const result = registerSchema.safeParse({
          ...validData,
          username: 'a'.repeat(21),
        });
        expect(result.success).toBe(false);
      });

      it('should reject username with invalid characters', () => {
        const invalidUsernames = ['user@name', 'user name', 'user!', 'user#123'];

        invalidUsernames.forEach((username) => {
          const result = registerSchema.safeParse({
            ...validData,
            username,
          });
          expect(result.success).toBe(false);
        });
      });

      it('should accept valid usernames', () => {
        const validUsernames = [
          'user',
          'user123',
          'user_name',
          'user-name',
          'User_Name-123',
        ];

        validUsernames.forEach((username) => {
          const result = registerSchema.safeParse({
            ...validData,
            username,
          });
          expect(result.success).toBe(true);
        });
      });

      it('should reject missing username', () => {
        const { username, ...dataWithoutUsername } = validData;
        const result = registerSchema.safeParse(dataWithoutUsername);
        expect(result.success).toBe(false);
      });
    });

    describe('password validation', () => {
      it('should reject password shorter than 8 characters', () => {
        const result = registerSchema.safeParse({
          ...validData,
          password: 'Short1',
        });
        expect(result.success).toBe(false);
      });

      it('should reject password without uppercase letter', () => {
        const result = registerSchema.safeParse({
          ...validData,
          password: 'lowercase123',
        });
        expect(result.success).toBe(false);
      });

      it('should reject password without lowercase letter', () => {
        const result = registerSchema.safeParse({
          ...validData,
          password: 'UPPERCASE123',
        });
        expect(result.success).toBe(false);
      });

      it('should reject password without number', () => {
        const result = registerSchema.safeParse({
          ...validData,
          password: 'NoNumbers',
        });
        expect(result.success).toBe(false);
      });

      it('should accept valid passwords', () => {
        const validPasswords = [
          'Password123',
          'Test1234',
          'MyP@ssw0rd',
          'Complex!Pass123',
          'Aa1' + 'x'.repeat(50), // Long password
        ];

        validPasswords.forEach((password) => {
          const result = registerSchema.safeParse({
            ...validData,
            password,
          });
          expect(result.success).toBe(true);
        });
      });

      it('should reject missing password', () => {
        const { password, ...dataWithoutPassword } = validData;
        const result = registerSchema.safeParse(dataWithoutPassword);
        expect(result.success).toBe(false);
      });
    });
  });

  describe('loginSchema', () => {
    const validData = {
      email: 'test@example.com',
      password: 'TestPass123',
    };

    it('should validate valid login data', () => {
      const result = loginSchema.safeParse(validData);
      expect(result.success).toBe(true);
    });

    it('should reject invalid email', () => {
      const result = loginSchema.safeParse({
        ...validData,
        email: 'invalid-email',
      });
      expect(result.success).toBe(false);
    });

    it('should reject missing email', () => {
      const { email, ...dataWithoutEmail } = validData;
      const result = loginSchema.safeParse(dataWithoutEmail);
      expect(result.success).toBe(false);
    });

    it('should reject missing password', () => {
      const { password, ...dataWithoutPassword } = validData;
      const result = loginSchema.safeParse(dataWithoutPassword);
      expect(result.success).toBe(false);
    });

    it('should accept any non-empty password for login', () => {
      // Login doesn't need password complexity validation
      const weakPasswords = ['weak', '123', 'abc'];

      weakPasswords.forEach((password) => {
        const result = loginSchema.safeParse({
          ...validData,
          password,
        });
        expect(result.success).toBe(true);
      });
    });
  });

  describe('refreshTokenSchema', () => {
    it('should validate valid refresh token data', () => {
      const result = refreshTokenSchema.safeParse({
        refreshToken: 'some-jwt-token-string',
      });
      expect(result.success).toBe(true);
    });

    it('should reject missing refreshToken', () => {
      const result = refreshTokenSchema.safeParse({});
      expect(result.success).toBe(false);
    });

    it('should reject empty refreshToken', () => {
      const result = refreshTokenSchema.safeParse({
        refreshToken: '',
      });
      expect(result.success).toBe(false);
    });

    it('should accept any non-empty string', () => {
      const tokens = ['token123', 'jwt.token.here', 'x'];

      tokens.forEach((refreshToken) => {
        const result = refreshTokenSchema.safeParse({
          refreshToken,
        });
        expect(result.success).toBe(true);
      });
    });
  });
});
