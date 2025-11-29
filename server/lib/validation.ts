import { z } from 'zod';

// Common weak passwords to block (partial list - in production use a larger dictionary)
const WEAK_PASSWORDS = [
  'password123',
  'Password123!',
  'Admin123!',
  'Welcome123!',
  'Qwerty123!',
  '123456789!Aa',
  'Password1!',
  'P@ssw0rd',
  'P@ssword123',
];

/**
 * Enhanced password validation with security best practices
 * Requirements:
 * - Minimum 12 characters
 * - At least one uppercase letter
 * - At least one lowercase letter
 * - At least one number
 * - At least one special character
 * - No common weak passwords
 * - Maximum 128 characters (prevent DoS)
 */
const passwordValidator = z
  .string()
  .min(12, 'Password must be at least 12 characters')
  .max(128, 'Password must be at most 128 characters')
  .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
  .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
  .regex(/[0-9]/, 'Password must contain at least one number')
  .regex(/[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/]/, 'Password must contain at least one special character')
  .refine(
    (password) => !WEAK_PASSWORDS.includes(password.toLowerCase()),
    { message: 'This password is too common. Please choose a stronger password.' }
  )
  .refine(
    (password) => !/(.)\1{2,}/.test(password),
    { message: 'Password cannot contain three or more consecutive identical characters.' }
  );

// User registration schema
export const registerSchema = z.object({
  email: z.string().email('Invalid email address'),
  username: z
    .string()
    .min(3, 'Username must be at least 3 characters')
    .max(20, 'Username must be at most 20 characters')
    .regex(/^[a-zA-Z0-9_-]+$/, 'Username can only contain letters, numbers, underscores, and hyphens'),
  password: passwordValidator,
});

// User login schema
export const loginSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(1, 'Password is required'),
});

// Refresh token schema
export const refreshTokenSchema = z.object({
  refreshToken: z.string().min(1, 'Refresh token is required'),
});

// Types inferred from schemas
export type RegisterInput = z.infer<typeof registerSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
export type RefreshTokenInput = z.infer<typeof refreshTokenSchema>;
