/**
 * Login Attempt Tracker
 *
 * Tracks failed login attempts and implements account lockout
 * to prevent brute force attacks.
 *
 * Security Features:
 * - Locks account after 5 failed attempts
 * - 15-minute lockout duration
 * - Automatic cleanup of old entries
 * - Rate limiting per email address
 */

import logger from '../config/logger.js';

interface LoginAttempt {
  count: number;
  firstAttempt: Date;
  lastAttempt: Date;
  lockedUntil?: Date;
}

// In-memory store for login attempts
// For production with multiple servers, use Redis
const loginAttempts = new Map<string, LoginAttempt>();

// Configuration
const MAX_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 15 * 60 * 1000; // 15 minutes
const ATTEMPT_WINDOW_MS = 15 * 60 * 1000; // 15 minutes window for attempts
const CLEANUP_INTERVAL_MS = 5 * 60 * 1000; // Clean up every 5 minutes

/**
 * Clean up expired entries periodically
 */
setInterval(() => {
  const now = Date.now();
  let cleaned = 0;

  for (const [email, attempt] of loginAttempts.entries()) {
    // Remove if:
    // 1. Lock expired and no recent attempts
    // 2. Attempt window expired
    const lockExpired = attempt.lockedUntil && attempt.lockedUntil.getTime() < now;
    const attemptsExpired = now - attempt.lastAttempt.getTime() > ATTEMPT_WINDOW_MS;

    if ((lockExpired && attemptsExpired) || (!attempt.lockedUntil && attemptsExpired)) {
      loginAttempts.delete(email);
      cleaned++;
    }
  }

  if (cleaned > 0) {
    logger.debug(`Cleaned ${cleaned} expired login attempt records`);
  }
}, CLEANUP_INTERVAL_MS);

/**
 * Check if an account is currently locked
 * @param email User's email address
 * @returns Object with locked status and remaining time
 */
export function isAccountLocked(email: string): { locked: boolean; remainingSeconds?: number } {
  const attempt = loginAttempts.get(email.toLowerCase());

  if (!attempt || !attempt.lockedUntil) {
    return { locked: false };
  }

  const now = Date.now();
  const lockExpires = attempt.lockedUntil.getTime();

  if (now >= lockExpires) {
    // Lock expired, remove it
    attempt.lockedUntil = undefined;
    attempt.count = 0;
    return { locked: false };
  }

  const remainingSeconds = Math.ceil((lockExpires - now) / 1000);
  return { locked: true, remainingSeconds };
}

/**
 * Record a failed login attempt
 * @param email User's email address
 * @returns Object indicating if account is now locked
 */
export function recordFailedAttempt(email: string): {
  locked: boolean;
  attemptsRemaining?: number;
  lockoutDuration?: number;
} {
  const normalizedEmail = email.toLowerCase();
  const now = new Date();
  const attempt = loginAttempts.get(normalizedEmail);

  if (!attempt) {
    // First failed attempt
    loginAttempts.set(normalizedEmail, {
      count: 1,
      firstAttempt: now,
      lastAttempt: now,
    });

    logger.debug('First failed login attempt recorded', { email: normalizedEmail });

    return {
      locked: false,
      attemptsRemaining: MAX_ATTEMPTS - 1,
    };
  }

  // Check if we should reset the counter (attempt window expired)
  const timeSinceFirst = now.getTime() - attempt.firstAttempt.getTime();
  if (timeSinceFirst > ATTEMPT_WINDOW_MS) {
    // Reset counter
    attempt.count = 1;
    attempt.firstAttempt = now;
    attempt.lastAttempt = now;
    attempt.lockedUntil = undefined;

    logger.debug('Login attempt counter reset (window expired)', { email: normalizedEmail });

    return {
      locked: false,
      attemptsRemaining: MAX_ATTEMPTS - 1,
    };
  }

  // Increment attempt count
  attempt.count++;
  attempt.lastAttempt = now;

  if (attempt.count >= MAX_ATTEMPTS) {
    // Lock the account
    attempt.lockedUntil = new Date(now.getTime() + LOCKOUT_DURATION_MS);

    logger.warn('Account locked due to too many failed login attempts', {
      email: normalizedEmail,
      attempts: attempt.count,
      lockoutMinutes: LOCKOUT_DURATION_MS / 60000,
    });

    return {
      locked: true,
      lockoutDuration: Math.ceil(LOCKOUT_DURATION_MS / 1000),
    };
  }

  logger.debug('Failed login attempt recorded', {
    email: normalizedEmail,
    attempts: attempt.count,
    remaining: MAX_ATTEMPTS - attempt.count,
  });

  return {
    locked: false,
    attemptsRemaining: MAX_ATTEMPTS - attempt.count,
  };
}

/**
 * Clear login attempts for an email (called on successful login)
 * @param email User's email address
 */
export function clearLoginAttempts(email: string): void {
  const normalizedEmail = email.toLowerCase();
  const hadAttempts = loginAttempts.has(normalizedEmail);

  loginAttempts.delete(normalizedEmail);

  if (hadAttempts) {
    logger.debug('Login attempts cleared for user', { email: normalizedEmail });
  }
}

/**
 * Manually unlock an account (admin function)
 * @param email User's email address
 */
export function unlockAccount(email: string): void {
  const normalizedEmail = email.toLowerCase();
  const attempt = loginAttempts.get(normalizedEmail);

  if (attempt && attempt.lockedUntil) {
    loginAttempts.delete(normalizedEmail);
    logger.info('Account manually unlocked', { email: normalizedEmail });
  }
}

/**
 * Get current attempt count for an email (for monitoring)
 * @param email User's email address
 */
export function getAttemptCount(email: string): number {
  const normalizedEmail = email.toLowerCase();
  const attempt = loginAttempts.get(normalizedEmail);
  return attempt?.count || 0;
}

/**
 * Get statistics about locked accounts
 */
export function getLockedAccountStats(): {
  totalLocked: number;
  emails: string[];
} {
  const now = Date.now();
  const locked: string[] = [];

  for (const [email, attempt] of loginAttempts.entries()) {
    if (attempt.lockedUntil && attempt.lockedUntil.getTime() > now) {
      locked.push(email);
    }
  }

  return {
    totalLocked: locked.length,
    emails: locked,
  };
}
