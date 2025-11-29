/**
 * Rate Limiting Middleware
 *
 * Protects endpoints from abuse with configurable rate limits:
 * - Per-user limits for authenticated endpoints
 * - Per-IP limits for public endpoints
 * - Special handling for share link operations
 */

import rateLimit from 'express-rate-limit';
import { Request, Response } from 'express';
import logger from '../config/logger.js';

/**
 * Get identifier for rate limiting
 * Uses userId if authenticated, otherwise IP address
 */
function getIdentifier(req: Request): string {
  // Use userId from auth token if available
  if (req.user && 'userId' in req.user) {
    return `user:${req.user.userId}`;
  }

  // Fall back to IP address
  const forwarded = req.headers['x-forwarded-for'];
  const ip = forwarded
    ? (Array.isArray(forwarded) ? forwarded[0] : forwarded.split(',')[0])
    : req.socket.remoteAddress;

  return `ip:${ip}`;
}

/**
 * Custom rate limit handler with logging
 */
function rateLimitHandler(req: Request, res: Response) {
  const identifier = getIdentifier(req);

  logger.warn('[RateLimit] Too many requests', {
    identifier,
    path: req.path,
    method: req.method,
    ip: req.ip,
  });

  res.status(429).json({
    error: 'Too many requests',
    message: 'You have exceeded the rate limit. Please try again later.',
    retryAfter: res.getHeader('Retry-After'),
  });
}

/**
 * Authentication Rate Limiters
 * Stricter limits for login/register to prevent brute force attacks
 */

/**
 * Login Rate Limiter
 * Limits: 5 login attempts per 15 minutes per email/IP
 * Works in conjunction with account lockout (after 5 failed attempts)
 */
export const loginRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Allow up to 10 login attempts (successful or failed)
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false, // Count all attempts
  keyGenerator: (req: Request) => {
    // Rate limit by email if provided, otherwise by IP
    const email = req.body?.email;
    const ip = getIdentifier(req);
    return email ? `login:${email.toLowerCase()}` : ip;
  },
  handler: rateLimitHandler,
  message: 'Too many login attempts. Please try again later.',
});

/**
 * Registration Rate Limiter
 * Limits: 3 registrations per hour per IP
 * Prevents spam account creation
 */
export const registerRateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // Only 3 registrations per hour per IP
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: getIdentifier, // By IP address
  handler: rateLimitHandler,
  message: 'Too many registration attempts. Please try again later.',
});

/**
 * Token Refresh Rate Limiter
 * Limits: 10 token refreshes per minute per user
 * Prevents token refresh abuse
 */
export const tokenRefreshRateLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: getIdentifier,
  handler: rateLimitHandler,
  message: 'Too many token refresh requests. Please try again later.',
});

/**
 * Password Reset Rate Limiter (for future implementation)
 * Limits: 3 password reset requests per hour per email
 */
export const passwordResetRateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req: Request) => {
    const email = req.body?.email;
    return email ? `reset:${email.toLowerCase()}` : getIdentifier(req);
  },
  handler: rateLimitHandler,
  message: 'Too many password reset requests. Please try again later.',
});

/**
 * Share Link Creation Rate Limiter
 * Limits: 10 share links per hour per user
 */
export const createShareLinkLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: getIdentifier,
  handler: rateLimitHandler,
  message: 'Too many share links created. Please try again later.',
});

/**
 * Join Request Rate Limiter
 * Limits: 5 join requests per 15 minutes per IP
 * Prevents spam and brute force attacks on password-protected shares
 */
export const joinRequestLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req: Request) => {
    // Use IP + shareCode to allow joining different shares
    const shareCode = req.params.shareCode || req.body.shareCode;
    const identifier = getIdentifier(req);
    return `${identifier}:${shareCode}`;
  },
  handler: rateLimitHandler,
  message: 'Too many join requests. Please try again later.',
});

/**
 * Share Settings Retrieval Rate Limiter
 * Limits: 20 requests per 5 minutes per IP
 * Prevents reconnaissance attacks
 */
export const getShareSettingsLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: getIdentifier,
  handler: rateLimitHandler,
  message: 'Too many requests. Please try again later.',
});

/**
 * Approve/Reject Connection Rate Limiter
 * Limits: 30 actions per minute per user
 * Prevents accidental spam clicks or automated abuse
 */
export const approveRejectLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: getIdentifier,
  handler: rateLimitHandler,
  message: 'Too many approval/rejection requests. Please slow down.',
});

/**
 * Share Management Rate Limiter
 * Limits: 60 requests per minute per user
 * For stats, pending connections, etc.
 */
export const shareManagementLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: getIdentifier,
  handler: rateLimitHandler,
  message: 'Too many requests. Please slow down.',
});

/**
 * Block IP Rate Limiter
 * Limits: 10 IP blocks per hour per user
 */
export const blockIPLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: getIdentifier,
  handler: rateLimitHandler,
  message: 'Too many IP blocking requests. Please try again later.',
});

/**
 * Deactivate Share Link Rate Limiter
 * Limits: 20 deactivations per hour per user
 */
export const deactivateShareLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: getIdentifier,
  handler: rateLimitHandler,
  message: 'Too many deactivation requests. Please try again later.',
});

/**
 * Socket Event Rate Limiter
 * In-memory store for tracking socket event rates
 */
class SocketRateLimiter {
  private store: Map<string, { count: number; resetTime: number }> = new Map();
  private cleanupInterval: NodeJS.Timeout;

  constructor() {
    // Cleanup expired entries every 5 minutes
    this.cleanupInterval = setInterval(() => {
      const now = Date.now();
      for (const [key, value] of this.store.entries()) {
        if (now > value.resetTime) {
          this.store.delete(key);
        }
      }
    }, 5 * 60 * 1000);
  }

  /**
   * Check if action is allowed
   * @param identifier Unique identifier (userId or socketId)
   * @param action Action name
   * @param maxRequests Maximum requests allowed
   * @param windowMs Time window in milliseconds
   * @returns true if allowed, false if rate limited
   */
  public isAllowed(
    identifier: string,
    action: string,
    maxRequests: number,
    windowMs: number
  ): boolean {
    const key = `${identifier}:${action}`;
    const now = Date.now();
    const entry = this.store.get(key);

    if (!entry || now > entry.resetTime) {
      // First request or window expired
      this.store.set(key, {
        count: 1,
        resetTime: now + windowMs,
      });
      return true;
    }

    if (entry.count >= maxRequests) {
      // Rate limit exceeded
      logger.warn('[SocketRateLimit] Too many socket events', {
        identifier,
        action,
        count: entry.count,
        maxRequests,
      });
      return false;
    }

    // Increment count
    entry.count++;
    return true;
  }

  /**
   * Clean up resources
   */
  public destroy(): void {
    clearInterval(this.cleanupInterval);
    this.store.clear();
  }
}

export const socketRateLimiter = new SocketRateLimiter();

/**
 * Socket rate limit configurations
 */
export const SOCKET_RATE_LIMITS = {
  // Share management events
  'share:get-details': { max: 30, windowMs: 60 * 1000 }, // 30 per minute
  'share:approve-connection': { max: 30, windowMs: 60 * 1000 }, // 30 per minute
  'share:reject-connection': { max: 30, windowMs: 60 * 1000 }, // 30 per minute
  'share:kick-user': { max: 20, windowMs: 60 * 1000 }, // 20 per minute
  'share:deactivate': { max: 10, windowMs: 60 * 1000 }, // 10 per minute

  // Terminal events for external users
  'share:connect-terminal': { max: 5, windowMs: 15 * 60 * 1000 }, // 5 per 15 minutes
  'terminal-input': { max: 1000, windowMs: 60 * 1000 }, // 1000 per minute (high for normal typing)
  'terminal-resize': { max: 30, windowMs: 60 * 1000 }, // 30 per minute
};
