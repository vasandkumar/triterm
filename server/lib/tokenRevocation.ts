/**
 * JWT Token Revocation System
 *
 * Provides token blacklisting capabilities to immediately invalidate JWTs.
 *
 * Current Implementation: In-memory storage
 * Production Recommendation: Migrate to Redis for distributed systems
 *
 * Use Cases:
 * - User logout (revoke access & refresh tokens)
 * - Admin deactivates user (revoke all user tokens)
 * - Password change (revoke all user tokens)
 * - Suspicious activity (revoke specific tokens)
 */

import logger from '../config/logger.js';

interface RevokedToken {
  token: string;
  userId: string;
  revokedAt: Date;
  expiresAt: Date; // When the token naturally expires (can remove from blacklist after)
  reason: 'logout' | 'user_deactivated' | 'password_change' | 'suspicious_activity' | 'admin_action';
}

// In-memory storage for revoked tokens
// TODO: Migrate to Redis for production multi-server deployments
const revokedTokens = new Map<string, RevokedToken>();

// Track all tokens by userId for bulk revocation
const userTokens = new Map<string, Set<string>>();

/**
 * Revoke a specific token
 */
export function revokeToken(
  token: string,
  userId: string,
  expiresAt: Date,
  reason: RevokedToken['reason']
): void {
  const revokedToken: RevokedToken = {
    token,
    userId,
    revokedAt: new Date(),
    expiresAt,
    reason,
  };

  revokedTokens.set(token, revokedToken);

  // Track token by userId for bulk operations
  if (!userTokens.has(userId)) {
    userTokens.set(userId, new Set());
  }
  userTokens.get(userId)!.add(token);

  logger.info('Token revoked', {
    userId,
    reason,
    expiresAt,
    totalRevoked: revokedTokens.size,
  });
}

/**
 * Check if a token has been revoked
 */
export function isTokenRevoked(token: string): boolean {
  const revoked = revokedTokens.has(token);

  if (revoked) {
    const revokedToken = revokedTokens.get(token)!;
    logger.debug('Revoked token access attempted', {
      userId: revokedToken.userId,
      reason: revokedToken.reason,
      revokedAt: revokedToken.revokedAt,
    });
  }

  return revoked;
}

/**
 * Revoke all tokens for a specific user
 * Useful when:
 * - Admin deactivates user
 * - User changes password
 * - Suspicious activity detected
 */
export function revokeAllUserTokens(
  userId: string,
  reason: RevokedToken['reason']
): number {
  const tokens = userTokens.get(userId);

  if (!tokens || tokens.size === 0) {
    logger.info('No active tokens to revoke for user', { userId, reason });
    return 0;
  }

  let revokedCount = 0;

  for (const token of tokens) {
    const existing = revokedTokens.get(token);
    if (existing) {
      // Update revocation reason if token already revoked
      existing.reason = reason;
      existing.revokedAt = new Date();
      revokedTokens.set(token, existing);
    }
    revokedCount++;
  }

  logger.info('Revoked all user tokens', {
    userId,
    reason,
    tokenCount: revokedCount,
  });

  return revokedCount;
}

/**
 * Clean up expired tokens from blacklist
 * Tokens that have naturally expired no longer need to be tracked
 */
export function cleanupExpiredTokens(): void {
  const now = new Date();
  let cleanedCount = 0;

  const entries = Array.from(revokedTokens.entries());
  for (const [token, revokedToken] of entries) {
    if (revokedToken.expiresAt <= now) {
      revokedTokens.delete(token);

      // Remove from user tokens set
      const userTokenSet = userTokens.get(revokedToken.userId);
      if (userTokenSet) {
        userTokenSet.delete(token);
        if (userTokenSet.size === 0) {
          userTokens.delete(revokedToken.userId);
        }
      }

      cleanedCount++;
    }
  }

  if (cleanedCount > 0) {
    logger.info('Cleaned up expired tokens from blacklist', {
      cleanedCount,
      remainingCount: revokedTokens.size,
    });
  }
}

/**
 * Get revocation statistics
 */
export function getRevocationStats(): {
  totalRevokedTokens: number;
  usersWithRevokedTokens: number;
  tokensByReason: Record<RevokedToken['reason'], number>;
} {
  const tokensByReason: Record<RevokedToken['reason'], number> = {
    logout: 0,
    user_deactivated: 0,
    password_change: 0,
    suspicious_activity: 0,
    admin_action: 0,
  };

  const values = Array.from(revokedTokens.values());
  for (const revokedToken of values) {
    tokensByReason[revokedToken.reason]++;
  }

  return {
    totalRevokedTokens: revokedTokens.size,
    usersWithRevokedTokens: userTokens.size,
    tokensByReason,
  };
}

/**
 * Get all revoked tokens for a user (for debugging/admin purposes)
 */
export function getUserRevokedTokens(userId: string): RevokedToken[] {
  const tokens = userTokens.get(userId);
  if (!tokens) return [];

  const tokenList: RevokedToken[] = [];
  for (const token of Array.from(tokens)) {
    const revokedToken = revokedTokens.get(token);
    if (revokedToken) {
      tokenList.push(revokedToken);
    }
  }
  return tokenList;
}

/**
 * Start automatic cleanup interval
 * Runs every 5 minutes to remove expired tokens from blacklist
 */
export function startCleanupSchedule(intervalMs: number = 5 * 60 * 1000): NodeJS.Timeout {
  logger.info('Starting token revocation cleanup schedule', {
    intervalMinutes: intervalMs / 60000,
  });

  return setInterval(() => {
    cleanupExpiredTokens();
  }, intervalMs);
}

// Auto-start cleanup on module load
const cleanupInterval = startCleanupSchedule();

// Export cleanup interval for testing/manual control
export { cleanupInterval };

/**
 * Migration Guide to Redis:
 *
 * For production multi-server deployments, migrate to Redis:
 *
 * 1. Install Redis client:
 *    npm install ioredis
 *
 * 2. Replace Map storage with Redis:
 *    - Use SET with expiration for individual tokens
 *    - Use SADD for user token sets
 *    - Set TTL based on token expiration
 *
 * 3. Example Redis implementation:
 *
 *    const redis = new Redis();
 *
 *    async function revokeToken(token, userId, expiresAt, reason) {
 *      const ttl = Math.floor((expiresAt.getTime() - Date.now()) / 1000);
 *      await redis.setex(`revoked:${token}`, ttl, JSON.stringify({ userId, reason }));
 *      await redis.sadd(`user:${userId}:revoked`, token);
 *    }
 *
 *    async function isTokenRevoked(token) {
 *      return await redis.exists(`revoked:${token}`) === 1;
 *    }
 *
 * 4. Benefits of Redis:
 *    - Shared state across multiple servers
 *    - Automatic expiration (no cleanup needed)
 *    - Persistence across server restarts
 *    - Better performance at scale
 */
