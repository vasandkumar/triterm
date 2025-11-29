/**
 * Redis Session Manager - Hybrid Cache for Terminal Sessions
 *
 * Implements a write-through cache pattern with race condition handling:
 * 1. DB-First Writes: PostgreSQL is source of truth
 * 2. Optimistic Locking: Version-based conflict resolution
 * 3. Distributed Locks: For critical dimension updates
 * 4. Tombstone Pattern: Prevents delete-while-reading races
 * 5. TTL-based invalidation: Auto-cleanup stale cache
 */

import { getRedisClient } from './redis.js';
import { prisma } from './prisma.js';
import logger from '../config/logger.js';

// Cache TTL: 1 hour (sessions auto-expire from cache)
const SESSION_TTL = 3600;

// Lock TTL: 10 seconds (prevents deadlocks)
const LOCK_TTL = 10000;

// Retry configuration
const MAX_LOCK_RETRIES = 3;
const LOCK_RETRY_DELAY = 100; // ms

/**
 * Session data structure with versioning
 */
interface CachedSessionData {
  version: number;
  terminalId: string;
  userId?: string;
  shell: string;
  cwd: string;
  cols: number;
  rows: number;
  active: boolean;
  primarySocketId?: string;
  lastActivityAt: string; // ISO timestamp
  createdAt: string;
  deleted?: boolean; // Tombstone marker
  deletedAt?: string;
}

/**
 * Redis Session Manager Class
 */
export class RedisSessionManager {
  private static readonly KEY_PREFIX = 'triterm:session:';
  private static readonly LOCK_PREFIX = 'triterm:lock:session:';

  /**
   * Generate Redis key for session
   */
  private static getSessionKey(terminalId: string): string {
    return `${this.KEY_PREFIX}${terminalId}`;
  }

  /**
   * Generate Redis key for distributed lock
   */
  private static getLockKey(terminalId: string): string {
    return `${this.LOCK_PREFIX}${terminalId}`;
  }

  /**
   * Acquire distributed lock with retry
   */
  private static async acquireLock(
    terminalId: string,
    retries = MAX_LOCK_RETRIES
  ): Promise<boolean> {
    const redis = getRedisClient();
    const lockKey = this.getLockKey(terminalId);

    for (let i = 0; i < retries; i++) {
      try {
        // SET NX (only if not exists) with expiration
        const acquired = await redis.set(lockKey, 'locked', {
          NX: true,
          PX: LOCK_TTL,
        });

        if (acquired) {
          return true;
        }

        // Wait before retry
        if (i < retries - 1) {
          await new Promise((resolve) =>
            setTimeout(resolve, LOCK_RETRY_DELAY * (i + 1))
          );
        }
      } catch (error) {
        logger.error('Error acquiring lock', { terminalId, error });
      }
    }

    return false;
  }

  /**
   * Release distributed lock
   */
  private static async releaseLock(terminalId: string): Promise<void> {
    try {
      const redis = getRedisClient();
      const lockKey = this.getLockKey(terminalId);
      await redis.del(lockKey);
    } catch (error) {
      logger.error('Error releasing lock', { terminalId, error });
    }
  }

  /**
   * Get session from cache (Redis)
   */
  private static async getFromCache(
    terminalId: string
  ): Promise<CachedSessionData | null> {
    try {
      const redis = getRedisClient();
      const key = this.getSessionKey(terminalId);
      const data = await redis.get(key);

      if (!data) {
        return null;
      }

      const session: CachedSessionData = JSON.parse(data);

      // Check tombstone
      if (session.deleted) {
        logger.debug('Session marked as deleted (tombstone)', { terminalId });
        return null;
      }

      return session;
    } catch (error) {
      logger.error('Error reading from Redis cache', { terminalId, error });
      return null;
    }
  }

  /**
   * Set session in cache (Redis) with version check
   */
  private static async setInCache(
    session: CachedSessionData
  ): Promise<void> {
    try {
      const redis = getRedisClient();
      const key = this.getSessionKey(session.terminalId);

      // Check if cached version is newer (prevent overwriting with stale data)
      const cached = await this.getFromCache(session.terminalId);
      if (cached && cached.version > session.version) {
        logger.debug('Skipping cache update - cached version is newer', {
          terminalId: session.terminalId,
          cachedVersion: cached.version,
          newVersion: session.version,
        });
        return;
      }

      // Write to cache with TTL
      await redis.setEx(key, SESSION_TTL, JSON.stringify(session));

      logger.debug('Session cached in Redis', {
        terminalId: session.terminalId,
        version: session.version,
        ttl: SESSION_TTL,
      });
    } catch (error) {
      // Log but don't fail - DB is source of truth
      logger.warn('Failed to cache session in Redis', {
        terminalId: session.terminalId,
        error,
      });
    }
  }

  /**
   * Create tombstone marker (prevents delete-while-reading race)
   */
  private static async setTombstone(terminalId: string): Promise<void> {
    try {
      const redis = getRedisClient();
      const key = this.getSessionKey(terminalId);

      const tombstone: CachedSessionData = {
        version: Date.now(), // High version number
        terminalId,
        shell: '',
        cwd: '',
        cols: 0,
        rows: 0,
        active: false,
        lastActivityAt: new Date().toISOString(),
        createdAt: new Date().toISOString(),
        deleted: true,
        deletedAt: new Date().toISOString(),
      };

      // Set tombstone with 1-hour TTL
      await redis.setEx(key, SESSION_TTL, JSON.stringify(tombstone));

      logger.debug('Tombstone set for deleted session', { terminalId });
    } catch (error) {
      logger.warn('Failed to set tombstone', { terminalId, error });
    }
  }

  /**
   * Get session (hybrid: cache-first, fallback to DB)
   */
  static async getSession(
    terminalId: string
  ): Promise<CachedSessionData | null> {
    try {
      // Try cache first
      const cached = await this.getFromCache(terminalId);
      if (cached) {
        logger.debug('Session cache HIT', { terminalId });
        return cached;
      }

      logger.debug('Session cache MISS', { terminalId });

      // Fallback to database
      const dbSession = await prisma.session.findUnique({
        where: { terminalId },
      });

      if (!dbSession) {
        return null;
      }

      // Convert DB format to cache format
      const sessionData: CachedSessionData = {
        version: new Date(dbSession.updatedAt || dbSession.createdAt).getTime(),
        terminalId: dbSession.terminalId,
        userId: dbSession.userId || undefined,
        shell: dbSession.shell,
        cwd: dbSession.cwd,
        cols: dbSession.cols,
        rows: dbSession.rows,
        active: dbSession.active,
        primarySocketId: dbSession.primarySocketId || undefined,
        lastActivityAt: dbSession.lastActivityAt.toISOString(),
        createdAt: dbSession.createdAt.toISOString(),
      };

      // Update cache (fire-and-forget)
      this.setInCache(sessionData).catch(() => {});

      return sessionData;
    } catch (error) {
      logger.error('Error getting session', { terminalId, error });
      return null;
    }
  }

  /**
   * Create session (DB-first write-through)
   */
  static async createSession(data: {
    terminalId: string;
    userId?: string;
    shell: string;
    cwd: string;
    cols: number;
    rows: number;
    socketId?: string;
  }): Promise<CachedSessionData> {
    try {
      // Write to DB first (source of truth)
      const dbSession = await prisma.session.create({
        data: {
          terminalId: data.terminalId,
          userId: data.userId,
          shell: data.shell,
          cwd: data.cwd,
          cols: data.cols,
          rows: data.rows,
          socketId: data.socketId,
          active: true,
          lastActivityAt: new Date(),
        },
      });

      logger.info('Session created in database', {
        terminalId: data.terminalId,
        userId: data.userId,
      });

      // Convert to cache format
      const sessionData: CachedSessionData = {
        version: new Date(dbSession.createdAt).getTime(),
        terminalId: dbSession.terminalId,
        userId: dbSession.userId || undefined,
        shell: dbSession.shell,
        cwd: dbSession.cwd,
        cols: dbSession.cols,
        rows: dbSession.rows,
        active: dbSession.active,
        primarySocketId: dbSession.primarySocketId || undefined,
        lastActivityAt: dbSession.lastActivityAt.toISOString(),
        createdAt: dbSession.createdAt.toISOString(),
      };

      // Update cache (fire-and-forget)
      this.setInCache(sessionData).catch(() => {});

      return sessionData;
    } catch (error) {
      logger.error('Error creating session', { data, error });
      throw error;
    }
  }

  /**
   * Update session activity (optimistic, no lock needed)
   */
  static async updateActivity(terminalId: string): Promise<void> {
    try {
      // Check if session exists
      const exists = await prisma.session.findUnique({
        where: { terminalId },
        select: { id: true },
      });

      if (!exists) {
        return; // Session doesn't exist (unauthenticated user)
      }

      // Update DB
      await prisma.session.update({
        where: { terminalId },
        data: { lastActivityAt: new Date() },
      });

      // Update cache (optimistic - just update timestamp)
      const cached = await this.getFromCache(terminalId);
      if (cached) {
        cached.lastActivityAt = new Date().toISOString();
        cached.version = Date.now();
        await this.setInCache(cached);
      }
    } catch (error) {
      logger.debug('Could not update session activity', { terminalId, error });
    }
  }

  /**
   * Update session dimensions (with distributed lock)
   */
  static async updateDimensions(
    terminalId: string,
    cols: number,
    rows: number
  ): Promise<void> {
    // Acquire lock to prevent concurrent dimension updates
    const lockAcquired = await this.acquireLock(terminalId);

    if (!lockAcquired) {
      logger.warn('Failed to acquire lock for dimension update', {
        terminalId,
      });
      return;
    }

    try {
      // Check if session exists
      const exists = await prisma.session.findUnique({
        where: { terminalId },
        select: { id: true },
      });

      if (!exists) {
        return; // Session doesn't exist
      }

      // Update DB first
      await prisma.session.update({
        where: { terminalId },
        data: {
          cols,
          rows,
          lastActivityAt: new Date(),
        },
      });

      // Update cache
      const cached = await this.getFromCache(terminalId);
      if (cached) {
        cached.cols = cols;
        cached.rows = rows;
        cached.lastActivityAt = new Date().toISOString();
        cached.version = Date.now();
        await this.setInCache(cached);
      }

      logger.debug('Session dimensions updated', { terminalId, cols, rows });
    } catch (error) {
      logger.error('Error updating session dimensions', {
        terminalId,
        error,
      });
    } finally {
      // Always release lock
      await this.releaseLock(terminalId);
    }
  }

  /**
   * Deactivate session (DB-first with tombstone)
   */
  static async deactivateSession(terminalId: string): Promise<void> {
    try {
      // Update DB first
      await prisma.session.update({
        where: { terminalId },
        data: {
          active: false,
          socketId: null,
        },
      });

      // Set tombstone to prevent cache resurrection
      await this.setTombstone(terminalId);

      logger.info('Session deactivated', { terminalId });
    } catch (error) {
      logger.error('Error deactivating session', { terminalId, error });
    }
  }

  /**
   * Delete session (DB-first with tombstone)
   */
  static async deleteSession(terminalId: string): Promise<void> {
    try {
      // Set tombstone FIRST (prevents read-while-deleting)
      await this.setTombstone(terminalId);

      // Then delete from DB
      await prisma.session.delete({
        where: { terminalId },
      });

      logger.info('Session deleted', { terminalId });
    } catch (error) {
      logger.debug('Could not delete session', { terminalId, error });
    }
  }

  /**
   * Update primary socket (with lock)
   */
  static async updatePrimarySocket(
    terminalId: string,
    socketId: string | null
  ): Promise<void> {
    const lockAcquired = await this.acquireLock(terminalId);

    if (!lockAcquired) {
      logger.warn('Failed to acquire lock for primary socket update', {
        terminalId,
      });
      return;
    }

    try {
      // Check if session exists
      const exists = await prisma.session.findUnique({
        where: { terminalId },
        select: { id: true },
      });

      if (!exists) {
        return;
      }

      // Update DB
      await prisma.session.update({
        where: { terminalId },
        data: {
          primarySocketId: socketId,
          lastActivityAt: new Date(),
        },
      });

      // Update cache
      const cached = await this.getFromCache(terminalId);
      if (cached) {
        cached.primarySocketId = socketId || undefined;
        cached.lastActivityAt = new Date().toISOString();
        cached.version = Date.now();
        await this.setInCache(cached);
      }
    } catch (error) {
      logger.error('Error updating primary socket', { terminalId, error });
    } finally {
      await this.releaseLock(terminalId);
    }
  }

  /**
   * Get all active sessions for a user
   */
  static async getUserActiveSessions(
    userId: string
  ): Promise<CachedSessionData[]> {
    try {
      // Read from DB (no caching for list queries to avoid consistency issues)
      const sessions = await prisma.session.findMany({
        where: {
          userId,
          active: true,
        },
        orderBy: {
          lastActivityAt: 'desc',
        },
      });

      return sessions.map((s) => ({
        version: new Date(s.updatedAt || s.createdAt).getTime(),
        terminalId: s.terminalId,
        userId: s.userId || undefined,
        shell: s.shell,
        cwd: s.cwd,
        cols: s.cols,
        rows: s.rows,
        active: s.active,
        primarySocketId: s.primarySocketId || undefined,
        lastActivityAt: s.lastActivityAt.toISOString(),
        createdAt: s.createdAt.toISOString(),
      }));
    } catch (error) {
      logger.error('Error fetching user sessions', { userId, error });
      return [];
    }
  }

  /**
   * Clean up old sessions (DB operation, invalidates cache)
   */
  static async cleanupOldSessions(inactiveHours = 24): Promise<number> {
    try {
      const cutoffTime = new Date();
      cutoffTime.setHours(cutoffTime.getHours() - inactiveHours);

      const result = await prisma.session.deleteMany({
        where: {
          OR: [
            {
              active: false,
              lastActivityAt: {
                lt: cutoffTime,
              },
            },
            {
              expiresAt: {
                lt: new Date(),
              },
            },
          ],
        },
      });

      if (result.count > 0) {
        logger.info('Cleaned up old sessions', {
          count: result.count,
          inactiveHours,
        });
      }

      // Note: Cache entries will auto-expire via TTL

      return result.count;
    } catch (error) {
      logger.error('Error cleaning up sessions', { error });
      return 0;
    }
  }
}
