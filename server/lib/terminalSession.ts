import { prisma } from './prisma.js';
import logger from '../config/logger.js';
import { RedisSessionManager } from './redisSessionManager.js';
import { isRedisHealthy } from './redis.js';

export interface TerminalSessionData {
  terminalId: string;
  userId?: string; // Optional to support unauthenticated terminals
  shell: string;
  cwd: string;
  cols: number;
  rows: number;
  socketId?: string;
}

/**
 * Create a new terminal session (hybrid: DB + Redis cache)
 */
export async function createTerminalSession(data: TerminalSessionData) {
  try {
    // Check if Redis is available
    const useRedis = await isRedisHealthy();

    if (useRedis) {
      // Use Redis hybrid approach
      const cachedSession = await RedisSessionManager.createSession(data);

      // Return in Prisma format for compatibility
      return {
        id: cachedSession.terminalId, // Use terminalId as id for compatibility
        terminalId: cachedSession.terminalId,
        userId: cachedSession.userId || null,
        shell: cachedSession.shell,
        cwd: cachedSession.cwd,
        cols: cachedSession.cols,
        rows: cachedSession.rows,
        active: cachedSession.active,
        socketId: data.socketId || null,
        primarySocketId: cachedSession.primarySocketId || null,
        createdAt: new Date(cachedSession.createdAt),
        lastActivityAt: new Date(cachedSession.lastActivityAt),
        expiresAt: null,
      };
    } else {
      // Fallback to direct DB access
      const session = await prisma.session.create({
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

      logger.info('Terminal session created in database (Redis unavailable)', {
        sessionId: session.id,
        terminalId: session.terminalId,
        userId: session.userId,
      });

      return session;
    }
  } catch (error) {
    logger.error('Error creating terminal session', { error, data });
    throw error;
  }
}

/**
 * Update terminal session activity timestamp (hybrid: Redis + DB)
 * Only updates if session exists (for authenticated users)
 */
export async function updateSessionActivity(terminalId: string) {
  try {
    const useRedis = await isRedisHealthy();

    if (useRedis) {
      await RedisSessionManager.updateActivity(terminalId);
    } else {
      // Fallback to direct DB
      const session = await prisma.session.findUnique({
        where: { terminalId },
      });

      if (!session) {
        return;
      }

      await prisma.session.update({
        where: { terminalId },
        data: { lastActivityAt: new Date() },
      });
    }
  } catch (error) {
    logger.debug('Could not update session activity', { terminalId, error });
  }
}

/**
 * Update terminal dimensions (hybrid: Redis + DB with distributed lock)
 * Only updates if session exists (for authenticated users)
 */
export async function updateSessionDimensions(
  terminalId: string,
  cols: number,
  rows: number
) {
  try {
    const useRedis = await isRedisHealthy();

    if (useRedis) {
      await RedisSessionManager.updateDimensions(terminalId, cols, rows);
    } else {
      // Fallback to direct DB
      const session = await prisma.session.findUnique({
        where: { terminalId },
      });

      if (!session) {
        return;
      }

      await prisma.session.update({
        where: { terminalId },
        data: {
          cols,
          rows,
          lastActivityAt: new Date(),
        },
      });
    }
  } catch (error) {
    logger.debug('Could not update session dimensions', { terminalId, error });
  }
}

/**
 * Mark a terminal session as inactive (hybrid: Redis + DB with tombstone)
 */
export async function deactivateSession(terminalId: string) {
  try {
    const useRedis = await isRedisHealthy();

    if (useRedis) {
      await RedisSessionManager.deactivateSession(terminalId);
    } else {
      // Fallback to direct DB
      await prisma.session.update({
        where: { terminalId },
        data: {
          active: false,
          socketId: null,
        },
      });

      logger.info('Terminal session deactivated', { terminalId });
    }
  } catch (error) {
    logger.error('Error deactivating terminal session', { error, terminalId });
  }
}

/**
 * Delete a terminal session (hybrid: Redis tombstone + DB delete)
 */
export async function deleteSession(terminalId: string) {
  try {
    const useRedis = await isRedisHealthy();

    if (useRedis) {
      await RedisSessionManager.deleteSession(terminalId);
    } else {
      // Fallback to direct DB
      await prisma.session.delete({
        where: { terminalId },
      });

      logger.info('Terminal session deleted', { terminalId });
    }
  } catch (error) {
    logger.debug('Could not delete session', { terminalId, error });
  }
}

/**
 * Get all active sessions for a user (hybrid: Redis + DB)
 */
export async function getUserActiveSessions(userId: string) {
  try {
    const useRedis = await isRedisHealthy();

    if (useRedis) {
      const cachedSessions =
        await RedisSessionManager.getUserActiveSessions(userId);

      // Convert to Prisma format for compatibility
      return cachedSessions.map((s) => ({
        id: s.terminalId,
        terminalId: s.terminalId,
        userId: s.userId || null,
        shell: s.shell,
        cwd: s.cwd,
        cols: s.cols,
        rows: s.rows,
        active: s.active,
        socketId: null,
        primarySocketId: s.primarySocketId || null,
        createdAt: new Date(s.createdAt),
        lastActivityAt: new Date(s.lastActivityAt),
        expiresAt: null,
      }));
    } else {
      // Fallback to direct DB
      const sessions = await prisma.session.findMany({
        where: {
          userId,
          active: true,
        },
        orderBy: {
          lastActivityAt: 'desc',
        },
      });

      return sessions;
    }
  } catch (error) {
    logger.error('Error fetching user sessions', { error, userId });
    return [];
  }
}

/**
 * Get a specific terminal session (hybrid: Redis cache-first)
 */
export async function getSession(terminalId: string) {
  try {
    const useRedis = await isRedisHealthy();

    if (useRedis) {
      const cachedSession = await RedisSessionManager.getSession(terminalId);

      if (!cachedSession) {
        return null;
      }

      // Convert to Prisma format
      return {
        id: cachedSession.terminalId,
        terminalId: cachedSession.terminalId,
        userId: cachedSession.userId || null,
        shell: cachedSession.shell,
        cwd: cachedSession.cwd,
        cols: cachedSession.cols,
        rows: cachedSession.rows,
        active: cachedSession.active,
        socketId: null,
        primarySocketId: cachedSession.primarySocketId || null,
        createdAt: new Date(cachedSession.createdAt),
        lastActivityAt: new Date(cachedSession.lastActivityAt),
        expiresAt: null,
      };
    } else {
      // Fallback to direct DB
      const session = await prisma.session.findUnique({
        where: { terminalId },
      });

      return session;
    }
  } catch (error) {
    logger.debug('Could not find session', { terminalId, error });
    return null;
  }
}

/**
 * Clean up inactive sessions older than specified hours (hybrid: DB cleanup)
 */
export async function cleanupOldSessions(inactiveHours: number = 24) {
  try {
    const useRedis = await isRedisHealthy();

    if (useRedis) {
      // Redis manager handles both DB cleanup and cache invalidation
      return await RedisSessionManager.cleanupOldSessions(inactiveHours);
    } else {
      // Fallback to direct DB
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
        logger.info('Cleaned up old terminal sessions', {
          count: result.count,
          inactiveHours,
        });
      }

      return result.count;
    }
  } catch (error) {
    logger.error('Error cleaning up old sessions', { error });
    return 0;
  }
}

/**
 * Update primary socket ID for a terminal session (hybrid: Redis + DB with lock)
 * Only updates if session exists (for authenticated users)
 */
export async function updateSessionSocket(terminalId: string, socketId: string | null) {
  try {
    const useRedis = await isRedisHealthy();

    if (useRedis) {
      await RedisSessionManager.updatePrimarySocket(terminalId, socketId);
    } else {
      // Fallback to direct DB
      const session = await prisma.session.findUnique({
        where: { terminalId },
      });

      if (!session) {
        return;
      }

      await prisma.session.update({
        where: { terminalId },
        data: {
          socketId,
          lastActivityAt: new Date(),
        },
      });
    }
  } catch (error) {
    logger.debug('Could not update session socket', { terminalId, error });
  }
}
