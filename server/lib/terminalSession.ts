import { prisma } from './prisma.js';
import logger from '../config/logger.js';

export interface TerminalSessionData {
  terminalId: string;
  userId: string;
  shell: string;
  cwd: string;
  cols: number;
  rows: number;
  socketId?: string;
}

/**
 * Create a new terminal session in the database
 */
export async function createTerminalSession(data: TerminalSessionData) {
  try {
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

    logger.info('Terminal session created in database', {
      sessionId: session.id,
      terminalId: session.terminalId,
      userId: session.userId,
    });

    return session;
  } catch (error) {
    logger.error('Error creating terminal session', { error, data });
    throw error;
  }
}

/**
 * Update terminal session activity timestamp
 * Only updates if session exists (for authenticated users)
 */
export async function updateSessionActivity(terminalId: string) {
  try {
    // Check if session exists first
    const session = await prisma.session.findUnique({
      where: { terminalId },
    });

    if (!session) {
      // Session doesn't exist (unauthenticated user), skip update
      return;
    }

    await prisma.session.update({
      where: { terminalId },
      data: { lastActivityAt: new Date() },
    });
  } catch (error) {
    // Silently fail - session might not exist
    logger.debug('Could not update session activity', { terminalId, error });
  }
}

/**
 * Update terminal dimensions
 * Only updates if session exists (for authenticated users)
 */
export async function updateSessionDimensions(
  terminalId: string,
  cols: number,
  rows: number
) {
  try {
    // Check if session exists first
    const session = await prisma.session.findUnique({
      where: { terminalId },
    });

    if (!session) {
      // Session doesn't exist (unauthenticated user), skip update
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
  } catch (error) {
    logger.debug('Could not update session dimensions', { terminalId, error });
  }
}

/**
 * Mark a terminal session as inactive
 */
export async function deactivateSession(terminalId: string) {
  try {
    await prisma.session.update({
      where: { terminalId },
      data: {
        active: false,
        socketId: null,
      },
    });

    logger.info('Terminal session deactivated', { terminalId });
  } catch (error) {
    logger.error('Error deactivating terminal session', { error, terminalId });
  }
}

/**
 * Delete a terminal session from database
 */
export async function deleteSession(terminalId: string) {
  try {
    await prisma.session.delete({
      where: { terminalId },
    });

    logger.info('Terminal session deleted', { terminalId });
  } catch (error) {
    logger.debug('Could not delete session', { terminalId, error });
  }
}

/**
 * Get all active sessions for a user
 */
export async function getUserActiveSessions(userId: string) {
  try {
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
  } catch (error) {
    logger.error('Error fetching user sessions', { error, userId });
    return [];
  }
}

/**
 * Get a specific terminal session
 */
export async function getSession(terminalId: string) {
  try {
    const session = await prisma.session.findUnique({
      where: { terminalId },
    });

    return session;
  } catch (error) {
    logger.debug('Could not find session', { terminalId, error });
    return null;
  }
}

/**
 * Clean up inactive sessions older than specified hours
 */
export async function cleanupOldSessions(inactiveHours: number = 24) {
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
      logger.info('Cleaned up old terminal sessions', {
        count: result.count,
        inactiveHours,
      });
    }

    return result.count;
  } catch (error) {
    logger.error('Error cleaning up old sessions', { error });
    return 0;
  }
}

/**
 * Update socket ID for a terminal session
 * Only updates if session exists (for authenticated users)
 */
export async function updateSessionSocket(terminalId: string, socketId: string | null) {
  try {
    // Check if session exists first
    const session = await prisma.session.findUnique({
      where: { terminalId },
    });

    if (!session) {
      // Session doesn't exist (unauthenticated user), skip update
      return;
    }

    await prisma.session.update({
      where: { terminalId },
      data: {
        socketId,
        lastActivityAt: new Date(),
      },
    });
  } catch (error) {
    logger.debug('Could not update session socket', { terminalId, error });
  }
}
