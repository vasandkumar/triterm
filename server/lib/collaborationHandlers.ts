import { Server, Socket } from 'socket.io';
import { presenceTracking } from './presenceTracking.js';
import { sessionRecording } from './sessionRecording.js';
import prisma from './prisma.js';
import logger from '../config/logger.js';

interface JoinTerminalData {
  terminalId: string;
  userId: string;
  username: string;
}

interface InputBroadcastData {
  terminalId: string;
  userId: string;
  username: string;
  input: string;
  cursorPosition?: { line: number; column: number };
}

interface CursorUpdateData {
  terminalId: string;
  userId: string;
  username: string;
  position: { line: number; column: number };
}

/**
 * Setup collaboration-related Socket.IO event handlers
 */
export function setupCollaborationHandlers(io: Server, socket: Socket, userId?: string) {
  /**
   * Join a terminal for collaboration
   */
  socket.on(
    'collaboration:join',
    async (data: JoinTerminalData, callback?: (response: any) => void) => {
      try {
        if (!userId) {
          const error = 'Authentication required';
          logger.warn('Unauthenticated join attempt', { terminalId: data.terminalId });
          callback?.({ success: false, error });
          return;
        }

        // Check if user has access to this terminal
        const access = await prisma.terminalAccess.findFirst({
          where: {
            terminalId: data.terminalId,
            sharedWithUserId: userId,
            isActive: true,
            OR: [{ expiresAt: null }, { expiresAt: { gt: new Date() } }],
          },
        });

        // Also check if user owns the terminal
        const terminal = await prisma.terminal.findFirst({
          where: {
            id: data.terminalId,
            userId,
          },
        });

        if (!access && !terminal) {
          const error = 'Access denied to this terminal';
          logger.warn('Unauthorized join attempt', {
            userId,
            terminalId: data.terminalId,
          });
          callback?.({ success: false, error });
          return;
        }

        // Determine permission level
        const permission = terminal ? 'CONTROL' : (access?.permission ?? 'VIEW');

        // Join terminal room
        presenceTracking.joinTerminal(socket, data.terminalId, userId, data.username, permission);

        // Broadcast presence update
        presenceTracking.broadcastPresence(io, data.terminalId);

        // Get current users
        const users = presenceTracking.getTerminalUsers(data.terminalId);

        logger.info('User joined collaboration session', {
          userId,
          terminalId: data.terminalId,
          permission,
          userCount: users.length,
        });

        callback?.({
          success: true,
          permission,
          users: users.map((u) => ({
            userId: u.userId,
            username: u.username,
            permission: u.permission,
          })),
        });
      } catch (error) {
        logger.error('Error joining collaboration session', { error, userId });
        callback?.({ success: false, error: 'Failed to join terminal' });
      }
    }
  );

  /**
   * Leave a terminal collaboration session
   */
  socket.on(
    'collaboration:leave',
    (data: { terminalId: string }, callback?: (response: any) => void) => {
      try {
        if (!userId) {
          callback?.({ success: false, error: 'Authentication required' });
          return;
        }

        presenceTracking.leaveTerminal(socket, data.terminalId, userId);
        presenceTracking.broadcastPresence(io, data.terminalId);

        logger.info('User left collaboration session', {
          userId,
          terminalId: data.terminalId,
        });

        callback?.({ success: true });
      } catch (error) {
        logger.error('Error leaving collaboration session', { error, userId });
        callback?.({ success: false, error: 'Failed to leave terminal' });
      }
    }
  );

  /**
   * Broadcast terminal input from one user to all collaborators
   */
  socket.on('collaboration:input', (data: InputBroadcastData) => {
    if (!userId) return;

    // Verify user has CONTROL permission
    const permission = presenceTracking.getUserPermission(data.terminalId, userId);
    if (permission !== 'CONTROL') {
      logger.warn('User without CONTROL permission tried to send input', {
        userId,
        terminalId: data.terminalId,
        permission,
      });
      return;
    }

    // Update activity
    presenceTracking.updateActivity(data.terminalId, userId);

    // Broadcast to all other users in terminal (except sender)
    socket.to(`terminal:${data.terminalId}`).emit('collaboration:input-received', {
      userId: data.userId,
      username: data.username,
      input: data.input,
      cursorPosition: data.cursorPosition,
      timestamp: Date.now(),
    });

    // Record input if recording is active
    if (sessionRecording.isRecording(data.terminalId)) {
      sessionRecording.recordInput(data.terminalId, data.input);
    }
  });

  /**
   * Broadcast cursor position updates
   */
  socket.on('collaboration:cursor', (data: CursorUpdateData) => {
    if (!userId) return;

    // Verify user is in terminal
    if (!presenceTracking.isUserInTerminal(data.terminalId, userId)) {
      return;
    }

    // Update activity
    presenceTracking.updateActivity(data.terminalId, userId);

    // Broadcast cursor position to all other users
    socket.to(`terminal:${data.terminalId}`).emit('collaboration:cursor-update', {
      userId: data.userId,
      username: data.username,
      position: data.position,
      timestamp: Date.now(),
    });
  });

  /**
   * Request control of a terminal (upgrade from VIEW to CONTROL)
   */
  socket.on(
    'collaboration:request-control',
    async (data: { terminalId: string }, callback?: (response: any) => void) => {
      try {
        if (!userId) {
          callback?.({ success: false, error: 'Authentication required' });
          return;
        }

        // Check current permission
        const currentPermission = presenceTracking.getUserPermission(data.terminalId, userId);
        if (currentPermission === 'CONTROL') {
          callback?.({ success: true, permission: 'CONTROL' });
          return;
        }

        // Check if user's access can be upgraded
        const access = await prisma.terminalAccess.findFirst({
          where: {
            terminalId: data.terminalId,
            sharedWithUserId: userId,
            isActive: true,
          },
        });

        if (!access || access.permission !== 'CONTROL') {
          callback?.({ success: false, error: 'Not authorized for control' });
          return;
        }

        // Update presence with new permission
        presenceTracking.leaveTerminal(socket, data.terminalId, userId);
        const username =
          (await prisma.user.findUnique({ where: { id: userId } }))?.username || 'Unknown';
        presenceTracking.joinTerminal(socket, data.terminalId, userId, username, 'CONTROL');

        // Broadcast presence update
        presenceTracking.broadcastPresence(io, data.terminalId);

        logger.info('User upgraded to CONTROL permission', {
          userId,
          terminalId: data.terminalId,
        });

        callback?.({ success: true, permission: 'CONTROL' });
      } catch (error) {
        logger.error('Error requesting control', { error, userId });
        callback?.({ success: false, error: 'Failed to request control' });
      }
    }
  );

  /**
   * Activity heartbeat to prevent timeout
   */
  socket.on('collaboration:heartbeat', (data: { terminalId: string }) => {
    if (!userId) return;

    presenceTracking.updateActivity(data.terminalId, userId);
  });

  /**
   * Handle disconnect
   */
  socket.on('disconnect', () => {
    if (!userId) return;

    // Get all terminals user was in
    const terminals = presenceTracking.getUserTerminals(userId);

    // Leave all and broadcast updates
    for (const terminalId of terminals) {
      presenceTracking.leaveTerminal(socket, terminalId, userId);
      presenceTracking.broadcastPresence(io, terminalId);
    }
  });
}

/**
 * Setup periodic cleanup of inactive users
 */
export function setupPresenceCleanup(io: Server) {
  // Run cleanup every 5 minutes
  setInterval(() => {
    presenceTracking.cleanupInactiveUsers(io);
  }, 5 * 60 * 1000);

  logger.info('Presence cleanup task initialized');
}

/**
 * Get presence statistics
 */
export function getPresenceStats() {
  return presenceTracking.getStats();
}
