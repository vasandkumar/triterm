import { Server, Socket } from 'socket.io';
import logger from '../config/logger.js';

interface UserPresence {
  userId: string;
  username: string;
  socketId: string;
  terminalId: string;
  connectedAt: number;
  lastActivity: number;
  permission: 'VIEW' | 'CONTROL';
}

interface TerminalPresence {
  terminalId: string;
  users: Map<string, UserPresence>;
}

class PresenceTrackingService {
  private terminalPresence = new Map<string, TerminalPresence>();
  private userSockets = new Map<string, Set<string>>();

  /**
   * Join a terminal session
   */
  joinTerminal(
    socket: Socket,
    terminalId: string,
    userId: string,
    username: string,
    permission: 'VIEW' | 'CONTROL'
  ): void {
    if (!this.terminalPresence.has(terminalId)) {
      this.terminalPresence.set(terminalId, {
        terminalId,
        users: new Map(),
      });
    }

    const presence = this.terminalPresence.get(terminalId)!;
    const userPresence: UserPresence = {
      userId,
      username,
      socketId: socket.id,
      terminalId,
      connectedAt: Date.now(),
      lastActivity: Date.now(),
      permission,
    };

    presence.users.set(userId, userPresence);

    // Track user's sockets
    if (!this.userSockets.has(userId)) {
      this.userSockets.set(userId, new Set());
    }
    this.userSockets.get(userId)!.add(socket.id);

    // Join Socket.IO room for this terminal
    socket.join(`terminal:${terminalId}`);

    logger.info('User joined terminal', {
      userId,
      username,
      terminalId,
      permission,
    });
  }

  /**
   * Leave a terminal session
   */
  leaveTerminal(socket: Socket, terminalId: string, userId: string): void {
    const presence = this.terminalPresence.get(terminalId);
    if (!presence) return;

    presence.users.delete(userId);

    // Clean up user socket tracking
    const userSocketSet = this.userSockets.get(userId);
    if (userSocketSet) {
      userSocketSet.delete(socket.id);
      if (userSocketSet.size === 0) {
        this.userSockets.delete(userId);
      }
    }

    // Leave Socket.IO room
    socket.leave(`terminal:${terminalId}`);

    // Clean up if no users left
    if (presence.users.size === 0) {
      this.terminalPresence.delete(terminalId);
    }

    logger.info('User left terminal', { userId, terminalId });
  }

  /**
   * Update user activity timestamp
   */
  updateActivity(terminalId: string, userId: string): void {
    const presence = this.terminalPresence.get(terminalId);
    if (!presence) return;

    const userPresence = presence.users.get(userId);
    if (userPresence) {
      userPresence.lastActivity = Date.now();
    }
  }

  /**
   * Get all users in a terminal
   */
  getTerminalUsers(terminalId: string): UserPresence[] {
    const presence = this.terminalPresence.get(terminalId);
    if (!presence) return [];

    return Array.from(presence.users.values());
  }

  /**
   * Get all terminals a user is in
   */
  getUserTerminals(userId: string): string[] {
    const terminals: string[] = [];

    for (const [terminalId, presence] of this.terminalPresence.entries()) {
      if (presence.users.has(userId)) {
        terminals.push(terminalId);
      }
    }

    return terminals;
  }

  /**
   * Check if user is in terminal
   */
  isUserInTerminal(terminalId: string, userId: string): boolean {
    const presence = this.terminalPresence.get(terminalId);
    return presence ? presence.users.has(userId) : false;
  }

  /**
   * Get user permission level for terminal
   */
  getUserPermission(terminalId: string, userId: string): 'VIEW' | 'CONTROL' | null {
    const presence = this.terminalPresence.get(terminalId);
    if (!presence) return null;

    const userPresence = presence.users.get(userId);
    return userPresence ? userPresence.permission : null;
  }

  /**
   * Broadcast presence update to all users in terminal
   */
  broadcastPresence(io: Server, terminalId: string): void {
    const users = this.getTerminalUsers(terminalId);

    io.to(`terminal:${terminalId}`).emit('presence-update', {
      terminalId,
      users: users.map((u) => ({
        userId: u.userId,
        username: u.username,
        permission: u.permission,
        connectedAt: u.connectedAt,
        lastActivity: u.lastActivity,
      })),
    });
  }

  /**
   * Handle socket disconnect - remove from all terminals
   */
  handleDisconnect(socket: Socket, userId?: string): void {
    if (!userId) return;

    // Find all terminals this user was in
    const terminals = this.getUserTerminals(userId);

    // Leave all terminals
    for (const terminalId of terminals) {
      this.leaveTerminal(socket, terminalId, userId);
    }

    logger.info('User disconnected from all terminals', { userId });
  }

  /**
   * Get presence statistics
   */
  getStats(): {
    activeTerminals: number;
    totalUsers: number;
    averageUsersPerTerminal: number;
  } {
    let totalUsers = 0;
    const activeTerminals = this.terminalPresence.size;

    for (const presence of this.terminalPresence.values()) {
      totalUsers += presence.users.size;
    }

    return {
      activeTerminals,
      totalUsers,
      averageUsersPerTerminal:
        activeTerminals > 0 ? Math.round((totalUsers / activeTerminals) * 100) / 100 : 0,
    };
  }

  /**
   * Clean up inactive users (no activity for 5 minutes)
   */
  cleanupInactiveUsers(io: Server, inactivityThreshold: number = 5 * 60 * 1000): number {
    const now = Date.now();
    let cleanedCount = 0;

    for (const [terminalId, presence] of this.terminalPresence.entries()) {
      for (const [userId, userPresence] of presence.users.entries()) {
        if (now - userPresence.lastActivity > inactivityThreshold) {
          // Find socket and leave
          const socket = io.sockets.sockets.get(userPresence.socketId);
          if (socket) {
            this.leaveTerminal(socket, terminalId, userId);
            cleanedCount++;
          }
        }
      }
    }

    if (cleanedCount > 0) {
      logger.info('Cleaned up inactive users', { count: cleanedCount });
    }

    return cleanedCount;
  }
}

// Export singleton instance
export const presenceTracking = new PresenceTrackingService();
