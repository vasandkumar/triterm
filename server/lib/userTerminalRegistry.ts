/**
 * User-Terminal-Socket Registry
 *
 * Manages the mapping between users, terminals, and socket connections
 * to support multi-device terminal access.
 */

import { Socket } from 'socket.io';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

interface DeviceInfo {
  socketId: string;
  deviceId?: string;
  deviceName?: string;
  connectedAt: Date;
  lastPingAt: Date;
}

interface TerminalDevices {
  userId: string;
  terminalId: string;
  devices: Map<string, DeviceInfo>; // socketId -> DeviceInfo
  primarySocketId?: string; // Primary control device
}

export class UserTerminalRegistry {
  // Map: userId -> Map: terminalId -> TerminalDevices
  private userTerminals: Map<string, Map<string, TerminalDevices>>;

  // Reverse lookup: socketId -> {userId, terminalId}
  private socketToTerminal: Map<string, { userId: string; terminalId: string }[]>;

  constructor() {
    this.userTerminals = new Map();
    this.socketToTerminal = new Map();
  }

  /**
   * Add a socket connection to a terminal
   */
  addSocket(
    userId: string,
    terminalId: string,
    socketId: string,
    deviceId?: string,
    deviceName?: string
  ): void {
    // Initialize user's terminal map if needed
    if (!this.userTerminals.has(userId)) {
      this.userTerminals.set(userId, new Map());
    }

    const userTerminals = this.userTerminals.get(userId)!;

    // Initialize terminal's device map if needed
    if (!userTerminals.has(terminalId)) {
      userTerminals.set(terminalId, {
        userId,
        terminalId,
        devices: new Map(),
        primarySocketId: socketId, // First device becomes primary
      });
    }

    const terminalDevices = userTerminals.get(terminalId)!;

    // Add device info
    terminalDevices.devices.set(socketId, {
      socketId,
      deviceId,
      deviceName,
      connectedAt: new Date(),
      lastPingAt: new Date(),
    });

    // Update reverse lookup
    if (!this.socketToTerminal.has(socketId)) {
      this.socketToTerminal.set(socketId, []);
    }
    this.socketToTerminal.get(socketId)!.push({ userId, terminalId });
  }

  /**
   * Remove a socket connection from a terminal
   */
  removeSocket(userId: string, terminalId: string, socketId: string): boolean {
    const userTerminals = this.userTerminals.get(userId);
    if (!userTerminals) return false;

    const terminalDevices = userTerminals.get(terminalId);
    if (!terminalDevices) return false;

    // Remove device
    const removed = terminalDevices.devices.delete(socketId);

    // If primary socket was removed, assign new primary
    if (terminalDevices.primarySocketId === socketId && terminalDevices.devices.size > 0) {
      // Assign first remaining device as primary
      terminalDevices.primarySocketId = terminalDevices.devices.keys().next().value;
    }

    // If no devices left, remove terminal entry
    if (terminalDevices.devices.size === 0) {
      userTerminals.delete(terminalId);
    }

    // If user has no terminals, remove user entry
    if (userTerminals.size === 0) {
      this.userTerminals.delete(userId);
    }

    // Update reverse lookup
    const socketTerminals = this.socketToTerminal.get(socketId);
    if (socketTerminals) {
      const index = socketTerminals.findIndex(
        (st) => st.userId === userId && st.terminalId === terminalId
      );
      if (index !== -1) {
        socketTerminals.splice(index, 1);
      }
      if (socketTerminals.length === 0) {
        this.socketToTerminal.delete(socketId);
      }
    }

    return removed;
  }

  /**
   * Remove all terminals for a socket (on disconnect)
   */
  removeSocketFromAllTerminals(socketId: string): void {
    const terminals = this.socketToTerminal.get(socketId);
    if (!terminals) return;

    // Make a copy since we'll be modifying the array
    const terminalsCopy = [...terminals];

    for (const { userId, terminalId } of terminalsCopy) {
      this.removeSocket(userId, terminalId, socketId);
    }
  }

  /**
   * Get all socket IDs connected to a terminal
   */
  getSocketsForTerminal(userId: string, terminalId: string): string[] {
    const userTerminals = this.userTerminals.get(userId);
    if (!userTerminals) return [];

    const terminalDevices = userTerminals.get(terminalId);
    if (!terminalDevices) return [];

    return Array.from(terminalDevices.devices.keys());
  }

  /**
   * Get all terminals for a user
   */
  getTerminalsForUser(userId: string): string[] {
    const userTerminals = this.userTerminals.get(userId);
    if (!userTerminals) return [];

    return Array.from(userTerminals.keys());
  }

  /**
   * Get all devices connected to a terminal
   */
  getDevicesForTerminal(userId: string, terminalId: string): DeviceInfo[] {
    const userTerminals = this.userTerminals.get(userId);
    if (!userTerminals) return [];

    const terminalDevices = userTerminals.get(terminalId);
    if (!terminalDevices) return [];

    return Array.from(terminalDevices.devices.values());
  }

  /**
   * Get primary socket ID for a terminal
   */
  getPrimarySocket(userId: string, terminalId: string): string | undefined {
    const userTerminals = this.userTerminals.get(userId);
    if (!userTerminals) return undefined;

    const terminalDevices = userTerminals.get(terminalId);
    return terminalDevices?.primarySocketId;
  }

  /**
   * Set primary socket for a terminal (transfer control)
   */
  setPrimarySocket(userId: string, terminalId: string, socketId: string): boolean {
    const userTerminals = this.userTerminals.get(userId);
    if (!userTerminals) return false;

    const terminalDevices = userTerminals.get(terminalId);
    if (!terminalDevices) return false;

    // Verify socket is connected to this terminal
    if (!terminalDevices.devices.has(socketId)) return false;

    terminalDevices.primarySocketId = socketId;
    return true;
  }

  /**
   * Update last ping time for a device
   */
  updatePing(userId: string, terminalId: string, socketId: string): void {
    const userTerminals = this.userTerminals.get(userId);
    if (!userTerminals) return;

    const terminalDevices = userTerminals.get(terminalId);
    if (!terminalDevices) return;

    const device = terminalDevices.devices.get(socketId);
    if (device) {
      device.lastPingAt = new Date();
    }
  }

  /**
   * Check if a socket is connected to a terminal
   */
  isSocketConnected(userId: string, terminalId: string, socketId: string): boolean {
    const sockets = this.getSocketsForTerminal(userId, terminalId);
    return sockets.includes(socketId);
  }

  /**
   * Get device count for a terminal
   */
  getDeviceCount(userId: string, terminalId: string): number {
    return this.getSocketsForTerminal(userId, terminalId).length;
  }

  /**
   * Check if terminal has any connected devices
   */
  hasConnectedDevices(userId: string, terminalId: string): boolean {
    return this.getDeviceCount(userId, terminalId) > 0;
  }

  /**
   * Get terminals for a socket
   */
  getTerminalsForSocket(socketId: string): Array<{ userId: string; terminalId: string }> {
    return this.socketToTerminal.get(socketId) || [];
  }

  /**
   * Get all active users
   */
  getActiveUsers(): string[] {
    return Array.from(this.userTerminals.keys());
  }

  /**
   * Clear all data (for testing or reset)
   */
  clear(): void {
    this.userTerminals.clear();
    this.socketToTerminal.clear();
  }

  /**
   * Get statistics
   */
  getStats() {
    let totalTerminals = 0;
    let totalDevices = 0;

    for (const userTerminals of this.userTerminals.values()) {
      totalTerminals += userTerminals.size;
      for (const terminalDevices of userTerminals.values()) {
        totalDevices += terminalDevices.devices.size;
      }
    }

    return {
      activeUsers: this.userTerminals.size,
      totalTerminals,
      totalDevices,
      averageDevicesPerTerminal: totalTerminals > 0 ? totalDevices / totalTerminals : 0,
    };
  }

  /**
   * Persist socket connection to database
   */
  async persistSocketConnection(
    sessionId: string,
    socketId: string,
    deviceId?: string,
    deviceName?: string
  ): Promise<void> {
    try {
      await prisma.terminalSocket.create({
        data: {
          sessionId,
          socketId,
          deviceId,
          deviceName,
          connectedAt: new Date(),
          lastPingAt: new Date(),
        },
      });
      console.log(`[Registry] Persisted socket connection ${socketId} for session ${sessionId}`);
    } catch (error) {
      console.error('[Registry] Failed to persist socket connection:', error);
    }
  }

  /**
   * Remove socket connection from database
   */
  async removeSocketFromDatabase(socketId: string): Promise<void> {
    try {
      await prisma.terminalSocket.deleteMany({
        where: { socketId },
      });
      console.log(`[Registry] Removed socket ${socketId} from database`);
    } catch (error) {
      console.error('[Registry] Failed to remove socket from database:', error);
    }
  }

  /**
   * Update last ping time in database
   */
  async updatePingInDatabase(socketId: string): Promise<void> {
    try {
      await prisma.terminalSocket.updateMany({
        where: { socketId },
        data: { lastPingAt: new Date() },
      });
    } catch (error) {
      console.error('[Registry] Failed to update ping in database:', error);
    }
  }

  /**
   * Update primary socket in database
   */
  async updatePrimarySocketInDatabase(terminalId: string, socketId: string): Promise<void> {
    try {
      await prisma.session.updateMany({
        where: { terminalId },
        data: { primarySocketId: socketId },
      });
      console.log(`[Registry] Updated primary socket to ${socketId} for terminal ${terminalId}`);
    } catch (error) {
      console.error('[Registry] Failed to update primary socket in database:', error);
    }
  }

  /**
   * Load active sessions from database (on server restart)
   * Returns sessions that should be recoverable
   */
  async loadActiveSessions(): Promise<
    Array<{ userId: string; terminalId: string; sessionId: string }>
  > {
    try {
      const activeSessions = await prisma.session.findMany({
        where: { active: true },
        include: { sockets: true },
      });

      console.log(`[Registry] Found ${activeSessions.length} active sessions in database`);

      return activeSessions.map((session) => ({
        userId: session.userId,
        terminalId: session.terminalId,
        sessionId: session.id,
      }));
    } catch (error) {
      console.error('[Registry] Failed to load active sessions from database:', error);
      return [];
    }
  }

  /**
   * Clean up stale socket entries from database
   * (Useful after server restart when old socket IDs are invalid)
   */
  async cleanupStaleConnections(): Promise<void> {
    try {
      // Remove all socket entries (they're stale after restart)
      const result = await prisma.terminalSocket.deleteMany({});
      console.log(`[Registry] Cleaned up ${result.count} stale socket connections from database`);
    } catch (error) {
      console.error('[Registry] Failed to cleanup stale connections:', error);
    }
  }
}

// Singleton instance
export const userTerminalRegistry = new UserTerminalRegistry();
