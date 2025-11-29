/**
 * User-Terminal-Socket Registry
 *
 * Manages the mapping between users, terminals, and socket connections
 * to support multi-device terminal access.
 *
 * Now uses Redis for distributed state management (hybrid approach with DB persistence)
 */

import { Socket } from 'socket.io';
import { PrismaClient } from '@prisma/client';
import { RedisRegistryManager } from './redisRegistryManager.js';
import { isRedisHealthy } from './redis.js';
import logger from '../config/logger.js';

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
  // Map: userId -> Map: terminalId -> TerminalDevices (legacy in-memory storage)
  private userTerminals: Map<string, Map<string, TerminalDevices>>;

  // Reverse lookup: socketId -> {userId, terminalId}
  private socketToTerminal: Map<string, { userId: string; terminalId: string }[]>;

  // Redis manager instance for distributed state
  private redisManager: RedisRegistryManager;

  constructor(serverId?: string) {
    this.userTerminals = new Map();
    this.socketToTerminal = new Map();
    this.redisManager = new RedisRegistryManager(serverId);
  }

  /**
   * Add a socket connection to a terminal (hybrid: Redis + in-memory fallback)
   */
  async addSocket(
    userId: string,
    terminalId: string,
    socketId: string,
    deviceId?: string,
    deviceName?: string
  ): Promise<void> {
    try {
      const useRedis = await isRedisHealthy();

      if (useRedis) {
        // Use Redis for distributed state
        await this.redisManager.addSocket(userId, terminalId, socketId, deviceId, deviceName);
      } else {
        // Fallback to in-memory storage
        this.addSocketInMemory(userId, terminalId, socketId, deviceId, deviceName);
      }
    } catch (error) {
      logger.error('Error adding socket, falling back to in-memory', { error });
      this.addSocketInMemory(userId, terminalId, socketId, deviceId, deviceName);
    }
  }

  /**
   * Legacy in-memory socket addition (fallback)
   */
  private addSocketInMemory(
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
   * Remove a socket connection from a terminal (hybrid: Redis + in-memory)
   */
  async removeSocket(userId: string, terminalId: string, socketId: string): Promise<boolean> {
    try {
      const useRedis = await isRedisHealthy();

      if (useRedis) {
        await this.redisManager.removeSocket(userId, terminalId, socketId);
        return true;
      } else {
        return this.removeSocketInMemory(userId, terminalId, socketId);
      }
    } catch (error) {
      logger.error('Error removing socket, falling back to in-memory', { error });
      return this.removeSocketInMemory(userId, terminalId, socketId);
    }
  }

  /**
   * Legacy in-memory socket removal (fallback)
   */
  private removeSocketInMemory(userId: string, terminalId: string, socketId: string): boolean {
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
   * Remove all terminals for a socket (on disconnect) - hybrid
   */
  async removeSocketFromAllTerminals(socketId: string): Promise<void> {
    try {
      const useRedis = await isRedisHealthy();

      if (useRedis) {
        await this.redisManager.removeSocketFromAllTerminals(socketId);
      } else {
        this.removeSocketFromAllTerminalsInMemory(socketId);
      }
    } catch (error) {
      logger.error('Error removing socket from all terminals, using in-memory', { error });
      this.removeSocketFromAllTerminalsInMemory(socketId);
    }
  }

  /**
   * Legacy in-memory removal from all terminals
   */
  private removeSocketFromAllTerminalsInMemory(socketId: string): void {
    const terminals = this.socketToTerminal.get(socketId);
    if (!terminals) return;

    // Make a copy since we'll be modifying the array
    const terminalsCopy = [...terminals];

    for (const { userId, terminalId } of terminalsCopy) {
      this.removeSocketInMemory(userId, terminalId, socketId);
    }
  }

  /**
   * Get all socket IDs connected to a terminal (hybrid)
   */
  async getSocketsForTerminal(userId: string, terminalId: string): Promise<string[]> {
    try {
      const useRedis = await isRedisHealthy();

      if (useRedis) {
        return await this.redisManager.getSocketsForTerminal(userId, terminalId);
      } else {
        return this.getSocketsForTerminalInMemory(userId, terminalId);
      }
    } catch (error) {
      logger.error('Error getting sockets, using in-memory', { error });
      return this.getSocketsForTerminalInMemory(userId, terminalId);
    }
  }

  /**
   * Legacy in-memory socket retrieval
   */
  private getSocketsForTerminalInMemory(userId: string, terminalId: string): string[] {
    const userTerminals = this.userTerminals.get(userId);
    if (!userTerminals) return [];

    const terminalDevices = userTerminals.get(terminalId);
    if (!terminalDevices) return [];

    return Array.from(terminalDevices.devices.keys());
  }

  /**
   * Get all terminals for a user (hybrid)
   */
  async getTerminalsForUser(userId: string): Promise<string[]> {
    try {
      const useRedis = await isRedisHealthy();

      if (useRedis) {
        return await this.redisManager.getTerminalsForUser(userId);
      } else {
        const userTerminals = this.userTerminals.get(userId);
        if (!userTerminals) return [];
        return Array.from(userTerminals.keys());
      }
    } catch (error) {
      logger.error('Error getting terminals for user, using in-memory', { error });
      const userTerminals = this.userTerminals.get(userId);
      if (!userTerminals) return [];
      return Array.from(userTerminals.keys());
    }
  }

  /**
   * Get all devices connected to a terminal (hybrid)
   */
  async getDevicesForTerminal(userId: string, terminalId: string): Promise<DeviceInfo[]> {
    try {
      const useRedis = await isRedisHealthy();

      if (useRedis) {
        const devices = await this.redisManager.getDevicesForTerminal(userId, terminalId);
        // Convert Redis format to internal format
        return devices.map(d => ({
          socketId: d.socketId,
          deviceId: d.deviceId,
          deviceName: d.deviceName,
          connectedAt: new Date(d.connectedAt),
          lastPingAt: new Date(d.lastPingAt),
        }));
      } else {
        const userTerminals = this.userTerminals.get(userId);
        if (!userTerminals) return [];

        const terminalDevices = userTerminals.get(terminalId);
        if (!terminalDevices) return [];

        return Array.from(terminalDevices.devices.values());
      }
    } catch (error) {
      logger.error('Error getting devices, using in-memory', { error });
      const userTerminals = this.userTerminals.get(userId);
      if (!userTerminals) return [];

      const terminalDevices = userTerminals.get(terminalId);
      if (!terminalDevices) return [];

      return Array.from(terminalDevices.devices.values());
    }
  }

  /**
   * Get primary socket ID for a terminal (hybrid)
   */
  async getPrimarySocket(userId: string, terminalId: string): Promise<string | undefined> {
    try {
      const useRedis = await isRedisHealthy();

      if (useRedis) {
        const primarySocket = await this.redisManager.getPrimarySocket(userId, terminalId);
        return primarySocket || undefined;
      } else {
        const userTerminals = this.userTerminals.get(userId);
        if (!userTerminals) return undefined;

        const terminalDevices = userTerminals.get(terminalId);
        return terminalDevices?.primarySocketId;
      }
    } catch (error) {
      logger.error('Error getting primary socket, using in-memory', { error });
      const userTerminals = this.userTerminals.get(userId);
      if (!userTerminals) return undefined;

      const terminalDevices = userTerminals.get(terminalId);
      return terminalDevices?.primarySocketId;
    }
  }

  /**
   * Set primary socket for a terminal (transfer control) - hybrid
   */
  async setPrimarySocket(userId: string, terminalId: string, socketId: string): Promise<boolean> {
    try {
      const useRedis = await isRedisHealthy();

      if (useRedis) {
        return await this.redisManager.setPrimarySocket(userId, terminalId, socketId);
      } else {
        const userTerminals = this.userTerminals.get(userId);
        if (!userTerminals) return false;

        const terminalDevices = userTerminals.get(terminalId);
        if (!terminalDevices) return false;

        // Verify socket is connected to this terminal
        if (!terminalDevices.devices.has(socketId)) return false;

        terminalDevices.primarySocketId = socketId;
        return true;
      }
    } catch (error) {
      logger.error('Error setting primary socket, using in-memory', { error });
      const userTerminals = this.userTerminals.get(userId);
      if (!userTerminals) return false;

      const terminalDevices = userTerminals.get(terminalId);
      if (!terminalDevices) return false;

      if (!terminalDevices.devices.has(socketId)) return false;

      terminalDevices.primarySocketId = socketId;
      return true;
    }
  }

  /**
   * Update last ping time for a device (hybrid)
   */
  async updatePing(userId: string, terminalId: string, socketId: string): Promise<void> {
    try {
      const useRedis = await isRedisHealthy();

      if (useRedis) {
        await this.redisManager.updatePing(userId, terminalId, socketId);
      } else {
        const userTerminals = this.userTerminals.get(userId);
        if (!userTerminals) return;

        const terminalDevices = userTerminals.get(terminalId);
        if (!terminalDevices) return;

        const device = terminalDevices.devices.get(socketId);
        if (device) {
          device.lastPingAt = new Date();
        }
      }
    } catch (error) {
      logger.error('Error updating ping, using in-memory', { error });
      const userTerminals = this.userTerminals.get(userId);
      if (!userTerminals) return;

      const terminalDevices = userTerminals.get(terminalId);
      if (!terminalDevices) return;

      const device = terminalDevices.devices.get(socketId);
      if (device) {
        device.lastPingAt = new Date();
      }
    }
  }

  /**
   * Check if a socket is connected to a terminal (hybrid)
   */
  async isSocketConnected(userId: string, terminalId: string, socketId: string): Promise<boolean> {
    try {
      const useRedis = await isRedisHealthy();

      if (useRedis) {
        return await this.redisManager.isSocketConnected(userId, terminalId, socketId);
      } else {
        const sockets = this.getSocketsForTerminalInMemory(userId, terminalId);
        return sockets.includes(socketId);
      }
    } catch (error) {
      logger.error('Error checking socket connection, using in-memory', { error });
      const sockets = this.getSocketsForTerminalInMemory(userId, terminalId);
      return sockets.includes(socketId);
    }
  }

  /**
   * Get device count for a terminal (hybrid)
   */
  async getDeviceCount(userId: string, terminalId: string): Promise<number> {
    try {
      const useRedis = await isRedisHealthy();

      if (useRedis) {
        return await this.redisManager.getDeviceCount(userId, terminalId);
      } else {
        return this.getSocketsForTerminalInMemory(userId, terminalId).length;
      }
    } catch (error) {
      logger.error('Error getting device count, using in-memory', { error });
      return this.getSocketsForTerminalInMemory(userId, terminalId).length;
    }
  }

  /**
   * Check if terminal has any connected devices (hybrid)
   */
  async hasConnectedDevices(userId: string, terminalId: string): Promise<boolean> {
    const count = await this.getDeviceCount(userId, terminalId);
    return count > 0;
  }

  /**
   * Get terminals for a socket (hybrid)
   */
  async getTerminalsForSocket(socketId: string): Promise<Array<{ userId: string; terminalId: string }>> {
    try {
      const useRedis = await isRedisHealthy();

      if (useRedis) {
        return await this.redisManager.getTerminalsForSocket(socketId);
      } else {
        return this.socketToTerminal.get(socketId) || [];
      }
    } catch (error) {
      logger.error('Error getting terminals for socket, using in-memory', { error });
      return this.socketToTerminal.get(socketId) || [];
    }
  }

  /**
   * Get all active users (in-memory only - not in Redis)
   */
  getActiveUsers(): string[] {
    return Array.from(this.userTerminals.keys());
  }

  /**
   * Clear all data (for testing or reset) - hybrid
   */
  async clear(): Promise<void> {
    try {
      const useRedis = await isRedisHealthy();

      if (useRedis) {
        await this.redisManager.clear();
      }
    } catch (error) {
      logger.error('Error clearing Redis registry', { error });
    }

    // Always clear in-memory
    this.userTerminals.clear();
    this.socketToTerminal.clear();
  }

  /**
   * Get statistics (hybrid)
   */
  async getStats() {
    try {
      const useRedis = await isRedisHealthy();

      if (useRedis) {
        return await this.redisManager.getStats();
      } else {
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
    } catch (error) {
      logger.error('Error getting stats, using in-memory', { error });
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
