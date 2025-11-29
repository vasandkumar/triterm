/**
 * Redis Registry Manager - Multi-Device Socket Tracking
 *
 * Manages socket connections across multiple servers using Redis:
 * - User → Terminal → Sockets mapping
 * - Atomic set operations (no race conditions)
 * - Primary socket designation
 * - Device information tracking
 * - Cross-server socket lookups
 */

import { getRedisClient } from './redis.js';
import { prisma } from './prisma.js';
import logger from '../config/logger.js';

const DEVICE_TTL = 3600; // 1 hour TTL for device info
const SOCKET_TTL = 7200; // 2 hours TTL for socket tracking

interface DeviceInfo {
  socketId: string;
  deviceId?: string;
  deviceName?: string;
  connectedAt: string; // ISO timestamp
  lastPingAt: string;
  serverId?: string; // Which server instance owns this socket
}

/**
 * Redis Registry Manager for Socket Tracking
 */
export class RedisRegistryManager {
  private static readonly USER_TERMINALS_KEY = 'triterm:user_terminals:';
  private static readonly TERMINAL_SOCKETS_KEY = 'triterm:terminal_sockets:';
  private static readonly SOCKET_INFO_KEY = 'triterm:socket_info:';
  private static readonly PRIMARY_SOCKET_KEY = 'triterm:primary_socket:';
  private static readonly SOCKET_TERMINALS_KEY = 'triterm:socket_terminals:';

  private serverId: string;

  constructor(serverId?: string) {
    // Unique server ID for multi-instance deployments
    this.serverId = serverId || process.env.SERVER_ID || `server-${Date.now()}`;
  }

  /**
   * Add socket connection to a terminal
   */
  async addSocket(
    userId: string,
    terminalId: string,
    socketId: string,
    deviceId?: string,
    deviceName?: string
  ): Promise<void> {
    try {
      const redis = getRedisClient();

      // Device info
      const deviceInfo: DeviceInfo = {
        socketId,
        deviceId,
        deviceName,
        connectedAt: new Date().toISOString(),
        lastPingAt: new Date().toISOString(),
        serverId: this.serverId,
      };

      // Use pipeline for atomic multi-operation
      const pipeline = redis.multi();

      // 1. Add terminal to user's terminal set
      pipeline.sAdd(`${this.USER_TERMINALS_KEY}${userId}`, terminalId);
      pipeline.expire(`${this.USER_TERMINALS_KEY}${userId}`, SOCKET_TTL);

      // 2. Add socket to terminal's socket set
      pipeline.sAdd(`${this.TERMINAL_SOCKETS_KEY}${terminalId}`, socketId);
      pipeline.expire(`${this.TERMINAL_SOCKETS_KEY}${terminalId}`, SOCKET_TTL);

      // 3. Store device info
      pipeline.setEx(
        `${this.SOCKET_INFO_KEY}${socketId}`,
        DEVICE_TTL,
        JSON.stringify(deviceInfo)
      );

      // 4. Add terminal to socket's terminal set (reverse lookup)
      pipeline.sAdd(
        `${this.SOCKET_TERMINALS_KEY}${socketId}`,
        `${userId}:${terminalId}`
      );
      pipeline.expire(`${this.SOCKET_TERMINALS_KEY}${socketId}`, SOCKET_TTL);

      // 5. Set primary socket if this is the first connection
      const primaryExists = await redis.exists(
        `${this.PRIMARY_SOCKET_KEY}${terminalId}`
      );
      if (!primaryExists) {
        pipeline.setEx(
          `${this.PRIMARY_SOCKET_KEY}${terminalId}`,
          SOCKET_TTL,
          socketId
        );
      }

      await pipeline.exec();

      // Persist to database (fire-and-forget)
      this.persistSocketConnection(
        terminalId,
        socketId,
        deviceId,
        deviceName
      ).catch((err) => {
        logger.warn('Failed to persist socket to DB', { err });
      });

      logger.debug('Socket added to registry', {
        userId,
        terminalId,
        socketId,
        deviceId,
      });
    } catch (error) {
      logger.error('Error adding socket to registry', {
        userId,
        terminalId,
        socketId,
        error,
      });
      throw error;
    }
  }

  /**
   * Remove socket from terminal
   */
  async removeSocket(
    userId: string,
    terminalId: string,
    socketId: string
  ): Promise<void> {
    try {
      const redis = getRedisClient();
      const pipeline = redis.multi();

      // 1. Remove socket from terminal's socket set
      pipeline.sRem(`${this.TERMINAL_SOCKETS_KEY}${terminalId}`, socketId);

      // 2. Delete socket info
      pipeline.del(`${this.SOCKET_INFO_KEY}${socketId}`);

      // 3. Remove from reverse lookup
      pipeline.del(`${this.SOCKET_TERMINALS_KEY}${socketId}`);

      // 4. Check if this was the primary socket
      const primarySocket = await redis.get(
        `${this.PRIMARY_SOCKET_KEY}${terminalId}`
      );

      if (primarySocket === socketId) {
        // Get remaining sockets and assign new primary
        const remainingSockets = await redis.sMembers(
          `${this.TERMINAL_SOCKETS_KEY}${terminalId}`
        );

        if (remainingSockets.length > 0) {
          // Assign first remaining socket as primary
          pipeline.setEx(
            `${this.PRIMARY_SOCKET_KEY}${terminalId}`,
            SOCKET_TTL,
            remainingSockets[0]
          );
        } else {
          // No sockets left, delete primary marker
          pipeline.del(`${this.PRIMARY_SOCKET_KEY}${terminalId}`);
          // Remove terminal from user's set
          pipeline.sRem(`${this.USER_TERMINALS_KEY}${userId}`, terminalId);
        }
      }

      await pipeline.exec();

      // Remove from database (fire-and-forget)
      this.removeSocketFromDatabase(socketId).catch(() => {});

      logger.debug('Socket removed from registry', {
        userId,
        terminalId,
        socketId,
      });
    } catch (error) {
      logger.error('Error removing socket from registry', {
        userId,
        terminalId,
        socketId,
        error,
      });
    }
  }

  /**
   * Remove all terminals for a socket (on disconnect)
   */
  async removeSocketFromAllTerminals(socketId: string): Promise<void> {
    try {
      const redis = getRedisClient();

      // Get all terminals for this socket
      const terminals = await redis.sMembers(
        `${this.SOCKET_TERMINALS_KEY}${socketId}`
      );

      for (const terminalKey of terminals) {
        const [userId, terminalId] = terminalKey.split(':');
        if (userId && terminalId) {
          await this.removeSocket(userId, terminalId, socketId);
        }
      }

      logger.debug('Socket removed from all terminals', { socketId });
    } catch (error) {
      logger.error('Error removing socket from all terminals', {
        socketId,
        error,
      });
    }
  }

  /**
   * Get all sockets connected to a terminal
   */
  async getSocketsForTerminal(
    userId: string,
    terminalId: string
  ): Promise<string[]> {
    try {
      const redis = getRedisClient();
      const sockets = await redis.sMembers(
        `${this.TERMINAL_SOCKETS_KEY}${terminalId}`
      );
      return sockets;
    } catch (error) {
      logger.error('Error getting sockets for terminal', {
        userId,
        terminalId,
        error,
      });
      return [];
    }
  }

  /**
   * Get all terminals for a user
   */
  async getTerminalsForUser(userId: string): Promise<string[]> {
    try {
      const redis = getRedisClient();
      const terminals = await redis.sMembers(
        `${this.USER_TERMINALS_KEY}${userId}`
      );
      return terminals;
    } catch (error) {
      logger.error('Error getting terminals for user', { userId, error });
      return [];
    }
  }

  /**
   * Get device info for all sockets on a terminal
   */
  async getDevicesForTerminal(
    userId: string,
    terminalId: string
  ): Promise<DeviceInfo[]> {
    try {
      const sockets = await this.getSocketsForTerminal(userId, terminalId);
      const devices: DeviceInfo[] = [];

      const redis = getRedisClient();

      for (const socketId of sockets) {
        const infoStr = await redis.get(`${this.SOCKET_INFO_KEY}${socketId}`);
        if (infoStr) {
          devices.push(JSON.parse(infoStr));
        }
      }

      return devices;
    } catch (error) {
      logger.error('Error getting devices for terminal', {
        userId,
        terminalId,
        error,
      });
      return [];
    }
  }

  /**
   * Get primary socket for a terminal
   */
  async getPrimarySocket(
    userId: string,
    terminalId: string
  ): Promise<string | null> {
    try {
      const redis = getRedisClient();
      const primarySocket = await redis.get(
        `${this.PRIMARY_SOCKET_KEY}${terminalId}`
      );
      return primarySocket;
    } catch (error) {
      logger.error('Error getting primary socket', {
        userId,
        terminalId,
        error,
      });
      return null;
    }
  }

  /**
   * Set primary socket for a terminal
   */
  async setPrimarySocket(
    userId: string,
    terminalId: string,
    socketId: string
  ): Promise<boolean> {
    try {
      const redis = getRedisClient();

      // Verify socket is connected to this terminal
      const isMember = await redis.sIsMember(
        `${this.TERMINAL_SOCKETS_KEY}${terminalId}`,
        socketId
      );

      if (!isMember) {
        logger.warn('Cannot set primary socket - socket not connected', {
          userId,
          terminalId,
          socketId,
        });
        return false;
      }

      // Set new primary
      await redis.setEx(
        `${this.PRIMARY_SOCKET_KEY}${terminalId}`,
        SOCKET_TTL,
        socketId
      );

      // Update in database (fire-and-forget)
      this.updatePrimarySocketInDatabase(terminalId, socketId).catch(() => {});

      logger.debug('Primary socket updated', {
        userId,
        terminalId,
        socketId,
      });

      return true;
    } catch (error) {
      logger.error('Error setting primary socket', {
        userId,
        terminalId,
        socketId,
        error,
      });
      return false;
    }
  }

  /**
   * Update last ping time for a socket
   */
  async updatePing(
    userId: string,
    terminalId: string,
    socketId: string
  ): Promise<void> {
    try {
      const redis = getRedisClient();
      const infoKey = `${this.SOCKET_INFO_KEY}${socketId}`;
      const infoStr = await redis.get(infoKey);

      if (!infoStr) {
        return;
      }

      const deviceInfo: DeviceInfo = JSON.parse(infoStr);
      deviceInfo.lastPingAt = new Date().toISOString();

      await redis.setEx(infoKey, DEVICE_TTL, JSON.stringify(deviceInfo));
    } catch (error) {
      logger.error('Error updating ping', { userId, terminalId, socketId, error });
    }
  }

  /**
   * Check if socket is connected to terminal
   */
  async isSocketConnected(
    userId: string,
    terminalId: string,
    socketId: string
  ): Promise<boolean> {
    try {
      const redis = getRedisClient();
      const isMember = await redis.sIsMember(
        `${this.TERMINAL_SOCKETS_KEY}${terminalId}`,
        socketId
      );
      return isMember;
    } catch (error) {
      logger.error('Error checking socket connection', {
        userId,
        terminalId,
        socketId,
        error,
      });
      return false;
    }
  }

  /**
   * Get device count for terminal
   */
  async getDeviceCount(userId: string, terminalId: string): Promise<number> {
    try {
      const redis = getRedisClient();
      const count = await redis.sCard(
        `${this.TERMINAL_SOCKETS_KEY}${terminalId}`
      );
      return count;
    } catch (error) {
      logger.error('Error getting device count', {
        userId,
        terminalId,
        error,
      });
      return 0;
    }
  }

  /**
   * Get terminals for a socket (reverse lookup)
   */
  async getTerminalsForSocket(
    socketId: string
  ): Promise<Array<{ userId: string; terminalId: string }>> {
    try {
      const redis = getRedisClient();
      const terminals = await redis.sMembers(
        `${this.SOCKET_TERMINALS_KEY}${socketId}`
      );

      return terminals.map((terminalKey) => {
        const [userId, terminalId] = terminalKey.split(':');
        return { userId, terminalId };
      });
    } catch (error) {
      logger.error('Error getting terminals for socket', { socketId, error });
      return [];
    }
  }

  /**
   * Get statistics
   */
  async getStats() {
    try {
      const redis = getRedisClient();

      // Get all user terminal keys
      const userKeys = await redis.keys(`${this.USER_TERMINALS_KEY}*`);

      let totalTerminals = 0;
      let totalDevices = 0;

      for (const userKey of userKeys) {
        const terminals = await redis.sMembers(userKey);
        totalTerminals += terminals.length;

        for (const terminalId of terminals) {
          const devices = await redis.sCard(
            `${this.TERMINAL_SOCKETS_KEY}${terminalId}`
          );
          totalDevices += devices;
        }
      }

      return {
        activeUsers: userKeys.length,
        totalTerminals,
        totalDevices,
        averageDevicesPerTerminal:
          totalTerminals > 0 ? totalDevices / totalTerminals : 0,
      };
    } catch (error) {
      logger.error('Error getting registry stats', { error });
      return {
        activeUsers: 0,
        totalTerminals: 0,
        totalDevices: 0,
        averageDevicesPerTerminal: 0,
      };
    }
  }

  /**
   * Persist socket connection to database
   */
  private async persistSocketConnection(
    terminalId: string,
    socketId: string,
    deviceId?: string,
    deviceName?: string
  ): Promise<void> {
    try {
      // Find session by terminalId
      const session = await prisma.session.findUnique({
        where: { terminalId },
        select: { id: true },
      });

      if (!session) {
        logger.debug('Session not found for socket persistence', {
          terminalId,
        });
        return;
      }

      await prisma.terminalSocket.create({
        data: {
          sessionId: session.id,
          socketId,
          deviceId,
          deviceName,
          connectedAt: new Date(),
          lastPingAt: new Date(),
        },
      });

      logger.debug('Socket persisted to database', { terminalId, socketId });
    } catch (error) {
      logger.error('Failed to persist socket connection', { error });
    }
  }

  /**
   * Remove socket from database
   */
  private async removeSocketFromDatabase(socketId: string): Promise<void> {
    try {
      await prisma.terminalSocket.deleteMany({
        where: { socketId },
      });
      logger.debug('Socket removed from database', { socketId });
    } catch (error) {
      logger.error('Failed to remove socket from database', { error });
    }
  }

  /**
   * Update primary socket in database
   */
  private async updatePrimarySocketInDatabase(
    terminalId: string,
    socketId: string
  ): Promise<void> {
    try {
      await prisma.session.updateMany({
        where: { terminalId },
        data: { primarySocketId: socketId },
      });
      logger.debug('Primary socket updated in database', {
        terminalId,
        socketId,
      });
    } catch (error) {
      logger.error('Failed to update primary socket in database', { error });
    }
  }

  /**
   * Clear all registry data (for testing)
   */
  async clear(): Promise<void> {
    try {
      const redis = getRedisClient();

      // Get all keys with our prefixes
      const patterns = [
        `${this.USER_TERMINALS_KEY}*`,
        `${this.TERMINAL_SOCKETS_KEY}*`,
        `${this.SOCKET_INFO_KEY}*`,
        `${this.PRIMARY_SOCKET_KEY}*`,
        `${this.SOCKET_TERMINALS_KEY}*`,
      ];

      for (const pattern of patterns) {
        const keys = await redis.keys(pattern);
        if (keys.length > 0) {
          await redis.del(keys);
        }
      }

      logger.info('Registry cleared from Redis');
    } catch (error) {
      logger.error('Error clearing registry', { error });
    }
  }
}
