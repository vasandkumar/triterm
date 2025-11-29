/**
 * Redis Client Configuration and Connection Manager
 *
 * Provides a centralized Redis client with:
 * - Automatic reconnection
 * - Connection pooling
 * - Error handling
 * - Graceful shutdown
 */

import { createClient, RedisClientType } from 'redis';
import logger from '../config/logger.js';

// Redis client instance (singleton)
let redisClient: RedisClientType | null = null;
let isConnecting = false;
let reconnectAttempts = 0;

const MAX_RECONNECT_ATTEMPTS = 10;
const RECONNECT_DELAY_MS = 5000;

/**
 * Redis configuration from environment variables
 */
interface RedisConfig {
  host: string;
  port: number;
  password?: string;
  db: number;
  maxRetriesPerRequest: number;
  enableOfflineQueue: boolean;
  retryStrategy?: (times: number) => number | void;
}

/**
 * Get Redis configuration from environment
 */
function getRedisConfig(): RedisConfig {
  return {
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT || '6379', 10),
    password: process.env.REDIS_PASSWORD,
    db: parseInt(process.env.REDIS_DB || '0', 10),
    maxRetriesPerRequest: 3,
    enableOfflineQueue: true,
  };
}

/**
 * Create and connect to Redis
 */
export async function connectRedis(): Promise<RedisClientType> {
  if (redisClient && redisClient.isOpen) {
    return redisClient;
  }

  if (isConnecting) {
    // Wait for existing connection attempt
    while (isConnecting) {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    if (redisClient && redisClient.isOpen) {
      return redisClient;
    }
  }

  isConnecting = true;

  try {
    const config = getRedisConfig();

    redisClient = createClient({
      socket: {
        host: config.host,
        port: config.port,
        reconnectStrategy: (retries) => {
          reconnectAttempts = retries;
          if (retries > MAX_RECONNECT_ATTEMPTS) {
            logger.error('Redis: Max reconnection attempts reached', {
              attempts: retries,
            });
            return new Error('Max reconnection attempts reached');
          }
          const delay = Math.min(retries * 1000, RECONNECT_DELAY_MS);
          logger.warn('Redis: Reconnecting...', {
            attempt: retries,
            delayMs: delay,
          });
          return delay;
        },
      },
      password: config.password,
      database: config.db,
    });

    // Event handlers
    redisClient.on('error', (err) => {
      logger.error('Redis client error', { error: err.message });
    });

    redisClient.on('connect', () => {
      reconnectAttempts = 0;
      logger.info('Redis: Connection established', {
        host: config.host,
        port: config.port,
        db: config.db,
      });
    });

    redisClient.on('ready', () => {
      logger.info('Redis: Client ready');
    });

    redisClient.on('reconnecting', () => {
      logger.warn('Redis: Reconnecting...', {
        attempts: reconnectAttempts,
      });
    });

    redisClient.on('end', () => {
      logger.info('Redis: Connection closed');
    });

    // Connect
    await redisClient.connect();

    logger.info('Redis: Successfully connected', {
      host: config.host,
      port: config.port,
    });

    return redisClient;
  } catch (error) {
    logger.error('Redis: Connection failed', { error });
    throw error;
  } finally {
    isConnecting = false;
  }
}

/**
 * Get the Redis client instance
 * Throws error if not connected
 */
export function getRedisClient(): RedisClientType {
  if (!redisClient || !redisClient.isOpen) {
    throw new Error('Redis client not connected. Call connectRedis() first.');
  }
  return redisClient;
}

/**
 * Check if Redis is connected and healthy
 */
export async function isRedisHealthy(): Promise<boolean> {
  try {
    if (!redisClient || !redisClient.isOpen) {
      return false;
    }
    await redisClient.ping();
    return true;
  } catch (error) {
    logger.error('Redis health check failed', { error });
    return false;
  }
}

/**
 * Gracefully disconnect from Redis
 */
export async function disconnectRedis(): Promise<void> {
  if (redisClient && redisClient.isOpen) {
    try {
      await redisClient.quit();
      logger.info('Redis: Disconnected gracefully');
    } catch (error) {
      logger.error('Redis: Error during disconnect', { error });
      // Force disconnect if graceful quit fails
      await redisClient.disconnect();
    }
  }
  redisClient = null;
}

/**
 * Flush all Redis data (USE WITH CAUTION - for testing only)
 */
export async function flushRedis(): Promise<void> {
  const client = getRedisClient();
  await client.flushDb();
  logger.warn('Redis: Database flushed');
}

/**
 * Get Redis connection status
 */
export function getRedisStatus() {
  return {
    connected: redisClient?.isOpen || false,
    reconnectAttempts,
    isConnecting,
  };
}

// Graceful shutdown handling
process.on('SIGTERM', async () => {
  logger.info('SIGTERM received, closing Redis connection');
  await disconnectRedis();
});

process.on('SIGINT', async () => {
  logger.info('SIGINT received, closing Redis connection');
  await disconnectRedis();
});
