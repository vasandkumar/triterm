import { Server, Socket } from 'socket.io';
import logger from '../config/logger.js';

interface ConnectionMetrics {
  totalConnections: number;
  activeConnections: number;
  totalMessages: number;
  errors: number;
  averageLatency: number;
  peakConnections: number;
}

class SocketOptimizationService {
  private metrics: ConnectionMetrics = {
    totalConnections: 0,
    activeConnections: 0,
    totalMessages: 0,
    errors: 0,
    averageLatency: 0,
    peakConnections: 0,
  };

  private latencyMeasurements: number[] = [];
  private maxLatencyMeasurements = 1000;
  private connectionStartTimes = new Map<string, number>();

  /**
   * Apply optimizations to Socket.IO server
   */
  optimizeServer(io: Server): void {
    // Configure server-level optimizations
    io.engine.opts.pingInterval = 25000; // Ping every 25 seconds
    io.engine.opts.pingTimeout = 60000; // Wait 60 seconds before considering connection lost
    io.engine.opts.maxHttpBufferSize = 1e6; // 1MB max message size
    io.engine.opts.perMessageDeflate = {
      threshold: 1024, // Only compress messages > 1KB
    };

    // Setup connection monitoring
    this.setupConnectionMonitoring(io);

    // Setup error handling
    this.setupErrorHandling(io);

    // Setup heartbeat
    this.setupHeartbeat(io);

    logger.info('Socket.IO optimizations applied', {
      pingInterval: io.engine.opts.pingInterval,
      pingTimeout: io.engine.opts.pingTimeout,
      maxBufferSize: io.engine.opts.maxHttpBufferSize,
    });
  }

  /**
   * Setup connection monitoring
   */
  private setupConnectionMonitoring(io: Server): void {
    io.on('connection', (socket: Socket) => {
      this.metrics.totalConnections++;
      this.metrics.activeConnections++;
      this.connectionStartTimes.set(socket.id, Date.now());

      if (this.metrics.activeConnections > this.metrics.peakConnections) {
        this.metrics.peakConnections = this.metrics.activeConnections;
      }

      logger.debug('Client connected', {
        socketId: socket.id,
        activeConnections: this.metrics.activeConnections,
      });

      // Track disconnect
      socket.on('disconnect', (reason) => {
        this.metrics.activeConnections--;
        const connectTime = this.connectionStartTimes.get(socket.id);
        const duration = connectTime ? Date.now() - connectTime : 0;

        this.connectionStartTimes.delete(socket.id);

        logger.debug('Client disconnected', {
          socketId: socket.id,
          reason,
          duration: `${(duration / 1000).toFixed(2)}s`,
          activeConnections: this.metrics.activeConnections,
        });
      });

      // Track messages
      socket.onAny(() => {
        this.metrics.totalMessages++;
      });
    });
  }

  /**
   * Setup error handling
   */
  private setupErrorHandling(io: Server): void {
    io.engine.on('connection_error', (err) => {
      this.metrics.errors++;
      logger.error('Connection error', {
        error: err.message,
        code: err.code,
        context: err.context,
      });
    });

    io.on('connect_error', (err) => {
      this.metrics.errors++;
      logger.error('Socket connect error', { error: err.message });
    });
  }

  /**
   * Setup heartbeat/ping-pong for latency monitoring
   */
  private setupHeartbeat(io: Server): void {
    io.on('connection', (socket: Socket) => {
      // Handle ping from client
      socket.on('ping', (callback) => {
        if (typeof callback === 'function') {
          callback(); // Immediately respond
        }
      });

      // Send periodic pings to measure latency
      const pingInterval = setInterval(() => {
        if (socket.connected) {
          const start = Date.now();
          socket.emit('ping', () => {
            const latency = Date.now() - start;
            this.recordLatency(latency);
          });
        }
      }, 30000); // Every 30 seconds

      socket.on('disconnect', () => {
        clearInterval(pingInterval);
      });
    });
  }

  /**
   * Record latency measurement
   */
  private recordLatency(latency: number): void {
    this.latencyMeasurements.push(latency);

    // Keep only recent measurements
    if (this.latencyMeasurements.length > this.maxLatencyMeasurements) {
      this.latencyMeasurements.shift();
    }

    // Calculate average
    const sum = this.latencyMeasurements.reduce((a, b) => a + b, 0);
    this.metrics.averageLatency = sum / this.latencyMeasurements.length;
  }

  /**
   * Get connection metrics
   */
  getMetrics(): ConnectionMetrics & {
    uptimePercentage: number;
    messagesPerConnection: number;
    errorsPerConnection: number;
  } {
    const uptimePercentage =
      this.metrics.totalConnections > 0
        ? ((this.metrics.totalConnections - this.metrics.errors) / this.metrics.totalConnections) *
          100
        : 100;

    const messagesPerConnection =
      this.metrics.totalConnections > 0
        ? this.metrics.totalMessages / this.metrics.totalConnections
        : 0;

    const errorsPerConnection =
      this.metrics.totalConnections > 0
        ? this.metrics.errors / this.metrics.totalConnections
        : 0;

    return {
      ...this.metrics,
      uptimePercentage,
      messagesPerConnection,
      errorsPerConnection,
    };
  }

  /**
   * Get health status
   */
  getHealthStatus(): {
    status: 'healthy' | 'degraded' | 'unhealthy';
    activeConnections: number;
    averageLatency: number;
    errorRate: number;
  } {
    const errorRate =
      this.metrics.totalConnections > 0
        ? this.metrics.errors / this.metrics.totalConnections
        : 0;

    let status: 'healthy' | 'degraded' | 'unhealthy' = 'healthy';

    if (errorRate > 0.1 || this.metrics.averageLatency > 1000) {
      status = 'degraded';
    }

    if (errorRate > 0.3 || this.metrics.averageLatency > 5000) {
      status = 'unhealthy';
    }

    return {
      status,
      activeConnections: this.metrics.activeConnections,
      averageLatency: this.metrics.averageLatency,
      errorRate,
    };
  }

  /**
   * Reset metrics
   */
  resetMetrics(): void {
    this.metrics = {
      totalConnections: 0,
      activeConnections: this.metrics.activeConnections, // Keep current active
      totalMessages: 0,
      errors: 0,
      averageLatency: 0,
      peakConnections: this.metrics.peakConnections,
    };
    this.latencyMeasurements = [];
  }

  /**
   * Optimize socket for terminal operations
   */
  optimizeTerminalSocket(socket: Socket): void {
    // Increase buffer size for terminal output
    socket.conn.setMaxListeners(20); // Allow more listeners for terminal events

    // Optimize for binary data (terminal output)
    socket.binary(true);

    // Setup compression for large terminal outputs
    socket.compress(true);
  }

  /**
   * Broadcast with acknowledgement tracking
   */
  async broadcastWithAck(
    io: Server,
    event: string,
    data: any,
    room?: string,
    timeout: number = 5000
  ): Promise<{ success: number; failed: number }> {
    const sockets = room ? await io.in(room).fetchSockets() : await io.fetchSockets();

    const results = await Promise.allSettled(
      sockets.map((socket) => {
        return new Promise<void>((resolve, reject) => {
          const timer = setTimeout(() => reject(new Error('Timeout')), timeout);

          socket.emit(event, data, (ack: any) => {
            clearTimeout(timer);
            resolve();
          });
        });
      })
    );

    const success = results.filter((r) => r.status === 'fulfilled').length;
    const failed = results.filter((r) => r.status === 'rejected').length;

    return { success, failed };
  }
}

// Export singleton instance
export const socketOptimization = new SocketOptimizationService();
