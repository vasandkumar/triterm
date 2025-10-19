import { io, Socket } from 'socket.io-client';

interface QueuedMessage {
  event: string;
  data: any;
  timestamp: number;
}

interface ConnectionMetrics {
  connectTime: number;
  disconnectCount: number;
  reconnectCount: number;
  messagesSent: number;
  messagesReceived: number;
  averageLatency: number;
  lastPingTime: number;
}

class OptimizedSocketClient {
  private socket: Socket | null = null;
  private messageQueue: QueuedMessage[] = [];
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 10;
  private reconnectDelay = 1000; // Start with 1 second
  private maxReconnectDelay = 30000; // Max 30 seconds
  private isConnecting = false;
  private metrics: ConnectionMetrics = {
    connectTime: 0,
    disconnectCount: 0,
    reconnectCount: 0,
    messagesSent: 0,
    messagesReceived: 0,
    averageLatency: 0,
    lastPingTime: 0,
  };
  private latencyMeasurements: number[] = [];
  private maxLatencyMeasurements = 100;

  /**
   * Connect to the server with optimized settings
   */
  connect(url: string): Socket {
    if (this.socket?.connected) {
      return this.socket;
    }

    if (this.isConnecting) {
      return this.socket!;
    }

    this.isConnecting = true;

    this.socket = io(url, {
      // Connection options
      reconnection: true,
      reconnectionAttempts: this.maxReconnectAttempts,
      reconnectionDelay: this.reconnectDelay,
      reconnectionDelayMax: this.maxReconnectDelay,
      timeout: 10000,

      // Transport options
      transports: ['websocket', 'polling'], // Prefer WebSocket, fall back to polling
      upgrade: true,

      // Performance options
      perMessageDeflate: {
        threshold: 1024, // Only compress messages > 1KB
      },

      // Connection pooling
      forceNew: false, // Reuse existing connection if available
      multiplex: true, // Allow multiple namespaces on same connection
    });

    this.setupEventHandlers();
    this.metrics.connectTime = Date.now();

    return this.socket;
  }

  /**
   * Setup event handlers for the socket
   */
  private setupEventHandlers(): void {
    if (!this.socket) return;

    // Connection events
    this.socket.on('connect', () => {
      console.log('[Socket] Connected');
      this.isConnecting = false;
      this.reconnectAttempts = 0;
      this.reconnectDelay = 1000; // Reset delay
      this.flushMessageQueue();
    });

    this.socket.on('disconnect', (reason) => {
      console.log('[Socket] Disconnected:', reason);
      this.metrics.disconnectCount++;

      // Auto-reconnect on unexpected disconnects
      if (reason === 'io server disconnect') {
        // Server forcibly disconnected, try to reconnect
        this.handleReconnect();
      }
    });

    this.socket.on('connect_error', (error) => {
      console.error('[Socket] Connection error:', error);
      this.isConnecting = false;
      this.handleReconnect();
    });

    this.socket.on('reconnect', (attemptNumber) => {
      console.log('[Socket] Reconnected after', attemptNumber, 'attempts');
      this.metrics.reconnectCount++;
      this.reconnectAttempts = 0;
    });

    this.socket.on('reconnect_attempt', (attemptNumber) => {
      console.log('[Socket] Reconnection attempt', attemptNumber);
    });

    this.socket.on('reconnect_failed', () => {
      console.error('[Socket] Reconnection failed after max attempts');
    });

    // Ping/pong for latency monitoring
    this.socket.on('pong', (latency) => {
      this.recordLatency(latency);
      this.metrics.lastPingTime = Date.now();
    });

    // Track received messages
    this.socket.onAny(() => {
      this.metrics.messagesReceived++;
    });
  }

  /**
   * Handle reconnection with exponential backoff
   */
  private handleReconnect(): void {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.error('[Socket] Max reconnect attempts reached');
      return;
    }

    this.reconnectAttempts++;

    // Exponential backoff
    const delay = Math.min(
      this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1),
      this.maxReconnectDelay
    );

    console.log(`[Socket] Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts})`);

    setTimeout(() => {
      if (!this.socket?.connected) {
        this.socket?.connect();
      }
    }, delay);
  }

  /**
   * Send a message with automatic queuing if disconnected
   */
  emit(event: string, data: any): void {
    if (!this.socket) {
      console.warn('[Socket] Not initialized, queuing message');
      this.queueMessage(event, data);
      return;
    }

    if (this.socket.connected) {
      this.socket.emit(event, data);
      this.metrics.messagesSent++;
    } else {
      // Queue message if disconnected
      this.queueMessage(event, data);
    }
  }

  /**
   * Send a message with acknowledgement and timeout
   */
  emitWithAck(event: string, data: any, timeout: number = 5000): Promise<any> {
    return new Promise((resolve, reject) => {
      if (!this.socket?.connected) {
        reject(new Error('Socket not connected'));
        return;
      }

      const timeoutId = setTimeout(() => {
        reject(new Error('Socket acknowledgement timeout'));
      }, timeout);

      this.socket.emit(event, data, (response: any) => {
        clearTimeout(timeoutId);
        this.metrics.messagesSent++;
        resolve(response);
      });
    });
  }

  /**
   * Queue a message for later delivery
   */
  private queueMessage(event: string, data: any): void {
    const message: QueuedMessage = {
      event,
      data,
      timestamp: Date.now(),
    };

    this.messageQueue.push(message);

    // Limit queue size to prevent memory issues
    if (this.messageQueue.length > 1000) {
      console.warn('[Socket] Message queue exceeded 1000, dropping oldest messages');
      this.messageQueue = this.messageQueue.slice(-1000);
    }
  }

  /**
   * Flush queued messages when reconnected
   */
  private flushMessageQueue(): void {
    if (!this.socket?.connected || this.messageQueue.length === 0) {
      return;
    }

    console.log(`[Socket] Flushing ${this.messageQueue.length} queued messages`);

    while (this.messageQueue.length > 0) {
      const message = this.messageQueue.shift();
      if (message) {
        this.socket.emit(message.event, message.data);
        this.metrics.messagesSent++;
      }
    }
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
   * Start heartbeat monitoring
   */
  startHeartbeat(interval: number = 30000): NodeJS.Timeout {
    return setInterval(() => {
      if (this.socket?.connected) {
        const start = Date.now();
        this.socket.emit('ping', () => {
          const latency = Date.now() - start;
          this.recordLatency(latency);
        });
      }
    }, interval);
  }

  /**
   * Get connection metrics
   */
  getMetrics(): ConnectionMetrics {
    return { ...this.metrics };
  }

  /**
   * Get current connection status
   */
  getStatus(): {
    connected: boolean;
    queuedMessages: number;
    reconnectAttempts: number;
    uptime: number;
  } {
    return {
      connected: this.socket?.connected || false,
      queuedMessages: this.messageQueue.length,
      reconnectAttempts: this.reconnectAttempts,
      uptime: this.metrics.connectTime > 0 ? Date.now() - this.metrics.connectTime : 0,
    };
  }

  /**
   * Register event listener
   */
  on(event: string, callback: (...args: any[]) => void): void {
    this.socket?.on(event, callback);
  }

  /**
   * Remove event listener
   */
  off(event: string, callback?: (...args: any[]) => void): void {
    this.socket?.off(event, callback);
  }

  /**
   * Disconnect from server
   */
  disconnect(): void {
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
    }
    this.messageQueue = [];
    this.reconnectAttempts = 0;
  }

  /**
   * Get the underlying socket instance
   */
  getSocket(): Socket | null {
    return this.socket;
  }
}

// Export singleton instance
export const optimizedSocket = new OptimizedSocketClient();
