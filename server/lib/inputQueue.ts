/**
 * Enterprise-grade Input Queue System
 *
 * Manages sequential processing of terminal input from multiple devices
 * to prevent race conditions and ensure input ordering consistency.
 *
 * Features:
 * - Sequential input processing with acknowledgments
 * - Automatic timeout handling for stuck inputs
 * - Metrics and monitoring
 * - Comprehensive error handling and logging
 * - Type-safe implementation
 */

import logger from '../config/logger.js';
import { EventEmitter } from 'events';

/**
 * Input entry in the queue
 */
interface QueuedInput {
  id: string;
  terminalId: string;
  socketId: string;
  input: string;
  timestamp: number;
  sequenceNumber: number;
  timeout?: NodeJS.Timeout;
  retries: number;
}

/**
 * Queue metrics for monitoring
 */
interface QueueMetrics {
  totalProcessed: number;
  totalFailed: number;
  totalTimedOut: number;
  averageProcessingTime: number;
  currentQueueSize: number;
  peakQueueSize: number;
}

/**
 * Configuration options for the input queue
 */
interface InputQueueConfig {
  maxQueueSize?: number;
  processingTimeout?: number;
  maxRetries?: number;
  enableMetrics?: boolean;
}

/**
 * Input Queue Manager
 *
 * Manages queued inputs for a specific terminal to ensure
 * sequential processing and prevent race conditions.
 */
class TerminalInputQueue extends EventEmitter {
  private queue: QueuedInput[] = [];
  private processing = false;
  private sequenceCounter = 0;
  private readonly maxQueueSize: number;
  private readonly processingTimeout: number;
  private readonly maxRetries: number;
  private readonly enableMetrics: boolean;

  // Metrics
  private metrics: QueueMetrics = {
    totalProcessed: 0,
    totalFailed: 0,
    totalTimedOut: 0,
    averageProcessingTime: 0,
    currentQueueSize: 0,
    peakQueueSize: 0,
  };

  private processingTimes: number[] = [];
  private readonly maxProcessingTimeSamples = 100;

  constructor(
    private readonly terminalId: string,
    config: InputQueueConfig = {}
  ) {
    super();
    this.maxQueueSize = config.maxQueueSize ?? 1000;
    this.processingTimeout = config.processingTimeout ?? 5000; // 5 seconds
    this.maxRetries = config.maxRetries ?? 3;
    this.enableMetrics = config.enableMetrics ?? true;

    logger.debug('[InputQueue] Created queue for terminal', {
      terminalId: this.terminalId,
      config: {
        maxQueueSize: this.maxQueueSize,
        processingTimeout: this.processingTimeout,
        maxRetries: this.maxRetries,
        enableMetrics: this.enableMetrics,
      },
    });
  }

  /**
   * Enqueue input for processing
   *
   * @param socketId - Socket ID that sent the input
   * @param input - Terminal input string
   * @returns Input ID for tracking
   * @throws Error if queue is full
   */
  enqueue(socketId: string, input: string): string {
    // Validate inputs
    if (!socketId || typeof socketId !== 'string') {
      throw new Error('Invalid socketId: must be a non-empty string');
    }

    if (typeof input !== 'string') {
      throw new Error('Invalid input: must be a string');
    }

    // Check queue capacity
    if (this.queue.length >= this.maxQueueSize) {
      const error = new Error(
        `Input queue full for terminal ${this.terminalId} (max: ${this.maxQueueSize})`
      );
      logger.error('[InputQueue] Queue capacity exceeded', {
        terminalId: this.terminalId,
        queueSize: this.queue.length,
        maxQueueSize: this.maxQueueSize,
      });
      this.metrics.totalFailed++;
      throw error;
    }

    const inputId = `${this.terminalId}-input-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const sequenceNumber = ++this.sequenceCounter;

    const queuedInput: QueuedInput = {
      id: inputId,
      terminalId: this.terminalId,
      socketId,
      input,
      timestamp: Date.now(),
      sequenceNumber,
      retries: 0,
    };

    this.queue.push(queuedInput);

    // Update metrics
    this.metrics.currentQueueSize = this.queue.length;
    if (this.queue.length > this.metrics.peakQueueSize) {
      this.metrics.peakQueueSize = this.queue.length;
    }

    logger.debug('[InputQueue] Input enqueued', {
      terminalId: this.terminalId,
      inputId,
      sequenceNumber,
      socketId,
      inputLength: input.length,
      queueSize: this.queue.length,
    });

    // Start processing if not already processing
    if (!this.processing) {
      this.processNext();
    }

    return inputId;
  }

  /**
   * Process next input in queue
   */
  private async processNext(): Promise<void> {
    if (this.queue.length === 0) {
      this.processing = false;
      logger.debug('[InputQueue] Queue empty, stopping processing', {
        terminalId: this.terminalId,
      });
      return;
    }

    this.processing = true;
    const queuedInput = this.queue[0];
    const startTime = Date.now();

    logger.debug('[InputQueue] Processing input', {
      terminalId: this.terminalId,
      inputId: queuedInput.id,
      sequenceNumber: queuedInput.sequenceNumber,
      socketId: queuedInput.socketId,
      queueSize: this.queue.length,
    });

    try {
      // Set timeout for processing
      const timeoutPromise = new Promise<never>((_, reject) => {
        queuedInput.timeout = setTimeout(() => {
          reject(new Error('Input processing timeout'));
        }, this.processingTimeout);
      });

      // Emit event for processing (server will handle actual PTY write)
      const processingPromise = new Promise<void>((resolve, reject) => {
        this.emit('process', queuedInput, (error?: Error) => {
          if (error) {
            reject(error);
          } else {
            resolve();
          }
        });
      });

      // Race between processing and timeout
      await Promise.race([processingPromise, timeoutPromise]);

      // Clear timeout
      if (queuedInput.timeout) {
        clearTimeout(queuedInput.timeout);
      }

      // Processing successful
      this.queue.shift(); // Remove from queue
      this.metrics.totalProcessed++;
      this.metrics.currentQueueSize = this.queue.length;

      // Update processing time metrics
      if (this.enableMetrics) {
        const processingTime = Date.now() - startTime;
        this.processingTimes.push(processingTime);
        if (this.processingTimes.length > this.maxProcessingTimeSamples) {
          this.processingTimes.shift();
        }
        this.metrics.averageProcessingTime =
          this.processingTimes.reduce((a, b) => a + b, 0) / this.processingTimes.length;
      }

      logger.debug('[InputQueue] Input processed successfully', {
        terminalId: this.terminalId,
        inputId: queuedInput.id,
        sequenceNumber: queuedInput.sequenceNumber,
        processingTime: Date.now() - startTime,
        remainingInQueue: this.queue.length,
      });

      // Emit acknowledgment
      this.emit('ack', {
        inputId: queuedInput.id,
        sequenceNumber: queuedInput.sequenceNumber,
        socketId: queuedInput.socketId,
        success: true,
      });

      // Process next input
      setImmediate(() => this.processNext());
    } catch (error) {
      // Clear timeout
      if (queuedInput.timeout) {
        clearTimeout(queuedInput.timeout);
      }

      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      const isTimeout = errorMessage.includes('timeout');

      logger.error('[InputQueue] Input processing failed', {
        terminalId: this.terminalId,
        inputId: queuedInput.id,
        sequenceNumber: queuedInput.sequenceNumber,
        error: errorMessage,
        isTimeout,
        retries: queuedInput.retries,
        maxRetries: this.maxRetries,
      });

      if (isTimeout) {
        this.metrics.totalTimedOut++;
      }

      // Retry logic
      if (queuedInput.retries < this.maxRetries) {
        queuedInput.retries++;
        logger.warn('[InputQueue] Retrying input processing', {
          terminalId: this.terminalId,
          inputId: queuedInput.id,
          retryAttempt: queuedInput.retries,
          maxRetries: this.maxRetries,
        });

        // Process again
        setImmediate(() => this.processNext());
      } else {
        // Max retries exceeded, discard input
        this.queue.shift();
        this.metrics.totalFailed++;
        this.metrics.currentQueueSize = this.queue.length;

        logger.error('[InputQueue] Input discarded after max retries', {
          terminalId: this.terminalId,
          inputId: queuedInput.id,
          sequenceNumber: queuedInput.sequenceNumber,
          retries: queuedInput.retries,
        });

        // Emit failure acknowledgment
        this.emit('ack', {
          inputId: queuedInput.id,
          sequenceNumber: queuedInput.sequenceNumber,
          socketId: queuedInput.socketId,
          success: false,
          error: errorMessage,
        });

        // Continue with next input
        setImmediate(() => this.processNext());
      }
    }
  }

  /**
   * Get current queue metrics
   */
  getMetrics(): Readonly<QueueMetrics> {
    return { ...this.metrics };
  }

  /**
   * Get current queue size
   */
  getQueueSize(): number {
    return this.queue.length;
  }

  /**
   * Check if queue is processing
   */
  isProcessing(): boolean {
    return this.processing;
  }

  /**
   * Clear all queued inputs (emergency use only)
   */
  clear(): void {
    logger.warn('[InputQueue] Clearing all queued inputs', {
      terminalId: this.terminalId,
      queueSize: this.queue.length,
    });

    // Clear all timeouts
    this.queue.forEach((input) => {
      if (input.timeout) {
        clearTimeout(input.timeout);
      }
    });

    this.queue = [];
    this.processing = false;
    this.metrics.currentQueueSize = 0;
  }

  /**
   * Destroy the queue and clean up resources
   */
  destroy(): void {
    logger.info('[InputQueue] Destroying queue', {
      terminalId: this.terminalId,
      queueSize: this.queue.length,
      metrics: this.metrics,
    });

    this.clear();
    this.removeAllListeners();
  }
}

/**
 * Global Input Queue Manager
 *
 * Manages input queues for all terminals
 */
class InputQueueManager {
  private queues: Map<string, TerminalInputQueue> = new Map();
  private readonly defaultConfig: InputQueueConfig;

  constructor(config: InputQueueConfig = {}) {
    this.defaultConfig = {
      maxQueueSize: config.maxQueueSize ?? 1000,
      processingTimeout: config.processingTimeout ?? 5000,
      maxRetries: config.maxRetries ?? 3,
      enableMetrics: config.enableMetrics ?? true,
    };

    logger.info('[InputQueueManager] Initialized', {
      defaultConfig: this.defaultConfig,
    });
  }

  /**
   * Get or create queue for a terminal
   */
  getQueue(terminalId: string, config?: InputQueueConfig): TerminalInputQueue {
    if (!this.queues.has(terminalId)) {
      const queue = new TerminalInputQueue(terminalId, {
        ...this.defaultConfig,
        ...config,
      });
      this.queues.set(terminalId, queue);

      logger.debug('[InputQueueManager] Created queue for terminal', {
        terminalId,
        totalQueues: this.queues.size,
      });
    }

    return this.queues.get(terminalId)!;
  }

  /**
   * Remove queue for a terminal
   */
  removeQueue(terminalId: string): void {
    const queue = this.queues.get(terminalId);
    if (queue) {
      queue.destroy();
      this.queues.delete(terminalId);

      logger.debug('[InputQueueManager] Removed queue for terminal', {
        terminalId,
        remainingQueues: this.queues.size,
      });
    }
  }

  /**
   * Get all queue metrics
   */
  getAllMetrics(): Map<string, QueueMetrics> {
    const metrics = new Map<string, QueueMetrics>();
    for (const [terminalId, queue] of this.queues.entries()) {
      metrics.set(terminalId, queue.getMetrics());
    }
    return metrics;
  }

  /**
   * Get aggregate metrics across all queues
   */
  getAggregateMetrics(): QueueMetrics {
    const aggregate: QueueMetrics = {
      totalProcessed: 0,
      totalFailed: 0,
      totalTimedOut: 0,
      averageProcessingTime: 0,
      currentQueueSize: 0,
      peakQueueSize: 0,
    };

    let totalAvgTime = 0;
    let queueCount = 0;

    for (const queue of this.queues.values()) {
      const metrics = queue.getMetrics();
      aggregate.totalProcessed += metrics.totalProcessed;
      aggregate.totalFailed += metrics.totalFailed;
      aggregate.totalTimedOut += metrics.totalTimedOut;
      aggregate.currentQueueSize += metrics.currentQueueSize;
      aggregate.peakQueueSize = Math.max(aggregate.peakQueueSize, metrics.peakQueueSize);
      totalAvgTime += metrics.averageProcessingTime;
      queueCount++;
    }

    if (queueCount > 0) {
      aggregate.averageProcessingTime = totalAvgTime / queueCount;
    }

    return aggregate;
  }

  /**
   * Get total number of queues
   */
  getQueueCount(): number {
    return this.queues.size;
  }

  /**
   * Clear all queues (emergency use only)
   */
  clearAll(): void {
    logger.warn('[InputQueueManager] Clearing all queues', {
      queueCount: this.queues.size,
    });

    for (const queue of this.queues.values()) {
      queue.clear();
    }
  }

  /**
   * Destroy all queues and clean up
   */
  destroy(): void {
    logger.info('[InputQueueManager] Destroying all queues', {
      queueCount: this.queues.size,
    });

    for (const queue of this.queues.values()) {
      queue.destroy();
    }

    this.queues.clear();
  }
}

// Export singleton instance
export const inputQueueManager = new InputQueueManager({
  maxQueueSize: parseInt(process.env.INPUT_QUEUE_MAX_SIZE || '1000'),
  processingTimeout: parseInt(process.env.INPUT_QUEUE_TIMEOUT || '5000'),
  maxRetries: parseInt(process.env.INPUT_QUEUE_MAX_RETRIES || '3'),
  enableMetrics: process.env.INPUT_QUEUE_METRICS !== 'false',
});

// Export types
export type { QueuedInput, QueueMetrics, InputQueueConfig };
export { TerminalInputQueue };
