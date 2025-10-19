import { writeFile, readFile, mkdir, readdir, unlink } from 'fs/promises';
import { existsSync } from 'fs';
import { join } from 'path';
import logger from '../config/logger.js';

interface RecordingEvent {
  timestamp: number;
  type: 'output' | 'input' | 'resize';
  data: string | { cols: number; rows: number };
}

interface RecordingMetadata {
  terminalId: string;
  userId: string;
  startTime: number;
  endTime?: number;
  duration?: number;
  eventCount: number;
  title?: string;
}

class SessionRecordingService {
  private recordings = new Map<string, RecordingEvent[]>();
  private metadata = new Map<string, RecordingMetadata>();
  private recordingsDir: string;

  constructor(recordingsDir: string = './recordings') {
    this.recordingsDir = recordingsDir;
    this.ensureRecordingsDir();
  }

  /**
   * Ensure recordings directory exists
   */
  private async ensureRecordingsDir(): Promise<void> {
    try {
      if (!existsSync(this.recordingsDir)) {
        await mkdir(this.recordingsDir, { recursive: true });
        logger.info('Created recordings directory', { path: this.recordingsDir });
      }
    } catch (error) {
      logger.error('Failed to create recordings directory', { error });
    }
  }

  /**
   * Start recording a terminal session
   */
  startRecording(terminalId: string, userId: string, title?: string): void {
    if (this.recordings.has(terminalId)) {
      logger.warn('Recording already in progress for terminal', { terminalId });
      return;
    }

    this.recordings.set(terminalId, []);
    this.metadata.set(terminalId, {
      terminalId,
      userId,
      startTime: Date.now(),
      eventCount: 0,
      title,
    });

    logger.info('Started recording session', { terminalId, userId, title });
  }

  /**
   * Record terminal output
   */
  recordOutput(terminalId: string, data: string): void {
    const events = this.recordings.get(terminalId);
    if (!events) return;

    events.push({
      timestamp: Date.now(),
      type: 'output',
      data,
    });

    const meta = this.metadata.get(terminalId);
    if (meta) {
      meta.eventCount = events.length;
    }
  }

  /**
   * Record terminal input
   */
  recordInput(terminalId: string, data: string): void {
    const events = this.recordings.get(terminalId);
    if (!events) return;

    events.push({
      timestamp: Date.now(),
      type: 'input',
      data,
    });

    const meta = this.metadata.get(terminalId);
    if (meta) {
      meta.eventCount = events.length;
    }
  }

  /**
   * Record terminal resize
   */
  recordResize(terminalId: string, cols: number, rows: number): void {
    const events = this.recordings.get(terminalId);
    if (!events) return;

    events.push({
      timestamp: Date.now(),
      type: 'resize',
      data: { cols, rows },
    });

    const meta = this.metadata.get(terminalId);
    if (meta) {
      meta.eventCount = events.length;
    }
  }

  /**
   * Stop recording and save to disk
   */
  async stopRecording(terminalId: string): Promise<string | null> {
    const events = this.recordings.get(terminalId);
    const meta = this.metadata.get(terminalId);

    if (!events || !meta) {
      logger.warn('No recording found for terminal', { terminalId });
      return null;
    }

    try {
      meta.endTime = Date.now();
      meta.duration = meta.endTime - meta.startTime;

      const filename = `${terminalId}-${meta.startTime}.json`;
      const filepath = join(this.recordingsDir, filename);

      const recording = {
        metadata: meta,
        events,
      };

      await writeFile(filepath, JSON.stringify(recording, null, 2));

      // Cleanup in-memory data
      this.recordings.delete(terminalId);
      this.metadata.delete(terminalId);

      logger.info('Saved recording', {
        terminalId,
        filename,
        duration: meta.duration,
        eventCount: meta.eventCount,
      });

      return filename;
    } catch (error) {
      logger.error('Failed to save recording', { terminalId, error });
      return null;
    }
  }

  /**
   * Load a recording from disk
   */
  async loadRecording(
    filename: string
  ): Promise<{ metadata: RecordingMetadata; events: RecordingEvent[] } | null> {
    try {
      const filepath = join(this.recordingsDir, filename);
      const content = await readFile(filepath, 'utf-8');
      return JSON.parse(content);
    } catch (error) {
      logger.error('Failed to load recording', { filename, error });
      return null;
    }
  }

  /**
   * List all recordings
   */
  async listRecordings(): Promise<string[]> {
    try {
      const files = await readdir(this.recordingsDir);
      return files.filter((file) => file.endsWith('.json'));
    } catch (error) {
      logger.error('Failed to list recordings', { error });
      return [];
    }
  }

  /**
   * List recordings for a specific user
   */
  async listUserRecordings(userId: string): Promise<RecordingMetadata[]> {
    try {
      const files = await this.listRecordings();
      const recordings: RecordingMetadata[] = [];

      for (const file of files) {
        const recording = await this.loadRecording(file);
        if (recording && recording.metadata.userId === userId) {
          recordings.push(recording.metadata);
        }
      }

      return recordings.sort((a, b) => b.startTime - a.startTime);
    } catch (error) {
      logger.error('Failed to list user recordings', { userId, error });
      return [];
    }
  }

  /**
   * Delete a recording
   */
  async deleteRecording(filename: string): Promise<boolean> {
    try {
      const filepath = join(this.recordingsDir, filename);
      await unlink(filepath);
      logger.info('Deleted recording', { filename });
      return true;
    } catch (error) {
      logger.error('Failed to delete recording', { filename, error });
      return false;
    }
  }

  /**
   * Get recording metadata without loading all events
   */
  async getRecordingMetadata(filename: string): Promise<RecordingMetadata | null> {
    const recording = await this.loadRecording(filename);
    return recording ? recording.metadata : null;
  }

  /**
   * Check if a terminal is currently being recorded
   */
  isRecording(terminalId: string): boolean {
    return this.recordings.has(terminalId);
  }

  /**
   * Get current recording stats
   */
  getRecordingStats(terminalId: string): RecordingMetadata | null {
    return this.metadata.get(terminalId) || null;
  }

  /**
   * Export recording to asciicast format (compatible with asciinema)
   */
  async exportToAsciicast(filename: string): Promise<string | null> {
    try {
      const recording = await this.loadRecording(filename);
      if (!recording) return null;

      const { metadata, events } = recording;

      // Asciicast v2 format
      const header = {
        version: 2,
        width: 80,
        height: 24,
        timestamp: Math.floor(metadata.startTime / 1000),
        duration: metadata.duration ? metadata.duration / 1000 : 0,
        title: metadata.title || 'Terminal Recording',
      };

      const lines: string[] = [JSON.stringify(header)];

      // Convert events to asciicast format
      const startTime = metadata.startTime;
      for (const event of events) {
        if (event.type === 'output' && typeof event.data === 'string') {
          const timestamp = (event.timestamp - startTime) / 1000;
          const line = [timestamp, 'o', event.data];
          lines.push(JSON.stringify(line));
        } else if (event.type === 'input' && typeof event.data === 'string') {
          const timestamp = (event.timestamp - startTime) / 1000;
          const line = [timestamp, 'i', event.data];
          lines.push(JSON.stringify(line));
        }
      }

      const asciicastFilename = filename.replace('.json', '.cast');
      const filepath = join(this.recordingsDir, asciicastFilename);
      await writeFile(filepath, lines.join('\n'));

      logger.info('Exported to asciicast format', { filename: asciicastFilename });
      return asciicastFilename;
    } catch (error) {
      logger.error('Failed to export to asciicast', { filename, error });
      return null;
    }
  }
}

// Export singleton instance
export const sessionRecording = new SessionRecordingService();
