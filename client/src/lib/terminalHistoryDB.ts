/**
 * IndexedDB service for terminal history caching
 * Stores terminal output, command history, and session data
 */

const DB_NAME = 'TriTermDB';
const DB_VERSION = 1;

// Store names
const STORES = {
  TERMINAL_HISTORY: 'terminalHistory',
  COMMAND_HISTORY: 'commandHistory',
  SESSION_DATA: 'sessionData',
};

export interface TerminalHistoryEntry {
  id?: number;
  terminalId: string;
  timestamp: number;
  output: string;
  type: 'stdout' | 'stderr' | 'input';
}

export interface CommandHistoryEntry {
  id?: number;
  terminalId: string;
  command: string;
  timestamp: number;
  cwd?: string;
}

export interface SessionData {
  terminalId: string;
  title?: string;
  createdAt: number;
  lastAccessedAt: number;
  metadata?: Record<string, any>;
}

class TerminalHistoryDB {
  private db: IDBDatabase | null = null;
  private initPromise: Promise<void> | null = null;

  /**
   * Initialize the database
   */
  async init(): Promise<void> {
    if (this.db) return;
    if (this.initPromise) return this.initPromise;

    this.initPromise = new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, DB_VERSION);

      request.onerror = () => {
        reject(new Error('Failed to open IndexedDB'));
      };

      request.onsuccess = () => {
        this.db = request.result;
        resolve();
      };

      request.onupgradeneeded = (event) => {
        const db = (event.target as IDBOpenDBRequest).result;

        // Terminal history store
        if (!db.objectStoreNames.contains(STORES.TERMINAL_HISTORY)) {
          const historyStore = db.createObjectStore(STORES.TERMINAL_HISTORY, {
            keyPath: 'id',
            autoIncrement: true,
          });
          historyStore.createIndex('terminalId', 'terminalId', { unique: false });
          historyStore.createIndex('timestamp', 'timestamp', { unique: false });
        }

        // Command history store
        if (!db.objectStoreNames.contains(STORES.COMMAND_HISTORY)) {
          const commandStore = db.createObjectStore(STORES.COMMAND_HISTORY, {
            keyPath: 'id',
            autoIncrement: true,
          });
          commandStore.createIndex('terminalId', 'terminalId', { unique: false });
          commandStore.createIndex('timestamp', 'timestamp', { unique: false });
        }

        // Session data store
        if (!db.objectStoreNames.contains(STORES.SESSION_DATA)) {
          db.createObjectStore(STORES.SESSION_DATA, { keyPath: 'terminalId' });
        }
      };
    });

    return this.initPromise;
  }

  /**
   * Add terminal output to history
   */
  async addTerminalOutput(entry: TerminalHistoryEntry): Promise<void> {
    await this.init();
    if (!this.db) throw new Error('Database not initialized');

    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction([STORES.TERMINAL_HISTORY], 'readwrite');
      const store = transaction.objectStore(STORES.TERMINAL_HISTORY);
      const request = store.add(entry);

      request.onsuccess = () => resolve();
      request.onerror = () => reject(new Error('Failed to add terminal output'));
    });
  }

  /**
   * Get terminal history for a specific terminal
   */
  async getTerminalHistory(
    terminalId: string,
    limit: number = 1000
  ): Promise<TerminalHistoryEntry[]> {
    await this.init();
    if (!this.db) throw new Error('Database not initialized');

    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction([STORES.TERMINAL_HISTORY], 'readonly');
      const store = transaction.objectStore(STORES.TERMINAL_HISTORY);
      const index = store.index('terminalId');
      const request = index.getAll(IDBKeyRange.only(terminalId));

      request.onsuccess = () => {
        const results = request.result as TerminalHistoryEntry[];
        // Sort by timestamp and limit
        const sorted = results.sort((a, b) => a.timestamp - b.timestamp);
        resolve(sorted.slice(-limit));
      };
      request.onerror = () => reject(new Error('Failed to get terminal history'));
    });
  }

  /**
   * Add command to history
   */
  async addCommand(entry: CommandHistoryEntry): Promise<void> {
    await this.init();
    if (!this.db) throw new Error('Database not initialized');

    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction([STORES.COMMAND_HISTORY], 'readwrite');
      const store = transaction.objectStore(STORES.COMMAND_HISTORY);
      const request = store.add(entry);

      request.onsuccess = () => resolve();
      request.onerror = () => reject(new Error('Failed to add command'));
    });
  }

  /**
   * Get command history for a terminal
   */
  async getCommandHistory(
    terminalId: string,
    limit: number = 100
  ): Promise<CommandHistoryEntry[]> {
    await this.init();
    if (!this.db) throw new Error('Database not initialized');

    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction([STORES.COMMAND_HISTORY], 'readonly');
      const store = transaction.objectStore(STORES.COMMAND_HISTORY);
      const index = store.index('terminalId');
      const request = index.getAll(IDBKeyRange.only(terminalId));

      request.onsuccess = () => {
        const results = request.result as CommandHistoryEntry[];
        // Sort by timestamp descending and limit
        const sorted = results.sort((a, b) => b.timestamp - a.timestamp);
        resolve(sorted.slice(0, limit));
      };
      request.onerror = () => reject(new Error('Failed to get command history'));
    });
  }

  /**
   * Search command history
   */
  async searchCommands(query: string, limit: number = 50): Promise<CommandHistoryEntry[]> {
    await this.init();
    if (!this.db) throw new Error('Database not initialized');

    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction([STORES.COMMAND_HISTORY], 'readonly');
      const store = transaction.objectStore(STORES.COMMAND_HISTORY);
      const request = store.getAll();

      request.onsuccess = () => {
        const results = request.result as CommandHistoryEntry[];
        const filtered = results
          .filter((entry) => entry.command.toLowerCase().includes(query.toLowerCase()))
          .sort((a, b) => b.timestamp - a.timestamp)
          .slice(0, limit);
        resolve(filtered);
      };
      request.onerror = () => reject(new Error('Failed to search commands'));
    });
  }

  /**
   * Save session data
   */
  async saveSessionData(data: SessionData): Promise<void> {
    await this.init();
    if (!this.db) throw new Error('Database not initialized');

    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction([STORES.SESSION_DATA], 'readwrite');
      const store = transaction.objectStore(STORES.SESSION_DATA);
      const request = store.put(data);

      request.onsuccess = () => resolve();
      request.onerror = () => reject(new Error('Failed to save session data'));
    });
  }

  /**
   * Get session data
   */
  async getSessionData(terminalId: string): Promise<SessionData | null> {
    await this.init();
    if (!this.db) throw new Error('Database not initialized');

    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction([STORES.SESSION_DATA], 'readonly');
      const store = transaction.objectStore(STORES.SESSION_DATA);
      const request = store.get(terminalId);

      request.onsuccess = () => resolve(request.result || null);
      request.onerror = () => reject(new Error('Failed to get session data'));
    });
  }

  /**
   * Clear history for a specific terminal
   */
  async clearTerminalHistory(terminalId: string): Promise<void> {
    await this.init();
    if (!this.db) throw new Error('Database not initialized');

    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction(
        [STORES.TERMINAL_HISTORY, STORES.COMMAND_HISTORY, STORES.SESSION_DATA],
        'readwrite'
      );

      // Clear terminal history
      const historyStore = transaction.objectStore(STORES.TERMINAL_HISTORY);
      const historyIndex = historyStore.index('terminalId');
      const historyRequest = historyIndex.openCursor(IDBKeyRange.only(terminalId));

      historyRequest.onsuccess = (event) => {
        const cursor = (event.target as IDBRequest).result;
        if (cursor) {
          cursor.delete();
          cursor.continue();
        }
      };

      // Clear command history
      const commandStore = transaction.objectStore(STORES.COMMAND_HISTORY);
      const commandIndex = commandStore.index('terminalId');
      const commandRequest = commandIndex.openCursor(IDBKeyRange.only(terminalId));

      commandRequest.onsuccess = (event) => {
        const cursor = (event.target as IDBRequest).result;
        if (cursor) {
          cursor.delete();
          cursor.continue();
        }
      };

      // Clear session data
      const sessionStore = transaction.objectStore(STORES.SESSION_DATA);
      sessionStore.delete(terminalId);

      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(new Error('Failed to clear terminal history'));
    });
  }

  /**
   * Clear all history (for privacy/cleanup)
   */
  async clearAllHistory(): Promise<void> {
    await this.init();
    if (!this.db) throw new Error('Database not initialized');

    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction(
        [STORES.TERMINAL_HISTORY, STORES.COMMAND_HISTORY, STORES.SESSION_DATA],
        'readwrite'
      );

      transaction.objectStore(STORES.TERMINAL_HISTORY).clear();
      transaction.objectStore(STORES.COMMAND_HISTORY).clear();
      transaction.objectStore(STORES.SESSION_DATA).clear();

      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(new Error('Failed to clear all history'));
    });
  }

  /**
   * Get storage usage statistics
   */
  async getStorageStats(): Promise<{
    historyCount: number;
    commandCount: number;
    sessionCount: number;
  }> {
    await this.init();
    if (!this.db) throw new Error('Database not initialized');

    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction(
        [STORES.TERMINAL_HISTORY, STORES.COMMAND_HISTORY, STORES.SESSION_DATA],
        'readonly'
      );

      let historyCount = 0;
      let commandCount = 0;
      let sessionCount = 0;

      transaction.objectStore(STORES.TERMINAL_HISTORY).count().onsuccess = (e) => {
        historyCount = (e.target as IDBRequest).result;
      };

      transaction.objectStore(STORES.COMMAND_HISTORY).count().onsuccess = (e) => {
        commandCount = (e.target as IDBRequest).result;
      };

      transaction.objectStore(STORES.SESSION_DATA).count().onsuccess = (e) => {
        sessionCount = (e.target as IDBRequest).result;
      };

      transaction.oncomplete = () => resolve({ historyCount, commandCount, sessionCount });
      transaction.onerror = () => reject(new Error('Failed to get storage stats'));
    });
  }

  /**
   * Close the database connection
   */
  close(): void {
    if (this.db) {
      this.db.close();
      this.db = null;
      this.initPromise = null;
    }
  }
}

// Export singleton instance
export const terminalHistoryDB = new TerminalHistoryDB();
