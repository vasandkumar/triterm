import { useEffect, useCallback, useState } from 'react';
import {
  terminalHistoryDB,
  TerminalHistoryEntry,
  CommandHistoryEntry,
  SessionData,
} from '../lib/terminalHistoryDB';

export function useTerminalHistory(terminalId: string) {
  const [isInitialized, setIsInitialized] = useState(false);

  useEffect(() => {
    terminalHistoryDB.init().then(() => setIsInitialized(true));
  }, []);

  const saveOutput = useCallback(
    async (output: string, type: 'stdout' | 'stderr' | 'input' = 'stdout') => {
      if (!isInitialized) return;

      try {
        await terminalHistoryDB.addTerminalOutput({
          terminalId,
          timestamp: Date.now(),
          output,
          type,
        });
      } catch (error) {
        console.error('Failed to save terminal output:', error);
      }
    },
    [terminalId, isInitialized]
  );

  const saveCommand = useCallback(
    async (command: string, cwd?: string) => {
      if (!isInitialized) return;

      try {
        await terminalHistoryDB.addCommand({
          terminalId,
          command,
          timestamp: Date.now(),
          cwd,
        });
      } catch (error) {
        console.error('Failed to save command:', error);
      }
    },
    [terminalId, isInitialized]
  );

  const getHistory = useCallback(
    async (limit?: number): Promise<TerminalHistoryEntry[]> => {
      if (!isInitialized) return [];

      try {
        return await terminalHistoryDB.getTerminalHistory(terminalId, limit);
      } catch (error) {
        console.error('Failed to get terminal history:', error);
        return [];
      }
    },
    [terminalId, isInitialized]
  );

  const getCommands = useCallback(
    async (limit?: number): Promise<CommandHistoryEntry[]> => {
      if (!isInitialized) return [];

      try {
        return await terminalHistoryDB.getCommandHistory(terminalId, limit);
      } catch (error) {
        console.error('Failed to get command history:', error);
        return [];
      }
    },
    [terminalId, isInitialized]
  );

  const saveSession = useCallback(
    async (data: Omit<SessionData, 'terminalId'>) => {
      if (!isInitialized) return;

      try {
        await terminalHistoryDB.saveSessionData({
          terminalId,
          ...data,
        });
      } catch (error) {
        console.error('Failed to save session data:', error);
      }
    },
    [terminalId, isInitialized]
  );

  const getSession = useCallback(async (): Promise<SessionData | null> => {
    if (!isInitialized) return null;

    try {
      return await terminalHistoryDB.getSessionData(terminalId);
    } catch (error) {
      console.error('Failed to get session data:', error);
      return null;
    }
  }, [terminalId, isInitialized]);

  const clearHistory = useCallback(async () => {
    if (!isInitialized) return;

    try {
      await terminalHistoryDB.clearTerminalHistory(terminalId);
    } catch (error) {
      console.error('Failed to clear history:', error);
    }
  }, [terminalId, isInitialized]);

  return {
    isInitialized,
    saveOutput,
    saveCommand,
    getHistory,
    getCommands,
    saveSession,
    getSession,
    clearHistory,
  };
}

/**
 * Hook for global history operations
 */
export function useGlobalTerminalHistory() {
  const [isInitialized, setIsInitialized] = useState(false);

  useEffect(() => {
    terminalHistoryDB.init().then(() => setIsInitialized(true));
  }, []);

  const searchCommands = useCallback(
    async (query: string, limit?: number): Promise<CommandHistoryEntry[]> => {
      if (!isInitialized) return [];

      try {
        return await terminalHistoryDB.searchCommands(query, limit);
      } catch (error) {
        console.error('Failed to search commands:', error);
        return [];
      }
    },
    [isInitialized]
  );

  const clearAllHistory = useCallback(async () => {
    if (!isInitialized) return;

    try {
      await terminalHistoryDB.clearAllHistory();
    } catch (error) {
      console.error('Failed to clear all history:', error);
    }
  }, [isInitialized]);

  const getStorageStats = useCallback(async () => {
    if (!isInitialized) return null;

    try {
      return await terminalHistoryDB.getStorageStats();
    } catch (error) {
      console.error('Failed to get storage stats:', error);
      return null;
    }
  }, [isInitialized]);

  return {
    isInitialized,
    searchCommands,
    clearAllHistory,
    getStorageStats,
  };
}
