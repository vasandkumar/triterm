import { useState, useEffect, useCallback } from 'react';

export interface CommandHistoryEntry {
  id: string;
  command: string;
  timestamp: number;
  terminalId?: string;
}

const HISTORY_STORAGE_KEY = 'triterm-command-history';
const MAX_HISTORY_ENTRIES = 1000;

/**
 * Hook to manage command history with localStorage persistence
 */
export function useCommandHistory() {
  const [history, setHistory] = useState<CommandHistoryEntry[]>(() => {
    try {
      const saved = localStorage.getItem(HISTORY_STORAGE_KEY);
      if (saved) {
        return JSON.parse(saved);
      }
    } catch (error) {
      console.error('Failed to load command history:', error);
    }
    return [];
  });

  // Save to localStorage whenever history changes
  useEffect(() => {
    try {
      localStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify(history));
    } catch (error) {
      console.error('Failed to save command history:', error);
    }
  }, [history]);

  // Add a command to history
  const addCommand = useCallback((command: string, terminalId?: string) => {
    // Only add non-empty commands
    const trimmed = command.trim();
    if (!trimmed) return;

    // Don't add if it's the same as the last command
    if (history.length > 0 && history[0].command === trimmed) return;

    const entry: CommandHistoryEntry = {
      id: `${Date.now()}-${Math.random()}`,
      command: trimmed,
      timestamp: Date.now(),
      terminalId,
    };

    setHistory((prev) => {
      const newHistory = [entry, ...prev];
      // Keep only the most recent MAX_HISTORY_ENTRIES
      return newHistory.slice(0, MAX_HISTORY_ENTRIES);
    });
  }, [history]);

  // Search command history
  const searchHistory = useCallback(
    (query: string): CommandHistoryEntry[] => {
      if (!query.trim()) {
        return history;
      }

      const lowerQuery = query.toLowerCase();
      return history.filter((entry) => entry.command.toLowerCase().includes(lowerQuery));
    },
    [history]
  );

  // Clear all history
  const clearHistory = useCallback(() => {
    setHistory([]);
    localStorage.removeItem(HISTORY_STORAGE_KEY);
  }, []);

  // Remove a specific entry
  const removeEntry = useCallback((id: string) => {
    setHistory((prev) => prev.filter((entry) => entry.id !== id));
  }, []);

  return {
    history,
    addCommand,
    searchHistory,
    clearHistory,
    removeEntry,
  };
}
