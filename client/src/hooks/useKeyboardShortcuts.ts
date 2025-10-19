import { useEffect, useCallback } from 'react';

export interface KeyboardShortcutHandlers {
  onNewTerminal?: () => void;
  onCloseTerminal?: () => void;
  onNextTerminal?: () => void;
  onPreviousTerminal?: () => void;
  onClearTerminal?: () => void;
  onToggleSettings?: () => void;
  onSearchHistory?: () => void;
}

/**
 * Hook to handle keyboard shortcuts for terminal management
 */
export function useKeyboardShortcuts(handlers: KeyboardShortcutHandlers) {
  const handleKeyDown = useCallback(
    (event: KeyboardEvent) => {
      // Check for shortcuts - using Ctrl (or Cmd on Mac) + Shift combinations
      const isMac = navigator.platform.toUpperCase().indexOf('MAC') >= 0;
      const modifier = isMac ? event.metaKey : event.ctrlKey;

      // Ctrl/Cmd + Shift + N: New Terminal
      if (modifier && event.shiftKey && event.key.toLowerCase() === 'n') {
        event.preventDefault();
        handlers.onNewTerminal?.();
        return;
      }

      // Ctrl/Cmd + Shift + W: Close Terminal
      if (modifier && event.shiftKey && event.key.toLowerCase() === 'w') {
        event.preventDefault();
        handlers.onCloseTerminal?.();
        return;
      }

      // Ctrl/Cmd + Tab: Next Terminal
      if (modifier && !event.shiftKey && event.key === 'Tab') {
        event.preventDefault();
        handlers.onNextTerminal?.();
        return;
      }

      // Ctrl/Cmd + Shift + Tab: Previous Terminal
      if (modifier && event.shiftKey && event.key === 'Tab') {
        event.preventDefault();
        handlers.onPreviousTerminal?.();
        return;
      }

      // Ctrl/Cmd + L: Clear Terminal (handled by terminal itself, but we can support it globally)
      if (modifier && !event.shiftKey && event.key.toLowerCase() === 'l') {
        event.preventDefault();
        handlers.onClearTerminal?.();
        return;
      }

      // Ctrl/Cmd + ,: Settings (common shortcut)
      if (modifier && !event.shiftKey && event.key === ',') {
        event.preventDefault();
        handlers.onToggleSettings?.();
        return;
      }

      // Ctrl/Cmd + Shift + F: Search History
      if (modifier && event.shiftKey && event.key.toLowerCase() === 'f') {
        event.preventDefault();
        handlers.onSearchHistory?.();
        return;
      }
    },
    [handlers]
  );

  useEffect(() => {
    window.addEventListener('keydown', handleKeyDown);
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, [handleKeyDown]);
}
