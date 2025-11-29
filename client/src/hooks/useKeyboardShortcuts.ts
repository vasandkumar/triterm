import { useEffect, useCallback, useRef } from 'react';

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
 * Uses Ctrl+K prefix pattern (VSCode-style) to avoid browser conflicts
 */
export function useKeyboardShortcuts(handlers: KeyboardShortcutHandlers) {
  const waitingForSecondKey = useRef(false);
  const timeoutRef = useRef<number | null>(null);

  const handleKeyDown = useCallback(
    (event: KeyboardEvent) => {
      const isMac = navigator.platform.toUpperCase().indexOf('MAC') >= 0;
      const modifier = isMac ? event.metaKey : event.ctrlKey;

      // If we're waiting for the second key in the Ctrl+K sequence
      if (waitingForSecondKey.current) {
        const key = event.key.toLowerCase();

        // If user is still holding Ctrl/Cmd, ignore modifier combos to prevent browser shortcuts
        // Only accept plain keys (no Ctrl/Cmd) or arrow keys
        const hasModifier = event.ctrlKey || event.metaKey;
        const isArrowKey = key.startsWith('arrow');

        // For regular letter keys, require NO modifiers (user must release Ctrl)
        // For arrow keys, allow with or without modifiers
        if (!isArrowKey && hasModifier) {
          // User is still holding Ctrl - don't process yet, wait for them to release
          return;
        }

        // Stop all event handling - we're in command mode
        event.preventDefault();
        event.stopPropagation();
        event.stopImmediatePropagation();
        waitingForSecondKey.current = false;

        if (timeoutRef.current) {
          clearTimeout(timeoutRef.current);
          timeoutRef.current = null;
        }

        // Ctrl+K, N: New Terminal
        if (key === 'n') {
          handlers.onNewTerminal?.();
          return;
        }

        // Ctrl+K, W: Close Terminal
        if (key === 'w') {
          handlers.onCloseTerminal?.();
          return;
        }

        // Ctrl+K, ArrowRight or ]: Next Terminal
        if (key === 'arrowright' || key === ']') {
          handlers.onNextTerminal?.();
          return;
        }

        // Ctrl+K, ArrowLeft or [: Previous Terminal
        if (key === 'arrowleft' || key === '[') {
          handlers.onPreviousTerminal?.();
          return;
        }

        // Ctrl+K, K: Clear Terminal
        if (key === 'k') {
          handlers.onClearTerminal?.();
          return;
        }

        // Ctrl+K, S: Settings
        if (key === 's') {
          handlers.onToggleSettings?.();
          return;
        }

        // Ctrl+K, F: Search/Find History
        if (key === 'f') {
          handlers.onSearchHistory?.();
          return;
        }

        return;
      }

      // Check for Ctrl+K prefix
      if (modifier && !event.shiftKey && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        event.stopPropagation();
        waitingForSecondKey.current = true;

        // Set timeout to reset if no second key is pressed within 2 seconds
        timeoutRef.current = window.setTimeout(() => {
          waitingForSecondKey.current = false;
          timeoutRef.current = null;
        }, 2000);

        return;
      }
    },
    [handlers]
  );

  useEffect(() => {
    // Use capture phase to intercept before browser default actions
    window.addEventListener('keydown', handleKeyDown, true);
    return () => {
      window.removeEventListener('keydown', handleKeyDown, true);
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
      }
    };
  }, [handleKeyDown]);
}
