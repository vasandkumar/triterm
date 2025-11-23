import { useState, useEffect } from 'react';
import { Terminal } from './Terminal';
import type { Socket } from 'socket.io-client';

interface TerminalTab {
  id: string;
  name?: string;
  shell: string;
  createdAt: number;
  initialBuffer?: string;
}

interface ResizableTerminalLayoutProps {
  terminalIds: string[];
  terminals: TerminalTab[];
  socket: Socket;
  onClose: (terminalId: string) => void;
  onRename: (terminalId: string, newName: string) => void;
  onCommand: (command: string, terminalId?: string) => void;
  gridColumns?: number;
  customLayout?: string;
  layoutMode?: 'auto' | 'custom';
  terminalHeight?: number;
}

export function ResizableTerminalLayout({
  terminalIds,
  terminals,
  socket,
  onClose,
  onRename,
  onCommand,
  gridColumns = 2,
  customLayout = '2,3',
  layoutMode = 'auto',
  terminalHeight = 400,
}: ResizableTerminalLayoutProps) {
  const [maximizedTerminal, setMaximizedTerminal] = useState<string | null>(null);

  // Helper to get terminal data by ID
  const getTerminal = (terminalId: string) => {
    return terminals.find((t) => t.id === terminalId);
  };

  // Handle maximize/restore toggle
  const handleMaximize = (terminalId: string) => {
    setMaximizedTerminal((current) => (current === terminalId ? null : terminalId));
  };

  // Reset maximized terminal if it's no longer in the terminal list
  useEffect(() => {
    if (maximizedTerminal && !terminalIds.includes(maximizedTerminal)) {
      setMaximizedTerminal(null);
    }
  }, [terminalIds, maximizedTerminal]);

  if (terminalIds.length === 0) {
    return null;
  }

  // Maximized view - show only the maximized terminal
  if (maximizedTerminal) {
    const terminal = getTerminal(maximizedTerminal);
    if (terminal) {
      return (
        <div className="h-full w-full p-2">
          <Terminal
            terminalId={maximizedTerminal}
            socket={socket}
            onClose={() => onClose(maximizedTerminal)}
            onRename={(newName) => onRename(maximizedTerminal, newName)}
            onCommand={(cmd) => onCommand(cmd, maximizedTerminal)}
            onMaximize={() => handleMaximize(maximizedTerminal)}
            isMaximized={true}
            initialBuffer={terminal?.initialBuffer}
          />
        </div>
      );
    }
  }

  // For auto mode, use uniform grid with fixed heights
  if (layoutMode === 'auto') {
    return (
      <div className="h-full w-full overflow-auto p-2">
        <div
          className="grid gap-2"
          style={{
            display: 'grid',
            gridTemplateColumns: `repeat(${gridColumns}, minmax(0, 1fr))`,
            gridAutoRows: `${terminalHeight}px`, // Use customizable height for each row
          }}
        >
        {terminalIds.map((terminalId) => {
          const terminal = getTerminal(terminalId);
          return (
            <div
              key={terminalId}
              className="overflow-hidden border rounded-md bg-background"
              style={{
                minHeight: 0,
                minWidth: 0,
              }}
            >
              <Terminal
                terminalId={terminalId}
                socket={socket}
                onClose={() => onClose(terminalId)}
                onRename={(newName) => onRename(terminalId, newName)}
                onCommand={(cmd) => onCommand(cmd, terminalId)}
                onMaximize={() => handleMaximize(terminalId)}
                isMaximized={false}
                initialBuffer={terminal?.initialBuffer}
              />
            </div>
          );
        })}
        </div>
      </div>
    );
  }

  // For custom mode, parse the layout pattern
  const rowConfig = customLayout.split(',').map(n => parseInt(n.trim())).filter(n => !isNaN(n) && n > 0);
  if (rowConfig.length === 0) {
    rowConfig.push(2); // Default fallback
  }

  // Distribute terminals across rows based on custom configuration
  const rows: string[][] = [];
  let terminalIndex = 0;
  let rowConfigIndex = 0;

  while (terminalIndex < terminalIds.length) {
    const columnsInRow = rowConfig[rowConfigIndex % rowConfig.length];
    const row: string[] = [];

    for (let i = 0; i < columnsInRow && terminalIndex < terminalIds.length; i++) {
      row.push(terminalIds[terminalIndex]);
      terminalIndex++;
    }

    rows.push(row);
    rowConfigIndex++;
  }

  return (
    <div className="h-full w-full overflow-auto p-2">
      <div className="flex flex-col gap-2">
        {rows.map((row, rowIndex) => {
          const columnsInThisRow = row.length;

          return (
            <div
              key={`row-${rowIndex}`}
              className="flex gap-2"
              style={{
                height: `${terminalHeight}px`, // Use customizable height for each row
                minHeight: '300px',
              }}
            >
            {row.map((terminalId) => {
              const terminal = getTerminal(terminalId);
              const columnWidth = `${100 / columnsInThisRow}%`;

              return (
                <div
                  key={terminalId}
                  className="overflow-hidden border rounded-md bg-background"
                  style={{
                    width: columnWidth,
                    minHeight: 0,
                    minWidth: 0,
                  }}
                >
                  <Terminal
                    terminalId={terminalId}
                    socket={socket}
                    onClose={() => onClose(terminalId)}
                    onRename={(newName) => onRename(terminalId, newName)}
                    onCommand={(cmd) => onCommand(cmd, terminalId)}
                    onMaximize={() => handleMaximize(terminalId)}
                    isMaximized={false}
                    initialBuffer={terminal?.initialBuffer}
                  />
                </div>
              );
            })}
          </div>
        );
      })}
      </div>
    </div>
  );
}