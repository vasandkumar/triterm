import { useState, useEffect } from 'react';
import { Responsive, WidthProvider, Layout } from 'react-grid-layout';
import { Terminal } from './Terminal';
import type { Socket } from 'socket.io-client';
import 'react-grid-layout/css/styles.css';
import 'react-resizable/css/styles.css';

const ResponsiveGridLayout = WidthProvider(Responsive);

interface TerminalTab {
  id: string;
  name?: string;
  shell: string;
  createdAt: number;
  initialBuffer?: string;
}

interface DraggableTerminalGridProps {
  terminalIds: string[];
  terminals: TerminalTab[];
  socket: Socket;
  onClose: (terminalId: string) => void;
  onRename: (terminalId: string, newName: string) => void;
  onCommand: (command: string, terminalId?: string) => void;
}

export function DraggableTerminalGrid({
  terminalIds,
  terminals,
  socket,
  onClose,
  onRename,
  onCommand,
}: DraggableTerminalGridProps) {
  const [maximizedTerminal, setMaximizedTerminal] = useState<string | null>(null);

  // Helper to get terminal data by ID
  const getTerminal = (terminalId: string) => {
    return terminals.find((t) => t.id === terminalId);
  };

  // Handle maximize/restore toggle
  const handleMaximize = (terminalId: string) => {
    setMaximizedTerminal((current) => (current === terminalId ? null : terminalId));
  };

  // Generate optimal layout for terminals that divides screen space
  const generateLayout = (ids: string[]): Layout[] => {
    const count = ids.length;

    if (count === 0) return [];

    // Calculate optimal grid dimensions
    let cols;
    if (count === 1) {
      cols = 1;
    } else if (count === 2) {
      cols = 2;
    } else if (count === 3) {
      cols = 3;
    } else if (count === 4) {
      cols = 2;
    } else if (count <= 6) {
      cols = 3;
    } else if (count <= 9) {
      cols = 3;
    } else {
      cols = 4;
    }

    const cellWidth = 12 / cols; // 12-column grid
    const cellHeight = 10; // Fixed height per row

    return ids.map((id, index) => {
      const col = index % cols;
      const row = Math.floor(index / cols);

      return {
        i: id,
        x: col * cellWidth,
        y: row * cellHeight,
        w: cellWidth,
        h: cellHeight,
        minW: 3, // Minimum width
        minH: 4, // Minimum height
      };
    });
  };

  const [layout, setLayout] = useState<Layout[]>(() => generateLayout(terminalIds));

  // Reset maximized terminal if it's no longer in the terminal list
  useEffect(() => {
    if (maximizedTerminal && !terminalIds.includes(maximizedTerminal)) {
      setMaximizedTerminal(null);
    }
  }, [terminalIds, maximizedTerminal]);

  // Regenerate layout whenever terminals change to auto-divide screen
  useEffect(() => {
    setLayout(generateLayout(terminalIds));
  }, [terminalIds]);

  const handleLayoutChange = (newLayout: Layout[]) => {
    setLayout(newLayout);
  };

  if (terminalIds.length === 0) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-center">
          <p className="text-muted-foreground text-lg">No terminal selected</p>
          <p className="text-muted-foreground text-sm mt-2">
            Click on a tab to view it, or create a new terminal
          </p>
        </div>
      </div>
    );
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

  return (
    <div className="h-full w-full overflow-auto p-2">
      <ResponsiveGridLayout
        className="layout"
        layouts={{ lg: layout }}
        breakpoints={{ lg: 1200, md: 996, sm: 768, xs: 480, xxs: 0 }}
        cols={{ lg: 12, md: 10, sm: 6, xs: 4, xxs: 2 }}
        rowHeight={60}
        onLayoutChange={handleLayoutChange}
        draggableHandle=".terminal-drag-handle"
        compactType={null} // Disable auto-compacting so terminals stay where you put them
        preventCollision={false} // Allow overlapping if user wants
        margin={[8, 8]} // Add margin between terminals
        containerPadding={[0, 0]}
      >
        {terminalIds.map((terminalId) => {
          const terminal = getTerminal(terminalId);
          return (
            <div
              key={terminalId}
              className="border rounded-md overflow-hidden bg-background"
              style={{ touchAction: 'none' }}
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
      </ResponsiveGridLayout>
    </div>
  );
}
