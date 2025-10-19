import { useState, useEffect, useMemo } from 'react';
import { Responsive, WidthProvider, Layout } from 'react-grid-layout';
import { Terminal } from './Terminal';
import type { Socket } from 'socket.io-client';
import 'react-grid-layout/css/styles.css';
import 'react-resizable/css/styles.css';

const ResponsiveGridLayout = WidthProvider(Responsive);

interface DraggableTerminalGridProps {
  terminalIds: string[];
  socket: Socket;
  onClose: (terminalId: string) => void;
  onRename: (terminalId: string, newName: string) => void;
  onCommand: (command: string, terminalId?: string) => void;
}

export function DraggableTerminalGrid({
  terminalIds,
  socket,
  onClose,
  onRename,
  onCommand,
}: DraggableTerminalGridProps) {
  // Generate optimal layout for terminals that divides screen space
  const generateLayout = (ids: string[]): Layout[] => {
    const count = ids.length;

    if (count === 0) return [];

    // Calculate optimal grid dimensions
    let cols, rows;
    if (count === 1) {
      cols = 1; rows = 1;
    } else if (count === 2) {
      cols = 2; rows = 1;
    } else if (count === 3) {
      cols = 3; rows = 1;
    } else if (count === 4) {
      cols = 2; rows = 2;
    } else if (count <= 6) {
      cols = 3; rows = 2;
    } else if (count <= 9) {
      cols = 3; rows = 3;
    } else {
      cols = 4; rows = Math.ceil(count / 4);
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
        {terminalIds.map((terminalId) => (
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
            />
          </div>
        ))}
      </ResponsiveGridLayout>
    </div>
  );
}
