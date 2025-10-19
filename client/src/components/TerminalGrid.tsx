import React, { useState, useCallback, useEffect } from 'react';
import { Terminal } from './Terminal';
import { Separator } from './ui/separator';
import { cn } from '../lib/utils';

export function TerminalGrid({ terminals, socket, onCloseTerminal }) {
  const [layout, setLayout] = useState('single'); // 'single', 'horizontal', 'vertical', 'grid'
  const [maximizedTerminal, setMaximizedTerminal] = useState(null);
  const [splitRatio, setSplitRatio] = useState(50); // For 2-terminal layouts
  const [isDragging, setIsDragging] = useState(false);

  // Determine best layout based on terminal count
  useEffect(() => {
    if (maximizedTerminal) {
      return; // Don't change layout when maximized
    }

    const count = terminals.length;
    if (count === 1) {
      setLayout('single');
    } else if (count === 2) {
      setLayout('horizontal');
    } else if (count === 3 || count === 4) {
      setLayout('grid');
    } else {
      setLayout('grid');
    }
  }, [terminals.length, maximizedTerminal]);

  const handleMaximize = useCallback((terminalId) => {
    setMaximizedTerminal((current) => (current === terminalId ? null : terminalId));
  }, []);

  const handleMouseDown = useCallback((e) => {
    e.preventDefault();
    setIsDragging(true);
  }, []);

  const handleMouseMove = useCallback(
    (e) => {
      if (!isDragging) return;

      const container = e.currentTarget;
      const rect = container.getBoundingClientRect();

      if (layout === 'horizontal') {
        const newRatio = ((e.clientX - rect.left) / rect.width) * 100;
        setSplitRatio(Math.max(20, Math.min(80, newRatio)));
      } else if (layout === 'vertical') {
        const newRatio = ((e.clientY - rect.top) / rect.height) * 100;
        setSplitRatio(Math.max(20, Math.min(80, newRatio)));
      }
    },
    [isDragging, layout]
  );

  const handleMouseUp = useCallback(() => {
    setIsDragging(false);
  }, []);

  useEffect(() => {
    if (isDragging) {
      document.addEventListener('mouseup', handleMouseUp);
      return () => document.removeEventListener('mouseup', handleMouseUp);
    }
  }, [isDragging, handleMouseUp]);

  if (terminals.length === 0) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-center">
          <p className="text-muted-foreground text-lg">No terminals open</p>
          <p className="text-muted-foreground text-sm mt-2">Click "New Terminal" to get started</p>
        </div>
      </div>
    );
  }

  // Maximized view
  if (maximizedTerminal) {
    const terminal = terminals.find((t) => t.id === maximizedTerminal);
    if (terminal) {
      return (
        <div className="h-full">
          <Terminal
            terminalId={terminal.id}
            socket={socket}
            onClose={() => onCloseTerminal(terminal.id)}
            onMaximize={() => handleMaximize(terminal.id)}
            isMaximized={true}
          />
        </div>
      );
    }
  }

  // Single terminal
  if (layout === 'single' && terminals.length === 1) {
    return (
      <div className="h-full">
        <Terminal
          terminalId={terminals[0].id}
          socket={socket}
          onClose={() => onCloseTerminal(terminals[0].id)}
          onMaximize={() => handleMaximize(terminals[0].id)}
        />
      </div>
    );
  }

  // Horizontal split (2 terminals side by side)
  if (layout === 'horizontal' && terminals.length === 2) {
    return (
      <div
        className="flex h-full"
        onMouseMove={handleMouseMove}
        style={{ cursor: isDragging ? 'col-resize' : 'default' }}
      >
        <div style={{ width: `${splitRatio}%` }} className="h-full">
          <Terminal
            terminalId={terminals[0].id}
            socket={socket}
            onClose={() => onCloseTerminal(terminals[0].id)}
            onMaximize={() => handleMaximize(terminals[0].id)}
          />
        </div>
        <div
          className="relative group"
          style={{ width: '4px', cursor: 'col-resize' }}
          onMouseDown={handleMouseDown}
        >
          <Separator
            orientation="vertical"
            className="absolute inset-0 group-hover:bg-primary/50 transition-colors"
          />
        </div>
        <div style={{ width: `${100 - splitRatio}%` }} className="h-full">
          <Terminal
            terminalId={terminals[1].id}
            socket={socket}
            onClose={() => onCloseTerminal(terminals[1].id)}
            onMaximize={() => handleMaximize(terminals[1].id)}
          />
        </div>
      </div>
    );
  }

  // Grid layout (2x2 or more)
  if (layout === 'grid') {
    const gridCols = terminals.length === 3 ? 2 : 2;
    const gridRows = Math.ceil(terminals.length / gridCols);

    return (
      <div
        className={cn(
          'grid h-full gap-2 p-2',
          terminals.length === 3 ? 'grid-cols-2 grid-rows-2' : `grid-cols-${gridCols}`
        )}
        style={{
          gridTemplateColumns: terminals.length === 3 ? '1fr 1fr' : `repeat(${gridCols}, 1fr)`,
          gridTemplateRows: terminals.length === 3 ? '1fr 1fr' : `repeat(${gridRows}, 1fr)`,
        }}
      >
        {terminals.map((terminal, index) => (
          <div
            key={terminal.id}
            className={cn('h-full', terminals.length === 3 && index === 0 && 'row-span-2')}
          >
            <Terminal
              terminalId={terminal.id}
              socket={socket}
              onClose={() => onCloseTerminal(terminal.id)}
              onMaximize={() => handleMaximize(terminal.id)}
            />
          </div>
        ))}
      </div>
    );
  }

  // Fallback: simple vertical stack
  return (
    <div className="flex flex-col h-full gap-2 p-2">
      {terminals.map((terminal) => (
        <div key={terminal.id} className="flex-1 min-h-0">
          <Terminal
            terminalId={terminal.id}
            socket={socket}
            onClose={() => onCloseTerminal(terminal.id)}
            onMaximize={() => handleMaximize(terminal.id)}
          />
        </div>
      ))}
    </div>
  );
}
