import React, { useEffect, useRef, useState, memo } from 'react';
import { Terminal as XTerm } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { WebLinksAddon } from '@xterm/addon-web-links';
import '@xterm/xterm/css/xterm.css';
import { X, Maximize2, Minimize2, MoreVertical, Edit3 } from 'lucide-react';
import { Button } from './ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from './ui/dropdown-menu';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from './ui/dialog';
import { Input } from './ui/input';
import { Label } from './ui/label';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from './ui/tooltip';
import { cn } from '../lib/utils';
import { useSettings } from '../contexts/SettingsContext';

export const Terminal = memo(function Terminal({
  terminalId,
  socket,
  onClose,
  onMaximize,
  onRename,
  onCommand,
  isMaximized = false,
  className,
}) {
  const terminalRef = useRef(null);
  const xtermRef = useRef(null);
  const fitAddonRef = useRef(null);
  const [isReady, setIsReady] = useState(false);
  const [title, setTitle] = useState('Terminal');
  const [renameDialogOpen, setRenameDialogOpen] = useState(false);
  const [newName, setNewName] = useState('');
  const commandBufferRef = useRef('');
  const { settings, colorScheme} = useSettings();

  useEffect(() => {
    if (!terminalRef.current || !socket || !terminalId) return;

    // Create xterm instance with settings
    const xterm = new XTerm({
      cursorBlink: true,
      fontSize: settings.fontSize,
      fontFamily: `"${settings.fontFamily}", "Courier New", monospace`,
      theme: colorScheme,
      allowProposedApi: true,
      scrollback: settings.scrollback,
      tabStopWidth: 4,
    });

    // Add addons
    const fitAddon = new FitAddon();
    const webLinksAddon = new WebLinksAddon();

    xterm.loadAddon(fitAddon);
    xterm.loadAddon(webLinksAddon);

    // Open terminal in DOM
    xterm.open(terminalRef.current);

    xtermRef.current = xterm;
    fitAddonRef.current = fitAddon;

    // Fit terminal to container after a short delay to ensure DOM is ready
    setTimeout(() => {
      try {
        if (fitAddonRef.current && terminalRef.current) {
          fitAddon.fit();
        }
      } catch (error) {
        console.error('Error fitting terminal on init:', error);
      }
    }, 0);

    // Handle terminal input
    xterm.onData((data) => {
      socket.emit('terminal-input', {
        terminalId,
        input: data,
      });

      // Track commands for history
      if (onCommand) {
        // Check if Enter was pressed (carriage return)
        if (data === '\r' || data === '\n') {
          const command = commandBufferRef.current.trim();
          if (command) {
            onCommand(command);
          }
          commandBufferRef.current = '';
        } else if (data === '\x7f' || data === '\b') {
          // Backspace - remove last character
          commandBufferRef.current = commandBufferRef.current.slice(0, -1);
        } else if (data.charCodeAt(0) >= 32 && data.charCodeAt(0) < 127) {
          // Printable ASCII character
          commandBufferRef.current += data;
        } else if (data === '\x03') {
          // Ctrl+C - clear buffer
          commandBufferRef.current = '';
        }
      }
    });

    // Handle title changes
    xterm.onTitleChange((newTitle) => {
      setTitle(newTitle || 'Terminal');
    });

    // Listen for output from server
    const handleOutput = ({ terminalId: id, data }) => {
      if (id === terminalId && xtermRef.current) {
        xtermRef.current.write(data);
      }
    };

    const handleExit = ({ terminalId: id }) => {
      if (id === terminalId) {
        xterm.write('\r\n\x1b[1;31mTerminal session ended\x1b[0m\r\n');
        // Optionally auto-close after a delay
        setTimeout(() => {
          onClose?.();
        }, 2000);
      }
    };

    const handleError = ({ terminalId: id, error }) => {
      if (id === terminalId && xtermRef.current) {
        xtermRef.current.write(`\r\n\x1b[1;31mError: ${error}\x1b[0m\r\n`);
      }
    };

    socket.on('terminal-output', handleOutput);
    socket.on('terminal-exit', handleExit);
    socket.on('terminal-error', handleError);

    setIsReady(true);

    // Cleanup
    return () => {
      socket.off('terminal-output', handleOutput);
      socket.off('terminal-exit', handleExit);
      socket.off('terminal-error', handleError);

      if (xtermRef.current) {
        xtermRef.current.dispose();
      }
    };
  }, [
    terminalId,
    socket,
    settings.fontSize,
    settings.fontFamily,
    settings.scrollback,
    colorScheme,
  ]);

  // Handle resize
  useEffect(() => {
    if (!isReady || !fitAddonRef.current || !socket) return;

    const handleResize = () => {
      if (fitAddonRef.current && xtermRef.current && terminalRef.current) {
        try {
          // Check if container has dimensions before fitting
          const container = terminalRef.current;
          if (container.offsetWidth > 0 && container.offsetHeight > 0) {
            fitAddonRef.current.fit();

            const { cols, rows } = xtermRef.current;
            socket.emit('terminal-resize', {
              terminalId,
              cols,
              rows,
            });
          }
        } catch (error) {
          console.error('Error resizing terminal:', error);
        }
      }
    };

    // Initial resize
    handleResize();

    // Use ResizeObserver for better resize detection
    const resizeObserver = new ResizeObserver(() => {
      handleResize();
    });

    if (terminalRef.current) {
      resizeObserver.observe(terminalRef.current);
    }

    return () => {
      resizeObserver.disconnect();
    };
  }, [isReady, socket, terminalId]);

  const handleClear = () => {
    if (xtermRef.current) {
      xtermRef.current.clear();
    }
  };

  const handleReset = () => {
    if (xtermRef.current) {
      xtermRef.current.reset();
    }
  };

  const handleRenameClick = () => {
    setNewName('');
    setRenameDialogOpen(true);
  };

  const handleRenameSubmit = () => {
    if (newName.trim() && onRename) {
      onRename(newName.trim());
      setRenameDialogOpen(false);
      setNewName('');
    }
  };

  return (
    <div
      className={cn(
        'flex flex-col h-full bg-background border rounded-lg overflow-hidden',
        className
      )}
    >
      {/* Terminal Header */}
      <div className="flex items-center justify-between px-3 py-2 bg-muted/50 border-b terminal-drag-handle cursor-move" role="toolbar" aria-label="Terminal controls">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-muted-foreground" aria-label="Terminal title">{title}</span>
        </div>

        <div className="flex items-center gap-1">
          <TooltipProvider delayDuration={300}>
            <Tooltip>
              <TooltipTrigger asChild>
                <Button variant="ghost" size="icon" className="h-7 w-7" onClick={onMaximize} aria-label={isMaximized ? 'Restore terminal' : 'Maximize terminal'}>
                  {isMaximized ? (
                    <Minimize2 className="h-4 w-4" aria-hidden="true" />
                  ) : (
                    <Maximize2 className="h-4 w-4" aria-hidden="true" />
                  )}
                </Button>
              </TooltipTrigger>
              <TooltipContent>{isMaximized ? 'Restore' : 'Maximize'}</TooltipContent>
            </Tooltip>

            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="icon" className="h-7 w-7" aria-label="More options">
                  <MoreVertical className="h-4 w-4" aria-hidden="true" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem onClick={handleRenameClick}>
                  <Edit3 className="h-4 w-4 mr-2" aria-hidden="true" />
                  Rename Terminal
                </DropdownMenuItem>
                <DropdownMenuItem onClick={handleClear}>Clear Terminal</DropdownMenuItem>
                <DropdownMenuItem onClick={handleReset}>Reset Terminal</DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>

            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-7 w-7 hover:bg-destructive/10 hover:text-destructive"
                  onClick={onClose}
                  aria-label="Close terminal"
                >
                  <X className="h-4 w-4" aria-hidden="true" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>Close Terminal</TooltipContent>
            </Tooltip>
          </TooltipProvider>
        </div>
      </div>

      {/* Terminal Content */}
      <div ref={terminalRef} className="flex-1 p-2 overflow-hidden" style={{ minHeight: 0 }} role="region" aria-label="Terminal output" />

      {/* Rename Dialog */}
      <Dialog open={renameDialogOpen} onOpenChange={setRenameDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Rename Terminal</DialogTitle>
            <DialogDescription>
              Enter a custom name for this terminal. Leave empty to use the default name.
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 py-4">
            <div className="grid gap-2">
              <Label htmlFor="terminal-name">Terminal Name</Label>
              <Input
                id="terminal-name"
                placeholder="e.g., Frontend Server, Build Tasks..."
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    handleRenameSubmit();
                  }
                }}
                autoFocus
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRenameDialogOpen(false)}>
              Cancel
            </Button>
            <Button onClick={handleRenameSubmit} disabled={!newName.trim()}>
              Rename
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
});
