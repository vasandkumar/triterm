import React, { useEffect, useRef, useState, memo } from 'react';
import { Terminal as XTerm } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { WebLinksAddon } from '@xterm/addon-web-links';
import '@xterm/xterm/css/xterm.css';
import { X, Maximize2, Minimize2, MoreVertical, Edit3, Copy, Clipboard, ArrowDown, Lock, Unlock, Ban, Type } from 'lucide-react';
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
  initialBuffer,
}) {
  const terminalRef = useRef(null);
  const xtermRef = useRef(null);
  const fitAddonRef = useRef(null);
  const [isReady, setIsReady] = useState(false);
  const [title, setTitle] = useState('Terminal');
  const [renameDialogOpen, setRenameDialogOpen] = useState(false);
  const [newName, setNewName] = useState('');
  const commandBufferRef = useRef('');
  const hasWrittenBuffer = useRef(false);
  const { settings, colorScheme} = useSettings();
  const [contextMenu, setContextMenu] = useState({ visible: false, x: 0, y: 0 });
  const [isAtBottom, setIsAtBottom] = useState(true);
  const [showScrollButton, setShowScrollButton] = useState(false);
  const [scrollLocked, setScrollLocked] = useState(false);
  const [inputLocked, setInputLocked] = useState(false);

  // Send keepalive messages to prevent terminal timeout
  useEffect(() => {
    if (!socket || !terminalId) return;

    // Send keepalive every 5 minutes to prevent 6-hour timeout
    const keepaliveInterval = setInterval(() => {
      socket.emit('terminal-keepalive', { terminalId });
    }, 5 * 60 * 1000); // 5 minutes

    return () => clearInterval(keepaliveInterval);
  }, [socket, terminalId]);

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
      scrollOnUserInput: true, // Auto-scroll to bottom on user input
      smoothScrollDuration: 0, // Disable smooth scroll for instant feedback
    });

    // Add addons
    const fitAddon = new FitAddon();
    const webLinksAddon = new WebLinksAddon();

    xterm.loadAddon(fitAddon);
    xterm.loadAddon(webLinksAddon);

    // Custom key event handler to intercept Ctrl+Shift+V before XTerm processes it
    xterm.attachCustomKeyEventHandler((event) => {
      // Debug: Log Ctrl key combinations
      if (event.ctrlKey || event.metaKey) {
        console.log('XTerm key event:', {
          key: event.key,
          ctrl: event.ctrlKey,
          shift: event.shiftKey,
          alt: event.altKey,
          meta: event.metaKey,
        });
      }

      // Intercept Ctrl+Shift+C for copy
      if ((event.ctrlKey || event.metaKey) && event.shiftKey && event.key === 'C') {
        console.log('XTerm - Intercepted Ctrl+Shift+C');
        event.preventDefault();
        const selection = xterm.getSelection();
        if (selection) {
          if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(selection).then(() => {
              console.log('Copy - Successfully copied:', selection.substring(0, 50));
            }).catch(err => {
              console.error('Copy failed:', err);
              // Fallback
              const textArea = document.createElement('textarea');
              textArea.value = selection;
              textArea.style.position = 'fixed';
              textArea.style.left = '-999999px';
              document.body.appendChild(textArea);
              textArea.select();
              document.execCommand('copy');
              document.body.removeChild(textArea);
              console.log('Copy - Used fallback method');
            });
          } else {
            // Fallback method
            const textArea = document.createElement('textarea');
            textArea.value = selection;
            textArea.style.position = 'fixed';
            textArea.style.left = '-999999px';
            document.body.appendChild(textArea);
            textArea.select();
            document.execCommand('copy');
            document.body.removeChild(textArea);
            console.log('Copy - Used fallback method (API not available)');
          }
        }
        return false; // Don't let XTerm handle it
      }

      // Intercept Ctrl+Shift+V for paste
      if ((event.ctrlKey || event.metaKey) && event.shiftKey && event.key === 'V') {
        console.log('XTerm - Intercepted Ctrl+Shift+V');
        event.preventDefault();

        // Block paste if input is locked
        if (inputLocked) {
          console.log('Paste - Blocked (input is locked)');
          return false;
        }

        // Try to read from clipboard
        if (navigator.clipboard && navigator.clipboard.readText) {
          navigator.clipboard.readText().then(text => {
            if (text && socket && terminalId) {
              console.log('Paste - Sending via Clipboard API:', text.substring(0, 50));
              socket.emit('terminal-input', {
                terminalId,
                input: text,
              });
            }
          }).catch(err => {
            console.error('Paste - Clipboard API failed:', err);
            console.log('Paste - Use Shift+Insert instead, or grant clipboard permissions');
          });
        } else {
          console.log('Paste - Clipboard API not available on HTTP');
          console.log('Paste - Please use Shift+Insert to paste');
        }

        return false; // Don't let XTerm handle it
      }

      // Let XTerm handle all other keys (including Ctrl+C)
      if ((event.ctrlKey || event.metaKey) && !event.shiftKey && event.key === 'c') {
        console.log('XTerm - Detected Ctrl+C, passing to XTerm for handling');
      }
      return true;
    });

    // Open terminal in DOM
    xterm.open(terminalRef.current);

    xtermRef.current = xterm;
    fitAddonRef.current = fitAddon;

    // Helper function to check if terminal is scrolled to bottom
    const checkIfAtBottom = () => {
      if (!xtermRef.current) return true;
      const term = xtermRef.current;

      // The scrollbar position relative to the base (scrollback)
      const baseY = term.buffer.active.baseY;
      // Current viewport Y position
      const viewportY = term.buffer.active.viewportY;

      // We're at the bottom when viewportY equals baseY
      // Allow 1 line tolerance for rounding/timing issues
      const isBottom = Math.abs(viewportY - baseY) <= 1;

      return isBottom;
    };

    // Scroll event handler
    const handleScroll = () => {
      const atBottom = checkIfAtBottom();
      console.log('Scroll event - atBottom:', atBottom, 'viewport:', xtermRef.current?.buffer.active.viewportY, 'baseY:', xtermRef.current?.buffer.active.baseY);
      setIsAtBottom(atBottom);
      setShowScrollButton(!atBottom);
    };

    // Listen for scroll events
    xterm.onScroll(() => {
      handleScroll();
    });

    // Fit terminal to container after a short delay to ensure DOM is ready
    setTimeout(() => {
      try {
        if (fitAddonRef.current && terminalRef.current && xtermRef.current) {
          fitAddon.fit();

          // Write initial buffer if provided (for reconnection)
          if (initialBuffer && !hasWrittenBuffer.current) {
            console.log('Writing initial buffer for terminal:', terminalId, 'size:', initialBuffer.length);
            xtermRef.current.write(initialBuffer);
            hasWrittenBuffer.current = true;
          }

          // Scroll to bottom after initial fit and buffer write
          xtermRef.current.scrollToBottom();
        }
      } catch (error) {
        console.error('Error fitting terminal on init:', error);
      }
    }, 0);

    // Handle terminal input
    xterm.onData((data) => {
      // Block input if locked
      if (inputLocked) {
        console.log('XTerm onData - Input blocked (terminal is locked)');
        return;
      }

      // Debug: Log control characters
      if (data === '\x03') {
        console.log('XTerm onData - Received Ctrl+C (\\x03)');
      }

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
        // Only auto-scroll if user is already at the bottom and scroll is not locked
        if (checkIfAtBottom() && !scrollLocked) {
          xtermRef.current.scrollToBottom();
        }
      }
    };

    const handleExit = ({ terminalId: id }) => {
      if (id === terminalId && xtermRef.current) {
        xtermRef.current.write('\r\n\x1b[1;31mTerminal session ended\x1b[0m\r\n');
        xtermRef.current.scrollToBottom();
        // Optionally auto-close after a delay
        setTimeout(() => {
          onClose?.();
        }, 2000);
      }
    };

    const handleError = ({ terminalId: id, error }) => {
      if (id === terminalId && xtermRef.current) {
        xtermRef.current.write(`\r\n\x1b[1;31mError: ${error}\x1b[0m\r\n`);
        xtermRef.current.scrollToBottom();
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
    scrollLocked,
    inputLocked,
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

            // Only scroll to bottom after resize if user was already at bottom and scroll is not locked
            // This helps maintain scroll position when resizing while scrolled up
            if (isAtBottom && !scrollLocked) {
              xtermRef.current.scrollToBottom();
            }
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

  // Context menu handlers
  const handleContextMenu = (e) => {
    e.preventDefault();
    setContextMenu({
      visible: true,
      x: e.clientX,
      y: e.clientY,
    });
  };

  const handleCopy = async () => {
    if (xtermRef.current) {
      const selection = xtermRef.current.getSelection();
      console.log('Copy - Selected text:', selection);
      if (selection) {
        // Check if Clipboard API is available
        if (navigator.clipboard && navigator.clipboard.writeText) {
          try {
            await navigator.clipboard.writeText(selection);
            console.log('Copy - Successfully copied to clipboard using Clipboard API');
          } catch (err) {
            console.error('Copy - Clipboard API failed:', err);
            // Try fallback
            copyFallback(selection);
          }
        } else {
          // Clipboard API not available (HTTP, not HTTPS), use fallback
          console.log('Copy - Clipboard API not available, using fallback method');
          copyFallback(selection);
        }
      } else {
        console.log('Copy - No text selected');
      }
    }
    setContextMenu({ visible: false, x: 0, y: 0 });
  };

  const copyFallback = (text) => {
    try {
      const textArea = document.createElement('textarea');
      textArea.value = text;
      textArea.style.position = 'fixed';
      textArea.style.left = '-999999px';
      textArea.style.top = '-999999px';
      document.body.appendChild(textArea);
      textArea.focus();
      textArea.select();
      const successful = document.execCommand('copy');
      document.body.removeChild(textArea);
      if (successful) {
        console.log('Copy - Successfully copied using execCommand fallback');
      } else {
        console.error('Copy - execCommand returned false');
      }
    } catch (fallbackErr) {
      console.error('Copy - Fallback also failed:', fallbackErr);
    }
  };

  const handlePaste = () => {
    console.log('Paste - Right-click paste triggered, simulating Shift+Insert');
    setContextMenu({ visible: false, x: 0, y: 0 });

    if (!xtermRef.current || !terminalRef.current) {
      console.log('Paste - Terminal not ready');
      return;
    }

    // Block paste if input is locked
    if (inputLocked) {
      console.log('Paste - Blocked (input is locked)');
      return;
    }

    // Focus the terminal first
    xtermRef.current.focus();

    // Create and dispatch a Shift+Insert KeyboardEvent
    const keydownEvent = new KeyboardEvent('keydown', {
      key: 'Insert',
      code: 'Insert',
      keyCode: 45,
      which: 45,
      shiftKey: true,
      ctrlKey: false,
      altKey: false,
      metaKey: false,
      bubbles: true,
      cancelable: true,
    });

    const keypressEvent = new KeyboardEvent('keypress', {
      key: 'Insert',
      code: 'Insert',
      keyCode: 45,
      which: 45,
      shiftKey: true,
      ctrlKey: false,
      altKey: false,
      metaKey: false,
      bubbles: true,
      cancelable: true,
    });

    const keyupEvent = new KeyboardEvent('keyup', {
      key: 'Insert',
      code: 'Insert',
      keyCode: 45,
      which: 45,
      shiftKey: true,
      ctrlKey: false,
      altKey: false,
      metaKey: false,
      bubbles: true,
      cancelable: true,
    });

    console.log('Paste - Dispatching Shift+Insert events to terminal');

    // Dispatch to the terminal element
    const terminalElement = terminalRef.current;
    terminalElement.dispatchEvent(keydownEvent);
    terminalElement.dispatchEvent(keypressEvent);
    terminalElement.dispatchEvent(keyupEvent);

    console.log('Paste - Shift+Insert events dispatched');
  };

  const handleSelectAll = () => {
    if (xtermRef.current) {
      xtermRef.current.selectAll();
    }
    setContextMenu({ visible: false, x: 0, y: 0 });
  };

  const handleScrollToBottom = () => {
    console.log('Scroll to bottom button clicked');
    if (xtermRef.current) {
      xtermRef.current.scrollToBottom();
      // Note: The xterm.onScroll event will fire after scrollToBottom()
      // and will automatically update isAtBottom and showScrollButton states
      // But we set them here too for immediate UI feedback
      setIsAtBottom(true);
      setShowScrollButton(false);
      console.log('After scroll to bottom - viewportY:', xtermRef.current.buffer.active.viewportY, 'baseY:', xtermRef.current.buffer.active.baseY);
    }
  };

  const handleToggleScrollLock = () => {
    setScrollLocked(!scrollLocked);
    console.log('Scroll lock toggled:', !scrollLocked);
  };

  const handleToggleInputLock = () => {
    setInputLocked(!inputLocked);
    console.log('Input lock toggled:', !inputLocked);
  };

  // Close context menu when clicking outside
  useEffect(() => {
    const handleClickOutside = () => {
      if (contextMenu.visible) {
        setContextMenu({ visible: false, x: 0, y: 0 });
      }
    };

    if (contextMenu.visible) {
      document.addEventListener('click', handleClickOutside);
      return () => document.removeEventListener('click', handleClickOutside);
    }
  }, [contextMenu.visible]);

  // Paste event handler - only handle paste, let XTerm handle all keyboard shortcuts
  useEffect(() => {
    if (!terminalRef.current || !xtermRef.current) return;

    const handlePasteEvent = async (e) => {
      console.log('Paste event fired!');
      e.preventDefault();
      e.stopPropagation();

      // Block paste if input is locked
      if (inputLocked) {
        console.log('Paste event - Blocked (input is locked)');
        return;
      }

      // Get text from clipboard data
      let text = '';

      if (e.clipboardData && e.clipboardData.getData) {
        text = e.clipboardData.getData('text/plain');
        console.log('Paste - Got text from clipboardData:', text?.substring(0, 50));
      }

      // Send to terminal if we have text
      if (text && socket && terminalId) {
        console.log('Paste - Sending to terminal:', text.length, 'characters');
        socket.emit('terminal-input', {
          terminalId,
          input: text,
        });
        console.log('Paste - Successfully sent to terminal');
      } else {
        console.log('Paste - No text or missing socket/terminalId');
      }
    };

    const terminalElement = terminalRef.current;
    terminalElement.addEventListener('paste', handlePasteEvent, true);

    return () => {
      terminalElement.removeEventListener('paste', handlePasteEvent, true);
    };
  }, [terminalRef.current, xtermRef.current, socket, terminalId, inputLocked]);

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
                <Button
                  variant="ghost"
                  size="icon"
                  className={`h-7 w-7 ${inputLocked ? 'text-destructive bg-destructive/10' : ''}`}
                  onClick={handleToggleInputLock}
                  aria-label={inputLocked ? 'Unlock input (enable keyboard input)' : 'Lock input (disable keyboard input)'}
                >
                  {inputLocked ? (
                    <Ban className="h-4 w-4" aria-hidden="true" />
                  ) : (
                    <Type className="h-4 w-4" aria-hidden="true" />
                  )}
                </Button>
              </TooltipTrigger>
              <TooltipContent className="z-50">{inputLocked ? 'Unlock Input' : 'Lock Input'}</TooltipContent>
            </Tooltip>

            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon"
                  className={`h-7 w-7 ${scrollLocked ? 'text-primary bg-primary/10' : ''}`}
                  onClick={handleToggleScrollLock}
                  aria-label={scrollLocked ? 'Unlock scroll (enable auto-scroll)' : 'Lock scroll (disable auto-scroll)'}
                >
                  {scrollLocked ? (
                    <Lock className="h-4 w-4" aria-hidden="true" />
                  ) : (
                    <Unlock className="h-4 w-4" aria-hidden="true" />
                  )}
                </Button>
              </TooltipTrigger>
              <TooltipContent className="z-50">{scrollLocked ? 'Unlock Scroll' : 'Lock Scroll'}</TooltipContent>
            </Tooltip>

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
              <TooltipContent className="z-50">{isMaximized ? 'Restore' : 'Maximize'}</TooltipContent>
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
              <TooltipContent className="z-50">Close Terminal</TooltipContent>
            </Tooltip>
          </TooltipProvider>
        </div>
      </div>

      {/* Terminal Content */}
      <div className="flex-1 relative overflow-hidden" style={{ minHeight: 0 }}>
        <div
          ref={terminalRef}
          className="w-full h-full overflow-hidden"
          role="region"
          aria-label="Terminal output"
          onContextMenu={handleContextMenu}
          tabIndex={0}
        />

        {/* Input Locked Overlay */}
        {inputLocked && (
          <div className="absolute inset-0 bg-destructive/5 pointer-events-none flex items-center justify-center">
            <div className="bg-destructive/90 text-destructive-foreground px-4 py-2 rounded-lg shadow-lg flex items-center gap-2">
              <Ban className="h-5 w-5" />
              <span className="text-sm font-medium">Input Locked</span>
            </div>
          </div>
        )}

        {/* Scroll to Bottom Button */}
        {showScrollButton && (
          <div className="absolute bottom-4 right-4 z-10">
            <TooltipProvider delayDuration={300}>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="default"
                    size="icon"
                    className="h-10 w-10 rounded-full shadow-lg"
                    onClick={handleScrollToBottom}
                    aria-label="Scroll to bottom"
                  >
                    <ArrowDown className="h-5 w-5" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent className="z-50">Scroll to bottom</TooltipContent>
              </Tooltip>
            </TooltipProvider>
          </div>
        )}
      </div>

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

      {/* Custom Context Menu */}
      {contextMenu.visible && (
        <div
          className="fixed z-50 min-w-[220px] bg-popover text-popover-foreground border rounded-md shadow-md"
          style={{
            left: `${contextMenu.x}px`,
            top: `${contextMenu.y}px`,
          }}
          onClick={(e) => e.stopPropagation()}
        >
          <div className="p-1">
            <button
              className="w-full flex items-center justify-between px-2 py-1.5 text-sm rounded-sm hover:bg-accent hover:text-accent-foreground cursor-pointer outline-none"
              onClick={handleCopy}
            >
              <div className="flex items-center gap-2">
                <Copy className="h-4 w-4" />
                Copy
              </div>
              <span className="text-xs text-muted-foreground">Ctrl+Shift+C</span>
            </button>
            <button
              className="w-full flex items-center gap-2 px-2 py-1.5 text-sm rounded-sm hover:bg-accent hover:text-accent-foreground cursor-pointer outline-none"
              onClick={handlePaste}
            >
              <Clipboard className="h-4 w-4" />
              Paste
            </button>
            <div className="h-px bg-border my-1" />
            <button
              className="w-full flex items-center gap-2 px-2 py-1.5 text-sm rounded-sm hover:bg-accent hover:text-accent-foreground cursor-pointer outline-none"
              onClick={handleSelectAll}
            >
              Select All
            </button>
            <button
              className="w-full flex items-center gap-2 px-2 py-1.5 text-sm rounded-sm hover:bg-accent hover:text-accent-foreground cursor-pointer outline-none"
              onClick={handleClear}
            >
              Clear Terminal
            </button>
          </div>
        </div>
      )}
    </div>
  );
});
