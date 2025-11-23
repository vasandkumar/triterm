/**
 * Shared Terminal Viewer Component
 *
 * Displays a terminal for external users accessing via share link
 * Supports VIEW and CONTROL permissions
 */

import { useEffect, useRef, useState } from 'react';
import { Terminal as XTerm } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { WebLinksAddon } from '@xterm/addon-web-links';
import { io, Socket } from 'socket.io-client';
import { AlertCircle, Eye, Edit3 } from 'lucide-react';
import '@xterm/xterm/css/xterm.css';

interface SharedTerminalViewerProps {
  shareCode: string;
}

export function SharedTerminalViewer({ shareCode }: SharedTerminalViewerProps) {
  const terminalRef = useRef<HTMLDivElement>(null);
  const xtermRef = useRef<XTerm | null>(null);
  const fitAddonRef = useRef<FitAddon | null>(null);
  const socketRef = useRef<Socket | null>(null);
  const permissionRef = useRef<'VIEW' | 'CONTROL'>('VIEW');

  const [error, setError] = useState<string | null>(null);
  const [permission, setPermission] = useState<'VIEW' | 'CONTROL'>('VIEW');
  const [loading, setLoading] = useState(true);
  const [connected, setConnected] = useState(false);
  const [terminalReady, setTerminalReady] = useState(false);

  // Initialize terminal first (runs once after mount)
  useEffect(() => {
    // Get connection details from sessionStorage
    const connectionId = sessionStorage.getItem('share_connection_id');
    const terminalId = sessionStorage.getItem('share_terminal_id');

    if (!connectionId || !terminalId) {
      setError('Invalid access. Please use the share link to request access.');
      setLoading(false);
      return;
    }

    // Wait for DOM to be ready
    const initTimer = setTimeout(() => {
      if (!terminalRef.current) {
        setError('Failed to initialize terminal container');
        setLoading(false);
        return;
      }

      // Initialize terminal
      const term = new XTerm({
      cursorBlink: true,
      fontSize: 14,
      fontFamily: 'Menlo, Monaco, "Courier New", monospace',
      theme: {
        background: '#1e1e1e',
        foreground: '#d4d4d4',
        cursor: '#ffffff',
        selectionBackground: '#264f78',
      },
      scrollback: 10000,
      allowProposedApi: true,
    });

    const fitAddon = new FitAddon();
    const webLinksAddon = new WebLinksAddon();

    term.loadAddon(fitAddon);
    term.loadAddon(webLinksAddon);

    xtermRef.current = term;
    fitAddonRef.current = fitAddon;

      term.open(terminalRef.current);

      // Force initial fit after a short delay
      setTimeout(() => {
        if (fitAddonRef.current) {
          fitAddonRef.current.fit();
        }
      }, 100);

      // Mark terminal as ready for socket connection
      setTerminalReady(true);
    }, 0); // No delay needed - React batches state updates

    return () => {
      clearTimeout(initTimer);
      // Clean up terminal on unmount
      if (xtermRef.current) {
        xtermRef.current.dispose();
        xtermRef.current = null;
      }
    };
  }, []); // Run once on mount

  // Connect to socket after terminal is ready
  useEffect(() => {
    if (!terminalReady || !xtermRef.current) {
      return;
    }

    const connectionId = sessionStorage.getItem('share_connection_id');
    const terminalId = sessionStorage.getItem('share_terminal_id');
    const term = xtermRef.current;

    // Initialize socket connection (no auth required for approved shared access)
    const socket = io({
      transports: ['websocket', 'polling'],
    });

    socketRef.current = socket;

    socket.on('connect', () => {
      // Connect to the shared terminal
      socket.emit('share:connect-terminal', { connectionId }, (response: any) => {
        if (response.success) {
          const userPermission = response.permission as 'VIEW' | 'CONTROL';
          setPermission(userPermission);
          permissionRef.current = userPermission;
          setConnected(true);
          setLoading(false);

          // Display welcome message
          term.writeln('\x1b[1;32mConnected to shared terminal\x1b[0m');
          term.writeln(`\x1b[1;33mPermission: ${response.permission}\x1b[0m`);

          if (response.permission === 'VIEW') {
            term.writeln('\x1b[1;31m[VIEW ONLY MODE - You cannot send commands]\x1b[0m');
          }

          term.writeln('');

          // Restore initial buffer if available
          if (response.buffer) {
            term.write(response.buffer);
          }
        } else {
          setError(response.error || 'Failed to connect to terminal');
          setLoading(false);
        }
      });
    });

    socket.on('connect_error', () => {
      setError('Failed to connect to server');
      setLoading(false);
    });

    // Listen for terminal output
    socket.on('terminal-output', (data: { terminalId: string; data: string }) => {
      if (data.terminalId === terminalId) {
        term.write(data.data);
      }
    });

    // Listen for terminal disconnection
    socket.on('terminal-closed', (data: { terminalId: string }) => {
      if (data.terminalId === terminalId) {
        term.writeln('\r\n\x1b[1;31m[Terminal closed by owner]\x1b[0m');
        setConnected(false);
      }
    });

    // Listen for being kicked
    socket.on('share:kicked', (data: { reason: string }) => {
      term.writeln('\r\n\x1b[1;31m[DISCONNECTED]\x1b[0m');
      term.writeln(`\x1b[1;31m${data.reason}\x1b[0m`);
      setConnected(false);
      setError(data.reason);
    });

    // Listen for share link deactivation
    socket.on('share:link-deactivated', (data: { reason: string }) => {
      term.writeln('\r\n\x1b[1;31m[SHARE LINK DEACTIVATED]\x1b[0m');
      term.writeln(`\x1b[1;31m${data.reason}\x1b[0m`);
      setConnected(false);
      setError(data.reason);
    });

    // Handle terminal input (only for CONTROL permission)
    term.onData((data) => {
      if (permissionRef.current === 'CONTROL' && socketRef.current?.connected) {
        socketRef.current.emit('terminal-input', { terminalId, data });
      }
    });

    // Handle terminal resize
    const handleResize = () => {
      if (fitAddonRef.current && xtermRef.current) {
        fitAddonRef.current.fit();
        const dims = fitAddonRef.current.proposeDimensions();
        if (dims && connected) {
          socket.emit('terminal-resize', {
            terminalId,
            cols: dims.cols,
            rows: dims.rows,
          });
        }
      }
    };

    window.addEventListener('resize', handleResize);

    // Initial resize after a short delay
    setTimeout(handleResize, 100);

    // Cleanup
    return () => {
      window.removeEventListener('resize', handleResize);
      if (socketRef.current) {
        socketRef.current.disconnect();
      }
    };
  }, [terminalReady]); // Run when terminal is ready

  if (error) {
    return (
      <div className="h-screen w-screen flex items-center justify-center bg-gray-900">
        <div className="text-center max-w-md p-8">
          <AlertCircle className="h-16 w-16 text-red-500 mx-auto mb-4" />
          <h1 className="text-2xl font-bold text-white mb-2">Connection Error</h1>
          <p className="text-gray-400">{error}</p>
          <button
            onClick={() => window.location.href = `/share/${shareCode}`}
            className="mt-6 px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
          >
            Back to Request Access
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="h-screen w-screen flex flex-col bg-gray-900 relative">
      {/* Header */}
      <div className="bg-gray-800 px-4 py-2 flex items-center justify-between border-b border-gray-700">
        <div className="flex items-center gap-2">
          <h1 className="text-white font-semibold">Shared Terminal</h1>
          <span className="text-gray-400 text-sm">({shareCode})</span>
        </div>
        <div className="flex items-center gap-2">
          {permission === 'VIEW' ? (
            <div className="flex items-center gap-1 text-yellow-500 text-sm">
              <Eye className="h-4 w-4" />
              <span>View Only</span>
            </div>
          ) : (
            <div className="flex items-center gap-1 text-green-500 text-sm">
              <Edit3 className="h-4 w-4" />
              <span>Control Enabled</span>
            </div>
          )}
        </div>
      </div>

      {/* Loading overlay */}
      {loading && (
        <div className="absolute inset-0 flex items-center justify-center bg-gray-900 bg-opacity-95 z-50">
          <div className="text-center">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4"></div>
            <p className="text-gray-400">Connecting to terminal...</p>
          </div>
        </div>
      )}

      {/* Terminal */}
      <div
        ref={terminalRef}
        className="flex-1 p-4 overflow-hidden"
        style={{
          height: 'calc(100vh - 60px)',
          minHeight: '400px',
          backgroundColor: '#1e1e1e',
        }}
      />
    </div>
  );
}
