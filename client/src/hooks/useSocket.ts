import { useEffect, useRef, useState } from 'react';
import { io, Socket } from 'socket.io-client';
import { getAccessToken } from '../lib/tokenStorage';

// Automatically determine the server URL
function getServerUrl(): string {
  // In development with Vite proxy, we can use the same origin
  // In production or network access, connect to port 3000 on the current host
  if (import.meta.env.DEV) {
    // Development mode - use Vite's proxy or construct URL
    const hostname = window.location.hostname;
    return `http://${hostname}:3000`;
  } else {
    // Production mode
    return window.location.origin;
  }
}

interface UseSocketReturn {
  socket: Socket | null;
  isConnected: boolean;
  error: string | null;
}

export function useSocket(url?: string): UseSocketReturn {
  const socketRef = useRef<Socket | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    // Only create socket once - don't recreate on every render
    if (socketRef.current) {
      return;
    }

    // Use provided URL or auto-detect
    const serverUrl = url || getServerUrl();

    // Get access token for authentication
    const token = getAccessToken();

    console.log('Creating socket connection to:', serverUrl);

    // Create socket connection with auth token
    socketRef.current = io(serverUrl, {
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 5000,
      reconnectionAttempts: Infinity,
      auth: {
        token, // Send token for server authentication
      },
    });

    const socket = socketRef.current;

    // Connection event handlers
    socket.on('connect', () => {
      console.log('Socket connected');
      setIsConnected(true);
      setError(null);
    });

    socket.on('disconnect', (reason: string) => {
      console.log('Socket disconnected:', reason);
      setIsConnected(false);

      // Provide user-friendly disconnect messages
      if (reason === 'io server disconnect') {
        setError('Server disconnected the session. Please refresh the page.');
      } else if (reason === 'transport close') {
        setError('Network connection lost. Reconnecting...');
      }
    });

    socket.on('connect_error', (err: Error) => {
      console.error('Socket connection error:', err);

      // Provide user-friendly error messages
      let userMessage = 'Unable to connect to server. ';

      if (err.message.includes('ECONNREFUSED')) {
        userMessage += 'The server is not running. Please start the server with "npm run dev:server".';
      } else if (err.message.includes('timeout')) {
        userMessage += 'Connection timed out. The server may be slow or unreachable.';
      } else if (err.message.includes('auth')) {
        userMessage += 'Authentication failed. Please log in again.';
      } else {
        userMessage += err.message;
      }

      setError(userMessage);
      setIsConnected(false);
    });

    socket.on('reconnect', (attemptNumber: number) => {
      console.log('Socket reconnected after', attemptNumber, 'attempts');
      setError(null);
    });

    socket.on('reconnect_attempt', (attemptNumber: number) => {
      console.log('Reconnection attempt', attemptNumber);
      setError(`Reconnecting... (attempt ${attemptNumber})`);
    });

    socket.on('reconnect_failed', () => {
      console.error('All reconnection attempts failed');
      setError('Failed to reconnect to server. Please refresh the page.');
    });

    // Cleanup
    return () => {
      console.log('Cleaning up socket connection');
      if (socketRef.current) {
        socketRef.current.disconnect();
        socketRef.current = null;
      }
    };
  }, []); // Only run once on mount

  return {
    socket: socketRef.current,
    isConnected,
    error,
  };
}
