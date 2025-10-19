import { useState, useEffect, useCallback } from 'react';
import { Socket } from 'socket.io-client';

interface CollaboratorPresence {
  userId: string;
  username: string;
  permission: 'VIEW' | 'CONTROL';
  connectedAt?: number;
  lastActivity?: number;
}

interface CollaborationState {
  collaborators: CollaboratorPresence[];
  myPermission: 'VIEW' | 'CONTROL' | null;
  isJoined: boolean;
}

interface CursorPosition {
  userId: string;
  username: string;
  position: { line: number; column: number };
  timestamp: number;
}

interface InputUpdate {
  userId: string;
  username: string;
  input: string;
  cursorPosition?: { line: number; column: number };
  timestamp: number;
}

export function useCollaboration(
  socket: Socket | null,
  terminalId: string | null,
  userId?: string,
  username?: string
) {
  const [state, setState] = useState<CollaborationState>({
    collaborators: [],
    myPermission: null,
    isJoined: false,
  });

  const [cursors, setCursors] = useState<Map<string, CursorPosition>>(new Map());
  const [recentInputs, setRecentInputs] = useState<Map<string, InputUpdate>>(new Map());

  /**
   * Join a collaboration session
   */
  const joinSession = useCallback(
    (permission?: 'VIEW' | 'CONTROL') => {
      if (!socket || !terminalId || !userId || !username) return;

      socket.emit(
        'collaboration:join',
        {
          terminalId,
          userId,
          username,
        },
        (response: any) => {
          if (response.success) {
            setState({
              collaborators: response.users || [],
              myPermission: response.permission || permission || 'VIEW',
              isJoined: true,
            });
          }
        }
      );
    },
    [socket, terminalId, userId, username]
  );

  /**
   * Leave a collaboration session
   */
  const leaveSession = useCallback(() => {
    if (!socket || !terminalId) return;

    socket.emit('collaboration:leave', { terminalId }, (response: any) => {
      if (response.success) {
        setState({
          collaborators: [],
          myPermission: null,
          isJoined: false,
        });
        setCursors(new Map());
        setRecentInputs(new Map());
      }
    });
  }, [socket, terminalId]);

  /**
   * Broadcast input to other collaborators
   */
  const broadcastInput = useCallback(
    (input: string, cursorPosition?: { line: number; column: number }) => {
      if (!socket || !terminalId || !userId || !username) return;

      socket.emit('collaboration:input', {
        terminalId,
        userId,
        username,
        input,
        cursorPosition,
      });
    },
    [socket, terminalId, userId, username]
  );

  /**
   * Broadcast cursor position
   */
  const broadcastCursor = useCallback(
    (position: { line: number; column: number }) => {
      if (!socket || !terminalId || !userId || !username) return;

      socket.emit('collaboration:cursor', {
        terminalId,
        userId,
        username,
        position,
      });
    },
    [socket, terminalId, userId, username]
  );

  /**
   * Request control permission
   */
  const requestControl = useCallback(() => {
    if (!socket || !terminalId) return Promise.reject('Not connected');

    return new Promise<boolean>((resolve) => {
      socket.emit('collaboration:request-control', { terminalId }, (response: any) => {
        if (response.success && response.permission === 'CONTROL') {
          setState((prev) => ({ ...prev, myPermission: 'CONTROL' }));
          resolve(true);
        } else {
          resolve(false);
        }
      });
    });
  }, [socket, terminalId]);

  /**
   * Send heartbeat to prevent timeout
   */
  const sendHeartbeat = useCallback(() => {
    if (!socket || !terminalId || !state.isJoined) return;

    socket.emit('collaboration:heartbeat', { terminalId });
  }, [socket, terminalId, state.isJoined]);

  // Setup event listeners
  useEffect(() => {
    if (!socket || !terminalId) return;

    // Handle presence updates
    const handlePresenceUpdate = (data: {
      terminalId: string;
      users: CollaboratorPresence[];
    }) => {
      if (data.terminalId === terminalId) {
        setState((prev) => ({
          ...prev,
          collaborators: data.users,
        }));
      }
    };

    // Handle incoming input from other users
    const handleInputReceived = (data: InputUpdate) => {
      setRecentInputs((prev) => {
        const updated = new Map(prev);
        updated.set(data.userId, data);

        // Clear after 2 seconds
        setTimeout(() => {
          setRecentInputs((current) => {
            const copy = new Map(current);
            copy.delete(data.userId);
            return copy;
          });
        }, 2000);

        return updated;
      });
    };

    // Handle cursor position updates
    const handleCursorUpdate = (data: CursorPosition) => {
      setCursors((prev) => {
        const updated = new Map(prev);
        updated.set(data.userId, data);
        return updated;
      });
    };

    socket.on('presence-update', handlePresenceUpdate);
    socket.on('collaboration:input-received', handleInputReceived);
    socket.on('collaboration:cursor-update', handleCursorUpdate);

    // Heartbeat interval (every 30 seconds)
    const heartbeatInterval = setInterval(sendHeartbeat, 30000);

    return () => {
      socket.off('presence-update', handlePresenceUpdate);
      socket.off('collaboration:input-received', handleInputReceived);
      socket.off('collaboration:cursor-update', handleCursorUpdate);
      clearInterval(heartbeatInterval);
    };
  }, [socket, terminalId, sendHeartbeat]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (state.isJoined) {
        leaveSession();
      }
    };
  }, [state.isJoined, leaveSession]);

  return {
    ...state,
    cursors: Array.from(cursors.values()),
    recentInputs: Array.from(recentInputs.values()),
    joinSession,
    leaveSession,
    broadcastInput,
    broadcastCursor,
    requestControl,
  };
}
