/**
 * Socket.IO Manager
 *
 * Provides a singleton Socket.IO instance that can be accessed
 * from anywhere in the application (routes, services, etc.)
 */

import { Server } from 'socket.io';

let io: Server | null = null;

/**
 * Set the Socket.IO instance
 * Called once during server initialization
 */
export function setSocketIO(ioInstance: Server): void {
  io = ioInstance;
}

/**
 * Get the Socket.IO instance
 * Returns the initialized io instance or throws if not initialized
 */
export function getSocketIO(): Server {
  if (!io) {
    throw new Error('Socket.IO not initialized. Call setSocketIO first.');
  }
  return io;
}

/**
 * Emit event to a specific user
 * Emits to all sockets in the user's room
 */
export function emitToUser(userId: string, event: string, data: any): void {
  const socketIO = getSocketIO();
  socketIO.to(`user:${userId}`).emit(event, data);
}

/**
 * Emit event to a specific share link owner
 */
export function emitToShareLinkOwner(userId: string, event: string, data: any): void {
  emitToUser(userId, event, data);
}
