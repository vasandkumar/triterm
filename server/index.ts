import express, { Request, Response } from 'express';
import { createServer } from 'http';
import { Server, Socket } from 'socket.io';
import * as pty from 'node-pty';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import os from 'os';
import expressWinston from 'express-winston';
import logger from './config/logger.js';
import authRoutes from './routes/auth.js';
import terminalRoutes from './routes/terminals.js';
import recordingsRoutes from './routes/recordings.js';
import adminRoutes from './routes/admin.js';
import { authenticateToken } from './middleware/auth.js';
import { verifyToken } from './lib/jwt.js';
import { prisma } from './lib/prisma.js';
import {
  createTerminalSession,
  updateSessionActivity,
  updateSessionDimensions,
  deactivateSession,
  deleteSession,
  cleanupOldSessions,
} from './lib/terminalSession.js';
import { initializeOAuthProviders } from './lib/oauthProviders.js';
import { setupCollaborationHandlers, setupPresenceCleanup } from './lib/collaborationHandlers.js';

dotenv.config();

// Initialize OAuth providers (Google, GitHub, Microsoft)
initializeOAuthProviders();

// TypeScript interfaces
interface TerminalSession {
  term: pty.IPty;
  socketId: string;
  userId?: string; // User ID from JWT authentication
  createdAt: number;
}

interface CreateTerminalData {
  cols?: number;
  rows?: number;
}

interface CreateTerminalCallback {
  success?: boolean;
  terminalId?: string;
  shell?: string;
  error?: string;
}

interface TerminalInputData {
  terminalId: string;
  input: string;
}

interface TerminalResizeData {
  terminalId: string;
  cols: number;
  rows: number;
}

interface CloseTerminalData {
  terminalId: string;
}

interface ClientToServerEvents {
  'create-terminal': (data: CreateTerminalData, callback: (response: CreateTerminalCallback) => void) => void;
  'terminal-input': (data: TerminalInputData) => void;
  'terminal-resize': (data: TerminalResizeData) => void;
  'close-terminal': (data: CloseTerminalData) => void;
}

interface ServerToClientEvents {
  'terminal-output': (data: { terminalId: string; data: string }) => void;
  'terminal-exit': (data: { terminalId: string; exitCode: number; signal?: number }) => void;
  'terminal-error': (data: { terminalId: string; error: string }) => void;
}

interface InterServerEvents {
  // Add any inter-server events here if needed
}

interface SocketData {
  user?: {
    userId: string;
    email: string;
    username: string;
  };
}

const app = express();
const httpServer = createServer(app);

// Security middleware
app.use(
  helmet({
    contentSecurityPolicy: false, // Allow for development
  })
);

// CORS configuration - allow network access in development
app.use(
  cors({
    origin: process.env.NODE_ENV === 'production' ? process.env.ALLOWED_ORIGINS?.split(',') : true, // Allow all origins in development
    credentials: true,
  })
);

// Rate limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW || '60000'),
  max: parseInt(process.env.RATE_LIMIT_MAX || '100'),
  message: 'Too many requests from this IP, please try again later.',
});

app.use(limiter);
app.use(express.json());

// HTTP request logging (before routes)
app.use(
  expressWinston.logger({
    winstonInstance: logger,
    meta: true,
    msg: 'HTTP {{req.method}} {{req.url}}',
    expressFormat: true,
    colorize: false,
    ignoreRoute: (req) => req.url === '/health', // Don't log health checks
  })
);

// Health check endpoint
app.get('/health', (_req: Request, res: Response) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Auth routes
app.use('/api/auth', authRoutes);

// Terminal sharing routes (protected with JWT authentication)
app.use('/api/terminals', authenticateToken, terminalRoutes);

// Recording routes (protected with JWT authentication)
app.use('/api/recordings', authenticateToken, recordingsRoutes);

// Admin routes (protected with JWT authentication and admin role)
app.use('/api/admin', authenticateToken, adminRoutes);

// Socket.io setup with security
const io = new Server<ClientToServerEvents, ServerToClientEvents, InterServerEvents, SocketData>(httpServer, {
  cors: {
    origin: process.env.NODE_ENV === 'production' ? process.env.ALLOWED_ORIGINS?.split(',') : true, // Allow all origins in development for network access
    credentials: true,
  },
  // Security: limit payload size
  maxHttpBufferSize: 1e6, // 1MB
  // Ping timeout
  pingTimeout: 60000,
  pingInterval: 25000,
});

// Store terminal sessions
const terminals = new Map<string, TerminalSession>();
const terminalCounts = new Map<string, number>();

// Maximum terminals per connection
const MAX_TERMINALS = parseInt(process.env.MAX_TERMINALS || '10');

// Authentication middleware for Socket.io
io.use((socket, next) => {
  const requireAuth = process.env.REQUIRE_AUTH === 'true';
  const token = socket.handshake.auth.token;

  // If token is provided, always try to authenticate (even if not required)
  if (token) {
    try {
      // Verify JWT token
      const payload = verifyToken(token);

      // Attach user info to socket
      socket.data.user = payload;

      logger.debug('Socket.io authentication successful', {
        socketId: socket.id,
        userId: payload.userId,
        username: payload.username
      });

      next();
    } catch (error) {
      logger.warn('Socket.io authentication failed', {
        socketId: socket.id,
        error: error instanceof Error ? error.message : 'Unknown error'
      });

      // If auth is required, reject the connection
      if (requireAuth) {
        return next(new Error('Authentication failed: Invalid or expired token'));
      }

      // If auth is optional, allow connection without user data
      next();
    }
  } else {
    // No token provided
    if (requireAuth) {
      return next(new Error('Authentication token required'));
    }

    // Authentication not required, continue without user data
    next();
  }
});

// Input sanitization: remove dangerous characters
function sanitizeInput(input: unknown): string {
  if (typeof input !== 'string') return '';

  // This is basic sanitization - in production, you may want more sophisticated filtering
  // We allow most characters for terminal use but remove null bytes
  return input.replace(/\0/g, '');
}

// Determine shell based on OS
function getShell(): string {
  if (os.platform() === 'win32') {
    return 'powershell.exe';
  }
  return process.env.SHELL || '/bin/bash';
}

// Verify terminal ownership
function verifyTerminalOwnership(
  terminal: TerminalSession | undefined,
  socket: Socket<ClientToServerEvents, ServerToClientEvents, InterServerEvents, SocketData>
): boolean {
  if (!terminal) {
    return false;
  }

  // Check socket ownership
  if (terminal.socketId !== socket.id) {
    return false;
  }

  // If authentication is required, also verify user ownership
  const requireAuth = process.env.REQUIRE_AUTH === 'true';
  if (requireAuth && socket.data.user) {
    if (terminal.userId !== socket.data.user.userId) {
      return false;
    }
  }

  return true;
}

io.on('connection', (socket: Socket<ClientToServerEvents, ServerToClientEvents, InterServerEvents, SocketData>) => {
  logger.info('Client connected', { socketId: socket.id });

  // Initialize terminal count for this connection
  terminalCounts.set(socket.id, 0);

  // Setup collaboration event handlers
  const userId = socket.data.user?.userId;
  setupCollaborationHandlers(io, socket, userId);

  // Create new terminal
  socket.on('create-terminal', (data, callback) => {
    try {
      const currentCount = terminalCounts.get(socket.id) || 0;

      // Check terminal limit
      if (currentCount >= MAX_TERMINALS) {
        callback({
          error: `Maximum terminal limit reached (${MAX_TERMINALS})`,
        });
        return;
      }

      const terminalId = `${socket.id}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

      // Spawn terminal
      const shell = getShell();
      const term = pty.spawn(shell, [], {
        name: 'xterm-256color',
        cols: data.cols || 80,
        rows: data.rows || 24,
        cwd: process.env.HOME || process.cwd(),
        env: process.env,
      });

      // Store terminal instance with user ownership
      terminals.set(terminalId, {
        term,
        socketId: socket.id,
        userId: socket.data.user?.userId, // Associate terminal with authenticated user
        createdAt: Date.now(),
      });

      // Update terminal count
      terminalCounts.set(socket.id, currentCount + 1);

      // Persist terminal session to database if user is authenticated
      if (socket.data.user?.userId) {
        createTerminalSession({
          terminalId,
          userId: socket.data.user.userId,
          shell,
          cwd: process.env.HOME || process.cwd(),
          cols: data.cols || 80,
          rows: data.rows || 24,
          socketId: socket.id,
        }).catch((error) => {
          logger.error('Failed to persist terminal session', { error, terminalId });
        });
      }

      // Handle terminal output
      term.onData((data) => {
        socket.emit('terminal-output', { terminalId, data });
      });

      // Handle terminal exit
      term.onExit(({ exitCode, signal }) => {
        logger.info('Terminal exited', { terminalId, exitCode, signal, socketId: socket.id });
        socket.emit('terminal-exit', { terminalId, exitCode, signal });

        // Cleanup
        terminals.delete(terminalId);
        const count = terminalCounts.get(socket.id) || 0;
        terminalCounts.set(socket.id, Math.max(0, count - 1));
      });

      logger.info('Terminal created', { terminalId, socketId: socket.id, shell });

      callback({
        success: true,
        terminalId,
        shell,
      });
    } catch (error) {
      logger.error('Error creating terminal', { error, socketId: socket.id });
      callback({ error: error instanceof Error ? error.message : 'Unknown error' });
    }
  });

  // Send input to terminal
  socket.on('terminal-input', (data) => {
    try {
      const { terminalId, input } = data;

      if (!terminalId || !input) {
        return;
      }

      const terminal = terminals.get(terminalId);

      if (!terminal) {
        socket.emit('terminal-error', {
          terminalId,
          error: 'Terminal not found',
        });
        return;
      }

      // Verify terminal ownership (socket + user)
      if (!verifyTerminalOwnership(terminal, socket)) {
        socket.emit('terminal-error', {
          terminalId,
          error: 'Unauthorized access to terminal',
        });
        logger.warn('Unauthorized terminal access attempt', {
          terminalId,
          socketId: socket.id,
          userId: socket.data.user?.userId,
          terminalUserId: terminal.userId,
        });
        return;
      }

      // Sanitize and write input
      const sanitizedInput = sanitizeInput(input);
      terminal.term.write(sanitizedInput);

      // Update session activity
      updateSessionActivity(terminalId).catch(() => {
        // Silently fail - session might not be persisted
      });
    } catch (error) {
      logger.error('Error handling terminal input', { error, terminalId: data.terminalId, socketId: socket.id });
      socket.emit('terminal-error', {
        terminalId: data.terminalId,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  // Resize terminal
  socket.on('terminal-resize', (data) => {
    try {
      const { terminalId, cols, rows } = data;

      if (!terminalId || !cols || !rows) {
        return;
      }

      const terminal = terminals.get(terminalId);

      if (!terminal) {
        return;
      }

      // Verify terminal ownership (socket + user)
      if (!verifyTerminalOwnership(terminal, socket)) {
        logger.warn('Unauthorized terminal resize attempt', {
          terminalId,
          socketId: socket.id,
          userId: socket.data.user?.userId,
          terminalUserId: terminal.userId,
        });
        return;
      }

      // Validate dimensions
      const validCols = Math.max(1, Math.min(1000, parseInt(String(cols))));
      const validRows = Math.max(1, Math.min(1000, parseInt(String(rows))));

      terminal.term.resize(validCols, validRows);

      // Update session dimensions
      updateSessionDimensions(terminalId, validCols, validRows).catch(() => {
        // Silently fail - session might not be persisted
      });
    } catch (error) {
      logger.error('Error resizing terminal', { error, terminalId: data.terminalId, socketId: socket.id });
    }
  });

  // Close terminal
  socket.on('close-terminal', (data) => {
    try {
      const { terminalId } = data;

      if (!terminalId) {
        return;
      }

      const terminal = terminals.get(terminalId);

      if (!terminal) {
        return;
      }

      // Verify terminal ownership (socket + user)
      if (!verifyTerminalOwnership(terminal, socket)) {
        logger.warn('Unauthorized terminal close attempt', {
          terminalId,
          socketId: socket.id,
          userId: socket.data.user?.userId,
          terminalUserId: terminal.userId,
        });
        return;
      }

      logger.info('Closing terminal', { terminalId, socketId: socket.id, userId: terminal.userId });
      terminal.term.kill();
      terminals.delete(terminalId);

      const count = terminalCounts.get(socket.id) || 0;
      terminalCounts.set(socket.id, Math.max(0, count - 1));

      // Deactivate session in database
      deactivateSession(terminalId).catch(() => {
        // Silently fail - session might not be persisted
      });
    } catch (error) {
      logger.error('Error closing terminal', { error, terminalId: data.terminalId, socketId: socket.id });
    }
  });

  // Handle disconnect
  socket.on('disconnect', () => {
    const userId = socket.data.user?.userId;
    logger.info('Client disconnected', { socketId: socket.id, userId });

    // Clean up all terminals for this socket and user
    for (const [terminalId, terminal] of terminals.entries()) {
      if (terminal.socketId === socket.id) {
        logger.info('Cleaning up terminal', {
          terminalId,
          socketId: socket.id,
          userId: terminal.userId,
        });
        try {
          terminal.term.kill();
        } catch (error) {
          logger.error('Error killing terminal', {
            error,
            terminalId,
            socketId: socket.id,
            userId: terminal.userId,
          });
        }
        terminals.delete(terminalId);
      }
    }

    terminalCounts.delete(socket.id);
  });
});

const PORT = parseInt(process.env.PORT || '3000');
const HOST = process.env.HOST || '0.0.0.0';

// Get local network IP
function getNetworkAddress(): string {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    const ifaceList = interfaces[name];
    if (!ifaceList) continue;

    for (const iface of ifaceList) {
      // Skip internal and non-IPv4 addresses
      if (!iface.internal && iface.family === 'IPv4') {
        return iface.address;
      }
    }
  }
  return 'localhost';
}

httpServer.listen(PORT, HOST, () => {
  const networkAddress = getNetworkAddress();
  const portStr = PORT.toString();

  logger.info('TriTerm Server Started', {
    port: PORT,
    host: HOST,
    environment: process.env.NODE_ENV || 'development',
    maxTerminals: MAX_TERMINALS,
    authRequired: process.env.REQUIRE_AUTH === 'true',
    localUrl: `http://localhost:${portStr}`,
    networkUrl: `http://${networkAddress}:${portStr}`,
  });

  // Pretty console output for development
  if (process.env.NODE_ENV !== 'production') {
    console.log(`
╔═══════════════════════════════════════════════╗
║         TriTerm Server Running                ║
╠═══════════════════════════════════════════════╣
║  Port: ${portStr.padEnd(38)} ║
║  Environment: ${(process.env.NODE_ENV || 'development').padEnd(30)} ║
║  Max Terminals: ${MAX_TERMINALS.toString().padEnd(28)} ║
║  Auth Required: ${(process.env.REQUIRE_AUTH === 'true' ? 'Yes' : 'No').padEnd(28)} ║
╠═══════════════════════════════════════════════╣
║  Local:   http://localhost:${portStr.padEnd(23)} ║
║  Network: http://${networkAddress}:${portStr.padEnd(23)} ║
╚═══════════════════════════════════════════════╝
  `);
  }
});

// Schedule cleanup of old/inactive sessions
const CLEANUP_INTERVAL = 60 * 60 * 1000; // 1 hour
const INACTIVE_HOURS = 24; // Delete sessions inactive for 24 hours

// Run cleanup immediately on startup
cleanupOldSessions(INACTIVE_HOURS).catch((error) => {
  logger.error('Error during initial session cleanup', { error });
});

// Schedule periodic cleanup
const cleanupIntervalId = setInterval(() => {
  cleanupOldSessions(INACTIVE_HOURS).catch((error) => {
    logger.error('Error during scheduled session cleanup', { error });
  });
}, CLEANUP_INTERVAL);

// Setup presence tracking cleanup
setupPresenceCleanup(io);

logger.info('Session cleanup scheduler started', {
  intervalMinutes: CLEANUP_INTERVAL / 60000,
  inactiveHours: INACTIVE_HOURS,
});

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received, closing server');

  // Stop cleanup scheduler
  clearInterval(cleanupIntervalId);

  // Close all terminals
  for (const [terminalId, terminal] of terminals.entries()) {
    try {
      terminal.term.kill();
      logger.info('Killed terminal during shutdown', {
        terminalId,
        userId: terminal.userId,
      });
    } catch (error) {
      logger.error('Error killing terminal during shutdown', {
        error,
        terminalId,
        userId: terminal.userId,
      });
    }
  }

  httpServer.close(() => {
    logger.info('Server closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  logger.info('SIGINT received, closing server');
  process.exit(0);
});
