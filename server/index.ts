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
import shareRoutes from './routes/share.js';
import { authenticateToken } from './middleware/auth.js';
import { verifyToken } from './lib/jwt.js';
import { prisma } from './lib/prisma.js';
import { cookieParser, csrfCookieMiddleware, csrfProtection } from './middleware/csrf.js';
import {
  createTerminalSession,
  updateSessionActivity,
  updateSessionDimensions,
  deactivateSession,
  deleteSession,
  cleanupOldSessions,
  getUserActiveSessions,
  getSession,
} from './lib/terminalSession.js';
import { initializeOAuthProviders } from './lib/oauthProviders.js';
import { setupCollaborationHandlers, setupPresenceCleanup } from './lib/collaborationHandlers.js';
import { userTerminalRegistry } from './lib/userTerminalRegistry.js';
import { inputQueueManager } from './lib/inputQueue.js';
import { setSocketIO } from './lib/socketManager.js';
import { socketRateLimiter, SOCKET_RATE_LIMITS } from './middleware/rateLimiter.js';
import { connectRedis, disconnectRedis, isRedisHealthy } from './lib/redis.js';

dotenv.config();

// Initialize OAuth providers (Google, GitHub, Microsoft)
initializeOAuthProviders();

// TypeScript interfaces
interface TerminalSession {
  term: pty.IPty;
  socketId: string; // DEPRECATED: Primary socket for backward compatibility
  userId?: string; // User ID from JWT authentication
  sessionId?: string; // Database session ID for persistence
  createdAt: number;
  outputBuffer: string[]; // Store recent output for session recovery
  lastActivityAt: number;
  shareUserSockets: string[]; // External share users' socket IDs
  connectedSockets: Set<string>; // All connected sockets (multi-device support)
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

interface ReconnectTerminalData {
  terminalId: string;
}

interface ReconnectTerminalCallback {
  success?: boolean;
  terminalId?: string;
  buffer?: string;
  error?: string;
}

interface ListTerminalsCallback {
  success?: boolean;
  terminals?: Array<{
    terminalId: string;
    shell: string;
    createdAt: number;
    lastActivityAt: number;
    deviceCount: number;
    devices: Array<{
      deviceId?: string;
      deviceName?: string;
      connectedAt: Date;
    }>;
    isConnectedOnThisDevice: boolean;
  }>;
  error?: string;
}

interface ClientToServerEvents {
  'create-terminal': (data: CreateTerminalData, callback: (response: CreateTerminalCallback) => void) => void;
  'reconnect-terminal': (data: ReconnectTerminalData, callback: (response: ReconnectTerminalCallback) => void) => void;
  'terminal-input': (data: TerminalInputData) => void;
  'terminal-resize': (data: TerminalResizeData) => void;
  'close-terminal': (data: CloseTerminalData) => void;
  'terminal-keepalive': (data: { terminalId: string }) => void;
  'list-terminals': (callback: (response: ListTerminalsCallback) => void) => void;
}

interface ServerToClientEvents {
  'terminal-output': (data: { terminalId: string; data: string }) => void;
  'terminal-exit': (data: { terminalId: string; exitCode: number; signal?: number }) => void;
  'terminal-error': (data: { terminalId: string; error: string }) => void;
  'terminal-device-connected': (data: {
    terminalId: string;
    deviceId?: string;
    deviceName?: string;
    deviceCount: number;
    devices: Array<{ deviceId?: string; deviceName?: string }>;
  }) => void;
  'terminal-device-disconnected': (data: {
    terminalId: string;
    deviceId?: string;
    deviceName?: string;
    deviceCount: number;
    devices: Array<{ deviceId?: string; deviceName?: string }>;
  }) => void;
  'terminal-input-received': (data: {
    terminalId: string;
    input: string;
    sequenceNumber: number;
    fromSocketId: string;
  }) => void;
  'terminal-input-ack': (data: {
    terminalId: string;
    inputId: string;
    sequenceNumber: number;
    success: boolean;
    error?: string;
  }) => void;
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
  device?: {
    deviceId?: string;
    deviceName?: string;
  };
}

const app = express();
const httpServer = createServer(app);

// Configure trust proxy - only trust proxy in production
app.set('trust proxy', process.env.NODE_ENV === 'production' ? 1 : false);

// Security middleware - Enhanced helmet configuration
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", process.env.NODE_ENV === 'development' ? "'unsafe-inline'" : "'none'"],
        styleSrc: ["'self'", "'unsafe-inline'"], // unsafe-inline for CSS-in-JS libraries
        imgSrc: ["'self'", 'data:', 'https:'],
        connectSrc: ["'self'", 'ws:', 'wss:'],
        fontSrc: ["'self'", 'data:'],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"],
        frameSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
        upgradeInsecureRequests: process.env.NODE_ENV === 'production' ? [] : null,
      },
    },
    hsts: {
      maxAge: 31536000, // 1 year
      includeSubDomains: true,
      preload: true,
    },
    frameguard: {
      action: 'deny', // Prevent clickjacking
    },
    xssFilter: true,
    noSniff: true, // Prevent MIME-type sniffing
    referrerPolicy: {
      policy: 'strict-origin-when-cross-origin', // Better privacy
    },
    // Disable dangerous features
    permittedCrossDomainPolicies: {
      permittedPolicies: 'none',
    },
    dnsPrefetchControl: {
      allow: false,
    },
  })
);

// Additional security headers
app.use((req, res, next) => {
  // Permissions Policy - Restrict browser features
  res.setHeader(
    'Permissions-Policy',
    'geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()'
  );

  // X-Content-Type-Options (redundant with helmet but explicit)
  res.setHeader('X-Content-Type-Options', 'nosniff');

  // X-Download-Options for IE
  res.setHeader('X-Download-Options', 'noopen');

  // X-Permitted-Cross-Domain-Policies
  res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');

  next();
});

// CORS configuration - whitelist allowed origins from environment
app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (like mobile apps or curl)
      if (!origin) return callback(null, true);

      const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',').map(o => o.trim()) || [];

      if (allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        logger.warn('CORS blocked request', { origin, allowedOrigins });
        callback(new Error('Not allowed by CORS'));
      }
    },
    credentials: true,
  })
);

// Rate limiting (disabled in development for convenience)
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW || '60000'),
  max: parseInt(process.env.RATE_LIMIT_MAX || '100'),
  message: 'Too many requests from this IP, please try again later.',
  skip: () => process.env.NODE_ENV !== 'production', // Skip rate limiting in development
});

app.use(limiter);

// Request size limits - Prevent DoS attacks
app.use(express.json({
  limit: '1mb', // Maximum request body size
  strict: true, // Only accept arrays and objects
}));
app.use(express.urlencoded({
  extended: true,
  limit: '1mb',
  parameterLimit: 100, // Maximum number of parameters
}));

app.use(cookieParser());
app.use(csrfCookieMiddleware);

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

// Auth routes (with CSRF protection)
app.use('/api/auth', csrfProtection, authRoutes);

// Terminal sharing routes (protected with JWT authentication and CSRF)
app.use('/api/terminals', authenticateToken, csrfProtection, terminalRoutes);

// Recording routes (protected with JWT authentication and CSRF)
app.use('/api/recordings', authenticateToken, csrfProtection, recordingsRoutes);

// Admin routes (protected with JWT authentication, admin role, and CSRF)
app.use('/api/admin', authenticateToken, csrfProtection, adminRoutes);

// Share routes (mixed: some public endpoints for joining, some protected for managing)
app.use('/api/share', csrfProtection, shareRoutes);

// Socket.io setup with security
const io = new Server<ClientToServerEvents, ServerToClientEvents, InterServerEvents, SocketData>(httpServer, {
  cors: {
    origin: process.env.NODE_ENV === 'production' ? process.env.ALLOWED_ORIGINS?.split(',') : true, // Allow all origins in development for network access
    credentials: true,
  },
  // Security: limit payload size
  maxHttpBufferSize: 1e6, // 1MB
  // Ping timeout - increased to prevent disconnections on slow networks
  pingTimeout: 120000, // 2 minutes (increased from 1 minute)
  pingInterval: 30000, // 30 seconds
});

// Make Socket.IO instance available globally for routes and services
setSocketIO(io);

// Store terminal sessions
const terminals = new Map<string, TerminalSession>();
const terminalCounts = new Map<string, number>();

// Maximum terminals per connection
const MAX_TERMINALS = parseInt(process.env.MAX_TERMINALS || '10');

// Maximum buffer size (keep last 1000 lines of output)
const MAX_BUFFER_LINES = 1000;

// Session timeout (kill terminals after 6 hours of inactivity)
// Increased from 1 hour to prevent premature disconnections
const SESSION_TIMEOUT_MS = 6 * 60 * 60 * 1000; // 6 hours

// Authentication middleware for Socket.io
io.use((socket, next) => {
  const requireAuth = process.env.REQUIRE_AUTH === 'true';
  const deviceId = socket.handshake.auth.deviceId;
  const deviceName = socket.handshake.auth.deviceName;

  // Store device information
  socket.data.device = {
    deviceId,
    deviceName,
  };

  // Try to get token from multiple sources:
  // 1. socket.handshake.auth.token (sent by client - legacy/fallback)
  // 2. httpOnly cookie (primary method - more secure)
  let token = socket.handshake.auth.token;

  if (!token) {
    // Parse cookies from handshake headers
    const cookieHeader = socket.handshake.headers.cookie;
    if (cookieHeader) {
      const cookies = cookieHeader.split(';').reduce((acc, cookie) => {
        const [key, value] = cookie.trim().split('=');
        if (key && value) {
          acc[key] = value;
        }
        return acc;
      }, {} as Record<string, string>);

      // Get token from httpOnly cookie
      token = cookies['triterm_access_token'];
    }
  }

  // If token is provided, always try to authenticate (even if not required)
  if (token) {
    try {
      // Verify JWT token
      const payload = verifyToken(token);

      // Attach user info to socket
      socket.data.user = payload;

      // Join user-specific room for notifications
      socket.join(`user:${payload.userId}`);

      logger.debug('Socket.io authentication successful', {
        socketId: socket.id,
        userId: payload.userId,
        username: payload.username,
        deviceId,
        deviceName,
        authMethod: socket.handshake.auth.token ? 'auth-header' : 'cookie',
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

  // Rate limit input length to prevent abuse
  if (input.length > 10000) {
    throw new Error('Input too long (max 10,000 characters)');
  }

  // Remove null bytes and truly dangerous control characters
  // PRESERVE essential terminal control sequences:
  // - \x03 (ETX - Ctrl+C for interrupt signal)
  // - \x04 (EOT - Ctrl+D for EOF)
  // - \x08 (BS - backspace)
  // - \x09 (HT - tab)
  // - \x0A (LF - line feed)
  // - \x0D (CR - carriage return)
  // - \x1B (ESC - escape, needed for ANSI sequences, arrow keys, colors, etc.)
  // - \x7F (DEL - delete)
  const sanitized = input
    .replace(/\0/g, '')  // Null bytes
    .replace(/[\x00-\x02\x05-\x07\x0B-\x0C\x0E-\x1A\x1C-\x1F]/g, '');  // Dangerous control chars only (preserving \x03, \x04)

  return sanitized;
}

// Determine shell based on OS
function getShell(): string {
  if (os.platform() === 'win32') {
    return 'powershell.exe';
  }
  return process.env.SHELL || '/bin/bash';
}

// Verify terminal ownership (multi-device aware)
async function verifyTerminalOwnership(
  terminal: TerminalSession | undefined,
  socket: Socket<ClientToServerEvents, ServerToClientEvents, InterServerEvents, SocketData>,
  terminalId?: string
): Promise<boolean> {
  if (!terminal) {
    logger.warn('Terminal ownership verification failed: terminal not found', {
      terminalId,
      socketId: socket.id,
    });
    return false;
  }

  // For authenticated users: verify the terminal belongs to this user
  if (terminal.userId && socket.data.user) {
    if (terminal.userId !== socket.data.user.userId) {
      logger.warn('Terminal ownership verification failed: user mismatch', {
        terminalId,
        terminalUserId: terminal.userId,
        currentUserId: socket.data.user.userId,
        socketId: socket.id,
      });
      return false;
    }
    // User ID matches - allow access (simplified check, no registry lookup needed)
    return true;
  }

  // For non-authenticated terminals: check socket ID matches
  if (!terminal.userId) {
    if (terminal.socketId !== socket.id) {
      logger.warn('Terminal ownership verification failed: socket mismatch (non-authenticated)', {
        terminalId,
        terminalSocketId: terminal.socketId,
        currentSocketId: socket.id,
      });
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
  socket.on('create-terminal', async (data, callback) => {
    try {
      const currentCount = terminalCounts.get(socket.id) || 0;
      const userId = socket.data.user?.userId;
      const deviceId = socket.data.device?.deviceId;
      const deviceName = socket.data.device?.deviceName;

      // Check if user is active (if authenticated)
      if (userId) {
        const user = await prisma.user.findUnique({
          where: { id: userId },
          select: { isActive: true },
        });

        if (!user || !user.isActive) {
          logger.warn('Inactive user attempted to create terminal', { userId });
          callback({
            error: 'Account pending approval. Please contact administrator.',
          });
          return;
        }
      }

      // Check terminal limit
      if (currentCount >= MAX_TERMINALS) {
        callback({
          error: `Maximum terminal limit reached (${MAX_TERMINALS})`,
        });
        return;
      }

      // Generate terminal ID based on userId if authenticated, otherwise use socket.id
      const terminalIdPrefix = userId ? `user-${userId}` : `anon-${socket.id}`;
      const terminalId = `${terminalIdPrefix}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

      // Spawn terminal
      const shell = getShell();
      const term = pty.spawn(shell, [], {
        name: 'xterm-256color',
        cols: data.cols || 80,
        rows: data.rows || 24,
        cwd: process.env.HOME || process.cwd(),
        env: process.env,
      });

      // Persist terminal session to database (always create session for sharing support)
      let sessionId: string | undefined;
      try {
        const session = await createTerminalSession({
          terminalId,
          userId: userId || undefined, // Allow undefined for unauthenticated sessions
          shell,
          cwd: process.env.HOME || process.cwd(),
          cols: data.cols || 80,
          rows: data.rows || 24,
          socketId: socket.id,
        });
        sessionId = session?.id;

        // Add socket to registry (only if authenticated)
        if (userId) {
          await userTerminalRegistry.addSocket(userId, terminalId, socket.id, deviceId, deviceName);

          // Persist socket connection to database
          if (sessionId) {
            await userTerminalRegistry.persistSocketConnection(sessionId, socket.id, deviceId, deviceName);
          }

          logger.info('Multi-device: Socket added to terminal', {
            terminalId,
            socketId: socket.id,
            userId,
            deviceId,
            deviceName,
            totalDevices: await userTerminalRegistry.getDeviceCount(userId, terminalId),
          });
        }
      } catch (error) {
        logger.error('Failed to persist terminal session', { error, terminalId });
      }

      // Store terminal instance with user ownership
      terminals.set(terminalId, {
        term,
        socketId: socket.id, // Primary socket
        userId,
        sessionId,
        createdAt: Date.now(),
        outputBuffer: [],
        lastActivityAt: Date.now(),
        shareUserSockets: [], // External share users
        connectedSockets: new Set([socket.id]), // Track all connected sockets
      });

      // Update terminal count
      terminalCounts.set(socket.id, currentCount + 1);

      // Set up input queue for this terminal
      const inputQueue = inputQueueManager.getQueue(terminalId);

      // Handle queued input processing
      inputQueue.on('process', async (queuedInput, callback) => {
        try {
          const terminal = terminals.get(terminalId);
          if (!terminal) {
            callback(new Error('Terminal not found'));
            return;
          }

          // Sanitize and write input to PTY
          const sanitizedInput = sanitizeInput(queuedInput.input);
          terminal.term.write(sanitizedInput);

          // Update last activity
          terminal.lastActivityAt = Date.now();

          // Multi-device: Broadcast input to ALL other connected devices (not the sender)
          if (terminal.userId) {
            const connectedSockets = await userTerminalRegistry.getSocketsForTerminal(terminal.userId, terminalId);
            connectedSockets.forEach((sid) => {
              if (sid !== queuedInput.socketId) {
                // Send input echo to other devices
                io.to(sid).emit('terminal-input-received', {
                  terminalId,
                  input: queuedInput.input,
                  sequenceNumber: queuedInput.sequenceNumber,
                  fromSocketId: queuedInput.socketId,
                });
              }
            });
          }

          // Update session activity in database
          updateSessionActivity(terminalId).catch(() => {
            // Silently fail - session might not be persisted
          });

          callback(); // Success
        } catch (error) {
          logger.error('[InputQueue] Failed to process input', {
            terminalId,
            inputId: queuedInput.id,
            error: error instanceof Error ? error.message : 'Unknown error',
          });
          callback(error instanceof Error ? error : new Error('Unknown error'));
        }
      });

      // Handle input acknowledgments
      inputQueue.on('ack', (ack) => {
        // Send acknowledgment back to the sender
        io.to(ack.socketId).emit('terminal-input-ack', {
          terminalId,
          inputId: ack.inputId,
          sequenceNumber: ack.sequenceNumber,
          success: ack.success,
          error: ack.error,
        });
      });

      logger.info('Input queue configured for terminal', {
        terminalId,
        socketId: socket.id,
      });

      // Handle terminal output
      term.onData(async (data) => {
        const terminal = terminals.get(terminalId);
        if (terminal) {
          // Store output in buffer for session recovery
          terminal.outputBuffer.push(data);

          // Limit buffer size (keep last MAX_BUFFER_LINES)
          if (terminal.outputBuffer.length > MAX_BUFFER_LINES) {
            terminal.outputBuffer = terminal.outputBuffer.slice(-MAX_BUFFER_LINES);
          }

          // Update last activity
          terminal.lastActivityAt = Date.now();

          // Broadcast to ALL connected sockets (simple, reliable approach)
          const targetSockets = new Set<string>();

          // Add all connected sockets from the terminal's Set
          terminal.connectedSockets.forEach((sid) => targetSockets.add(sid));

          // Add external share users' sockets
          if (terminal.shareUserSockets && terminal.shareUserSockets.length > 0) {
            terminal.shareUserSockets.forEach((sid) => targetSockets.add(sid));
          }

          // Fallback: ensure primary socket is included
          if (targetSockets.size === 0) {
            targetSockets.add(terminal.socketId);
          }

          // Broadcast to all target sockets
          targetSockets.forEach((socketId) => {
            io.to(socketId).emit('terminal-output', { terminalId, data });
          });
        }
      });

      // Handle terminal exit
      term.onExit(async ({ exitCode, signal }) => {
        logger.info('Terminal exited', { terminalId, exitCode, signal, socketId: socket.id });

        const terminal = terminals.get(terminalId);

        // Multi-device: Broadcast exit to ALL connected sockets
        if (terminal?.userId) {
          const connectedSockets = await userTerminalRegistry.getSocketsForTerminal(terminal.userId, terminalId);
          connectedSockets.forEach((socketId) => {
            io.to(socketId).emit('terminal-exit', { terminalId, exitCode, signal });

            // Update terminal count for each socket
            const count = terminalCounts.get(socketId) || 0;
            terminalCounts.set(socketId, Math.max(0, count - 1));
          });

          // Clean up registry for all sockets
          for (const socketId of connectedSockets) {
            await userTerminalRegistry.removeSocket(terminal.userId!, terminalId, socketId);
          }
        } else {
          // For non-authenticated users
          socket.emit('terminal-exit', { terminalId, exitCode, signal });
          const count = terminalCounts.get(socket.id) || 0;
          terminalCounts.set(socket.id, Math.max(0, count - 1));
        }

        // Cleanup
        terminals.delete(terminalId);

        // Clean up input queue
        inputQueueManager.removeQueue(terminalId);
        logger.debug('Input queue cleaned up for terminal', { terminalId });
      });

      logger.info('Terminal created', { terminalId, socketId: socket.id, shell, sessionId });

      callback({
        success: true,
        terminalId,
        shell,
        sessionId,
      });
    } catch (error) {
      logger.error('Error creating terminal', { error, socketId: socket.id });
      callback({ error: error instanceof Error ? error.message : 'Unknown error' });
    }
  });

  // Reconnect to existing terminal (multi-device aware)
  // If PTY is not running but session exists in DB, spawn a new PTY
  socket.on('reconnect-terminal', async (data, callback) => {
    try {
      const { terminalId } = data;
      const userId = socket.data.user?.userId;
      const deviceId = socket.data.device?.deviceId;
      const deviceName = socket.data.device?.deviceName;

      if (!terminalId) {
        callback({ error: 'Terminal ID is required' });
        return;
      }

      logger.info('Attempting to reconnect terminal', {
        terminalId,
        socketId: socket.id,
        userId,
        deviceId,
        deviceName,
        totalTerminals: terminals.size,
        availableTerminals: Array.from(terminals.keys()),
      });

      let terminal = terminals.get(terminalId);

      // If no PTY running, check if session exists in database and spawn new PTY
      if (!terminal) {
        const dbSession = await getSession(terminalId);

        if (!dbSession || !dbSession.active) {
          logger.error('Terminal session not found in database', {
            terminalId,
            socketId: socket.id,
          });
          callback({ error: 'Terminal not found or has been terminated' });
          return;
        }

        // Verify ownership
        if (userId && dbSession.userId !== userId) {
          callback({ error: 'Unauthorized: Terminal belongs to another user' });
          return;
        }

        logger.info('Spawning new PTY for existing session (multi-device reconnect)', {
          terminalId,
          socketId: socket.id,
          userId,
          shell: dbSession.shell,
        });

        // Spawn new PTY process for this session
        const shell = dbSession.shell || getShell();
        const cwd = dbSession.cwd || os.homedir();
        const cols = dbSession.cols || 80;
        const rows = dbSession.rows || 24;

        const term = pty.spawn(shell, [], {
          name: 'xterm-256color',
          cols,
          rows,
          cwd,
          env: {
            ...process.env,
            TERM: 'xterm-256color',
            COLORTERM: 'truecolor',
          },
        });

        // Store terminal instance
        terminals.set(terminalId, {
          term,
          socketId: socket.id,
          userId: dbSession.userId || undefined,
          sessionId: dbSession.id,
          createdAt: dbSession.createdAt?.getTime() || Date.now(),
          outputBuffer: [],
          lastActivityAt: Date.now(),
          shareUserSockets: [],
          connectedSockets: new Set([socket.id]),
        });

        terminal = terminals.get(terminalId)!;

        // Set up output handler
        term.onData((output) => {
          const termInstance = terminals.get(terminalId);
          if (!termInstance) return;

          // Update activity timestamp
          termInstance.lastActivityAt = Date.now();

          // Buffer output (keep last N chunks for session recovery)
          termInstance.outputBuffer.push(output);
          if (termInstance.outputBuffer.length > MAX_BUFFER_LINES) {
            termInstance.outputBuffer = termInstance.outputBuffer.slice(-MAX_BUFFER_LINES);
          }

          // Multi-device: Send output to ALL connected devices
          if (termInstance.userId) {
            userTerminalRegistry.getSocketsForTerminal(termInstance.userId, terminalId).then((connectedSockets) => {
              connectedSockets.forEach((sid) => {
                io.to(sid).emit('terminal-output', { terminalId, data: output });
              });
            });
          } else {
            io.to(termInstance.socketId).emit('terminal-output', { terminalId, data: output });
          }

          // Also send to external share users
          termInstance.shareUserSockets.forEach((sid) => {
            io.to(sid).emit('terminal-output', { terminalId, data: output });
          });
        });

        // Handle terminal exit
        term.onExit(({ exitCode, signal }) => {
          logger.info('Terminal exited (respawned)', { terminalId, exitCode, signal });

          const termInstance = terminals.get(terminalId);
          if (termInstance) {
            // Multi-device: Notify ALL connected devices
            if (termInstance.userId) {
              userTerminalRegistry.getSocketsForTerminal(termInstance.userId, terminalId).then((connectedSockets) => {
                connectedSockets.forEach((sid) => {
                  io.to(sid).emit('terminal-exit', { terminalId, exitCode, signal });
                });
              });
            } else {
              io.to(termInstance.socketId).emit('terminal-exit', { terminalId, exitCode, signal });
            }

            terminals.delete(terminalId);
          }

          // Mark session as inactive
          deactivateSession(terminalId).catch(() => {});
        });

        // Set up input queue for this terminal
        const inputQueue = inputQueueManager.getQueue(terminalId);
        inputQueue.on('process', async (queuedInput, queueCallback) => {
          try {
            const termInstance = terminals.get(terminalId);
            if (!termInstance) {
              queueCallback(new Error('Terminal not found'));
              return;
            }
            const sanitizedInput = sanitizeInput(queuedInput.input);
            termInstance.term.write(sanitizedInput);
            termInstance.lastActivityAt = Date.now();

            // Multi-device: Broadcast input to ALL other connected devices
            if (termInstance.userId) {
              const connectedSockets = await userTerminalRegistry.getSocketsForTerminal(termInstance.userId, terminalId);
              connectedSockets.forEach((sid) => {
                if (sid !== queuedInput.socketId) {
                  io.to(sid).emit('terminal-input-received', {
                    terminalId,
                    input: queuedInput.input,
                    sequenceNumber: queuedInput.sequenceNumber,
                    fromSocketId: queuedInput.socketId,
                  });
                }
              });
            }

            updateSessionActivity(terminalId).catch(() => {});
            queueCallback();
          } catch (error) {
            queueCallback(error instanceof Error ? error : new Error('Unknown error'));
          }
        });
      }

      // Verify user ownership for authenticated users
      if (userId && terminal.userId !== userId) {
        callback({ error: 'Unauthorized: Terminal belongs to another user' });
        logger.warn('Unauthorized terminal reconnect attempt', {
          terminalId,
          socketId: socket.id,
          userId,
          terminalUserId: terminal.userId,
        });
        return;
      }

      // Multi-device: Add this socket to the terminal (don't replace existing connections)
      // Always add to connectedSockets Set (simple, reliable tracking)
      terminal.connectedSockets.add(socket.id);
      logger.info('Added socket to terminal connectedSockets', {
        terminalId,
        socketId: socket.id,
        totalConnected: terminal.connectedSockets.size,
        allSockets: Array.from(terminal.connectedSockets),
      });

      if (userId && terminal.userId) {
        // Check if socket is already registered
        const isAlreadyConnected = await userTerminalRegistry.isSocketConnected(userId, terminalId, socket.id);

        if (!isAlreadyConnected) {
          // Add socket to registry
          await userTerminalRegistry.addSocket(userId, terminalId, socket.id, deviceId, deviceName);

          // Persist to database if we have a sessionId
          if (terminal.sessionId) {
            await userTerminalRegistry.persistSocketConnection(terminal.sessionId, socket.id, deviceId, deviceName);
          }

          logger.info('Multi-device: Additional socket connected to terminal', {
            terminalId,
            socketId: socket.id,
            userId,
            deviceId,
            deviceName,
            totalDevices: await userTerminalRegistry.getDeviceCount(userId, terminalId),
          });

          // Notify all other connected devices about the new device
          const connectedSockets = await userTerminalRegistry.getSocketsForTerminal(userId, terminalId);
          const devices = await userTerminalRegistry.getDevicesForTerminal(userId, terminalId);
          connectedSockets.forEach((sid) => {
            if (sid !== socket.id) {
              io.to(sid).emit('terminal-device-connected', {
                terminalId,
                deviceId,
                deviceName,
                deviceCount: devices.length,
                devices: devices.map(d => ({ deviceId: d.deviceId, deviceName: d.deviceName })),
              });
            }
          });
        }

        // Update primary socket if this is the first reconnection
        if (terminal.socketId !== socket.id && !isAlreadyConnected) {
          terminal.socketId = socket.id;
        }
      } else {
        // For non-authenticated users, replace socket ID
        terminal.socketId = socket.id;
      }

      terminal.lastActivityAt = Date.now();

      // Get buffered output to send back to client
      const buffer = terminal.outputBuffer.join('');

      // Get device count for this terminal
      const deviceCount = userId ? await userTerminalRegistry.getDeviceCount(userId, terminalId) : 1;

      logger.info('Terminal reconnected', {
        terminalId,
        socketId: socket.id,
        userId: terminal.userId,
        bufferSize: buffer.length,
        deviceCount,
      });

      // Return buffer in callback so client can write it after Terminal component mounts
      callback({
        success: true,
        terminalId,
        buffer,
      });
    } catch (error) {
      logger.error('Error reconnecting terminal', { error, socketId: socket.id });
      callback({ error: error instanceof Error ? error.message : 'Unknown error' });
    }
  });

  // Send input to terminal (using enterprise-grade input queue)
  socket.on('terminal-input', async (data) => {
    try {
      const { terminalId, input } = data;

      // Validate input
      if (!terminalId || typeof terminalId !== 'string') {
        logger.warn('[TerminalInput] Invalid terminalId', { socketId: socket.id, terminalId });
        socket.emit('terminal-error', {
          terminalId: terminalId || 'unknown',
          error: 'Invalid terminal ID',
        });
        return;
      }

      if (!input || typeof input !== 'string') {
        logger.warn('[TerminalInput] Invalid input', { socketId: socket.id, terminalId, inputType: typeof input });
        return;
      }

      const terminal = terminals.get(terminalId);

      if (!terminal) {
        logger.warn('[TerminalInput] Terminal not found', { socketId: socket.id, terminalId });
        socket.emit('terminal-error', {
          terminalId,
          error: 'Terminal not found',
        });
        return;
      }

      // Verify terminal ownership (socket + user)
      if (!(await verifyTerminalOwnership(terminal, socket, terminalId))) {
        logger.warn('[TerminalInput] Unauthorized access attempt', {
          socketId: socket.id,
          terminalId,
          userId: socket.data.user?.userId,
          terminalUserId: terminal.userId,
        });
        socket.emit('terminal-error', {
          terminalId,
          error: 'Unauthorized access to terminal',
        });
        return;
      }

      // Enqueue input for sequential processing
      try {
        const inputQueue = inputQueueManager.getQueue(terminalId);
        const inputId = inputQueue.enqueue(socket.id, input);

        logger.debug('[TerminalInput] Input enqueued', {
          terminalId,
          inputId,
          socketId: socket.id,
          inputLength: input.length,
          queueSize: inputQueue.getQueueSize(),
        });
      } catch (queueError) {
        // Queue full or other queue error
        logger.error('[TerminalInput] Failed to enqueue input', {
          terminalId,
          socketId: socket.id,
          error: queueError instanceof Error ? queueError.message : 'Unknown error',
        });
        socket.emit('terminal-error', {
          terminalId,
          error: queueError instanceof Error ? queueError.message : 'Input queue error',
        });
      }
    } catch (error) {
      logger.error('[TerminalInput] Unexpected error handling terminal input', {
        error: error instanceof Error ? error.message : 'Unknown error',
        terminalId: data?.terminalId,
        socketId: socket.id,
      });
      socket.emit('terminal-error', {
        terminalId: data?.terminalId || 'unknown',
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  // Resize terminal
  socket.on('terminal-resize', async (data) => {
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
      if (!(await verifyTerminalOwnership(terminal, socket, terminalId))) {
        return;
      }

      // Validate dimensions
      const validCols = Math.max(1, Math.min(1000, parseInt(String(cols))));
      const validRows = Math.max(1, Math.min(1000, parseInt(String(rows))));

      terminal.term.resize(validCols, validRows);

      // Update last activity time (resizing counts as activity)
      terminal.lastActivityAt = Date.now();

      // Update session dimensions
      updateSessionDimensions(terminalId, validCols, validRows).catch(() => {
        // Silently fail - session might not be persisted
      });
    } catch (error) {
      logger.error('Error resizing terminal', { error, terminalId: data.terminalId, socketId: socket.id });
    }
  });

  // Keep terminal alive - updates activity timestamp
  socket.on('terminal-keepalive', async (data) => {
    try {
      const { terminalId } = data;

      if (!terminalId) {
        return;
      }

      const terminal = terminals.get(terminalId);

      if (!terminal) {
        return;
      }

      // Verify ownership before updating activity
      if (!(await verifyTerminalOwnership(terminal, socket, terminalId))) {
        return;
      }

      // Update last activity time
      terminal.lastActivityAt = Date.now();

      // Update ping in registry
      if (terminal.userId) {
        await userTerminalRegistry.updatePing(terminal.userId, terminalId, socket.id);
      }
    } catch (error) {
      // Silently fail - keepalive is not critical
    }
  });

  // List all terminals for the authenticated user (multi-device support)
  // Only returns terminals that are currently running in memory (PTY active)
  // Stale DB sessions are cleaned up, not shown to users
  socket.on('list-terminals', async (callback) => {
    try {
      const userId = socket.data.user?.userId;

      if (!userId) {
        callback({ error: 'Authentication required to list terminals' });
        return;
      }

      // Only return terminals that are CURRENTLY RUNNING in memory
      // This is the correct behavior - we can't "reconnect" to a PTY that doesn't exist
      // DB sessions are for persistence metadata, not for respawning dead terminals
      const userTerminals = [];

      for (const [terminalId, terminal] of terminals.entries()) {
        // Only include terminals owned by this user
        if (terminal.userId !== userId) continue;

        // Get device info from registry
        const devices = await userTerminalRegistry.getDevicesForTerminal(userId, terminalId);
        const deviceCount = devices.length;

        userTerminals.push({
          terminalId,
          shell: getShell(),
          createdAt: terminal.createdAt,
          lastActivityAt: terminal.lastActivityAt,
          deviceCount,
          devices: devices.map(d => ({
            deviceId: d.deviceId,
            deviceName: d.deviceName,
            connectedAt: d.connectedAt,
          })),
          // Terminal is "connected on this device" if this socket is registered
          isConnectedOnThisDevice: await userTerminalRegistry.isSocketConnected(userId, terminalId, socket.id),
          // PTY is always running since we're iterating in-memory terminals
          isRunning: true,
        });
      }

      logger.info('Listing terminals for user', {
        userId,
        terminalCount: userTerminals.length,
        inMemoryCount: userTerminals.length,
        socketId: socket.id,
      });

      callback({
        success: true,
        terminals: userTerminals,
      });
    } catch (error) {
      logger.error('Error listing terminals', { error, socketId: socket.id });
      callback({ error: error instanceof Error ? error.message : 'Unknown error' });
    }
  });

  // Close terminal
  socket.on('close-terminal', async (data) => {
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
      if (!(await verifyTerminalOwnership(terminal, socket, terminalId))) {
        return;
      }

      // Check if terminal has active share links
      let hasActiveShareLinks = false;
      let hasActiveConnections = false;
      try {
        const activeShareLinks = await prisma.sharedLink.findMany({
          where: {
            terminalId,
            active: true,
            expiresAt: { gt: new Date() },
          },
          include: {
            activeConnections: {
              where: {
                disconnectedAt: null,
              },
            },
          },
        });

        hasActiveShareLinks = activeShareLinks.length > 0;
        hasActiveConnections = activeShareLinks.some(link => link.activeConnections.length > 0);
      } catch (error) {
        logger.error('Error checking share links before closing terminal', {
          terminalId,
          error: error instanceof Error ? error.message : 'Unknown error',
        });
      }

      if (hasActiveShareLinks || hasActiveConnections) {
        // Terminal has active share links or connected external users
        // Detach it from owner but keep it alive
        logger.info('Terminal has active share links, detaching instead of closing', {
          terminalId,
          socketId: socket.id,
          userId: terminal.userId,
          hasActiveShareLinks,
          hasActiveConnections,
        });

        // Remove socket from registry but don't kill the terminal
        if (terminal.userId) {
          await userTerminalRegistry.removeSocket(terminal.userId, terminalId, socket.id);
          await userTerminalRegistry.removeSocketFromDatabase(socket.id);
        }

        const count = terminalCounts.get(socket.id) || 0;
        terminalCounts.set(socket.id, Math.max(0, count - 1));

        // Notify owner that terminal was detached instead of closed
        socket.emit('terminal-detached', {
          terminalId,
          reason: 'Terminal has active share links and will remain available for shared users',
        });

        return;
      }

      logger.info('Closing terminal', { terminalId, socketId: socket.id, userId: terminal.userId });
      terminal.term.kill();
      terminals.delete(terminalId);

      const count = terminalCounts.get(socket.id) || 0;
      terminalCounts.set(socket.id, Math.max(0, count - 1));

      // Clean up input queue
      inputQueueManager.removeQueue(terminalId);
      logger.debug('Input queue cleaned up for closed terminal', { terminalId });

      // Deactivate session in database
      deactivateSession(terminalId).catch(() => {
        // Silently fail - session might not be persisted
      });
    } catch (error) {
      logger.error('Error closing terminal', { error, terminalId: data.terminalId, socketId: socket.id });
    }
  });

  /**
   * External Sharing: Socket.IO Approval Workflow Events
   */

  // Get pending connection requests for a share link
  socket.on('share:get-pending', async (data: { shareCode: string }, callback) => {
    try {
      const userId = socket.data.user?.userId;
      if (!userId) {
        return callback({ success: false, error: 'Authentication required' });
      }

      // Verify ownership of share link
      const shareLink = await prisma.sharedLink.findUnique({
        where: { shareCode: data.shareCode },
        include: {
          pendingConnections: {
            where: { status: 'PENDING' },
            orderBy: { requestedAt: 'desc' },
          },
        },
      });

      if (!shareLink) {
        return callback({ success: false, error: 'Share link not found' });
      }

      if (shareLink.createdBy !== userId) {
        return callback({ success: false, error: 'Unauthorized' });
      }

      callback({
        success: true,
        pendingConnections: shareLink.pendingConnections,
      });
    } catch (error) {
      logger.error('[Share] Error getting pending connections', {
        error: error instanceof Error ? error.message : 'Unknown error',
        shareCode: data.shareCode,
      });
      callback({ success: false, error: 'Failed to get pending connections' });
    }
  });

  // Notify owner of new join request (triggered by REST API)
  // Owner socket listens for 'share:new-request' event

  // Approve a pending connection
  socket.on('share:approve-connection', async (data: { connectionId: string }, callback) => {
    try {
      const userId = socket.data.user?.userId;
      if (!userId) {
        return callback({ success: false, error: 'Authentication required' });
      }

      // Rate limiting
      const limit = SOCKET_RATE_LIMITS['share:approve-connection'];
      if (!socketRateLimiter.isAllowed(userId, 'share:approve-connection', limit.max, limit.windowMs)) {
        return callback({ success: false, error: 'Too many requests. Please slow down.' });
      }

      // Get connection details
      const connection = await prisma.pendingConnection.findUnique({
        where: { id: data.connectionId },
        include: { sharedLink: true },
      });

      if (!connection) {
        return callback({ success: false, error: 'Connection not found' });
      }

      // Verify ownership
      if (connection.sharedLink.createdBy !== userId) {
        return callback({ success: false, error: 'Unauthorized' });
      }

      if (connection.status !== 'PENDING') {
        return callback({ success: false, error: 'Connection already processed' });
      }

      // Approve the connection
      await prisma.pendingConnection.update({
        where: { id: data.connectionId },
        data: {
          status: 'APPROVED',
          respondedAt: new Date(),
          respondedBy: userId,
        },
      });

      // Create audit log
      await prisma.shareAuditLog.create({
        data: {
          sharedLinkId: connection.sharedLinkId,
          action: 'APPROVED',
          actorId: userId,
          targetName: connection.name,
          targetEmail: connection.email,
          ipAddress: connection.ipAddress,
        },
      });

      // Notify the waiting user via connection room
      io.to(`connection:${data.connectionId}`).emit('share:connection-approved', {
        connectionId: data.connectionId,
        terminalId: connection.sharedLink.terminalId,
        permission: connection.sharedLink.permission,
      });

      logger.info('[Share] Connection approved', {
        connectionId: data.connectionId,
        approvedBy: userId,
        name: connection.name,
      });

      // Notify owner's management dialog about the approval
      const terminal = terminals.get(connection.sharedLink.terminalId);
      if (terminal && terminal.userId) {
        const ownerSockets = await userTerminalRegistry.getSocketsForTerminal(terminal.userId, connection.sharedLink.terminalId);
        ownerSockets.forEach((ownerSocketId) => {
          io.to(ownerSocketId).emit('share:connection-approved-owner', {
            shareCode: connection.sharedLink.shareCode,
            connectionId: data.connectionId,
          });
        });
      }

      callback({ success: true });
    } catch (error) {
      logger.error('[Share] Error approving connection', {
        error: error instanceof Error ? error.message : 'Unknown error',
        connectionId: data.connectionId,
      });
      callback({ success: false, error: 'Failed to approve connection' });
    }
  });

  // Reject a pending connection
  socket.on('share:reject-connection', async (data: { connectionId: string; reason?: string }, callback) => {
    try {
      const userId = socket.data.user?.userId;
      if (!userId) {
        return callback({ success: false, error: 'Authentication required' });
      }

      // Rate limiting
      const limit = SOCKET_RATE_LIMITS['share:reject-connection'];
      if (!socketRateLimiter.isAllowed(userId, 'share:reject-connection', limit.max, limit.windowMs)) {
        return callback({ success: false, error: 'Too many requests. Please slow down.' });
      }

      // Get connection details
      const connection = await prisma.pendingConnection.findUnique({
        where: { id: data.connectionId },
        include: { sharedLink: true },
      });

      if (!connection) {
        return callback({ success: false, error: 'Connection not found' });
      }

      // Verify ownership
      if (connection.sharedLink.createdBy !== userId) {
        return callback({ success: false, error: 'Unauthorized' });
      }

      if (connection.status !== 'PENDING') {
        return callback({ success: false, error: 'Connection already processed' });
      }

      // Reject the connection
      await prisma.pendingConnection.update({
        where: { id: data.connectionId },
        data: {
          status: 'REJECTED',
          respondedAt: new Date(),
          respondedBy: userId,
          rejectionReason: data.reason || null,
        },
      });

      // Create audit log
      await prisma.shareAuditLog.create({
        data: {
          sharedLinkId: connection.sharedLinkId,
          action: 'REJECTED',
          actorId: userId,
          targetName: connection.name,
          targetEmail: connection.email,
          ipAddress: connection.ipAddress,
          metadata: data.reason ? JSON.stringify({ reason: data.reason }) : null,
        },
      });

      // Notify the waiting user via connection room
      io.to(`connection:${data.connectionId}`).emit('share:connection-rejected', {
        connectionId: data.connectionId,
        reason: data.reason,
      });

      logger.info('[Share] Connection rejected', {
        connectionId: data.connectionId,
        rejectedBy: userId,
        name: connection.name,
        reason: data.reason,
      });

      // Notify owner's management dialog about the rejection
      const terminal = terminals.get(connection.sharedLink.terminalId);
      if (terminal && terminal.userId) {
        const ownerSockets = await userTerminalRegistry.getSocketsForTerminal(terminal.userId, connection.sharedLink.terminalId);
        ownerSockets.forEach((ownerSocketId) => {
          io.to(ownerSocketId).emit('share:connection-rejected-owner', {
            shareCode: connection.sharedLink.shareCode,
            connectionId: data.connectionId,
          });
        });
      }

      callback({ success: true });
    } catch (error) {
      logger.error('[Share] Error rejecting connection', {
        error: error instanceof Error ? error.message : 'Unknown error',
        connectionId: data.connectionId,
      });
      callback({ success: false, error: 'Failed to reject connection' });
    }
  });

  // Join connection-specific room to listen for approval/rejection (public, no auth required)
  socket.on('share:join-connection-room', (data: { connectionId: string }) => {
    if (!data.connectionId) return;

    const roomName = `connection:${data.connectionId}`;
    socket.join(roomName);

    logger.debug('[Share] Client joined connection room', {
      socketId: socket.id,
      connectionId: data.connectionId,
      room: roomName,
    });
  });

  // Connect to shared terminal (for approved external users)
  socket.on('share:connect-terminal', async (data: { connectionId: string }, callback) => {
    try {
      // Rate limiting (use socket.id since external users aren't authenticated)
      const identifier = socket.id;
      const limit = SOCKET_RATE_LIMITS['share:connect-terminal'];
      if (!socketRateLimiter.isAllowed(identifier, 'share:connect-terminal', limit.max, limit.windowMs)) {
        return callback({ success: false, error: 'Too many connection attempts. Please try again later.' });
      }

      // Get approved connection
      const connection = await prisma.pendingConnection.findUnique({
        where: { id: data.connectionId },
        include: { sharedLink: true },
      });

      if (!connection) {
        return callback({ success: false, error: 'Connection not found' });
      }

      if (connection.status !== 'APPROVED') {
        return callback({ success: false, error: 'Connection not approved' });
      }

      const shareLink = connection.sharedLink;

      // Check if share link is still active
      if (!shareLink.active) {
        return callback({ success: false, error: 'Share link has been deactivated' });
      }

      if (new Date() > shareLink.expiresAt) {
        return callback({ success: false, error: 'Share link has expired' });
      }

      // Get terminal
      const terminal = terminals.get(shareLink.terminalId);
      if (!terminal) {
        return callback({ success: false, error: 'Terminal not found or inactive' });
      }

      // Create active connection record
      const activeConnection = await prisma.activeConnection.create({
        data: {
          sharedLinkId: shareLink.id,
          connectionId: data.connectionId,
          socketId: socket.id,
          name: connection.name,
          email: connection.email,
          organization: connection.organization,
          ipAddress: connection.ipAddress,
        },
      });

      // Update pending connection with socket ID
      await prisma.pendingConnection.update({
        where: { id: data.connectionId },
        data: { socketId: socket.id },
      });

      // Increment usage counter
      await prisma.sharedLink.update({
        where: { id: shareLink.id },
        data: { currentUses: { increment: 1 } },
      });

      // Store share connection info on socket
      socket.data.shareConnection = {
        connectionId: data.connectionId,
        activeConnectionId: activeConnection.id,
        shareCode: shareLink.shareCode,
        permission: shareLink.permission,
        terminalId: shareLink.terminalId,
      };

      // Add this socket to the terminal's share user sockets list
      if (!terminal.shareUserSockets) {
        terminal.shareUserSockets = [];
      }
      terminal.shareUserSockets.push(socket.id);

      logger.debug('[Share] Added external user socket to terminal', {
        terminalId: shareLink.terminalId,
        socketId: socket.id,
        totalShareUsers: terminal.shareUserSockets.length,
      });

      // Send terminal details and buffer
      const buffer = terminal.outputBuffer.join('');

      // Create audit log
      await prisma.shareAuditLog.create({
        data: {
          sharedLinkId: shareLink.id,
          action: 'CONNECTED',
          targetName: connection.name,
          targetEmail: connection.email,
          ipAddress: connection.ipAddress,
        },
      });

      // Notify owner
      if (terminal.userId) {
        const ownerSockets = await userTerminalRegistry.getSocketsForTerminal(terminal.userId, shareLink.terminalId);
        ownerSockets.forEach((ownerSocketId) => {
          io.to(ownerSocketId).emit('share:external-user-connected', {
            terminalId: shareLink.terminalId,
            connectionId: data.connectionId,
            name: connection.name,
            email: connection.email,
          });
        });
      }

      logger.info('[Share] External user connected to terminal', {
        connectionId: data.connectionId,
        terminalId: shareLink.terminalId,
        name: connection.name,
        permission: shareLink.permission,
      });

      callback({
        success: true,
        terminalId: shareLink.terminalId,
        buffer,
        permission: shareLink.permission,
        cols: terminal.term.cols,
        rows: terminal.term.rows,
      });
    } catch (error) {
      logger.error('[Share] Error connecting to shared terminal', {
        error: error instanceof Error ? error.message : 'Unknown error',
        connectionId: data.connectionId,
      });
      callback({ success: false, error: 'Failed to connect to terminal' });
    }
  });

  // Get share link details (for share management dialog)
  socket.on('share:get-details', async (data: { shareCode: string }, callback) => {
    try {
      // Rate limiting
      const userId = socket.data.user?.userId || socket.id;
      const limit = SOCKET_RATE_LIMITS['share:get-details'];
      if (!socketRateLimiter.isAllowed(userId, 'share:get-details', limit.max, limit.windowMs)) {
        return callback({ success: false, error: 'Too many requests. Please slow down.' });
      }

      const { shareCode } = data;

      if (!shareCode) {
        return callback({ success: false, error: 'Share code required' });
      }

      // Verify terminal ownership
      if (!userId || userId === socket.id) {
        return callback({ success: false, error: 'Not authenticated' });
      }

      // Get share link with connections
      const shareLink = await prisma.sharedLink.findUnique({
        where: { shareCode },
        include: {
          pendingConnections: {
            where: { status: 'PENDING' },
            orderBy: { requestedAt: 'desc' },
          },
          activeConnections: {
            where: { disconnectedAt: null },
            orderBy: { connectedAt: 'desc' },
          },
        },
      });

      if (!shareLink) {
        return callback({ success: false, error: 'Share link not found' });
      }

      // Verify ownership of the terminal
      const terminal = terminals.get(shareLink.terminalId);
      if (!terminal || terminal.userId !== userId) {
        return callback({ success: false, error: 'Not authorized' });
      }

      logger.info('[Share] Fetched share link details', {
        shareCode,
        pendingCount: shareLink.pendingConnections.length,
        activeCount: shareLink.activeConnections.length,
      });

      callback({
        success: true,
        shareLink: {
          id: shareLink.id,
          shareCode: shareLink.shareCode,
          permission: shareLink.permission,
          approvalMode: shareLink.approvalMode,
          active: shareLink.active,
          expiresAt: shareLink.expiresAt.toISOString(),
          currentUses: shareLink.currentUses,
          maxUses: shareLink.maxUses,
          pendingConnections: shareLink.pendingConnections.map((conn) => ({
            id: conn.id,
            name: conn.name,
            email: conn.email,
            organization: conn.organization,
            reason: conn.reason,
            requestedAt: conn.requestedAt.toISOString(),
            ipAddress: conn.ipAddress,
          })),
          activeConnections: shareLink.activeConnections.map((conn) => ({
            id: conn.id,
            name: conn.name,
            email: conn.email,
            organization: conn.organization,
            connectedAt: conn.connectedAt.toISOString(),
            ipAddress: conn.ipAddress,
            socketId: conn.socketId,
          })),
        },
      });
    } catch (error) {
      logger.error('[Share] Error fetching share link details', {
        error: error instanceof Error ? error.message : 'Unknown error',
        shareCode: data.shareCode,
      });
      callback({ success: false, error: 'Failed to fetch share link details' });
    }
  });

  // Kick an active external user
  socket.on('share:kick-user', async (data: { activeConnectionId: string }, callback) => {
    try {
      const { activeConnectionId } = data;

      if (!activeConnectionId) {
        return callback({ success: false, error: 'Active connection ID required' });
      }

      // Verify terminal ownership
      const userId = socket.data.user?.userId;
      if (!userId) {
        return callback({ success: false, error: 'Not authenticated' });
      }

      // Rate limiting
      const limit = SOCKET_RATE_LIMITS['share:kick-user'];
      if (!socketRateLimiter.isAllowed(userId, 'share:kick-user', limit.max, limit.windowMs)) {
        return callback({ success: false, error: 'Too many requests. Please slow down.' });
      }

      // Get active connection
      const activeConnection = await prisma.activeConnection.findUnique({
        where: { id: activeConnectionId },
        include: { sharedLink: true },
      });

      if (!activeConnection) {
        return callback({ success: false, error: 'Connection not found' });
      }

      // Verify ownership of the terminal
      const terminal = terminals.get(activeConnection.sharedLink.terminalId);
      if (!terminal || terminal.userId !== userId) {
        return callback({ success: false, error: 'Not authorized' });
      }

      // Disconnect the user's socket
      const targetSocket = io.sockets.sockets.get(activeConnection.socketId);
      if (targetSocket) {
        targetSocket.emit('share:kicked', {
          reason: 'You have been disconnected by the terminal owner',
        });
        targetSocket.disconnect(true);
      }

      // Remove socket from terminal's share user sockets
      if (terminal.shareUserSockets) {
        const index = terminal.shareUserSockets.indexOf(activeConnection.socketId);
        if (index > -1) {
          terminal.shareUserSockets.splice(index, 1);
        }
      }

      // Update connection record
      await prisma.activeConnection.update({
        where: { id: activeConnectionId },
        data: { disconnectedAt: new Date() },
      });

      // Create audit log
      await prisma.shareAuditLog.create({
        data: {
          sharedLinkId: activeConnection.sharedLink.id,
          action: 'KICKED',
          actorId: userId,
          targetName: activeConnection.name,
          targetEmail: activeConnection.email,
          ipAddress: activeConnection.ipAddress,
        },
      });

      logger.info('[Share] Kicked external user', {
        activeConnectionId,
        terminalId: activeConnection.sharedLink.terminalId,
        name: activeConnection.name,
      });

      // Notify all owner's sockets about the kick
      if (terminal.userId) {
        const ownerSockets = await userTerminalRegistry.getSocketsForTerminal(terminal.userId, activeConnection.sharedLink.terminalId);
        ownerSockets.forEach((ownerSocketId) => {
          io.to(ownerSocketId).emit('share:user-kicked', {
            shareCode: activeConnection.sharedLink.shareCode,
            activeConnectionId,
          });
        });
      }

      callback({ success: true });
    } catch (error) {
      logger.error('[Share] Error kicking user', {
        error: error instanceof Error ? error.message : 'Unknown error',
        activeConnectionId: data.activeConnectionId,
      });
      callback({ success: false, error: 'Failed to kick user' });
    }
  });

  // Deactivate share link and terminate all connections
  socket.on('share:deactivate', async (data: { shareCode: string }, callback) => {
    try {
      const { shareCode } = data;

      if (!shareCode) {
        return callback({ success: false, error: 'Share code required' });
      }

      // Verify terminal ownership
      const userId = socket.data.user?.userId;
      if (!userId) {
        return callback({ success: false, error: 'Not authenticated' });
      }

      // Rate limiting
      const limit = SOCKET_RATE_LIMITS['share:deactivate'];
      if (!socketRateLimiter.isAllowed(userId, 'share:deactivate', limit.max, limit.windowMs)) {
        return callback({ success: false, error: 'Too many requests. Please slow down.' });
      }

      // Get share link with connections
      const shareLink = await prisma.sharedLink.findUnique({
        where: { shareCode },
        include: {
          activeConnections: {
            where: { disconnectedAt: null },
          },
        },
      });

      if (!shareLink) {
        return callback({ success: false, error: 'Share link not found' });
      }

      // Verify ownership of the terminal
      const terminal = terminals.get(shareLink.terminalId);
      if (!terminal || terminal.userId !== userId) {
        return callback({ success: false, error: 'Not authorized' });
      }

      // Disconnect all active external users
      for (const connection of shareLink.activeConnections) {
        const targetSocket = io.sockets.sockets.get(connection.socketId);
        if (targetSocket) {
          targetSocket.emit('share:link-deactivated', {
            reason: 'This share link has been deactivated by the terminal owner',
          });
          targetSocket.disconnect(true);
        }

        // Remove socket from terminal's share user sockets
        if (terminal.shareUserSockets) {
          const index = terminal.shareUserSockets.indexOf(connection.socketId);
          if (index > -1) {
            terminal.shareUserSockets.splice(index, 1);
          }
        }

        // Update connection record
        await prisma.activeConnection.update({
          where: { id: connection.id },
          data: { disconnectedAt: new Date() },
        });
      }

      // Deactivate the share link
      await prisma.sharedLink.update({
        where: { id: shareLink.id },
        data: { active: false },
      });

      // Create audit log
      await prisma.shareAuditLog.create({
        data: {
          sharedLinkId: shareLink.id,
          action: 'DEACTIVATED',
          actorId: userId,
          ipAddress: socket.handshake.address,
        },
      });

      logger.info('[Share] Deactivated share link', {
        shareCode,
        terminalId: shareLink.terminalId,
        disconnectedUsers: shareLink.activeConnections.length,
      });

      // Notify owner's sockets that share link was deactivated
      if (terminal.userId) {
        const ownerSockets = await userTerminalRegistry.getSocketsForTerminal(terminal.userId, shareLink.terminalId);
        ownerSockets.forEach((ownerSocketId) => {
          io.to(ownerSocketId).emit('share:link-deactivated-owner', {
            terminalId: shareLink.terminalId,
            shareCode,
          });
        });
      }

      callback({ success: true });
    } catch (error) {
      logger.error('[Share] Error deactivating share link', {
        error: error instanceof Error ? error.message : 'Unknown error',
        shareCode: data.shareCode,
      });
      callback({ success: false, error: 'Failed to deactivate share link' });
    }
  });

  // Handle disconnect (multi-device aware)
  socket.on('disconnect', async () => {
    const userId = socket.data.user?.userId;
    const deviceId = socket.data.device?.deviceId;
    const deviceName = socket.data.device?.deviceName;

    logger.info('Client disconnected', {
      socketId: socket.id,
      userId,
      deviceId,
      deviceName,
      totalTerminals: terminals.size,
    });

    // Remove socket from all terminals' connectedSockets Set
    for (const [terminalId, terminal] of terminals.entries()) {
      if (terminal.connectedSockets.has(socket.id)) {
        terminal.connectedSockets.delete(socket.id);
        logger.info('Removed socket from terminal connectedSockets on disconnect', {
          terminalId,
          socketId: socket.id,
          remainingConnected: terminal.connectedSockets.size,
        });
      }
    }

    // Multi-device: Remove this socket from the registry
    if (userId) {
      const affectedTerminals = await userTerminalRegistry.getTerminalsForSocket(socket.id);

      for (const { userId: terminalUserId, terminalId } of affectedTerminals) {
        // Remove socket from registry
        await userTerminalRegistry.removeSocket(terminalUserId, terminalId, socket.id);

        // Remove from database
        await userTerminalRegistry.removeSocketFromDatabase(socket.id);

        // Notify other connected devices about this device disconnecting
        const remainingSockets = await userTerminalRegistry.getSocketsForTerminal(terminalUserId, terminalId);
        const devices = await userTerminalRegistry.getDevicesForTerminal(terminalUserId, terminalId);

        remainingSockets.forEach((sid) => {
          io.to(sid).emit('terminal-device-disconnected', {
            terminalId,
            deviceId,
            deviceName,
            deviceCount: devices.length,
            devices: devices.map(d => ({ deviceId: d.deviceId, deviceName: d.deviceName })),
          });
        });

        const hasOtherDevices = await userTerminalRegistry.hasConnectedDevices(terminalUserId, terminalId);

        if (hasOtherDevices) {
          logger.info('Multi-device: Socket disconnected but terminal kept alive (other devices connected)', {
            terminalId,
            socketId: socket.id,
            userId: terminalUserId,
            remainingDevices: remainingSockets.length,
          });
        } else {
          logger.info('Multi-device: Last device disconnected, terminal detached (kept alive for reconnection)', {
            terminalId,
            socketId: socket.id,
            userId: terminalUserId,
            bufferSize: terminals.get(terminalId)?.outputBuffer.length || 0,
          });
        }
      }
    } else {
      // For non-authenticated users, just log detachment
      let detachedCount = 0;
      for (const [terminalId, terminal] of terminals.entries()) {
        if (terminal.socketId === socket.id) {
          detachedCount++;
          logger.info('Terminal detached (kept alive for reconnection)', {
            terminalId,
            socketId: socket.id,
            userId: terminal.userId,
            bufferSize: terminal.outputBuffer.length,
          });
        }
      }

      logger.info('Disconnect complete (non-authenticated)', {
        socketId: socket.id,
        detachedTerminals: detachedCount,
      });
    }

    // Clean up external share connections if this is a shared terminal user
    if (socket.data.shareConnection) {
      try {
        const { activeConnectionId, shareCode, terminalId } = socket.data.shareConnection;

        // Remove socket from terminal's share user sockets
        const terminal = terminals.get(terminalId);
        if (terminal && terminal.shareUserSockets) {
          const index = terminal.shareUserSockets.indexOf(socket.id);
          if (index > -1) {
            terminal.shareUserSockets.splice(index, 1);
            logger.debug('[Share] Removed external user socket from terminal', {
              terminalId,
              socketId: socket.id,
              remainingShareUsers: terminal.shareUserSockets.length,
            });
          }
        }

        // Mark active connection as disconnected
        await prisma.activeConnection.update({
          where: { id: activeConnectionId },
          data: { disconnectedAt: new Date() },
        });

        // Get connection details
        const activeConnection = await prisma.activeConnection.findUnique({
          where: { id: activeConnectionId },
          include: { sharedLink: true },
        });

        if (activeConnection) {
          // Create audit log
          await prisma.shareAuditLog.create({
            data: {
              sharedLinkId: activeConnection.sharedLinkId,
              action: 'DISCONNECTED',
              targetName: activeConnection.name,
              targetEmail: activeConnection.email,
              ipAddress: activeConnection.ipAddress,
            },
          });

          // Notify owner
          if (terminal && terminal.userId) {
            const ownerSockets = await userTerminalRegistry.getSocketsForTerminal(terminal.userId, terminalId);
            ownerSockets.forEach((ownerSocketId) => {
              io.to(ownerSocketId).emit('share:external-user-disconnected', {
                terminalId,
                connectionId: activeConnection.connectionId,
                name: activeConnection.name,
              });
            });
          }

          logger.info('[Share] External user disconnected', {
            activeConnectionId,
            shareCode,
            name: activeConnection.name,
          });
        }
      } catch (error) {
        logger.error('[Share] Error cleaning up share connection on disconnect', {
          error: error instanceof Error ? error.message : 'Unknown error',
          socketId: socket.id,
        });
      }
    }

    terminalCounts.delete(socket.id);
  });
});

// Cleanup inactive terminals periodically (multi-device aware)
setInterval(async () => {
  const now = Date.now();
  const terminalsToKill: string[] = [];

  for (const [terminalId, terminal] of terminals.entries()) {
    // Multi-device: Check if any device has recent activity
    let hasRecentActivity = false;

    if (terminal.userId) {
      // For authenticated users, check if any device is still connected
      const hasConnectedDevices = await userTerminalRegistry.hasConnectedDevices(terminal.userId, terminalId);

      if (hasConnectedDevices) {
        // If devices are connected, check their last activity
        const devices = await userTerminalRegistry.getDevicesForTerminal(terminal.userId, terminalId);
        hasRecentActivity = devices.some(device =>
          now - device.lastPingAt.getTime() < SESSION_TIMEOUT_MS
        );
      }
    }

    // Check if terminal has active share links - don't kill if it does
    let hasActiveShareLinks = false;
    try {
      const activeShareLinks = await prisma.sharedLink.findMany({
        where: {
          terminalId,
          active: true,
          expiresAt: { gt: new Date() },
        },
      });
      hasActiveShareLinks = activeShareLinks.length > 0;
    } catch (error) {
      logger.error('Error checking share links for terminal', {
        terminalId,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }

    // Kill terminals that have been inactive for SESSION_TIMEOUT_MS
    // AND have no connected devices with recent activity
    // AND have no active share links
    if (!hasRecentActivity && !hasActiveShareLinks && now - terminal.lastActivityAt > SESSION_TIMEOUT_MS) {
      terminalsToKill.push(terminalId);
    }
  }

  for (const terminalId of terminalsToKill) {
    const terminal = terminals.get(terminalId);
    if (terminal) {
      const inactiveMinutes = Math.round((now - terminal.lastActivityAt) / 60000);

      logger.info('Killing inactive terminal', {
        terminalId,
        userId: terminal.userId,
        inactiveFor: inactiveMinutes + ' minutes',
      });

      try {
        terminal.term.kill();
      } catch (error) {
        logger.error('Error killing inactive terminal', { error, terminalId });
      }

      terminals.delete(terminalId);

      // Clean up registry
      if (terminal.userId) {
        const connectedSockets = await userTerminalRegistry.getSocketsForTerminal(terminal.userId, terminalId);
        connectedSockets.forEach((socketId) => {
          userTerminalRegistry.removeSocket(terminal.userId!, terminalId, socketId);
        });
      }

      // Clean up input queue
      inputQueueManager.removeQueue(terminalId);

      // Also deactivate in database
      deactivateSession(terminalId).catch(() => {
        // Silently fail
      });
    }
  }

  // Log queue metrics periodically
  if (terminalsToKill.length > 0) {
    const queueMetrics = inputQueueManager.getAggregateMetrics();
    logger.info('[InputQueue] Aggregate metrics', {
      queueCount: inputQueueManager.getQueueCount(),
      metrics: queueMetrics,
    });
  }
}, 60000); // Check every minute

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

// Initialize Redis connection (optional - gracefully degrades if not available)
async function initializeRedis() {
  try {
    await connectRedis();
    const healthy = await isRedisHealthy();
    if (healthy) {
      logger.info('Redis connected successfully - using hybrid cache mode');
    } else {
      logger.warn('Redis health check failed - using in-memory mode');
    }
  } catch (error) {
    logger.warn('Redis connection failed - using in-memory mode', { error: (error as Error).message });
  }
}

// Start server with Redis initialization
async function startServer() {
  // Initialize Redis (non-blocking, will gracefully degrade if unavailable)
  await initializeRedis();

  // Check Redis status for display
  const redisHealthy = await isRedisHealthy();
  const redisStatus = redisHealthy ? 'Connected' : 'In-Memory Mode';

  httpServer.listen(PORT, HOST, () => {
  const networkAddress = getNetworkAddress();
  const portStr = PORT.toString();

  logger.info('TriTerm Server Started', {
    port: PORT,
    host: HOST,
    environment: process.env.NODE_ENV || 'development',
    maxTerminals: MAX_TERMINALS,
    authRequired: process.env.REQUIRE_AUTH === 'true',
    redisMode: redisStatus,
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
║  Redis: ${redisStatus.padEnd(36)} ║
╠═══════════════════════════════════════════════╣
║  Local:   http://localhost:${portStr.padEnd(23)} ║
║  Network: http://${networkAddress}:${portStr.padEnd(23)} ║
╚═══════════════════════════════════════════════╝
  `);
  }
  });
}

// Start the server
startServer().catch((error) => {
  logger.error('Failed to start server', { error });
  process.exit(1);
});

// Schedule cleanup of old/inactive sessions
const CLEANUP_INTERVAL = 60 * 60 * 1000; // 1 hour
const INACTIVE_HOURS = 24; // Delete sessions inactive for 24 hours

// On server startup, mark ALL sessions as inactive
// PTY processes don't survive server restarts, so all old sessions are stale
(async () => {
  try {
    const result = await prisma.session.updateMany({
      where: { active: true },
      data: { active: false },
    });
    logger.info('Marked all previous sessions as inactive on startup', {
      count: result.count,
    });
  } catch (error) {
    logger.error('Error marking sessions inactive on startup', { error });
  }
})();

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
process.on('SIGTERM', async () => {
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

  // Disconnect Redis
  await disconnectRedis();

  httpServer.close(() => {
    logger.info('Server closed');
    process.exit(0);
  });
});

process.on('SIGINT', async () => {
  logger.info('SIGINT received, closing server');
  await disconnectRedis();
  process.exit(0);
});
