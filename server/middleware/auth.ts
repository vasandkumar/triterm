import { Request, Response, NextFunction } from 'express';
import { verifyToken, JWTPayload } from '../lib/jwt.js';
import logger from '../config/logger.js';

// Extend Express Request type to include user
declare global {
  namespace Express {
    interface Request {
      user?: JWTPayload;
    }
  }
}

/**
 * Middleware to verify JWT token and attach user to request
 */
export function authenticateToken(req: Request, res: Response, next: NextFunction): void {
  try {
    // Get token from Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({ error: 'No token provided' });
      return;
    }

    const token = authHeader.substring(7);

    // Verify token
    const payload = verifyToken(token);

    // Attach user to request
    req.user = payload;

    next();
  } catch (error) {
    if (error instanceof Error && (error.message === 'Token expired' || error.message === 'Invalid token')) {
      logger.warn('Authentication failed', { error: error.message, path: req.path });
      res.status(401).json({ error: error.message });
      return;
    }

    logger.error('Authentication error', { error, path: req.path });
    res.status(500).json({ error: 'Internal server error' });
  }
}

/**
 * Optional authentication middleware - does not reject if no token
 */
export function optionalAuth(req: Request, _res: Response, next: NextFunction): void {
  try {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      const payload = verifyToken(token);
      req.user = payload;
    }
  } catch (error) {
    // Silently ignore authentication errors for optional auth
    logger.debug('Optional auth failed', { error, path: req.path });
  }

  next();
}
