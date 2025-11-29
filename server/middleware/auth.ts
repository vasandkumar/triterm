import { Request, Response, NextFunction } from 'express';
import { verifyToken, JWTPayload } from '../lib/jwt.js';
import { getAccessTokenFromCookies } from '../lib/authCookies.js';
import { isTokenRevoked } from '../lib/tokenRevocation.js';
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
 * Supports both httpOnly cookies (primary) and Authorization header (fallback)
 */
export function authenticateToken(req: Request, res: Response, next: NextFunction): void {
  try {
    let token: string | undefined;

    // Primary: Try to get token from httpOnly cookie
    token = getAccessTokenFromCookies(req.cookies || {});

    // Fallback: Try Authorization header (for backward compatibility / API clients)
    if (!token) {
      const authHeader = req.headers.authorization;
      if (authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.substring(7);
      }
    }

    if (!token) {
      res.status(401).json({ error: 'No token provided' });
      return;
    }

    // Verify token
    const payload = verifyToken(token);

    // Check if token has been revoked
    if (isTokenRevoked(token)) {
      logger.warn('Revoked token access attempted', {
        userId: payload.userId,
        path: req.path,
      });
      res.status(401).json({ error: 'Token has been revoked' });
      return;
    }

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
    let token: string | undefined;

    // Primary: Try to get token from httpOnly cookie
    token = getAccessTokenFromCookies(req.cookies || {});

    // Fallback: Try Authorization header
    if (!token) {
      const authHeader = req.headers.authorization;
      if (authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.substring(7);
      }
    }

    if (token) {
      const payload = verifyToken(token);

      // Check if token has been revoked (silently skip for optional auth)
      if (!isTokenRevoked(token)) {
        req.user = payload;
      }
    }
  } catch (error) {
    // Silently ignore authentication errors for optional auth
    logger.debug('Optional auth failed', { error, path: req.path });
  }

  next();
}
