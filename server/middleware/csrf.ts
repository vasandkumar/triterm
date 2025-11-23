import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import cookieParser from 'cookie-parser';

/**
 * CSRF Protection Middleware
 *
 * Uses double-submit cookie pattern:
 * 1. Server sets a CSRF token in a cookie
 * 2. Client must send the same token in a custom header
 * 3. Server validates they match
 *
 * This protects against CSRF even though we use JWT auth,
 * as an additional layer of defense.
 */

const CSRF_COOKIE_NAME = 'XSRF-TOKEN';
const CSRF_HEADER_NAME = 'x-xsrf-token';
const CSRF_TOKEN_LENGTH = 32;

/**
 * Generate a random CSRF token
 */
function generateToken(): string {
  return crypto.randomBytes(CSRF_TOKEN_LENGTH).toString('hex');
}

/**
 * Middleware to set CSRF token in cookie
 */
export function csrfCookieMiddleware(req: Request, res: Response, next: NextFunction) {
  // Check if CSRF token already exists in cookies
  let token = req.cookies?.[CSRF_COOKIE_NAME];

  if (!token) {
    // Generate new token
    token = generateToken();

    // Set token in cookie
    res.cookie(CSRF_COOKIE_NAME, token, {
      httpOnly: false, // Must be readable by JavaScript
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    });
  }

  next();
}

/**
 * Middleware to validate CSRF token on state-changing requests
 */
export function csrfProtection(req: Request, res: Response, next: NextFunction) {
  // Only check CSRF for state-changing methods
  const safeMethod = ['GET', 'HEAD', 'OPTIONS'].includes(req.method);

  if (safeMethod) {
    return next();
  }

  // Get token from cookie and header
  const cookieToken = req.cookies?.[CSRF_COOKIE_NAME];
  const headerToken = req.headers[CSRF_HEADER_NAME] as string;

  // Validate tokens exist and match
  if (!cookieToken || !headerToken) {
    return res.status(403).json({
      error: 'CSRF token missing',
    });
  }

  if (cookieToken !== headerToken) {
    return res.status(403).json({
      error: 'CSRF token mismatch',
    });
  }

  next();
}

/**
 * Export cookie parser for use in app
 */
export { cookieParser };
