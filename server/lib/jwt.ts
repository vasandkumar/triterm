import jwt, { SignOptions } from 'jsonwebtoken';
import crypto from 'crypto';

// JWT Secret - must be loaded from environment
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  throw new Error('FATAL: JWT_SECRET environment variable is required');
}

if (JWT_SECRET.length < 32) {
  throw new Error('FATAL: JWT_SECRET must be at least 32 characters long');
}

// Session timeout configuration
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '15m'; // 15 minutes for access token
const JWT_REFRESH_EXPIRES_IN = process.env.JWT_REFRESH_EXPIRES_IN || '7d'; // 7 days for refresh token
const ABSOLUTE_SESSION_TIMEOUT = process.env.ABSOLUTE_SESSION_TIMEOUT || '30d'; // Absolute max session duration

export interface JWTPayload {
  userId: string;
  email: string;
  username: string;
  role: string;
  // Standard JWT claims
  iat?: number; // Issued at (automatically added by jwt.sign)
  exp?: number; // Expiration time (automatically added by jwt.sign)
  jti?: string; // JWT ID for revocation tracking
  sessionStart?: number; // Track absolute session start time
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

/**
 * Generate a unique JWT ID for token tracking
 */
function generateJti(): string {
  return crypto.randomBytes(16).toString('hex');
}

/**
 * Generate an access token with enhanced security claims
 * @param payload - User data to encode in token
 * @param sessionStart - Optional session start timestamp (for absolute timeout)
 * @returns string - JWT access token
 */
export function generateAccessToken(payload: JWTPayload, sessionStart?: number): string {
  const tokenPayload = {
    ...payload,
    jti: generateJti(), // Unique token ID for revocation
    sessionStart: sessionStart || Math.floor(Date.now() / 1000), // Track session start
  };

  return jwt.sign(tokenPayload as object, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN as string | number,
  } as SignOptions);
}

/**
 * Generate a refresh token with enhanced security claims
 * @param payload - User data to encode in token
 * @param sessionStart - Session start timestamp (for absolute timeout)
 * @returns string - JWT refresh token
 */
export function generateRefreshToken(payload: JWTPayload, sessionStart?: number): string {
  const tokenPayload = {
    ...payload,
    jti: generateJti(), // Unique token ID for revocation
    sessionStart: sessionStart || Math.floor(Date.now() / 1000), // Track session start
  };

  return jwt.sign(tokenPayload as object, JWT_SECRET, {
    expiresIn: JWT_REFRESH_EXPIRES_IN as string | number,
  } as SignOptions);
}

/**
 * Generate both access and refresh tokens with shared session start
 * @param payload - User data to encode in tokens
 * @returns TokenPair - Access and refresh tokens
 */
export function generateTokenPair(payload: JWTPayload): TokenPair {
  const sessionStart = Math.floor(Date.now() / 1000);

  return {
    accessToken: generateAccessToken(payload, sessionStart),
    refreshToken: generateRefreshToken(payload, sessionStart),
  };
}

/**
 * Parse absolute session timeout duration to seconds
 */
function parseTimeoutToSeconds(timeout: string): number {
  const match = timeout.match(/^(\d+)([smhd])$/);
  if (!match) return 30 * 24 * 60 * 60; // Default 30 days

  const value = parseInt(match[1]);
  const unit = match[2];

  switch (unit) {
    case 's': return value;
    case 'm': return value * 60;
    case 'h': return value * 60 * 60;
    case 'd': return value * 24 * 60 * 60;
    default: return 30 * 24 * 60 * 60;
  }
}

/**
 * Verify and decode a JWT token with absolute session timeout check
 * @param token - JWT token to verify
 * @returns JWTPayload - Decoded token payload
 * @throws Error if token is invalid, expired, or session exceeded absolute timeout
 */
export function verifyToken(token: string): JWTPayload {
  try {
    const decoded = jwt.verify(token, JWT_SECRET) as JWTPayload;

    // Check absolute session timeout
    if (decoded.sessionStart) {
      const now = Math.floor(Date.now() / 1000);
      const sessionAge = now - decoded.sessionStart;
      const maxSessionAge = parseTimeoutToSeconds(ABSOLUTE_SESSION_TIMEOUT);

      if (sessionAge > maxSessionAge) {
        throw new Error('Session expired - absolute timeout exceeded');
      }
    }

    return decoded;
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      throw new Error('Token expired');
    }
    if (error instanceof jwt.JsonWebTokenError) {
      throw new Error('Invalid token');
    }
    if (error instanceof Error && error.message.includes('Session expired')) {
      throw error; // Re-throw session timeout errors
    }
    throw error;
  }
}

/**
 * Decode a token without verifying (useful for debugging)
 * @param token - JWT token to decode
 * @returns JWTPayload | null - Decoded token payload or null if invalid
 */
export function decodeToken(token: string): JWTPayload | null {
  try {
    return jwt.decode(token) as JWTPayload;
  } catch {
    return null;
  }
}
