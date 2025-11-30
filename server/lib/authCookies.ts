/**
 * Authentication Cookie Management
 *
 * Manages JWT tokens via httpOnly cookies for enhanced security.
 * Tokens are not accessible to JavaScript, preventing XSS token theft.
 */

import { Response } from 'express';
import { TokenPair } from './jwt.js';

// Cookie names
export const ACCESS_TOKEN_COOKIE = 'triterm_access_token';
export const REFRESH_TOKEN_COOKIE = 'triterm_refresh_token';

// Cookie configuration
// In development, we need 'lax' sameSite and no domain restriction for cross-port/cross-device access
const isDev = process.env.NODE_ENV !== 'production';

const COOKIE_CONFIG: {
  httpOnly: boolean;
  secure: boolean;
  sameSite: 'strict' | 'lax' | 'none';
  path: string;
} = {
  httpOnly: true, // Cannot be accessed by JavaScript (prevents XSS)
  secure: !isDev, // HTTPS only in production
  // 'lax' allows cookies on same-site navigations (needed for cross-port dev setup)
  // 'strict' in production for maximum CSRF protection
  sameSite: isDev ? 'lax' : 'strict',
  path: '/', // Available for all routes
  // Note: Don't set 'domain' - let browser use the request domain automatically
};

// Token expiration times (matching JWT expiration)
const ACCESS_TOKEN_MAX_AGE = 15 * 60 * 1000; // 15 minutes (matches JWT_EXPIRES_IN)
const REFRESH_TOKEN_MAX_AGE = 7 * 24 * 60 * 60 * 1000; // 7 days (matches JWT_REFRESH_EXPIRES_IN)

/**
 * Set authentication tokens in httpOnly cookies
 * @param res Express response object
 * @param tokens Access and refresh tokens
 */
export function setAuthCookies(res: Response, tokens: TokenPair): void {
  // Set access token cookie
  res.cookie(ACCESS_TOKEN_COOKIE, tokens.accessToken, {
    ...COOKIE_CONFIG,
    maxAge: ACCESS_TOKEN_MAX_AGE,
  });

  // Set refresh token cookie
  res.cookie(REFRESH_TOKEN_COOKIE, tokens.refreshToken, {
    ...COOKIE_CONFIG,
    maxAge: REFRESH_TOKEN_MAX_AGE,
  });
}

/**
 * Clear authentication cookies (for logout)
 * @param res Express response object
 */
export function clearAuthCookies(res: Response): void {
  res.clearCookie(ACCESS_TOKEN_COOKIE, COOKIE_CONFIG);
  res.clearCookie(REFRESH_TOKEN_COOKIE, COOKIE_CONFIG);
}

/**
 * Extract access token from cookies
 * @param cookies Cookie object from request
 * @returns Access token or undefined
 */
export function getAccessTokenFromCookies(cookies: Record<string, string>): string | undefined {
  return cookies[ACCESS_TOKEN_COOKIE];
}

/**
 * Extract refresh token from cookies
 * @param cookies Cookie object from request
 * @returns Refresh token or undefined
 */
export function getRefreshTokenFromCookies(cookies: Record<string, string>): string | undefined {
  return cookies[REFRESH_TOKEN_COOKIE];
}
