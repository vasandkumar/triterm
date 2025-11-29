import { Router, Request, Response } from 'express';
import { z } from 'zod';
import crypto from 'crypto';
import prisma from '../lib/prisma.js';
import { hashPassword, comparePassword } from '../lib/password.js';
import { generateTokenPair, verifyToken } from '../lib/jwt.js';
import { registerSchema, loginSchema, refreshTokenSchema } from '../lib/validation.js';
import { oauthService } from '../lib/oauthProviders.js';
import logger from '../config/logger.js';
import { logAuditEvent, AuditAction, getClientIp, getUserAgent } from '../lib/auditLogger.js';
import { encryptToken, decryptToken } from '../lib/encryption.js';
import {
  isAccountLocked,
  recordFailedAttempt,
  clearLoginAttempts,
} from '../lib/loginAttempts.js';
import {
  loginRateLimiter,
  registerRateLimiter,
  tokenRefreshRateLimiter,
} from '../middleware/rateLimiter.js';
import { setAuthCookies, clearAuthCookies, getRefreshTokenFromCookies, getAccessTokenFromCookies } from '../lib/authCookies.js';
import { revokeToken } from '../lib/tokenRevocation.js';

const router = Router();

// Store OAuth state tokens (in production, use Redis or database)
const oauthStates = new Map<string, { timestamp: number; provider: string }>();

// Clean up expired state tokens every 10 minutes
setInterval(() => {
  const now = Date.now();
  for (const [state, data] of oauthStates.entries()) {
    if (now - data.timestamp > 10 * 60 * 1000) {
      // 10 minutes
      oauthStates.delete(state);
    }
  }
}, 10 * 60 * 1000);

/**
 * POST /api/auth/register
 * Register a new user
 */
router.post('/register', registerRateLimiter, async (req: Request, res: Response) => {
  try {
    // Validate request body
    const validatedData = registerSchema.parse(req.body);

    // Check if this is the first user
    const userCount = await prisma.user.count();
    const isFirstUser = userCount === 0;

    // Check if signup is enabled (only for non-first users)
    if (!isFirstUser) {
      // Get system settings
      const settings = await prisma.systemSettings.findUnique({
        where: { id: 'singleton' },
      });

      if (!settings || !settings.signupEnabled) {
        return res.status(403).json({
          error: 'Signup is currently disabled',
          message: 'New user registration is disabled. Please contact the administrator for access.',
        });
      }
    }

    // Check if user already exists
    const existingUser = await prisma.user.findFirst({
      where: {
        OR: [{ email: validatedData.email }, { username: validatedData.username }],
      },
    });

    if (existingUser) {
      // Generic error message to prevent user enumeration
      // Don't reveal whether email or username is taken
      logger.warn('Registration attempt with existing credentials', {
        email: validatedData.email,
        username: validatedData.username,
        conflictType: existingUser.email === validatedData.email ? 'email' : 'username',
      });

      return res.status(400).json({
        error: 'Registration failed',
        message: 'An account with these credentials already exists. If you already have an account, please login instead.',
      });
    }

    // Hash password
    const hashedPassword = await hashPassword(validatedData.password);

    // Create user
    // First user: admin role, active immediately
    // Other users: user role, inactive until admin approves
    const user = await prisma.user.create({
      data: {
        email: validatedData.email,
        username: validatedData.username,
        password: hashedPassword,
        role: isFirstUser ? 'ADMIN' : 'USER',
        isActive: isFirstUser, // Only first user is active immediately
      },
      select: {
        id: true,
        email: true,
        username: true,
        role: true,
        isActive: true,
        createdAt: true,
      },
    });

    // If first user, create system settings and disable signup
    if (isFirstUser) {
      await prisma.systemSettings.upsert({
        where: { id: 'singleton' },
        create: {
          id: 'singleton',
          signupEnabled: false, // Disable signup after first user
          updatedBy: user.id,
        },
        update: {
          signupEnabled: false,
          updatedBy: user.id,
        },
      });

      logger.info('First user registered - signup disabled', { userId: user.id });
    }

    // Generate tokens only for active users (first user)
    // Non-active users will get tokens after admin approval
    const tokens = isFirstUser
      ? generateTokenPair({
          userId: user.id,
          email: user.email,
          username: user.username,
          role: user.role,
        })
      : { accessToken: null, refreshToken: null };

    // Log audit event
    await logAuditEvent({
      userId: user.id,
      action: AuditAction.REGISTER,
      resource: `user:${user.id}`,
      ipAddress: getClientIp(req) || null,
      userAgent: getUserAgent(req) || null,
      metadata: {
        username: user.username,
        email: user.email,
        role: user.role,
        isActive: user.isActive,
        isFirstUser,
      },
    });

    logger.info('User registered', {
      userId: user.id,
      username: user.username,
      email: user.email,
      isActive: user.isActive,
      isFirstUser,
    });

    // Return different responses based on user status
    if (isFirstUser) {
      // Set tokens in httpOnly cookies for first user (auto-approved)
      setAuthCookies(res, tokens);

      return res.status(201).json({
        success: true,
        user,
      });
    } else {
      return res.status(201).json({
        success: true,
        user,
        message: 'Account created successfully. Your account is pending admin approval. You will be able to login once approved.',
        pendingApproval: true,
      });
    }
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: 'Validation error', details: error.issues });
    }

    logger.error('Registration error', { error });
    return res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * POST /api/auth/login
 * Login with email and password
 */
router.post('/login', loginRateLimiter, async (req: Request, res: Response) => {
  try {
    // Validate request body
    const validatedData = loginSchema.parse(req.body);

    // Check if account is locked due to too many failed attempts
    const lockStatus = isAccountLocked(validatedData.email);
    if (lockStatus.locked) {
      logger.warn('Login attempt on locked account', {
        email: validatedData.email,
        remainingSeconds: lockStatus.remainingSeconds,
      });

      return res.status(429).json({
        error: 'Account temporarily locked',
        message: 'Too many failed login attempts. Please try again later.',
        retryAfter: lockStatus.remainingSeconds,
      });
    }

    // Find user
    const user = await prisma.user.findUnique({
      where: { email: validatedData.email },
      select: {
        id: true,
        email: true,
        username: true,
        password: true,
        role: true,
        isActive: true,
        createdAt: true,
      },
    });

    if (!user) {
      // Record failed attempt (user not found)
      const attemptResult = recordFailedAttempt(validatedData.email);

      // Log failed attempt
      await logAuditEvent({
        userId: null,
        action: AuditAction.LOGIN_FAILED,
        resource: 'auth:login',
        ipAddress: getClientIp(req) || null,
        userAgent: getUserAgent(req) || null,
        metadata: {
          email: validatedData.email,
          reason: 'user_not_found',
          attemptsRemaining: attemptResult.attemptsRemaining,
        },
      });

      logger.warn('Failed login attempt - user not found', { email: validatedData.email });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check if account is active
    if (!user.isActive) {
      logger.warn('Inactive account login attempt', { email: validatedData.email });

      await logAuditEvent({
        userId: user.id,
        action: AuditAction.LOGIN_FAILED,
        resource: `user:${user.id}`,
        ipAddress: getClientIp(req) || null,
        userAgent: getUserAgent(req) || null,
        metadata: {
          email: validatedData.email,
          reason: 'account_inactive',
        },
      });

      return res.status(403).json({
        error: 'Account is pending approval or has been deactivated',
      });
    }

    // Verify password
    const isValidPassword = await comparePassword(validatedData.password, user.password);

    if (!isValidPassword) {
      // Record failed attempt
      const attemptResult = recordFailedAttempt(validatedData.email);

      // Log failed attempt
      await logAuditEvent({
        userId: user.id,
        action: AuditAction.LOGIN_FAILED,
        resource: `user:${user.id}`,
        ipAddress: getClientIp(req) || null,
        userAgent: getUserAgent(req) || null,
        metadata: {
          email: validatedData.email,
          reason: 'invalid_password',
          attemptsRemaining: attemptResult.attemptsRemaining,
          locked: attemptResult.locked,
        },
      });

      // If account is now locked, log lockout event
      if (attemptResult.locked) {
        await logAuditEvent({
          userId: user.id,
          action: AuditAction.ACCOUNT_LOCKED,
          resource: `user:${user.id}`,
          ipAddress: getClientIp(req) || null,
          userAgent: getUserAgent(req) || null,
          metadata: {
            email: validatedData.email,
            lockoutDuration: attemptResult.lockoutDuration,
            reason: 'too_many_failed_attempts',
          },
        });

        logger.warn('Account locked due to failed login attempts', {
          userId: user.id,
          email: validatedData.email,
        });

        return res.status(429).json({
          error: 'Account temporarily locked',
          message: 'Too many failed login attempts. Please try again later.',
          retryAfter: attemptResult.lockoutDuration,
        });
      }

      logger.warn('Failed login attempt - invalid password', {
        userId: user.id,
        email: validatedData.email,
        attemptsRemaining: attemptResult.attemptsRemaining,
      });

      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Clear any failed login attempts on successful login
    clearLoginAttempts(validatedData.email);

    // Generate tokens
    const tokens = generateTokenPair({
      userId: user.id,
      email: user.email,
      username: user.username,
      role: user.role,
    });

    // Log audit event
    await logAuditEvent({
      userId: user.id,
      action: AuditAction.LOGIN,
      resource: `user:${user.id}`,
      ipAddress: getClientIp(req) || null,
      userAgent: getUserAgent(req) || null,
      metadata: {
        username: user.username,
        email: user.email,
        role: user.role,
      },
    });

    logger.info('User logged in', { userId: user.id, username: user.username, role: user.role });

    // Set tokens in httpOnly cookies (secure, not accessible to JavaScript)
    setAuthCookies(res, tokens);

    return res.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        role: user.role,
        isActive: user.isActive,
        createdAt: user.createdAt,
      },
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: 'Validation error', details: error.issues });
    }

    logger.error('Login error', { error });
    return res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * POST /api/auth/refresh
 * Refresh access token using refresh token
 */
router.post('/refresh', tokenRefreshRateLimiter, async (req: Request, res: Response) => {
  try {
    // Get refresh token from httpOnly cookie
    const refreshToken = getRefreshTokenFromCookies(req.cookies || {});

    if (!refreshToken) {
      return res.status(401).json({ error: 'No refresh token provided' });
    }

    // Verify refresh token
    const payload = verifyToken(refreshToken);

    // Verify user still exists and is active
    const user = await prisma.user.findUnique({
      where: { id: payload.userId },
      select: {
        id: true,
        email: true,
        username: true,
        role: true,
        isActive: true,
      },
    });

    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }

    if (!user.isActive) {
      return res.status(403).json({ error: 'Account is deactivated' });
    }

    // Generate new tokens
    const tokens = generateTokenPair({
      userId: user.id,
      email: user.email,
      username: user.username,
      role: user.role,
    });

    // Log audit event
    await logAuditEvent({
      userId: user.id,
      action: AuditAction.TOKEN_REFRESH,
      resource: `user:${user.id}`,
      ipAddress: getClientIp(req) || null,
      userAgent: getUserAgent(req) || null,
      metadata: {
        username: user.username,
      },
    });

    logger.info('Token refreshed', { userId: user.id });

    // Set new tokens in httpOnly cookies
    setAuthCookies(res, tokens);

    return res.json({
      success: true,
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: 'Validation error', details: error.issues });
    }

    if (error instanceof Error && (error.message === 'Token expired' || error.message === 'Invalid token')) {
      return res.status(401).json({ error: error.message });
    }

    logger.error('Token refresh error', { error });
    return res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /api/auth/me
 * Get current user information
 */
router.get('/me', async (req: Request, res: Response) => {
  try {
    // Get token from Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.substring(7);

    // Verify token
    const payload = verifyToken(token);

    // Get user
    const user = await prisma.user.findUnique({
      where: { id: payload.userId },
      select: {
        id: true,
        email: true,
        username: true,
        role: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    return res.json({
      success: true,
      user,
    });
  } catch (error) {
    if (error instanceof Error && (error.message === 'Token expired' || error.message === 'Invalid token')) {
      return res.status(401).json({ error: error.message });
    }

    logger.error('Get user error', { error });
    return res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * POST /api/auth/logout
 * Logout (client-side token deletion, placeholder for future session management)
 */
router.post('/logout', async (req: Request, res: Response) => {
  try {
    let accessToken: string | undefined;
    let refreshToken: string | undefined;

    // Try to get access token from cookie or header
    accessToken = getAccessTokenFromCookies(req.cookies || {});
    if (!accessToken) {
      const authHeader = req.headers.authorization;
      if (authHeader && authHeader.startsWith('Bearer ')) {
        accessToken = authHeader.substring(7);
      }
    }

    // Get refresh token from cookie
    refreshToken = getRefreshTokenFromCookies(req.cookies || {});

    if (accessToken) {
      try {
        const payload = verifyToken(accessToken);

        // Revoke access token
        revokeToken(
          accessToken,
          payload.userId,
          new Date(payload.exp * 1000), // Convert Unix timestamp to Date
          'logout'
        );

        // Revoke refresh token if present
        if (refreshToken) {
          try {
            const refreshPayload = verifyToken(refreshToken);
            revokeToken(
              refreshToken,
              refreshPayload.userId,
              new Date(refreshPayload.exp * 1000),
              'logout'
            );
          } catch {
            // Refresh token invalid, ignore
          }
        }

        // Log audit event
        await logAuditEvent({
          userId: payload.userId,
          action: AuditAction.LOGOUT,
          resource: `user:${payload.userId}`,
          ipAddress: getClientIp(req) || null,
          userAgent: getUserAgent(req) || null,
          metadata: {
            username: payload.username,
            tokensRevoked: refreshToken ? 2 : 1,
          },
        });

        logger.info('User logged out', {
          userId: payload.userId,
          tokensRevoked: refreshToken ? 2 : 1,
        });
      } catch {
        // Invalid token, ignore but still clear cookies
      }
    }

    // Clear authentication cookies
    clearAuthCookies(res);

    res.json({ success: true, message: 'Logged out successfully' });
  } catch (error) {
    logger.error('Logout error', { error });
    // Clear cookies even if there's an error
    clearAuthCookies(res);
    res.json({ success: true, message: 'Logged out successfully' });
  }
});

/**
 * GET /api/auth/signup-status
 * Check if signup is currently enabled
 */
router.get('/signup-status', async (req: Request, res: Response) => {
  try {
    // Check if any users exist
    const userCount = await prisma.user.count();
    const isFirstUser = userCount === 0;

    // If no users exist, signup is always enabled for first user
    if (isFirstUser) {
      return res.json({
        success: true,
        signupEnabled: true,
        isFirstUser: true,
        message: 'Create your admin account to get started',
      });
    }

    // Get system settings
    const settings = await prisma.systemSettings.findUnique({
      where: { id: 'singleton' },
    });

    return res.json({
      success: true,
      signupEnabled: settings?.signupEnabled || false,
      isFirstUser: false,
      message: settings?.signupEnabled
        ? 'Signup is currently enabled'
        : 'Signup is currently disabled. Contact administrator for access.',
    });
  } catch (error) {
    logger.error('Error checking signup status', { error });
    return res.status(500).json({ error: 'Failed to check signup status' });
  }
});

/**
 * GET /api/auth/oauth/providers
 * Get list of available OAuth providers
 */
router.get('/oauth/providers', (req: Request, res: Response) => {
  const providers = oauthService.getAvailableProviders();
  res.json({ success: true, providers });
});

/**
 * GET /api/auth/oauth/:provider
 * Initiate OAuth flow with provider
 */
router.get('/oauth/:provider', (req: Request, res: Response) => {
  try {
    const { provider } = req.params;

    // Generate random state for CSRF protection
    const state = crypto.randomBytes(32).toString('hex');
    oauthStates.set(state, { timestamp: Date.now(), provider });

    // Get authorization URL
    const authUrl = oauthService.getAuthorizationUrl(provider, state);

    if (!authUrl) {
      return res.status(404).json({ error: 'OAuth provider not found or not configured' });
    }

    logger.info('OAuth flow initiated', { provider, state });

    // Redirect to OAuth provider
    return res.redirect(authUrl);
  } catch (error) {
    logger.error('OAuth initiation error', { error });
    return res.status(500).json({ error: 'Failed to initiate OAuth flow' });
  }
});

/**
 * GET /api/auth/oauth/callback
 * Handle OAuth callback from provider
 */
router.get('/oauth/callback', async (req: Request, res: Response) => {
  try {
    const { code, state, error: oauthError } = req.query;

    // Check for OAuth errors
    if (oauthError) {
      logger.warn('OAuth error from provider', { error: oauthError });
      return res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/login?error=oauth_failed`);
    }

    // Validate parameters
    if (!code || !state || typeof code !== 'string' || typeof state !== 'string') {
      return res.status(400).json({ error: 'Invalid OAuth callback parameters' });
    }

    // Verify state (CSRF protection)
    const stateData = oauthStates.get(state);
    if (!stateData) {
      logger.warn('Invalid OAuth state', { state });
      return res.status(400).json({ error: 'Invalid or expired state parameter' });
    }

    // Delete used state
    oauthStates.delete(state);

    const { provider } = stateData;

    // Exchange code for access token
    const tokenData = await oauthService.exchangeCodeForToken(provider, code);
    if (!tokenData) {
      logger.error('Failed to exchange OAuth code for token', { provider });
      return res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/login?error=oauth_failed`);
    }

    // Get user info from provider
    const oauthUser = await oauthService.getUserInfo(provider, tokenData.access_token);
    if (!oauthUser) {
      logger.error('Failed to get OAuth user info', { provider });
      return res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/login?error=oauth_failed`);
    }

    logger.info('OAuth user info retrieved', {
      provider,
      oauthUserId: oauthUser.id,
      email: oauthUser.email,
    });

    // Find or create user
    let user = await prisma.user.findFirst({
      where: {
        OR: [
          { email: oauthUser.email },
          {
            oauthProviders: {
              some: {
                provider,
                providerUserId: oauthUser.id,
              },
            },
          },
        ],
      },
      include: {
        oauthProviders: true,
      },
    });

    if (user) {
      // Check if this OAuth provider is already linked
      const hasProvider = user.oauthProviders.some(
        (p) => p.provider === provider && p.providerUserId === oauthUser.id
      );

      if (!hasProvider) {
        // Link OAuth provider to existing user
        await prisma.oAuthProvider.create({
          data: {
            userId: user.id,
            provider,
            providerUserId: oauthUser.id,
            accessToken: encryptToken(tokenData.access_token),
            refreshToken: tokenData.refresh_token ? encryptToken(tokenData.refresh_token) : null,
          },
        });

        logger.info('OAuth provider linked to existing user', {
          userId: user.id,
          provider,
        });
      } else {
        // Update tokens
        await prisma.oAuthProvider.updateMany({
          where: {
            userId: user.id,
            provider,
            providerUserId: oauthUser.id,
          },
          data: {
            accessToken: encryptToken(tokenData.access_token),
            refreshToken: tokenData.refresh_token ? encryptToken(tokenData.refresh_token) : null,
          },
        });
      }
    } else {
      // Create new user via OAuth
      const userCount = await prisma.user.count();
      const isFirstUser = userCount === 0;

      // Check if signup is enabled (only for non-first users)
      if (!isFirstUser) {
        const settings = await prisma.systemSettings.findUnique({
          where: { id: 'singleton' },
        });

        if (!settings || !settings.signupEnabled) {
          return res.redirect(
            `${process.env.CLIENT_URL || 'http://localhost:5173'}/login?error=signup_disabled`
          );
        }
      }

      user = await prisma.user.create({
        data: {
          email: oauthUser.email,
          username: oauthUser.name || oauthUser.email.split('@')[0],
          password: await hashPassword(crypto.randomBytes(32).toString('hex')), // Random password for OAuth users
          role: isFirstUser ? 'ADMIN' : 'USER',
          isActive: isFirstUser, // Only first user is active immediately
          oauthProviders: {
            create: {
              provider,
              providerUserId: oauthUser.id,
              accessToken: encryptToken(tokenData.access_token),
              refreshToken: tokenData.refresh_token ? encryptToken(tokenData.refresh_token) : null,
            },
          },
        },
        include: {
          oauthProviders: true,
        },
      });

      // If first user, disable signup
      if (isFirstUser) {
        await prisma.systemSettings.upsert({
          where: { id: 'singleton' },
          create: {
            id: 'singleton',
            signupEnabled: false,
            updatedBy: user.id,
          },
          update: {
            signupEnabled: false,
            updatedBy: user.id,
          },
        });
      }

      logger.info('User created via OAuth', {
        userId: user.id,
        provider,
        email: user.email,
        isActive: user.isActive,
        isFirstUser,
      });

      // If user is not active (pending approval), redirect with pending message
      if (!user.isActive) {
        return res.redirect(
          `${process.env.CLIENT_URL || 'http://localhost:5173'}/login?pendingApproval=true`
        );
      }
    }

    // Generate JWT tokens
    const tokens = generateTokenPair({
      userId: user.id,
      email: user.email,
      username: user.username,
      role: user.role,
    });

    // Log audit event
    await logAuditEvent({
      userId: user.id,
      action: AuditAction.LOGIN,
      resource: `user:${user.id}`,
      ipAddress: getClientIp(req) || null,
      userAgent: getUserAgent(req) || null,
      metadata: {
        username: user.username,
        email: user.email,
        role: user.role,
        provider,
        loginMethod: 'oauth',
      },
    });

    // Set tokens in httpOnly cookies (secure, not exposed in URL)
    setAuthCookies(res, tokens);

    // Redirect to client OAuth callback (tokens now in cookies)
    return res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/oauth-callback`);
  } catch (error) {
    logger.error('OAuth callback error', { error });
    return res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/login?error=oauth_failed`);
  }
});

export default router;
