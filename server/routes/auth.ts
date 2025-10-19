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
router.post('/register', async (req: Request, res: Response) => {
  try {
    // Validate request body
    const validatedData = registerSchema.parse(req.body);

    // Check if user already exists
    const existingUser = await prisma.user.findFirst({
      where: {
        OR: [{ email: validatedData.email }, { username: validatedData.username }],
      },
    });

    if (existingUser) {
      if (existingUser.email === validatedData.email) {
        return res.status(400).json({ error: 'Email already registered' });
      }
      return res.status(400).json({ error: 'Username already taken' });
    }

    // Hash password
    const hashedPassword = await hashPassword(validatedData.password);

    // Create user (first user is admin, rest are regular users)
    const userCount = await prisma.user.count();
    const isFirstUser = userCount === 0;

    const user = await prisma.user.create({
      data: {
        email: validatedData.email,
        username: validatedData.username,
        password: hashedPassword,
        role: isFirstUser ? 'ADMIN' : 'USER', // First user gets admin role
      },
      select: {
        id: true,
        email: true,
        username: true,
        role: true,
        createdAt: true,
      },
    });

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
      action: AuditAction.REGISTER,
      resource: `user:${user.id}`,
      ipAddress: getClientIp(req) || null,
      userAgent: getUserAgent(req) || null,
      metadata: {
        username: user.username,
        email: user.email,
        role: user.role,
      },
    });

    logger.info('User registered', { userId: user.id, username: user.username, email: user.email });

    return res.status(201).json({
      success: true,
      user,
      ...tokens,
    });
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
router.post('/login', async (req: Request, res: Response) => {
  try {
    // Validate request body
    const validatedData = loginSchema.parse(req.body);

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
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Check if account is active
    if (!user.isActive) {
      logger.warn('Inactive account login attempt', { email: validatedData.email });
      return res.status(403).json({ error: 'Account is deactivated' });
    }

    // Verify password
    const isValidPassword = await comparePassword(validatedData.password, user.password);

    if (!isValidPassword) {
      logger.warn('Failed login attempt', { email: validatedData.email });
      return res.status(401).json({ error: 'Invalid email or password' });
    }

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

    return res.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        role: user.role,
        createdAt: user.createdAt,
      },
      ...tokens,
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
router.post('/refresh', async (req: Request, res: Response) => {
  try {
    // Validate request body
    const validatedData = refreshTokenSchema.parse(req.body);

    // Verify refresh token
    const payload = verifyToken(validatedData.refreshToken);

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

    return res.json({
      success: true,
      ...tokens,
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
  // For JWT, logout is handled client-side by deleting the token
  // This endpoint can be used for logging purposes or future session management
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    try {
      const payload = verifyToken(token);

      // Log audit event
      await logAuditEvent({
        userId: payload.userId,
        action: AuditAction.LOGOUT,
        resource: `user:${payload.userId}`,
        ipAddress: getClientIp(req) || null,
        userAgent: getUserAgent(req) || null,
        metadata: {
          username: payload.username,
        },
      });

      logger.info('User logged out', { userId: payload.userId });
    } catch {
      // Invalid token, ignore
    }
  }

  res.json({ success: true, message: 'Logged out successfully' });
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
            accessToken: tokenData.access_token,
            refreshToken: tokenData.refresh_token,
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
            accessToken: tokenData.access_token,
            refreshToken: tokenData.refresh_token,
          },
        });
      }
    } else {
      // Create new user
      const userCount = await prisma.user.count();
      const isFirstUser = userCount === 0;

      user = await prisma.user.create({
        data: {
          email: oauthUser.email,
          username: oauthUser.name || oauthUser.email.split('@')[0],
          password: await hashPassword(crypto.randomBytes(32).toString('hex')), // Random password for OAuth users
          role: isFirstUser ? 'ADMIN' : 'USER',
          oauthProviders: {
            create: {
              provider,
              providerUserId: oauthUser.id,
              accessToken: tokenData.access_token,
              refreshToken: tokenData.refresh_token,
            },
          },
        },
        include: {
          oauthProviders: true,
        },
      });

      logger.info('User created via OAuth', {
        userId: user.id,
        provider,
        email: user.email,
      });
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

    // Redirect to client with tokens
    const redirectUrl = new URL(process.env.CLIENT_URL || 'http://localhost:5173');
    redirectUrl.pathname = '/oauth-callback';
    redirectUrl.searchParams.set('accessToken', tokens.accessToken);
    redirectUrl.searchParams.set('refreshToken', tokens.refreshToken);

    return res.redirect(redirectUrl.toString());
  } catch (error) {
    logger.error('OAuth callback error', { error });
    return res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/login?error=oauth_failed`);
  }
});

export default router;
