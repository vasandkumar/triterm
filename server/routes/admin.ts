import express from 'express';
import { prisma } from '../lib/prisma.js';
import { requireAdmin } from '../middleware/rbac.js';
import { logAuditEvent } from '../lib/auditLogger.js';
import { revokeAllUserTokens } from '../lib/tokenRevocation.js';
import { adminCreateUserSchema } from '../lib/validation.js';
import bcrypt from 'bcrypt';
import os from 'os';

const router = express.Router();

// Apply admin-only middleware to all routes
router.use(requireAdmin);

/**
 * GET /api/admin/users
 * Get all users
 */
router.get('/users', async (req, res) => {
  try {
    const users = await prisma.user.findMany({
      select: {
        id: true,
        username: true,
        email: true,
        role: true,
        isActive: true,
        createdAt: true,
        updatedAt: true,
      },
      orderBy: {
        createdAt: 'desc',
      },
    });

    res.json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

/**
 * POST /api/admin/users
 * Create a new user (admin only)
 */
router.post('/users', async (req, res) => {
  try {
    // Validate input
    const validationResult = adminCreateUserSchema.safeParse(req.body);
    if (!validationResult.success) {
      const errorMessages = validationResult.error.issues.map(issue => issue.message);
      return res.status(400).json({
        error: 'Validation failed',
        details: errorMessages,
      });
    }

    const { email, username, password, role, isActive } = validationResult.data;

    // Check if user already exists
    const existingUser = await prisma.user.findFirst({
      where: {
        OR: [{ email: email.toLowerCase() }, { username: username.toLowerCase() }],
      },
    });

    if (existingUser) {
      if (existingUser.email.toLowerCase() === email.toLowerCase()) {
        return res.status(409).json({ error: 'Email already registered' });
      }
      if (existingUser.username.toLowerCase() === username.toLowerCase()) {
        return res.status(409).json({ error: 'Username already taken' });
      }
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create user
    const user = await prisma.user.create({
      data: {
        email: email.toLowerCase(),
        username,
        password: hashedPassword,
        role,
        isActive,
      },
      select: {
        id: true,
        username: true,
        email: true,
        role: true,
        isActive: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    // Log the action
    await logAuditEvent({
      userId: req.user!.userId,
      action: 'CREATE_USER',
      resource: `user:${user.id}`,
      ipAddress: req.ip || null,
      userAgent: req.get('user-agent') || null,
      metadata: {
        createdUserId: user.id,
        createdUsername: user.username,
        createdEmail: user.email,
        assignedRole: role,
        isActive,
        createdBy: 'admin',
      },
    });

    res.status(201).json(user);
  } catch (error: any) {
    console.error('Error creating user:', error);
    if (error.code === 'P2002') {
      // Unique constraint violation
      return res.status(409).json({ error: 'User with this email or username already exists' });
    }
    res.status(500).json({ error: 'Failed to create user' });
  }
});

/**
 * PATCH /api/admin/users/:id
 * Update user role
 */
router.patch('/users/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { role } = req.body;

    if (!role || !['USER', 'ADMIN'].includes(role)) {
      return res.status(400).json({ error: 'Invalid role. Must be USER or ADMIN' });
    }

    // Prevent changing own role
    if (id === req.user?.userId) {
      return res.status(403).json({ error: 'Cannot change your own role' });
    }

    const user = await prisma.user.update({
      where: { id },
      data: { role },
      select: {
        id: true,
        username: true,
        email: true,
        role: true,
        isActive: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    // Log the action
    await logAuditEvent({
      userId: req.user!.userId,
      action: 'UPDATE_USER',
      resource: `user:${id}`,
      ipAddress: req.ip || null,
      userAgent: req.get('user-agent') || null,
      metadata: {
        targetUserId: id,
        targetUsername: user.username,
        newRole: role,
      },
    });

    res.json(user);
  } catch (error: any) {
    console.error('Error updating user:', error);
    if (error.code === 'P2025') {
      return res.status(404).json({ error: 'User not found' });
    }
    res.status(500).json({ error: 'Failed to update user' });
  }
});

/**
 * DELETE /api/admin/users/:id
 * Delete user and all associated data
 */
router.delete('/users/:id', async (req, res) => {
  try {
    const { id } = req.params;

    // Prevent deleting own account
    if (id === req.user?.userId) {
      return res.status(403).json({ error: 'Cannot delete your own account' });
    }

    // Get user info before deletion for audit log
    const user = await prisma.user.findUnique({
      where: { id },
      select: { username: true, email: true },
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Revoke all active tokens for this user before deletion
    const revokedTokenCount = revokeAllUserTokens(id, 'admin_action');

    // Delete user (cascades to sessions, recordings, audit logs)
    await prisma.user.delete({
      where: { id },
    });

    // Log the action
    await logAuditEvent({
      userId: req.user!.userId,
      action: 'DELETE_USER',
      resource: `user:${id}`,
      ipAddress: req.ip || null,
      userAgent: req.get('user-agent') || null,
      metadata: {
        deletedUserId: id,
        deletedUsername: user.username,
        deletedEmail: user.email,
        tokensRevoked: revokedTokenCount,
      },
    });

    res.json({ success: true });
  } catch (error: any) {
    console.error('Error deleting user:', error);
    if (error.code === 'P2025') {
      return res.status(404).json({ error: 'User not found' });
    }
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

/**
 * GET /api/admin/audit-logs
 * Get audit logs with optional filters
 */
router.get('/audit-logs', async (req, res) => {
  try {
    const { action, userId, limit = '100' } = req.query;

    const where: any = {};
    if (action && typeof action === 'string') {
      where.action = action;
    }
    if (userId && typeof userId === 'string') {
      where.userId = userId;
    }

    const logs = await prisma.auditLog.findMany({
      where,
      include: {
        user: {
          select: {
            username: true,
            email: true,
          },
        },
      },
      orderBy: {
        createdAt: 'desc',
      },
      take: Math.min(parseInt(limit as string), 500), // Max 500 entries
    });

    res.json(logs);
  } catch (error) {
    console.error('Error fetching audit logs:', error);
    res.status(500).json({ error: 'Failed to fetch audit logs' });
  }
});

/**
 * GET /api/admin/sessions
 * Get all terminal sessions with user info
 */
router.get('/sessions', async (req, res) => {
  try {
    const { active } = req.query;

    const where: any = {};
    if (active === 'true') {
      where.active = true;
    }

    const sessions = await prisma.session.findMany({
      where,
      include: {
        user: {
          select: {
            username: true,
            email: true,
          },
        },
      },
      orderBy: {
        lastActivityAt: 'desc',
      },
    });

    res.json(sessions);
  } catch (error) {
    console.error('Error fetching sessions:', error);
    res.status(500).json({ error: 'Failed to fetch sessions' });
  }
});

/**
 * GET /api/admin/stats
 * Get system statistics
 */
router.get('/stats', async (req, res) => {
  try {
    // Get user statistics
    const totalUsers = await prisma.user.count();

    // Count active users based on recent sessions (users with activity in last 30 days)
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const recentSessions = await prisma.session.groupBy({
      by: ['userId'],
      where: {
        lastActivityAt: {
          gte: thirtyDaysAgo,
        },
      },
    });
    const activeUsers = recentSessions.length;

    // Get session statistics
    const [totalSessions, activeSessions] = await Promise.all([
      prisma.session.count(),
      prisma.session.count({
        where: {
          active: true,
        },
      }),
    ]);

    // Get recent audit events (last 24 hours)
    const recentAuditEvents = await prisma.auditLog.count({
      where: {
        createdAt: {
          gte: new Date(Date.now() - 24 * 60 * 60 * 1000),
        },
      },
    });

    // System information
    const uptime = process.uptime();
    const totalMemory = os.totalmem();
    const freeMemory = os.freemem();
    const cpuUsage = process.cpuUsage();
    const loadAverage = os.loadavg();

    // Calculate CPU usage percentage (approximate)
    const cpuPercent = (cpuUsage.user + cpuUsage.system) / 1000000 / uptime / os.cpus().length;

    res.json({
      totalUsers,
      activeUsers,
      activeSessions,
      totalSessions,
      recentAuditEvents,
      uptime,
      system: {
        platform: os.platform(),
        arch: os.arch(),
        nodeVersion: process.version,
        cpuUsage: Math.min(cpuPercent, 1), // Normalize to 0-1
        memoryUsage: (totalMemory - freeMemory) / totalMemory, // 0-1
        totalMemory,
        freeMemory,
        loadAverage,
      },
    });
  } catch (error) {
    console.error('Error fetching system stats:', error);
    res.status(500).json({ error: 'Failed to fetch system statistics' });
  }
});

/**
 * GET /api/admin/pending-users
 * Get all users pending approval (isActive = false)
 */
router.get('/pending-users', async (req, res) => {
  try {
    const pendingUsers = await prisma.user.findMany({
      where: {
        isActive: false,
      },
      select: {
        id: true,
        username: true,
        email: true,
        role: true,
        isActive: true,
        createdAt: true,
        updatedAt: true,
      },
      orderBy: {
        createdAt: 'desc',
      },
    });

    res.json(pendingUsers);
  } catch (error) {
    console.error('Error fetching pending users:', error);
    res.status(500).json({ error: 'Failed to fetch pending users' });
  }
});

/**
 * PATCH /api/admin/users/:id/activate
 * Activate a user account
 */
router.patch('/users/:id/activate', async (req, res) => {
  try {
    const { id } = req.params;

    const user = await prisma.user.update({
      where: { id },
      data: { isActive: true },
      select: {
        id: true,
        username: true,
        email: true,
        role: true,
        isActive: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    // Log the action
    await logAuditEvent({
      userId: req.user!.userId,
      action: 'ACTIVATE_USER',
      resource: `user:${id}`,
      ipAddress: req.ip || null,
      userAgent: req.get('user-agent') || null,
      metadata: {
        targetUserId: id,
        targetUsername: user.username,
        targetEmail: user.email,
      },
    });

    res.json(user);
  } catch (error: any) {
    console.error('Error activating user:', error);
    if (error.code === 'P2025') {
      return res.status(404).json({ error: 'User not found' });
    }
    res.status(500).json({ error: 'Failed to activate user' });
  }
});

/**
 * PATCH /api/admin/users/:id/deactivate
 * Deactivate a user account
 */
router.patch('/users/:id/deactivate', async (req, res) => {
  try {
    const { id } = req.params;

    // Prevent deactivating own account
    if (id === req.user?.userId) {
      return res.status(403).json({ error: 'Cannot deactivate your own account' });
    }

    const user = await prisma.user.update({
      where: { id },
      data: { isActive: false },
      select: {
        id: true,
        username: true,
        email: true,
        role: true,
        isActive: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    // Revoke all active tokens for this user (immediate logout)
    const revokedTokenCount = revokeAllUserTokens(id, 'user_deactivated');

    // Log the action
    await logAuditEvent({
      userId: req.user!.userId,
      action: 'DEACTIVATE_USER',
      resource: `user:${id}`,
      ipAddress: req.ip || null,
      userAgent: req.get('user-agent') || null,
      metadata: {
        targetUserId: id,
        targetUsername: user.username,
        targetEmail: user.email,
        tokensRevoked: revokedTokenCount,
      },
    });

    res.json(user);
  } catch (error: any) {
    console.error('Error deactivating user:', error);
    if (error.code === 'P2025') {
      return res.status(404).json({ error: 'User not found' });
    }
    res.status(500).json({ error: 'Failed to deactivate user' });
  }
});

/**
 * GET /api/admin/settings
 * Get system settings
 */
router.get('/settings', async (req, res) => {
  try {
    let settings = await prisma.systemSettings.findUnique({
      where: { id: 'singleton' },
    });

    // If settings don't exist, create default
    if (!settings) {
      settings = await prisma.systemSettings.create({
        data: {
          id: 'singleton',
          signupEnabled: false,
        },
      });
    }

    res.json(settings);
  } catch (error) {
    console.error('Error fetching settings:', error);
    res.status(500).json({ error: 'Failed to fetch system settings' });
  }
});

/**
 * PATCH /api/admin/settings/signup
 * Toggle signup enabled/disabled
 */
router.patch('/settings/signup', async (req, res) => {
  try {
    const { enabled } = req.body;

    if (typeof enabled !== 'boolean') {
      return res.status(400).json({ error: 'enabled must be a boolean' });
    }

    const settings = await prisma.systemSettings.upsert({
      where: { id: 'singleton' },
      create: {
        id: 'singleton',
        signupEnabled: enabled,
        updatedBy: req.user!.userId,
      },
      update: {
        signupEnabled: enabled,
        updatedBy: req.user!.userId,
      },
    });

    // Log the action
    await logAuditEvent({
      userId: req.user!.userId,
      action: enabled ? 'ENABLE_SIGNUP' : 'DISABLE_SIGNUP',
      resource: 'system:settings',
      ipAddress: req.ip || null,
      userAgent: req.get('user-agent') || null,
      metadata: {
        signupEnabled: enabled,
      },
    });

    res.json(settings);
  } catch (error) {
    console.error('Error updating signup settings:', error);
    res.status(500).json({ error: 'Failed to update signup settings' });
  }
});

export default router;
