import express from 'express';
import { prisma } from '../lib/prisma.js';
import { requireAdmin } from '../middleware/rbac.js';
import { logAuditEvent } from '../lib/auditLogger.js';
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
    if (id === req.user?.id) {
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
      userId: req.user!.id,
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
    if (id === req.user?.id) {
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

    // Delete user (cascades to sessions, recordings, audit logs)
    await prisma.user.delete({
      where: { id },
    });

    // Log the action
    await logAuditEvent({
      userId: req.user!.id,
      action: 'DELETE_USER',
      resource: `user:${id}`,
      ipAddress: req.ip || null,
      userAgent: req.get('user-agent') || null,
      metadata: {
        deletedUserId: id,
        deletedUsername: user.username,
        deletedEmail: user.email,
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

export default router;
