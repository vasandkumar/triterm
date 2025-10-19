import { Router, Response } from 'express';
import { z } from 'zod';
import prisma from '../lib/prisma.js';
import { AuthenticatedRequest, requireRole, canAccessTerminal, canControlTerminal } from '../middleware/rbac.js';
import { logAuditEvent, AuditAction, getClientIp, getUserAgent } from '../lib/auditLogger.js';
import logger from '../config/logger.js';
import { UserRole } from '@prisma/client';

const router = Router();

// Validation schemas
const shareTerminalSchema = z.object({
  userIds: z.array(z.string().uuid()).min(1).max(10),
  permission: z.enum(['VIEW', 'CONTROL']).default('VIEW'),
  expiresAt: z.string().datetime().optional(),
});

const updatePermissionSchema = z.object({
  permission: z.enum(['VIEW', 'CONTROL']),
});

/**
 * POST /api/terminals/:terminalId/share
 * Share a terminal with other users
 */
router.post('/:terminalId/share', async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const { terminalId } = req.params;
    const validatedData = shareTerminalSchema.parse(req.body);

    // Check if terminal session exists and belongs to user
    const session = await prisma.session.findUnique({
      where: { terminalId },
    });

    if (!session) {
      return res.status(404).json({ error: 'Terminal not found' });
    }

    // Check if user has permission to share this terminal
    if (session.userId !== req.user.id && req.user.role !== UserRole.ADMIN) {
      return res.status(403).json({ error: 'Only the terminal owner or admin can share it' });
    }

    // Create or update shared terminal
    let sharedTerminal = await prisma.sharedTerminal.findUnique({
      where: { terminalId },
    });

    if (!sharedTerminal) {
      sharedTerminal = await prisma.sharedTerminal.create({
        data: {
          terminalId,
          ownerId: session.userId,
          expiresAt: validatedData.expiresAt ? new Date(validatedData.expiresAt) : null,
        },
      });
    }

    // Verify all users exist
    const users = await prisma.user.findMany({
      where: {
        id: { in: validatedData.userIds },
        isActive: true,
      },
      select: { id: true, username: true },
    });

    if (users.length !== validatedData.userIds.length) {
      return res.status(400).json({ error: 'One or more users not found or inactive' });
    }

    // Grant access to users (upsert to avoid duplicates)
    const accessGrants = await Promise.all(
      users.map((user) =>
        prisma.terminalAccess.upsert({
          where: {
            sharedTerminalId_userId: {
              sharedTerminalId: sharedTerminal!.id,
              userId: user.id,
            },
          },
          update: {
            permission: validatedData.permission,
          },
          create: {
            sharedTerminalId: sharedTerminal!.id,
            userId: user.id,
            permission: validatedData.permission,
          },
        })
      )
    );

    // Audit log
    await logAuditEvent({
      userId: req.user.id,
      action: AuditAction.TERMINAL_SHARE,
      resource: terminalId,
      metadata: {
        sharedWith: users.map((u) => u.username),
        permission: validatedData.permission,
      },
      ipAddress: getClientIp(req),
      userAgent: getUserAgent(req),
    });

    logger.info('Terminal shared', {
      terminalId,
      ownerId: req.user.id,
      sharedWith: users.map((u) => u.id),
      permission: validatedData.permission,
    });

    return res.status(200).json({
      success: true,
      sharedTerminal,
      accessGrants: accessGrants.map((grant) => ({
        userId: grant.userId,
        permission: grant.permission,
        createdAt: grant.createdAt,
      })),
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: 'Validation error', details: error.issues });
    }

    logger.error('Terminal sharing error', { error });
    return res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * DELETE /api/terminals/:terminalId/share/:userId
 * Revoke access to a shared terminal
 */
router.delete('/:terminalId/share/:userId', async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const { terminalId, userId } = req.params;

    // Get shared terminal
    const sharedTerminal = await prisma.sharedTerminal.findUnique({
      where: { terminalId },
      include: { owner: true },
    });

    if (!sharedTerminal) {
      return res.status(404).json({ error: 'Shared terminal not found' });
    }

    // Check if user has permission to revoke access
    if (sharedTerminal.ownerId !== req.user.id && req.user.role !== UserRole.ADMIN) {
      return res.status(403).json({ error: 'Only the terminal owner or admin can revoke access' });
    }

    // Delete the access grant
    const deletedGrant = await prisma.terminalAccess.deleteMany({
      where: {
        sharedTerminalId: sharedTerminal.id,
        userId: userId,
      },
    });

    if (deletedGrant.count === 0) {
      return res.status(404).json({ error: 'User does not have access to this terminal' });
    }

    // Audit log
    await logAuditEvent({
      userId: req.user.id,
      action: AuditAction.TERMINAL_ACCESS_REVOKE,
      resource: terminalId,
      metadata: { revokedUserId: userId },
      ipAddress: getClientIp(req),
      userAgent: getUserAgent(req),
    });

    logger.info('Terminal access revoked', {
      terminalId,
      ownerId: req.user.id,
      revokedUserId: userId,
    });

    // Check if there are any remaining access grants
    const remainingGrants = await prisma.terminalAccess.count({
      where: { sharedTerminalId: sharedTerminal.id },
    });

    // If no more grants, delete the shared terminal entry
    if (remainingGrants === 0) {
      await prisma.sharedTerminal.delete({
        where: { id: sharedTerminal.id },
      });
    }

    return res.status(200).json({
      success: true,
      message: 'Access revoked successfully',
    });
  } catch (error) {
    logger.error('Revoke access error', { error });
    return res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /api/terminals/shared
 * Get all terminals shared with the current user
 */
router.get('/shared', async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    // Get all terminal access grants for this user
    const accessGrants = await prisma.terminalAccess.findMany({
      where: { userId: req.user.id },
      include: {
        sharedTerminal: {
          include: {
            owner: {
              select: {
                id: true,
                username: true,
                email: true,
              },
            },
          },
        },
      },
    });

    // Get corresponding sessions to check if they're still active
    const terminalIds = accessGrants.map((grant) => grant.sharedTerminal.terminalId);
    const sessions = await prisma.session.findMany({
      where: {
        terminalId: { in: terminalIds },
        active: true,
      },
    });

    const sessionMap = new Map(sessions.map((s) => [s.terminalId, s]));

    const sharedTerminals = accessGrants.map((grant) => ({
      terminalId: grant.sharedTerminal.terminalId,
      owner: grant.sharedTerminal.owner,
      permission: grant.permission,
      sharedAt: grant.createdAt,
      expiresAt: grant.sharedTerminal.expiresAt,
      active: sessionMap.has(grant.sharedTerminal.terminalId),
      session: sessionMap.get(grant.sharedTerminal.terminalId) || null,
    }));

    return res.status(200).json({
      success: true,
      sharedTerminals,
    });
  } catch (error) {
    logger.error('Get shared terminals error', { error });
    return res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /api/terminals/:terminalId/collaborators
 * Get list of users who have access to a terminal
 */
router.get('/:terminalId/collaborators', async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const { terminalId } = req.params;

    // Get shared terminal
    const sharedTerminal = await prisma.sharedTerminal.findUnique({
      where: { terminalId },
      include: {
        owner: {
          select: {
            id: true,
            username: true,
            email: true,
          },
        },
        accessGrants: {
          include: {
            user: {
              select: {
                id: true,
                username: true,
                email: true,
              },
            },
          },
        },
      },
    });

    if (!sharedTerminal) {
      return res.status(404).json({ error: 'Shared terminal not found' });
    }

    // Check if user has permission to view collaborators
    const hasAccess =
      sharedTerminal.ownerId === req.user.id ||
      req.user.role === UserRole.ADMIN ||
      sharedTerminal.accessGrants.some((grant) => grant.userId === req.user!.id);

    if (!hasAccess) {
      return res.status(403).json({ error: 'You do not have access to this terminal' });
    }

    const collaborators = sharedTerminal.accessGrants.map((grant) => ({
      userId: grant.user.id,
      username: grant.user.username,
      email: grant.user.email,
      permission: grant.permission,
      grantedAt: grant.createdAt,
    }));

    return res.status(200).json({
      success: true,
      owner: sharedTerminal.owner,
      collaborators,
      expiresAt: sharedTerminal.expiresAt,
    });
  } catch (error) {
    logger.error('Get collaborators error', { error });
    return res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * PATCH /api/terminals/:terminalId/share/:userId
 * Update permission level for a user
 */
router.patch('/:terminalId/share/:userId', async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const { terminalId, userId } = req.params;
    const validatedData = updatePermissionSchema.parse(req.body);

    // Get shared terminal
    const sharedTerminal = await prisma.sharedTerminal.findUnique({
      where: { terminalId },
    });

    if (!sharedTerminal) {
      return res.status(404).json({ error: 'Shared terminal not found' });
    }

    // Check if user has permission to update permissions
    if (sharedTerminal.ownerId !== req.user.id && req.user.role !== UserRole.ADMIN) {
      return res.status(403).json({ error: 'Only the terminal owner or admin can update permissions' });
    }

    // Update the permission
    const updatedGrant = await prisma.terminalAccess.updateMany({
      where: {
        sharedTerminalId: sharedTerminal.id,
        userId: userId,
      },
      data: {
        permission: validatedData.permission,
      },
    });

    if (updatedGrant.count === 0) {
      return res.status(404).json({ error: 'User does not have access to this terminal' });
    }

    // Audit log
    await logAuditEvent({
      userId: req.user.id,
      action: AuditAction.TERMINAL_ACCESS_GRANT,
      resource: terminalId,
      metadata: {
        targetUserId: userId,
        newPermission: validatedData.permission,
      },
      ipAddress: getClientIp(req),
      userAgent: getUserAgent(req),
    });

    logger.info('Terminal permission updated', {
      terminalId,
      ownerId: req.user.id,
      targetUserId: userId,
      newPermission: validatedData.permission,
    });

    return res.status(200).json({
      success: true,
      message: 'Permission updated successfully',
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: 'Validation error', details: error.issues });
    }

    logger.error('Update permission error', { error });
    return res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * DELETE /api/terminals/:terminalId/share
 * Unshare a terminal (remove all access grants)
 */
router.delete('/:terminalId/share', async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const { terminalId } = req.params;

    // Get shared terminal
    const sharedTerminal = await prisma.sharedTerminal.findUnique({
      where: { terminalId },
    });

    if (!sharedTerminal) {
      return res.status(404).json({ error: 'Shared terminal not found' });
    }

    // Check if user has permission to unshare
    if (sharedTerminal.ownerId !== req.user.id && req.user.role !== UserRole.ADMIN) {
      return res.status(403).json({ error: 'Only the terminal owner or admin can unshare the terminal' });
    }

    // Delete all access grants and the shared terminal
    await prisma.sharedTerminal.delete({
      where: { id: sharedTerminal.id },
    });

    // Audit log
    await logAuditEvent({
      userId: req.user.id,
      action: AuditAction.TERMINAL_UNSHARE,
      resource: terminalId,
      ipAddress: getClientIp(req),
      userAgent: getUserAgent(req),
    });

    logger.info('Terminal unshared', {
      terminalId,
      ownerId: req.user.id,
    });

    return res.status(200).json({
      success: true,
      message: 'Terminal unshared successfully',
    });
  } catch (error) {
    logger.error('Unshare terminal error', { error });
    return res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
