/**
 * External Share Link API Routes
 *
 * Handles public terminal sharing with comprehensive security features:
 * - Share link creation and management
 * - Join request validation and processing
 * - Approval workflow
 * - Statistics and audit logs
 */

import { Router, Request, Response } from 'express';
import { z } from 'zod';
import prisma from '../lib/prisma.js';
import { AuthenticatedRequest } from '../middleware/rbac.js';
import { authenticateToken } from '../middleware/auth.js';
import { logAuditEvent, AuditAction, getClientIp, getUserAgent } from '../lib/auditLogger.js';
import logger from '../config/logger.js';
import {
  createShareLink,
  validateJoinRequest,
  createPendingConnection,
  approveConnection,
  rejectConnection,
  blockIP,
  getShareLinkStats,
} from '../lib/shareLinkManager.js';
import { emitToShareLinkOwner } from '../lib/socketManager.js';
import {
  createShareLinkLimiter,
  joinRequestLimiter,
  getShareSettingsLimiter,
  approveRejectLimiter,
  shareManagementLimiter,
  blockIPLimiter,
  deactivateShareLimiter,
} from '../middleware/rateLimiter.js';
import {
  validateJoinRequestData,
  validateIPList,
  validateShareCode,
  detectMaliciousInput,
} from '../lib/shareValidation.js';

const router = Router();

// Validation schemas
const createShareLinkSchema = z.object({
  terminalId: z.string(),
  sessionId: z.string(),
  permission: z.enum(['VIEW', 'CONTROL']).default('VIEW'),

  // Name collection settings
  requireName: z.boolean().default(true),
  requireEmail: z.boolean().default(false),
  requireReason: z.boolean().default(false),
  nameMinLength: z.number().min(1).max(100).default(2),
  nameMaxLength: z.number().min(1).max(200).default(50),
  allowAnonymous: z.boolean().default(false),

  // Security settings
  approvalMode: z.enum(['MANUAL', 'AUTO', 'PASSWORD_ONLY']).default('MANUAL'),
  maxConcurrentUsers: z.number().min(1).max(100).default(5),
  maxTotalUses: z.number().min(1).max(1000).nullable().default(50),
  password: z.string().min(4).optional(),
  allowedIPs: z.array(z.string()).optional(),

  // Expiration (in hours)
  expiresInHours: z.number().min(1).max(168).default(24), // Max 1 week
});

const joinRequestSchema = z.object({
  shareCode: z.string().min(6).max(16),
  name: z.string().min(1).max(100),
  email: z.string().email().optional(),
  reason: z.string().max(500).optional(),
  organization: z.string().max(100).optional(),
  password: z.string().optional(),
});

const approveConnectionSchema = z.object({
  connectionId: z.string().uuid(),
});

const rejectConnectionSchema = z.object({
  connectionId: z.string().uuid(),
  reason: z.string().max(200).optional(),
});

const blockIPSchema = z.object({
  ipAddress: z.string(),
});

/**
 * POST /api/share/create
 * Create a new share link for a terminal (PROTECTED)
 */
router.post('/create', createShareLinkLimiter, authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const validatedData = createShareLinkSchema.parse(req.body);

    // Additional security validation for IP list
    if (validatedData.allowedIPs && validatedData.allowedIPs.length > 0) {
      const ipValidation = validateIPList(validatedData.allowedIPs);
      if (!ipValidation.valid) {
        return res.status(400).json({ error: ipValidation.error });
      }
    }

    // Create share link
    const result = await createShareLink({
      terminalId: validatedData.terminalId,
      sessionId: validatedData.sessionId,
      createdBy: req.user.userId,
      permission: validatedData.permission,

      requireName: validatedData.requireName,
      requireEmail: validatedData.requireEmail,
      requireReason: validatedData.requireReason,
      nameMinLength: validatedData.nameMinLength,
      nameMaxLength: validatedData.nameMaxLength,
      allowAnonymous: validatedData.allowAnonymous,

      approvalMode: validatedData.approvalMode,
      maxConcurrentUsers: validatedData.maxConcurrentUsers,
      maxTotalUses: validatedData.maxTotalUses,
      password: validatedData.password,
      allowedIPs: validatedData.allowedIPs,

      expiresIn: validatedData.expiresInHours * 60 * 60 * 1000,
    });

    if (!result.success) {
      return res.status(400).json({ error: result.error });
    }

    // Audit log
    await logAuditEvent({
      userId: req.user.userId,
      action: AuditAction.SHARE_TERMINAL,
      resource: `terminal:${validatedData.terminalId}`,
      metadata: JSON.stringify({
        shareCode: result.shareCode,
        approvalMode: validatedData.approvalMode,
        permission: validatedData.permission,
      }),
      ipAddress: getClientIp(req),
      userAgent: getUserAgent(req),
    });

    res.status(201).json({
      success: true,
      shareCode: result.shareCode,
      shareUrl: result.shareUrl,
      shareLink: {
        id: result.shareLink.id,
        shareCode: result.shareCode,
        expiresAt: result.shareLink.expiresAt,
        approvalMode: result.shareLink.approvalMode,
        permission: result.shareLink.permission,
        maxConcurrentUsers: result.shareLink.maxConcurrentUsers,
        maxTotalUses: result.shareLink.maxTotalUses,
      },
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({
        error: 'Validation failed',
        details: error.errors,
      });
    }

    logger.error('[ShareAPI] Failed to create share link', {
      error: error instanceof Error ? error.message : 'Unknown error',
      userId: req.user?.userId,
    });

    res.status(500).json({ error: 'Failed to create share link' });
  }
});

/**
 * GET /api/share/:shareCode/settings
 * Get share link settings (public endpoint)
 */
router.get('/:shareCode/settings', getShareSettingsLimiter, async (req: Request, res: Response) => {
  try {
    const { shareCode } = req.params;

    // Validate share code format
    const codeValidation = validateShareCode(shareCode);
    if (!codeValidation.valid) {
      return res.status(400).json({ error: codeValidation.error });
    }

    const shareLink = await prisma.sharedLink.findUnique({
      where: { shareCode },
      select: {
        id: true,
        shareCode: true,
        requireName: true,
        requireEmail: true,
        requireReason: true,
        nameMinLength: true,
        nameMaxLength: true,
        allowAnonymous: true,
        requirePassword: true,
        approvalMode: true,
        permission: true,
        expiresAt: true,
        active: true,
        maxConcurrentUsers: true,
        maxTotalUses: true,
        currentUses: true,
      },
    });

    if (!shareLink) {
      return res.status(404).json({ error: 'Share link not found' });
    }

    if (!shareLink.active) {
      return res.status(410).json({ error: 'This share link has been deactivated' });
    }

    if (new Date() > shareLink.expiresAt) {
      return res.status(410).json({ error: 'This share link has expired' });
    }

    res.json({
      success: true,
      settings: {
        shareCode: shareLink.shareCode,
        requireName: shareLink.requireName,
        requireEmail: shareLink.requireEmail,
        requireReason: shareLink.requireReason,
        nameMinLength: shareLink.nameMinLength,
        nameMaxLength: shareLink.nameMaxLength,
        allowAnonymous: shareLink.allowAnonymous,
        requirePassword: shareLink.requirePassword,
        approvalMode: shareLink.approvalMode,
        permission: shareLink.permission,
        expiresAt: shareLink.expiresAt,
      },
    });
  } catch (error) {
    logger.error('[ShareAPI] Failed to get share settings', {
      error: error instanceof Error ? error.message : 'Unknown error',
      shareCode: req.params.shareCode,
    });

    res.status(500).json({ error: 'Failed to retrieve share link settings' });
  }
});

/**
 * POST /api/share/:shareCode/join
 * Submit a join request (public endpoint)
 */
router.post('/:shareCode/join', joinRequestLimiter, async (req: Request, res: Response) => {
  try {
    const { shareCode } = req.params;

    // Validate share code format
    const codeValidation = validateShareCode(shareCode);
    if (!codeValidation.valid) {
      return res.status(400).json({ error: codeValidation.error });
    }

    const validatedData = joinRequestSchema.parse({
      ...req.body,
      shareCode,
    });

    // Additional security validation for user input
    const inputValidation = validateJoinRequestData({
      name: validatedData.name,
      email: validatedData.email,
      reason: validatedData.reason,
      organization: validatedData.organization,
      password: validatedData.password,
    });

    if (!inputValidation.valid) {
      return res.status(400).json({ error: inputValidation.error });
    }

    // Use sanitized data
    const sanitizedData = {
      ...validatedData,
      ...inputValidation.sanitized,
    };

    // Get client information
    const ipAddress = getClientIp(req);
    const userAgent = getUserAgent(req);

    // Validate join request
    const validation = await validateJoinRequest({
      ...sanitizedData,
      ipAddress,
      userAgent,
    });

    if (!validation.valid) {
      return res.status(400).json({ error: validation.error });
    }

    // Check if approval is required
    if (validation.requiresApproval) {
      // Create pending connection
      const result = await createPendingConnection(validation.shareLink, {
        ...sanitizedData,
        ipAddress,
        userAgent,
      });

      if (!result.success) {
        return res.status(500).json({ error: result.error });
      }

      // Emit socket event to notify the terminal owner of the new request
      try {
        const shareLink = validation.shareLink;
        emitToShareLinkOwner(shareLink.createdBy, 'share:new-request', {
          shareCode,
          connection: {
            id: result.connectionId,
            name: sanitizedData.name,
            email: sanitizedData.email,
            organization: sanitizedData.organization,
            reason: sanitizedData.reason,
            ipAddress,
            userAgent,
            requestedAt: new Date().toISOString(),
          },
        });
      } catch (socketError) {
        // Don't fail the request if socket notification fails
        logger.error('[ShareAPI] Failed to emit socket notification', {
          error: socketError instanceof Error ? socketError.message : 'Unknown error',
          connectionId: result.connectionId,
        });
      }

      return res.status(202).json({
        success: true,
        status: 'PENDING',
        message: 'Your request has been submitted and is awaiting approval',
        connectionId: result.connectionId,
      });
    }

    // Auto-approve (for AUTO or PASSWORD_ONLY modes with correct password)
    const result = await createPendingConnection(validation.shareLink, {
      ...sanitizedData,
      ipAddress,
      userAgent,
    });

    if (!result.success) {
      return res.status(500).json({ error: result.error });
    }

    // Auto-approve the connection
    await approveConnection(result.connectionId!, 'system');

    return res.status(200).json({
      success: true,
      status: 'APPROVED',
      message: 'Access granted',
      connectionId: result.connectionId,
      terminalId: validation.shareLink.terminalId,
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({
        error: 'Validation failed',
        details: error.errors,
      });
    }

    logger.error('[ShareAPI] Failed to process join request', {
      error: error instanceof Error ? error.message : 'Unknown error',
      shareCode: req.params.shareCode,
    });

    res.status(500).json({ error: 'Failed to process join request' });
  }
});

/**
 * POST /api/share/approve
 * Approve a pending connection (PROTECTED)
 */
router.post('/approve', approveRejectLimiter, authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const validatedData = approveConnectionSchema.parse(req.body);

    const result = await approveConnection(validatedData.connectionId, req.user.userId);

    if (!result.success) {
      return res.status(400).json({ error: result.error });
    }

    // Audit log
    await logAuditEvent({
      userId: req.user.userId,
      action: AuditAction.APPROVE_SHARE_REQUEST,
      resource: `connection:${validatedData.connectionId}`,
      ipAddress: getClientIp(req),
      userAgent: getUserAgent(req),
    });

    res.json({
      success: true,
      message: 'Connection approved',
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({
        error: 'Validation failed',
        details: error.errors,
      });
    }

    logger.error('[ShareAPI] Failed to approve connection', {
      error: error instanceof Error ? error.message : 'Unknown error',
      userId: req.user?.userId,
    });

    res.status(500).json({ error: 'Failed to approve connection' });
  }
});

/**
 * POST /api/share/reject
 * Reject a pending connection (PROTECTED)
 */
router.post('/reject', approveRejectLimiter, authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const validatedData = rejectConnectionSchema.parse(req.body);

    const result = await rejectConnection(
      validatedData.connectionId,
      req.user.userId,
      validatedData.reason
    );

    if (!result.success) {
      return res.status(400).json({ error: result.error });
    }

    // Audit log
    await logAuditEvent({
      userId: req.user.userId,
      action: AuditAction.REJECT_SHARE_REQUEST,
      resource: `connection:${validatedData.connectionId}`,
      metadata: validatedData.reason ? JSON.stringify({ reason: validatedData.reason }) : undefined,
      ipAddress: getClientIp(req),
      userAgent: getUserAgent(req),
    });

    res.json({
      success: true,
      message: 'Connection rejected',
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({
        error: 'Validation failed',
        details: error.errors,
      });
    }

    logger.error('[ShareAPI] Failed to reject connection', {
      error: error instanceof Error ? error.message : 'Unknown error',
      userId: req.user?.userId,
    });

    res.status(500).json({ error: 'Failed to reject connection' });
  }
});

/**
 * POST /api/share/:shareCode/block-ip
 * Block an IP address (PROTECTED)
 */
router.post('/:shareCode/block-ip', blockIPLimiter, authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const { shareCode } = req.params;
    const validatedData = blockIPSchema.parse(req.body);

    const result = await blockIP(shareCode, validatedData.ipAddress, req.user.userId);

    if (!result.success) {
      return res.status(400).json({ error: result.error });
    }

    // Audit log
    await logAuditEvent({
      userId: req.user.userId,
      action: AuditAction.BLOCK_IP,
      resource: `share:${shareCode}`,
      metadata: JSON.stringify({ blockedIP: validatedData.ipAddress }),
      ipAddress: getClientIp(req),
      userAgent: getUserAgent(req),
    });

    res.json({
      success: true,
      message: 'IP address blocked',
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({
        error: 'Validation failed',
        details: error.errors,
      });
    }

    logger.error('[ShareAPI] Failed to block IP', {
      error: error instanceof Error ? error.message : 'Unknown error',
      userId: req.user?.userId,
    });

    res.status(500).json({ error: 'Failed to block IP address' });
  }
});

/**
 * GET /api/share/:shareCode/stats
 * Get share link statistics (PROTECTED)
 */
router.get('/:shareCode/stats', shareManagementLimiter, authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const { shareCode } = req.params;

    // Verify ownership
    const shareLink = await prisma.sharedLink.findUnique({
      where: { shareCode },
    });

    if (!shareLink) {
      return res.status(404).json({ error: 'Share link not found' });
    }

    if (shareLink.createdBy !== req.user.userId && req.user.role !== 'ADMIN') {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    const result = await getShareLinkStats(shareCode);

    if (!result.success) {
      return res.status(500).json({ error: result.error });
    }

    res.json({
      success: true,
      stats: result.stats,
    });
  } catch (error) {
    logger.error('[ShareAPI] Failed to get stats', {
      error: error instanceof Error ? error.message : 'Unknown error',
      userId: req.user?.userId,
    });

    res.status(500).json({ error: 'Failed to retrieve statistics' });
  }
});

/**
 * GET /api/share/:shareCode/pending
 * Get pending connection requests for a share link (PROTECTED)
 */
router.get('/:shareCode/pending', shareManagementLimiter, authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const { shareCode } = req.params;

    // Verify ownership
    const shareLink = await prisma.sharedLink.findUnique({
      where: { shareCode },
      include: {
        pendingConnections: {
          where: {
            status: 'PENDING',
          },
          orderBy: {
            requestedAt: 'desc',
          },
        },
      },
    });

    if (!shareLink) {
      return res.status(404).json({ error: 'Share link not found' });
    }

    if (shareLink.createdBy !== req.user.userId && req.user.role !== 'ADMIN') {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    res.json({
      success: true,
      pendingConnections: shareLink.pendingConnections,
    });
  } catch (error) {
    logger.error('[ShareAPI] Failed to get pending connections', {
      error: error instanceof Error ? error.message : 'Unknown error',
      userId: req.user?.userId,
    });

    res.status(500).json({ error: 'Failed to retrieve pending connections' });
  }
});

/**
 * DELETE /api/share/:shareCode
 * Deactivate a share link (PROTECTED)
 */
router.delete('/:shareCode', deactivateShareLimiter, authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const { shareCode } = req.params;

    // Verify ownership
    const shareLink = await prisma.sharedLink.findUnique({
      where: { shareCode },
    });

    if (!shareLink) {
      return res.status(404).json({ error: 'Share link not found' });
    }

    if (shareLink.createdBy !== req.user.userId && req.user.role !== 'ADMIN') {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    // Deactivate the share link
    await prisma.sharedLink.update({
      where: { shareCode },
      data: { active: false },
    });

    // Audit log
    await logAuditEvent({
      userId: req.user.userId,
      action: AuditAction.DEACTIVATE_SHARE_LINK,
      resource: `share:${shareCode}`,
      ipAddress: getClientIp(req),
      userAgent: getUserAgent(req),
    });

    res.json({
      success: true,
      message: 'Share link deactivated',
    });
  } catch (error) {
    logger.error('[ShareAPI] Failed to deactivate share link', {
      error: error instanceof Error ? error.message : 'Unknown error',
      userId: req.user?.userId,
    });

    res.status(500).json({ error: 'Failed to deactivate share link' });
  }
});

export default router;
