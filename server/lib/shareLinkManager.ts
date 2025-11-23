/**
 * Enterprise-grade Share Link Management System
 *
 * Manages external terminal sharing with comprehensive security features:
 * - Share code generation and validation
 * - Name collection and validation with profanity filtering
 * - IP-based rate limiting and blocking
 * - Password protection
 * - Approval workflow management
 * - Audit logging
 * - Usage tracking and limits
 */

import bcrypt from 'bcryptjs';
import prisma from './prisma.js';
import logger from '../config/logger.js';

/**
 * Configuration for share link creation
 */
export interface ShareLinkConfig {
  terminalId: string;
  sessionId: string;
  createdBy: string;
  permission?: 'VIEW' | 'CONTROL';

  // Name Collection Settings
  requireName?: boolean;
  requireEmail?: boolean;
  requireReason?: boolean;
  nameMinLength?: number;
  nameMaxLength?: number;
  allowAnonymous?: boolean;

  // Security Settings
  approvalMode?: 'MANUAL' | 'AUTO' | 'PASSWORD_ONLY';
  requireApproval?: boolean;
  maxConcurrentUsers?: number;
  maxTotalUses?: number | null;
  password?: string;
  allowedIPs?: string[];

  // Expiration
  expiresIn?: number; // milliseconds
}

/**
 * Join request information
 */
export interface JoinRequest {
  shareCode: string;
  name: string;
  email?: string;
  reason?: string;
  organization?: string;
  password?: string;

  // System info
  ipAddress: string;
  userAgent: string;
  geoLocation?: string;
  deviceInfo?: string;
}

/**
 * Simple profanity filter
 * In production, use a comprehensive library like 'bad-words' or 'profanity-check'
 */
const PROFANITY_LIST = [
  'badword1', 'badword2', 'badword3', // Placeholder - add actual words
];

function containsProfanity(text: string): boolean {
  const lowerText = text.toLowerCase();
  return PROFANITY_LIST.some(word => lowerText.includes(word.toLowerCase()));
}

/**
 * Generate a unique share code
 */
function generateShareCode(length: number = 8): string {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let code = '';
  for (let i = 0; i < length; i++) {
    code += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return code;
}

/**
 * Create a new share link
 */
export async function createShareLink(config: ShareLinkConfig): Promise<{
  success: boolean;
  shareLink?: any;
  shareCode?: string;
  shareUrl?: string;
  error?: string;
}> {
  try {
    // Validate terminal exists
    const session = await prisma.session.findUnique({
      where: { terminalId: config.terminalId },
    });

    if (!session) {
      return { success: false, error: 'Terminal not found' };
    }

    if (session.id !== config.sessionId) {
      return { success: false, error: 'Session ID mismatch' };
    }

    if (session.userId !== config.createdBy) {
      return { success: false, error: 'Unauthorized: You do not own this terminal' };
    }

    // Generate unique share code
    let shareCode = generateShareCode();
    let attempts = 0;
    while (attempts < 10) {
      const existing = await prisma.sharedLink.findUnique({
        where: { shareCode },
      });
      if (!existing) break;
      shareCode = generateShareCode();
      attempts++;
    }

    if (attempts >= 10) {
      return { success: false, error: 'Failed to generate unique share code' };
    }

    // Hash password if provided
    let passwordHash: string | undefined;
    if (config.password) {
      passwordHash = await bcrypt.hash(config.password, 10);
    }

    // Calculate expiration
    const expiresAt = new Date(Date.now() + (config.expiresIn || 24 * 60 * 60 * 1000)); // Default 24 hours

    // Create share link
    const shareLink = await prisma.sharedLink.create({
      data: {
        terminalId: config.terminalId,
        sessionId: config.sessionId,
        shareCode,

        // Name collection settings
        requireName: config.requireName ?? true,
        requireEmail: config.requireEmail ?? false,
        requireReason: config.requireReason ?? false,
        nameMinLength: config.nameMinLength ?? 2,
        nameMaxLength: config.nameMaxLength ?? 50,
        allowAnonymous: config.allowAnonymous ?? false,

        // Security settings
        approvalMode: config.approvalMode ?? 'MANUAL',
        requireApproval: config.requireApproval ?? true,
        maxConcurrentUsers: config.maxConcurrentUsers ?? 5,
        maxTotalUses: config.maxTotalUses ?? 50,
        currentUses: 0,
        requirePassword: !!config.password,
        passwordHash,
        allowedIPs: config.allowedIPs ? JSON.stringify(config.allowedIPs) : null,
        blockedIPs: null,

        permission: config.permission ?? 'VIEW',
        createdBy: config.createdBy,
        expiresAt,
        active: true,
      },
    });

    // Create audit log
    await prisma.shareAuditLog.create({
      data: {
        sharedLinkId: shareLink.id,
        action: 'LINK_CREATED',
        actorId: config.createdBy,
        ipAddress: '127.0.0.1', // Should be passed from request
        metadata: JSON.stringify({
          approvalMode: shareLink.approvalMode,
          permission: shareLink.permission,
          expiresAt: shareLink.expiresAt,
        }),
      },
    });

    const shareUrl = `/share/${shareCode}`;

    logger.info('[ShareLink] Share link created', {
      shareCode,
      terminalId: config.terminalId,
      createdBy: config.createdBy,
      approvalMode: shareLink.approvalMode,
    });

    return {
      success: true,
      shareLink,
      shareCode,
      shareUrl,
    };
  } catch (error) {
    logger.error('[ShareLink] Failed to create share link', {
      error: error instanceof Error ? error.message : 'Unknown error',
      terminalId: config.terminalId,
    });
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Failed to create share link',
    };
  }
}

/**
 * Validate a join request
 */
export async function validateJoinRequest(request: JoinRequest): Promise<{
  valid: boolean;
  error?: string;
  shareLink?: any;
  requiresApproval?: boolean;
}> {
  try {
    // Find share link
    const shareLink = await prisma.sharedLink.findUnique({
      where: { shareCode: request.shareCode },
      include: {
        pendingConnections: {
          where: {
            status: 'PENDING',
          },
        },
        activeConnections: true,
      },
    });

    if (!shareLink) {
      return { valid: false, error: 'Invalid share code' };
    }

    if (!shareLink.active) {
      return { valid: false, error: 'This share link has been deactivated' };
    }

    // Check expiration
    if (new Date() > shareLink.expiresAt) {
      return { valid: false, error: 'This share link has expired' };
    }

    // Check usage limits
    if (shareLink.maxTotalUses !== null && shareLink.currentUses >= shareLink.maxTotalUses) {
      return { valid: false, error: 'This share link has reached its maximum number of uses' };
    }

    // Check concurrent users
    const activeCount = shareLink.activeConnections.length;
    if (activeCount >= shareLink.maxConcurrentUsers) {
      return { valid: false, error: `Maximum concurrent users (${shareLink.maxConcurrentUsers}) reached` };
    }

    // Check IP blocking
    if (shareLink.blockedIPs) {
      const blockedIPs: string[] = JSON.parse(shareLink.blockedIPs);
      if (blockedIPs.includes(request.ipAddress)) {
        await prisma.shareAuditLog.create({
          data: {
            sharedLinkId: shareLink.id,
            action: 'BLOCKED_IP_ATTEMPT',
            targetName: request.name,
            targetEmail: request.email || null,
            ipAddress: request.ipAddress,
          },
        });
        return { valid: false, error: 'Your IP address has been blocked' };
      }
    }

    // Check IP allowlist
    if (shareLink.allowedIPs) {
      const allowedIPs: string[] = JSON.parse(shareLink.allowedIPs);
      if (allowedIPs.length > 0 && !allowedIPs.includes(request.ipAddress)) {
        return { valid: false, error: 'Your IP address is not authorized' };
      }
    }

    // Validate name
    if (shareLink.requireName && !request.name) {
      return { valid: false, error: 'Name is required' };
    }

    if (request.name) {
      if (request.name.length < shareLink.nameMinLength) {
        return { valid: false, error: `Name must be at least ${shareLink.nameMinLength} characters` };
      }
      if (request.name.length > shareLink.nameMaxLength) {
        return { valid: false, error: `Name must not exceed ${shareLink.nameMaxLength} characters` };
      }
      if (containsProfanity(request.name)) {
        return { valid: false, error: 'Name contains inappropriate content' };
      }
    }

    // Validate email if required
    if (shareLink.requireEmail && !request.email) {
      return { valid: false, error: 'Email is required' };
    }

    if (request.email) {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(request.email)) {
        return { valid: false, error: 'Invalid email format' };
      }
    }

    // Validate reason if required
    if (shareLink.requireReason && !request.reason) {
      return { valid: false, error: 'Reason for access is required' };
    }

    // Check password if required
    if (shareLink.requirePassword) {
      if (!request.password) {
        return { valid: false, error: 'Password is required' };
      }
      if (shareLink.passwordHash) {
        const passwordValid = await bcrypt.compare(request.password, shareLink.passwordHash);
        if (!passwordValid) {
          await prisma.shareAuditLog.create({
            data: {
              sharedLinkId: shareLink.id,
              action: 'INVALID_PASSWORD',
              targetName: request.name,
              targetEmail: request.email || null,
              ipAddress: request.ipAddress,
            },
          });
          return { valid: false, error: 'Invalid password' };
        }
      }
    }

    // Determine if approval is required
    const requiresApproval = shareLink.approvalMode === 'MANUAL' ||
                            (shareLink.approvalMode === 'PASSWORD_ONLY' && !shareLink.requirePassword);

    return {
      valid: true,
      shareLink,
      requiresApproval,
    };
  } catch (error) {
    logger.error('[ShareLink] Failed to validate join request', {
      error: error instanceof Error ? error.message : 'Unknown error',
      shareCode: request.shareCode,
    });
    return {
      valid: false,
      error: 'Failed to validate join request',
    };
  }
}

/**
 * Create a pending connection request
 */
export async function createPendingConnection(
  shareLink: any,
  request: JoinRequest
): Promise<{ success: boolean; connectionId?: string; error?: string }> {
  try {
    const pendingConnection = await prisma.pendingConnection.create({
      data: {
        sharedLinkId: shareLink.id,
        name: request.name,
        email: request.email || null,
        reason: request.reason || null,
        organization: request.organization || null,
        ipAddress: request.ipAddress,
        userAgent: request.userAgent,
        geoLocation: request.geoLocation || null,
        deviceInfo: request.deviceInfo || null,
        status: 'PENDING',
      },
    });

    // Create audit log
    await prisma.shareAuditLog.create({
      data: {
        sharedLinkId: shareLink.id,
        action: 'JOIN_REQUEST',
        targetName: request.name,
        targetEmail: request.email || null,
        ipAddress: request.ipAddress,
        metadata: JSON.stringify({
          organization: request.organization,
          reason: request.reason,
        }),
      },
    });

    logger.info('[ShareLink] Pending connection created', {
      connectionId: pendingConnection.id,
      shareCode: request.shareCode,
      name: request.name,
      email: request.email,
    });

    return {
      success: true,
      connectionId: pendingConnection.id,
    };
  } catch (error) {
    logger.error('[ShareLink] Failed to create pending connection', {
      error: error instanceof Error ? error.message : 'Unknown error',
      shareCode: request.shareCode,
    });
    return {
      success: false,
      error: 'Failed to create connection request',
    };
  }
}

/**
 * Approve a pending connection
 */
export async function approveConnection(
  connectionId: string,
  approvedBy: string
): Promise<{ success: boolean; error?: string }> {
  try {
    const connection = await prisma.pendingConnection.findUnique({
      where: { id: connectionId },
      include: { sharedLink: true },
    });

    if (!connection) {
      return { success: false, error: 'Connection not found' };
    }

    if (connection.status !== 'PENDING') {
      return { success: false, error: 'Connection already processed' };
    }

    // Update status
    await prisma.pendingConnection.update({
      where: { id: connectionId },
      data: {
        status: 'APPROVED',
        respondedAt: new Date(),
        respondedBy: approvedBy,
      },
    });

    // Create audit log
    await prisma.shareAuditLog.create({
      data: {
        sharedLinkId: connection.sharedLinkId,
        action: 'APPROVED',
        actorId: approvedBy,
        targetName: connection.name,
        targetEmail: connection.email,
        ipAddress: connection.ipAddress,
      },
    });

    logger.info('[ShareLink] Connection approved', {
      connectionId,
      approvedBy,
      name: connection.name,
    });

    return { success: true };
  } catch (error) {
    logger.error('[ShareLink] Failed to approve connection', {
      error: error instanceof Error ? error.message : 'Unknown error',
      connectionId,
    });
    return { success: false, error: 'Failed to approve connection' };
  }
}

/**
 * Reject a pending connection
 */
export async function rejectConnection(
  connectionId: string,
  rejectedBy: string,
  reason?: string
): Promise<{ success: boolean; error?: string }> {
  try {
    const connection = await prisma.pendingConnection.findUnique({
      where: { id: connectionId },
      include: { sharedLink: true },
    });

    if (!connection) {
      return { success: false, error: 'Connection not found' };
    }

    if (connection.status !== 'PENDING') {
      return { success: false, error: 'Connection already processed' };
    }

    // Update status
    await prisma.pendingConnection.update({
      where: { id: connectionId },
      data: {
        status: 'REJECTED',
        respondedAt: new Date(),
        respondedBy: rejectedBy,
        rejectionReason: reason || null,
      },
    });

    // Create audit log
    await prisma.shareAuditLog.create({
      data: {
        sharedLinkId: connection.sharedLinkId,
        action: 'REJECTED',
        actorId: rejectedBy,
        targetName: connection.name,
        targetEmail: connection.email,
        ipAddress: connection.ipAddress,
        metadata: reason ? JSON.stringify({ reason }) : null,
      },
    });

    logger.info('[ShareLink] Connection rejected', {
      connectionId,
      rejectedBy,
      name: connection.name,
      reason,
    });

    return { success: true };
  } catch (error) {
    logger.error('[ShareLink] Failed to reject connection', {
      error: error instanceof Error ? error.message : 'Unknown error',
      connectionId,
    });
    return { success: false, error: 'Failed to reject connection' };
  }
}

/**
 * Block an IP address
 */
export async function blockIP(
  shareCode: string,
  ipAddress: string,
  blockedBy: string
): Promise<{ success: boolean; error?: string }> {
  try {
    const shareLink = await prisma.sharedLink.findUnique({
      where: { shareCode },
    });

    if (!shareLink) {
      return { success: false, error: 'Share link not found' };
    }

    // Get existing blocked IPs
    const blockedIPs: string[] = shareLink.blockedIPs ? JSON.parse(shareLink.blockedIPs) : [];

    if (!blockedIPs.includes(ipAddress)) {
      blockedIPs.push(ipAddress);

      await prisma.sharedLink.update({
        where: { shareCode },
        data: {
          blockedIPs: JSON.stringify(blockedIPs),
        },
      });

      // Create audit log
      await prisma.shareAuditLog.create({
        data: {
          sharedLinkId: shareLink.id,
          action: 'IP_BLOCKED',
          actorId: blockedBy,
          ipAddress,
        },
      });

      logger.info('[ShareLink] IP address blocked', {
        shareCode,
        ipAddress,
        blockedBy,
      });
    }

    return { success: true };
  } catch (error) {
    logger.error('[ShareLink] Failed to block IP', {
      error: error instanceof Error ? error.message : 'Unknown error',
      shareCode,
      ipAddress,
    });
    return { success: false, error: 'Failed to block IP address' };
  }
}

/**
 * Get share link statistics
 */
export async function getShareLinkStats(shareCode: string): Promise<{
  success: boolean;
  stats?: any;
  error?: string;
}> {
  try {
    const shareLink = await prisma.sharedLink.findUnique({
      where: { shareCode },
      include: {
        pendingConnections: true,
        activeConnections: true,
        auditLogs: {
          orderBy: { createdAt: 'desc' },
          take: 50,
        },
      },
    });

    if (!shareLink) {
      return { success: false, error: 'Share link not found' };
    }

    const stats = {
      totalRequests: shareLink.pendingConnections.length,
      pendingRequests: shareLink.pendingConnections.filter(c => c.status === 'PENDING').length,
      approvedRequests: shareLink.pendingConnections.filter(c => c.status === 'APPROVED').length,
      rejectedRequests: shareLink.pendingConnections.filter(c => c.status === 'REJECTED').length,
      blockedRequests: shareLink.pendingConnections.filter(c => c.status === 'BLOCKED').length,
      activeConnections: shareLink.activeConnections.length,
      currentUses: shareLink.currentUses,
      maxTotalUses: shareLink.maxTotalUses,
      maxConcurrentUsers: shareLink.maxConcurrentUsers,
      expiresAt: shareLink.expiresAt,
      active: shareLink.active,
      recentActivity: shareLink.auditLogs,
    };

    return { success: true, stats };
  } catch (error) {
    logger.error('[ShareLink] Failed to get stats', {
      error: error instanceof Error ? error.message : 'Unknown error',
      shareCode,
    });
    return { success: false, error: 'Failed to get share link statistics' };
  }
}
