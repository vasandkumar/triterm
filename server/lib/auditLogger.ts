import { PrismaClient } from '@prisma/client';
import { Request } from 'express';
import logger from '../config/logger.js';

const prisma = new PrismaClient();

export interface AuditLogData {
  userId: string;
  action: string;
  resource: string;
  metadata?: Record<string, any>;
  ipAddress?: string;
  userAgent?: string;
}

/**
 * Audit log actions enum for consistency
 */
export enum AuditAction {
  // Authentication
  LOGIN = 'auth.login',
  LOGOUT = 'auth.logout',
  REGISTER = 'auth.register',
  PASSWORD_CHANGE = 'auth.password_change',

  // Terminal Operations
  TERMINAL_CREATE = 'terminal.create',
  TERMINAL_DELETE = 'terminal.delete',
  TERMINAL_RESIZE = 'terminal.resize',
  TERMINAL_INPUT = 'terminal.input',
  TERMINAL_CLOSE = 'terminal.close',

  // Sharing & Collaboration
  TERMINAL_SHARE = 'terminal.share',
  TERMINAL_UNSHARE = 'terminal.unshare',
  TERMINAL_ACCESS_GRANT = 'terminal.access_grant',
  TERMINAL_ACCESS_REVOKE = 'terminal.access_revoke',

  // User Management (Admin only)
  USER_CREATE = 'user.create',
  USER_UPDATE = 'user.update',
  USER_DELETE = 'user.delete',
  USER_ROLE_CHANGE = 'user.role_change',
  USER_DEACTIVATE = 'user.deactivate',
  USER_ACTIVATE = 'user.activate',

  // Session Management
  SESSION_CREATE = 'session.create',
  SESSION_RESTORE = 'session.restore',
  SESSION_EXPIRE = 'session.expire',
}

/**
 * Log an audit event to the database
 */
export async function logAuditEvent(data: AuditLogData): Promise<void> {
  try {
    await prisma.auditLog.create({
      data: {
        userId: data.userId,
        action: data.action,
        resource: data.resource,
        metadata: data.metadata ? JSON.stringify(data.metadata) : null,
        ipAddress: data.ipAddress,
        userAgent: data.userAgent,
      },
    });

    // Also log to Winston for immediate visibility
    logger.info('Audit event logged', {
      userId: data.userId,
      action: data.action,
      resource: data.resource,
      ip: data.ipAddress,
    });
  } catch (error) {
    // Don't let audit logging failure break the app
    logger.error('Failed to log audit event', {
      error: error instanceof Error ? error.message : 'Unknown error',
      data,
    });
  }
}

/**
 * Extract IP address from request
 */
export function getClientIp(req: Request): string | undefined {
  return (
    (req.headers['x-forwarded-for'] as string)?.split(',')[0] ||
    req.headers['x-real-ip'] as string ||
    req.socket.remoteAddress
  );
}

/**
 * Extract user agent from request
 */
export function getUserAgent(req: Request): string | undefined {
  return req.headers['user-agent'];
}

/**
 * Create audit log middleware
 * Automatically logs the specified action when route is accessed
 */
export function auditLog(action: AuditAction, getResourceId: (req: any) => string) {
  return async (req: any, res: any, next: any) => {
    // Skip if user not authenticated
    if (!req.user) {
      return next();
    }

    try {
      await logAuditEvent({
        userId: req.user.id,
        action,
        resource: getResourceId(req),
        ipAddress: getClientIp(req),
        userAgent: getUserAgent(req),
      });
    } catch (error) {
      // Don't block the request if audit logging fails
      logger.error('Audit logging middleware error', { error });
    }

    next();
  };
}

/**
 * Get audit logs for a user
 */
export async function getUserAuditLogs(
  userId: string,
  limit: number = 100,
  offset: number = 0
) {
  return prisma.auditLog.findMany({
    where: { userId },
    orderBy: { createdAt: 'desc' },
    take: limit,
    skip: offset,
  });
}

/**
 * Get audit logs for a specific action
 */
export async function getAuditLogsByAction(
  action: string,
  limit: number = 100,
  offset: number = 0
) {
  return prisma.auditLog.findMany({
    where: { action },
    orderBy: { createdAt: 'desc' },
    take: limit,
    skip: offset,
    include: {
      user: {
        select: {
          id: true,
          username: true,
          email: true,
        },
      },
    },
  });
}

/**
 * Get all audit logs (admin only)
 */
export async function getAllAuditLogs(
  limit: number = 100,
  offset: number = 0,
  filters?: {
    userId?: string;
    action?: string;
    startDate?: Date;
    endDate?: Date;
  }
) {
  const where: any = {};

  if (filters?.userId) {
    where.userId = filters.userId;
  }

  if (filters?.action) {
    where.action = filters.action;
  }

  if (filters?.startDate || filters?.endDate) {
    where.createdAt = {};
    if (filters.startDate) {
      where.createdAt.gte = filters.startDate;
    }
    if (filters.endDate) {
      where.createdAt.lte = filters.endDate;
    }
  }

  return prisma.auditLog.findMany({
    where,
    orderBy: { createdAt: 'desc' },
    take: limit,
    skip: offset,
    include: {
      user: {
        select: {
          id: true,
          username: true,
          email: true,
          role: true,
        },
      },
    },
  });
}

export default {
  logAuditEvent,
  getUserAuditLogs,
  getAuditLogsByAction,
  getAllAuditLogs,
  AuditAction,
};
