import { Request, Response, NextFunction } from 'express';
import { UserRole } from '@prisma/client';

// Extend Express Request to include user info
export interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    email: string;
    username: string;
    role: UserRole;
  };
}

/**
 * Middleware to check if user has required role
 * @param allowedRoles Array of roles that can access the route
 */
export function requireRole(...allowedRoles: UserRole[]) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'Authentication required',
      });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        error: 'Insufficient permissions',
        required: allowedRoles,
        current: req.user.role,
      });
    }

    next();
  };
}

/**
 * Middleware to check if user is an admin
 */
export function requireAdmin(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  return requireRole(UserRole.ADMIN)(req, res, next);
}

/**
 * Middleware to check if user is admin or the resource owner
 * @param getUserId Function to extract user ID from request
 */
export function requireAdminOrOwner(getUserId: (req: AuthenticatedRequest) => string) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'Authentication required',
      });
    }

    const resourceUserId = getUserId(req);
    const isOwner = req.user.id === resourceUserId;
    const isAdmin = req.user.role === UserRole.ADMIN;

    if (!isOwner && !isAdmin) {
      return res.status(403).json({
        error: 'Insufficient permissions - must be admin or resource owner',
      });
    }

    next();
  };
}

/**
 * Check if user has permission to access a terminal
 * @param terminalOwnerId The owner of the terminal
 * @param userId The user trying to access
 * @param userRole The role of the user
 */
export function canAccessTerminal(
  terminalOwnerId: string,
  userId: string,
  userRole: UserRole
): boolean {
  // Admins can access any terminal
  if (userRole === UserRole.ADMIN) {
    return true;
  }

  // Users can access their own terminals
  if (terminalOwnerId === userId) {
    return true;
  }

  // Other access requires explicit sharing (checked separately)
  return false;
}

/**
 * Check if user can control a terminal
 * @param terminalOwnerId The owner of the terminal
 * @param userId The user trying to control
 * @param userRole The role of the user
 * @param permission The permission level (from SharedTerminal)
 */
export function canControlTerminal(
  terminalOwnerId: string,
  userId: string,
  userRole: UserRole,
  permission?: string
): boolean {
  // Admins can control any terminal
  if (userRole === UserRole.ADMIN) {
    return true;
  }

  // Owners can control their own terminals
  if (terminalOwnerId === userId) {
    return true;
  }

  // Shared users need CONTROL permission
  return permission === 'CONTROL';
}
