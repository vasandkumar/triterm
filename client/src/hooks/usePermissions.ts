import { useMemo } from 'react';
import { useAuth } from '../contexts/AuthContext';

export type UserRole = 'ADMIN' | 'USER' | 'VIEWER';

export interface Permissions {
  isAdmin: boolean;
  isUser: boolean;
  isViewer: boolean;
  canCreateTerminals: boolean;
  canManageUsers: boolean;
  canShareTerminals: boolean;
  canControlSharedTerminals: boolean;
  canViewAuditLogs: boolean;
  hasRole: (role: UserRole | UserRole[]) => boolean;
}

/**
 * Hook to check user permissions based on their role
 */
export function usePermissions(): Permissions {
  const { user } = useAuth();

  const permissions = useMemo<Permissions>(() => {
    const role = user?.role || 'VIEWER';

    const isAdmin = role === 'ADMIN';
    const isUser = role === 'USER' || isAdmin;
    const isViewer = role === 'VIEWER' || isUser;

    return {
      isAdmin,
      isUser,
      isViewer,

      // Terminal permissions
      canCreateTerminals: isUser, // USER and ADMIN can create terminals
      canShareTerminals: isUser, // USER and ADMIN can share their terminals
      canControlSharedTerminals: isUser, // USER and ADMIN can control shared terminals (if granted)

      // Admin-only permissions
      canManageUsers: isAdmin,
      canViewAuditLogs: isAdmin,

      // Helper function to check if user has a specific role
      hasRole: (requiredRole: UserRole | UserRole[]) => {
        if (Array.isArray(requiredRole)) {
          return requiredRole.includes(role);
        }
        return role === requiredRole;
      },
    };
  }, [user]);

  return permissions;
}

/**
 * Hook to check if user is admin
 */
export function useIsAdmin(): boolean {
  const { user } = useAuth();
  return user?.role === 'ADMIN';
}

/**
 * Hook to check if user can perform an action
 */
export function useCanPerformAction(action: keyof Omit<Permissions, 'hasRole'>): boolean {
  const permissions = usePermissions();
  return permissions[action] as boolean;
}
