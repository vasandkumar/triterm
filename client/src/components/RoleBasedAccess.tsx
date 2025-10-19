import { ReactNode } from 'react';
import { usePermissions, UserRole } from '../hooks/usePermissions';

interface RoleBasedAccessProps {
  children: ReactNode;
  requiredRole?: UserRole | UserRole[];
  requiredPermission?: keyof Omit<ReturnType<typeof usePermissions>, 'hasRole'>;
  fallback?: ReactNode;
}

/**
 * Component that conditionally renders children based on user role or permission
 *
 * @example
 * // Show only to admins
 * <RoleBasedAccess requiredRole="ADMIN">
 *   <AdminPanel />
 * </RoleBasedAccess>
 *
 * @example
 * // Show to users or admins
 * <RoleBasedAccess requiredRole={['USER', 'ADMIN']}>
 *   <CreateTerminalButton />
 * </RoleBasedAccess>
 *
 * @example
 * // Show based on permission
 * <RoleBasedAccess requiredPermission="canShareTerminals">
 *   <ShareButton />
 * </RoleBasedAccess>
 */
export function RoleBasedAccess({
  children,
  requiredRole,
  requiredPermission,
  fallback = null,
}: RoleBasedAccessProps) {
  const permissions = usePermissions();

  let hasAccess = false;

  if (requiredRole) {
    hasAccess = permissions.hasRole(requiredRole);
  } else if (requiredPermission) {
    hasAccess = permissions[requiredPermission] as boolean;
  } else {
    // If no requirements specified, grant access
    hasAccess = true;
  }

  if (!hasAccess) {
    return <>{fallback}</>;
  }

  return <>{children}</>;
}

/**
 * Component that renders children only for admin users
 */
export function AdminOnly({ children, fallback }: { children: ReactNode; fallback?: ReactNode }) {
  return (
    <RoleBasedAccess requiredRole="ADMIN" fallback={fallback}>
      {children}
    </RoleBasedAccess>
  );
}

/**
 * Component that renders children only for users (not viewers)
 */
export function UserOnly({ children, fallback }: { children: ReactNode; fallback?: ReactNode }) {
  return (
    <RoleBasedAccess requiredRole={['USER', 'ADMIN']} fallback={fallback}>
      {children}
    </RoleBasedAccess>
  );
}
