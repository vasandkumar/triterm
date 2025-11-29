import { getAccessToken } from './tokenStorage';

// Automatically determine the API URL based on current hostname
function getApiUrl(): string {
  if (import.meta.env.DEV) {
    // Development mode - use current hostname with port 3000
    const hostname = window.location.hostname;
    return `http://${hostname}:3000/api`;
  } else {
    // Production mode - use same origin
    return `${window.location.origin}/api`;
  }
}

const API_URL = getApiUrl();

export interface User {
  id: string;
  username: string;
  email: string;
  role: 'USER' | 'ADMIN';
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface AuditLog {
  id: string;
  userId: string | null;
  action: string;
  ipAddress: string | null;
  userAgent: string | null;
  metadata: any;
  createdAt: Date;
  user?: {
    username: string;
    email: string;
  };
}

export interface SystemStats {
  totalUsers: number;
  activeUsers: number;
  activeSessions: number;
  totalSessions: number;
  recentAuditEvents: number;
  uptime: number;
  system?: {
    platform: string;
    arch: string;
    nodeVersion: string;
    cpuUsage: number;
    memoryUsage: number;
    totalMemory: number;
    freeMemory: number;
    loadAverage: number[];
  };
  database?: {
    size: number;
    connections: number;
  };
}

// Helper function to get CSRF token from cookie
function getCsrfToken(): string | null {
  const name = 'XSRF-TOKEN=';
  const decodedCookie = decodeURIComponent(document.cookie);
  const ca = decodedCookie.split(';');
  for (let i = 0; i < ca.length; i++) {
    let c = ca[i];
    while (c.charAt(0) === ' ') {
      c = c.substring(1);
    }
    if (c.indexOf(name) === 0) {
      return c.substring(name.length, c.length);
    }
  }
  return null;
}

async function fetchWithAuth(url: string, options: RequestInit = {}) {
  // With httpOnly cookies, tokens are automatically sent in cookies
  // No need to manually get from localStorage

  const csrfToken = getCsrfToken();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string>),
  };

  // Add CSRF token for state-changing requests
  if (csrfToken) {
    headers['x-xsrf-token'] = csrfToken;
  }

  // Fallback: Include Authorization header if token exists in localStorage
  // (for backward compatibility during migration)
  const token = getAccessToken();
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const response = await fetch(url, {
    ...options,
    headers,
    credentials: 'include', // CRITICAL: Send httpOnly cookies with requests
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: 'Request failed' }));
    throw new Error(error.error || `HTTP ${response.status}`);
  }

  return response.json();
}

export async function getAllUsers(): Promise<User[]> {
  return fetchWithAuth(`${API_URL}/admin/users`);
}

export async function updateUserRole(userId: string, role: 'USER' | 'ADMIN'): Promise<User> {
  return fetchWithAuth(`${API_URL}/admin/users/${userId}`, {
    method: 'PATCH',
    body: JSON.stringify({ role }),
  });
}

export async function deleteUser(userId: string): Promise<void> {
  await fetchWithAuth(`${API_URL}/admin/users/${userId}`, {
    method: 'DELETE',
  });
}

export async function getAuditLogs(params?: {
  action?: string;
  userId?: string;
  limit?: number;
}): Promise<AuditLog[]> {
  const queryParams = new URLSearchParams();
  if (params?.action) queryParams.append('action', params.action);
  if (params?.userId) queryParams.append('userId', params.userId);
  if (params?.limit) queryParams.append('limit', params.limit.toString());

  const url = `${API_URL}/admin/audit-logs${queryParams.toString() ? `?${queryParams}` : ''}`;
  return fetchWithAuth(url);
}

export interface Session {
  id: string;
  userId: string;
  terminalId: string;
  shell: string;
  cwd: string;
  cols: number;
  rows: number;
  active: boolean;
  socketId: string | null;
  createdAt: Date;
  lastActivityAt: Date;
  expiresAt: Date | null;
  user?: {
    username: string;
    email: string;
  };
}

export async function getSessions(activeOnly: boolean = false): Promise<Session[]> {
  const queryParams = activeOnly ? '?active=true' : '';
  return fetchWithAuth(`${API_URL}/admin/sessions${queryParams}`);
}

export async function getSystemStats(): Promise<SystemStats> {
  return fetchWithAuth(`${API_URL}/admin/stats`);
}

/**
 * Get all users pending approval (isActive = false)
 */
export async function getPendingUsers(): Promise<User[]> {
  return fetchWithAuth(`${API_URL}/admin/pending-users`);
}

/**
 * Activate a user account
 */
export async function activateUser(userId: string): Promise<User> {
  return fetchWithAuth(`${API_URL}/admin/users/${userId}/activate`, {
    method: 'PATCH',
  });
}

/**
 * Deactivate a user account
 */
export async function deactivateUser(userId: string): Promise<User> {
  return fetchWithAuth(`${API_URL}/admin/users/${userId}/deactivate`, {
    method: 'PATCH',
  });
}

/**
 * Get system settings
 */
export interface SystemSettings {
  id: string;
  signupEnabled: boolean;
  createdAt: Date;
  updatedAt: Date;
  updatedBy: string | null;
}

export async function getSystemSettings(): Promise<SystemSettings> {
  return fetchWithAuth(`${API_URL}/admin/settings`);
}

/**
 * Toggle signup enabled/disabled
 */
export async function toggleSignup(enabled: boolean): Promise<SystemSettings> {
  return fetchWithAuth(`${API_URL}/admin/settings/signup`, {
    method: 'PATCH',
    body: JSON.stringify({ enabled }),
  });
}
