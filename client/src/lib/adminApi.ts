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

async function fetchWithAuth(url: string, options: RequestInit = {}) {
  const token = getAccessToken();

  if (!token) {
    throw new Error('Authentication required');
  }

  const headers = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`,
    ...options.headers,
  };

  const response = await fetch(url, { ...options, headers });

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
