import axios, { AxiosError } from 'axios';
import { getAccessToken } from './tokenStorage';

// Automatically determine the API base URL
function getApiBaseUrl(): string {
  if (import.meta.env.VITE_API_URL) {
    return import.meta.env.VITE_API_URL;
  }

  if (import.meta.env.DEV) {
    const hostname = window.location.hostname;
    return `http://${hostname}:3000`;
  }

  return window.location.origin;
}

const API_BASE_URL = getApiBaseUrl();

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true, // Send cookies with requests
});

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

// Request interceptor to add auth token and CSRF token
api.interceptors.request.use(
  (config) => {
    const token = getAccessToken();
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }

    // Add CSRF token for state-changing requests
    const csrfToken = getCsrfToken();
    if (csrfToken) {
      config.headers['x-xsrf-token'] = csrfToken;
    }

    return config;
  },
  (error) => Promise.reject(error)
);

export interface ShareTerminalData {
  userIds: string[];
  permission: 'VIEW' | 'CONTROL';
  expiresAt?: string;
}

export interface TerminalAccessGrant {
  userId: string;
  permission: 'VIEW' | 'CONTROL';
  createdAt: string;
}

export interface SharedTerminal {
  terminalId: string;
  owner: {
    id: string;
    username: string;
    email: string;
  };
  permission: 'VIEW' | 'CONTROL';
  sharedAt: string;
  expiresAt?: string;
  active: boolean;
}

export interface Collaborator {
  userId: string;
  username: string;
  email: string;
  permission: 'VIEW' | 'CONTROL';
  grantedAt: string;
}

/**
 * Share a terminal with other users
 */
export async function shareTerminal(
  terminalId: string,
  data: ShareTerminalData
): Promise<{ success: boolean; accessGrants: TerminalAccessGrant[] }> {
  try {
    const response = await api.post(`/api/terminals/${terminalId}/share`, data);
    return response.data;
  } catch (error) {
    if (error instanceof AxiosError && error.response?.data?.error) {
      throw new Error(error.response.data.error);
    }
    throw new Error(error instanceof Error ? error.message : 'Failed to share terminal');
  }
}

/**
 * Revoke access to a shared terminal
 */
export async function revokeTerminalAccess(
  terminalId: string,
  userId: string
): Promise<{ success: boolean; message: string }> {
  try {
    const response = await api.delete(`/api/terminals/${terminalId}/share/${userId}`);
    return response.data;
  } catch (error) {
    if (error instanceof AxiosError && error.response?.data?.error) {
      throw new Error(error.response.data.error);
    }
    throw new Error(error instanceof Error ? error.message : 'Failed to revoke access');
  }
}

/**
 * Get all terminals shared with the current user
 */
export async function getSharedTerminals(): Promise<SharedTerminal[]> {
  try {
    const response = await api.get('/api/terminals/shared');
    return response.data.sharedTerminals;
  } catch (error) {
    if (error instanceof AxiosError && error.response?.data?.error) {
      throw new Error(error.response.data.error);
    }
    throw new Error(error instanceof Error ? error.message : 'Failed to fetch shared terminals');
  }
}

/**
 * Get list of collaborators for a terminal
 */
export async function getTerminalCollaborators(terminalId: string): Promise<{
  owner: { id: string; username: string; email: string };
  collaborators: Collaborator[];
  expiresAt?: string;
}> {
  try {
    const response = await api.get(`/api/terminals/${terminalId}/collaborators`);
    return response.data;
  } catch (error) {
    if (error instanceof AxiosError && error.response?.data?.error) {
      throw new Error(error.response.data.error);
    }
    throw new Error(error instanceof Error ? error.message : 'Failed to fetch collaborators');
  }
}

/**
 * Update permission level for a user
 */
export async function updateTerminalPermission(
  terminalId: string,
  userId: string,
  permission: 'VIEW' | 'CONTROL'
): Promise<{ success: boolean; message: string }> {
  try {
    const response = await api.patch(`/api/terminals/${terminalId}/share/${userId}`, {
      permission,
    });
    return response.data;
  } catch (error) {
    if (error instanceof AxiosError && error.response?.data?.error) {
      throw new Error(error.response.data.error);
    }
    throw new Error(error instanceof Error ? error.message : 'Failed to update permission');
  }
}

/**
 * Unshare a terminal completely (remove all access grants)
 */
export async function unshareTerminal(terminalId: string): Promise<{ success: boolean; message: string }> {
  try {
    const response = await api.delete(`/api/terminals/${terminalId}/share`);
    return response.data;
  } catch (error) {
    if (error instanceof AxiosError && error.response?.data?.error) {
      throw new Error(error.response.data.error);
    }
    throw new Error(error instanceof Error ? error.message : 'Failed to unshare terminal');
  }
}
