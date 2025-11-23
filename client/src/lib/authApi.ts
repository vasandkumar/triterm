import axios, { AxiosError } from 'axios';
import { saveTokens, getAccessToken, getRefreshToken, clearTokens } from './tokenStorage';

// Automatically determine the API base URL
function getApiBaseUrl(): string {
  // If VITE_API_URL is set, use it
  if (import.meta.env.VITE_API_URL) {
    return import.meta.env.VITE_API_URL;
  }

  // In development, use the current hostname with port 3000
  if (import.meta.env.DEV) {
    const hostname = window.location.hostname;
    return `http://${hostname}:3000`;
  }

  // In production, use the same origin
  return window.location.origin;
}

// API base URL - dynamically determined based on current hostname
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

// Response interceptor to handle token refresh
api.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config;

    // If 401 and we have a refresh token, try to refresh
    if (error.response?.status === 401 && originalRequest && !originalRequest.headers['X-Retry']) {
      const refreshToken = getRefreshToken();

      if (refreshToken) {
        try {
          const response = await axios.post(`${API_BASE_URL}/api/auth/refresh`, {
            refreshToken,
          });

          const { accessToken, refreshToken: newRefreshToken } = response.data;
          saveTokens({ accessToken, refreshToken: newRefreshToken });

          // Retry original request with new token
          originalRequest.headers['Authorization'] = `Bearer ${accessToken}`;
          originalRequest.headers['X-Retry'] = 'true';
          return api(originalRequest);
        } catch (refreshError) {
          // Refresh failed, clear tokens
          clearTokens();
          window.location.href = '/';
          return Promise.reject(refreshError);
        }
      }
    }

    return Promise.reject(error);
  }
);

export interface User {
  id: string;
  email: string;
  username: string;
  role: 'ADMIN' | 'USER' | 'VIEWER';
  createdAt: string;
  updatedAt?: string;
}

export interface RegisterData {
  email: string;
  username: string;
  password: string;
}

export interface LoginData {
  email: string;
  password: string;
}

export interface AuthResponse {
  success: boolean;
  user: User;
  accessToken: string;
  refreshToken: string;
}

export interface ErrorResponse {
  error: string;
  details?: unknown;
}

/**
 * Register a new user
 */
export async function register(data: RegisterData): Promise<AuthResponse> {
  try {
    const response = await api.post<AuthResponse>('/api/auth/register', data);
    return response.data;
  } catch (error) {
    if (error instanceof AxiosError && error.response?.data?.error) {
      // Throw the server's error message
      throw new Error(error.response.data.error);
    }
    // For network errors or other issues
    throw new Error(error instanceof Error ? error.message : 'Network error. Please check your connection.');
  }
}

/**
 * Login with email and password
 */
export async function login(data: LoginData): Promise<AuthResponse> {
  try {
    const response = await api.post<AuthResponse>('/api/auth/login', data);
    return response.data;
  } catch (error) {
    if (error instanceof AxiosError && error.response?.data?.error) {
      // Throw the server's error message
      throw new Error(error.response.data.error);
    }
    // For network errors or other issues
    throw new Error(error instanceof Error ? error.message : 'Network error. Please check your connection.');
  }
}

/**
 * Get current user information
 */
export async function getCurrentUser(): Promise<User> {
  const response = await api.get<{ success: boolean; user: User }>('/api/auth/me');
  return response.data.user;
}

/**
 * Logout (client-side token cleanup)
 */
export async function logout(): Promise<void> {
  try {
    await api.post('/api/auth/logout');
  } catch (error) {
    // Ignore errors, we're logging out anyway
  } finally {
    clearTokens();
  }
}

export { api };
