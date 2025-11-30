import { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import {
  User,
  RegisterData,
  LoginData,
  register as registerApi,
  login as loginApi,
  logout as logoutApi,
  getCurrentUser,
} from '../lib/authApi';
import { clearTokens } from '../lib/tokenStorage';

interface AuthContextValue {
  user: User | null;
  loading: boolean;
  error: string | null;
  isAuthenticated: boolean;
  login: (data: LoginData) => Promise<void>;
  register: (data: RegisterData) => Promise<void>;
  logout: () => Promise<void>;
  clearError: () => void;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Load user on mount - relies on httpOnly cookies being sent automatically
  useEffect(() => {
    async function loadUser() {
      try {
        // Try to get current user - cookies are sent automatically with withCredentials: true
        const currentUser = await getCurrentUser();
        setUser(currentUser);
      } catch (err) {
        // User is not authenticated or token expired - this is expected on first visit
        // Clear any legacy localStorage tokens
        clearTokens();
      }
      setLoading(false);
    }

    loadUser();
  }, []);

  const login = async (data: LoginData) => {
    try {
      setLoading(true);
      setError(null);

      const response = await loginApi(data);

      // Tokens are now in httpOnly cookies (set by backend)
      // No need to save to localStorage - more secure!

      setUser(response.user);
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : 'Login failed';
      setError(errorMessage);
      throw err;
    } finally {
      setLoading(false);
    }
  };

  const register = async (data: RegisterData) => {
    try {
      setLoading(true);
      setError(null);

      const response = await registerApi(data);

      // Tokens are now in httpOnly cookies (set by backend for first user)
      // No need to save to localStorage - more secure!

      setUser(response.user);
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : 'Registration failed';
      setError(errorMessage);
      throw err;
    } finally {
      setLoading(false);
    }
  };

  const logout = async () => {
    try {
      setLoading(true);
      await logoutApi();
    } catch (err) {
      console.error('Logout error:', err);
    } finally {
      clearTokens();
      setUser(null);
      setLoading(false);
    }
  };

  const clearError = () => {
    setError(null);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        error,
        isAuthenticated: !!user,
        login,
        register,
        logout,
        clearError,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
