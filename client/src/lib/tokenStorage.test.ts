import { describe, it, expect, beforeEach, vi } from 'vitest';
import { saveTokens, getAccessToken, getRefreshToken, clearTokens, isAuthenticated } from './tokenStorage';

describe('Token Storage', () => {
  // Mock localStorage
  const localStorageMock = (() => {
    let store: Record<string, string> = {};

    return {
      getItem: (key: string) => store[key] || null,
      setItem: (key: string, value: string) => {
        store[key] = value.toString();
      },
      removeItem: (key: string) => {
        delete store[key];
      },
      clear: () => {
        store = {};
      },
    };
  })();

  beforeEach(() => {
    // Reset localStorage before each test
    Object.defineProperty(window, 'localStorage', {
      value: localStorageMock,
      writable: true,
    });
    localStorageMock.clear();
  });

  describe('saveTokens', () => {
    it('should save both access and refresh tokens', () => {
      const tokens = {
        accessToken: 'test-access-token',
        refreshToken: 'test-refresh-token',
      };

      saveTokens(tokens);

      expect(localStorage.getItem('triterm_access_token')).toBe(tokens.accessToken);
      expect(localStorage.getItem('triterm_refresh_token')).toBe(tokens.refreshToken);
    });

    it('should overwrite existing tokens', () => {
      const oldTokens = {
        accessToken: 'old-access-token',
        refreshToken: 'old-refresh-token',
      };
      const newTokens = {
        accessToken: 'new-access-token',
        refreshToken: 'new-refresh-token',
      };

      saveTokens(oldTokens);
      saveTokens(newTokens);

      expect(localStorage.getItem('triterm_access_token')).toBe(newTokens.accessToken);
      expect(localStorage.getItem('triterm_refresh_token')).toBe(newTokens.refreshToken);
    });
  });

  describe('getAccessToken', () => {
    it('should retrieve saved access token', () => {
      const token = 'test-access-token';
      localStorage.setItem('triterm_access_token', token);

      expect(getAccessToken()).toBe(token);
    });

    it('should return null when no token exists', () => {
      expect(getAccessToken()).toBeNull();
    });
  });

  describe('getRefreshToken', () => {
    it('should retrieve saved refresh token', () => {
      const token = 'test-refresh-token';
      localStorage.setItem('triterm_refresh_token', token);

      expect(getRefreshToken()).toBe(token);
    });

    it('should return null when no token exists', () => {
      expect(getRefreshToken()).toBeNull();
    });
  });

  describe('clearTokens', () => {
    it('should remove both tokens', () => {
      saveTokens({
        accessToken: 'test-access-token',
        refreshToken: 'test-refresh-token',
      });

      clearTokens();

      expect(localStorage.getItem('triterm_access_token')).toBeNull();
      expect(localStorage.getItem('triterm_refresh_token')).toBeNull();
    });

    it('should not throw error when tokens do not exist', () => {
      expect(() => clearTokens()).not.toThrow();
    });
  });

  describe('isAuthenticated', () => {
    it('should return true when access token exists', () => {
      saveTokens({
        accessToken: 'test-access-token',
        refreshToken: 'test-refresh-token',
      });

      expect(isAuthenticated()).toBe(true);
    });

    it('should return false when no access token exists', () => {
      expect(isAuthenticated()).toBe(false);
    });

    it('should return true even if only access token exists', () => {
      localStorage.setItem('triterm_access_token', 'test-access-token');

      expect(isAuthenticated()).toBe(true);
    });

    it('should return false after tokens are cleared', () => {
      saveTokens({
        accessToken: 'test-access-token',
        refreshToken: 'test-refresh-token',
      });

      clearTokens();

      expect(isAuthenticated()).toBe(false);
    });
  });
});
