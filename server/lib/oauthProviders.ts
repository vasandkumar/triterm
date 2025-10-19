import axios from 'axios';
import logger from '../config/logger.js';

export interface OAuthProvider {
  name: string;
  authorizationUrl: string;
  tokenUrl: string;
  userInfoUrl: string;
  clientId: string;
  clientSecret: string;
  scope: string;
  redirectUri: string;
}

export interface OAuthUser {
  id: string;
  email: string;
  name?: string;
  avatar?: string;
  provider: string;
}

class OAuthService {
  private providers: Map<string, OAuthProvider> = new Map();

  /**
   * Register an OAuth provider
   */
  registerProvider(name: string, config: Omit<OAuthProvider, 'name'>): void {
    this.providers.set(name, {
      name,
      ...config,
    });
    logger.info('OAuth provider registered', { provider: name });
  }

  /**
   * Get authorization URL for a provider
   */
  getAuthorizationUrl(providerName: string, state: string): string | null {
    const provider = this.providers.get(providerName);
    if (!provider) {
      logger.warn('OAuth provider not found', { provider: providerName });
      return null;
    }

    const params = new URLSearchParams({
      client_id: provider.clientId,
      redirect_uri: provider.redirectUri,
      response_type: 'code',
      scope: provider.scope,
      state,
    });

    return `${provider.authorizationUrl}?${params.toString()}`;
  }

  /**
   * Exchange authorization code for access token
   */
  async exchangeCodeForToken(
    providerName: string,
    code: string
  ): Promise<{ access_token: string; refresh_token?: string } | null> {
    const provider = this.providers.get(providerName);
    if (!provider) {
      logger.warn('OAuth provider not found', { provider: providerName });
      return null;
    }

    try {
      const response = await axios.post(
        provider.tokenUrl,
        {
          client_id: provider.clientId,
          client_secret: provider.clientSecret,
          code,
          redirect_uri: provider.redirectUri,
          grant_type: 'authorization_code',
        },
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
        }
      );

      return response.data;
    } catch (error) {
      logger.error('Failed to exchange OAuth code for token', {
        provider: providerName,
        error,
      });
      return null;
    }
  }

  /**
   * Get user information from provider
   */
  async getUserInfo(providerName: string, accessToken: string): Promise<OAuthUser | null> {
    const provider = this.providers.get(providerName);
    if (!provider) {
      logger.warn('OAuth provider not found', { provider: providerName });
      return null;
    }

    try {
      const response = await axios.get(provider.userInfoUrl, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      });

      // Transform provider-specific user data to our format
      return this.transformUserInfo(providerName, response.data);
    } catch (error) {
      logger.error('Failed to get OAuth user info', {
        provider: providerName,
        error,
      });
      return null;
    }
  }

  /**
   * Transform provider-specific user data to standard format
   */
  private transformUserInfo(providerName: string, data: any): OAuthUser {
    switch (providerName) {
      case 'google':
        return {
          id: data.sub || data.id,
          email: data.email,
          name: data.name,
          avatar: data.picture,
          provider: 'google',
        };

      case 'github':
        return {
          id: data.id.toString(),
          email: data.email,
          name: data.name || data.login,
          avatar: data.avatar_url,
          provider: 'github',
        };

      case 'microsoft':
        return {
          id: data.id,
          email: data.userPrincipalName || data.mail,
          name: data.displayName,
          avatar: undefined,
          provider: 'microsoft',
        };

      default:
        // Generic transformation
        return {
          id: data.id || data.sub,
          email: data.email,
          name: data.name,
          avatar: data.picture || data.avatar_url,
          provider: providerName,
        };
    }
  }

  /**
   * List available OAuth providers
   */
  getAvailableProviders(): string[] {
    return Array.from(this.providers.keys());
  }
}

// Export singleton instance
export const oauthService = new OAuthService();

// Initialize default providers if environment variables are set
export function initializeOAuthProviders(): void {
  // Google OAuth
  if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
    oauthService.registerProvider('google', {
      authorizationUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
      tokenUrl: 'https://oauth2.googleapis.com/token',
      userInfoUrl: 'https://www.googleapis.com/oauth2/v2/userinfo',
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      scope: 'openid email profile',
      redirectUri: process.env.OAUTH_REDIRECT_URI || 'http://localhost:3000/api/auth/oauth/callback',
    });
  }

  // GitHub OAuth
  if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
    oauthService.registerProvider('github', {
      authorizationUrl: 'https://github.com/login/oauth/authorize',
      tokenUrl: 'https://github.com/login/oauth/access_token',
      userInfoUrl: 'https://api.github.com/user',
      clientId: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      scope: 'read:user user:email',
      redirectUri: process.env.OAUTH_REDIRECT_URI || 'http://localhost:3000/api/auth/oauth/callback',
    });
  }

  // Microsoft OAuth
  if (process.env.MICROSOFT_CLIENT_ID && process.env.MICROSOFT_CLIENT_SECRET) {
    const tenantId = process.env.MICROSOFT_TENANT_ID || 'common';
    oauthService.registerProvider('microsoft', {
      authorizationUrl: `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/authorize`,
      tokenUrl: `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`,
      userInfoUrl: 'https://graph.microsoft.com/v1.0/me',
      clientId: process.env.MICROSOFT_CLIENT_ID,
      clientSecret: process.env.MICROSOFT_CLIENT_SECRET,
      scope: 'openid email profile User.Read',
      redirectUri: process.env.OAUTH_REDIRECT_URI || 'http://localhost:3000/api/auth/oauth/callback',
    });
  }
}
