/**
 * OIDC Authentication Service for Keycloak Integration
 * 
 * Handles OpenID Connect authentication flows with Keycloak including:
 * - Authorization Code flow with PKCE
 * - Token refresh
 * - Silent authentication
 * - Logout
 */

export interface AuthUser {
  id: string
  email: string
  role: 'viewer' | 'auditor' | 'admin'
  firstName?: string
  lastName?: string
}

// OIDC Configuration from environment
const OIDC_CONFIG = {
  authority: import.meta.env.VITE_OIDC_AUTHORITY || 'http://localhost:8080/realms/securesys',
  clientId: import.meta.env.VITE_OIDC_CLIENT_ID || 'securesys-frontend',
  redirectUri: import.meta.env.VITE_OIDC_REDIRECT_URI || `${window.location.origin}/auth/callback`,
  postLogoutRedirectUri: import.meta.env.VITE_OIDC_POST_LOGOUT_URI || window.location.origin,
  scope: 'openid profile email roles',
  responseType: 'code',
}

// Storage keys
const STORAGE_KEYS = {
  codeVerifier: 'oidc_code_verifier',
  state: 'oidc_state',
  nonce: 'oidc_nonce',
  tokens: 'oidc_tokens',
}

// OIDC endpoint paths
const ENDPOINTS = {
  authorization: '/protocol/openid-connect/auth',
  token: '/protocol/openid-connect/token',
  userinfo: '/protocol/openid-connect/userinfo',
  logout: '/protocol/openid-connect/logout',
}

/**
 * Generate a random string for PKCE and state
 */
function generateRandomString(length: number): string {
  const array = new Uint8Array(length)
  crypto.getRandomValues(array)
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('')
}

/**
 * Generate PKCE code verifier and challenge
 */
async function generatePKCE(): Promise<{ verifier: string; challenge: string }> {
  const verifier = generateRandomString(64)
  
  // Create SHA-256 hash of verifier
  const encoder = new TextEncoder()
  const data = encoder.encode(verifier)
  const hash = await crypto.subtle.digest('SHA-256', data)
  
  // Base64url encode the hash
  const challenge = btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
  
  return { verifier, challenge }
}

/**
 * Parse JWT token claims (without verification - verification happens server-side)
 */
function parseJwt(token: string): Record<string, any> {
  try {
    const base64Url = token.split('.')[1]
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/')
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split('')
        .map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    )
    return JSON.parse(jsonPayload)
  } catch {
    return {}
  }
}

/**
 * OIDC Tokens interface
 */
export interface OIDCTokens {
  accessToken: string
  refreshToken: string
  idToken: string
  expiresAt: number
}

/**
 * OIDC Service for Keycloak authentication
 */
export class OIDCService {
  private config = OIDC_CONFIG

  /**
   * Check if OIDC is enabled
   */
  isEnabled(): boolean {
    return import.meta.env.VITE_OIDC_ENABLED === 'true'
  }

  /**
   * Initiate OIDC login flow
   */
  async login(): Promise<void> {
    const { verifier, challenge } = await generatePKCE()
    const state = generateRandomString(32)
    const nonce = generateRandomString(32)

    // Store values for callback verification
    sessionStorage.setItem(STORAGE_KEYS.codeVerifier, verifier)
    sessionStorage.setItem(STORAGE_KEYS.state, state)
    sessionStorage.setItem(STORAGE_KEYS.nonce, nonce)

    // Build authorization URL
    const params = new URLSearchParams({
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      response_type: this.config.responseType,
      scope: this.config.scope,
      state: state,
      nonce: nonce,
      code_challenge: challenge,
      code_challenge_method: 'S256',
    })

    const authUrl = `${this.config.authority}${ENDPOINTS.authorization}?${params}`
    window.location.href = authUrl
  }

  /**
   * Handle OIDC callback after authentication
   */
  async handleCallback(callbackUrl: string): Promise<{ user: AuthUser; tokens: OIDCTokens }> {
    const url = new URL(callbackUrl)
    const code = url.searchParams.get('code')
    const state = url.searchParams.get('state')
    const error = url.searchParams.get('error')
    const errorDescription = url.searchParams.get('error_description')

    if (error) {
      throw new Error(`Authentication failed: ${errorDescription || error}`)
    }

    if (!code) {
      throw new Error('No authorization code received')
    }

    // Verify state
    const storedState = sessionStorage.getItem(STORAGE_KEYS.state)
    if (state !== storedState) {
      throw new Error('Invalid state parameter - possible CSRF attack')
    }

    // Get code verifier
    const codeVerifier = sessionStorage.getItem(STORAGE_KEYS.codeVerifier)
    if (!codeVerifier) {
      throw new Error('Code verifier not found')
    }

    // Exchange code for tokens
    const tokens = await this.exchangeCodeForTokens(code, codeVerifier)

    // Clear temporary storage
    sessionStorage.removeItem(STORAGE_KEYS.codeVerifier)
    sessionStorage.removeItem(STORAGE_KEYS.state)
    sessionStorage.removeItem(STORAGE_KEYS.nonce)

    // Parse user info from token
    const user = this.extractUserFromToken(tokens.idToken)

    // Store tokens
    this.storeTokens(tokens)

    return { user, tokens }
  }

  /**
   * Exchange authorization code for tokens
   */
  private async exchangeCodeForTokens(code: string, codeVerifier: string): Promise<OIDCTokens> {
    const response = await fetch(`${this.config.authority}${ENDPOINTS.token}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: this.config.clientId,
        code: code,
        redirect_uri: this.config.redirectUri,
        code_verifier: codeVerifier,
      }),
    })

    if (!response.ok) {
      const error = await response.text()
      throw new Error(`Token exchange failed: ${error}`)
    }

    const data = await response.json()

    return {
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
      idToken: data.id_token,
      expiresAt: Date.now() + data.expires_in * 1000,
    }
  }

  /**
   * Refresh access token
   */
  async refreshTokens(): Promise<OIDCTokens | null> {
    const tokens = this.getStoredTokens()
    if (!tokens?.refreshToken) {
      return null
    }

    try {
      const response = await fetch(`${this.config.authority}${ENDPOINTS.token}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          client_id: this.config.clientId,
          refresh_token: tokens.refreshToken,
        }),
      })

      if (!response.ok) {
        // Refresh token expired or invalid
        this.clearTokens()
        return null
      }

      const data = await response.json()

      const newTokens: OIDCTokens = {
        accessToken: data.access_token,
        refreshToken: data.refresh_token || tokens.refreshToken,
        idToken: data.id_token || tokens.idToken,
        expiresAt: Date.now() + data.expires_in * 1000,
      }

      this.storeTokens(newTokens)
      return newTokens
    } catch {
      return null
    }
  }

  /**
   * Get valid access token, refreshing if needed
   */
  async getValidAccessToken(): Promise<string | null> {
    const tokens = this.getStoredTokens()
    if (!tokens) {
      return null
    }

    // Check if token is expired or will expire in the next 30 seconds
    if (tokens.expiresAt < Date.now() + 30000) {
      const newTokens = await this.refreshTokens()
      return newTokens?.accessToken || null
    }

    return tokens.accessToken
  }

  /**
   * Logout and redirect to Keycloak logout
   */
  async logout(): Promise<void> {
    const tokens = this.getStoredTokens()
    this.clearTokens()

    if (tokens?.idToken) {
      const params = new URLSearchParams({
        client_id: this.config.clientId,
        id_token_hint: tokens.idToken,
        post_logout_redirect_uri: this.config.postLogoutRedirectUri,
      })

      window.location.href = `${this.config.authority}${ENDPOINTS.logout}?${params}`
    } else {
      window.location.href = '/'
    }
  }

  /**
   * Extract user info from ID token
   */
  private extractUserFromToken(idToken: string): AuthUser {
    const claims = parseJwt(idToken)

    // Extract role from realm_access or resource_access
    let role: AuthUser['role'] = 'viewer'
    const realmRoles = claims.realm_access?.roles || []
    if (realmRoles.includes('admin')) {
      role = 'admin'
    } else if (realmRoles.includes('auditor')) {
      role = 'auditor'
    }

    return {
      id: claims.sub,
      email: claims.email || claims.preferred_username,
      firstName: claims.given_name || '',
      lastName: claims.family_name || '',
      role,
    }
  }

  /**
   * Store tokens in localStorage
   */
  private storeTokens(tokens: OIDCTokens): void {
    localStorage.setItem(STORAGE_KEYS.tokens, JSON.stringify(tokens))
  }

  /**
   * Get stored tokens
   */
  getStoredTokens(): OIDCTokens | null {
    const stored = localStorage.getItem(STORAGE_KEYS.tokens)
    if (!stored) {
      return null
    }

    try {
      return JSON.parse(stored)
    } catch {
      return null
    }
  }

  /**
   * Clear stored tokens
   */
  clearTokens(): void {
    localStorage.removeItem(STORAGE_KEYS.tokens)
  }

  /**
   * Check if user is authenticated
   */
  isAuthenticated(): boolean {
    const tokens = this.getStoredTokens()
    return tokens !== null && tokens.expiresAt > Date.now()
  }

  /**
   * Get current user from stored tokens
   */
  getCurrentUser(): AuthUser | null {
    const tokens = this.getStoredTokens()
    if (!tokens?.idToken) {
      return null
    }
    return this.extractUserFromToken(tokens.idToken)
  }
}

// Export singleton instance
export const oidcService = new OIDCService()
