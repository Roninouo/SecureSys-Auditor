import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import { oidcService } from '../services/oidc'

interface User {
  id: string
  email: string
  role: string
  firstName?: string
  lastName?: string
}

interface AuthState {
  user: User | null
  accessToken: string | null
  refreshToken: string | null
  isAuthenticated: boolean
  authMethod: 'jwt' | 'oidc' | null
  login: (user: User, accessToken: string, refreshToken: string) => void
  loginOIDC: (user: User, accessToken: string, refreshToken: string) => void
  logout: () => void
  setTokens: (accessToken: string, refreshToken: string) => void
  refreshAccessToken: () => Promise<boolean>
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      user: null,
      accessToken: null,
      refreshToken: null,
      isAuthenticated: false,
      authMethod: null,

      login: (user, accessToken, refreshToken) =>
        set({
          user,
          accessToken,
          refreshToken,
          isAuthenticated: true,
          authMethod: 'jwt',
        }),

      loginOIDC: (user, accessToken, refreshToken) =>
        set({
          user,
          accessToken,
          refreshToken,
          isAuthenticated: true,
          authMethod: 'oidc',
        }),

      logout: () => {
        const state = get()

        // Clear state first
        set({
          user: null,
          accessToken: null,
          refreshToken: null,
          isAuthenticated: false,
          authMethod: null,
        })

        // If using OIDC, also logout from Keycloak
        if (state.authMethod === 'oidc') {
          oidcService.logout()
        }
      },

      setTokens: (accessToken, refreshToken) =>
        set({
          accessToken,
          refreshToken,
        }),

      refreshAccessToken: async () => {
        const state = get()

        if (state.authMethod === 'oidc') {
          const tokens = await oidcService.refreshTokens()
          if (tokens) {
            set({
              accessToken: tokens.accessToken,
              refreshToken: tokens.refreshToken,
            })
            return true
          }
          return false
        }

        // JWT refresh handled by API interceptor
        return true
      },
    }),
    {
      name: 'auth-storage',
    }
  )
)
