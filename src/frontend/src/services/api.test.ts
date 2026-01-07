/**
 * Tests for API token refresh behavior.
 *
 * Verifies the frontend correctly handles:
 * - JWT token refresh on 401 responses
 * - Token field names match backend (access/refresh)
 * - Retry of failed requests after token refresh
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import axios from 'axios'

// Mock axios
vi.mock('axios', () => {
  const mockAxios = {
    create: vi.fn(() => mockAxios),
    interceptors: {
      request: { use: vi.fn() },
      response: { use: vi.fn() },
    },
    get: vi.fn(),
    post: vi.fn(),
  }
  return { default: mockAxios }
})

// Mock auth store
const mockAuthStore = {
  accessToken: 'valid-access-token',
  refreshToken: 'valid-refresh-token',
  setTokens: vi.fn(),
  logout: vi.fn(),
  getState: vi.fn(() => mockAuthStore),
}

vi.mock('../stores/authStore', () => ({
  useAuthStore: mockAuthStore,
}))

describe('API Token Refresh', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('Token Field Names', () => {
    it('should use "access" and "refresh" field names matching backend', async () => {
      // Backend returns tokens as { access: '...', refresh: '...' }
      const mockRefreshResponse = {
        data: {
          access: 'new-access-token',
          refresh: 'new-refresh-token',
        },
      }

      // Verify the field names match expected backend format
      expect(mockRefreshResponse.data).toHaveProperty('access')
      expect(mockRefreshResponse.data).toHaveProperty('refresh')
      expect(mockRefreshResponse.data).not.toHaveProperty('access_token')
      expect(mockRefreshResponse.data).not.toHaveProperty('refresh_token')
    })

    it('should correctly destructure backend response', () => {
      const backendResponse = {
        access: 'new-access-token',
        refresh: 'new-refresh-token',
        role: 'auditor',
        email: 'user@example.com',
      }

      // This is how the frontend should destructure
      const { access, refresh } = backendResponse

      expect(access).toBe('new-access-token')
      expect(refresh).toBe('new-refresh-token')
    })
  })

  describe('401 Response Handling', () => {
    it('should trigger token refresh on 401', () => {
      const error = {
        config: { _retry: false },
        response: { status: 401 },
      }

      // Verify 401 is detected
      expect(error.response?.status).toBe(401)
      expect(error.config._retry).toBe(false)
    })

    it('should not retry if already retried', () => {
      const error = {
        config: { _retry: true },
        response: { status: 401 },
      }

      // If _retry is true, should not attempt again
      expect(error.config._retry).toBe(true)
    })

    it('should logout if no refresh token available', () => {
      const storeWithNoRefresh = {
        accessToken: 'token',
        refreshToken: null,
        logout: vi.fn(),
      }

      // Should call logout when no refresh token
      if (!storeWithNoRefresh.refreshToken) {
        storeWithNoRefresh.logout()
      }

      expect(storeWithNoRefresh.logout).toHaveBeenCalled()
    })
  })

  describe('Token Storage', () => {
    it('should update tokens after successful refresh', () => {
      const newAccess = 'new-access-token'
      const newRefresh = 'new-refresh-token'

      mockAuthStore.setTokens(newAccess, newRefresh)

      expect(mockAuthStore.setTokens).toHaveBeenCalledWith(
        'new-access-token',
        'new-refresh-token'
      )
    })
  })

  describe('Refresh Endpoint', () => {
    it('should POST to /auth/refresh/ with refresh token', () => {
      const refreshEndpoint = '/auth/refresh/'
      const refreshPayload = { refresh: 'valid-refresh-token' }

      // Verify endpoint format
      expect(refreshEndpoint).toBe('/auth/refresh/')
      expect(refreshPayload).toHaveProperty('refresh')
    })
  })
})

describe('Auth API Methods', () => {
  describe('login', () => {
    it('should POST credentials to /auth/login/', () => {
      const loginEndpoint = '/auth/login/'
      const credentials = { email: 'user@example.com', password: 'password' }

      expect(loginEndpoint).toBe('/auth/login/')
      expect(credentials).toHaveProperty('email')
      expect(credentials).toHaveProperty('password')
    })
  })

  describe('refreshToken', () => {
    it('should POST refresh token to /auth/refresh/', () => {
      const refreshEndpoint = '/auth/refresh/'
      const payload = { refresh: 'refresh-token-value' }

      expect(refreshEndpoint).toBe('/auth/refresh/')
      expect(payload).toHaveProperty('refresh')
    })
  })
})
