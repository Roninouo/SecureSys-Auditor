import axios from 'axios'
import { useAuthStore } from '../stores/authStore'
import { usePreferencesStore } from '../stores/preferencesStore'

const API_BASE_URL = import.meta.env.VITE_API_URL || '/api/v1'

// New scanning API base URL (decoupled architecture)
const SCANNING_API_URL = import.meta.env.VITE_SCANNING_API_URL || '/api/v1/scanning'

export const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Create scanning-specific API instance
export const scanningApi = axios.create({
  baseURL: SCANNING_API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Request interceptor to add auth token
api.interceptors.request.use(
  (config) => {
    const token = useAuthStore.getState().accessToken
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// Apply same interceptors to scanning API
scanningApi.interceptors.request.use(
  (config) => {
    const token = useAuthStore.getState().accessToken
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// Response interceptor to handle 401 errors
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config

    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true

      const refreshToken = useAuthStore.getState().refreshToken

      if (refreshToken) {
        try {
          const response = await axios.post(`${API_BASE_URL}/auth/refresh/`, {
            refresh: refreshToken,
          })

          const { access, refresh } = response.data
          useAuthStore.getState().setTokens(access, refresh)

          originalRequest.headers.Authorization = `Bearer ${access}`
          return api(originalRequest)
        } catch (refreshError) {
          useAuthStore.getState().logout()
          window.location.href = '/login'
        }
      } else {
        useAuthStore.getState().logout()
        window.location.href = '/login'
      }
    }

    return Promise.reject(error)
  }
)

// Apply same response interceptor to scanning API
scanningApi.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config

    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true

      const refreshToken = useAuthStore.getState().refreshToken

      if (refreshToken) {
        try {
          const response = await axios.post(`${API_BASE_URL}/auth/refresh/`, {
            refresh: refreshToken,
          })

          const { access, refresh } = response.data
          useAuthStore.getState().setTokens(access, refresh)

          originalRequest.headers.Authorization = `Bearer ${access}`
          return scanningApi(originalRequest)
        } catch (refreshError) {
          useAuthStore.getState().logout()
          window.location.href = '/login'
        }
      } else {
        useAuthStore.getState().logout()
        window.location.href = '/login'
      }
    }

    return Promise.reject(error)
  }
)

// Auth API
export const authApi = {
  login: async (email: string, password: string) => {
    const response = await api.post('/auth/login/', { email, password })
    return response.data
  },

  refreshToken: async (refreshToken: string) => {
    const response = await api.post('/auth/refresh/', { refresh: refreshToken })
    return response.data
  },
}

// Reports API
export const reportsApi = {
  generate: async (data: {
    scan_id: string
    report_type: 'executive' | 'technical' | 'compliance'
    async?: boolean
    company_name?: string
  }) => {
    const response = await api.post('/reports/generate/', data)
    return response.data
  },

  getStatus: async (taskId: string) => {
    const response = await api.get('/reports/generate/', {
      params: { task_id: taskId },
    })
    return response.data
  },

  download: async (filename: string) => {
    const response = await api.get(`/reports/download/${filename}/`, {
      responseType: 'blob',
    })

    const blob = new Blob([response.data], { type: 'application/pdf' })
    const url = window.URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = filename
    document.body.appendChild(anchor)
    anchor.click()
    anchor.remove()
    window.URL.revokeObjectURL(url)
  },
}

// Systems API (uses new scanning module)
export const systemsApi = {
  getAll: async () => {
    const includeSynthetic = usePreferencesStore.getState().showSyntheticData
    const response = await scanningApi.get('/systems/', {
      params: includeSynthetic ? { include_synthetic: true } : undefined,
    })
    return response.data.results || response.data
  },

  getById: async (id: string) => {
    const response = await scanningApi.get(`/systems/${id}/`)
    return response.data
  },

  create: async (data: {
    hostname: string
    os: string
    environment: string
    description?: string
    ip_address?: string
  }) => {
    const response = await scanningApi.post('/systems/', data)
    return response.data
  },

  update: async (id: string, data: Partial<{
    hostname: string
    os: string
    environment: string
    description?: string
    ip_address?: string
  }>) => {
    const response = await scanningApi.patch(`/systems/${id}/`, data)
    return response.data
  },

  delete: async (id: string) => {
    const response = await scanningApi.delete(`/systems/${id}/`)
    return response.data
  },

  getScans: async (systemId: string) => {
    const includeSynthetic = usePreferencesStore.getState().showSyntheticData
    const response = await scanningApi.get(`/systems/${systemId}/scans/`, {
      params: includeSynthetic ? { include_synthetic: true } : undefined,
    })
    return response.data
  },

  getByHostname: async (hostname: string) => {
    const response = await scanningApi.get(`/systems/by_hostname/`, {
      params: { hostname }
    })
    return response.data
  },
}

// Scans API (uses new scanning module)
export const scansApi = {
  getAll: async () => {
    const includeSynthetic = usePreferencesStore.getState().showSyntheticData
    const response = await scanningApi.get('/scans/', {
      params: includeSynthetic ? { include_synthetic: true } : undefined,
    })
    return response.data.results || response.data
  },

  getById: async (id: string) => {
    const response = await scanningApi.get(`/scans/${id}/`)
    return response.data
  },

  submit: async (data: { system_id: string; scan_payload: object; scan_type?: string }) => {
    const response = await scanningApi.post('/scans/submit/', data)
    return response.data
  },

  getFindings: async (scanId: string, filters?: { severity?: string; category?: string }) => {
    const includeSynthetic = usePreferencesStore.getState().showSyntheticData
    const params = {
      ...(filters || {}),
      ...(includeSynthetic ? { include_synthetic: true } : {}),
    }
    const response = await scanningApi.get(`/scans/${scanId}/findings/`, { params })
    return response.data
  },

  getSummary: async (scanId: string) => {
    const response = await scanningApi.get(`/scans/${scanId}/summary/`)
    return response.data
  },

  // URL/Website scanning with deep content analysis
  scanUrl: async (data: { url: string; environment?: string; description?: string; deep_analysis?: boolean }) => {
    const response = await scanningApi.post('/scans/url/', {
      ...data,
      deep_analysis: data.deep_analysis ?? true, // Enable deep analysis by default
    })
    return response.data
  },
}

// Findings API (uses new scanning module)
export const findingsApi = {
  getAll: async (filters?: { severity?: string; category?: string; is_resolved?: boolean }) => {
    const includeSynthetic = usePreferencesStore.getState().showSyntheticData
    const params = {
      ...(filters || {}),
      ...(includeSynthetic ? { include_synthetic: true } : {}),
    }
    const response = await scanningApi.get('/findings/', { params })
    return response.data.results || response.data
  },

  getById: async (id: string) => {
    const response = await scanningApi.get(`/findings/${id}/`)
    return response.data
  },

  resolve: async (id: string) => {
    const response = await scanningApi.post(`/findings/${id}/resolve/`)
    return response.data
  },

  unresolve: async (id: string) => {
    const response = await scanningApi.post(`/findings/${id}/unresolve/`)
    return response.data
  },

  getRecommendations: async (findingId: string) => {
    const response = await scanningApi.get(`/findings/${findingId}/recommendations/`)
    return response.data
  },
}

// Dashboard API (uses new scanning module)
export const dashboardApi = {
  getStats: async () => {
    const includeSynthetic = usePreferencesStore.getState().showSyntheticData
    const response = await scanningApi.get('/dashboard/stats/', {
      params: includeSynthetic ? { include_synthetic: true } : undefined,
    })
    return response.data
  },
}

export default api
