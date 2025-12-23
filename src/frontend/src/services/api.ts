import axios from 'axios'
import { useAuthStore } from '../stores/authStore'

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

// Systems API (uses new scanning module)
export const systemsApi = {
  getAll: async () => {
    const response = await scanningApi.get('/systems/')
    return response.data.results || response.data
  },
  
  getById: async (id: string) => {
    const response = await scanningApi.get(`/systems/${id}/`)
    return response.data
  },
  
  create: async (data: { hostname: string; os: string; environment: string }) => {
    const response = await scanningApi.post('/systems/', data)
    return response.data
  },
  
  getScans: async (systemId: string) => {
    const response = await scanningApi.get(`/systems/${systemId}/scans/`)
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
    const response = await scanningApi.get('/scans/')
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
    const response = await scanningApi.get(`/scans/${scanId}/findings/`, {
      params: filters
    })
    return response.data
  },
  
  getSummary: async (scanId: string) => {
    const response = await scanningApi.get(`/scans/${scanId}/summary/`)
    return response.data
  },
}

// Findings API (uses new scanning module)
export const findingsApi = {
  getAll: async (filters?: { severity?: string; category?: string; is_resolved?: boolean }) => {
    const response = await scanningApi.get('/findings/', { params: filters })
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
    const response = await scanningApi.get('/dashboard/stats/')
    return response.data
  },
}

export default api
