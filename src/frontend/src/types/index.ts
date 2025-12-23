// Type definitions for SecureSys Auditor

export interface User {
  id: string
  email: string
  first_name: string
  last_name: string
  role: 'viewer' | 'auditor' | 'admin'
  is_active: boolean
  created_at: string
  updated_at: string
}

export interface System {
  id: string
  hostname: string
  os: string
  os_version?: string
  environment: 'development' | 'staging' | 'production' | 'testing'
  ip_address?: string
  description?: string
  is_active: boolean
  created_at: string
  updated_at: string
  last_seen?: string
  latest_risk_score?: number
  latest_maturity_level?: string
}

export interface Scan {
  id: string
  system: string
  system_hostname?: string
  scan_date: string
  status: 'pending' | 'processing' | 'completed' | 'failed'
  risk_score?: number
  maturity_level?: 'reactive' | 'basic' | 'managed' | 'optimized'
  score_breakdown?: {
    critical: number
    high: number
    medium: number
    low: number
  }
  error_message?: string
  started_at?: string
  completed_at?: string
  created_at: string
  updated_at: string
  findings_count?: number
  findings?: Finding[]
}

export interface Finding {
  id: string
  scan: string
  category: 'access_control' | 'configuration' | 'patch_management' | 'network' | 'authentication' | 'encryption' | 'logging' | 'other'
  severity: 'low' | 'medium' | 'high' | 'critical'
  title: string
  description: string
  evidence?: Record<string, unknown>
  cwe_id?: string
  cvss_score?: number
  is_resolved: boolean
  resolved_at?: string
  created_at: string
  updated_at: string
  recommendations?: Recommendation[]
}

export interface Recommendation {
  id: string
  finding: string
  priority: 'low' | 'medium' | 'high' | 'critical'
  effort: 'low' | 'medium' | 'high'
  title: string
  description: string
  steps: string[]
  script_bash?: string
  script_powershell?: string
  script_ansible?: string
  references?: string[]
  created_at: string
  updated_at: string
}

export interface DashboardStats {
  total_systems: number
  total_scans: number
  completed_scans: number
  severity_counts: {
    critical: number
    high: number
    medium: number
    low: number
  }
  average_risk_score: number
  total_unresolved_findings: number
}

export interface AuditLog {
  id: string
  user: string
  user_email?: string
  action: string
  timestamp: string
  ip_address?: string
  resource_type?: string
  resource_id?: string
  metadata?: Record<string, unknown>
}
