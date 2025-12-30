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

export type SystemType = 'server' | 'website'

export interface System {
  id: string
  system_type: SystemType
  hostname: string
  url?: string
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
  scan_type?: 'full' | 'quick' | 'compliance' | 'vulnerability' | 'url_scan'
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
  scan_payload?: URLScanPayload
}

export interface URLScanPayload {
  url: string
  final_url: string
  status_code: number
  response_time_ms: number
  ssl_info?: SSLInfo
  security_headers?: SecurityHeaders
  cookies?: CookieInfo[]
  redirects?: string[]
  server_info?: Record<string, string>
  scan_timestamp?: string
  errors?: string[]
}

export interface SSLInfo {
  is_valid: boolean
  issuer: string
  subject: string
  not_before?: string
  not_after?: string
  days_until_expiry?: number
  protocol_version?: string
  cipher_suite?: string
  key_size?: number
  is_self_signed?: boolean
  san_domains?: string[]
  errors?: string[]
}

export interface SecurityHeaders {
  strict_transport_security?: string
  content_security_policy?: string
  x_frame_options?: string
  x_content_type_options?: string
  x_xss_protection?: string
  referrer_policy?: string
  permissions_policy?: string
  cross_origin_opener_policy?: string
  cross_origin_resource_policy?: string
  server?: string
  x_powered_by?: string
  missing_headers?: string[]
  weak_headers?: Array<{ header: string; issue: string }>
}

export interface CookieInfo {
  name: string
  secure: boolean
  http_only: boolean
  same_site?: string
  path?: string
  domain?: string
  expires?: string
  issues?: string[]
}

export interface Finding {
  id: string
  scan: string
  category: 'access_control' | 'configuration' | 'patch_management' | 'network' | 'authentication' | 'encryption' | 'logging' | 'web_security' | 'ssl_tls' | 'http_headers' | 'other'
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
  recent_scans?: Scan[]
  systems_by_environment?: {
    development?: number
    staging?: number
    production?: number
    testing?: number
  }
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

export interface URLScanRequest {
  url: string
  environment?: 'development' | 'staging' | 'production' | 'testing'
  description?: string
}

export interface URLScanResponse {
  scan_id: string
  system_id: string
  url: string
  status: 'completed' | 'failed'
  risk_score: number
  maturity_level: string
  findings_count: number
  score_breakdown: {
    critical: number
    high: number
    medium: number
    low: number
  }
  scan_details: {
    final_url: string
    status_code: number
    response_time_ms: number
    ssl_valid?: boolean
    ssl_days_until_expiry?: number
    missing_headers: string[]
    redirects: string[]
    errors: string[]
  }
}
