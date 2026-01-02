/**
 * SecureSys Auditor TypeScript Client
 *
 * A type-safe client for the SecureSys Auditor API.
 *
 * @example
 * ```typescript
 * import { SecureSysClient, Finding } from './securesys-client';
 *
 * const client = new SecureSysClient({
 *   apiUrl: 'https://api.securesys.io',
 *   apiKey: 'your-api-key'
 * });
 *
 * const scan = await client.submitScan({
 *   hostname: 'webserver-01.example.com',
 *   scanType: 'vulnerability',
 *   findings: [
 *     { title: 'CVE-2023-1234', severity: 'high', description: '...' }
 *   ]
 * });
 * ```
 */

// =============================================================================
// Types
// =============================================================================

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type ScanType = 'vulnerability' | 'compliance' | 'configuration';
export type ScanStatus = 'pending' | 'processing' | 'completed' | 'failed';

export interface Finding {
  title: string;
  severity: Severity;
  description: string;
  recommendation?: string;
  affectedComponent?: string;
  cveId?: string;
  cweId?: string;
}

export interface ScanSubmission {
  hostname: string;
  scanType: ScanType;
  findings: Finding[];
  agentVersion?: string;
  metadata?: Record<string, unknown>;
}

export interface ScanResult {
  id: string;
  hostname: string;
  scanType: ScanType;
  status: ScanStatus;
  createdAt: string;
  completedAt?: string;
  findingsCount: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
}

export interface PaginatedResponse<T> {
  count: number;
  next: string | null;
  previous: string | null;
  results: T[];
}

export interface DashboardStats {
  totalSystems: number;
  totalScans: number;
  totalFindings: number;
  criticalFindings: number;
  highFindings: number;
  recentScans: ScanResult[];
}

export interface WebhookEndpoint {
  id: string;
  name: string;
  url: string;
  eventTypes: string[];
  isActive: boolean;
  lastTriggered?: string;
}

export interface ClientConfig {
  apiUrl: string;
  apiKey: string;
  timeout?: number;
  retries?: number;
}

// =============================================================================
// Errors
// =============================================================================

export class SecureSysError extends Error {
  constructor(
    message: string,
    public statusCode?: number,
    public response?: unknown
  ) {
    super(message);
    this.name = 'SecureSysError';
  }
}

export class AuthenticationError extends SecureSysError {
  constructor(message: string = 'Authentication failed') {
    super(message, 401);
    this.name = 'AuthenticationError';
  }
}

export class RateLimitError extends SecureSysError {
  constructor(
    message: string = 'Rate limit exceeded',
    public retryAfter?: number
  ) {
    super(message, 429);
    this.name = 'RateLimitError';
  }
}

export class ValidationError extends SecureSysError {
  constructor(message: string, public errors?: Record<string, string[]>) {
    super(message, 400);
    this.name = 'ValidationError';
  }
}

// =============================================================================
// Client
// =============================================================================

export class SecureSysClient {
  private apiUrl: string;
  private apiKey: string;
  private timeout: number;
  private retries: number;

  constructor(config: ClientConfig) {
    this.apiUrl = config.apiUrl.replace(/\/$/, '');
    this.apiKey = config.apiKey;
    this.timeout = config.timeout ?? 30000;
    this.retries = config.retries ?? 3;
  }

  // ===========================================================================
  // Private Methods
  // ===========================================================================

  private async request<T>(
    method: string,
    endpoint: string,
    options: {
      body?: unknown;
      params?: Record<string, string | number>;
    } = {}
  ): Promise<T> {
    const url = new URL(`${this.apiUrl}${endpoint}`);

    if (options.params) {
      Object.entries(options.params).forEach(([key, value]) => {
        url.searchParams.append(key, String(value));
      });
    }

    const headers: HeadersInit = {
      'Authorization': `Bearer ${this.apiKey}`,
      'Content-Type': 'application/json',
      'User-Agent': 'SecureSys-TypeScript-Client/1.0',
    };

    let lastError: Error | null = null;

    for (let attempt = 0; attempt < this.retries; attempt++) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);

        const response = await fetch(url.toString(), {
          method,
          headers,
          body: options.body ? JSON.stringify(options.body) : undefined,
          signal: controller.signal,
        });

        clearTimeout(timeoutId);

        if (response.status === 401) {
          throw new AuthenticationError();
        }

        if (response.status === 429) {
          const retryAfter = response.headers.get('Retry-After');
          throw new RateLimitError(
            'Rate limit exceeded',
            retryAfter ? parseInt(retryAfter, 10) : undefined
          );
        }

        if (response.status === 400) {
          const errorData = await response.json();
          throw new ValidationError('Validation failed', errorData);
        }

        if (!response.ok) {
          throw new SecureSysError(
            `API error: ${response.statusText}`,
            response.status
          );
        }

        const text = await response.text();
        return text ? JSON.parse(text) : {} as T;

      } catch (error) {
        lastError = error as Error;

        // Don't retry auth errors or validation errors
        if (
          error instanceof AuthenticationError ||
          error instanceof ValidationError
        ) {
          throw error;
        }

        // Retry on rate limit with backoff
        if (error instanceof RateLimitError && error.retryAfter) {
          await this.sleep(error.retryAfter * 1000);
          continue;
        }

        // Exponential backoff for other errors
        if (attempt < this.retries - 1) {
          await this.sleep(Math.pow(2, attempt) * 1000);
        }
      }
    }

    throw lastError || new SecureSysError('Request failed after retries');
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  private toSnakeCase(obj: Record<string, unknown>): Record<string, unknown> {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj)) {
      const snakeKey = key.replace(/([A-Z])/g, '_$1').toLowerCase();
      result[snakeKey] = value;
    }
    return result;
  }

  // ===========================================================================
  // Health & Status
  // ===========================================================================

  async healthCheck(): Promise<{ status: string; version: string }> {
    return this.request('GET', '/api/v1/health/');
  }

  // ===========================================================================
  // Scans
  // ===========================================================================

  async submitScan(scan: ScanSubmission): Promise<ScanResult> {
    const now = new Date().toISOString();

    const body = {
      hostname: scan.hostname,
      scan_type: scan.scanType,
      agent_version: scan.agentVersion || 'typescript-client-1.0',
      started_at: now,
      completed_at: now,
      findings: scan.findings.map(f => ({
        title: f.title,
        severity: f.severity,
        description: f.description,
        recommendation: f.recommendation || '',
        affected_component: f.affectedComponent || '',
        cve_id: f.cveId,
        cwe_id: f.cweId,
      })),
      metadata: scan.metadata || {},
    };

    const result = await this.request<Record<string, unknown>>('POST', '/api/v1/scans/', { body });
    return this.parseScanResult(result);
  }

  async getScan(scanId: string): Promise<ScanResult> {
    const result = await this.request<Record<string, unknown>>('GET', `/api/v1/scans/${scanId}/`);
    return this.parseScanResult(result);
  }

  async listScans(options?: {
    page?: number;
    pageSize?: number;
    hostname?: string;
    status?: ScanStatus;
  }): Promise<PaginatedResponse<ScanResult>> {
    const params: Record<string, string | number> = {
      page: options?.page ?? 1,
      page_size: options?.pageSize ?? 20,
    };

    if (options?.hostname) params.hostname = options.hostname;
    if (options?.status) params.status = options.status;

    const result = await this.request<{
      count: number;
      next: string | null;
      previous: string | null;
      results: Record<string, unknown>[];
    }>('GET', '/api/v1/scans/', { params });

    return {
      ...result,
      results: result.results.map(r => this.parseScanResult(r)),
    };
  }

  async getScanFindings(scanId: string): Promise<Finding[]> {
    const result = await this.request<{ results: Finding[] }>(
      'GET',
      `/api/v1/scans/${scanId}/findings/`
    );
    return result.results;
  }

  // ===========================================================================
  // Systems
  // ===========================================================================

  async listSystems(options?: {
    page?: number;
    pageSize?: number;
  }): Promise<PaginatedResponse<{ id: string; hostname: string; lastScan?: string }>> {
    return this.request('GET', '/api/v1/systems/', {
      params: {
        page: options?.page ?? 1,
        page_size: options?.pageSize ?? 20,
      },
    });
  }

  // ===========================================================================
  // Dashboard
  // ===========================================================================

  async getDashboardStats(): Promise<DashboardStats> {
    return this.request('GET', '/api/v1/dashboard/stats/');
  }

  async getSeverityBreakdown(): Promise<Record<Severity, number>> {
    return this.request('GET', '/api/v1/dashboard/severity-breakdown/');
  }

  // ===========================================================================
  // Webhooks
  // ===========================================================================

  async listWebhooks(): Promise<WebhookEndpoint[]> {
    const result = await this.request<{ results: WebhookEndpoint[] }>(
      'GET',
      '/api/v1/webhooks/'
    );
    return result.results;
  }

  async createWebhook(webhook: {
    name: string;
    url: string;
    eventTypes: string[];
    secret?: string;
  }): Promise<WebhookEndpoint> {
    return this.request('POST', '/api/v1/webhooks/', {
      body: {
        name: webhook.name,
        url: webhook.url,
        event_types: webhook.eventTypes,
        secret: webhook.secret,
      },
    });
  }

  // ===========================================================================
  // Helpers
  // ===========================================================================

  private parseScanResult(data: Record<string, unknown>): ScanResult {
    return {
      id: data.id as string,
      hostname: data.hostname as string,
      scanType: data.scan_type as ScanType,
      status: data.status as ScanStatus,
      createdAt: data.created_at as string,
      completedAt: data.completed_at as string | undefined,
      findingsCount: (data.findings_count as number) ?? 0,
      criticalCount: (data.critical_count as number) ?? 0,
      highCount: (data.high_count as number) ?? 0,
      mediumCount: (data.medium_count as number) ?? 0,
      lowCount: (data.low_count as number) ?? 0,
    };
  }
}

// =============================================================================
// Factory Function
// =============================================================================

export function createClient(config: ClientConfig): SecureSysClient {
  return new SecureSysClient(config);
}

// =============================================================================
// Example Usage
// =============================================================================

/*
const client = new SecureSysClient({
  apiUrl: 'https://api.securesys.io',
  apiKey: 'your-api-key',
});

// Submit a scan
const scan = await client.submitScan({
  hostname: 'webserver-01.example.com',
  scanType: 'vulnerability',
  findings: [
    {
      title: 'CVE-2023-1234',
      severity: 'high',
      description: 'A vulnerability was found',
      recommendation: 'Update to the latest version',
    },
  ],
});

console.log(`Submitted scan: ${scan.id}`);

// List recent scans
const scans = await client.listScans({ pageSize: 10 });
console.log(`Found ${scans.count} scans`);
*/
