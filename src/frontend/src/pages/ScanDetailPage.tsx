import { useMemo, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  ArrowLeft,
  AlertTriangle,
  CheckCircle,
  Clock,
  Shield,
  ChevronRight,
  Globe,
  Lock,
  ExternalLink,
  RefreshCw
} from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { scansApi } from '@/services/api'
import { safeLabel } from '@/lib/labels'
import {
  cn,
  formatDateTime,
  getRiskScoreColor,
  getMaturityLevelColor,
  getStatusColor,
  getSeverityColor
} from '@/lib/utils'
import type { Scan, Finding } from '@/types'

type FindingGuidance = {
  explanation: string
  impact: string
  remediation: string[]
  verification: string[]
}

function buildFindingGuidance(finding: Finding): FindingGuidance {
  const severityImpact: Record<Finding['severity'], string> = {
    critical: 'Very high impact: may expose sensitive data or allow system compromise.',
    high: 'High impact: significantly increases the risk of exploitation or data leakage.',
    medium: 'Medium impact: weakens controls and enables attacks in certain scenarios.',
    low: 'Low impact: reduces security posture or leaks non-critical information.',
  }

  const base: FindingGuidance = {
    explanation: finding.description || 'A condition was detected that may weaken security.',
    impact: severityImpact[finding.severity],
    remediation: [],
    verification: [],
  }

  const title = (finding.title || '').toLowerCase()
  const category = finding.category

  // Prefer structured recommendations if present.
  if (finding.recommendations && finding.recommendations.length > 0) {
    const top = finding.recommendations[0]
    const steps = (top.steps || []).filter(Boolean)
    base.remediation = [top.description, ...steps].filter(Boolean)
    if (top.references && top.references.length > 0) {
      base.verification = ['Review provided references and re-run the scan to confirm the fix.']
    }
    return base
  }

  // Curated guidance for common web findings (matches the screenshot examples).
  if (title.includes('cookie') || category === 'web_security') {
    base.explanation =
      'Detected cookies do not meet recommended attributes (e.g., Secure, HttpOnly and/or SameSite). This increases the attack surface (session theft, XSS/CSRF, leakage over insecure transport).'
    base.remediation = [
      'Mark session/auth cookies with `Secure` (HTTPS only).',
      'Add `HttpOnly` to prevent access from JavaScript (mitigates XSS).',
      'Set `SameSite=Lax` (or `Strict` where feasible) and use `SameSite=None` only when necessary and always with `Secure`.',
      'Restrict `Domain` and `Path` to the minimum required.',
      'Avoid persistent session cookies unless required (control `Expires/Max-Age`).',
    ]
    base.verification = [
      'Verify HTTP responses and `Set-Cookie` headers (in DevTools or with `curl -I`) to confirm attributes.',
      'Re-run the scan and verify the finding disappears.',
    ]
    return base
  }

  if (title.includes('server information') || title.includes('information disclosure') || category === 'configuration') {
    base.explanation =
      'The server is revealing version/technology information via headers or banners (e.g., `Server`, `X-Powered-By`). This helps an attacker profile the stack and look for specific exploits.'
    base.remediation = [
      'Disable/anonymize identifying headers (e.g., remove `Server` and `X-Powered-By`).',
      'Ensure error pages do not expose stack traces or versions.',
      'Keep components up to date (web server, framework, runtime) to reduce exposure if the stack is inferred.',
    ]
    base.verification = [
      'Run `curl -I https://your-domain` and confirm no sensitive headers are exposed.',
      'Re-run the scan and verify the fix.',
    ]
    return base
  }

  // Generic fallback.
  base.remediation = [
    'Apply configuration hardening according to the affected component.',
    'Reduce exposure of unnecessary information and follow the principle of least privilege.',
    'Re-run the scan to verify remediation.',
  ]
  base.verification = ['Review evidence, apply fixes, and re-scan to confirm.']
  return base
}

export default function ScanDetailPage() {
  const { scanId } = useParams<{ scanId: string }>()
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null)

  const { data: scan, isLoading, error } = useQuery<Scan>({
    queryKey: ['scan', scanId],
    queryFn: () => scansApi.getById(scanId!),
    enabled: !!scanId,
  })

  // All hooks must be called before any conditional returns
  const findings = scan?.findings ?? []
  const guidanceByFindingId = useMemo(() => {
    const map = new Map<string, FindingGuidance>()
    findings.forEach((f) => map.set(f.id, buildFindingGuidance(f)))
    return map
  }, [findings])

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    )
  }

  if (!scan) {
    return (
      <div className="text-center p-8">
        <AlertTriangle className="h-12 w-12 text-yellow-500 mx-auto mb-4" />
        <h2 className="text-lg font-semibold">Scan not found</h2>
        {error ? (
          <p className="text-sm text-muted-foreground mt-2">
            {error instanceof Error ? error.message : 'Failed to load scan details.'}
          </p>
        ) : null}
        <Link to="/systems">
          <Button variant="link">Back to Systems</Button>
        </Link>
      </div>
    )
  }

  const isUrlScan = scan.scan_type === 'url_scan'
  const urlPayload = scan.scan_payload

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <Link to={`/systems/${scan.system}`}>
          <Button variant="ghost" size="icon">
            <ArrowLeft className="h-5 w-5" />
          </Button>
        </Link>
        <div className="flex-1">
          <h1 className="text-2xl font-bold flex items-center gap-2">
            {isUrlScan ? <Globe className="h-6 w-6" /> : <Shield className="h-6 w-6" />}
            {isUrlScan ? 'Website Security Scan' : 'Scan Results'}
          </h1>
          <p className="text-muted-foreground">
            {formatDateTime(scan.scan_date)}
          </p>
        </div>
        <Badge className={getStatusColor(scan.status)}>
          {scan.status}
        </Badge>
      </div>

      {/* URL Scan Info */}
      {isUrlScan && urlPayload && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Globe className="h-5 w-5" />
              Scanned URL
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="flex items-center gap-2">
                <span className="font-mono text-sm bg-muted px-2 py-1 rounded">
                  {urlPayload.url ?? 'N/A'}
                </span>
                {urlPayload.url ? (
                <a
                  href={urlPayload.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  aria-label="Open scanned URL in a new tab"
                  title="Open scanned URL"
                  className="text-blue-500 hover:text-blue-600"
                >
                  <ExternalLink className="h-4 w-4" />
                </a>
                ) : null}
              </div>
              {urlPayload.final_url && urlPayload.final_url !== urlPayload.url && (
                <div className="flex items-center gap-2 text-sm text-muted-foreground">
                  <RefreshCw className="h-4 w-4" />
                  Redirected to: <span className="font-mono">{urlPayload.final_url}</span>
                </div>
              )}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 pt-2">
                <div>
                  <span className="text-sm text-muted-foreground">Status Code</span>
                  <div className={cn(
                    "text-lg font-semibold",
                    urlPayload.status_code >= 200 && urlPayload.status_code < 300 ? 'text-green-600' :
                    urlPayload.status_code >= 400 ? 'text-red-600' : 'text-yellow-600'
                  )}>
                    {urlPayload.status_code}
                  </div>
                </div>
                <div>
                  <span className="text-sm text-muted-foreground">Response Time</span>
                  <div className="text-lg font-semibold">
                    {Math.round(urlPayload.response_time_ms ?? 0)}ms
                  </div>
                </div>
                {(urlPayload.redirects ?? []).length > 0 && (
                  <div>
                    <span className="text-sm text-muted-foreground">Redirects</span>
                    <div className="text-lg font-semibold">
                      {(urlPayload.redirects ?? []).length}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Scan Overview */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-2 text-sm font-medium text-muted-foreground">
              <Shield className="h-4 w-4" />
              Risk Score
            </div>
            <div className={cn('text-3xl font-bold mt-2', getRiskScoreColor(scan.risk_score || 0))}>
              {scan.risk_score ?? 'N/A'}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="text-sm font-medium text-muted-foreground">Maturity Level</div>
            <div className="mt-2">
              {scan.maturity_level ? (
                <Badge className={cn('text-base', getMaturityLevelColor(scan.maturity_level))}>
                  {scan.maturity_level}
                </Badge>
              ) : (
                <span className="text-muted-foreground">N/A</span>
              )}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="text-sm font-medium text-muted-foreground">Total Findings</div>
            <div className="text-3xl font-bold mt-2">
              {findings.length || scan.findings_count || 0}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-2 text-sm font-medium text-muted-foreground">
              <Clock className="h-4 w-4" />
              Duration
            </div>
            <div className="text-sm mt-2">
              {scan.started_at && scan.completed_at
                ? `${Math.round((new Date(scan.completed_at).getTime() - new Date(scan.started_at).getTime()) / 1000)}s`
                : 'N/A'}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* SSL Information (for URL scans) */}
      {isUrlScan && urlPayload?.ssl_info && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              {urlPayload.ssl_info.is_valid ? (
                <Lock className="h-5 w-5 text-green-600" />
              ) : (
                <Lock className="h-5 w-5 text-red-600" />
              )}
              SSL/TLS Certificate
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
              <div>
                <span className="text-sm text-muted-foreground">Status</span>
                <div className="mt-1">
                  <Badge className={urlPayload.ssl_info.is_valid ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}>
                    {urlPayload.ssl_info.is_valid ? 'Valid' : 'Invalid'}
                  </Badge>
                </div>
              </div>
              {urlPayload.ssl_info.days_until_expiry !== undefined && (
                <div>
                  <span className="text-sm text-muted-foreground">Expires In</span>
                  <div className={cn(
                    "text-lg font-semibold mt-1",
                    urlPayload.ssl_info.days_until_expiry <= 30 ? 'text-red-600' :
                    urlPayload.ssl_info.days_until_expiry <= 90 ? 'text-yellow-600' : 'text-green-600'
                  )}>
                    {urlPayload.ssl_info.days_until_expiry} days
                  </div>
                </div>
              )}
              {urlPayload.ssl_info.protocol_version && (
                <div>
                  <span className="text-sm text-muted-foreground">Protocol</span>
                  <div className="text-lg font-semibold mt-1">
                    {urlPayload.ssl_info.protocol_version}
                  </div>
                </div>
              )}
              {urlPayload.ssl_info.issuer && (
                <div>
                  <span className="text-sm text-muted-foreground">Issuer</span>
                  <div className="text-sm mt-1 truncate" title={urlPayload.ssl_info.issuer}>
                    {String(urlPayload.ssl_info.issuer ?? '').split(',')[0]}
                  </div>
                </div>
              )}
            </div>
            {urlPayload.ssl_info.is_self_signed && (
              <div className="mt-4 p-3 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 rounded-lg">
                <div className="flex items-center gap-2 text-yellow-700 dark:text-yellow-400">
                  <AlertTriangle className="h-4 w-4" />
                  <span className="font-medium">Self-signed certificate detected</span>
                </div>
              </div>
            )}
            {urlPayload.ssl_info.errors && urlPayload.ssl_info.errors.length > 0 && (
              <div className="mt-4 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 rounded-lg">
                <div className="text-red-700 dark:text-red-400 text-sm">
                  {urlPayload.ssl_info.errors.map((err, i) => (
                    <div key={i}>{err}</div>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Security Headers (for URL scans) */}
      {isUrlScan && urlPayload?.security_headers && (
        <Card>
          <CardHeader>
            <CardTitle>Security Headers</CardTitle>
            <CardDescription>HTTP security headers analysis</CardDescription>
          </CardHeader>
          <CardContent>
            {(urlPayload.security_headers?.missing_headers ?? []).length > 0 && (
              <div className="mb-4">
                <h4 className="text-sm font-medium text-red-600 mb-2">Missing Headers</h4>
                <div className="flex flex-wrap gap-2">
                  {(urlPayload.security_headers?.missing_headers ?? []).map((header) => (
                    <Badge key={header} variant="outline" className="text-red-600 border-red-300">
                      {header}
                    </Badge>
                  ))}
                </div>
              </div>
            )}
            <div className="grid gap-2">
              {urlPayload.security_headers.strict_transport_security && (
                <div className="flex justify-between items-center p-2 bg-muted/50 rounded">
                  <span className="font-medium">Strict-Transport-Security</span>
                  <CheckCircle className="h-4 w-4 text-green-600" />
                </div>
              )}
              {urlPayload.security_headers.content_security_policy && (
                <div className="flex justify-between items-center p-2 bg-muted/50 rounded">
                  <span className="font-medium">Content-Security-Policy</span>
                  <CheckCircle className="h-4 w-4 text-green-600" />
                </div>
              )}
              {urlPayload.security_headers.x_frame_options && (
                <div className="flex justify-between items-center p-2 bg-muted/50 rounded">
                  <span className="font-medium">X-Frame-Options</span>
                  <span className="text-sm text-muted-foreground">{urlPayload.security_headers.x_frame_options}</span>
                </div>
              )}
              {urlPayload.security_headers.x_content_type_options && (
                <div className="flex justify-between items-center p-2 bg-muted/50 rounded">
                  <span className="font-medium">X-Content-Type-Options</span>
                  <span className="text-sm text-muted-foreground">{urlPayload.security_headers.x_content_type_options}</span>
                </div>
              )}
              {urlPayload.security_headers.referrer_policy && (
                <div className="flex justify-between items-center p-2 bg-muted/50 rounded">
                  <span className="font-medium">Referrer-Policy</span>
                  <span className="text-sm text-muted-foreground">{urlPayload.security_headers.referrer_policy}</span>
                </div>
              )}
            </div>
            {urlPayload.security_headers.server && (
              <div className="mt-4 p-3 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 rounded-lg">
                <div className="text-yellow-700 dark:text-yellow-400 text-sm">
                  <span className="font-medium">Server header exposed: </span>
                  {urlPayload.security_headers.server}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Content Analysis (for URL scans with deep analysis) */}
      {isUrlScan && urlPayload?.content_analysis && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5" />
              Deep Content Analysis
            </CardTitle>
            <CardDescription>
              Comprehensive security analysis of website content, scripts, forms, and resources
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-6">
              {/* Page Overview */}
              {urlPayload.content_analysis.page_title && (
                <div className="p-4 bg-muted/30 rounded-lg">
                  <h4 className="text-sm font-medium text-muted-foreground mb-2">Page Title</h4>
                  <p className="font-medium">{urlPayload.content_analysis.page_title}</p>
                </div>
              )}

              {/* Content Stats Grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="p-4 bg-muted/30 rounded-lg text-center">
                  <div className="text-2xl font-bold text-blue-600">
                    {urlPayload.content_analysis.scripts?.length || 0}
                  </div>
                  <div className="text-sm text-muted-foreground">Scripts</div>
                </div>
                <div className="p-4 bg-muted/30 rounded-lg text-center">
                  <div className="text-2xl font-bold text-purple-600">
                    {urlPayload.content_analysis.forms?.length || 0}
                  </div>
                  <div className="text-sm text-muted-foreground">Forms</div>
                </div>
                <div className="p-4 bg-muted/30 rounded-lg text-center">
                  <div className="text-2xl font-bold text-orange-600">
                    {urlPayload.content_analysis.third_party_resources?.length || 0}
                  </div>
                  <div className="text-sm text-muted-foreground">3rd Party Resources</div>
                </div>
                <div className="p-4 bg-muted/30 rounded-lg text-center">
                  <div className="text-2xl font-bold text-green-600">
                    {urlPayload.content_analysis.iframes?.length || 0}
                  </div>
                  <div className="text-sm text-muted-foreground">Iframes</div>
                </div>
              </div>

              {/* Security Indicators */}
              <div className="space-y-3">
                <h4 className="font-medium">Security Indicators</h4>
                <div className="grid gap-2">
                  {urlPayload.content_analysis.has_mixed_content && (
                    <div className="flex items-center gap-2 p-2 bg-red-50 dark:bg-red-900/20 rounded">
                      <AlertTriangle className="h-4 w-4 text-red-600" />
                      <span className="text-sm text-red-700 dark:text-red-400">Mixed content detected (HTTP resources on HTTPS page)</span>
                    </div>
                  )}
                  {(urlPayload.content_analysis.has_inline_event_handlers || 0) > 5 && (
                    <div className="flex items-center gap-2 p-2 bg-yellow-50 dark:bg-yellow-900/20 rounded">
                      <AlertTriangle className="h-4 w-4 text-yellow-600" />
                      <span className="text-sm text-yellow-700 dark:text-yellow-400">
                        {urlPayload.content_analysis.has_inline_event_handlers} inline event handlers found
                      </span>
                    </div>
                  )}
                  {urlPayload.content_analysis.has_document_write && (
                    <div className="flex items-center gap-2 p-2 bg-yellow-50 dark:bg-yellow-900/20 rounded">
                      <AlertTriangle className="h-4 w-4 text-yellow-600" />
                      <span className="text-sm text-yellow-700 dark:text-yellow-400">document.write() usage detected</span>
                    </div>
                  )}
                  {urlPayload.content_analysis.has_eval_usage && (
                    <div className="flex items-center gap-2 p-2 bg-red-50 dark:bg-red-900/20 rounded">
                      <AlertTriangle className="h-4 w-4 text-red-600" />
                      <span className="text-sm text-red-700 dark:text-red-400">eval() usage detected (potential XSS risk)</span>
                    </div>
                  )}
                  {!urlPayload.content_analysis.has_mixed_content &&
                   !urlPayload.content_analysis.has_document_write &&
                   !urlPayload.content_analysis.has_eval_usage &&
                   (urlPayload.content_analysis.has_inline_event_handlers || 0) <= 5 && (
                    <div className="flex items-center gap-2 p-2 bg-green-50 dark:bg-green-900/20 rounded">
                      <CheckCircle className="h-4 w-4 text-green-600" />
                      <span className="text-sm text-green-700 dark:text-green-400">No critical JavaScript security issues detected</span>
                    </div>
                  )}
                </div>
              </div>

              {/* Sensitive Data Exposure */}
              {urlPayload.content_analysis.sensitive_data && (
                <div className="space-y-3">
                  <h4 className="font-medium">Sensitive Data Exposure</h4>
                  <div className="grid gap-2">
                    {(urlPayload.content_analysis.sensitive_data.emails_count || 0) > 10 && (
                      <div className="flex items-center gap-2 p-2 bg-yellow-50 dark:bg-yellow-900/20 rounded">
                        <AlertTriangle className="h-4 w-4 text-yellow-600" />
                        <span className="text-sm text-yellow-700 dark:text-yellow-400">
                          {urlPayload.content_analysis.sensitive_data.emails_count} email addresses found in page source
                        </span>
                      </div>
                    )}
                    {(urlPayload.content_analysis.sensitive_data.api_keys?.length || 0) > 0 && (
                      <div className="flex items-center gap-2 p-2 bg-red-50 dark:bg-red-900/20 rounded">
                        <AlertTriangle className="h-4 w-4 text-red-600" />
                        <span className="text-sm text-red-700 dark:text-red-400">
                          {urlPayload.content_analysis.sensitive_data.api_keys.length} API keys/tokens exposed!
                        </span>
                      </div>
                    )}
                    {urlPayload.content_analysis.sensitive_data.private_keys_found && (
                      <div className="flex items-center gap-2 p-2 bg-red-50 dark:bg-red-900/20 rounded">
                        <AlertTriangle className="h-4 w-4 text-red-600" />
                        <span className="text-sm text-red-700 dark:text-red-400 font-medium">
                          CRITICAL: Private key material found in page source!
                        </span>
                      </div>
                    )}
                    {(urlPayload.content_analysis.sensitive_data.internal_paths?.length || 0) > 0 && (
                      <div className="flex items-center gap-2 p-2 bg-yellow-50 dark:bg-yellow-900/20 rounded">
                        <AlertTriangle className="h-4 w-4 text-yellow-600" />
                        <span className="text-sm text-yellow-700 dark:text-yellow-400">
                          Internal server paths exposed
                        </span>
                      </div>
                    )}
                    {(urlPayload.content_analysis.sensitive_data.debug_info?.length || 0) > 0 && (
                      <div className="flex items-center gap-2 p-2 bg-yellow-50 dark:bg-yellow-900/20 rounded">
                        <AlertTriangle className="h-4 w-4 text-yellow-600" />
                        <span className="text-sm text-yellow-700 dark:text-yellow-400">
                          Debug/development information found: {urlPayload.content_analysis.sensitive_data.debug_info.join(', ')}
                        </span>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Third-Party Resources */}
              {urlPayload.content_analysis.third_party_resources && urlPayload.content_analysis.third_party_resources.length > 0 && (
                <div className="space-y-3">
                  <h4 className="font-medium">Third-Party Resources ({urlPayload.content_analysis.third_party_resources.length})</h4>
                  <div className="max-h-48 overflow-y-auto space-y-2">
                    {urlPayload.content_analysis.third_party_resources.slice(0, 10).map((resource, idx) => (
                      <div key={idx} className="flex items-center justify-between p-2 bg-muted/30 rounded text-sm">
                        <div className="flex items-center gap-2">
                          <Badge variant="outline" className="text-xs">
                            {resource.resource_type}
                          </Badge>
                          <span className="truncate max-w-[300px]" title={resource.domain}>
                            {resource.domain}
                          </span>
                        </div>
                        <div className="flex items-center gap-2">
                          {resource.is_tracking && (
                            <Badge className="bg-purple-100 text-purple-700 text-xs">Tracking</Badge>
                          )}
                          {resource.has_integrity ? (
                            <span title="Has SRI">
                              <CheckCircle className="h-4 w-4 text-green-600" />
                            </span>
                          ) : resource.resource_type === 'script' ? (
                            <span title="No SRI">
                              <AlertTriangle className="h-4 w-4 text-yellow-600" />
                            </span>
                          ) : null}
                        </div>
                      </div>
                    ))}
                    {urlPayload.content_analysis.third_party_resources.length > 10 && (
                      <div className="text-sm text-muted-foreground text-center py-2">
                        ... and {urlPayload.content_analysis.third_party_resources.length - 10} more
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Detected Technologies */}
              {urlPayload.content_analysis.detected_technologies && urlPayload.content_analysis.detected_technologies.length > 0 && (
                <div className="space-y-3">
                  <h4 className="font-medium">Detected Technologies</h4>
                  <div className="flex flex-wrap gap-2">
                    {urlPayload.content_analysis.detected_technologies.map((tech, idx) => (
                      <Badge
                        key={idx}
                        variant="outline"
                        className={cn(
                          tech.confidence === 'confirmed' && 'border-green-500 text-green-700',
                          tech.confidence === 'high' && 'border-blue-500 text-blue-700',
                        )}
                      >
                        {tech.name}
                        {tech.confidence === 'confirmed' && ' ✓'}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}

              {/* Forms Analysis */}
              {urlPayload.content_analysis.forms && urlPayload.content_analysis.forms.length > 0 && (
                <div className="space-y-3">
                  <h4 className="font-medium">Forms Security ({urlPayload.content_analysis.forms.length} forms)</h4>
                  <div className="space-y-2">
                    {urlPayload.content_analysis.forms.map((form, idx) => (
                      <div key={idx} className="p-3 bg-muted/30 rounded-lg">
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center gap-2">
                            <Badge variant="outline">{form.method}</Badge>
                            <span className="text-sm truncate max-w-[300px]" title={form.action || ''}>
                              {form.action ? new URL(form.action).pathname : '/'}
                            </span>
                          </div>
                          <div className="flex items-center gap-2">
                            {form.has_csrf_token ? (
                              <Badge className="bg-green-100 text-green-700 text-xs">CSRF ✓</Badge>
                            ) : form.method === 'POST' ? (
                              <Badge className="bg-red-100 text-red-700 text-xs">No CSRF</Badge>
                            ) : null}
                            {form.password_fields > 0 && (
                              <Badge className="bg-yellow-100 text-yellow-700 text-xs">
                                {form.password_fields} Password Field{form.password_fields > 1 ? 's' : ''}
                              </Badge>
                            )}
                          </div>
                        </div>
                        {form.security_issues && form.security_issues.length > 0 && (
                          <div className="mt-2 space-y-1">
                            {form.security_issues.map((issue, i) => (
                              <div key={i} className="flex items-center gap-2 text-sm text-red-600">
                                <AlertTriangle className="h-3 w-3" />
                                {issue}
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Links Analysis */}
              {urlPayload.content_analysis.links && (
                <div className="space-y-3">
                  <h4 className="font-medium">Links Analysis</h4>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div className="p-3 bg-muted/30 rounded-lg text-center">
                      <div className="text-xl font-bold">{urlPayload.content_analysis.links.total_links}</div>
                      <div className="text-xs text-muted-foreground">Total Links</div>
                    </div>
                    <div className="p-3 bg-muted/30 rounded-lg text-center">
                      <div className="text-xl font-bold text-blue-600">{urlPayload.content_analysis.links.internal_links}</div>
                      <div className="text-xs text-muted-foreground">Internal</div>
                    </div>
                    <div className="p-3 bg-muted/30 rounded-lg text-center">
                      <div className="text-xl font-bold text-orange-600">{urlPayload.content_analysis.links.external_links}</div>
                      <div className="text-xs text-muted-foreground">External</div>
                    </div>
                    <div className="p-3 bg-muted/30 rounded-lg text-center">
                      <div className={cn("text-xl font-bold", (urlPayload.content_analysis.links.http_links?.length || 0) > 0 ? 'text-red-600' : 'text-green-600')}>
                        {urlPayload.content_analysis.links.http_links?.length || 0}
                      </div>
                      <div className="text-xs text-muted-foreground">Insecure (HTTP)</div>
                    </div>
                  </div>
                  {(urlPayload.content_analysis.links.suspicious_links?.length || 0) > 0 && (
                    <div className="p-3 bg-red-50 dark:bg-red-900/20 rounded-lg">
                      <div className="font-medium text-red-700 dark:text-red-400 mb-2">Suspicious Links Detected</div>
                      {urlPayload.content_analysis.links.suspicious_links?.slice(0, 5).map((link, idx) => (
                        <div key={idx} className="text-sm text-red-600 truncate">
                          {link.reason}: {link.url}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Score Breakdown */}
      {scan.score_breakdown && Object.keys(scan.score_breakdown).length > 0 && (() => {
        const scoreBreakdown = scan.score_breakdown
        return (
        <Card>
          <CardHeader>
            <CardTitle>Severity Breakdown</CardTitle>
            <CardDescription>Distribution of findings by severity level</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-4 gap-4">
              {(['critical', 'high', 'medium', 'low'] as const).map((severity) => (
                <div key={severity} className="text-center p-4 rounded-lg bg-muted/50">
                  <div className={cn(
                    'text-2xl font-bold',
                    severity === 'critical' && 'text-red-600',
                    severity === 'high' && 'text-orange-600',
                    severity === 'medium' && 'text-yellow-600',
                    severity === 'low' && 'text-green-600',
                  )}>
                    {scoreBreakdown?.[severity] ?? 0}
                  </div>
                  <div className="text-sm text-muted-foreground capitalize">{severity}</div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
        )
      })()}

      {/* Findings List */}
      <Card>
        <CardHeader>
          <CardTitle>Findings</CardTitle>
          <CardDescription>Security issues detected during this scan</CardDescription>
        </CardHeader>
        <CardContent>
          {findings.length > 0 ? (
            <div className="space-y-4">
              {findings.map((finding: Finding) => (
                <div key={finding.id} className="rounded-lg border">
                  <div
                    role="button"
                    tabIndex={0}
                    onClick={() =>
                      setExpandedFindingId((prev) => (prev === finding.id ? null : finding.id))
                    }
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault()
                        setExpandedFindingId((prev) => (prev === finding.id ? null : finding.id))
                      }
                    }}
                    className="flex items-center justify-between p-4 hover:border-primary transition-colors cursor-pointer"
                  >
                    <div className="flex items-center gap-4">
                      <div
                        className={cn(
                          'flex h-10 w-10 items-center justify-center rounded-lg',
                          getSeverityColor(finding.severity)
                        )}
                      >
                        {finding.is_resolved ? (
                          <CheckCircle className="h-5 w-5" />
                        ) : (
                          <AlertTriangle className="h-5 w-5" />
                        )}
                      </div>
                      <div>
                        <div className="font-medium">{finding.title}</div>
                        <div className="text-sm text-muted-foreground capitalize">
                          {safeLabel(finding.category)}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      <Badge className={getSeverityColor(finding.severity)}>{finding.severity}</Badge>
                      {finding.is_resolved && (
                        <Badge variant="outline" className="text-green-600">
                          Resolved
                        </Badge>
                      )}
                      <ChevronRight
                        className={cn(
                          'h-5 w-5 text-muted-foreground transition-transform',
                          expandedFindingId === finding.id && 'rotate-90'
                        )}
                      />
                    </div>
                  </div>

                  {expandedFindingId === finding.id && (() => {
                    const guidance = guidanceByFindingId.get(finding.id)
                    const evidence = finding.evidence
                    const hasEvidence = evidence && Object.keys(evidence).length > 0
                    return (
                      <div className="px-4 pb-4">
                        <div className="mt-2 rounded-lg bg-muted/40 p-4 space-y-3">
                          <div>
                            <div className="text-sm font-semibold">Explanation</div>
                            <div className="text-sm text-muted-foreground">
                              {guidance?.explanation}
                            </div>
                          </div>
                          <div>
                            <div className="text-sm font-semibold">Impact</div>
                            <div className="text-sm text-muted-foreground">{guidance?.impact}</div>
                            {(finding.cvss_score !== undefined || finding.cwe_id) && (
                              <div className="text-xs text-muted-foreground mt-1">
                                {finding.cwe_id ? `CWE: ${finding.cwe_id}` : ''}
                                {finding.cwe_id && finding.cvss_score !== undefined ? ' • ' : ''}
                                {finding.cvss_score !== undefined ? `CVSS: ${finding.cvss_score}` : ''}
                              </div>
                            )}
                          </div>
                          <div>
                            <div className="text-sm font-semibold">Remediation / Strategy</div>
                            <ul className="text-sm text-muted-foreground list-disc pl-5 space-y-1">
                              {(guidance?.remediation || []).map((step, idx) => (
                                <li key={idx}>{step}</li>
                              ))}
                            </ul>
                          </div>
                          <div>
                            <div className="text-sm font-semibold">Verification</div>
                            <ul className="text-sm text-muted-foreground list-disc pl-5 space-y-1">
                              {(guidance?.verification || []).map((step, idx) => (
                                <li key={idx}>{step}</li>
                              ))}
                            </ul>
                          </div>
                          {hasEvidence && (
                            <div>
                              <div className="text-sm font-semibold">Evidence</div>
                              <pre className="mt-2 text-xs bg-background/60 border rounded p-3 overflow-auto">
                                {JSON.stringify(evidence, null, 2)}
                              </pre>
                            </div>
                          )}
                        </div>
                      </div>
                    )
                  })()}
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8">
              <CheckCircle className="h-12 w-12 text-green-500 mx-auto mb-4" />
              <h3 className="text-lg font-semibold">No findings</h3>
              <p className="text-muted-foreground">
                Great! No security issues were detected in this scan.
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Error Message (if scan failed) */}
      {scan.status === 'failed' && scan.error_message && (
        <Card className="border-red-200 bg-red-50">
          <CardHeader>
            <CardTitle className="text-red-600">Scan Error</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-red-600 font-mono text-sm">{scan.error_message}</p>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
