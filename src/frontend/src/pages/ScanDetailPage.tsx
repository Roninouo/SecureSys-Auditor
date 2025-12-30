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
import { 
  cn, 
  formatDateTime, 
  getRiskScoreColor, 
  getMaturityLevelColor,
  getStatusColor,
  getSeverityColor
} from '@/lib/utils'
import type { Scan, Finding } from '@/types'

export default function ScanDetailPage() {
  const { scanId } = useParams<{ scanId: string }>()

  const { data: scan, isLoading } = useQuery<Scan>({
    queryKey: ['scan', scanId],
    queryFn: () => scansApi.getById(scanId!),
    enabled: !!scanId,
  })

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
                  {urlPayload.url}
                </span>
                <a 
                  href={urlPayload.url} 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="text-blue-500 hover:text-blue-600"
                >
                  <ExternalLink className="h-4 w-4" />
                </a>
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
                    {Math.round(urlPayload.response_time_ms)}ms
                  </div>
                </div>
                {urlPayload.redirects && urlPayload.redirects.length > 0 && (
                  <div>
                    <span className="text-sm text-muted-foreground">Redirects</span>
                    <div className="text-lg font-semibold">
                      {urlPayload.redirects.length}
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
              {scan.findings?.length || scan.findings_count || 0}
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
                    {urlPayload.ssl_info.issuer.split(',')[0]}
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
            {urlPayload.security_headers.missing_headers && urlPayload.security_headers.missing_headers.length > 0 && (
              <div className="mb-4">
                <h4 className="text-sm font-medium text-red-600 mb-2">Missing Headers</h4>
                <div className="flex flex-wrap gap-2">
                  {urlPayload.security_headers.missing_headers.map((header) => (
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
          {scan.findings && scan.findings.length > 0 ? (
            <div className="space-y-4">
              {scan.findings.map((finding: Finding) => (
                <div 
                  key={finding.id}
                  className="flex items-center justify-between p-4 rounded-lg border hover:border-primary transition-colors"
                >
                  <div className="flex items-center gap-4">
                    <div className={cn(
                      'flex h-10 w-10 items-center justify-center rounded-lg',
                      getSeverityColor(finding.severity)
                    )}>
                      {finding.is_resolved ? (
                        <CheckCircle className="h-5 w-5" />
                      ) : (
                        <AlertTriangle className="h-5 w-5" />
                      )}
                    </div>
                    <div>
                      <div className="font-medium">{finding.title}</div>
                      <div className="text-sm text-muted-foreground capitalize">
                        {finding.category.replace(/_/g, ' ')}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-4">
                    <Badge className={getSeverityColor(finding.severity)}>
                      {finding.severity}
                    </Badge>
                    {finding.is_resolved && (
                      <Badge variant="outline" className="text-green-600">
                        Resolved
                      </Badge>
                    )}
                    <ChevronRight className="h-5 w-5 text-muted-foreground" />
                  </div>
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
