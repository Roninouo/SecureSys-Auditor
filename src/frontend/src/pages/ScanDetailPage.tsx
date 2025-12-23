import { useParams, Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { 
  ArrowLeft, 
  AlertTriangle, 
  CheckCircle,
  Clock,
  Shield,
  ChevronRight
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
          <h1 className="text-2xl font-bold">Scan Results</h1>
          <p className="text-muted-foreground">
            {formatDateTime(scan.scan_date)}
          </p>
        </div>
        <Badge className={getStatusColor(scan.status)}>
          {scan.status}
        </Badge>
      </div>

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

      {/* Score Breakdown */}
      {scan.score_breakdown && Object.keys(scan.score_breakdown).length > 0 && (
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
                    {scan.score_breakdown[severity] || 0}
                  </div>
                  <div className="text-sm text-muted-foreground capitalize">{severity}</div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

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
                        {finding.category.replace('_', ' ')}
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
