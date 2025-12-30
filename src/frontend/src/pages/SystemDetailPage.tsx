import { useParams, Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { 
  ArrowLeft, 
  Server, 
  AlertTriangle, 
  Calendar,
  Activity,
  Play
} from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { systemsApi } from '@/services/api'
import { 
  cn, 
  formatDateTime, 
  getRiskScoreColor, 
  getMaturityLevelColor,
  getStatusColor
} from '@/lib/utils'
import type { System, Scan } from '@/types'

export default function SystemDetailPage() {
  const { systemId } = useParams<{ systemId: string }>()

  const { data: system, isLoading: systemLoading } = useQuery<System>({
    queryKey: ['system', systemId],
    queryFn: () => systemsApi.getById(systemId!),
    enabled: !!systemId,
  })

  const { data: scans, isLoading: scansLoading } = useQuery<Scan[]>({
    queryKey: ['system-scans', systemId],
    queryFn: () => systemsApi.getScans(systemId!),
    enabled: !!systemId,
  })

  if (systemLoading || scansLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    )
  }

  if (!system) {
    return (
      <div className="text-center p-8">
        <AlertTriangle className="h-12 w-12 text-yellow-500 mx-auto mb-4" />
        <h2 className="text-lg font-semibold">System not found</h2>
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
        <Link to="/systems">
          <Button variant="ghost" size="icon">
            <ArrowLeft className="h-5 w-5" />
          </Button>
        </Link>
        <div className="flex-1">
          <div className="flex items-center gap-3">
            <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-primary/10">
              <Server className="h-6 w-6 text-primary" />
            </div>
            <div>
              <h1 className="text-2xl font-bold">{system.hostname}</h1>
              <p className="text-muted-foreground">{system.os} {system.os_version}</p>
            </div>
          </div>
        </div>
        <Button>
          <Play className="mr-2 h-4 w-4" />
          Run New Scan
        </Button>
      </div>

      {/* System Overview */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardContent className="pt-6">
            <div className="text-sm font-medium text-muted-foreground">Environment</div>
            <div className="mt-1">
              <Badge variant="outline" className="capitalize">
                {system.environment}
              </Badge>
            </div>
          </CardContent>
        </Card>
        
        <Card>
          <CardContent className="pt-6">
            <div className="text-sm font-medium text-muted-foreground">Risk Score</div>
            <div className={cn('text-2xl font-bold mt-1', getRiskScoreColor(system.latest_risk_score || 0))}>
              {system.latest_risk_score ?? 'N/A'}
            </div>
          </CardContent>
        </Card>
        
        <Card>
          <CardContent className="pt-6">
            <div className="text-sm font-medium text-muted-foreground">Maturity Level</div>
            <div className="mt-1">
              {system.latest_maturity_level ? (
                <Badge className={getMaturityLevelColor(system.latest_maturity_level)}>
                  {system.latest_maturity_level}
                </Badge>
              ) : (
                <span className="text-muted-foreground">N/A</span>
              )}
            </div>
          </CardContent>
        </Card>
        
        <Card>
          <CardContent className="pt-6">
            <div className="text-sm font-medium text-muted-foreground">Last Seen</div>
            <div className="text-sm mt-1">
              {system.last_seen ? formatDateTime(system.last_seen) : 'Never'}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Scans History */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Activity className="h-5 w-5" />
            Scan History
          </CardTitle>
        </CardHeader>
        <CardContent>
          {scans && scans.length > 0 ? (
            <div className="space-y-4">
              {scans.map((scan) => (
                <Link 
                  key={scan.id} 
                  to={`/scans/${scan.id}`}
                  className="block"
                >
                  <div className="flex items-center justify-between p-4 rounded-lg border hover:border-primary transition-colors">
                    <div className="flex items-center gap-4">
                      <Calendar className="h-5 w-5 text-muted-foreground" />
                      <div>
                        <div className="font-medium">
                          {formatDateTime(scan.scan_date)}
                        </div>
                        <div className="text-sm text-muted-foreground">
                          {scan.findings_count || 0} findings
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      <Badge className={getStatusColor(scan.status)}>
                        {scan.status}
                      </Badge>
                      {scan.risk_score !== null && scan.risk_score !== undefined && (
                        <span className={cn('font-bold', getRiskScoreColor(scan.risk_score))}>
                          {scan.risk_score}
                        </span>
                      )}
                      {scan.maturity_level && (
                        <Badge className={getMaturityLevelColor(scan.maturity_level)}>
                          {scan.maturity_level}
                        </Badge>
                      )}
                    </div>
                  </div>
                </Link>
              ))}
            </div>
          ) : (
            <div className="text-center py-8">
              <Activity className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
              <h3 className="text-lg font-semibold">No scans yet</h3>
              <p className="text-muted-foreground">Run your first scan to see results</p>
              <Button className="mt-4">
                <Play className="mr-2 h-4 w-4" />
                Run Scan
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      {/* System Details */}
      <Card>
        <CardHeader>
          <CardTitle>System Details</CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="grid grid-cols-2 gap-4">
            <div>
              <dt className="text-sm font-medium text-muted-foreground">System ID</dt>
              <dd className="mt-1 text-sm font-mono">{system.id}</dd>
            </div>
            <div>
              <dt className="text-sm font-medium text-muted-foreground">IP Address</dt>
              <dd className="mt-1 text-sm">{system.ip_address || 'Not recorded'}</dd>
            </div>
            <div>
              <dt className="text-sm font-medium text-muted-foreground">Created</dt>
              <dd className="mt-1 text-sm">{formatDateTime(system.created_at)}</dd>
            </div>
            <div>
              <dt className="text-sm font-medium text-muted-foreground">Last Updated</dt>
              <dd className="mt-1 text-sm">{formatDateTime(system.updated_at)}</dd>
            </div>
            {system.description && (
              <div className="col-span-2">
                <dt className="text-sm font-medium text-muted-foreground">Description</dt>
                <dd className="mt-1 text-sm">{system.description}</dd>
              </div>
            )}
          </dl>
        </CardContent>
      </Card>
    </div>
  )
}
