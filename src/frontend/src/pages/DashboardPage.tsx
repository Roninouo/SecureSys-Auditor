import { useQuery } from '@tanstack/react-query'
import { 
  Shield, 
  Server, 
  AlertTriangle, 
  CheckCircle,
  TrendingUp,
  Activity
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { dashboardApi } from '@/services/api'
import { cn, getRiskScoreColor } from '@/lib/utils'
import type { DashboardStats } from '@/types'

function StatCard({ 
  title, 
  value, 
  icon: Icon, 
  description,
  trend 
}: { 
  title: string
  value: string | number
  icon: React.ElementType
  description?: string
  trend?: 'up' | 'down' | 'neutral'
}) {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium">{title}</CardTitle>
        <Icon className="h-4 w-4 text-muted-foreground" />
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-bold">{value}</div>
        {description && (
          <p className="text-xs text-muted-foreground">{description}</p>
        )}
      </CardContent>
    </Card>
  )
}

function SeverityCard({ severity, count }: { severity: string; count: number }) {
  const colors = {
    critical: 'bg-red-500',
    high: 'bg-orange-500',
    medium: 'bg-yellow-500',
    low: 'bg-green-500',
  }
  
  return (
    <div className="flex items-center justify-between p-4 rounded-lg bg-muted/50">
      <div className="flex items-center gap-3">
        <div className={cn('h-3 w-3 rounded-full', colors[severity as keyof typeof colors])} />
        <span className="capitalize font-medium">{severity}</span>
      </div>
      <span className="text-2xl font-bold">{count}</span>
    </div>
  )
}

export default function DashboardPage() {
  const { data: stats, isLoading, error } = useQuery<DashboardStats>({
    queryKey: ['dashboard-stats'],
    queryFn: dashboardApi.getStats,
  })

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="text-center p-8">
        <AlertTriangle className="h-12 w-12 text-yellow-500 mx-auto mb-4" />
        <h2 className="text-lg font-semibold">Failed to load dashboard</h2>
        <p className="text-muted-foreground">Please try again later</p>
      </div>
    )
  }

  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Security Dashboard</h1>
        <p className="text-muted-foreground">
          Overview of your organization's security posture
        </p>
      </div>

      {/* Stats Grid */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <StatCard
          title="Total Systems"
          value={stats?.total_systems || 0}
          icon={Server}
          description="Active monitored systems"
        />
        <StatCard
          title="Completed Scans"
          value={stats?.completed_scans || 0}
          icon={CheckCircle}
          description={`of ${stats?.total_scans || 0} total scans`}
        />
        <StatCard
          title="Average Risk Score"
          value={stats?.average_risk_score || 0}
          icon={Activity}
        />
        <StatCard
          title="Unresolved Findings"
          value={stats?.total_unresolved_findings || 0}
          icon={AlertTriangle}
          description="Require attention"
        />
      </div>

      {/* Risk Score and Findings */}
      <div className="grid gap-4 md:grid-cols-2">
        {/* Risk Score Card */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <TrendingUp className="h-5 w-5" />
              Overall Risk Score
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-center py-8">
              <div className="relative">
                <svg className="h-32 w-32 transform -rotate-90">
                  <circle
                    cx="64"
                    cy="64"
                    r="56"
                    stroke="currentColor"
                    strokeWidth="8"
                    fill="none"
                    className="text-muted"
                  />
                  <circle
                    cx="64"
                    cy="64"
                    r="56"
                    stroke="currentColor"
                    strokeWidth="8"
                    fill="none"
                    strokeDasharray={`${(stats?.average_risk_score || 0) * 3.52} 352`}
                    className={getRiskScoreColor(stats?.average_risk_score || 0)}
                  />
                </svg>
                <div className="absolute inset-0 flex items-center justify-center">
                  <span className={cn('text-3xl font-bold', getRiskScoreColor(stats?.average_risk_score || 0))}>
                    {stats?.average_risk_score || 0}
                  </span>
                </div>
              </div>
            </div>
            <div className="text-center text-sm text-muted-foreground">
              {(stats?.average_risk_score || 0) < 40 && 'Low Risk - Good security posture'}
              {(stats?.average_risk_score || 0) >= 40 && (stats?.average_risk_score || 0) < 60 && 'Medium Risk - Some improvements needed'}
              {(stats?.average_risk_score || 0) >= 60 && (stats?.average_risk_score || 0) < 80 && 'High Risk - Attention required'}
              {(stats?.average_risk_score || 0) >= 80 && 'Critical Risk - Immediate action needed'}
            </div>
          </CardContent>
        </Card>

        {/* Findings by Severity */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5" />
              Findings by Severity
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <SeverityCard severity="critical" count={stats?.severity_counts?.critical || 0} />
            <SeverityCard severity="high" count={stats?.severity_counts?.high || 0} />
            <SeverityCard severity="medium" count={stats?.severity_counts?.medium || 0} />
            <SeverityCard severity="low" count={stats?.severity_counts?.low || 0} />
          </CardContent>
        </Card>
      </div>

      {/* Quick Actions */}
      <Card>
        <CardHeader>
          <CardTitle>Quick Actions</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-2">
            <Badge variant="outline" className="cursor-pointer hover:bg-accent">
              View Critical Findings
            </Badge>
            <Badge variant="outline" className="cursor-pointer hover:bg-accent">
              Generate Report
            </Badge>
            <Badge variant="outline" className="cursor-pointer hover:bg-accent">
              Add New System
            </Badge>
            <Badge variant="outline" className="cursor-pointer hover:bg-accent">
              Run New Scan
            </Badge>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
