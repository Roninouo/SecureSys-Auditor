import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  Search,
  Scan,
  AlertTriangle,
  CheckCircle,
  Clock,
  XCircle,
  ChevronRight,
  RefreshCw,
  Download
} from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Card, CardContent } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { scansApi } from '@/services/api'
import { cn, formatDateTime, getRiskScoreColor, getMaturityLevelColor } from '@/lib/utils'
import { useToast } from '@/components/ui/Toast'
import type { Scan as ScanType } from '@/types'

const statusConfig = {
  pending: {
    label: 'Pending',
    icon: Clock,
    color: 'bg-yellow-500/10 text-yellow-500',
  },
  processing: {
    label: 'Processing',
    icon: Clock,
    color: 'bg-blue-500/10 text-blue-500',
  },
  completed: {
    label: 'Completed',
    icon: CheckCircle,
    color: 'bg-green-500/10 text-green-500',
  },
  failed: {
    label: 'Failed',
    icon: XCircle,
    color: 'bg-red-500/10 text-red-500',
  },
}

function ScanStatusBadge({ status }: { status: ScanType['status'] }) {
  const config = statusConfig[status]
  const Icon = config.icon

  return (
    <Badge className={cn('gap-1', config.color)}>
      <Icon className="h-3 w-3" />
      {config.label}
    </Badge>
  )
}

export default function ScanListPage() {
  const [searchTerm, setSearchTerm] = useState('')
  const [statusFilter, setStatusFilter] = useState<string | null>(null)
  const { addToast } = useToast()

  const { data: scans, isLoading, error, refetch, isFetching } = useQuery<ScanType[]>({
    queryKey: ['scans'],
    queryFn: scansApi.getAll,
    refetchInterval: 10000, // Poll every 10 seconds for status updates
  })

  const filteredScans = scans?.filter(scan => {
    const matchesSearch =
      scan.system_hostname?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      scan.id.toLowerCase().includes(searchTerm.toLowerCase())

    const matchesStatus = !statusFilter || scan.status === statusFilter

    return matchesSearch && matchesStatus
  })

  const handleRefresh = async () => {
    await refetch()
    addToast({
      type: 'success',
      title: 'Actualizado',
      message: 'Lista de escaneos actualizada'
    })
  }

  const handleExportCSV = () => {
    if (!scans || scans.length === 0) {
      addToast({
        type: 'warning',
        title: 'Sin datos',
        message: 'No hay escaneos para exportar'
      })
      return
    }

    const headers = ['ID', 'Sistema', 'Estado', 'Risk Score', 'Maturity Level', 'Findings', 'Fecha']
    const rows = scans.map(scan => [
      scan.id,
      scan.system_hostname || 'N/A',
      scan.status,
      scan.risk_score?.toString() || 'N/A',
      scan.maturity_level || 'N/A',
      scan.findings_count?.toString() || '0',
      formatDateTime(scan.scan_date)
    ])

    const csvContent = [headers, ...rows].map(row => row.join(',')).join('\n')
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `scans-export-${new Date().toISOString().split('T')[0]}.csv`
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    URL.revokeObjectURL(url)

    addToast({
      type: 'success',
      title: 'Exportado',
      message: 'Escaneos exportados a CSV'
    })
  }

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
        <h2 className="text-lg font-semibold">Failed to load scans</h2>
        <p className="text-muted-foreground">Please try again later</p>
        <Button className="mt-4" onClick={() => refetch()}>
          Retry
        </Button>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Scans</h1>
          <p className="text-muted-foreground">
            View and manage security scan results
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={handleExportCSV}>
            <Download className="mr-2 h-4 w-4" />
            Export CSV
          </Button>
          <Button variant="outline" onClick={handleRefresh} disabled={isFetching}>
            <RefreshCw className={cn("mr-2 h-4 w-4", isFetching && "animate-spin")} />
            Refresh
          </Button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search scans by hostname or ID..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="pl-10"
          />
        </div>
        <div className="flex gap-2">
          <Button
            variant={statusFilter === null ? 'default' : 'outline'}
            onClick={() => setStatusFilter(null)}
            size="sm"
          >
            All
          </Button>
          {Object.entries(statusConfig).map(([key, config]) => (
            <Button
              key={key}
              variant={statusFilter === key ? 'default' : 'outline'}
              onClick={() => setStatusFilter(key)}
              size="sm"
            >
              {config.label}
            </Button>
          ))}
        </div>
      </div>

      {/* Stats */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardContent className="pt-6">
            <div className="text-2xl font-bold">{scans?.length || 0}</div>
            <p className="text-xs text-muted-foreground">Total Scans</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="text-2xl font-bold text-green-500">
              {scans?.filter(s => s.status === 'completed').length || 0}
            </div>
            <p className="text-xs text-muted-foreground">Completed</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="text-2xl font-bold text-blue-500">
              {scans?.filter(s => s.status === 'processing').length || 0}
            </div>
            <p className="text-xs text-muted-foreground">Processing</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="text-2xl font-bold text-red-500">
              {scans?.filter(s => s.status === 'failed').length || 0}
            </div>
            <p className="text-xs text-muted-foreground">Failed</p>
          </CardContent>
        </Card>
      </div>

      {/* Scans List */}
      {filteredScans && filteredScans.length > 0 ? (
        <div className="space-y-4">
          {filteredScans.map((scan) => (
            <Link key={scan.id} to={`/scans/${scan.id}`}>
              <Card className="hover:border-primary transition-colors cursor-pointer">
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4">
                      <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-primary/10">
                        <Scan className="h-6 w-6 text-primary" />
                      </div>
                      <div>
                        <h3 className="font-semibold">{scan.system_hostname}</h3>
                        <div className="flex items-center gap-2 text-sm text-muted-foreground">
                          <span>{formatDateTime(scan.scan_date)}</span>
                          <span>•</span>
                          <span className="font-mono text-xs">{scan.id.slice(0, 8)}...</span>
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-4">
                      <ScanStatusBadge status={scan.status} />

                      {scan.status === 'completed' && (
                        <div className="text-right">
                          <div className={cn('text-lg font-bold', getRiskScoreColor(scan.risk_score || 0))}>
                            {scan.risk_score}
                          </div>
                          <div className="text-xs text-muted-foreground">Risk Score</div>
                        </div>
                      )}

                      {scan.maturity_level && (
                        <Badge className={getMaturityLevelColor(scan.maturity_level)}>
                          {scan.maturity_level}
                        </Badge>
                      )}

                      <div className="text-right">
                        <div className="font-semibold">{scan.findings_count || 0}</div>
                        <div className="text-xs text-muted-foreground">Findings</div>
                      </div>

                      <ChevronRight className="h-5 w-5 text-muted-foreground" />
                    </div>
                  </div>
                </CardContent>
              </Card>
            </Link>
          ))}
        </div>
      ) : (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <Scan className="h-12 w-12 text-muted-foreground mb-4" />
            <h3 className="text-lg font-semibold">No scans found</h3>
            <p className="text-muted-foreground text-center mt-1">
              {searchTerm || statusFilter
                ? 'Try adjusting your filters'
                : 'Run a scan using the SecureSys Agent'}
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
