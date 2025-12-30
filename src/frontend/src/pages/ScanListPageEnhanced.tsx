import { useState, useMemo } from 'react'
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
} from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Card, CardContent } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Pagination } from '@/components/ui/Pagination'
import { FilterBar, type FilterConfig } from '@/components/ui/FilterBar'
import { ExportButton } from '@/components/ui/Export'
import { scansApi } from '@/services/api'
import { cn, formatDateTime, getRiskScoreColor, getMaturityLevelColor } from '@/lib/utils'
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

const filterConfig: FilterConfig[] = [
  {
    key: 'status',
    label: 'Status',
    type: 'select',
    options: [
      { label: 'Pending', value: 'pending' },
      { label: 'Processing', value: 'processing' },
      { label: 'Completed', value: 'completed' },
      { label: 'Failed', value: 'failed' },
    ],
  },
  {
    key: 'maturity_level',
    label: 'Maturity Level',
    type: 'select',
    options: [
      { label: 'Reactive', value: 'reactive' },
      { label: 'Basic', value: 'basic' },
      { label: 'Managed', value: 'managed' },
      { label: 'Optimized', value: 'optimized' },
    ],
  },
  {
    key: 'risk_score_range',
    label: 'Risk Score',
    type: 'select',
    options: [
      { label: 'Low (0-25)', value: '0-25' },
      { label: 'Medium (26-50)', value: '26-50' },
      { label: 'High (51-75)', value: '51-75' },
      { label: 'Critical (76-100)', value: '76-100' },
    ],
  },
]

// CSV export headers
const exportHeaders: { key: keyof ScanType | ((item: ScanType) => string); label: string }[] = [
  { key: 'id', label: 'Scan ID' },
  { key: 'system_hostname', label: 'Hostname' },
  { key: 'status', label: 'Status' },
  { key: 'scan_date', label: 'Scan Date' },
  { key: 'risk_score', label: 'Risk Score' },
  { key: 'maturity_level', label: 'Maturity Level' },
  { key: 'findings_count', label: 'Findings Count' },
  { key: (item) => item.score_breakdown?.critical?.toString() || '0', label: 'Critical Findings' },
  { key: (item) => item.score_breakdown?.high?.toString() || '0', label: 'High Findings' },
  { key: (item) => item.score_breakdown?.medium?.toString() || '0', label: 'Medium Findings' },
  { key: (item) => item.score_breakdown?.low?.toString() || '0', label: 'Low Findings' },
  { key: 'started_at', label: 'Started At' },
  { key: 'completed_at', label: 'Completed At' },
]

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
  const [activeFilters, setActiveFilters] = useState<Record<string, string | string[]>>({})
  const [currentPage, setCurrentPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  
  const { data: scans, isLoading, error, refetch } = useQuery<ScanType[]>({
    queryKey: ['scans'],
    queryFn: scansApi.getAll,
    refetchInterval: 10000, // Poll every 10 seconds for status updates
  })

  // Filter and search logic
  const filteredScans = useMemo(() => {
    if (!scans) return []
    
    return scans.filter(scan => {
      // Search filter
      const matchesSearch = !searchTerm || 
        scan.system_hostname?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        scan.id.toLowerCase().includes(searchTerm.toLowerCase())
      
      // Status filter
      const matchesStatus = !activeFilters.status || scan.status === activeFilters.status
      
      // Maturity level filter
      const matchesMaturity = !activeFilters.maturity_level || scan.maturity_level === activeFilters.maturity_level
      
      // Risk score range filter
      let matchesRiskScore = true
      if (activeFilters.risk_score_range && scan.risk_score !== undefined) {
        const [min, max] = (activeFilters.risk_score_range as string).split('-').map(Number)
        matchesRiskScore = scan.risk_score >= min && scan.risk_score <= max
      }
      
      return matchesSearch && matchesStatus && matchesMaturity && matchesRiskScore
    })
  }, [scans, searchTerm, activeFilters])

  // Pagination
  const totalPages = Math.ceil(filteredScans.length / pageSize)
  const paginatedScans = useMemo(() => {
    const start = (currentPage - 1) * pageSize
    return filteredScans.slice(start, start + pageSize)
  }, [filteredScans, currentPage, pageSize])

  // Reset to first page when filters change
  const handleFilterChange = (key: string, value: string | string[] | null) => {
    setActiveFilters(prev => {
      if (value === null) {
        const { [key]: _, ...rest } = prev
        return rest
      }
      return { ...prev, [key]: value }
    })
    setCurrentPage(1)
  }

  const handleClearFilters = () => {
    setActiveFilters({})
    setSearchTerm('')
    setCurrentPage(1)
  }

  const handlePageSizeChange = (newSize: number) => {
    setPageSize(newSize)
    setCurrentPage(1)
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
        <ExportButton
          data={filteredScans as unknown as Record<string, unknown>[]}
          filename="securesys-scans"
          headers={exportHeaders as { key: keyof Record<string, unknown> | ((item: Record<string, unknown>) => string); label: string }[]}
        />
      </div>

      {/* Search */}
      <div className="relative">
        <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          placeholder="Search scans by hostname or ID..."
          value={searchTerm}
          onChange={(e) => {
            setSearchTerm(e.target.value)
            setCurrentPage(1)
          }}
          className="pl-10"
        />
      </div>

      {/* Filters */}
      <FilterBar
        filters={filterConfig}
        activeFilters={activeFilters}
        onFilterChange={handleFilterChange}
        onClearAll={handleClearFilters}
      />

      {/* Stats */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardContent className="pt-6">
            <div className="text-2xl font-bold">{filteredScans.length}</div>
            <p className="text-xs text-muted-foreground">
              {filteredScans.length === scans?.length ? 'Total Scans' : 'Filtered Results'}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="text-2xl font-bold text-green-500">
              {filteredScans.filter(s => s.status === 'completed').length}
            </div>
            <p className="text-xs text-muted-foreground">Completed</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="text-2xl font-bold text-blue-500">
              {filteredScans.filter(s => s.status === 'processing').length}
            </div>
            <p className="text-xs text-muted-foreground">Processing</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="text-2xl font-bold text-red-500">
              {filteredScans.filter(s => s.status === 'failed').length}
            </div>
            <p className="text-xs text-muted-foreground">Failed</p>
          </CardContent>
        </Card>
      </div>

      {/* Scans List */}
      {paginatedScans.length > 0 ? (
        <div className="space-y-4">
          {paginatedScans.map((scan) => (
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
              {searchTerm || Object.keys(activeFilters).length > 0
                ? 'Try adjusting your filters'
                : 'Run a scan using the SecureSys Agent'}
            </p>
          </CardContent>
        </Card>
      )}

      {/* Pagination */}
      {filteredScans.length > 0 && (
        <Pagination
          currentPage={currentPage}
          totalPages={totalPages}
          totalItems={filteredScans.length}
          pageSize={pageSize}
          onPageChange={setCurrentPage}
          onPageSizeChange={handlePageSizeChange}
        />
      )}
    </div>
  )
}
