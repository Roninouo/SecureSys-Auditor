import { useMemo, useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { FileText, AlertTriangle, Download, Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Card, CardContent } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { scansApi, reportsApi } from '@/services/api'
import { cn, formatDateTime, getMaturityLevelColor, getRiskScoreColor } from '@/lib/utils'
import type { Scan as ScanType } from '@/types'

type ReportType = 'executive' | 'technical' | 'compliance'

type ReportTaskStatus =
  | { status: 'pending' | 'processing'; message?: string }
  | { status: 'completed'; report: { filename: string; report_type?: string; generated_at?: string } }
  | { status: 'failed'; error?: string }

export default function ReportsPage() {
  const [companyName, setCompanyName] = useState('Organization')
  const [activeTaskId, setActiveTaskId] = useState<string | null>(null)

  const { data: scans, isLoading: scansLoading, error: scansError, refetch: refetchScans } = useQuery<ScanType[]>({
    queryKey: ['scans'],
    queryFn: scansApi.getAll,
    refetchInterval: 15000,
  })

  const completedScans = useMemo(
    () => (scans || []).filter((s) => s.status === 'completed'),
    [scans]
  )

  const generateMutation = useMutation({
    mutationFn: (payload: { scanId: string; reportType: ReportType }) =>
      reportsApi.generate({
        scan_id: payload.scanId,
        report_type: payload.reportType,
        async: true,
        company_name: companyName || 'Organization',
      }),
    onSuccess: (data) => {
      if (data?.task_id) setActiveTaskId(data.task_id)
    },
  })

  const {
    data: taskStatus,
    isFetching: statusFetching,
    error: statusError,
  } = useQuery<ReportTaskStatus>({
    queryKey: ['report-task', activeTaskId],
    queryFn: () => reportsApi.getStatus(activeTaskId!),
    enabled: Boolean(activeTaskId),
    refetchInterval: (query) => {
      const status = (query.state.data as ReportTaskStatus | undefined)?.status
      return status && (status === 'completed' || status === 'failed') ? false : 2000
    },
  })

  if (scansLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
      </div>
    )
  }

  if (scansError) {
    return (
      <div className="text-center p-8">
        <AlertTriangle className="h-12 w-12 text-yellow-500 mx-auto mb-4" />
        <h2 className="text-lg font-semibold">Failed to load scans</h2>
        <p className="text-muted-foreground">Reports require completed scans</p>
        <Button className="mt-4" onClick={() => refetchScans()}>
          Retry
        </Button>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Reports</h1>
          <p className="text-muted-foreground">Generate PDF reports from completed scans</p>
        </div>
      </div>

      <Card>
        <CardContent className="p-6 space-y-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
              <FileText className="h-5 w-5 text-primary" />
            </div>
            <div>
              <div className="font-semibold">Report generation</div>
              <div className="text-sm text-muted-foreground">Choose a completed scan below</div>
            </div>
          </div>

          <div className="max-w-md">
            <label className="text-sm font-medium">Company name (optional)</label>
            <Input
              className="mt-2"
              value={companyName}
              onChange={(e) => setCompanyName(e.target.value)}
              placeholder="Organization"
            />
          </div>

          {activeTaskId && (
            <div className="rounded-md border p-4">
              <div className="flex items-center justify-between gap-4 flex-wrap">
                <div className="text-sm">
                  <div className="font-medium">Latest report task</div>
                  <div className="text-muted-foreground font-mono break-all">{activeTaskId}</div>
                </div>

                <div className="flex items-center gap-3">
                  {statusFetching && (
                    <Badge className="gap-1 bg-blue-500/10 text-blue-500">
                      <Loader2 className="h-3 w-3 animate-spin" />
                      Checking…
                    </Badge>
                  )}

                  {taskStatus?.status === 'pending' && (
                    <Badge className="bg-yellow-500/10 text-yellow-500">Queued</Badge>
                  )}
                  {taskStatus?.status === 'processing' && (
                    <Badge className="bg-blue-500/10 text-blue-500">Processing</Badge>
                  )}
                  {taskStatus?.status === 'failed' && (
                    <Badge className="bg-red-500/10 text-red-500">Failed</Badge>
                  )}
                  {taskStatus?.status === 'completed' && (
                    <Badge className="bg-green-500/10 text-green-500">Completed</Badge>
                  )}

                  {taskStatus?.status === 'completed' && taskStatus.report?.filename && (
                    <Button
                      size="sm"
                      onClick={() => reportsApi.download(taskStatus.report.filename)}
                      className="gap-2"
                    >
                      <Download className="h-4 w-4" />
                      Download
                    </Button>
                  )}
                </div>
              </div>

              {(statusError || taskStatus?.status === 'failed') && (
                <div className="mt-3 text-sm text-red-500">
                  {taskStatus?.status === 'failed' ? taskStatus.error || 'Report generation failed' : 'Failed to check status'}
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {completedScans.length > 0 ? (
        <div className="space-y-4">
          {completedScans.map((scan) => (
            <Card key={scan.id}>
              <CardContent className="p-6">
                <div className="flex items-start justify-between gap-4 flex-wrap">
                  <div className="min-w-[240px]">
                    <div className="font-semibold">{scan.system_hostname || 'Unknown host'}</div>
                    <div className="text-sm text-muted-foreground">
                      Completed {formatDateTime(scan.scan_date)}
                    </div>
                    <div className="mt-2 flex items-center gap-2 flex-wrap">
                      <Badge className="bg-green-500/10 text-green-500">Completed</Badge>
                      {typeof scan.risk_score === 'number' && (
                        <Badge className={cn('font-semibold', getRiskScoreColor(scan.risk_score))}>
                          Risk {scan.risk_score}
                        </Badge>
                      )}
                      {scan.maturity_level && (
                        <Badge className={getMaturityLevelColor(scan.maturity_level)}>
                          {scan.maturity_level}
                        </Badge>
                      )}
                      <span className="text-xs text-muted-foreground font-mono">{scan.id}</span>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={generateMutation.isPending}
                      onClick={() => generateMutation.mutate({ scanId: scan.id, reportType: 'executive' })}
                    >
                      Executive
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={generateMutation.isPending}
                      onClick={() => generateMutation.mutate({ scanId: scan.id, reportType: 'technical' })}
                    >
                      Technical
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={generateMutation.isPending}
                      onClick={() => generateMutation.mutate({ scanId: scan.id, reportType: 'compliance' })}
                    >
                      Compliance
                    </Button>
                  </div>
                </div>

                {generateMutation.isError && (
                  <div className="mt-3 text-sm text-red-500">Failed to start report generation</div>
                )}
              </CardContent>
            </Card>
          ))}
        </div>
      ) : (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <FileText className="h-12 w-12 text-muted-foreground mb-4" />
            <h3 className="text-lg font-semibold">No completed scans</h3>
            <p className="text-muted-foreground text-center mt-1">Run a scan first, then generate a report here</p>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
