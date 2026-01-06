import { useState } from 'react'
import { useParams, Link, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  ArrowLeft,
  Server,
  AlertTriangle,
  Calendar,
  Activity,
  Play,
  Trash2,
  Loader2,
  Globe
} from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { systemsApi, scansApi } from '@/services/api'
import { useToast } from '@/components/ui/Toast'
import { safeLabel } from '@/lib/labels'
import {
  cn,
  formatDateTime,
  getRiskScoreColor,
  getMaturityLevelColor,
  getStatusColor
} from '@/lib/utils'
import type { System, Scan, URLScanResponse } from '@/types'

// Simple Modal component
function Modal({
  isOpen,
  onClose,
  title,
  children
}: {
  isOpen: boolean
  onClose: () => void
  title: string
  children: React.ReactNode
}) {
  if (!isOpen) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="fixed inset-0 bg-black/50" onClick={onClose} />
      <div className="relative bg-background border rounded-lg shadow-lg w-full max-w-md p-6 m-4">
        <h2 className="text-lg font-semibold mb-4">{title}</h2>
        {children}
      </div>
    </div>
  )
}

export default function SystemDetailPage() {
  const { systemId } = useParams<{ systemId: string }>()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const { addToast } = useToast()

  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false)
  const [isRunScanModalOpen, setIsRunScanModalOpen] = useState(false)

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

  // URL scan mutation for websites
  const urlScanMutation = useMutation({
    mutationFn: (url: string) => scansApi.scanUrl({ url }),
    onSuccess: (data: URLScanResponse) => {
      queryClient.invalidateQueries({ queryKey: ['system-scans', systemId] })
      queryClient.invalidateQueries({ queryKey: ['system', systemId] })
      setIsRunScanModalOpen(false)
      addToast({
        type: 'success',
        title: 'Escaneo iniciado',
        message: 'El escaneo de seguridad ha comenzado'
      })
      navigate(`/scans/${data.scan_id}`)
    },
    onError: (error: Error) => {
      addToast({
        type: 'error',
        title: 'Error',
        message: error.message || 'No se pudo iniciar el escaneo'
      })
    }
  })

  // Delete mutation
  const deleteMutation = useMutation({
    mutationFn: () => systemsApi.delete(systemId!),
    onSuccess: () => {
      addToast({
        type: 'success',
        title: 'Sistema eliminado',
        message: 'El sistema ha sido eliminado correctamente'
      })
      navigate('/systems')
    },
    onError: (error: Error) => {
      addToast({
        type: 'error',
        title: 'Error',
        message: error.message || 'No se pudo eliminar el sistema'
      })
    }
  })

  const handleRunScan = () => {
    if (system?.system_type === 'website' && system?.url) {
      urlScanMutation.mutate(system.url)
    } else {
      addToast({
        type: 'info',
        title: 'Ejecutar agente',
        message: 'Para escanear servidores, ejecuta el SecureSys Agent en el servidor'
      })
      setIsRunScanModalOpen(false)
    }
  }

  const handleDelete = () => {
    deleteMutation.mutate()
  }

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
            <div className={cn(
              "flex h-12 w-12 items-center justify-center rounded-lg",
              system.system_type === 'website' ? 'bg-blue-500/10' : 'bg-primary/10'
            )}>
              {system.system_type === 'website' ? (
                <Globe className="h-6 w-6 text-blue-500" />
              ) : (
                <Server className="h-6 w-6 text-primary" />
              )}
            </div>
            <div>
              <h1 className="text-2xl font-bold">{system.hostname}</h1>
              <p className="text-muted-foreground">
                {system.system_type === 'website'
                  ? (system.url ?? 'N/A')
                  : `${safeLabel(system.os, 'N/A')} ${safeLabel(system.os_version, '')}`}
              </p>
            </div>
          </div>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            className="text-red-600 hover:text-red-700 hover:bg-red-50"
            onClick={() => setIsDeleteModalOpen(true)}
          >
            <Trash2 className="mr-2 h-4 w-4" />
            Delete
          </Button>
          <Button onClick={() => setIsRunScanModalOpen(true)}>
            <Play className="mr-2 h-4 w-4" />
            Run New Scan
          </Button>
        </div>
      </div>

      {/* System Overview */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardContent className="pt-6">
            <div className="text-sm font-medium text-muted-foreground">Environment</div>
            <div className="mt-1">
              <Badge variant="outline" className="capitalize">
                {safeLabel(system.environment, 'N/A')}
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
              <Button className="mt-4" onClick={() => setIsRunScanModalOpen(true)}>
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

      {/* Delete Confirmation Modal */}
      <Modal
        isOpen={isDeleteModalOpen}
        onClose={() => setIsDeleteModalOpen(false)}
        title="Eliminar Sistema"
      >
        <div className="space-y-4">
          <p className="text-muted-foreground">
            ¿Estás seguro de que deseas eliminar <strong>{system.hostname}</strong>?
            Esta acción no se puede deshacer y se eliminarán todos los escaneos asociados.
          </p>
          <div className="flex justify-end gap-2 pt-4">
            <Button variant="outline" onClick={() => setIsDeleteModalOpen(false)}>
              Cancelar
            </Button>
            <Button
              variant="destructive"
              onClick={handleDelete}
              disabled={deleteMutation.isPending}
              className="bg-red-600 hover:bg-red-700"
            >
              {deleteMutation.isPending ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Eliminando...
                </>
              ) : (
                <>
                  <Trash2 className="mr-2 h-4 w-4" />
                  Eliminar
                </>
              )}
            </Button>
          </div>
        </div>
      </Modal>

      {/* Run Scan Modal */}
      <Modal
        isOpen={isRunScanModalOpen}
        onClose={() => setIsRunScanModalOpen(false)}
        title="Ejecutar Nuevo Escaneo"
      >
        <div className="space-y-4">
          {system.system_type === 'website' ? (
            <>
              <p className="text-muted-foreground">
                Se ejecutará un escaneo de seguridad completo en:
              </p>
              <div className="p-3 bg-muted rounded-lg">
                <code className="text-sm">{system.url}</code>
              </div>
              <p className="text-sm text-muted-foreground">
                El escaneo analizará headers de seguridad, certificado SSL, cookies y más.
              </p>
            </>
          ) : (
            <>
              <p className="text-muted-foreground">
                Para escanear servidores, necesitas ejecutar el SecureSys Agent directamente en el servidor.
              </p>
              <div className="p-3 bg-muted rounded-lg">
                <code className="text-sm">securesys-agent scan --system-id {system.id}</code>
              </div>
              <p className="text-sm text-muted-foreground">
                Consulta la documentación para instrucciones de instalación del agente.
              </p>
            </>
          )}
          <div className="flex justify-end gap-2 pt-4">
            <Button variant="outline" onClick={() => setIsRunScanModalOpen(false)}>
              Cancelar
            </Button>
            {system.system_type === 'website' && (
              <Button
                onClick={handleRunScan}
                disabled={urlScanMutation.isPending}
              >
                {urlScanMutation.isPending ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Escaneando...
                  </>
                ) : (
                  <>
                    <Play className="mr-2 h-4 w-4" />
                    Iniciar Escaneo
                  </>
                )}
              </Button>
            )}
          </div>
        </div>
      </Modal>
    </div>
  )
}
