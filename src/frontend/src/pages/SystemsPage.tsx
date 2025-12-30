import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link, useNavigate } from 'react-router-dom'
import { 
  Plus, 
  Search, 
  Server, 
  Globe,
  AlertTriangle,
  ChevronRight,
  Loader2 
} from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { systemsApi, scansApi } from '@/services/api'
import { cn, formatDateTime, getRiskScoreColor, getMaturityLevelColor } from '@/lib/utils'
import type { System, URLScanResponse } from '@/types'

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

export default function SystemsPage() {
  const [searchTerm, setSearchTerm] = useState('')
  const [showSynthetic, setShowSynthetic] = useState(true)
  const [isAddWebsiteOpen, setIsAddWebsiteOpen] = useState(false)
  const [websiteUrl, setWebsiteUrl] = useState('')
  const [websiteEnv, setWebsiteEnv] = useState<'development' | 'staging' | 'production' | 'testing'>('production')
  const [websiteDesc, setWebsiteDesc] = useState('')

  const isDev = import.meta.env.DEV

  const isSyntheticSystem = (system: System): boolean => {
    const description = (system.description || '').toLowerCase()
    // Synthetic generator sets: "Auto-generated ... system for testing"
    return (
      description.includes('auto-generated') ||
      description.includes('synthetic') ||
      description.includes('for testing')
    )
  }
  
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  
  const { data: systems, isLoading, error } = useQuery<System[]>({
    queryKey: ['systems'],
    queryFn: systemsApi.getAll,
  })
  
  // URL scan mutation
  const urlScanMutation = useMutation({
    mutationFn: (data: { url: string; environment: string; description: string }) => 
      scansApi.scanUrl(data),
    onSuccess: (data: URLScanResponse) => {
      queryClient.invalidateQueries({ queryKey: ['systems'] })
      setIsAddWebsiteOpen(false)
      setWebsiteUrl('')
      setWebsiteDesc('')
      // Navigate to scan results
      navigate(`/scans/${data.scan_id}`)
    },
  })

  const handleAddWebsite = () => {
    if (!websiteUrl.trim()) return
    urlScanMutation.mutate({
      url: websiteUrl,
      environment: websiteEnv,
      description: websiteDesc,
    })
  }

  const searchFiltered = systems?.filter(system =>
    system.hostname.toLowerCase().includes(searchTerm.toLowerCase()) ||
    system.os.toLowerCase().includes(searchTerm.toLowerCase()) ||
    (system.url && system.url.toLowerCase().includes(searchTerm.toLowerCase()))
  )

  const syntheticCount = isDev
    ? (searchFiltered || []).filter(isSyntheticSystem).length
    : 0

  const filteredSystems = (searchFiltered || []).filter((system) =>
    !isDev || showSynthetic || !isSyntheticSystem(system)
  )
  
  // Separate servers and websites
  const servers = filteredSystems?.filter(s => s.system_type !== 'website') || []
  const websites = filteredSystems?.filter(s => s.system_type === 'website') || []

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
        <h2 className="text-lg font-semibold">Failed to load systems</h2>
        <p className="text-muted-foreground">Please try again later</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Systems</h1>
          <p className="text-muted-foreground">
            Manage and monitor your registered systems and websites
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => setIsAddWebsiteOpen(true)}>
            <Globe className="mr-2 h-4 w-4" />
            Add Website
          </Button>
          <Button>
            <Plus className="mr-2 h-4 w-4" />
            Add Server
          </Button>
        </div>
      </div>

      {/* Search */}
      <div className="space-y-2">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search systems and websites..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="pl-10"
          />
        </div>
        {isDev && syntheticCount > 0 && (
          <div className="flex items-center justify-between">
            <div className="text-xs text-muted-foreground">
              Synthetic systems detected: {syntheticCount}
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setShowSynthetic((prev) => !prev)}
            >
              {showSynthetic ? 'Hide synthetic' : 'Show synthetic'}
            </Button>
          </div>
        )}
      </div>

      {/* Websites Section */}
      {websites.length > 0 && (
        <div className="space-y-4">
          <h2 className="text-xl font-semibold flex items-center gap-2">
            <Globe className="h-5 w-5" />
            Websites ({websites.length})
          </h2>
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {websites.map((system) => (
              <Link key={system.id} to={`/systems/${system.id}`}>
                <Card className="hover:border-primary transition-colors cursor-pointer">
                  <CardHeader className="flex flex-row items-start justify-between space-y-0 pb-2">
                    <div className="flex items-center gap-3">
                      <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-blue-500/10">
                        <Globe className="h-5 w-5 text-blue-500" />
                      </div>
                      <div className="min-w-0 flex-1">
                        <CardTitle className="text-base truncate">{system.hostname}</CardTitle>
                        <p className="text-sm text-muted-foreground truncate">{system.url}</p>
                      </div>
                    </div>
                    <ChevronRight className="h-5 w-5 text-muted-foreground flex-shrink-0" />
                  </CardHeader>
                  <CardContent>
                    <div className="flex items-center justify-between">
                      <div className="flex gap-2">
                        <Badge variant="outline" className="capitalize">
                          {system.environment}
                        </Badge>
                        <Badge variant="secondary">Website</Badge>
                      </div>
                      <div className="text-right">
                        {system.latest_risk_score !== null && system.latest_risk_score !== undefined ? (
                          <div>
                            <span className={cn('text-lg font-bold', getRiskScoreColor(system.latest_risk_score))}>
                              {system.latest_risk_score}
                            </span>
                            <span className="text-sm text-muted-foreground ml-1">risk</span>
                          </div>
                        ) : (
                          <span className="text-sm text-muted-foreground">No scans</span>
                        )}
                      </div>
                    </div>
                    
                    <div className="mt-4 flex items-center justify-between text-sm">
                      {system.latest_maturity_level && (
                        <Badge className={getMaturityLevelColor(system.latest_maturity_level)}>
                          {system.latest_maturity_level}
                        </Badge>
                      )}
                      {system.last_seen && (
                        <span className="text-muted-foreground">
                          Last scan: {formatDateTime(system.last_seen)}
                        </span>
                      )}
                    </div>
                  </CardContent>
                </Card>
              </Link>
            ))}
          </div>
        </div>
      )}

      {/* Servers Section */}
      {servers.length > 0 && (
        <div className="space-y-4">
          <h2 className="text-xl font-semibold flex items-center gap-2">
            <Server className="h-5 w-5" />
            Servers ({servers.length})
          </h2>
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {servers.map((system) => (
              <Link key={system.id} to={`/systems/${system.id}`}>
                <Card className="hover:border-primary transition-colors cursor-pointer">
                  <CardHeader className="flex flex-row items-start justify-between space-y-0 pb-2">
                    <div className="flex items-center gap-3">
                      <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
                        <Server className="h-5 w-5 text-primary" />
                      </div>
                      <div>
                        <CardTitle className="text-base">{system.hostname}</CardTitle>
                        <p className="text-sm text-muted-foreground">{system.os}</p>
                      </div>
                    </div>
                    <ChevronRight className="h-5 w-5 text-muted-foreground" />
                  </CardHeader>
                  <CardContent>
                    <div className="flex items-center justify-between">
                      <div>
                        <Badge variant="outline" className="capitalize">
                          {system.environment}
                        </Badge>
                      </div>
                      <div className="text-right">
                        {system.latest_risk_score !== null && system.latest_risk_score !== undefined ? (
                          <div>
                            <span className={cn('text-lg font-bold', getRiskScoreColor(system.latest_risk_score))}>
                              {system.latest_risk_score}
                            </span>
                            <span className="text-sm text-muted-foreground ml-1">risk</span>
                          </div>
                        ) : (
                          <span className="text-sm text-muted-foreground">No scans</span>
                        )}
                      </div>
                    </div>
                    
                    <div className="mt-4 flex items-center justify-between text-sm">
                      {system.latest_maturity_level && (
                        <Badge className={getMaturityLevelColor(system.latest_maturity_level)}>
                          {system.latest_maturity_level}
                        </Badge>
                      )}
                      {system.last_seen && (
                        <span className="text-muted-foreground">
                          Last seen: {formatDateTime(system.last_seen)}
                        </span>
                      )}
                    </div>
                  </CardContent>
                </Card>
              </Link>
            ))}
          </div>
        </div>
      )}

      {/* Empty State */}
      {filteredSystems && filteredSystems.length === 0 && (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <Server className="h-12 w-12 text-muted-foreground mb-4" />
            <h3 className="text-lg font-semibold">No systems found</h3>
            <p className="text-muted-foreground text-center mt-1">
              {searchTerm
                ? 'Try adjusting your search terms'
                : 'Get started by adding your first system or website'}
            </p>
            {!searchTerm && (
              <div className="flex gap-2 mt-4">
                <Button variant="outline" onClick={() => setIsAddWebsiteOpen(true)}>
                  <Globe className="mr-2 h-4 w-4" />
                  Add Website
                </Button>
                <Button>
                  <Plus className="mr-2 h-4 w-4" />
                  Add Server
                </Button>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Add Website Modal */}
      <Modal 
        isOpen={isAddWebsiteOpen} 
        onClose={() => setIsAddWebsiteOpen(false)}
        title="Add Website for Security Scan"
      >
        <div className="space-y-4">
          <div>
            <label htmlFor="website-url" className="text-sm font-medium">Website URL</label>
            <Input
              id="website-url"
              placeholder="https://example.com"
              value={websiteUrl}
              onChange={(e) => setWebsiteUrl(e.target.value)}
              className="mt-1"
            />
            <p className="text-xs text-muted-foreground mt-1">
              Enter the full URL including https://
            </p>
          </div>
          
          <div>
            <label htmlFor="website-environment" className="text-sm font-medium">Environment</label>
            <select
              id="website-environment"
              value={websiteEnv}
              onChange={(e) => setWebsiteEnv(e.target.value as typeof websiteEnv)}
              className="mt-1 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
            >
              <option value="production">Production</option>
              <option value="staging">Staging</option>
              <option value="development">Development</option>
              <option value="testing">Testing</option>
            </select>
          </div>
          
          <div>
            <label htmlFor="website-description" className="text-sm font-medium">Description (optional)</label>
            <Input
              id="website-description"
              placeholder="Main company website"
              value={websiteDesc}
              onChange={(e) => setWebsiteDesc(e.target.value)}
              className="mt-1"
            />
          </div>
          
          {urlScanMutation.isError && (
            <div className="text-sm text-red-500 bg-red-50 dark:bg-red-950 p-3 rounded">
              {(urlScanMutation.error as Error)?.message || 'Failed to scan website'}
            </div>
          )}
          
          <div className="flex justify-end gap-2 pt-4">
            <Button variant="outline" onClick={() => setIsAddWebsiteOpen(false)}>
              Cancel
            </Button>
            <Button 
              onClick={handleAddWebsite}
              disabled={!websiteUrl.trim() || urlScanMutation.isPending}
            >
              {urlScanMutation.isPending ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Scanning...
                </>
              ) : (
                <>
                  <Globe className="mr-2 h-4 w-4" />
                  Scan Website
                </>
              )}
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  )
}
