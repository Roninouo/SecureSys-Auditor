import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { 
  Plus, 
  Search, 
  Server, 
  AlertTriangle,
  ChevronRight 
} from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { systemsApi } from '@/services/api'
import { cn, formatDateTime, getRiskScoreColor, getMaturityLevelColor } from '@/lib/utils'
import type { System } from '@/types'

export default function SystemsPage() {
  const [searchTerm, setSearchTerm] = useState('')
  
  const { data: systems, isLoading, error } = useQuery<System[]>({
    queryKey: ['systems'],
    queryFn: systemsApi.getAll,
  })

  const filteredSystems = systems?.filter(system =>
    system.hostname.toLowerCase().includes(searchTerm.toLowerCase()) ||
    system.os.toLowerCase().includes(searchTerm.toLowerCase())
  )

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
            Manage and monitor your registered systems
          </p>
        </div>
        <Button>
          <Plus className="mr-2 h-4 w-4" />
          Add System
        </Button>
      </div>

      {/* Search */}
      <div className="relative">
        <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          placeholder="Search systems..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="pl-10"
        />
      </div>

      {/* Systems Grid */}
      {filteredSystems && filteredSystems.length > 0 ? (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {filteredSystems.map((system) => (
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
      ) : (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <Server className="h-12 w-12 text-muted-foreground mb-4" />
            <h3 className="text-lg font-semibold">No systems found</h3>
            <p className="text-muted-foreground text-center mt-1">
              {searchTerm
                ? 'Try adjusting your search terms'
                : 'Get started by adding your first system'}
            </p>
            {!searchTerm && (
              <Button className="mt-4">
                <Plus className="mr-2 h-4 w-4" />
                Add System
              </Button>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  )
}
