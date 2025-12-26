import { Shield, User as UserIcon } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { useAuthStore } from '@/stores/authStore'

export default function SettingsPage() {
  const user = useAuthStore((s) => s.user)

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Settings</h1>
          <p className="text-muted-foreground">Account and application information</p>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
                <UserIcon className="h-5 w-5 text-primary" />
              </div>
              <div>
                <div className="font-semibold">Account</div>
                <div className="text-sm text-muted-foreground">Current signed-in user</div>
              </div>
            </div>

            <div className="mt-4 space-y-2 text-sm">
              <div>
                <span className="text-muted-foreground">Email: </span>
                <span className="font-medium">{user?.email || 'Unknown'}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-muted-foreground">Role:</span>
                <Badge className="bg-primary/10 text-primary">{user?.role || 'viewer'}</Badge>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
                <Shield className="h-5 w-5 text-primary" />
              </div>
              <div>
                <div className="font-semibold">Permissions</div>
                <div className="text-sm text-muted-foreground">Feature access is role-based</div>
              </div>
            </div>

            <div className="mt-4 text-sm text-muted-foreground">
              Reports and certain scan actions require <span className="font-medium">auditor</span> or <span className="font-medium">admin</span>.
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
