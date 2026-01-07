import { useState } from 'react'
import { Shield, User as UserIcon, LogOut, RefreshCw, Moon, Sun, Monitor } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { useAuthStore } from '@/stores/authStore'
import { useToast } from '@/components/ui/Toast'
import { usePreferencesStore } from '@/stores/preferencesStore'

export default function SettingsPage() {
  const user = useAuthStore((s) => s.user)
  const logout = useAuthStore((s) => s.logout)
  const { addToast } = useToast()
  const [theme, setTheme] = useState<'light' | 'dark' | 'system'>('system')
  const showSyntheticData = usePreferencesStore((s) => s.showSyntheticData)
  const toggleShowSyntheticData = usePreferencesStore((s) => s.toggleShowSyntheticData)

  const handleLogout = () => {
    logout()
    addToast({
      type: 'success',
      title: 'Logged Out',
      message: 'You have successfully logged out'
    })
  }

  const handleThemeChange = (newTheme: 'light' | 'dark' | 'system') => {
    setTheme(newTheme)
    // Apply theme
    if (newTheme === 'dark') {
      document.documentElement.classList.add('dark')
    } else if (newTheme === 'light') {
      document.documentElement.classList.remove('dark')
    } else {
      // System preference
      if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
        document.documentElement.classList.add('dark')
      } else {
        document.documentElement.classList.remove('dark')
      }
    }
    addToast({
      type: 'success',
      title: 'Theme Updated',
      message: `Theme changed to ${newTheme === 'system' ? 'automatic' : newTheme === 'dark' ? 'dark' : 'light'}`
    })
  }

  const handleClearCache = () => {
    // Clear React Query cache
    localStorage.removeItem('auth-storage')
    addToast({
      type: 'info',
      title: 'Cache Cleared',
      message: 'The application cache has been cleared. Reload the page to apply the changes.'
    })
  }

  const handleToggleSyntheticData = () => {
    toggleShowSyntheticData()
    addToast({
      type: 'success',
      title: 'Preference updated',
      message: showSyntheticData
        ? 'The synthetic data is now hidden'
        : 'The synthetic data is now shown',
    })
  }

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

            <div className="mt-6">
              <Button
                variant="outline"
                className="w-full text-red-600 hover:text-red-700 hover:bg-red-50"
                onClick={handleLogout}
              >
                <LogOut className="mr-2 h-4 w-4" />
                Sign Out
              </Button>
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

            <div className="mt-4 space-y-2">
              <div className="flex items-center justify-between text-sm">
                <span>View Dashboard</span>
                <Badge variant="outline" className="text-green-600">Allowed</Badge>
              </div>
              <div className="flex items-center justify-between text-sm">
                <span>View Systems</span>
                <Badge variant="outline" className="text-green-600">Allowed</Badge>
              </div>
              <div className="flex items-center justify-between text-sm">
                <span>Generate Reports</span>
                <Badge variant="outline" className={user?.role === 'viewer' ? 'text-red-600' : 'text-green-600'}>
                  {user?.role === 'viewer' ? 'Restricted' : 'Allowed'}
                </Badge>
              </div>
              <div className="flex items-center justify-between text-sm">
                <span>Admin Settings</span>
                <Badge variant="outline" className={user?.role === 'admin' ? 'text-green-600' : 'text-red-600'}>
                  {user?.role === 'admin' ? 'Allowed' : 'Restricted'}
                </Badge>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Theme Settings */}
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
                <Sun className="h-5 w-5 text-primary" />
              </div>
              <div>
                <div className="font-semibold">Appearance</div>
                <div className="text-sm text-muted-foreground">Customize the app appearance</div>
              </div>
            </div>

            <div className="mt-4 flex gap-2">
              <Button
                variant={theme === 'light' ? 'default' : 'outline'}
                size="sm"
                onClick={() => handleThemeChange('light')}
              >
                <Sun className="mr-2 h-4 w-4" />
                Light
              </Button>
              <Button
                variant={theme === 'dark' ? 'default' : 'outline'}
                size="sm"
                onClick={() => handleThemeChange('dark')}
              >
                <Moon className="mr-2 h-4 w-4" />
                Dark
              </Button>
              <Button
                variant={theme === 'system' ? 'default' : 'outline'}
                size="sm"
                onClick={() => handleThemeChange('system')}
              >
                <Monitor className="mr-2 h-4 w-4" />
                System
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Cache Settings */}
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
                <RefreshCw className="h-5 w-5 text-primary" />
              </div>
              <div>
                <div className="font-semibold">Cache & Data</div>
                <div className="text-sm text-muted-foreground">Manage local storage</div>
              </div>
            </div>

            <div className="mt-4 text-sm text-muted-foreground">
              Clear cached data if you experience issues with the application.
            </div>

            <div className="mt-4 flex items-center justify-between gap-4">
              <div className="text-sm">
                <div className="font-medium">Synth data</div>
                <div className="text-muted-foreground">
                  Hide or show synthetic data (real data is always preserved).
                </div>
              </div>
              <Button variant="outline" size="sm" onClick={handleToggleSyntheticData}>
                {showSyntheticData ? 'Hide' : 'Show'}
              </Button>
            </div>

            <div className="mt-4">
              <Button variant="outline" onClick={handleClearCache}>
                <RefreshCw className="mr-2 h-4 w-4" />
                Clear Cache
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* App Info */}
      <Card>
        <CardContent className="p-6">
          <div className="text-center text-sm text-muted-foreground">
            <p>SecureSys Auditor v1.0.0</p>
            <p className="mt-1">© 2025 SecureSys. All rights reserved.</p>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
