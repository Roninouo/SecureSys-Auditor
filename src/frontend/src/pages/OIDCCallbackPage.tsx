/**
 * OIDC Callback Page
 *
 * Handles the redirect back from Keycloak after authentication.
 * Exchanges the authorization code for tokens and redirects to the dashboard.
 */

import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Loader2, AlertCircle, Shield } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { oidcService } from '@/services/oidc'
import { useAuthStore } from '@/stores/authStore'

export default function OIDCCallbackPage() {
  const navigate = useNavigate()
  const login = useAuthStore((state) => state.login)
  const [error, setError] = useState<string | null>(null)
  const [status, setStatus] = useState('Processing authentication...')

  useEffect(() => {
    const handleCallback = async () => {
      try {
        setStatus('Exchanging authorization code...')

        const { user, tokens } = await oidcService.handleCallback(window.location.href)

        setStatus('Authentication successful, redirecting...')

        // Update auth store
        login(
          {
            id: user.id,
            email: user.email,
            role: user.role,
          },
          tokens.accessToken,
          tokens.refreshToken
        )

        // Redirect to dashboard
        setTimeout(() => {
          navigate('/dashboard', { replace: true })
        }, 500)

      } catch (err: any) {
        console.error('OIDC callback error:', err)
        setError(err.message || 'Authentication failed')
      }
    }

    handleCallback()
  }, [navigate, login])

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-100 dark:from-gray-900 dark:to-gray-800 p-4">
        <Card className="w-full max-w-md">
          <CardHeader className="text-center">
            <div className="flex justify-center mb-4">
              <div className="flex h-16 w-16 items-center justify-center rounded-full bg-red-100">
                <AlertCircle className="h-8 w-8 text-red-600" />
              </div>
            </div>
            <CardTitle className="text-xl text-red-600">Authentication Failed</CardTitle>
          </CardHeader>
          <CardContent className="text-center space-y-4">
            <p className="text-gray-600 dark:text-gray-400">{error}</p>
            <button
              onClick={() => navigate('/login')}
              className="px-4 py-2 bg-primary text-white rounded-md hover:bg-primary/90"
            >
              Return to Login
            </button>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-100 dark:from-gray-900 dark:to-gray-800 p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <div className="flex justify-center mb-4">
            <div className="flex h-16 w-16 items-center justify-center rounded-full bg-primary">
              <Shield className="h-8 w-8 text-primary-foreground" />
            </div>
          </div>
          <CardTitle className="text-xl">SecureSys Auditor</CardTitle>
        </CardHeader>
        <CardContent className="text-center space-y-4">
          <div className="flex items-center justify-center space-x-2">
            <Loader2 className="h-5 w-5 animate-spin text-primary" />
            <span className="text-gray-600 dark:text-gray-400">{status}</span>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
