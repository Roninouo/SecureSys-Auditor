import React from 'react'
import { Link } from 'react-router-dom'
import { AlertTriangle } from 'lucide-react'

import { Button } from '@/components/ui/Button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'

type Props = {
  children: React.ReactNode
  title?: string
}

type State = {
  hasError: boolean
  error?: Error
}

export default class ErrorBoundary extends React.Component<Props, State> {
  state: State = { hasError: false }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error }
  }

  render() {
    if (!this.state.hasError) return this.props.children

    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-yellow-500" />
            {this.props.title ?? 'Something went wrong'}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-sm text-muted-foreground">
            We couldn’t render this page. Please try going back and opening the scan again.
          </p>
          <div className="flex gap-2">
            <Link to="/scans">
              <Button variant="outline">Back to Scans</Button>
            </Link>
            <Button variant="outline" onClick={() => window.location.reload()}>
              Reload
            </Button>
          </div>
          {import.meta.env.DEV && this.state.error?.message ? (
            <pre className="text-xs bg-muted/50 border rounded p-3 overflow-auto">{this.state.error.message}</pre>
          ) : null}
        </CardContent>
      </Card>
    )
  }
}
