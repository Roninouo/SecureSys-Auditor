import { Routes, Route, Navigate } from 'react-router-dom'
import { useAuthStore } from './stores/authStore'
import Layout from './components/layout/Layout'
import LoginPage from './pages/LoginPage'
import OIDCCallbackPage from './pages/OIDCCallbackPage'
import DashboardPage from './pages/DashboardPage'
import SystemsPage from './pages/SystemsPage'
import SystemDetailPage from './pages/SystemDetailPage'
import ScanDetailPage from './pages/ScanDetailPage'
import ScanListPage from './pages/ScanListPage'
import ReportsPage from './pages/ReportsPage'
import SettingsPage from './pages/SettingsPage'
import ErrorBoundary from './components/ErrorBoundary'

function PrivateRoute({ children }: { children: React.ReactNode }) {
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated)
  return isAuthenticated ? <>{children}</> : <Navigate to="/login" />
}

function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/auth/callback" element={<OIDCCallbackPage />} />
      <Route
        path="/"
        element={
          <PrivateRoute>
            <Layout />
          </PrivateRoute>
        }
      >
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard" element={<DashboardPage />} />
        <Route path="systems" element={<SystemsPage />} />
        <Route path="systems/:systemId" element={<SystemDetailPage />} />
        <Route path="scans" element={<ScanListPage />} />
        <Route
          path="scans/:scanId"
          element={
            <ErrorBoundary title="Scan view crashed">
              <ScanDetailPage />
            </ErrorBoundary>
          }
        />
        <Route path="reports" element={<ReportsPage />} />
        <Route path="settings" element={<SettingsPage />} />
      </Route>
    </Routes>
  )
}

export default App
