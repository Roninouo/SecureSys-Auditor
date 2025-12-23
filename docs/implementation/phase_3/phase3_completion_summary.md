# Phase 3 - End-to-End Integration & Core Decoupling

## Summary
This phase completed the architectural refactoring by migrating data models out of core and establishing a functional end-to-end loop: Agent → Backend → Frontend.

## Changes Made

### 1. Data Models Decoupling (Backend)

**New file: `src/backend/scanning/models.py`**
- Migrated `System`, `Scan`, `Finding`, and `Recommendation` models from `core/models.py`
- Updated table names to use `scanning_` prefix for clean separation
- Added `scan_type` field to Scan model (full, quick, compliance, vulnerability)

### 2. Scanning API Implementation (Backend)

**New file: `src/backend/scanning/serializers.py`**
- `SystemSerializer`, `SystemListSerializer`, `SystemCreateSerializer`
- `ScanSerializer`, `ScanListSerializer`, `ScanSubmitSerializer`
- `FindingSerializer`, `FindingListSerializer`, `FindingDetailSerializer`
- `RecommendationSerializer`, `RecommendationListSerializer`
- `DashboardStatsSerializer`

**New file: `src/backend/scanning/views.py`**
- `SystemViewSet` - System CRUD + `/by_hostname/` endpoint for agent
- `ScanViewSet` - Scan management + `/submit/` and `/summary/` endpoints
- `FindingViewSet` - Finding management + `/resolve/` and `/unresolve/` actions
- `RecommendationViewSet` - Read-only recommendations
- `DashboardStatsView` - Aggregated statistics endpoint
- `ScanningHealthCheckView` - Service health check

**New file: `src/backend/scanning/urls.py`**
- Routes for all scanning endpoints under `/api/v1/scanning/`

**New file: `src/backend/scanning/admin.py`**
- Django admin registration for System, Scan, Finding, Recommendation

**Updated: `src/backend/scanning/services.py`**
- Changed imports to use new `scanning.models` instead of `core.models`

**Updated: `src/backend/scanning/tasks.py`**
- Changed imports to use new `scanning.models` instead of `core.models`

**Updated: `src/backend/backend/urls.py`**
- Added route: `path('api/v1/scanning/', include('scanning.urls'))`

### 3. Agent Updates

**Updated: `src/agent/cli.py`**
- Added async support with `--async` flag
- Added `--scan-type` option (full, quick, compliance, vulnerability)
- Added `--wait` flag to wait for scan completion
- Integrated with `AsyncSecureSysClient`

**Updated: `src/agent/client/async_client.py`**
- Updated API endpoints to use `/api/v1/scanning/` prefix
- Updated `register_or_get_system()` to use `/by_hostname/` endpoint
- Updated `submit_scan()` to use new scanning endpoint
- Updated `get_scan_status()` and `get_findings()` endpoints

### 4. Frontend Integration

**New file: `src/frontend/src/pages/ScanListPage.tsx`**
- Full scan list page with search and status filtering
- Stats cards showing scan counts by status
- Real-time polling for status updates (10s interval)
- Links to scan detail pages

**Updated: `src/frontend/src/App.tsx`**
- Added `/scans` route pointing to `ScanListPage`

**Updated: `src/frontend/src/components/layout/Layout.tsx`**
- Added "Scans" link to navigation sidebar

**Updated: `src/frontend/src/services/api.ts`**
- Added `scanningApi` axios instance for new scanning endpoints
- Updated `systemsApi`, `scansApi`, `findingsApi`, `dashboardApi` to use scanning API
- Added new methods: `getByHostname()`, `getSummary()`, `unresolve()`

**Updated: `src/frontend/src/types/index.ts`**
- Added `recent_scans` and `systems_by_environment` to `DashboardStats`

## API Endpoints (New Scanning Module)

### Systems
- `GET /api/v1/scanning/systems/` - List systems
- `POST /api/v1/scanning/systems/` - Create/register system
- `GET /api/v1/scanning/systems/{id}/` - Get system detail
- `GET /api/v1/scanning/systems/{id}/scans/` - Get system scans
- `GET /api/v1/scanning/systems/by_hostname/?hostname=<name>` - Get by hostname

### Scans
- `GET /api/v1/scanning/scans/` - List scans
- `POST /api/v1/scanning/scans/submit/` - Submit new scan (agent)
- `GET /api/v1/scanning/scans/{id}/` - Get scan detail
- `GET /api/v1/scanning/scans/{id}/findings/` - Get scan findings
- `GET /api/v1/scanning/scans/{id}/summary/` - Get scan summary stats

### Findings
- `GET /api/v1/scanning/findings/` - List findings
- `GET /api/v1/scanning/findings/{id}/` - Get finding detail
- `POST /api/v1/scanning/findings/{id}/resolve/` - Resolve finding
- `POST /api/v1/scanning/findings/{id}/unresolve/` - Unresolve finding
- `GET /api/v1/scanning/findings/{id}/recommendations/` - Get recommendations

### Dashboard
- `GET /api/v1/scanning/dashboard/stats/` - Dashboard statistics

### Health
- `GET /api/v1/scanning/health/` - Service health check

## Database Migration

Since we're creating fresh tables with the `scanning_` prefix, run:

```bash
cd src/backend
python manage.py makemigrations scanning
python manage.py migrate
```

**Note:** The old tables in `core` remain available during transition. Once verified, they can be deprecated.

## Agent Usage

```bash
# Basic scan
securesys-agent scan

# Scan and submit to API
securesys-agent scan --submit

# Async submission with wait
securesys-agent scan --submit --async --wait

# Specific scan type
securesys-agent scan --submit --scan-type compliance

# All options
securesys-agent scan -o json --submit --async --wait --scan-type full -v
```

## Next Steps

1. **Database Migration**: Run migrations to create new tables
2. **Data Migration**: Optionally migrate existing data from core tables
3. **Testing**: Run full E2E tests with agent → backend → frontend flow
4. **Deprecation**: Remove legacy routes in core app after verification
