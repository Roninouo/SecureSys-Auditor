# Grafana Dashboards Configuration for SecureSys Auditor

This directory contains Grafana dashboard definitions for monitoring SecureSys Auditor.

## Dashboards

### 1. Application Overview Dashboard
- Request rate and latency
- Error rates by endpoint
- Active users
- Scan submission rate
- System health metrics

### 2. Security Scan Dashboard
- Scans by status (pending, processing, completed, failed)
- Average scan processing time
- Findings by severity
- Top vulnerable systems
- Risk score trends

### 3. Webhook Delivery Dashboard
- Delivery success/failure rates
- Circuit breaker status by endpoint
- Retry attempts
- Response time distribution
- Rate limit hits

### 4. Infrastructure Dashboard
- Database connections and query performance
- Redis memory usage and hit rates
- Celery worker utilization
- Queue depths
- Container resource usage

## Dashboard Installation

### Option 1: API Import
```bash
# Import dashboard via Grafana API
curl -X POST http://localhost:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d @application-overview.json
```

### Option 2: UI Import
1. Navigate to Grafana UI
2. Click "+" → "Import"
3. Upload JSON file or paste JSON content
4. Select Prometheus data source
5. Click "Import"

### Option 3: Provisioning
Add to `grafana/provisioning/dashboards/dashboards.yml`:
```yaml
apiVersion: 1

providers:
  - name: 'SecureSys'
    orgId: 1
    folder: 'SecureSys Auditor'
    type: file
    disableDeletion: false
    updateIntervalSeconds: 10
    allowUiUpdates: true
    options:
      path: /etc/grafana/provisioning/dashboards/securesys
```

## Data Sources

Required Prometheus metrics from SecureSys:
- `http_request_duration_seconds` - Request latency
- `http_requests_total` - Request count
- `scan_processing_duration_seconds` - Scan processing time
- `scans_total` - Total scans by status
- `findings_total` - Findings by severity
- `webhook_delivery_attempts_total` - Webhook delivery attempts
- `webhook_delivery_duration_seconds` - Webhook response time
- `celery_task_duration_seconds` - Celery task duration
- `celery_tasks_total` - Celery task count by status

## Alert Rules

Create alert rules in Grafana for:
- High error rate (> 5% of requests)
- Slow response time (p95 > 2s)
- Failed scans (> 10% failure rate)
- Webhook delivery failures (> 20% failure rate)
- Circuit breaker open state
- High celery queue depth (> 100 tasks)

Example alert configuration:
```yaml
groups:
  - name: securesys_alerts
    rules:
      - alert: HighErrorRate
        expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.05
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High error rate detected"
          description: "Error rate is {{ $value | humanizePercentage }}"
```

## Customization

To customize dashboards:
1. Edit JSON files in this directory
2. Update panel queries to match your metrics
3. Adjust thresholds and alerts as needed
4. Re-import to Grafana

## Dashboard IDs

- Application Overview: `securesys-app-overview`
- Security Scans: `securesys-scans`
- Webhooks: `securesys-webhooks`
- Infrastructure: `securesys-infrastructure`
