# Production Readiness Checklist

## 1. Security
- [ ] **Secrets Management**: `secrets.yaml.template` removed; ExternalSecrets/SealedSecrets configured.
- [ ] **API Documentation**: Restricted to admin/internal networks in production.
- [ ] **Network Policies**: Egress/Ingress rules configured (deny-all default).
- [ ] **Container Security**: Images scanned (Trivy), non-root user enforced.
- [ ] **Headers**: HSTS, CSP, X-Frame-Options configured in Nginx/Ingress.

## 2. Database & Data
- [ ] **Backups**: Automated daily backups configured & tested (S3 offsite).
- [ ] **Encryption**: At-rest encryption enabled (EBS/RDS).
- [ ] **Migrations**: All migrations applied; data integrity verified.
- [ ] **Connection Pooling**: PgBouncer or similar configured for high load.

## 3. Observability
- [ ] **Logging**: JSON logging enabled; logs shipping to aggregator (ELK/Splunk).
- [ ] **Metrics**: Prometheus scraping `/metrics` endpoint.
- [ ] **Alerting**: Critical alerts configured (High Error Rate, High Latency, Saturation).
- [ ] **Tracing**: OpenTelemetry instrumentation active.

## 4. Reliability
- [ ] **Health Checks**: Liveness/Readiness probes configured and passing.
- [ ] **HPA**: Horizontal Pod Autoscaling enabled (CPU/Memory targets).
- [ ] **PDB**: Pod Disruption Budgets configured for zero-downtime upgrades.
- [ ] **Circuit Breakers**: Configured for external dependencies (Webhooks).

## 5. Pre-Launch Verification
Run the verification script:
```bash
./scripts/production-check.sh https://api.securesys.io
```
