# Phase 4 Quick Setup Guide

## Post-Phase 4 Configuration Steps

This guide helps you configure the new Phase 4 features.

---

## 1. Install New Dependencies

```bash
# For production
pip install -r reqs/requirements-prod.txt

# For development
pip install -r reqs/requirements-dev.txt
```

---

## 2. Update Django Settings

Add the following to `src/backend/backend/settings.py`:

```python
# ============================================================================
# PHASE 4 ADDITIONS
# ============================================================================

# 1. Add rate limiting middleware
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'observability.middleware.ObservabilityMiddleware',
    'core.rate_limiting.RateLimitMiddleware',  # ADD THIS
]

# 2. Add drf-spectacular for API docs
INSTALLED_APPS = [
    # ... existing apps
    'drf_spectacular',  # ADD THIS
]

REST_FRAMEWORK = {
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
    # ... existing REST_FRAMEWORK config
}

SPECTACULAR_SETTINGS = {
    'TITLE': 'SecureSys Auditor API',
    'DESCRIPTION': 'Enterprise Security Assessment Platform',
    'VERSION': '2.0.0',
    'SERVE_INCLUDE_SCHEMA': False,
}

# 3. Configure OIDC authentication
AUTHENTICATION_BACKENDS = [
    'core.oidc_integration.KeycloakOIDCBackend',  # ADD THIS
    'django.contrib.auth.backends.ModelBackend',
]

# OIDC Configuration (use environment variables)
OIDC_RP_CLIENT_ID = os.getenv('OIDC_RP_CLIENT_ID', '')
OIDC_RP_CLIENT_SECRET = os.getenv('OIDC_RP_CLIENT_SECRET', '')
OIDC_OP_AUTHORIZATION_ENDPOINT = os.getenv('OIDC_OP_AUTHORIZATION_ENDPOINT', '')
OIDC_OP_TOKEN_ENDPOINT = os.getenv('OIDC_OP_TOKEN_ENDPOINT', '')
OIDC_OP_USER_ENDPOINT = os.getenv('OIDC_OP_USER_ENDPOINT', '')
OIDC_OP_JWKS_ENDPOINT = os.getenv('OIDC_OP_JWKS_ENDPOINT', '')
OIDC_RP_SIGN_ALGO = 'RS256'
OIDC_RP_SCOPES = 'openid email profile'

# Keycloak Admin (optional)
KEYCLOAK_SERVER_URL = os.getenv('KEYCLOAK_SERVER_URL', '')
KEYCLOAK_REALM = os.getenv('KEYCLOAK_REALM', 'master')
KEYCLOAK_ADMIN_CLIENT_ID = os.getenv('KEYCLOAK_ADMIN_CLIENT_ID', '')
KEYCLOAK_ADMIN_CLIENT_SECRET = os.getenv('KEYCLOAK_ADMIN_CLIENT_SECRET', '')

# 4. Rate limiting configuration
RATE_LIMITS = {
    'authenticated': int(os.getenv('RATE_LIMIT_AUTHENTICATED', '100')),
    'anonymous': int(os.getenv('RATE_LIMIT_ANONYMOUS', '20')),
    'admin': int(os.getenv('RATE_LIMIT_ADMIN', '200')),
}

RATE_LIMIT_BURST = {
    'authenticated': 20,
    'anonymous': 5,
    'admin': 50,
}

# 5. Webhook configuration
WEBHOOK_ENABLED = os.getenv('WEBHOOK_ENABLED', 'true').lower() == 'true'
WEBHOOK_SECRET = os.getenv('WEBHOOK_SECRET', 'change-me-in-production')

# 6. OpenTelemetry (already configured, verify these)
OTEL_ENABLED = os.getenv('OTEL_ENABLED', 'false').lower() == 'true'
OTEL_SERVICE_NAME = os.getenv('OTEL_SERVICE_NAME', 'securesys-backend')
OTEL_EXPORTER_OTLP_ENDPOINT = os.getenv('OTEL_EXPORTER_OTLP_ENDPOINT', 'http://localhost:4317')

# ============================================================================
```

---

## 3. Update URL Configuration

Add to `src/backend/backend/urls.py`:

```python
from django.urls import path, include
from backend.api_docs import urlpatterns as api_doc_urls

urlpatterns = [
    # ... existing patterns
    
    # API Documentation (Phase 4)
    path('api/', include(api_doc_urls)),
]
```

---

## 4. Environment Variables

Update your `.env` file (or create from `env.example`):

```bash
# Phase 4 - OpenTelemetry
OTEL_ENABLED=true
OTEL_SERVICE_NAME=securesys-backend
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317

# Phase 4 - Webhooks
WEBHOOK_ENABLED=true
WEBHOOK_SECRET=your-webhook-secret-here

# Phase 4 - Rate Limiting
RATE_LIMIT_AUTHENTICATED=100
RATE_LIMIT_ANONYMOUS=20
RATE_LIMIT_ADMIN=200

# Phase 4 - OIDC/SSO (Keycloak)
OIDC_RP_CLIENT_ID=securesys-auditor
OIDC_RP_CLIENT_SECRET=your-client-secret
OIDC_OP_AUTHORIZATION_ENDPOINT=https://keycloak.example.com/auth/realms/master/protocol/openid-connect/auth
OIDC_OP_TOKEN_ENDPOINT=https://keycloak.example.com/auth/realms/master/protocol/openid-connect/token
OIDC_OP_USER_ENDPOINT=https://keycloak.example.com/auth/realms/master/protocol/openid-connect/userinfo
OIDC_OP_JWKS_ENDPOINT=https://keycloak.example.com/auth/realms/master/protocol/openid-connect/certs

# Keycloak Admin API (optional)
KEYCLOAK_SERVER_URL=https://keycloak.example.com/auth
KEYCLOAK_REALM=master
KEYCLOAK_ADMIN_CLIENT_ID=admin-cli
KEYCLOAK_ADMIN_CLIENT_SECRET=your-admin-secret
```

---

## 5. Database Migrations

Run new migrations for Phase 4 models:

```bash
cd src/backend

# Create migrations for new models
python manage.py makemigrations core scanning

# Apply migrations
python manage.py migrate

# Optional: Migrate data from core to scanning (if upgrading)
python manage.py migrate_scanning_data --dry-run  # Preview
python manage.py migrate_scanning_data --backup    # Execute with backup
python manage.py migrate_scanning_data --verify    # Verify integrity
```

---

## 6. Test Phase 4 Features

### Test API Documentation

```bash
# Access Swagger UI
open http://localhost:8000/api/docs/

# Access ReDoc
open http://localhost:8000/api/redoc/

# Get OpenAPI schema
curl http://localhost:8000/api/schema/
```

### Test Rate Limiting

```bash
# Make multiple requests quickly
for i in {1..25}; do
  curl -X GET http://localhost:8000/api/scans/ \
    -H "Authorization: Bearer your-token"
done

# Should see 429 after limit exceeded
```

### Test E2E Suite

```bash
# Run E2E tests
pytest tests/test_e2e.py --e2e -v

# Run webhook tests
pytest tests/test_webhooks.py -v
```

### Test Webhook Service

```python
from core.webhook_service import webhook_service

# Send test webhook
result = webhook_service.send_webhook(
    endpoint_url="https://webhook.site/your-unique-url",
    endpoint_id="test-endpoint",
    event_type="test.event",
    payload={"message": "Hello from SecureSys"}
)

print(result)
```

---

## 7. Configure Observability Stack

### Option A: Using Docker Compose

```yaml
# Add to docker-compose.yml

services:
  # ... existing services
  
  jaeger:
    image: jaegertracing/all-in-one:latest
    ports:
      - "16686:16686"  # Jaeger UI
      - "4317:4317"    # OTLP gRPC
      - "4318:4318"    # OTLP HTTP
    environment:
      - COLLECTOR_OTLP_ENABLED=true
  
  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
  
  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - ./docs/grafana:/etc/grafana/provisioning/dashboards
```

### Start Observability Stack

```bash
docker-compose up -d jaeger prometheus grafana
```

### Access UIs

- **Jaeger (Tracing):** http://localhost:16686
- **Prometheus (Metrics):** http://localhost:9090
- **Grafana (Dashboards):** http://localhost:3000

---

## 8. Configure Keycloak (Optional)

### Using Docker

```bash
# Start Keycloak
docker run -d \
  -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  --name keycloak \
  quay.io/keycloak/keycloak:latest start-dev

# Import realm configuration
docker cp keycloak/realm-export.json keycloak:/tmp/
docker exec keycloak /opt/keycloak/bin/kc.sh import \
  --file /tmp/realm-export.json
```

### Access Keycloak

- **URL:** http://localhost:8080
- **Username:** admin
- **Password:** admin

### Configure Client

1. Go to "Clients" → Create new client
2. Client ID: `securesys-auditor`
3. Client Protocol: `openid-connect`
4. Access Type: `confidential`
5. Valid Redirect URIs: `http://localhost:8000/*`
6. Save and get client secret from "Credentials" tab

---

## 9. Run Tests

```bash
# Unit tests
pytest tests/ -v

# E2E tests
pytest tests/test_e2e.py --e2e -v

# Webhook tests
pytest tests/test_webhooks.py -v

# With coverage
pytest tests/ --cov=src --cov-report=html
open htmlcov/index.html
```

---

## 10. Verify Production Readiness

```bash
# 1. Check health endpoints
curl http://localhost:8000/health/
curl http://localhost:8000/health/database/
curl http://localhost:8000/health/celery/

# 2. Verify observability
curl http://localhost:8000/metrics  # Prometheus metrics

# 3. Check API docs
curl http://localhost:8000/api/schema/ | jq

# 4. Test rate limiting
# Should return 429 after limit
for i in {1..150}; do 
  curl -w "%{http_code}\n" http://localhost:8000/api/scans/ 
done
```

---

## 11. Configure CI/CD

The CI pipeline is already updated. Verify by pushing code:

```bash
git add .
git commit -m "feat: implement Phase 4 - reliability and observability"
git push origin main
```

CI will run:
1. Lint checks
2. Unit tests
3. E2E tests
4. Migration validation
5. Docker build

---

## Troubleshooting

### Issue: OIDC login fails

**Solution:** Verify Keycloak endpoints and client credentials

```bash
# Test Keycloak endpoints
curl https://keycloak.example.com/auth/realms/master/.well-known/openid-configuration
```

### Issue: Rate limiting too strict

**Solution:** Adjust limits in settings or environment variables

```python
RATE_LIMITS = {
    'authenticated': 200,  # Increase from 100
    'anonymous': 50,       # Increase from 20
}
```

### Issue: Webhooks not delivering

**Solution:** Check circuit breaker status and endpoint configuration

```python
from core.webhook_service import webhook_service

cb = webhook_service.get_circuit_breaker("your-endpoint-id")
print(f"Circuit state: {cb.get_state()}")
```

### Issue: Observability not working

**Solution:** Verify OTEL configuration and services

```bash
# Check if Jaeger is running
docker ps | grep jaeger

# Verify environment variables
echo $OTEL_ENABLED
echo $OTEL_EXPORTER_OTLP_ENDPOINT

# Test OTLP endpoint
curl http://localhost:4318/v1/traces
```

---

## Next Steps

1. **Deploy to Staging** - Test all features in staging environment
2. **Load Testing** - Use tools like Locust or k6
3. **Security Audit** - Review configurations and permissions
4. **Documentation** - Update team documentation
5. **Training** - Train team on new features

---

## Support & Resources

- **Phase 4 Documentation:** [phase4_completion_summary.md](phase4_completion_summary.md)
- **Migration Guide:** [DATABASE_MIGRATION.md](../DATABASE_MIGRATION.md)
- **Grafana Dashboards:** [docs/grafana/](../grafana/)
- **API Documentation:** http://localhost:8000/api/docs/

---

**Setup Version:** 1.0  
**Last Updated:** December 23, 2025
