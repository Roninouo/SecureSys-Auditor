# Phase 4 Architecture Diagram

## System Architecture with Phase 4 Enhancements

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              EXTERNAL SYSTEMS                                    │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐                   │
│  │  Keycloak    │     │  SIEM        │     │  Ticketing   │                   │
│  │  (SSO/OIDC)  │     │  (Webhooks)  │     │  (Webhooks)  │                   │
│  └──────┬───────┘     └──────▲───────┘     └──────▲───────┘                   │
│         │                     │                     │                            │
└─────────┼─────────────────────┼─────────────────────┼────────────────────────────┘
          │                     │                     │
          │ OIDC Auth           │ Webhook Delivery    │ Webhook Delivery
          │                     │ (Circuit Breaker)   │ (Circuit Breaker)
          │                     │                     │
┌─────────▼─────────────────────┴─────────────────────┴────────────────────────────┐
│                         API GATEWAY / LOAD BALANCER                              │
│                         (Rate Limiting, TLS Termination)                         │
└─────────┬────────────────────────────────────────────────────────────────────────┘
          │
          │ HTTP/REST
          │
┌─────────▼─────────────────────────────────────────────────────────────────────┐
│                              DJANGO APPLICATION                                │
├───────────────────────────────────────────────────────────────────────────────┤
│                                                                                │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                         MIDDLEWARE STACK                             │    │
│  ├─────────────────────────────────────────────────────────────────────┤    │
│  │  1. SecurityMiddleware                                               │    │
│  │  2. CORS Middleware                                                  │    │
│  │  3. CSRF Middleware                                                  │    │
│  │  4. Authentication (OIDC + ModelBackend)  ← PHASE 4                │    │
│  │  5. ObservabilityMiddleware (OpenTelemetry)                         │    │
│  │  6. RateLimitMiddleware (Token Bucket)    ← PHASE 4                │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                                │
│  ┌──────────────────────┐  ┌──────────────────────┐                          │
│  │   API ENDPOINTS      │  │   API DOCUMENTATION  │                          │
│  ├──────────────────────┤  ├──────────────────────┤                          │
│  │ • /api/scans/        │  │ • /api/docs/        │ ← PHASE 4                │
│  │ • /api/systems/      │  │ • /api/redoc/       │ ← PHASE 4                │
│  │ • /api/findings/     │  │ • /api/schema/      │ ← PHASE 4                │
│  │ • /api/webhooks/     │  └──────────────────────┘                          │
│  │ • /health/           │                                                     │
│  └──────────────────────┘                                                     │
│                                                                                │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                      CORE SERVICES (PHASE 4)                         │    │
│  ├─────────────────────────────────────────────────────────────────────┤    │
│  │  • EnhancedWebhookService                                            │    │
│  │    - Circuit Breaker Pattern                                         │    │
│  │    - Exponential Backoff Retries                                     │    │
│  │    - Rate Limiting per Endpoint                                      │    │
│  │    - Delivery Tracking & Auditing                                    │    │
│  │                                                                       │    │
│  │  • KeycloakOIDCBackend                                               │    │
│  │    - User Authentication & Provisioning                              │    │
│  │    - Role Mapping (Keycloak → App)                                   │    │
│  │    - Token Validation                                                │    │
│  │                                                                       │    │
│  │  • RateLimitMiddleware                                               │    │
│  │    - Per-User Rate Limiting                                          │    │
│  │    - Per-IP Rate Limiting                                            │    │
│  │    - Token Bucket Algorithm                                          │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                                │
└────────┬───────────────────┬────────────────────┬────────────────────────────┘
         │                   │                    │
         │                   │                    │
         ▼                   ▼                    ▼
┌────────────────┐  ┌────────────────┐  ┌────────────────────┐
│   PostgreSQL   │  │     Redis      │  │   Celery Workers   │
│   (Database)   │  │   (Cache &     │  │   (Background      │
│                │  │    Queue)      │  │    Processing)     │
├────────────────┤  ├────────────────┤  ├────────────────────┤
│ • users        │  │ • Rate limit   │  │ • process_scan     │
│ • systems      │  │   counters     │  │ • send_webhook     │
│ • scans        │  │ • Circuit      │  │ • generate_report  │
│ • findings     │  │   breaker      │  │ • cleanup_old      │
│ • webhooks     │  │   state        │  │   _scans           │
│ • audit_logs   │  │ • Session      │  └────────────────────┘
│ • deliveries   │  │   cache        │
│   ↑ PHASE 4    │  └────────────────┘
└────────────────┘
         │
         │
         ▼
┌────────────────────────────────────────────────────────────────────┐
│                    OBSERVABILITY STACK (PHASE 4)                   │
├────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────────┐   ┌──────────────────┐   ┌───────────────┐ │
│  │  OpenTelemetry   │   │   Prometheus     │   │    Grafana    │ │
│  │   (Tracing &     │──▶│   (Metrics       │──▶│  (Dashboards) │ │
│  │    Metrics)      │   │    Storage)      │   │               │ │
│  └──────────────────┘   └──────────────────┘   └───────────────┘ │
│           │                                                         │
│           ▼                                                         │
│  ┌──────────────────┐                                              │
│  │     Jaeger       │                                              │
│  │  (Trace Viewer)  │                                              │
│  └──────────────────┘                                              │
│                                                                     │
│  Key Metrics:                                                      │
│  • HTTP request duration & count                                   │
│  • Scan processing duration                                        │
│  • Webhook delivery success rate                                   │
│  • Circuit breaker state                                           │
│  • Rate limit hits                                                 │
│  • Celery task duration                                            │
│  • Database query performance                                      │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘


┌─────────────────────────────────────────────────────────────────────┐
│                         CLIENT LAYER                                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐     │
│  │   Frontend   │    │    Agent     │    │   API Client     │     │
│  │   (React)    │    │   (Python)   │    │   (Third-party)  │     │
│  └──────────────┘    └──────────────┘    └──────────────────┘     │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Phase 4 Data Flow Examples

### 1. Scan Submission with Observability

```
Agent
  │
  │ 1. POST /api/scans/submit/
  │    (HMAC signed, rate limited)
  ▼
API Gateway
  │
  │ 2. Check rate limit (Token Bucket)
  │    Log: X-RateLimit-Remaining
  ▼
RateLimitMiddleware
  │
  │ 3. Authenticate (OIDC or Token)
  ▼
Django View
  │
  │ 4. Start OpenTelemetry span
  │    Span: "scan_submission"
  ▼
Database (PostgreSQL)
  │
  │ 5. Create Scan record
  │    Status: PENDING
  ▼
Celery Queue (Redis)
  │
  │ 6. Queue process_scan task
  │    Priority: high
  ▼
Return 202 Accepted
  │
  │ 7. Export trace to Jaeger
  │    Export metrics to Prometheus
  ▼
Client receives scan_id
```

### 2. Webhook Delivery with Circuit Breaker

```
Scan Completed
  │
  │ 1. Trigger webhook event
  ▼
EnhancedWebhookService
  │
  │ 2. Check circuit breaker
  │    State: CLOSED ✓
  ▼
  │ 3. Check rate limit
  │    Endpoint: 45/100 requests ✓
  ▼
  │ 4. Sign payload (HMAC-SHA256)
  │    Header: X-SecureSys-Signature
  ▼
  │ 5. Attempt delivery
  │    Timeout: 30s
  ▼
External System
  │
  │ 6. Response received
  ├─── Success (200) ────────┐
  │                           │
  │ 7. Record success        │
  │    Circuit: stays CLOSED  │
  │    Delivery: SUCCEEDED    │
  │                           │
  └─── Failure (500) ────────┤
                              │
      8. Increment failure    │
         count                │
                              │
      9. Retry with backoff   │
         (2^attempt seconds)  │
                              │
      10. If threshold (5)    │
          → OPEN circuit      │
                              │
      11. Record delivery     │
          attempt in DB       │
                              │
  ▼
WebhookDelivery record created
```

### 3. OIDC Authentication Flow

```
User clicks "Login with SSO"
  │
  │ 1. Redirect to Keycloak
  │    /auth/realms/master/protocol/openid-connect/auth
  ▼
Keycloak
  │
  │ 2. User authenticates
  │    (Username/Password, MFA, etc.)
  ▼
  │ 3. Authorization code returned
  │    callback: /oidc/callback/
  ▼
KeycloakOIDCBackend
  │
  │ 4. Exchange code for token
  │    POST /protocol/openid-connect/token
  ▼
  │ 5. Validate ID token
  │    Verify signature (JWK)
  ▼
  │ 6. Extract claims
  │    email, given_name, family_name, roles
  ▼
  │ 7. Get or create user
  │    User.objects.get_or_create(email=...)
  ▼
  │ 8. Map roles
  │    securesys-admin → role='admin', is_staff=True
  │    securesys-auditor → role='auditor'
  │    securesys-viewer → role='viewer'
  ▼
  │ 9. Create session
  │    Django session cookie
  ▼
User logged in
```

### 4. Rate Limiting Flow

```
HTTP Request
  │
  │ 1. Extract identifier
  │    User: user_id
  │    Anon: IP address
  ▼
RateLimitMiddleware
  │
  │ 2. Get rate limit key
  │    ratelimit:user:12345
  ▼
Redis Cache
  │
  │ 3. Get token bucket state
  │    {tokens: 8.5, last_update: 1234567890}
  ▼
  │ 4. Calculate tokens to add
  │    time_passed * (rate/60)
  │    = 5s * (100/60) = 8.33 tokens
  ▼
  │ 5. Update bucket
  │    tokens = min(burst, 8.5 + 8.33) = 16.83
  ▼
  │ 6. Check if token available
  ├─── tokens >= 1.0 ────────┐
  │                           │
  │ 7. Consume token         │
  │    tokens -= 1 = 15.83   │
  │    → Allow request       │
  │                           │
  └─── tokens < 1.0 ─────────┤
                              │
      8. Calculate retry_after│
         seconds_needed / rate│
         → Return 429         │
         X-RateLimit-Retry:   │
         After: 2s            │
                              │
  ▼
Request processed or rejected
```

## Key Phase 4 Components

### 1. Circuit Breaker States

```
        Success
     ┌──────────┐
     │          │
     ▼          │
  CLOSED ◄──────┤
     │          │
     │ 5 failures
     │          │
     ▼          │
   OPEN ────────┤
     │          │
     │ timeout  │
     │          │
     ▼          │
  HALF_OPEN    │
     │          │
     │ 2 successes
     └──────────┘

Circuit returns to CLOSED on success
Circuit returns to OPEN on failure in HALF_OPEN
```

### 2. Database Schema Changes

```sql
-- New WebhookDelivery table
CREATE TABLE webhook_deliveries (
    id UUID PRIMARY KEY,
    endpoint_id UUID REFERENCES webhook_endpoints(id),
    event_type VARCHAR(100),
    payload JSONB,
    attempt_number INTEGER,
    status VARCHAR(20),  -- success, failed, pending
    http_status_code INTEGER,
    error_message TEXT,
    response_time_ms INTEGER,
    created_at TIMESTAMP,
    delivered_at TIMESTAMP
);

CREATE INDEX idx_webhook_deliveries_endpoint ON webhook_deliveries(endpoint_id, created_at);
CREATE INDEX idx_webhook_deliveries_event ON webhook_deliveries(event_type);
CREATE INDEX idx_webhook_deliveries_status ON webhook_deliveries(status);
```

### 3. Redis Keys

```
# Rate Limiting
ratelimit:user:{user_id}         → (tokens, last_update)
ratelimit:ip:{ip_address}        → (tokens, last_update)
endpoint_limit:{func}:user:{id}  → request_count

# Circuit Breaker
circuit:state:{endpoint_id}      → CLOSED|OPEN|HALF_OPEN
circuit:failures:{endpoint_id}   → failure_count
circuit:successes:{endpoint_id}  → success_count
circuit:opened_at:{endpoint_id}  → timestamp
```

## Performance Characteristics

### Rate Limiting
- **Overhead:** ~1-2ms per request
- **Memory:** ~100 bytes per active user
- **Accuracy:** 99%+ (token bucket)

### Circuit Breaker
- **Detection:** 5 consecutive failures
- **Recovery:** 60 second timeout
- **Overhead:** ~0.5ms per webhook

### Observability
- **Trace Overhead:** ~2-3ms per request
- **Metric Export:** Every 60 seconds
- **Storage:** ~1KB per trace span

---

This architecture provides:
- ✅ High Availability
- ✅ Horizontal Scalability
- ✅ Observability
- ✅ Security
- ✅ Resilience
