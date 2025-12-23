# SecureSys Auditor - Security Audit Checklist

This document provides a comprehensive security audit checklist for production deployment. All items must be verified before going live.

## Pre-Production Security Requirements

### Critical (Must Pass Before Production)

#### Authentication & Authorization
- [ ] **HTTPS enforced** on all endpoints (no HTTP fallback)
- [ ] **TLS 1.2+ only** - disable SSLv3, TLS 1.0, TLS 1.1
- [ ] **Strong TLS cipher suites** - prefer ECDHE, disable RC4, 3DES
- [ ] **HSTS enabled** with `max-age=31536000; includeSubDomains; preload`
- [ ] **JWT tokens** have appropriate expiration (1 hour access, 7 day refresh)
- [ ] **API keys** are properly hashed before storage
- [ ] **OIDC/Keycloak** integration tested with token refresh
- [ ] **Session management** - secure cookies, httponly, samesite=strict

#### Configuration Security
- [ ] **DEBUG=False** in production
- [ ] **SECRET_KEY** is unique, random, and not in source control
- [ ] **ALLOWED_HOSTS** is properly configured (no wildcards)
- [ ] **CORS origins** are explicitly whitelisted
- [ ] **Database credentials** are not in source control
- [ ] **No default passwords** in any configuration

#### Input Validation
- [ ] **SQL injection** protection verified
- [ ] **XSS protection** enabled
- [ ] **CSRF protection** enabled on all state-changing endpoints
- [ ] **File upload validation** - type, size, content inspection
- [ ] **Rate limiting** configured on all endpoints
- [ ] **Request size limits** enforced

#### Secrets Management
- [ ] All secrets stored in **environment variables** or secrets manager
- [ ] **Webhook secrets** are unique per endpoint
- [ ] **Database passwords** meet complexity requirements (16+ chars)
- [ ] **API keys** are rotatable without downtime

---

### High Priority (Complete Within First Sprint)

#### Network Security
- [ ] **Firewall rules** restrict database access to app servers only
- [ ] **Redis** requires authentication
- [ ] **Internal services** not exposed to internet
- [ ] **Container networks** are properly isolated
- [ ] **Egress filtering** - limit outbound connections

#### Application Security
- [ ] **Bandit scan** passes with no high/critical findings
- [ ] **Dependency scan** (Safety, Snyk) shows no critical vulnerabilities
- [ ] **OWASP ZAP** or similar dynamic scan completed
- [ ] **Security headers** properly configured:
  - [x] X-Content-Type-Options: nosniff
  - [x] X-Frame-Options: DENY
  - [x] Content-Security-Policy configured
  - [x] Referrer-Policy: strict-origin-when-cross-origin

#### Logging & Monitoring
- [ ] **Security events** are logged (auth failures, permission denials)
- [ ] **Logs do not contain** sensitive data (passwords, tokens, PII)
- [ ] **Log retention** meets compliance requirements
- [ ] **Alert rules** configured for security anomalies

---

### Medium Priority (Complete Within 30 Days)

#### Penetration Testing
- [ ] External penetration test scheduled
- [ ] Internal penetration test scheduled
- [ ] Bug bounty program considered
- [ ] Remediation plan for findings documented

#### Compliance
- [ ] Data classification completed
- [ ] PII handling documented
- [ ] Data retention policies implemented
- [ ] Right to deletion (GDPR) supported
- [ ] Audit trail maintained

#### Backup & Recovery
- [ ] Backup encryption at rest
- [ ] Backup access controls
- [ ] Recovery tested and documented
- [ ] Backup integrity verification

---

## Security Configuration Checklist

### Django Settings Verification

```python
# settings.py - Production Security Settings

# Must be True in production
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# Must be False in production
DEBUG = False

# Content Security
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
SECURE_BROWSER_XSS_FILTER = True  # Deprecated but harmless
```

### NGINX TLS Configuration

```nginx
# /etc/nginx/conf.d/ssl.conf

ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:50m;
ssl_stapling on;
ssl_stapling_verify on;

# HSTS
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

# Security Headers
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';" always;
```

---

## Vulnerability Scanning Commands

### Static Analysis (SAST)

```bash
# Run Bandit security linter
bandit -r src/ -x tests/ -ll -f json -o bandit-results.json

# Check for high/critical issues
bandit -r src/ -x tests/ -ll --severity-level high

# Run Safety dependency check
safety check -r reqs/requirements-base.txt --full-report

# Run pip-audit
pip-audit --require-hashes --desc
```

### Dynamic Analysis (DAST)

```bash
# OWASP ZAP baseline scan
docker run -t owasp/zap2docker-stable zap-baseline.py \
  -t https://api.securesys.io \
  -r zap-report.html

# Full scan (more aggressive)
docker run -t owasp/zap2docker-stable zap-full-scan.py \
  -t https://api.securesys.io \
  -r zap-full-report.html
```

### Infrastructure Scanning

```bash
# Docker image scanning with Trivy
trivy image securesys-auditor:latest

# Kubernetes manifest scanning
trivy config k8s/

# Secret scanning with gitleaks
gitleaks detect --source . --verbose
```

---

## Security Testing Scenarios

### Authentication Tests

| Test | Expected Result | Status |
|------|-----------------|--------|
| Invalid JWT token | 401 Unauthorized | ☐ |
| Expired JWT token | 401 Unauthorized | ☐ |
| Missing Authorization header | 401 Unauthorized | ☐ |
| Invalid API key | 401 Unauthorized | ☐ |
| Rate limit exceeded | 429 Too Many Requests | ☐ |
| Brute force login detection | Account locked | ☐ |

### Authorization Tests

| Test | Expected Result | Status |
|------|-----------------|--------|
| Access other user's resources | 403 Forbidden | ☐ |
| Admin-only endpoint as user | 403 Forbidden | ☐ |
| Viewer attempting write | 403 Forbidden | ☐ |
| IDOR attempt | 403/404 | ☐ |

### Input Validation Tests

| Test | Expected Result | Status |
|------|-----------------|--------|
| SQL injection in search | No SQL error, sanitized | ☐ |
| XSS in scan name | HTML escaped | ☐ |
| Oversized request body | 413 Payload Too Large | ☐ |
| Invalid JSON | 400 Bad Request | ☐ |
| Path traversal attempt | 400 Bad Request | ☐ |

---

## Incident Response Contacts

| Role | Contact | Escalation Time |
|------|---------|-----------------|
| Security Team Lead | security@securesys.io | Immediate |
| DevOps On-Call | PagerDuty | < 15 min |
| CISO | ciso@securesys.io | < 1 hour |
| Legal (data breach) | legal@securesys.io | < 4 hours |

---

## Post-Audit Actions

### Findings Template

| Finding ID | Severity | Description | Remediation | Owner | Due Date | Status |
|------------|----------|-------------|-------------|-------|----------|--------|
| SEC-001 | Critical | Example | Fix X | @dev | 2024-01-01 | ☐ Open |

### Sign-Off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Security Lead | | | |
| DevOps Lead | | | |
| Engineering Manager | | | |
| CISO | | | |

---

## Automated Security Checks

These checks are integrated into CI/CD:

```yaml
# .github/workflows/security.yml
- name: Run security scans
  run: |
    # Static analysis
    bandit -r src/ -ll
    
    # Dependency check
    safety check
    
    # Secret detection
    gitleaks detect --exit-code 1
    
    # Docker image scan
    trivy image $IMAGE_NAME --exit-code 1 --severity CRITICAL,HIGH
```
