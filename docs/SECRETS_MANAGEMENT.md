# Secrets Management Policy

This document outlines the security policies and procedures for managing secrets in the SecureSys Auditor project.

## Overview

**CRITICAL**: Never commit real secrets, passwords, API keys, or sensitive credentials to version control.

## Secret Types

The following types of secrets are used in this project:

| Secret | Purpose | Where Used |
|--------|---------|------------|
| `DJANGO_SECRET_KEY` | Django cryptographic signing | Backend server |
| `DB_PASSWORD` | PostgreSQL database access | Backend, Workers |
| `KEYCLOAK_ADMIN_PASSWORD` | Keycloak admin access | Authentication setup |
| `KC_DB_PASSWORD` | Keycloak database access | Keycloak service |
| `WEBHOOK_SECRET` | HMAC signing for webhooks | Webhook integrations |

## Configuration Files

### `.env` (Local Development)
- **NEVER committed to git** (listed in `.gitignore`)
- Contains actual secrets for local development
- Each developer maintains their own copy

### `.env.example` (Template)
- **Safe to commit** - contains only placeholders
- Copy to `.env` and fill in actual values

### Production Secrets
- Use Kubernetes Secrets or external secret managers (Vault, AWS Secrets Manager)
- See `k8s/base/external-secret.yaml` for Kubernetes integration

## Generating Secrets

### Django Secret Key
```bash
python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
```

### Strong Passwords
```bash
openssl rand -base64 32
```

### HMAC Secrets
```bash
openssl rand -hex 32
```

## Pre-commit Hooks

We use pre-commit hooks to prevent accidental secret commits:

```bash
# Install pre-commit
pip install pre-commit

# Install hooks
pre-commit install

# Run manually on all files
pre-commit run --all-files
```

The hooks include:
- **detect-secrets**: Scans for high-entropy strings and known patterns
- **gitleaks**: Git-aware secret scanning

## CI/CD Secret Scanning

### On Every PR
1. **Gitleaks** scans the entire commit history
2. **detect-secrets** baseline comparison
3. Build fails if secrets are detected

### Scheduled Scans
Daily scans run at 2 AM UTC checking for:
- New vulnerabilities in dependencies
- Leaked secrets in codebase
- Outdated security configurations

## Incident Response

### If a Secret is Committed

1. **Immediately rotate the secret** - assume it's compromised
2. Remove from git history:
   ```bash
   # Use BFG Repo Cleaner or git filter-branch
   bfg --replace-text secrets.txt
   git push --force
   ```
3. Update `.secrets.baseline` if needed
4. Notify the team via security channel

### Secret Rotation Schedule

| Secret | Rotation Frequency |
|--------|-------------------|
| `DJANGO_SECRET_KEY` | On compromise or annually |
| `DB_PASSWORD` | On compromise or quarterly |
| `KEYCLOAK_ADMIN_PASSWORD` | On compromise or monthly |
| API Keys | On compromise or as needed |

## Development Best Practices

1. **Never hardcode secrets** in source code
2. **Use environment variables** for configuration
3. **Review diffs carefully** before committing
4. **Use secret managers** in production (Vault, AWS Secrets Manager, etc.)
5. **Audit access** to production secrets regularly

## Kubernetes Secrets

For production Kubernetes deployments:

```yaml
# Using External Secrets Operator
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: securesys-secrets
spec:
  secretStoreRef:
    name: vault-backend
    kind: ClusterSecretStore
  target:
    name: securesys-secrets
  data:
    - secretKey: DJANGO_SECRET_KEY
      remoteRef:
        key: securesys/django
        property: secret_key
```

## Contact

For security concerns, contact the security team at security@example.com.

## References

- [Django Security](https://docs.djangoproject.com/en/stable/topics/security/)
- [OWASP Secrets Management](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [detect-secrets](https://github.com/Yelp/detect-secrets)
- [gitleaks](https://github.com/gitleaks/gitleaks)
