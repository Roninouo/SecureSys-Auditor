# Secrets Rotation Guide

## Overview

This document outlines the procedures for rotating sensitive credentials in the SecureSys Auditor production environment.

## Rotation Schedule

| Secret Type | Frequency | Automated? | Impact |
|-------------|-----------|------------|--------|
| Database Credentials | 90 Days | Yes (AWS Secrets Manager) | Zero-downtime (with connection draining) |
| Django Secret Key | 180 Days | No | Requires rolling restart |
| Webhook Signing Secrets | 90 Days | No | Requires client coordination |
| JWT Signing Keys | 30 Days | Yes (Automated) | Zero-downtime |

## Procedures

### 1. Database Credentials

If using AWS RDS with Secrets Manager:
1. Trigger rotation in AWS Secrets Manager.
2. ExternalSecrets operator will pick up the new value within 1 hour.
3. Pods will need to be restarted to pick up the new environment variables if not using a reloader.
   ```bash
   kubectl rollout restart deployment/backend -n securesys
   kubectl rollout restart deployment/worker -n securesys
   ```

### 2. Django Secret Key

1. Generate a new key:
   ```bash
   python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
   ```
2. Update the secret in your secret store (Vault/AWS Secrets Manager).
3. Wait for ExternalSecret to sync.
4. Perform a rolling restart of the backend.
   *Note: This will invalidate existing sessions unless using a persistent session store (Redis/DB).*

### 3. Webhook Signing Secrets

1. Generate a new secret.
2. Update the `WebhookEndpoint` configuration in the admin panel or via API.
   *Note: This supports multiple active secrets during rotation if implemented in the application logic.*

### 4. JWT Signing Keys

Managed automatically by the application.
- Keys are rotated every 30 days.
- Old keys are kept for verification for the duration of `REFRESH_TOKEN_LIFETIME`.

## Emergency Rotation

In case of compromise:
1. Immediately revoke the compromised credential.
2. Generate new credentials.
3. Force sync ExternalSecrets:
   ```bash
   kubectl annotate externalsecret securesys-secrets -n securesys force-sync=$(date +%s) --overwrite
   ```
4. Force restart all pods:
   ```bash
   kubectl rollout restart deployment -n securesys
   ```
