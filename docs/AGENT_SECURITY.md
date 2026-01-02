# Agent Security Documentation

This document describes the security features implemented in the SecureSys Agent.

## Overview

The SecureSys Agent collects security-relevant data from systems and submits it to the backend API. To ensure the integrity and confidentiality of this process, several security measures are implemented.

## TLS Enforcement

### Requirement
All API communication **must** use HTTPS (TLS) in production environments.

### Implementation
```python
# The agent validates the API URL scheme
client = SecureSysAPIClient(
    api_url='https://api.example.com',  # ✓ Valid
    api_key='your-api-key'
)

# HTTP URLs are rejected by default
client = SecureSysAPIClient(
    api_url='http://api.example.com',   # ✗ Raises ValueError
    api_key='your-api-key'
)
```

### Development Exception
For local development, HTTP can be enabled for localhost only:

```python
client = SecureSysAPIClient(
    api_url='http://localhost:8000',
    api_key='your-api-key',
    allow_insecure_localhost=True  # Only for development!
)
```

**Warning**: Never use `allow_insecure_localhost=True` in production.

## HMAC-SHA256 Payload Signing

### Purpose
Payload signing ensures:
1. **Integrity**: Scan data cannot be tampered with in transit
2. **Authentication**: Only agents with valid API keys can submit scans
3. **Non-repudiation**: Submissions can be verified against the signing key

### Signature Generation

The signature is computed as:
```
signature = HMAC-SHA256(api_key, timestamp + "." + canonical_payload)
```

Where:
- `api_key`: The agent's API key (shared secret)
- `timestamp`: Unix timestamp of the request
- `canonical_payload`: JSON-serialized payload with sorted keys

### Headers

Each signed request includes:

| Header | Description |
|--------|-------------|
| `X-Signature` | Hex-encoded HMAC-SHA256 signature |
| `X-Timestamp` | Unix timestamp when request was created |

### Example

```python
# Request payload
payload = {
    'system_id': 'abc123',
    'scan_payload': {'hostname': 'server-01', ...}
}

# Generated headers
headers = {
    'X-Signature': 'a1b2c3d4e5f6...',  # 64-char hex string
    'X-Timestamp': '1703318400'
}
```

### Replay Attack Prevention

The timestamp header prevents replay attacks:
- Backend rejects requests older than 5 minutes
- Each timestamp + payload combination produces a unique signature

### Backend Validation

The backend should validate signatures as follows:

```python
import hmac
import hashlib
import json
import time

def validate_signature(request):
    # Extract headers
    signature = request.headers.get('X-Signature')
    timestamp = request.headers.get('X-Timestamp')

    if not signature or not timestamp:
        return False, 'Missing signature headers'

    # Check timestamp freshness (5-minute window)
    request_time = int(timestamp)
    current_time = int(time.time())
    if abs(current_time - request_time) > 300:
        return False, 'Request timestamp expired'

    # Reconstruct signature
    payload = request.json
    canonical = json.dumps(payload, sort_keys=True, separators=(',', ':'))
    message = f"{timestamp}.{canonical}"

    expected = hmac.new(
        key=api_key.encode('utf-8'),
        msg=message.encode('utf-8'),
        digestmod=hashlib.sha256
    ).hexdigest()

    # Constant-time comparison
    if not hmac.compare_digest(signature, expected):
        return False, 'Invalid signature'

    return True, None
```

## Minimal Telemetry Mode

### Purpose
Minimal telemetry mode filters sensitive data from scan payloads to protect privacy while still enabling security analysis.

### Configuration

```python
# In agent config
config = Config(
    api_url='https://api.example.com',
    api_key='your-key',
    minimal_telemetry=True  # Default: True
)
```

Or via environment variable:
```bash
export SECURESYS_MINIMAL_TELEMETRY=true
```

### Filtered Fields

When enabled, these fields are automatically removed from scan data:

| Field | Description |
|-------|-------------|
| `ip_address` | System IP addresses |
| `mac_address` | Network interface MAC addresses |
| `user_home_paths` | User home directory paths |
| `environment_variables` | System environment variables |
| `command_history` | Shell command history |
| `ssh_keys` | SSH key contents |
| `private_keys` | Any private key material |
| `passwords` | Password fields |
| `tokens` | API tokens or secrets |
| `credentials` | Authentication credentials |

### Custom Sensitive Fields

You can customize the filtered fields:

```python
config = Config(
    minimal_telemetry=True,
    sensitive_fields=[
        'ip_address',
        'custom_secret_field',
        'internal_data'
    ]
)
```

## Credential Rotation

### API Key Rotation

**Recommended frequency**: Every 90 days

**Process**:
1. Generate new API key in the SecureSys dashboard
2. Update agent configuration with new key
3. Verify agent can authenticate with new key
4. Revoke old API key in dashboard

```bash
# Update agent config
securesys-agent config set api_key NEW_API_KEY

# Verify connectivity
securesys-agent status
```

### Best Practices

1. **Use strong API keys**: Minimum 32 characters, random
2. **Store securely**: Use environment variables or secure vaults
3. **Rotate regularly**: Establish a rotation schedule
4. **Monitor usage**: Review audit logs for unauthorized access
5. **Revoke immediately**: If key compromise is suspected

## Security Checklist

Before deploying agents to production:

- [ ] API URL uses HTTPS (not HTTP)
- [ ] API key is securely stored (not in code)
- [ ] `allow_insecure_localhost` is `False`
- [ ] `minimal_telemetry` is enabled unless full data is required
- [ ] Credential rotation schedule is established
- [ ] Agent logs do not contain sensitive data
- [ ] Network allows outbound HTTPS to API endpoint
