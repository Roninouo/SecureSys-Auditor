# SecureSys Auditor - API Client Examples

This directory contains example API clients, SDK implementations, and Postman collections for integrating with SecureSys Auditor.

## Contents

- `python/` - Full-featured Python client with retry logic and type hints
- `typescript/` - TypeScript client with complete type definitions
- `postman/` - Postman collection and environment files

## Quick Start

### Postman Collection (Recommended for Exploration)

Import the Postman collection for quick API exploration:

1. Open Postman
2. Click **Import** → **File**
3. Select `postman/SecureSys-Auditor-API.postman_collection.json`
4. Import the environment file: `postman/local.postman_environment.json`
5. Set your API key in the environment variables

The collection includes pre-configured requests for all API endpoints with example payloads.

### Python

```python
import requests

API_URL = "https://api.securesys.io"
API_KEY = "your-api-key"

headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

# Submit a scan
scan_data = {
    "hostname": "webserver-01.example.com",
    "scan_type": "vulnerability",
    "findings": [
        {
            "title": "CVE-2023-1234",
            "severity": "high",
            "description": "Description of the vulnerability",
            "recommendation": "Update to version X.Y.Z"
        }
    ]
}

response = requests.post(f"{API_URL}/api/v1/scans/", json=scan_data, headers=headers)
print(response.json())
```

### cURL

```bash
# Health check
curl -X GET "https://api.securesys.io/api/v1/health/"

# Submit a scan
curl -X POST "https://api.securesys.io/api/v1/scans/" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "hostname": "webserver-01.example.com",
    "scan_type": "vulnerability",
    "findings": []
  }'

# List scans
curl -X GET "https://api.securesys.io/api/v1/scans/?page=1&page_size=20" \
  -H "Authorization: Bearer YOUR_API_KEY"
```

## Available Clients

- [Python Client](./python/) - Full-featured Python client with async support
- [TypeScript Client](./typescript/) - Type-safe TypeScript/JavaScript client
- [Postman Collection](./postman/) - Import into Postman for interactive testing

## Authentication

SecureSys Auditor supports two authentication methods:

### 1. API Key (Recommended for Agents)

```bash
Authorization: Bearer your-api-key-here
```

### 2. OIDC/JWT (Recommended for Users)

For SSO integration with Keycloak or other OIDC providers:

```bash
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

## Rate Limits

| Endpoint | Anonymous | Authenticated |
|----------|-----------|---------------|
| General | 100/hour | 1000/hour |
| Scan Submission | N/A | 100/hour |

Rate limit headers are included in all responses:
- `X-RateLimit-Limit`
- `X-RateLimit-Remaining`
- `X-RateLimit-Reset`

## Webhook Events

Configure webhooks to receive real-time notifications:

| Event | Description |
|-------|-------------|
| `scan.created` | New scan submitted |
| `scan.completed` | Scan processing completed |
| `scan.failed` | Scan processing failed |
| `finding.critical` | Critical finding detected |
| `report.generated` | PDF report ready |

## Support

- Documentation: https://docs.securesys.io
- API Reference: https://api.securesys.io/api/docs/
- Issues: https://github.com/your-org/securesys-auditor/issues
