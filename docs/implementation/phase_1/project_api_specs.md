# ✅ API Specification (REST – Django REST Framework)

**API Style:** REST
**Format:** JSON
**Auth:** JWT (OAuth2/OIDC-ready)
**Base URL:** `/api/v1/`

---

## 1. Authentication & Authorization

### 1.1 Login

**POST** `/auth/login`

```json
{
  "email": "user@company.com",
  "password": "********"
}
```

**Response**

```json
{
  "access_token": "jwt_token",
  "refresh_token": "jwt_refresh",
  "expires_in": 3600,
  "role": "auditor"
}
```

---

### 1.2 Refresh Token

**POST** `/auth/refresh`

```json
{
  "refresh_token": "jwt_refresh"
}
```

---

### Roles

* **Viewer:** Read-only
* **Auditor:** Run scans, view findings
* **Admin:** User & system management

---

## 2. Systems

### 2.1 Register System

**POST** `/systems`

```json
{
  "hostname": "srv-prod-01",
  "os": "Ubuntu 22.04",
  "environment": "production"
}
```

**Response**

```json
{
  "id": "uuid",
  "created_at": "2025-01-01T10:00:00Z"
}
```

---

### 2.2 List Systems

**GET** `/systems`

**Response**

```json
[
  {
    "id": "uuid",
    "hostname": "srv-prod-01",
    "os": "Ubuntu",
    "last_seen": "2025-01-02T14:30:00Z",
    "risk_score": 72
  }
]
```

---

## 3. Scans

### 3.1 Submit Scan (Agent)

**POST** `/scans`

Headers:

```
Authorization: Bearer <agent_token>
```

```json
{
  "system_id": "uuid",
  "scan_payload": {
    "users": [...],
    "packages": [...],
    "network": [...]
  }
}
```

**Response**

```json
{
  "scan_id": "uuid",
  "status": "processing"
}
```

---

### 3.2 Scan Status

**GET** `/scans/{scan_id}`

```json
{
  "status": "completed",
  "risk_score": 81,
  "maturity_level": "managed"
}
```

---

## 4. Findings

### 4.1 List Findings by Scan

**GET** `/scans/{scan_id}/findings`

```json
[
  {
    "id": "uuid",
    "category": "Access Control",
    "severity": "high",
    "description": "Root login enabled via SSH"
  }
]
```

---

### 4.2 Finding Detail

**GET** `/findings/{id}`

```json
{
  "severity": "high",
  "evidence": {
    "config_file": "/etc/ssh/sshd_config",
    "value": "PermitRootLogin yes"
  }
}
```

---

## 5. Recommendations

### 5.1 Recommendations by Finding

**GET** `/findings/{id}/recommendations`

```json
{
  "priority": "high",
  "effort": "low",
  "steps": [
    "Edit sshd_config",
    "Set PermitRootLogin no",
    "Restart SSH service"
  ]
}
```

---

## 6. Reports

### 6.1 Generate Report

**POST** `/reports`

```json
{
  "scan_id": "uuid",
  "format": "pdf",
  "type": "executive"
}
```

**Response**

```json
{
  "report_url": "/media/reports/report_uuid.pdf"
}
```

---

## 7. Audit Logs (Admin)

### 7.1 List Logs

**GET** `/audit-logs`

```json
[
  {
    "user": "admin@company.com",
    "action": "GENERATE_REPORT",
    "timestamp": "2025-01-02T18:00:00Z"
  }
]
```

---

## 8. API Design Best Practices Applied

✅ Versioning
✅ Role-based permissions
✅ Idempotent writes
✅ Async processing
✅ Clear resource ownership
✅ Secure defaults

---
