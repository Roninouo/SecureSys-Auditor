# ✅ Architecture Diagram (Architecture Document)

## 1. High-Level Architecture Overview

**SecureSys Auditor** follows a **modular, secure, and scalable architecture** based on separation of concerns, least privilege, and auditability.

### Architecture Style

* **Agent-based data collection**
* **API-driven backend**
* **Asynchronous processing**
* **Web-based dashboard**
* **Security-by-design**

---

## 2. Logical Architecture Diagram (Textual)

```
┌────────────────────┐
│   Target System    │
│ (Windows/Linux/mac)│
└─────────┬──────────┘
          │
          │ Local scan (non-intrusive)
          ▼
┌────────────────────────┐
│ SecureSys Agent (CLI)  │
│  - Inventory           │
│  - Access checks       │
│  - Config checks       │
│  - Signed payload      │
└─────────┬──────────────┘
          │ TLS + Signed JSON
          ▼
┌─────────────────────────────┐
│ Django REST API (Backend)   │
│  - Auth & RBAC              │
│  - Scan ingestion           │
│  - Validation               │
└─────────┬───────────────────┘
          │ Async task
          ▼
┌─────────────────────────────┐
│ Celery Workers              │
│  - Risk scoring             │
│  - Maturity evaluation      │
│  - Recommendation engine    │
└─────────┬───────────────────┘
          │
          ▼
┌─────────────────────────────┐
│ PostgreSQL Database         │
│  - Systems                  │
│  - Scans                    │
│  - Findings                 │
│  - Recommendations          │
│  - Audit logs               │
└─────────┬───────────────────┘
          │
          ▼
┌─────────────────────────────┐
│ Web Dashboard (React + TS)  │
│  - System overview          │
│  - Risk & maturity          │
│  - Findings & remediation   │
└─────────┬───────────────────┘
          │
          ▼
┌─────────────────────────────┐
│ Report Engine               │
│  - PDF (Executive/Tech)     │
│  - JSON / CSV exports       │
└─────────────────────────────┘
```

---

## 3. Security Boundaries

* **Agent → API:** TLS + signed payload
* **API → Workers:** Internal network only
* **Database:** Private network, encrypted at rest
* **Frontend:** Authenticated access via OIDC
* **Secrets:** External vault (never in code)

---

## 4. Technology Rationale (Summary)

| Component | Technology         | Reason                             |
| --------- | ------------------ | ---------------------------------- |
| Agent     | Rust / Go          | Security, performance, portability |
| Backend   | Django + DRF       | Mature, enterprise-proven          |
| Async     | Celery + Redis     | Reliable background processing     |
| DB        | PostgreSQL         | Strong consistency, auditing       |
| UI        | React + TypeScript | Scalable UX                        |
| Auth      | OIDC / RBAC        | Enterprise IAM standard            |

---

# ✅ Data Model (Logical & Relational)

## 1. Core Entities

### 1.1 System

Represents a monitored machine.

| Field       | Type      | Description      |
| ----------- | --------- | ---------------- |
| id          | UUID      | Primary key      |
| hostname    | String    | System name      |
| os          | String    | Operating system |
| environment | String    | Prod / Dev       |
| created_at  | Timestamp | First seen       |
| last_seen   | Timestamp | Last scan        |

---

### 1.2 Scan

Represents a single assessment execution.

| Field          | Type        | Description         |
| -------------- | ----------- | ------------------- |
| id             | UUID        | Primary key         |
| system_id      | FK → System | Related system      |
| scan_date      | Timestamp   | Execution time      |
| status         | Enum        | Pending / Completed |
| risk_score     | Integer     | 0–100               |
| maturity_level | Enum        | Reactive–Optimized  |

---

### 1.3 Finding

Represents a detected security issue.

| Field       | Type      | Description            |
| ----------- | --------- | ---------------------- |
| id          | UUID      | Primary key            |
| scan_id     | FK → Scan | Source scan            |
| category    | String    | Access, Patch, Network |
| severity    | Enum      | Low / Medium / High    |
| description | Text      | Issue details          |
| evidence    | JSON      | Supporting data        |

---

### 1.4 Recommendation

Represents remediation guidance.

| Field      | Type         | Description         |
| ---------- | ------------ | ------------------- |
| id         | UUID         | Primary key         |
| finding_id | FK → Finding | Related issue       |
| priority   | Enum         | Low / Medium / High |
| effort     | Enum         | Low / Medium / High |
| steps      | Text         | Step-by-step fix    |

---

### 1.5 User

Authenticated platform user.

| Field      | Type      | Description              |
| ---------- | --------- | ------------------------ |
| id         | UUID      | Primary key              |
| email      | String    | Login                    |
| role       | Enum      | Viewer / Auditor / Admin |
| created_at | Timestamp | Creation date            |

---

### 1.6 AuditLog

Tracks sensitive actions.

| Field     | Type      | Description |
| --------- | --------- | ----------- |
| id        | UUID      | Primary key |
| user_id   | FK → User | Actor       |
| action    | String    | Action name |
| timestamp | Timestamp | Event time  |
| metadata  | JSON      | Context     |

---

## 2. Relationships (Summary)

* **System 1 → N Scan**
* **Scan 1 → N Finding**
* **Finding 1 → N Recommendation**
* **User 1 → N AuditLog**

---

## 3. Data Governance

* Scan data is immutable after completion
* Audit logs are append-only
* Retention policies configurable
* Soft deletes for business entities

---

## 4. Indexing Strategy (Initial)

* `system.hostname`
* `scan.scan_date`
* `finding.severity`
* `auditlog.timestamp`

---
