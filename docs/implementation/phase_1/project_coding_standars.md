
# ✅ Coding Standards & Style Guide

## 1.1 Naming Conventions

| Element                | Convention           | Example                  |
| ---------------------- | -------------------- | ------------------------ |
| Variables              | `snake_case`         | `risk_score`             |
| Constants              | `UPPER_SNAKE_CASE`   | `MAX_RETRIES`            |
| Functions / Methods    | `snake_case`         | `calculate_risk_score()` |
| Classes                | `PascalCase`         | `SecurityAgent`          |
| Modules / Files        | `snake_case.py`      | `scan_processor.py`      |
| Packages / Folders     | `snake_case/`        | `utils/`                 |
| React Components       | `PascalCase.jsx/tsx` | `DashboardCard.tsx`      |
| CSS / Tailwind classes | `kebab-case`         | `risk-score-high`        |

---

## 1.2 Folder Structure (Django + React)

```
secure_sys_auditor/
├── backend/
│   ├── manage.py
│   ├── core/                 # Django apps
│   │   ├── models.py
│   │   ├── serializers.py
│   │   ├── views.py
│   │   ├── urls.py
│   │   └── tasks.py          # Celery tasks
│   ├── security/             # Auth, RBAC, tokens
│   └── utils/                # Logging, helpers
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── services/         # API calls
│   │   ├── hooks/
│   │   └── styles/
├── agent/                    # Rust / Go CLI agent
├── docs/
├── tests/
├── docker/
├── scripts/
└── README.md
```

---

## 1.3 Linting & Formatting Rules

* **Python:**

  * `black` (formatter)
  * `ruff` / `flake8` (lint)
  * `bandit` (security lint)
* **JavaScript / TypeScript:**

  * `eslint` + `prettier`
  * Strict type-checking
* **Commit Hooks:**

  * Pre-commit hooks for linting + formatting (`pre-commit` library)

---

## 1.4 Commit Message Format (Conventional Commits)

```
<type>[optional scope]: <short description>
[optional body]
[optional footer(s)]
```

| Type     | Description                |
| -------- | -------------------------- |
| feat     | New feature                |
| fix      | Bug fix                    |
| refactor | Code refactor              |
| docs     | Documentation              |
| style    | Formatting, no code change |
| test     | Tests only                 |
| chore    | Maintenance / build tools  |

**Example:**

```
feat(scan): add risk score calculation for new rules
```

---

## 1.5 Logging System

**Requirements:**

* Structured, easy to read, not overwhelming
* JSON logs for backend
* Severity levels: `DEBUG | INFO | WARNING | ERROR | CRITICAL`
* Include: timestamp, module, action, user_id / system_id
* Rotating logs (file or external aggregator: ELK / Grafana)
* Minimal console noise for production

**Python Example:**

```python
import logging
import sys
import json_log_formatter

formatter = json_log_formatter.JSONFormatter()
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(formatter)

logger = logging.getLogger("secure_sys")
logger.setLevel(logging.INFO)
logger.addHandler(handler)

logger.info("scan_completed", extra={"scan_id": scan.id, "system_id": system.id})
```

---
