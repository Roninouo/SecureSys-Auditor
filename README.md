# SecureSys Auditor

**Cybersecurity Assessment Platform**

A comprehensive security assessment platform that automates the collection, analysis, and reporting of system security posture across enterprise infrastructure.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)
![Django](https://img.shields.io/badge/django-4.2%2B-green.svg)
![React](https://img.shields.io/badge/react-18.2%2B-61dafb.svg)
![CI](https://github.com/securesys/auditor/actions/workflows/ci.yml/badge.svg)
![Coverage](https://codecov.io/gh/securesys/auditor/branch/main/graph/badge.svg)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
- [API Documentation](#api-documentation)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

---

## 🎯 Overview

SecureSys Auditor is designed for IT and security teams who need to:

- **Assess** - Automatically collect security-relevant data from systems
- **Analyze** - Process collected data against security rules and benchmarks
- **Visualize** - Present risk scores and findings through an intuitive dashboard
- **Report** - Generate actionable recommendations for remediation

### Key Pipeline

```
Agent Scan → API Ingestion → Risk Analysis → Dashboard Visualization
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     SecureSys Auditor                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐       │
│  │   CLI       │     │   Django    │     │   React     │       │
│  │   Agent     │────▶│   Backend   │◀────│   Frontend  │       │
│  │  (Scanner)  │     │   (API)     │     │ (Dashboard) │       │
│  └─────────────┘     └──────┬──────┘     └─────────────┘       │
│                             │                                   │
│                      ┌──────▼──────┐                           │
│                      │   Celery    │                           │
│                      │  (Analysis) │                           │
│                      └──────┬──────┘                           │
│                             │                                   │
│         ┌───────────────────┼───────────────────┐              │
│         ▼                   ▼                   ▼              │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐       │
│  │ PostgreSQL  │     │    Redis    │     │   Redis     │       │
│  │  (Storage)  │     │   (Cache)   │     │  (Broker)   │       │
│  └─────────────┘     └─────────────┘     └─────────────┘       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## ✨ Features

### Phase 1 (Current)

- ✅ **CLI Agent** - Cross-platform system scanner (Windows, Linux, macOS)
- ✅ **REST API** - Django REST Framework backend with JWT authentication
- ✅ **Async Processing** - Celery-based analysis with Redis broker
- ✅ **Security Dashboard** - React TypeScript frontend with real-time updates
- ✅ **Risk Scoring** - Automated security maturity assessment
- ✅ **RBAC** - Role-based access control (viewer, auditor, admin)

### Coming Soon

- 🔄 Scheduled scans and automation
- 📊 Advanced reporting and exports
- 🔗 SIEM integrations
- 🛡️ CIS Benchmark support

---

## 🚀 Quick Start

### Prerequisites

- Python 3.9+
- Node.js 18+
- PostgreSQL 13+
- Redis 6+
- Docker & Docker Compose (recommended)

### One-Command Local Deploy (Docker)

```bash
# Clone and enter directory
git clone https://github.com/securesys/auditor.git
cd SecureSys-Auditor

# Copy environment file
cp .env.example .env

# Start everything (backend + worker + db + redis + frontend)
docker-compose up -d

# Wait for services to be healthy, then access:
# - Frontend Dashboard: http://localhost:3000
# - Backend API: http://localhost:8000/api/v1/
# - API Health: http://localhost:8000/api/v1/health/
# - API Docs: http://localhost:8000/api/docs/
```

### Quick End-to-End Test

After starting services, run a sample scan:

```bash
# Create a test user
docker-compose exec backend python manage.py createsuperuser

# Run the agent scanner locally (collects system info)
python run.py scan --api-url http://localhost:8000 --api-key YOUR_KEY

# Or use the test script
python run.py test
```

### Using Docker (Recommended)

```bash
# Clone repository
git clone https://github.com/securesys/auditor.git
cd SecureSys-Auditor

# Copy environment template
cp .env.example .env
# Edit .env with your configuration

# Start all services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f backend

# The API will be available at http://localhost:8000
# Health check: http://localhost:8000/api/v1/health/
```

### Docker Commands

```bash
# Start services in background
docker-compose up -d

# Stop services
docker-compose down

# Rebuild after code changes
docker-compose up --build -d

# View Celery worker logs
docker-compose logs -f celery-worker

# Run migrations manually
docker-compose exec backend python manage.py migrate

# Create superuser
docker-compose exec backend python manage.py createsuperuser
```

### Backend Setup (Manual)

```bash
# Clone repository
cd SecureSys-Auditor

# Create virtual environment
python -m venv SecureSys-venv
source SecureSys-venv/bin/activate  # Windows: .\SecureSys-venv\Scripts\activate

# Install dependencies
pip install -r reqs/requirements-base.txt
pip install -r reqs/requirements-dev.txt

# Setup database
cd src/backend
python manage.py migrate
python manage.py createsuperuser

# Run development server
python manage.py runserver
```

### Frontend Setup

```bash
# Navigate to frontend
cd src/frontend

# Install dependencies
npm install

# Start development server
npm run dev
```

### Agent Setup

```bash
# Install agent
pip install -r reqs/requirements-agent.txt

# Run scan
cd src/agent
python -m agent.cli scan --output json

# Or with submission
python -m agent.cli register --api-url http://localhost:8000 --api-key YOUR_TOKEN
python -m agent.cli scan --submit
```

---

## 📦 Installation

### Development Installation

```bash
# Backend
pip install -r reqs/requirements-base.txt
pip install -r reqs/requirements-async.txt
pip install -r reqs/requirements-dev.txt

# Frontend
cd src/frontend && npm install

# Agent
pip install -r reqs/requirements-agent.txt
```

### Production Installation

```bash
# Backend with production dependencies
pip install -r reqs/requirements-prod.txt

# Frontend build
cd src/frontend && npm run build
```

---

## 📖 Usage

### CLI Agent Commands

```bash
# Scan local system
securesys-agent scan --output json

# Save to file
securesys-agent scan --output json --file scan_report.json

# Submit to API
securesys-agent scan --submit

# Register with API
securesys-agent register --api-url https://api.securesys.io --api-key YOUR_KEY

# Check status
securesys-agent status
```

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/auth/token/` | POST | Obtain JWT token |
| `/api/v1/systems/` | GET, POST | List/create systems |
| `/api/v1/scans/` | GET, POST | List/create scans |
| `/api/v1/scans/submit/` | POST | Submit scan from agent |
| `/api/v1/findings/` | GET | List security findings |
| `/api/v1/dashboard/stats/` | GET | Dashboard statistics |

### Dashboard Features

- **Overview** - System health, risk score, severity distribution
- **Systems** - Monitored system inventory with search/filter
- **Scans** - Scan history with detailed findings
- **Reports** - Security assessment reports

---

## 🔧 Configuration

### Environment Variables

Copy `.env.example` to `.env` and configure the required variables:

```bash
cp .env.example .env
```

#### Required in Production

| Variable | Description | Example |
|----------|-------------|---------|
| `DJANGO_SECRET_KEY` | Django secret key (generate unique) | `django-insecure-xxx` |
| `ALLOWED_HOSTS` | Comma-separated allowed hostnames | `api.example.com` |
| `ENVIRONMENT` | Environment name | `production` |

#### Database Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `DB_NAME` | PostgreSQL database name | `securesys_db` |
| `DB_USER` | PostgreSQL username | `securesys_user` |
| `DB_PASSWORD` | PostgreSQL password | - |
| `DB_HOST` | PostgreSQL host | `localhost` |
| `DB_PORT` | PostgreSQL port | `5432` |

#### Security Notes

- **`DEBUG`**: Defaults to `False`. Cannot be `True` in production.
- **`DJANGO_SECRET_KEY`**: Required in production. Generate with:
  ```bash
  python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
  ```
- **`ALLOWED_HOSTS`**: Required in production. Must list all valid hostnames.

### Backend Environment Variables

```bash
# .env file
DEBUG=False
DJANGO_SECRET_KEY=your-secret-key
ENVIRONMENT=production
ALLOWED_HOSTS=your-domain.com,api.your-domain.com
DB_NAME=securesys_db
DB_USER=securesys_user
DB_PASSWORD=your-secure-password
CELERY_BROKER_URL=redis://localhost:6380/0
CORS_ALLOWED_ORIGINS=https://your-domain.com
```

### Frontend Environment Variables

```bash
# .env file
VITE_API_URL=http://localhost:8000/api/v1
# Optional (overrides scanning base separately)
VITE_SCANNING_API_URL=http://localhost:8000/api/v1/scanning
```

---

## 📁 Project Structure

```
SecureSys-Auditor/
├── docs/
│   └── implementation/
│       └── phase_1/            # Phase 1 documentation
├── reqs/
│   ├── requirements-base.txt   # Core Python dependencies
│   ├── requirements-async.txt  # Celery/Redis dependencies
│   ├── requirements-dev.txt    # Development tools
│   ├── requirements-prod.txt   # Production dependencies
│   └── requirements-agent.txt  # Agent-specific packages
├── src/
│   ├── agent/                  # CLI Agent
│   │   ├── cli.py              # CLI entry point
│   │   ├── scanner.py          # System scanner
│   │   ├── api_client.py       # API communication
│   │   └── config.py           # Configuration management
│   ├── backend/                # Django Backend
│   │   ├── backend/            # Django project settings
│   │   └── core/               # Main Django app
│   │       ├── models.py       # Data models
│   │       ├── views.py        # API viewsets
│   │       ├── serializers.py  # DRF serializers
│   │       ├── analysis.py     # Security analysis engine
│   │       └── tasks.py        # Celery tasks
│   └── frontend/               # React Frontend
│       └── src/
│           ├── components/     # UI components
│           ├── pages/          # Page components
│           ├── stores/         # Zustand stores
│           └── services/       # API services
└── tests/                      # Test suites
```

---

## 🧪 Development

### Running Tests

```bash
# Run all tests with coverage
pytest tests/ --cov=src --cov-report=term-missing --cov-fail-under=60

# Backend tests only
pytest tests/test_models.py tests/test_tasks.py tests/test_analysis.py -v

# Agent tests only
pytest tests/test_agent.py -v

# Frontend tests
cd src/frontend
npm run test
```

### Code Quality

```bash
# Run all linters
black --check src/ tests/
flake8 src/ tests/
isort --check-only src/ tests/
bandit -r src/ -x tests/ -ll

# Auto-format code
black src/ tests/
isort src/ tests/

# Frontend linting
cd src/frontend
npm run lint

# Type checking
npm run typecheck
```

### Starting Celery Worker

```bash
cd src/backend
celery -A backend worker -l INFO
```

---

## 🔒 Security

### Authentication

- JWT-based authentication with access (1h) and refresh (7d) tokens
- Role-based access control (RBAC) with three roles: viewer, auditor, admin

### Data Protection

- All sensitive data encrypted at rest
- TLS required for production API communication
- Audit logging for all sensitive operations

### Agent Security

The agent implements several security measures:

#### TLS Enforcement
- Agent requires HTTPS for API communication in production
- HTTP is only allowed for `localhost` with explicit opt-in for development

#### Payload Signing (HMAC-SHA256)
All scan submissions are signed to ensure integrity:

```
X-Signature: HMAC-SHA256(api_key, timestamp + "." + json_payload)
X-Timestamp: Unix timestamp
```

- Prevents tampering with scan data in transit
- Timestamp prevents replay attacks (5-minute window)
- Backend validates signature before processing

#### Minimal Telemetry Mode
When enabled (default), filters sensitive data from scans:
- IP addresses and MAC addresses
- User home paths
- Environment variables
- SSH keys and credentials
- Command history

Configure in agent:
```bash
# In config file or environment
SECURESYS_MINIMAL_TELEMETRY=true
```

### Credential Rotation

For enhanced security, rotate credentials periodically:

1. **API Keys**: Generate new API key in dashboard, update agent config, invalidate old key
2. **JWT Tokens**: Tokens expire automatically (access: 1h, refresh: 7d)
3. **Django Secret Key**: Rotate during maintenance windows, invalidates all sessions

---

## 📄 API Documentation

Full API documentation is available at:

- **Development**: `http://localhost:8000/api/v1/docs/`
- **Swagger UI**: `http://localhost:8000/api/v1/swagger/`
- **ReDoc**: `http://localhost:8000/api/v1/redoc/`

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please read our [Contributing Guidelines](CONTRIBUTING.md) for details.

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 📞 Support

- **Documentation**: [docs.securesys.io](https://docs.securesys.io)
- **Issues**: [GitHub Issues](https://github.com/securesys/auditor/issues)
- **Email**: support@securesys.io

---

**Built with ❤️ by the SecureSys Team**
