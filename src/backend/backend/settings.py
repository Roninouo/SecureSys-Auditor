"""
Django settings for SecureSys Auditor backend.
"""

import os
import sys
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Environment detection
ENVIRONMENT = os.getenv('ENVIRONMENT', 'development').lower()
IS_PRODUCTION = ENVIRONMENT == 'production'
IS_TESTING = 'pytest' in sys.modules or os.getenv('TESTING', 'False').lower() == 'true'

# SECURITY WARNING: keep the secret key used in production secret!
# In production, DJANGO_SECRET_KEY must be explicitly set
_default_secret_key = 'django-insecure-dev-key-change-in-production' if not IS_PRODUCTION else None
SECRET_KEY = os.getenv('DJANGO_SECRET_KEY', _default_secret_key)

if IS_PRODUCTION and not SECRET_KEY:
    raise ValueError(
        "DJANGO_SECRET_KEY environment variable is required in production. "
        "Generate a secure key using: python -c \"from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())\""
    )

# SECURITY WARNING: don't run with debug turned on in production!
# Default to False for security - must explicitly enable DEBUG
DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'

if IS_PRODUCTION and DEBUG:
    raise ValueError(
        "DEBUG cannot be True in production environment. "
        "Set DEBUG=False or remove DEBUG from environment variables."
    )

# ALLOWED_HOSTS configuration
# In production, ALLOWED_HOSTS must be explicitly configured
_allowed_hosts_env = os.getenv('ALLOWED_HOSTS', '')
if IS_PRODUCTION and not _allowed_hosts_env:
    raise ValueError(
        "ALLOWED_HOSTS environment variable is required in production. "
        "Set ALLOWED_HOSTS to a comma-separated list of allowed hostnames."
    )
ALLOWED_HOSTS = _allowed_hosts_env.split(',') if _allowed_hosts_env else ['localhost', '127.0.0.1']

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    
    # Third-party apps
    'rest_framework',
    'rest_framework_simplejwt',
    'corsheaders',
    'django_filters',
    'django_celery_results',
    'django_celery_beat',
    'drf_spectacular',  # OpenAPI schema generation
    
    # Local apps - Core (legacy, being refactored)
    'core',
    
    # Local apps - Modular architecture
    'authentication',  # Auth providers, permissions
    'scanning',        # Scan processing
    'reports',         # PDF report generation
    'webhooks',        # Webhook notifications
    'observability',   # Telemetry, metrics, health checks
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    # Observability - adds request context to traces
    'observability.middleware.HealthCheckBypassMiddleware',
    'observability.middleware.RequestContextMiddleware',
]

ROOT_URLCONF = 'backend.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'backend.wsgi.application'

# Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.getenv('DB_NAME', 'securesys_db'),
        'USER': os.getenv('DB_USER', 'securesys_user'),
        'PASSWORD': os.getenv('DB_PASSWORD', ''),
        'HOST': os.getenv('DB_HOST', 'localhost'),
        'PORT': os.getenv('DB_PORT', '5432'),
    }
}

# In tests, use a lightweight local DB to keep unit/integration tests self-contained.
if IS_TESTING:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'test_db.sqlite3',
        }
    }

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# Custom User Model
AUTH_USER_MODEL = 'core.User'

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
STATIC_URL = 'static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'

# Media files
MEDIA_URL = 'media/'
MEDIA_ROOT = BASE_DIR / 'media'

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# REST Framework Configuration
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        # Uses Chain of Responsibility pattern - tries OIDC first, then JWT
        'authentication.backends.ProviderChainAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
    'DEFAULT_FILTER_BACKENDS': (
        'django_filters.rest_framework.DjangoFilterBackend',
        'rest_framework.filters.SearchFilter',
        'rest_framework.filters.OrderingFilter',
    ),
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 20,
    'DEFAULT_RENDERER_CLASSES': (
        'rest_framework.renderers.JSONRenderer',
    ),
    'DEFAULT_THROTTLE_CLASSES': (
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle',
    ),
    'DEFAULT_THROTTLE_RATES': {
        'anon': '100/hour',
        'user': '1000/hour',
        'scans': '100/hour',  # Rate limit for scan submissions
    },
    # OpenAPI schema generation
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
}

# Simple JWT Configuration
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(hours=1),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    'AUTH_HEADER_TYPES': ('Bearer',),
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
}

# CORS Configuration
CORS_ALLOWED_ORIGINS = os.getenv(
    'CORS_ALLOWED_ORIGINS',
    'http://localhost:3000,http://127.0.0.1:3000'
).split(',')

CORS_ALLOW_CREDENTIALS = True

# Celery Configuration
CELERY_BROKER_URL = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0')
CELERY_RESULT_BACKEND = 'django-db'
CELERY_CACHE_BACKEND = 'django-cache'
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = TIME_ZONE
CELERY_TASK_TRACK_STARTED = True
CELERY_TASK_TIME_LIMIT = 30 * 60  # 30 minutes

# Dedicated queues for different task types (scalability improvement)
# This prevents report generation from blocking scan processing
CELERY_TASK_QUEUES = {
    'default': {'exchange': 'default', 'routing_key': 'default'},
    'scans': {'exchange': 'scans', 'routing_key': 'scans'},
    'reports': {'exchange': 'reports', 'routing_key': 'reports'},
    'webhooks': {'exchange': 'webhooks', 'routing_key': 'webhooks'},
}

# Route tasks to appropriate queues
CELERY_TASK_ROUTES = {
    'scanning.tasks.*': {'queue': 'scans'},
    'reports.tasks.*': {'queue': 'reports'},
    'webhooks.tasks.*': {'queue': 'webhooks'},
}

# Worker prefetch multiplier (lower = better for long tasks)
CELERY_WORKER_PREFETCH_MULTIPLIER = 1

# Logging Configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'json': {
            'class': 'pythonjsonlogger.jsonlogger.JsonFormatter',
            'format': '%(asctime)s %(levelname)s %(name)s %(message)s'
        },
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose' if DEBUG else 'json',
        },
        'file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': BASE_DIR / 'logs' / 'securesys.log',
            'maxBytes': 1024 * 1024 * 10,  # 10 MB
            'backupCount': 5,
            'formatter': 'json',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': os.getenv('DJANGO_LOG_LEVEL', 'INFO'),
            'propagate': False,
        },
        'core': {
            'handlers': ['console', 'file'] if not DEBUG else ['console'],
            'level': 'DEBUG' if DEBUG else 'INFO',
            'propagate': False,
        },
    },
}

# Create logs directory
(BASE_DIR / 'logs').mkdir(exist_ok=True)

# =============================================================================
# OIDC/Keycloak Configuration (Enterprise IAM)
# =============================================================================
OIDC_AUTH = {
    'ENABLED': os.getenv('OIDC_ENABLED', 'False').lower() == 'true',
    'ISSUER': os.getenv('OIDC_ISSUER', 'http://localhost:8080/realms/securesys'),
    'AUDIENCE': os.getenv('OIDC_AUDIENCE', 'securesys-backend'),
    'AUTO_CREATE_USER': os.getenv('OIDC_AUTO_CREATE_USER', 'True').lower() == 'true',
    'ALLOW_JWT_FALLBACK': os.getenv('OIDC_ALLOW_JWT_FALLBACK', 'True').lower() == 'true',
    # Role mappings from Keycloak realm roles to Django roles
    'ROLE_MAPPINGS': {
        'admin': 'admin',
        'auditor': 'auditor',
        'viewer': 'viewer',
    },
    # Token refresh settings
    'TOKEN_REFRESH_WINDOW': int(os.getenv('OIDC_TOKEN_REFRESH_WINDOW', '300')),  # Refresh 5 min before expiry
    'SESSION_MAX_AGE': int(os.getenv('OIDC_SESSION_MAX_AGE', '28800')),  # 8 hours
    'JWKS_CACHE_TTL': int(os.getenv('OIDC_JWKS_CACHE_TTL', '3600')),  # 1 hour
    # Key rotation settings
    'KEY_ROTATION_CHECK_INTERVAL': int(os.getenv('OIDC_KEY_ROTATION_CHECK', '3600')),  # 1 hour
    'ALLOW_ALGORITHM_RS256': True,
    'ALLOW_ALGORITHM_RS384': True,
    'ALLOW_ALGORITHM_RS512': True,
}

# Session security settings
SESSION_ENGINE = 'django.contrib.sessions.backends.db'
SESSION_COOKIE_NAME = 'securesys_session'
SESSION_COOKIE_AGE = OIDC_AUTH['SESSION_MAX_AGE']
SESSION_COOKIE_SECURE = IS_PRODUCTION
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict' if IS_PRODUCTION else 'Lax'
SESSION_EXPIRE_AT_BROWSER_CLOSE = False
SESSION_SAVE_EVERY_REQUEST = True  # Extend session on activity

# CSRF settings
CSRF_COOKIE_SECURE = IS_PRODUCTION
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = 'Strict' if IS_PRODUCTION else 'Lax'
CSRF_TRUSTED_ORIGINS = os.getenv('CSRF_TRUSTED_ORIGINS', '').split(',') if os.getenv('CSRF_TRUSTED_ORIGINS') else []

# Authentication providers (processed in order of priority)
# Uses Strategy pattern - easily add new providers
AUTH_PROVIDERS = [
    'authentication.providers.KeycloakOIDCProvider',
    'authentication.providers.SimpleJWTProvider',
]

# =============================================================================
# OpenTelemetry Configuration (Observability)
# =============================================================================
OTEL_ENABLED = os.getenv('OTEL_ENABLED', 'False').lower() == 'true'
OTEL_SERVICE_NAME = os.getenv('OTEL_SERVICE_NAME', 'securesys-backend')
OTEL_EXPORTER_OTLP_ENDPOINT = os.getenv('OTEL_EXPORTER_OTLP_ENDPOINT', 'http://localhost:4317')

# =============================================================================
# Webhook Configuration (External Integrations)
# =============================================================================
WEBHOOK_ENABLED = os.getenv('WEBHOOK_ENABLED', 'False').lower() == 'true'
WEBHOOK_SECRET = os.getenv('WEBHOOK_SECRET', '')

# =============================================================================
# OpenAPI Documentation (drf-spectacular)
# =============================================================================
SPECTACULAR_SETTINGS = {
    'TITLE': 'SecureSys Auditor API',
    'DESCRIPTION': '''
## Security Scanning & Vulnerability Management Platform

SecureSys Auditor provides a comprehensive REST API for:

- **Scan Management**: Submit, track, and retrieve security scan results
- **Finding Analysis**: Query and analyze discovered vulnerabilities
- **System Inventory**: Track monitored systems and their security posture
- **Webhook Integration**: Real-time notifications for security events
- **Report Generation**: Generate PDF reports for compliance and auditing

### Authentication

All API endpoints require authentication via:
- **Bearer Token**: JWT tokens issued via `/api/v1/auth/token/`
- **OIDC/Keycloak**: Enterprise SSO integration

### Rate Limiting

- Anonymous: 100 requests/hour
- Authenticated: 1000 requests/hour
- Scan submissions: 100/hour

### Versioning

The API uses URL-based versioning. Current version: `v1`
''',
    'VERSION': '2.0.0',
    'CONTACT': {
        'name': 'SecureSys Support',
        'email': 'support@securesys.io',
        'url': 'https://docs.securesys.io',
    },
    'LICENSE': {
        'name': 'MIT',
        'url': 'https://opensource.org/licenses/MIT',
    },
    'SERVERS': [
        {'url': 'https://api.securesys.io', 'description': 'Production'},
        {'url': 'https://staging-api.securesys.io', 'description': 'Staging'},
        {'url': 'http://localhost:8000', 'description': 'Local Development'},
    ],
    'SERVE_INCLUDE_SCHEMA': False,
    'COMPONENT_SPLIT_REQUEST': True,
    'SCHEMA_PATH_PREFIX': r'/api/v[0-9]+',
    'SWAGGER_UI_SETTINGS': {
        'deepLinking': True,
        'persistAuthorization': True,
        'displayOperationId': False,
        'filter': True,
    },
    'SWAGGER_UI_DIST': 'SIDECAR',  # Use swagger-ui-dist from npm
    'SWAGGER_UI_FAVICON_HREF': 'SIDECAR',
    'REDOC_DIST': 'SIDECAR',
    # Authentication schemes
    'SECURITY': [
        {'BearerAuth': []},
    ],
    'APPEND_COMPONENTS': {
        'securitySchemes': {
            'BearerAuth': {
                'type': 'http',
                'scheme': 'bearer',
                'bearerFormat': 'JWT',
                'description': 'JWT Bearer token authentication. Obtain tokens via POST /api/v1/auth/token/',
            },
        },
    },
    # Tags for grouping endpoints
    'TAGS': [
        {'name': 'Health', 'description': 'Health check and system status endpoints'},
        {'name': 'Authentication', 'description': 'User authentication and token management'},
        {'name': 'Scans', 'description': 'Security scan submission and retrieval'},
        {'name': 'Systems', 'description': 'Monitored system inventory'},
        {'name': 'Dashboard', 'description': 'Aggregated statistics and metrics'},
        {'name': 'Webhooks', 'description': 'Webhook endpoint configuration'},
        {'name': 'Reports', 'description': 'Report generation and download'},
    ],
    # Enum naming
    'ENUM_NAME_OVERRIDES': {
        'SeverityEnum': 'core.models.Finding.Severity.choices',
        'ScanStatusEnum': 'core.models.Scan.Status.choices',
    },
}
