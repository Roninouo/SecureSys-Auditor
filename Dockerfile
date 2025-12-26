# SecureSys Auditor Backend Dockerfile
# Multi-stage build for optimized production image

# Build stage
FROM python:3.11-slim as builder

# Allow configuring pip index/timeout for restricted networks
ARG PIP_INDEX_URL=https://mirrors.aliyun.com/pypi/simple/
ARG PIP_DEFAULT_TIMEOUT=60
ENV PIP_INDEX_URL=${PIP_INDEX_URL} \
    PIP_DEFAULT_TIMEOUT=${PIP_DEFAULT_TIMEOUT} \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY reqs/requirements-base.txt reqs/requirements-async.txt reqs/requirements-prod.txt ./reqs/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r reqs/requirements-base.txt && \
    pip install --no-cache-dir -r reqs/requirements-async.txt && \
    pip install --no-cache-dir -r reqs/requirements-prod.txt


# Production stage
FROM python:3.11-slim as production

# Security: Run as non-root user
RUN groupadd -r securesys && useradd -r -g securesys securesys

WORKDIR /app

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application code
COPY src/backend/ ./

# Create necessary directories
RUN mkdir -p logs staticfiles media && \
    chown -R securesys:securesys /app

# Switch to non-root user
USER securesys

# Environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DJANGO_SETTINGS_MODULE=backend.settings

# Collect static files
RUN python manage.py collectstatic --noinput --clear 2>/dev/null || true

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health/ || exit 1

# Expose port
EXPOSE 8000

# Default command - use gunicorn for production
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "4", "--threads", "2", "backend.wsgi:application"]
