#!/bin/bash
# SecureSys Auditor - Database Restore Script
# Usage: ./db-restore.sh <backup_file>

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging
log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Check arguments
if [ $# -lt 1 ]; then
    echo "Usage: $0 <backup_file> [--force]"
    echo ""
    echo "Options:"
    echo "  --force    Skip confirmation prompt"
    echo ""
    echo "Available backups:"
    ls -lh /backups/securesys_backup_*.sql.gz 2>/dev/null || echo "No backups found"
    exit 1
fi

BACKUP_FILE="$1"
FORCE_RESTORE="${2:-}"

# Verify backup file exists
if [ ! -f "${BACKUP_FILE}" ]; then
    # Try with /backups prefix
    if [ -f "/backups/${BACKUP_FILE}" ]; then
        BACKUP_FILE="/backups/${BACKUP_FILE}"
    else
        log_error "Backup file not found: ${BACKUP_FILE}"
        exit 1
    fi
fi

log "Preparing to restore from: ${BACKUP_FILE}"

# Verify backup integrity
log "Verifying backup integrity..."
if gunzip -t "${BACKUP_FILE}"; then
    log_success "Backup integrity verified"
else
    log_error "Backup file is corrupted!"
    exit 1
fi

# Confirmation prompt
if [ "${FORCE_RESTORE}" != "--force" ]; then
    log_warn "This will OVERWRITE the current database!"
    log_warn "Database: ${PGDATABASE:-securesys_db}"
    log_warn "Host: ${PGHOST:-localhost}"
    echo ""
    read -p "Are you sure you want to continue? (yes/no): " CONFIRM
    if [ "${CONFIRM}" != "yes" ]; then
        log "Restore cancelled by user"
        exit 0
    fi
fi

# Create pre-restore backup
PRE_RESTORE_BACKUP="/backups/pre_restore_$(date +%Y%m%d_%H%M%S).sql.gz"
log "Creating pre-restore backup: ${PRE_RESTORE_BACKUP}"
pg_dump --format=custom --file="${PRE_RESTORE_BACKUP%.gz}" 2>/dev/null || true
gzip "${PRE_RESTORE_BACKUP%.gz}" 2>/dev/null || true

# Stop application connections (optional - comment out if not needed)
log "Terminating existing database connections..."
psql -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '${PGDATABASE}' AND pid <> pg_backend_pid();" 2>/dev/null || true

# Restore from backup
log "Restoring database from backup..."
gunzip -c "${BACKUP_FILE}" | pg_restore \
    --verbose \
    --clean \
    --if-exists \
    --no-owner \
    --no-privileges \
    --dbname="${PGDATABASE:-securesys_db}"

if [ $? -eq 0 ]; then
    log_success "Database restored successfully!"
else
    log_error "Database restore failed!"
    log_warn "Pre-restore backup available at: ${PRE_RESTORE_BACKUP}"
    exit 1
fi

# Verify restore
log "Verifying restore..."
SYSTEM_COUNT=$(psql -t -c "SELECT COUNT(*) FROM scanning_systems;" 2>/dev/null || echo "0")
SCAN_COUNT=$(psql -t -c "SELECT COUNT(*) FROM scanning_scans;" 2>/dev/null || echo "0")

log "Restore verification:"
log "  - Systems: ${SYSTEM_COUNT}"
log "  - Scans: ${SCAN_COUNT}"

log_success "Database restore completed!"
