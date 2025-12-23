#!/bin/bash
# SecureSys Auditor - Database Backup Script
# Runs as a cron job inside the backup container

set -euo pipefail

# Configuration
BACKUP_DIR="/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/securesys_backup_${TIMESTAMP}.sql.gz"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"

# Logging
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

log "Starting database backup..."

# Create backup directory if it doesn't exist
mkdir -p "${BACKUP_DIR}"

# Create compressed backup
log "Creating backup: ${BACKUP_FILE}"
pg_dump \
    --format=custom \
    --verbose \
    --file="${BACKUP_FILE%.gz}" \
    --no-owner \
    --no-privileges

# Compress backup
gzip "${BACKUP_FILE%.gz}"

# Verify backup integrity
log "Verifying backup integrity..."
if gunzip -t "${BACKUP_FILE}"; then
    log "Backup integrity check passed"
else
    log "ERROR: Backup integrity check failed!"
    exit 1
fi

# Calculate backup size
BACKUP_SIZE=$(du -h "${BACKUP_FILE}" | cut -f1)
log "Backup created successfully: ${BACKUP_FILE} (${BACKUP_SIZE})"

# Cleanup old backups
log "Cleaning up backups older than ${RETENTION_DAYS} days..."
DELETED_COUNT=$(find "${BACKUP_DIR}" -name "securesys_backup_*.sql.gz" -mtime +${RETENTION_DAYS} -delete -print | wc -l)
log "Deleted ${DELETED_COUNT} old backup(s)"

# List current backups
log "Current backups:"
ls -lh "${BACKUP_DIR}"/securesys_backup_*.sql.gz 2>/dev/null || echo "No backups found"

# Calculate total backup storage used
TOTAL_SIZE=$(du -sh "${BACKUP_DIR}" | cut -f1)
log "Total backup storage used: ${TOTAL_SIZE}"

log "Backup completed successfully"
