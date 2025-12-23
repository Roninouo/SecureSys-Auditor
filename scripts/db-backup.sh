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

# Encryption
if [ -n "${BACKUP_ENCRYPTION_KEY:-}" ]; then
    log "Encrypting backup..."
    openssl enc -aes-256-cbc -salt -in "${BACKUP_FILE}" -out "${BACKUP_FILE}.enc" -pass pass:"${BACKUP_ENCRYPTION_KEY}"
    rm "${BACKUP_FILE}"
    BACKUP_FILE="${BACKUP_FILE}.enc"
    log "Backup encrypted: ${BACKUP_FILE}"
fi

# Offsite Backup
if [ -n "${AWS_S3_BUCKET:-}" ]; then
    log "Uploading to S3: s3://${AWS_S3_BUCKET}/backups/$(basename "${BACKUP_FILE}")"
    if command -v aws >/dev/null 2>&1; then
        aws s3 cp "${BACKUP_FILE}" "s3://${AWS_S3_BUCKET}/backups/"
        log "Upload complete"
    else
        log "WARNING: aws CLI not found, skipping S3 upload"
    fi
fi

# Calculate backup size
BACKUP_SIZE=$(du -h "${BACKUP_FILE}" | cut -f1)
log "Backup created successfully: ${BACKUP_FILE} (${BACKUP_SIZE})"

# Cleanup old backups
log "Cleaning up backups older than ${RETENTION_DAYS} days..."
# Note: This cleanup only handles local files. S3 lifecycle policies should handle remote backups.
find "${BACKUP_DIR}" -name "securesys_backup_*" -mtime +${RETENTION_DAYS} -delete
log "Cleanup complete"

# List current backups
log "Current backups:"
ls -lh "${BACKUP_DIR}"/securesys_backup_* 2>/dev/null || echo "No backups found"

# Calculate total backup storage used
TOTAL_SIZE=$(du -sh "${BACKUP_DIR}" | cut -f1)
log "Total backup storage used: ${TOTAL_SIZE}"

log "Backup completed successfully"
