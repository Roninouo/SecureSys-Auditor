#!/bin/bash
# SecureSys Auditor - Backup Restore Verification
# Restores the latest backup into a temporary database, runs a sanity query, and cleans up.

set -euo pipefail

BACKUP_DIR="/backups"
TMP_DIR="/tmp"
VERIFY_DB_PREFIX="securesys_restore_verify"

log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

push_restore_verify_success_metric() {
  if [ -z "${PUSHGATEWAY_URL:-}" ]; then
    return 0
  fi
  if ! command -v curl >/dev/null 2>&1; then
    log "WARNING: curl not found; cannot push restore verification metrics"
    return 0
  fi

  local ts
  ts=$(date +%s)
  local job
  job="${PUSHGATEWAY_JOB:-securesys_postgres_restore_verify}"
  local instance
  instance="${PUSHGATEWAY_INSTANCE:-${HOSTNAME}}"
  local url
  url="${PUSHGATEWAY_URL%/}/metrics/job/${job}/instance/${instance}"

  local metrics
  metrics=$(cat <<EOF
# TYPE backup_restore_verify_last_success_timestamp gauge
backup_restore_verify_last_success_timestamp ${ts}
EOF
)

  if echo "${metrics}" | curl --silent --show-error --fail --data-binary @- "${url}" >/dev/null; then
    log "Pushed backup_restore_verify_last_success_timestamp=${ts} to Pushgateway"
  else
    log "WARNING: Failed to push restore verification metrics to Pushgateway (${url})"
  fi
}

die() {
  log "ERROR: $1"
  exit 1
}

if [ ! -d "${BACKUP_DIR}" ]; then
  die "Backup dir not found: ${BACKUP_DIR}"
fi

LATEST_BACKUP=$(ls -1t "${BACKUP_DIR}"/securesys_backup_* 2>/dev/null | head -n 1 || true)
if [ -z "${LATEST_BACKUP}" ]; then
  die "No backups found in ${BACKUP_DIR}"
fi

log "Latest backup: ${LATEST_BACKUP}"

WORK_FILE="${LATEST_BACKUP}"
CLEANUP_FILES=()

# Decrypt if needed
if [[ "${WORK_FILE}" == *.enc ]]; then
  if [ -z "${BACKUP_ENCRYPTION_KEY:-}" ]; then
    die "Backup is encrypted but BACKUP_ENCRYPTION_KEY is not set"
  fi
  if ! command -v openssl >/dev/null 2>&1; then
    die "openssl not found (required to decrypt encrypted backups)"
  fi

  DECRYPTED_FILE="${TMP_DIR}/$(basename "${WORK_FILE%.enc}")"
  log "Decrypting to ${DECRYPTED_FILE}"
  openssl enc -d -aes-256-cbc -in "${WORK_FILE}" -out "${DECRYPTED_FILE}" -pass pass:"${BACKUP_ENCRYPTION_KEY}"
  WORK_FILE="${DECRYPTED_FILE}"
  CLEANUP_FILES+=("${DECRYPTED_FILE}")
fi

# Unzip if needed
if [[ "${WORK_FILE}" == *.gz ]]; then
  UNZIPPED_FILE="${TMP_DIR}/$(basename "${WORK_FILE%.gz}")"
  log "Unzipping to ${UNZIPPED_FILE}"
  gunzip -c "${WORK_FILE}" > "${UNZIPPED_FILE}"
  WORK_FILE="${UNZIPPED_FILE}"
  CLEANUP_FILES+=("${UNZIPPED_FILE}")
fi

TS=$(date +%s)
VERIFY_DB="${VERIFY_DB_PREFIX}_${TS}"

cleanup() {
  set +e
  for f in "${CLEANUP_FILES[@]:-}"; do
    rm -f "$f" >/dev/null 2>&1
  done
  dropdb "${VERIFY_DB}" >/dev/null 2>&1
}
trap cleanup EXIT

log "Creating temporary DB: ${VERIFY_DB}"
createdb "${VERIFY_DB}"

log "Restoring backup into ${VERIFY_DB}"
pg_restore --verbose --no-owner --no-privileges --dbname="${VERIFY_DB}" "${WORK_FILE}"

log "Running verification query"
psql --dbname="${VERIFY_DB}" --tuples-only --command="SELECT 1;" >/dev/null

log "Restore verification succeeded"

push_restore_verify_success_metric
