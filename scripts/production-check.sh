#!/bin/bash
# Production Readiness Verification Script
# Usage: ./production-check.sh <base_url>

set -euo pipefail

BASE_URL="${1:-http://localhost:8000}"
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

log() {
    echo -e "[$(date +'%T')] $1"
}

check_endpoint() {
    local url="$1"
    local expected_code="${2:-200}"

    log "Checking $url..."
    local code=$(curl -s -o /dev/null -w "%{http_code}" "$url")

    if [ "$code" -eq "$expected_code" ]; then
        echo -e "${GREEN}PASS${NC}: $url returned $code"
        return 0
    else
        echo -e "${RED}FAIL${NC}: $url returned $code (expected $expected_code)"
        return 1
    fi
}

log "Starting Production Readiness Checks for $BASE_URL"

# 1. Health Checks
check_endpoint "$BASE_URL/health/live/" 200
check_endpoint "$BASE_URL/health/ready/" 200

# 2. Metrics
check_endpoint "$BASE_URL/health/metrics/" 200

# 3. API Documentation (Should be protected/hidden or 200 if public)
# In production, this might return 403 or 401 if restricted
log "Checking API Docs (Expect 200 or 403 depending on config)..."
CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/api/docs/")
if [[ "$CODE" == "200" || "$CODE" == "403" || "$CODE" == "401" ]]; then
     echo -e "${GREEN}PASS${NC}: API Docs returned $CODE"
else
     echo -e "${RED}FAIL${NC}: API Docs returned $CODE"
fi

# 4. Security Headers (Basic check)
log "Checking Security Headers..."
HEADERS=$(curl -s -I "$BASE_URL/health/live/")
if echo "$HEADERS" | grep -q "X-Content-Type-Options: nosniff"; then
    echo -e "${GREEN}PASS${NC}: X-Content-Type-Options header present"
else
    echo -e "${RED}FAIL${NC}: X-Content-Type-Options header missing"
fi

log "Checks complete."
