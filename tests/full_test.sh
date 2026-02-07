#!/bin/bash
# =============================================================================
# EPP Client Full Command Test Suite
# =============================================================================
# Tests all EPP commands against the OTE server and logs results.
#
# Usage:
#   ./full_test.sh
#   ./full_test.sh --config /path/to/config.yaml
#   ./full_test.sh --host epp-ote.aeda.ae --client-id tester4 --password XXX
#
# Results are logged to /tmp/epp-test-results-YYYYMMDD-HHMMSS.log
# =============================================================================

set -euo pipefail

# Test configuration
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
LOG_FILE="/tmp/epp-test-results-${TIMESTAMP}.log"
PASS=0
FAIL=0
SKIP=0

# Test data - unique per run to avoid conflicts
RUN_ID=$(date +%s | tail -c 5)
CONTACT_ID="TSTC${RUN_ID}"
HOST1="ns1.epptest${RUN_ID}.ae"
HOST2="ns2.epptest${RUN_ID}.ae"
DOMAIN="epptest${RUN_ID}.ae"

# Pass through all CLI args (--config, --host, --client-id, etc.)
EPP_OPTS="$*"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# =============================================================================
# Helper functions
# =============================================================================

log() {
    echo -e "$1" | tee -a "$LOG_FILE"
}

run_test() {
    local test_name="$1"
    local cmd="$2"
    local expect_fail="${3:-false}"

    log ""
    log "${CYAN}━━━ TEST: ${test_name} ━━━${NC}"
    log "CMD: epp ${EPP_OPTS} ${cmd}"

    # Run command and capture output + exit code
    set +e
    output=$(eval "epp ${EPP_OPTS} ${cmd}" 2>&1)
    exit_code=$?
    set -e

    echo "$output" >> "$LOG_FILE"

    if [ "$expect_fail" = "true" ]; then
        if [ $exit_code -ne 0 ]; then
            log "${GREEN}PASS${NC} (expected failure) - exit code: ${exit_code}"
            PASS=$((PASS + 1))
        else
            log "${RED}FAIL${NC} (expected failure but succeeded)"
            FAIL=$((FAIL + 1))
        fi
    else
        if [ $exit_code -eq 0 ]; then
            log "${GREEN}PASS${NC}"
            echo "$output" | head -20 | while IFS= read -r line; do
                log "  $line"
            done
            PASS=$((PASS + 1))
        else
            log "${RED}FAIL${NC} - exit code: ${exit_code}"
            echo "$output" | while IFS= read -r line; do
                log "  $line"
            done
            FAIL=$((FAIL + 1))
        fi
    fi

    # Small delay between commands
    sleep 1
}

# =============================================================================
# Start
# =============================================================================

log "============================================="
log " EPP Client Full Command Test Suite"
log " $(date)"
log " Log: ${LOG_FILE}"
log "============================================="
log ""
log "Test data:"
log "  Contact ID : ${CONTACT_ID}"
log "  Host 1     : ${HOST1}"
log "  Host 2     : ${HOST2}"
log "  Domain     : ${DOMAIN}"
log ""

# =============================================================================
# 1. CONTACT COMMANDS
# =============================================================================

log "${YELLOW}═══ CONTACT COMMANDS ═══${NC}"

run_test "Contact Check (should be available)" \
    "contact check ${CONTACT_ID}"

run_test "Contact Create" \
    "contact create ${CONTACT_ID} \
        --name 'EPP Test User' \
        --email 'epptest@example.ae' \
        --city 'Abu Dhabi' \
        --country AE \
        --org 'EPP Test Company LLC' \
        --street '123 Test Street' \
        --state 'Abu Dhabi' \
        --postal-code '00000' \
        --voice '+971.501234567'"

run_test "Contact Check (should be taken)" \
    "contact check ${CONTACT_ID}"

run_test "Contact Info" \
    "contact info ${CONTACT_ID}"

run_test "Contact Update (change email)" \
    "contact update ${CONTACT_ID} --email 'updated@example.ae'"

run_test "Contact Info (verify update)" \
    "contact info ${CONTACT_ID}"

# =============================================================================
# 2. HOST COMMANDS
# =============================================================================

log ""
log "${YELLOW}═══ HOST COMMANDS ═══${NC}"

run_test "Host Check (should be available)" \
    "host check ${HOST1} ${HOST2}"

run_test "Host Create (ns1)" \
    "host create ${HOST1} --ipv4 192.168.1.1"

run_test "Host Create (ns2)" \
    "host create ${HOST2} --ipv4 192.168.1.2"

run_test "Host Check (should be taken)" \
    "host check ${HOST1} ${HOST2}"

run_test "Host Info" \
    "host info ${HOST1}"

run_test "Host Update (add IP)" \
    "host update ${HOST1} --add-ipv4 10.0.0.1"

run_test "Host Info (verify update)" \
    "host info ${HOST1}"

# =============================================================================
# 3. DOMAIN COMMANDS
# =============================================================================

log ""
log "${YELLOW}═══ DOMAIN COMMANDS ═══${NC}"

run_test "Domain Check (should be available)" \
    "domain check ${DOMAIN}"

run_test "Domain Create" \
    "domain create ${DOMAIN} \
        --registrant ${CONTACT_ID} \
        --tech ${CONTACT_ID} \
        --ns ${HOST1} \
        --ns ${HOST2} \
        --period 1"

run_test "Domain Check (should be taken)" \
    "domain check ${DOMAIN}"

run_test "Domain Info" \
    "domain info ${DOMAIN}"

# Capture expiry date for renew
EXPIRY=$(epp ${EPP_OPTS} domain info ${DOMAIN} 2>/dev/null | grep -i "expir\|exDate\|exp" | head -1 | grep -oP '\d{4}-\d{2}-\d{2}' || echo "")
if [ -z "$EXPIRY" ]; then
    # Default to 1 year from now if we can't parse it
    EXPIRY=$(date -d "+1 year" +%Y-%m-%d 2>/dev/null || date -v+1y +%Y-%m-%d 2>/dev/null || echo "2027-02-06")
fi
log "  Detected expiry date: ${EXPIRY}"

run_test "Domain Update (add clientHold)" \
    "domain update ${DOMAIN} --add-status clientHold --add-status-reason 'Testing EPP client'"

run_test "Domain Info (verify clientHold)" \
    "domain info ${DOMAIN}"

run_test "Domain Update (remove clientHold)" \
    "domain update ${DOMAIN} --rem-status clientHold"

run_test "Domain Renew" \
    "domain renew ${DOMAIN} --exp-date ${EXPIRY} --period 1"

run_test "Domain Info (verify renewed)" \
    "domain info ${DOMAIN}"

# =============================================================================
# 4. POLL COMMANDS
# =============================================================================

log ""
log "${YELLOW}═══ POLL COMMANDS ═══${NC}"

run_test "Poll Request" \
    "poll request"

# =============================================================================
# 5. CUSTOM clTRID TEST
# =============================================================================

log ""
log "${YELLOW}═══ CUSTOM clTRID TEST ═══${NC}"

run_test "Domain Check with custom clTRID" \
    "domain check ${DOMAIN} --cltrid 'CUSTOM-TEST-${RUN_ID}'"

# =============================================================================
# 6. CLEANUP - Delete in reverse order
# =============================================================================

log ""
log "${YELLOW}═══ CLEANUP ═══${NC}"

run_test "Domain Delete" \
    "domain delete ${DOMAIN} -y"

run_test "Host Delete (ns1)" \
    "host delete ${HOST1} -y"

run_test "Host Delete (ns2)" \
    "host delete ${HOST2} -y"

run_test "Contact Delete" \
    "contact delete ${CONTACT_ID} -y"

# Verify cleanup
run_test "Domain Check (should be available after delete)" \
    "domain check ${DOMAIN}"

run_test "Contact Check (should be available after delete)" \
    "contact check ${CONTACT_ID}"

# =============================================================================
# 7. ERROR HANDLING TESTS
# =============================================================================

log ""
log "${YELLOW}═══ ERROR HANDLING ═══${NC}"

run_test "Domain Info on non-existent domain (expect fail)" \
    "domain info doesnotexist999.ae" \
    true

run_test "Contact Info on non-existent contact (expect fail)" \
    "contact info NOEXIST999" \
    true

run_test "Host Info on non-existent host (expect fail)" \
    "host info ns1.doesnotexist999.ae" \
    true

# =============================================================================
# RESULTS
# =============================================================================

log ""
log "============================================="
log " TEST RESULTS"
log "============================================="
log " ${GREEN}PASSED : ${PASS}${NC}"
log " ${RED}FAILED : ${FAIL}${NC}"
log " ${YELLOW}SKIPPED: ${SKIP}${NC}"
log " TOTAL  : $((PASS + FAIL + SKIP))"
log "============================================="
log " Log file: ${LOG_FILE}"
log "============================================="

if [ $FAIL -gt 0 ]; then
    log ""
    log "${RED}Some tests failed! Check the log for details.${NC}"
    exit 1
else
    log ""
    log "${GREEN}All tests passed!${NC}"
    exit 0
fi
