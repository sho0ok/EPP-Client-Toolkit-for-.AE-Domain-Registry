#!/bin/bash
# =============================================================================
# EPP Full Test Suite — Tests ALL EPP Commands via Raw XML
# =============================================================================
# Covers: Contact, Host, Domain (CRUD + statuses + renew),
#         Transfer, Poll, Extensions (.co.ae), Cleanup
#
# Usage:  bash tests/epp-full-test.sh
# =============================================================================

set -uo pipefail

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
SUFFIX=$(printf '%04d' $((RANDOM % 10000)))
LOG_FILE="/tmp/epp-full-test-${TIMESTAMP}.log"
PASS=0
FAIL=0
SKIP=0
TOTAL=0

# Test object names (unique per run)
CONTACT1="TST${SUFFIX}A"
CONTACT2="TST${SUFFIX}B"
DOMAIN1="fulltest${SUFFIX}.ae"
DOMAIN2="fulltest${SUFFIX}.co.ae"
# Subordinate hosts under DOMAIN1 (registrar has full authority)
HOST1="ns1.${DOMAIN1}"
HOST2="ns2.${DOMAIN1}"
# Well-known external nameservers for domain create (before our hosts exist)
EXT_NS1="ns1.google.com"
EXT_NS2="ns2.google.com"

# Transfer test domain (pre-existing, owned by another registrar)
TRANSFER_DOMAIN="20250902.ae"
TRANSFER_AUTH="e\$t5h\$h#"

# Auth info for newly created objects
AUTH_PW="Te5t!@Pw78#\$Ab12"

# Colors
RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[0;33m'
CYN='\033[0;36m'
NC='\033[0m'

log() { echo -e "$1" | tee -a "$LOG_FILE"; }

# ── Generic raw XML runner ──
run_raw() {
    local name="$1"
    local xml="$2"
    local expect_code="${3:-1000}"

    TOTAL=$((TOTAL + 1))
    log ""
    log "${CYN}━━━ TEST ${TOTAL}: ${name} ━━━${NC}"

    set +e
    output=$(epp raw "${xml}" --pretty 2>&1)
    exit_code=$?
    set -e

    echo "$output" >> "$LOG_FILE"

    result_code=$(echo "$output" | grep -oP 'code="\K[0-9]+' | head -1 || echo "")

    if [ -z "$result_code" ]; then
        log "${RED}FAIL${NC} - No response code (exit=$exit_code)"
        echo "$output" | head -5 | while IFS= read -r line; do log "  $line"; done
        FAIL=$((FAIL + 1))
    elif [ "$result_code" = "$expect_code" ]; then
        log "${GRN}PASS${NC} - code=${result_code}"
        # Show key response data
        echo "$output" | grep -E '<(msg|domain:name|contact:id|host:name|domain:crDate|domain:exDate|trStatus|domain:status)' | head -8 | while IFS= read -r line; do
            log "  $(echo $line | sed 's/^[[:space:]]*//')"
        done
        PASS=$((PASS + 1))
    else
        log "${RED}FAIL${NC} - expected=${expect_code} got=${result_code}"
        echo "$output" | grep -E '<(msg|value|reason)' | head -5 | while IFS= read -r line; do
            log "  $(echo $line | sed 's/^[[:space:]]*//')"
        done
        FAIL=$((FAIL + 1))
    fi

    LAST_OUTPUT="$output"
    sleep 0.5
}

# =============================================================================
log "============================================================"
log " EPP Full Test Suite"
log " $(date)"
log " Suffix: ${SUFFIX}"
log " Contact1: ${CONTACT1}  Contact2: ${CONTACT2}"
log " Host1: ${HOST1}  Host2: ${HOST2}"
log " Domain1: ${DOMAIN1}  Domain2: ${DOMAIN2}"
log " Transfer: ${TRANSFER_DOMAIN}"
log " Log: ${LOG_FILE}"
log "============================================================"

# =============================================================================
# PHASE 1: CONTACT OPERATIONS
# =============================================================================
log ""
log "${YLW}═══════════════════════════════════════════${NC}"
log "${YLW}  PHASE 1: CONTACT OPERATIONS${NC}"
log "${YLW}═══════════════════════════════════════════${NC}"

run_raw "Contact Check (both should be available)" \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><check><contact:check xmlns:contact=\"urn:ietf:params:xml:ns:contact-1.0\"><contact:id>${CONTACT1}</contact:id><contact:id>${CONTACT2}</contact:id></contact:check></check><clTRID>T.CON.CHK.001</clTRID></command></epp>"

run_raw "Contact Create ${CONTACT1} (registrant)" \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><create><contact:create xmlns:contact=\"urn:ietf:params:xml:ns:contact-1.0\"><contact:id>${CONTACT1}</contact:id><contact:postalInfo type=\"loc\"><contact:name>Test Registrant ${SUFFIX}</contact:name><contact:org>Test Company LLC</contact:org><contact:addr><contact:street>123 Test Street</contact:street><contact:city>Abu Dhabi</contact:city><contact:sp>Abu Dhabi</contact:sp><contact:pc>12345</contact:pc><contact:cc>AE</contact:cc></contact:addr></contact:postalInfo><contact:voice>+971.12345678</contact:voice><contact:email>test${SUFFIX}@example.ae</contact:email><contact:authInfo><contact:pw>${AUTH_PW}</contact:pw></contact:authInfo></contact:create></create><clTRID>T.CON.CR.001</clTRID></command></epp>"

run_raw "Contact Create ${CONTACT2} (tech)" \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><create><contact:create xmlns:contact=\"urn:ietf:params:xml:ns:contact-1.0\"><contact:id>${CONTACT2}</contact:id><contact:postalInfo type=\"loc\"><contact:name>Tech Contact ${SUFFIX}</contact:name><contact:org>Tech Corp</contact:org><contact:addr><contact:street>456 Tech Road</contact:street><contact:city>Dubai</contact:city><contact:sp>Dubai</contact:sp><contact:pc>67890</contact:pc><contact:cc>AE</contact:cc></contact:addr></contact:postalInfo><contact:voice>+971.87654321</contact:voice><contact:email>tech${SUFFIX}@example.ae</contact:email><contact:authInfo><contact:pw>${AUTH_PW}</contact:pw></contact:authInfo></contact:create></create><clTRID>T.CON.CR.002</clTRID></command></epp>"

run_raw "Contact Info ${CONTACT1}" \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><info><contact:info xmlns:contact=\"urn:ietf:params:xml:ns:contact-1.0\"><contact:id>${CONTACT1}</contact:id><contact:authInfo><contact:pw>${AUTH_PW}</contact:pw></contact:authInfo></contact:info></info><clTRID>T.CON.INF.001</clTRID></command></epp>"

run_raw "Contact Update ${CONTACT2} (change org)" \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><update><contact:update xmlns:contact=\"urn:ietf:params:xml:ns:contact-1.0\"><contact:id>${CONTACT2}</contact:id><contact:chg><contact:postalInfo type=\"loc\"><contact:name>Tech Contact ${SUFFIX}</contact:name><contact:org>Updated Tech Corp</contact:org><contact:addr><contact:street>456 Tech Road</contact:street><contact:city>Dubai</contact:city><contact:sp>Dubai</contact:sp><contact:pc>67890</contact:pc><contact:cc>AE</contact:cc></contact:addr></contact:postalInfo></contact:chg></contact:update></update><clTRID>T.CON.UPD.001</clTRID></command></epp>"

# =============================================================================
# PHASE 2: DOMAIN CREATE (using well-known external nameservers)
# =============================================================================
log ""
log "${YLW}═══════════════════════════════════════════${NC}"
log "${YLW}  PHASE 2: DOMAIN CREATE${NC}"
log "${YLW}═══════════════════════════════════════════${NC}"

run_raw "Domain Check ${DOMAIN1}" \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><check><domain:check xmlns:domain=\"urn:ietf:params:xml:ns:domain-1.0\"><domain:name>${DOMAIN1}</domain:name><domain:name>${DOMAIN2}</domain:name></domain:check></check><clTRID>T.DOM.CHK.001</clTRID></command></epp>"

run_raw "Domain Create ${DOMAIN1} (.ae, 1 year)" \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><create><domain:create xmlns:domain=\"urn:ietf:params:xml:ns:domain-1.0\"><domain:name>${DOMAIN1}</domain:name><domain:period unit=\"y\">1</domain:period><domain:ns><domain:hostObj>${EXT_NS1}</domain:hostObj><domain:hostObj>${EXT_NS2}</domain:hostObj></domain:ns><domain:registrant>${CONTACT1}</domain:registrant><domain:contact type=\"tech\">${CONTACT2}</domain:contact><domain:authInfo><domain:pw>${AUTH_PW}</domain:pw></domain:authInfo></domain:create></create><clTRID>T.DOM.CR.001</clTRID></command></epp>"

run_raw "Domain Create ${DOMAIN2} (.co.ae with AE extension)" \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><create><domain:create xmlns:domain=\"urn:ietf:params:xml:ns:domain-1.0\"><domain:name>${DOMAIN2}</domain:name><domain:period unit=\"y\">1</domain:period><domain:ns><domain:hostObj>${EXT_NS1}</domain:hostObj><domain:hostObj>${EXT_NS2}</domain:hostObj></domain:ns><domain:registrant>${CONTACT1}</domain:registrant><domain:contact type=\"tech\">${CONTACT2}</domain:contact><domain:authInfo><domain:pw>${AUTH_PW}</domain:pw></domain:authInfo></domain:create></create><extension><aeext:create xmlns:aeext=\"urn:X-ae:params:xml:ns:aeext-1.0\"><aeext:aeProperties><aeext:registrantName>Test Company LLC</aeext:registrantName><aeext:registrantID type=\"Trade License\">TL${SUFFIX}999</aeext:registrantID><aeext:eligibilityType>Trade License</aeext:eligibilityType><aeext:policyReason>1</aeext:policyReason></aeext:aeProperties></aeext:create></extension><clTRID>T.DOM.CR.002</clTRID></command></epp>"

run_raw "Domain Info ${DOMAIN1}" \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><info><domain:info xmlns:domain=\"urn:ietf:params:xml:ns:domain-1.0\"><domain:name hosts=\"all\">${DOMAIN1}</domain:name></domain:info></info><clTRID>T.DOM.INF.001</clTRID></command></epp>"

run_raw "Domain Info ${DOMAIN2}" \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><info><domain:info xmlns:domain=\"urn:ietf:params:xml:ns:domain-1.0\"><domain:name hosts=\"all\">${DOMAIN2}</domain:name></domain:info></info><clTRID>T.DOM.INF.002</clTRID></command></epp>"

# =============================================================================
# PHASE 3: HOST OPERATIONS (subordinate hosts under DOMAIN1)
# =============================================================================
log ""
log "${YLW}═══════════════════════════════════════════${NC}"
log "${YLW}  PHASE 3: HOST OPERATIONS (subordinate)${NC}"
log "${YLW}═══════════════════════════════════════════${NC}"

run_raw "Host Check (both should be available)" \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><check><host:check xmlns:host=\"urn:ietf:params:xml:ns:host-1.0\"><host:name>${HOST1}</host:name><host:name>${HOST2}</host:name></host:check></check><clTRID>T.HOS.CHK.001</clTRID></command></epp>"

run_raw "Host Create ${HOST1} (subordinate, with glue)" \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><create><host:create xmlns:host=\"urn:ietf:params:xml:ns:host-1.0\"><host:name>${HOST1}</host:name><host:addr ip=\"v4\">192.0.2.1</host:addr></host:create></create><clTRID>T.HOS.CR.001</clTRID></command></epp>"

run_raw "Host Create ${HOST2} (subordinate, with glue)" \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><create><host:create xmlns:host=\"urn:ietf:params:xml:ns:host-1.0\"><host:name>${HOST2}</host:name><host:addr ip=\"v4\">192.0.2.2</host:addr></host:create></create><clTRID>T.HOS.CR.002</clTRID></command></epp>"

run_raw "Host Info ${HOST1}" \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><info><host:info xmlns:host=\"urn:ietf:params:xml:ns:host-1.0\"><host:name>${HOST1}</host:name></host:info></info><clTRID>T.HOS.INF.001</clTRID></command></epp>"

run_raw "Host Update ${HOST2} (add status)" \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><update><host:update xmlns:host=\"urn:ietf:params:xml:ns:host-1.0\"><host:name>${HOST2}</host:name><host:add><host:status s=\"clientUpdateProhibited\"/></host:add></host:update></update><clTRID>T.HOS.UPD.001</clTRID></command></epp>"

# Switch domain NS to external before deleting subordinate hosts
run_raw "Domain Update (switch NS to external before host cleanup)" \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><update><domain:update xmlns:domain=\"urn:ietf:params:xml:ns:domain-1.0\"><domain:name>${DOMAIN1}</domain:name><domain:add><domain:ns><domain:hostObj>${EXT_NS1}</domain:hostObj><domain:hostObj>${EXT_NS2}</domain:hostObj></domain:ns></domain:add><domain:rem><domain:ns><domain:hostObj>${HOST1}</domain:hostObj><domain:hostObj>${HOST2}</domain:hostObj></domain:ns></domain:rem></domain:update></update><clTRID>T.HOS.PREP.001</clTRID></command></epp>"

# =============================================================================
# PHASE 4: DOMAIN STATUS UPDATES (clientHold, clientDelete/Renew/UpdateProhibited)
# =============================================================================
log ""
log "${YLW}═══════════════════════════════════════════${NC}"
log "${YLW}  PHASE 4: DOMAIN STATUS UPDATES${NC}"
log "${YLW}═══════════════════════════════════════════${NC}"

run_raw "Add clientHold" \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><update><domain:update xmlns:domain=\"urn:ietf:params:xml:ns:domain-1.0\"><domain:name>${DOMAIN1}</domain:name><domain:add><domain:status s=\"clientHold\"/></domain:add></domain:update></update><clTRID>T.ST.ADD.001</clTRID></command></epp>"

run_raw "Add clientDeleteProhibited" \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><update><domain:update xmlns:domain=\"urn:ietf:params:xml:ns:domain-1.0\"><domain:name>${DOMAIN1}</domain:name><domain:add><domain:status s=\"clientDeleteProhibited\"/></domain:add></domain:update></update><clTRID>T.ST.ADD.002</clTRID></command></epp>"

run_raw "Add clientRenewProhibited" \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><update><domain:update xmlns:domain=\"urn:ietf:params:xml:ns:domain-1.0\"><domain:name>${DOMAIN1}</domain:name><domain:add><domain:status s=\"clientRenewProhibited\"/></domain:add></domain:update></update><clTRID>T.ST.ADD.003</clTRID></command></epp>"

run_raw "Add clientUpdateProhibited" \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><update><domain:update xmlns:domain=\"urn:ietf:params:xml:ns:domain-1.0\"><domain:name>${DOMAIN1}</domain:name><domain:add><domain:status s=\"clientUpdateProhibited\"/></domain:add></domain:update></update><clTRID>T.ST.ADD.004</clTRID></command></epp>"

run_raw "Domain Info (verify all statuses)" \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><info><domain:info xmlns:domain=\"urn:ietf:params:xml:ns:domain-1.0\"><domain:name hosts=\"all\">${DOMAIN1}</domain:name></domain:info></info><clTRID>T.ST.INF.001</clTRID></command></epp>"

run_raw "Remove clientUpdateProhibited" \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><update><domain:update xmlns:domain=\"urn:ietf:params:xml:ns:domain-1.0\"><domain:name>${DOMAIN1}</domain:name><domain:rem><domain:status s=\"clientUpdateProhibited\"/></domain:rem></domain:update></update><clTRID>T.ST.REM.001</clTRID></command></epp>"

run_raw "Remove clientRenewProhibited" \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><update><domain:update xmlns:domain=\"urn:ietf:params:xml:ns:domain-1.0\"><domain:name>${DOMAIN1}</domain:name><domain:rem><domain:status s=\"clientRenewProhibited\"/></domain:rem></domain:update></update><clTRID>T.ST.REM.002</clTRID></command></epp>"

run_raw "Remove clientDeleteProhibited" \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><update><domain:update xmlns:domain=\"urn:ietf:params:xml:ns:domain-1.0\"><domain:name>${DOMAIN1}</domain:name><domain:rem><domain:status s=\"clientDeleteProhibited\"/></domain:rem></domain:update></update><clTRID>T.ST.REM.003</clTRID></command></epp>"

run_raw "Remove clientHold" \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><update><domain:update xmlns:domain=\"urn:ietf:params:xml:ns:domain-1.0\"><domain:name>${DOMAIN1}</domain:name><domain:rem><domain:status s=\"clientHold\"/></domain:rem></domain:update></update><clTRID>T.ST.REM.004</clTRID></command></epp>"

run_raw "Domain Info (verify statuses cleared)" \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><info><domain:info xmlns:domain=\"urn:ietf:params:xml:ns:domain-1.0\"><domain:name hosts=\"all\">${DOMAIN1}</domain:name></domain:info></info><clTRID>T.ST.INF.002</clTRID></command></epp>"

# =============================================================================
# PHASE 5: DOMAIN UPDATE (contacts, nameservers, authInfo)
# =============================================================================
log ""
log "${YLW}═══════════════════════════════════════════${NC}"
log "${YLW}  PHASE 5: DOMAIN UPDATE (general)${NC}"
log "${YLW}═══════════════════════════════════════════${NC}"

run_raw "Domain Update - change auth password" \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><update><domain:update xmlns:domain=\"urn:ietf:params:xml:ns:domain-1.0\"><domain:name>${DOMAIN1}</domain:name><domain:chg><domain:authInfo><domain:pw>Nw99!@Pw55#\$Cd77</domain:pw></domain:authInfo></domain:chg></domain:update></update><clTRID>T.DOM.UPD.001</clTRID></command></epp>"

# =============================================================================
# PHASE 6: DOMAIN RENEW
# =============================================================================
log ""
log "${YLW}═══════════════════════════════════════════${NC}"
log "${YLW}  PHASE 6: DOMAIN RENEW${NC}"
log "${YLW}═══════════════════════════════════════════${NC}"

# Extract current expiry date from domain info
run_raw "Domain Info (get expiry for renew)" \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><info><domain:info xmlns:domain=\"urn:ietf:params:xml:ns:domain-1.0\"><domain:name hosts=\"all\">${DOMAIN1}</domain:name></domain:info></info><clTRID>T.RNW.INF.001</clTRID></command></epp>"

set +o pipefail
EXPIRY=$(echo "$LAST_OUTPUT" | grep -oP '<domain:exDate>\K[^<]+' | head -1 | cut -dT -f1)
set -o pipefail

if [ -n "$EXPIRY" ]; then
    log "  Extracted expiry: ${EXPIRY}"
    run_raw "Domain Renew ${DOMAIN1} (1 year)" \
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><renew><domain:renew xmlns:domain=\"urn:ietf:params:xml:ns:domain-1.0\"><domain:name>${DOMAIN1}</domain:name><domain:curExpDate>${EXPIRY}</domain:curExpDate><domain:period unit=\"y\">1</domain:period></domain:renew></renew><clTRID>T.DOM.RNW.001</clTRID></command></epp>"
else
    log "  ${YLW}SKIP${NC} - Could not extract expiry date"
    SKIP=$((SKIP + 1))
fi

# =============================================================================
# PHASE 7: DOMAIN TRANSFER
# Cancel any pending transfer first, then request fresh
# =============================================================================
log ""
log "${YLW}═══════════════════════════════════════════${NC}"
log "${YLW}  PHASE 7: DOMAIN TRANSFER (${TRANSFER_DOMAIN})${NC}"
log "${YLW}═══════════════════════════════════════════${NC}"

run_raw "Domain Info (before transfer)" \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><info><domain:info xmlns:domain=\"urn:ietf:params:xml:ns:domain-1.0\"><domain:name hosts=\"all\">${TRANSFER_DOMAIN}</domain:name></domain:info></info><clTRID>T.TR.INF.001</clTRID></command></epp>"

# Cancel any pending transfer from a previous test run (ignore errors)
log ""
log "  (Cancelling any stale pending transfer...)"
set +e
epp raw "<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><transfer op=\"cancel\"><domain:transfer xmlns:domain=\"urn:ietf:params:xml:ns:domain-1.0\"><domain:name>${TRANSFER_DOMAIN}</domain:name></domain:transfer></transfer><clTRID>T.TR.CLEANUP</clTRID></command></epp>" --pretty >> "$LOG_FILE" 2>&1
set -e
sleep 0.5

run_raw "Transfer Request" \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><transfer op=\"request\"><domain:transfer xmlns:domain=\"urn:ietf:params:xml:ns:domain-1.0\"><domain:name>${TRANSFER_DOMAIN}</domain:name><domain:authInfo><domain:pw>${TRANSFER_AUTH}</domain:pw></domain:authInfo></domain:transfer></transfer><clTRID>T.TR.REQ.001</clTRID></command></epp>" \
    "1001"

run_raw "Transfer Query" \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><transfer op=\"query\"><domain:transfer xmlns:domain=\"urn:ietf:params:xml:ns:domain-1.0\"><domain:name>${TRANSFER_DOMAIN}</domain:name><domain:authInfo><domain:pw>${TRANSFER_AUTH}</domain:pw></domain:authInfo></domain:transfer></transfer><clTRID>T.TR.QRY.001</clTRID></command></epp>"

# =============================================================================
# PHASE 8: POLL (request + ack)
# =============================================================================
log ""
log "${YLW}═══════════════════════════════════════════${NC}"
log "${YLW}  PHASE 8: POLL${NC}"
log "${YLW}═══════════════════════════════════════════${NC}"

run_raw "Poll Request" \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><poll op=\"req\"/><clTRID>T.POLL.REQ.001</clTRID></command></epp>" \
    "1301"

set +o pipefail
MSG_ID=$(echo "$LAST_OUTPUT" | grep -oP 'id="\K[0-9]+' | head -1 || echo "")
set -o pipefail

if [ -n "$MSG_ID" ]; then
    log "  Extracted msgID: ${MSG_ID}"

    run_raw "Poll Ack (msgID=${MSG_ID})" \
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><poll op=\"ack\" msgID=\"${MSG_ID}\"/><clTRID>T.POLL.ACK.001</clTRID></command></epp>"

    run_raw "Poll Request (next)" \
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><poll op=\"req\"/><clTRID>T.POLL.REQ.002</clTRID></command></epp>" \
        "1301"
else
    log "  ${YLW}No msgID found — skipping ack${NC}"
    SKIP=$((SKIP + 1))
fi

# =============================================================================
# PHASE 9: TRANSFER CANCEL (requesting registrar cancels own request)
# =============================================================================
log ""
log "${YLW}═══════════════════════════════════════════${NC}"
log "${YLW}  PHASE 9: TRANSFER CANCEL${NC}"
log "${YLW}═══════════════════════════════════════════${NC}"

run_raw "Transfer Cancel ${TRANSFER_DOMAIN}" \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><transfer op=\"cancel\"><domain:transfer xmlns:domain=\"urn:ietf:params:xml:ns:domain-1.0\"><domain:name>${TRANSFER_DOMAIN}</domain:name></domain:transfer></transfer><clTRID>T.TR.CAN.001</clTRID></command></epp>"

run_raw "Domain Info (after transfer cancel)" \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><info><domain:info xmlns:domain=\"urn:ietf:params:xml:ns:domain-1.0\"><domain:name hosts=\"all\">${TRANSFER_DOMAIN}</domain:name></domain:info></info><clTRID>T.TR.INF.002</clTRID></command></epp>"

# =============================================================================
# PHASE 10: DOMAIN DELETE
# =============================================================================
log ""
log "${YLW}═══════════════════════════════════════════${NC}"
log "${YLW}  PHASE 10: DOMAIN DELETE${NC}"
log "${YLW}═══════════════════════════════════════════${NC}"

run_raw "Domain Delete ${DOMAIN2}" \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><delete><domain:delete xmlns:domain=\"urn:ietf:params:xml:ns:domain-1.0\"><domain:name>${DOMAIN2}</domain:name></domain:delete></delete><clTRID>T.DOM.DEL.001</clTRID></command></epp>"

run_raw "Domain Delete ${DOMAIN1}" \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><delete><domain:delete xmlns:domain=\"urn:ietf:params:xml:ns:domain-1.0\"><domain:name>${DOMAIN1}</domain:name></domain:delete></delete><clTRID>T.DOM.DEL.002</clTRID></command></epp>"

# =============================================================================
# PHASE 11: HOST DELETE (subordinate hosts, removed from domain NS already)
# =============================================================================
log ""
log "${YLW}═══════════════════════════════════════════${NC}"
log "${YLW}  PHASE 11: HOST DELETE${NC}"
log "${YLW}═══════════════════════════════════════════${NC}"

run_raw "Host Delete ${HOST1}" \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><delete><host:delete xmlns:host=\"urn:ietf:params:xml:ns:host-1.0\"><host:name>${HOST1}</host:name></host:delete></delete><clTRID>T.HOS.DEL.001</clTRID></command></epp>"

# Remove status before deleting HOST2
run_raw "Host Update ${HOST2} (remove status before delete)" \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><update><host:update xmlns:host=\"urn:ietf:params:xml:ns:host-1.0\"><host:name>${HOST2}</host:name><host:rem><host:status s=\"clientUpdateProhibited\"/></host:rem></host:update></update><clTRID>T.HOS.UPD.002</clTRID></command></epp>"

run_raw "Host Delete ${HOST2}" \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><delete><host:delete xmlns:host=\"urn:ietf:params:xml:ns:host-1.0\"><host:name>${HOST2}</host:name></host:delete></delete><clTRID>T.HOS.DEL.002</clTRID></command></epp>"

# =============================================================================
# PHASE 12: CONTACT DELETE
# =============================================================================
log ""
log "${YLW}═══════════════════════════════════════════${NC}"
log "${YLW}  PHASE 12: CONTACT DELETE${NC}"
log "${YLW}═══════════════════════════════════════════${NC}"

run_raw "Contact Delete ${CONTACT1}" \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><delete><contact:delete xmlns:contact=\"urn:ietf:params:xml:ns:contact-1.0\"><contact:id>${CONTACT1}</contact:id></contact:delete></delete><clTRID>T.CON.DEL.001</clTRID></command></epp>"

run_raw "Contact Delete ${CONTACT2}" \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"><command><delete><contact:delete xmlns:contact=\"urn:ietf:params:xml:ns:contact-1.0\"><contact:id>${CONTACT2}</contact:id></contact:delete></delete><clTRID>T.CON.DEL.002</clTRID></command></epp>"

# =============================================================================
# RESULTS
# =============================================================================
log ""
log "============================================================"
log "  TEST RESULTS"
log "============================================================"
log "  ${GRN}PASSED  : ${PASS}${NC}"
log "  ${RED}FAILED  : ${FAIL}${NC}"
log "  ${YLW}SKIPPED : ${SKIP}${NC}"
log "  TOTAL   : ${TOTAL}"
log "============================================================"
log "  Log: ${LOG_FILE}"
log "============================================================"

if [ $FAIL -gt 0 ]; then
    log ""
    log "${RED}Some tests failed! Check log for details.${NC}"
    exit 1
else
    log ""
    log "${GRN}All tests passed!${NC}"
    exit 0
fi
