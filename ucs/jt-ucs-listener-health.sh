#!/bin/bash
#
# UCS Listener / Notifier Health Check (read-only)
# Author: Jason Cheng (Jason Tools)
# jason@jason.tools
# www.jason.tools
# ------------------------------------------------------------
# Purpose:
#   Read-only check of the Univention Directory Listener/Notifier replication
#   pipeline — the mechanism that turns LDAP changes into local actions and
#   propagates them to replicas / the S4 connector. When it stalls, UMC changes
#   silently stop taking effect. This tool NEVER writes anything.
#
# Checks:
#   1. univention-directory-listener / -notifier services are active
#   2. Notifier transaction ID vs the ID last processed by the local Listener
#      (the "lag"); re-samples to tell "catching up" from "stuck"
#   3. Failed handler LDIF (failed.ldif) present?
#
# Usage:
#   ./jt-ucs-listener-health.sh           # human-readable report
#   ./jt-ucs-listener-health.sh -q        # quiet: issues + summary only
#
# Exit code: 0 = healthy, 1 = problem found, 2 = setup error.
# Suitable for cron / monitoring.
#
# Note: run as root on a UCS Directory Node.
# ------------------------------------------------------------

set -o pipefail

LISTENER_ID_FILE="/var/lib/univention-directory-listener/notifier_id"
FAILED_LDIF="/var/lib/univention-directory-listener/failed.ldif"
RESAMPLE_WAIT=3      # seconds between lag samples to detect movement

C_RESET='\033[0m'; C_INFO='\033[1;34m'; C_OK='\033[1;32m'
C_WARN='\033[1;33m'; C_ERR='\033[1;31m'
info()  { echo -e "${C_INFO}[INFO]${C_RESET} $*"; }
ok()    { echo -e "${C_OK}[ OK ]${C_RESET} $*"; }
warn()  { echo -e "${C_WARN}[WARN]${C_RESET} $*"; }
err()   { echo -e "${C_ERR}[FAIL]${C_RESET} $*" >&2; }

QUIET=0
[[ "$1" == "-q" || "$1" == "--quiet" ]] && QUIET=1

if [[ $EUID -ne 0 ]]; then err "This script must be run as root."; exit 2; fi
command -v univention-directory-listener-ctrl >/dev/null 2>&1 \
    || { err "univention-directory-listener-ctrl not found. Is this a UCS Directory Node?"; exit 2; }

ROLE="$(ucr get server/role 2>/dev/null)"
[[ $QUIET -eq 0 ]] && info "Server role: ${ROLE:-unknown}"

ISSUES=0

# ============================================================
# 1. Services active
# ============================================================
for svc in univention-directory-listener univention-directory-notifier; do
    # The notifier normally runs only on Primary/Backup nodes.
    if [[ "$svc" == "univention-directory-notifier" \
          && "$ROLE" != "domaincontroller_master" \
          && "$ROLE" != "domaincontroller_backup" ]]; then
        continue
    fi
    state="$(systemctl is-active "$svc" 2>/dev/null)"
    if [[ "$state" == "active" ]]; then
        [[ $QUIET -eq 0 ]] && ok "service ${svc}: active"
    else
        err "service ${svc}: ${state:-not-active}"
        ISSUES=$((ISSUES+1))
    fi
done

# ============================================================
# 2. Notifier vs Listener transaction ID (lag)
# ============================================================
STATUS="$(univention-directory-listener-ctrl status 2>/dev/null)"
# "Current Notifier ID ...\n <num>" — grab the number on the following line.
CUR="$(echo "$STATUS"  | awk '/Current Notifier ID/{getline; gsub(/[^0-9]/,""); print; exit}')"
LAST="$(echo "$STATUS" | awk '/Last Notifier ID processed/{getline; gsub(/[^0-9]/,""); print; exit}')"
# Fallback to the raw file for the locally-processed ID.
[[ -z "$LAST" && -r "$LISTENER_ID_FILE" ]] && LAST="$(tr -dc '0-9' < "$LISTENER_ID_FILE")"

if [[ -z "$CUR" || -z "$LAST" ]]; then
    err "Could not read Notifier/Listener IDs (notifier down or master unreachable?)."
    [[ $QUIET -eq 0 ]] && echo "$STATUS" | sed 's/^/   /'
    ISSUES=$((ISSUES+1))
else
    LAG=$(( CUR - LAST ))
    if [[ $LAG -le 0 ]]; then
        ok "Replication in sync (Notifier=${CUR}, Listener=${LAST}, lag=0)."
    else
        # Behind — re-sample to distinguish "catching up" from "stuck".
        info "Listener behind by ${LAG} (Notifier=${CUR}, Listener=${LAST}); re-sampling in ${RESAMPLE_WAIT}s ..."
        sleep "$RESAMPLE_WAIT"
        LAST2="$(tr -dc '0-9' < "$LISTENER_ID_FILE" 2>/dev/null)"
        if [[ -n "$LAST2" && "$LAST2" -gt "$LAST" ]]; then
            warn "Listener is BEHIND but catching up (advanced ${LAST}→${LAST2}). Re-check shortly."
            ISSUES=$((ISSUES+1))
        else
            err "Listener appears STUCK — behind by ${LAG} and not advancing (still ${LAST})."
            err "  Try: systemctl restart univention-directory-listener"
            err "  Or resync a module: univention-directory-listener-ctrl resync <module>"
            ISSUES=$((ISSUES+1))
        fi
    fi
fi

# ============================================================
# 3. Failed handler LDIF
# ============================================================
if [[ -s "$FAILED_LDIF" ]]; then
    err "Failed handler transactions present: ${FAILED_LDIF} ($(wc -l < "$FAILED_LDIF") lines)."
    err "  A module failed to process a change — inspect the file and listener.log."
    ISSUES=$((ISSUES+1))
else
    [[ $QUIET -eq 0 ]] && ok "No failed handler LDIF."
fi

# ============================================================
# Summary
# ============================================================
echo
if [[ $ISSUES -eq 0 ]]; then
    ok "Listener/Notifier healthy."
    exit 0
else
    err "Listener/Notifier check found ${ISSUES} issue(s). See [WARN]/[FAIL] above."
    exit 1
fi
