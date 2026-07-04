#!/bin/bash
#
# UCS Backup -> Primary Promotion Wrapper  (backup2master)
# Author: Jason Cheng (Jason Tools)
# jason@jason.tools
# www.jason.tools
# ------------------------------------------------------------
# !!! DESTRUCTIVE / ONE-WAY / DISASTER-RECOVERY ONLY !!!
#
# Purpose:
#   Safely drive `univention-backup2master`, which promotes a BACKUP Directory
#   Node to become the new PRIMARY when the old Primary is permanently gone.
#   This wrapper adds the guard rails the bare command lacks:
#     - refuses to run unless THIS node is a Backup Directory Node
#     - SPLIT-BRAIN guard: aborts if the old Primary still answers on the network
#     - dry-run, explicit typed confirmation, and post-promotion verification
#
#   Promotion is IRREVERSIBLE and changes the whole domain. Only proceed once you
#   are certain the old Primary will never return. Do NOT run this to "test".
#
# Usage:
#   ./jt-ucs-backup2master.sh -n        # dry-run: preflight + show plan, no change
#   ./jt-ucs-backup2master.sh           # real promotion (guarded, needs confirmation)
#   ./jt-ucs-backup2master.sh --force-old-master-gone   # skip reachability abort
#                                                       # (only if you KNOW it is dead)
#
# Note: run as root ON THE BACKUP NODE you want to promote.
# ------------------------------------------------------------

set -o pipefail

C_RESET='\033[0m'; C_INFO='\033[1;34m'; C_OK='\033[1;32m'
C_WARN='\033[1;33m'; C_ERR='\033[1;31m'; C_ASK='\033[1;36m'
info()  { echo -e "${C_INFO}[INFO]${C_RESET} $*"; }
ok()    { echo -e "${C_OK}[ OK ]${C_RESET} $*"; }
warn()  { echo -e "${C_WARN}[WARN]${C_RESET} $*"; }
err()   { echo -e "${C_ERR}[FAIL]${C_RESET} $*" >&2; }

DRY_RUN=0
FORCE_GONE=0
for a in "$@"; do
    case "$a" in
        -n|--dry-run)            DRY_RUN=1 ;;
        --force-old-master-gone) FORCE_GONE=1 ;;
        -h|--help) grep -E '^# ' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) err "Unknown option: $a"; exit 2 ;;
    esac
done

# ---- pre-checks ----
if [[ $EUID -ne 0 ]]; then err "This script must be run as root."; exit 2; fi
command -v ucr >/dev/null 2>&1 || { err "ucr not found. Is this a UCS system?"; exit 2; }

ROLE="$(ucr get server/role 2>/dev/null)"
OLD_MASTER="$(ucr get ldap/master 2>/dev/null)"
FQDN="$(hostname -f 2>/dev/null)"
DOMAIN="$(ucr get domainname 2>/dev/null)"

# ============================================================
# Guard 1: must be a Backup Directory Node
# ============================================================
if [[ "$ROLE" != "domaincontroller_backup" ]]; then
    err "This node's role is '${ROLE:-unknown}', not 'domaincontroller_backup'."
    err "backup2master promotion must be run ON THE BACKUP NODE you want to promote."
    exit 2
fi
ok "Role check: this is a Backup Directory Node."

echo
info "===== Promotion context ====="
echo "   this node (to become Primary): ${FQDN}"
echo "   old Primary (ldap/master)    : ${OLD_MASTER}"
echo "   domain                       : ${DOMAIN}"
echo

# ============================================================
# Guard 2: split-brain — is the old Primary still alive?
# ============================================================
info "Checking whether the old Primary '${OLD_MASTER}' still responds ..."
REACHABLE=0
if ping -c1 -W2 "$OLD_MASTER" >/dev/null 2>&1; then
    REACHABLE=1; warn "  old Primary answers ICMP ping."
fi
if command -v ldapsearch >/dev/null 2>&1 \
        && ldapsearch -x -H "ldap://${OLD_MASTER}" -b "" -s base -LLL >/dev/null 2>&1; then
    REACHABLE=1; warn "  old Primary answers LDAP (port 389)."
fi

if [[ $REACHABLE -eq 1 ]]; then
    err "The old Primary appears to be ALIVE on the network."
    err "Promoting now would create TWO Primaries (split-brain) and corrupt the domain."
    if [[ $FORCE_GONE -eq 1 ]]; then
        warn "--force-old-master-gone given; continuing despite reachability. BE SURE."
    else
        err "Aborting. Shut the old Primary down permanently first, or pass"
        err "--force-old-master-gone only if you are certain it is dead."
        exit 1
    fi
else
    ok "Old Primary does not respond (ping/LDAP) — no split-brain detected."
fi

# ============================================================
# Plan / dry-run
# ============================================================
echo
info "===== Plan ====="
echo "   1. Run: univention-backup2master"
echo "   2. Re-run join scripts if prompted"
echo "   3. Verify role/notifier/S4 connector/sysvol afterwards"
echo

if [[ $DRY_RUN -eq 1 ]]; then
    ok "Dry-run only — no changes made. Re-run without -n to promote."
    exit 0
fi

# ============================================================
# Confirmation gate (typed)
# ============================================================
warn "This is IRREVERSIBLE and changes the entire domain."
echo -ne "${C_ASK}[ASK ]${C_RESET} Type the FQDN of THIS node (${FQDN}) to proceed: "
read -r CONFIRM
if [[ "$CONFIRM" != "$FQDN" ]]; then
    err "Confirmation did not match. Aborting — no changes made."
    exit 1
fi

# ============================================================
# Execute
# ============================================================
if ! command -v univention-backup2master >/dev/null 2>&1; then
    err "univention-backup2master not found."
    err "Install it first:  univention-install univention-server-backup"
    err "Docs: https://docs.software-univention.de/  (Backup Directory Node promotion)"
    exit 2
fi

info "Running univention-backup2master ..."
if univention-backup2master; then
    ok "backup2master finished."
else
    err "backup2master returned an error — review its output above."
    err "Do NOT bring the old Primary back online. Consult Univention support/docs."
    exit 1
fi

# ============================================================
# Post-checks
# ============================================================
echo
info "===== Post-promotion checks ====="
NEW_ROLE="$(ucr get server/role 2>/dev/null)"
if [[ "$NEW_ROLE" == "domaincontroller_master" ]]; then
    ok "server/role is now domaincontroller_master."
else
    warn "server/role is '${NEW_ROLE}' — expected domaincontroller_master. Investigate."
fi
for svc in slapd univention-directory-notifier univention-directory-listener; do
    printf "   %s: " "$svc"; systemctl is-active "$svc" 2>/dev/null || echo "not-active"
done
echo
info "Follow-up:"
echo "   * Run the listener/notifier health check: jt-ucs-listener-health.sh"
echo "   * Check S4 Connector rejects:            jt-ucs-ldap-audit.sh"
echo "   * Verify Samba FSMO roles:               samba-tool fsmo show"
echo "   * Re-join / update other nodes to point at the new Primary."
echo
ok "Promotion workflow complete."
