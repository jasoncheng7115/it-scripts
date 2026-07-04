#!/bin/bash
#
# UCS Primary Directory Node Restore-from-Snapshot  (runbook)
# Author: Jason Cheng (Jason Tools)
# jason@jason.tools
# www.jason.tools
# ------------------------------------------------------------
# !!! DESTRUCTIVE / DISASTER-RECOVERY ONLY — LAB or REPLACEMENT NODE !!!
#
# Purpose:
#   Rebuild a PRIMARY Directory Node from a jt-ucs-snapshot.sh restore point onto
#   a FRESH / REPLACEMENT machine (same UCS version, same hostname/role intent)
#   when the original Primary is unrecoverable AND you have no Backup node to
#   promote. This restores: SSL CA + /etc/univention, secrets, OpenLDAP, and
#   guides the Samba AD DB restore.
#
#   By DEFAULT this only PRINTS the runbook (dry-run). Nothing is changed unless
#   you pass --execute, and every destructive phase then asks for confirmation.
#
#   NEVER run --execute against a healthy, populated Primary: it refuses if the
#   local OpenLDAP already holds a directory (override only with --force-wipe).
#
# Usage:
#   ./jt-ucs-pdn-restore.sh                       # print runbook for newest snapshot
#   ./jt-ucs-pdn-restore.sh --snapshot <dir>      # choose a snapshot
#   ./jt-ucs-pdn-restore.sh --snapshot <dir> --execute   # actually restore (guarded)
#
# Note: run as root on the replacement Primary node.
# ------------------------------------------------------------

set -o pipefail

SNAP_ROOT="/var/univention-backup/snapshots"
LDAP_DIR="/var/lib/univention-ldap/ldap"
SLAPD_CONF="/etc/ldap/slapd.conf"
LIVE_GUARD=50          # if local LDAP already has >= this many entries, refuse

C_RESET='\033[0m'; C_INFO='\033[1;34m'; C_OK='\033[1;32m'
C_WARN='\033[1;33m'; C_ERR='\033[1;31m'; C_ASK='\033[1;36m'
info()  { echo -e "${C_INFO}[INFO]${C_RESET} $*"; }
ok()    { echo -e "${C_OK}[ OK ]${C_RESET} $*"; }
warn()  { echo -e "${C_WARN}[WARN]${C_RESET} $*"; }
err()   { echo -e "${C_ERR}[FAIL]${C_RESET} $*" >&2; }
step()  { echo -e "\n${C_INFO}==== $* ====${C_RESET}"; }

EXECUTE=0
FORCE_WIPE=0
SNAP_DIR=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --execute)      EXECUTE=1 ;;
        --force-wipe)   FORCE_WIPE=1 ;;
        --snapshot)     SNAP_DIR="$2"; shift ;;
        -h|--help)      grep -E '^# ' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)              err "Unknown option: $1"; exit 2 ;;
    esac
    shift
done

if [[ $EUID -ne 0 ]]; then err "This script must be run as root."; exit 2; fi
command -v ucr >/dev/null 2>&1 || { err "ucr not found. Is this a UCS system?"; exit 2; }

# do_cmd "<human note>" "<command>" : print it; in --execute mode ask & run it.
do_cmd() {
    local note="$1" cmd="$2"
    echo -e "   ${C_INFO}#${C_RESET} ${note}"
    echo "     ${cmd}"
    if [[ $EXECUTE -eq 1 ]]; then
        echo -ne "     ${C_ASK}run this step? (y/n):${C_RESET} "
        read -r a
        if [[ "$a" =~ ^[Yy]$ ]]; then
            if eval "$cmd"; then ok "step done."; else err "step FAILED — stopping."; exit 1; fi
        else
            warn "skipped."
        fi
    fi
}

# ============================================================
# Locate + verify the snapshot
# ============================================================
if [[ -z "$SNAP_DIR" ]]; then
    SNAP_DIR="$(ls -1dt "${SNAP_ROOT}"/snapshot_* 2>/dev/null | head -1)"
    [[ -z "$SNAP_DIR" ]] && { err "No snapshots under ${SNAP_ROOT}; pass --snapshot <dir>."; exit 2; }
fi
SNAP_DIR="${SNAP_DIR%/}"
[[ -d "$SNAP_DIR" ]] || { err "Not a directory: $SNAP_DIR"; exit 2; }
info "Snapshot: $SNAP_DIR"

step "Phase 0 — verify snapshot is usable"
VERIFIER="$(command -v jt-ucs-snapshot-verify.sh || echo /opt/jt-ucs-snapshot-verify.sh)"
if [[ -x "$VERIFIER" ]]; then
    if "$VERIFIER" "$SNAP_DIR"; then ok "Snapshot verified."; else
        err "Snapshot verification FAILED — refusing to restore from a bad snapshot."; exit 1
    fi
else
    warn "jt-ucs-snapshot-verify.sh not found — doing minimal inline checks."
    gzip -t "$SNAP_DIR/openldap.ldif.gz" 2>/dev/null || { err "openldap.ldif.gz missing/corrupt."; exit 1; }
    tar tzf "$SNAP_DIR/configs.tar.gz" 2>/dev/null | grep -q 'etc/univention/ssl/ucsCA/CAcert.pem' \
        || { err "SSL CA not found in configs.tar.gz — unsafe to rebuild a Primary."; exit 1; }
    ok "Minimal checks passed."
fi

SAMBA_ARCHIVE="$(ls -1 "$SNAP_DIR"/samba/samba-backup-*.tar.bz2 2>/dev/null | head -1)"

# ============================================================
# Environment + live-directory guard
# ============================================================
step "Phase 0 — environment & safety guard"
ROLE="$(ucr get server/role 2>/dev/null)"
LDAP_BASE="$(ucr get ldap/base 2>/dev/null)"
FQDN="$(hostname -f 2>/dev/null)"
SHORT="$(hostname -s 2>/dev/null)"
echo "   role=${ROLE:-unset}  base=${LDAP_BASE:-unset}  fqdn=${FQDN}"

LIVE_COUNT=0
if systemctl is-active slapd >/dev/null 2>&1; then
    LIVE_COUNT="$(ldapsearch -x -H ldapi:/// -b "${LDAP_BASE:-}" dn 2>/dev/null | grep -c '^dn:')"
fi
info "Local OpenLDAP currently holds ${LIVE_COUNT} entries."
if [[ "$LIVE_COUNT" -ge $LIVE_GUARD ]]; then
    warn "This node already has a POPULATED directory (${LIVE_COUNT} entries)."
    warn "PDN restore WIPES OpenLDAP and is meant for a FRESH / replacement node."
    if [[ $FORCE_WIPE -eq 1 ]]; then
        warn "--force-wipe given; continuing anyway. This DESTROYS the current directory."
    else
        err "Refusing. Re-run with --force-wipe only if you truly mean to overwrite it."
        exit 1
    fi
fi

# ============================================================
# Runbook
# ============================================================
if [[ $EXECUTE -eq 0 ]]; then
    warn "DRY-RUN: printing the runbook only. Re-run with --execute to perform it."
else
    warn "EXECUTE mode: each destructive step will ask for confirmation."
    echo -ne "${C_ASK}[ASK ]${C_RESET} Type RESTORE to begin: "; read -r c
    [[ "$c" == "RESTORE" ]] || { err "Not confirmed. Aborting."; exit 1; }
fi

step "Phase 1 — restore SSL CA + /etc/univention + /etc/ldap"
warn "Overwrites config under /etc (SSL CA, UCR base.conf). Intended for a fresh node."
do_cmd "extract configs (etc/univention, etc/ldap, sysvol) to /" \
       "tar xzf '${SNAP_DIR}/configs.tar.gz' -C /"

step "Phase 2 — restore secrets"
do_cmd "extract ldap.secret / machine.secret to /" \
       "tar xzf '${SNAP_DIR}/secrets.tar.gz' -C /"

step "Phase 3 — restore OpenLDAP database (slapadd)"
do_cmd "stop the directory server" \
       "systemctl stop slapd"
do_cmd "move the current (empty/old) DB aside" \
       "mv '${LDAP_DIR}' '${LDAP_DIR}.pre-restore' && mkdir -p '${LDAP_DIR}'"
do_cmd "decompress the LDAP dump" \
       "zcat '${SNAP_DIR}/openldap.ldif.gz' > /tmp/pdn-restore.ldif"
do_cmd "load the dump into the DB" \
       "slapadd -q -f '${SLAPD_CONF}' -l /tmp/pdn-restore.ldif"
do_cmd "fix ownership" \
       "chown -R openldap:openldap '${LDAP_DIR}'"
do_cmd "rebuild indexes" \
       "slapindex -f '${SLAPD_CONF}' && chown -R openldap:openldap '${LDAP_DIR}'"
do_cmd "start the directory server" \
       "systemctl start slapd"
do_cmd "shred the temporary plaintext dump (contains hashes)" \
       "shred -u /tmp/pdn-restore.ldif"

step "Phase 4 — restore Samba AD DB   (MANUAL — not auto-run)"
if [[ -n "$SAMBA_ARCHIVE" ]]; then
    echo "   Samba restore is environment-specific; run it yourself and verify:"
    echo "     systemctl stop samba"
    echo "     mv /var/lib/samba /var/lib/samba.pre-restore"
    echo "     samba-tool domain backup restore \\"
    echo "         --backup-file='${SAMBA_ARCHIVE}' \\"
    echo "         --newservername='${SHORT}' --targetdir=/var/lib/samba"
    echo "     # then reconcile paths per Univention docs, and:"
    echo "     systemctl start samba"
else
    info "No Samba backup in this snapshot — skip if this is not an AD DC."
fi

step "Phase 5 — bring services back & reconcile"
do_cmd "restart notifier + listener" \
       "systemctl restart univention-directory-notifier univention-directory-listener"
do_cmd "re-run join scripts" \
       "univention-run-join-scripts"
echo "   # then validate:"
echo "     jt-ucs-listener-health.sh"
echo "     jt-ucs-ldap-audit.sh"
echo "     samba-tool fsmo show          # if AD DC"

echo
if [[ $EXECUTE -eq 0 ]]; then
    ok "Runbook printed (dry-run). Review carefully, then re-run with --execute on the replacement node."
else
    ok "Restore steps completed (those you confirmed). Validate with the checks above."
    warn "Old DB kept at ${LDAP_DIR}.pre-restore — remove once verified."
fi
