#!/bin/bash
#
# UCS Pre-Change Snapshot Tool
# Author: Jason Cheng (Jason Tools)
# jason@jason.tools
# www.jason.tools
# ------------------------------------------------------------
# Purpose:
#   Take a consistent restore point BEFORE doing anything risky (bulk edits,
#   upgrades, connector changes). Captures the directory + config so you can
#   recover if something goes wrong.
#
# Captured into  /var/univention-backup/snapshots/snapshot_<timestamp>/ :
#   - openldap.ldif.gz     : full OpenLDAP dump (slapcat)
#   - ucr.txt              : UCR variables (ucr dump)
#   - configs.tar.gz       : /etc/univention, /etc/ldap, Samba sysvol
#   - secrets.tar.gz       : /etc/ldap.secret, /etc/machine.secret (sensitive!)
#   - samba/               : samba-tool domain backup offline (Samba4 AD DCs)
#   - packages.txt         : dpkg selections + UCS version + server role
#   - MANIFEST.txt         : metadata + sha256 of every file
#
# This tool is READ-ONLY with respect to running services — it only writes new
# files. It does NOT modify LDAP/Samba.
#
# Usage:
#   ./jt-ucs-snapshot.sh                 # snapshot with auto timestamp
#   ./jt-ucs-snapshot.sh <label>         # append a label to the snapshot dir
#
# Note: run as root on a UCS Directory Node.
# ------------------------------------------------------------

set -o pipefail

BACKUP_DIR="/var/univention-backup"
SNAP_ROOT="${BACKUP_DIR}/snapshots"

C_RESET='\033[0m'; C_INFO='\033[1;34m'; C_OK='\033[1;32m'
C_WARN='\033[1;33m'; C_ERR='\033[1;31m'
info()  { echo -e "${C_INFO}[INFO]${C_RESET} $*"; }
ok()    { echo -e "${C_OK}[ OK ]${C_RESET} $*"; }
warn()  { echo -e "${C_WARN}[WARN]${C_RESET} $*"; }
err()   { echo -e "${C_ERR}[FAIL]${C_RESET} $*" >&2; }

# ---- pre-checks ----
if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root."
    exit 1
fi
for cmd in slapcat gzip tar ucr sha256sum dpkg; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        err "Required command not found: ${cmd}"
        exit 1
    fi
done

LABEL="$1"
TS="$(date +%Y%m%d-%H%M%S)"
SNAP_NAME="snapshot_${TS}${LABEL:+_${LABEL}}"
SNAP_DIR="${SNAP_ROOT}/${SNAP_NAME}"

# Refuse to clobber; create with tight perms (contains secrets/hashes).
if [[ -e "$SNAP_DIR" ]]; then
    err "Snapshot dir already exists: $SNAP_DIR"
    exit 1
fi
umask 077
mkdir -p "$SNAP_DIR"
chmod 700 "$SNAP_ROOT" "$SNAP_DIR"
info "Snapshot directory: $SNAP_DIR"

# Free-space heads-up (informational only).
AVAIL_KB="$(df -Pk "$SNAP_ROOT" | awk 'NR==2{print $4}')"
info "Free space on target: $(( AVAIL_KB / 1024 )) MB"

FAILED=0

# ---- 1. OpenLDAP dump ----
info "[1/6] Dumping OpenLDAP (slapcat) ..."
if slapcat 2>/dev/null | gzip > "${SNAP_DIR}/openldap.ldif.gz"; then
    ok "OpenLDAP dumped ($(du -h "${SNAP_DIR}/openldap.ldif.gz" | cut -f1))."
else
    err "slapcat failed."; FAILED=1
fi

# ---- 2. UCR variables ----
info "[2/6] Saving UCR variables ..."
if ucr dump > "${SNAP_DIR}/ucr.txt" 2>/dev/null; then
    ok "UCR saved ($(wc -l < "${SNAP_DIR}/ucr.txt") vars)."
else
    warn "ucr dump failed."; FAILED=1
fi

# ---- 3. Config directories + sysvol ----
info "[3/6] Archiving config dirs (/etc/univention, /etc/ldap, sysvol) ..."
SYSVOL=""
[[ -d /var/lib/samba/sysvol ]] && SYSVOL="/var/lib/samba/sysvol"
if tar czf "${SNAP_DIR}/configs.tar.gz" \
        --ignore-failed-read \
        /etc/univention /etc/ldap ${SYSVOL} 2>/dev/null; then
    ok "Configs archived ($(du -h "${SNAP_DIR}/configs.tar.gz" | cut -f1))."
else
    warn "config tar reported errors (some paths may not exist)."
fi

# ---- 4. Secrets ----
info "[4/6] Archiving secrets (sensitive) ..."
SECRETS=()
for s in /etc/ldap.secret /etc/machine.secret; do
    [[ -f "$s" ]] && SECRETS+=("$s")
done
if [[ ${#SECRETS[@]} -gt 0 ]] && tar czf "${SNAP_DIR}/secrets.tar.gz" "${SECRETS[@]}" 2>/dev/null; then
    chmod 600 "${SNAP_DIR}/secrets.tar.gz"
    ok "Secrets archived."
else
    warn "No secrets archived."
fi

# ---- 5. Samba domain backup (AD DC only) ----
info "[5/6] Samba domain backup (if this is a Samba4 AD DC) ..."
if command -v samba-tool >/dev/null 2>&1 && [[ -n "$(ucr get samba4/ldap/base 2>/dev/null)" ]]; then
    mkdir -p "${SNAP_DIR}/samba"
    if samba-tool domain backup offline --targetdir="${SNAP_DIR}/samba" >"${SNAP_DIR}/samba/backup.log" 2>&1; then
        ok "Samba offline backup done ($(du -sh "${SNAP_DIR}/samba" | cut -f1))."
    else
        warn "samba-tool domain backup failed — see ${SNAP_DIR}/samba/backup.log"
        warn "Fallback: copying raw private dir with tdbbackup ..."
        if tar czf "${SNAP_DIR}/samba/private-raw.tar.gz" /var/lib/samba/private 2>/dev/null; then
            ok "Raw Samba private dir archived (may be less consistent)."
        else
            err "Samba fallback also failed."; FAILED=1
        fi
    fi
else
    info "Not a Samba4 AD DC (or samba-tool absent) — skipping Samba backup."
fi

# ---- 6. Package/version/role metadata + manifest ----
info "[6/6] Recording metadata and checksums ..."
{
    echo "hostname:    $(hostname -f 2>/dev/null)"
    echo "server/role: $(ucr get server/role 2>/dev/null)"
    echo "ldap/base:   $(ucr get ldap/base 2>/dev/null)"
    echo "UCS version: $(ucr get version/version 2>/dev/null)-$(ucr get version/patchlevel 2>/dev/null) (erratum $(ucr get version/erratum 2>/dev/null))"
    echo
    echo "== dpkg selections =="
    dpkg --get-selections 2>/dev/null
} > "${SNAP_DIR}/packages.txt"

{
    echo "UCS Pre-Change Snapshot"
    echo "created:     ${TS}"
    echo "hostname:    $(hostname -f 2>/dev/null)"
    echo "server/role: $(ucr get server/role 2>/dev/null)"
    echo "ldap/base:   $(ucr get ldap/base 2>/dev/null)"
    echo
    echo "== files (sha256) =="
    ( cd "$SNAP_DIR" && find . -type f ! -name MANIFEST.txt -exec sha256sum {} \; )
} > "${SNAP_DIR}/MANIFEST.txt"
ok "Manifest written."

echo
if [[ $FAILED -eq 0 ]]; then
    ok "Snapshot complete: ${SNAP_DIR} (total $(du -sh "$SNAP_DIR" | cut -f1))"
else
    warn "Snapshot finished WITH ERRORS — review the messages above: ${SNAP_DIR}"
fi

echo
info "===== Restore hints (manual, use with care) ====="
echo "   * OpenLDAP objects : recover single objects with the *-recovery.sh tools"
echo "     using this dump, or for full rebuild: slapadd from openldap.ldif.gz"
echo "     (directory server stopped) — do this only during PDN recovery."
echo "   * Samba AD DB      : samba-tool domain backup restore --backup-file=... "
echo "     (see ${SNAP_DIR}/samba/) — full DC restore procedure only."
echo "   * UCR / configs    : reference ucr.txt and configs.tar.gz; do NOT blindly"
echo "     overwrite /etc on a running system."
echo "   * secrets.tar.gz contains ldap.secret/machine.secret — keep it protected."
echo
warn "This snapshot contains password hashes and secrets. Store/rotate securely;"
warn "shred old snapshots you no longer need:  rm -rf <snapshot dir>"
