#!/bin/bash
#
# UCS Snapshot Completeness Verifier (read-only)
# Author: Jason Cheng (Jason Tools)
# jason@jason.tools
# www.jason.tools
# ------------------------------------------------------------
# Purpose:
#   Verify that a snapshot produced by jt-ucs-snapshot.sh is actually usable for
#   recovery BEFORE you rely on it. Catches truncated dumps, corrupt archives,
#   checksum drift, and — the classic PDN-recovery trap — a MISSING SSL CA
#   (/etc/univention/ssl/ucsCA), without which every joined host loses trust and
#   must re-join. This tool is READ-ONLY.
#
# Checks:
#   1. All expected files present
#   2. openldap.ldif.gz integrity + sane entry count
#   3. configs.tar.gz / secrets.tar.gz / samba backup archive integrity
#   4. SSL CA (cert + private key) present inside configs.tar.gz
#   5. sha256 of every file matches MANIFEST.txt
#
# Usage:
#   ./jt-ucs-snapshot-verify.sh                 # verify the newest snapshot
#   ./jt-ucs-snapshot-verify.sh <snapshot-dir>  # verify a specific snapshot
#
# Exit code: 0 = usable, 1 = problem found, 2 = setup error.
# ------------------------------------------------------------

set -o pipefail

SNAP_ROOT="/var/univention-backup/snapshots"
MIN_LDAP_ENTRIES=50     # a real UCS directory has far more than this

C_RESET='\033[0m'; C_INFO='\033[1;34m'; C_OK='\033[1;32m'
C_WARN='\033[1;33m'; C_ERR='\033[1;31m'
info()  { echo -e "${C_INFO}[INFO]${C_RESET} $*"; }
ok()    { echo -e "${C_OK}[ OK ]${C_RESET} $*"; }
warn()  { echo -e "${C_WARN}[WARN]${C_RESET} $*"; }
err()   { echo -e "${C_ERR}[FAIL]${C_RESET} $*" >&2; }

if [[ $EUID -ne 0 ]]; then err "This script must be run as root (snapshots are 0700)."; exit 2; fi
for cmd in gzip tar bzip2 sha256sum awk; do
    command -v "$cmd" >/dev/null 2>&1 || { err "Required command not found: ${cmd}"; exit 2; }
done

# ---- locate snapshot dir ----
DIR="$1"
if [[ -z "$DIR" ]]; then
    DIR="$(ls -1dt "${SNAP_ROOT}"/snapshot_* 2>/dev/null | head -1)"
    [[ -z "$DIR" ]] && { err "No snapshots found under ${SNAP_ROOT}."; exit 2; }
    info "No dir given; verifying newest: $(basename "$DIR")"
fi
[[ -d "$DIR" ]] || { err "Not a directory: $DIR"; exit 2; }
DIR="${DIR%/}"
info "Verifying snapshot: $DIR"
echo

ISSUES=0

# ============================================================
# 1. Expected files present
# ============================================================
for f in openldap.ldif.gz ucr.txt configs.tar.gz secrets.tar.gz packages.txt MANIFEST.txt; do
    if [[ -s "$DIR/$f" ]]; then
        ok "present: $f ($(du -h "$DIR/$f" | cut -f1))"
    else
        err "MISSING or empty: $f"
        ISSUES=$((ISSUES+1))
    fi
done

# Samba backup is expected only for AD DC snapshots.
SAMBA_ARCHIVE="$(ls -1 "$DIR"/samba/samba-backup-*.tar.bz2 2>/dev/null | head -1)"
if [[ -n "$SAMBA_ARCHIVE" ]]; then
    ok "present: samba/$(basename "$SAMBA_ARCHIVE") ($(du -h "$SAMBA_ARCHIVE" | cut -f1))"
elif [[ -f "$DIR/samba/private-raw.tar.gz" ]]; then
    warn "samba: only raw fallback archive present (private-raw.tar.gz) — less consistent."
else
    info "samba: no Samba backup in this snapshot (non-DC, or Samba step was skipped)."
fi

# ============================================================
# 2. OpenLDAP dump integrity + entry count
# ============================================================
if [[ -s "$DIR/openldap.ldif.gz" ]]; then
    if gzip -t "$DIR/openldap.ldif.gz" 2>/dev/null; then
        ENTRIES="$(zcat "$DIR/openldap.ldif.gz" 2>/dev/null | grep -c '^dn:')"
        if [[ "$ENTRIES" -ge $MIN_LDAP_ENTRIES ]]; then
            ok "openldap.ldif.gz: valid gzip, ${ENTRIES} entries"
        else
            err "openldap.ldif.gz: only ${ENTRIES} entries (< ${MIN_LDAP_ENTRIES}) — likely truncated."
            ISSUES=$((ISSUES+1))
        fi
    else
        err "openldap.ldif.gz: gzip integrity check FAILED (corrupt)."
        ISSUES=$((ISSUES+1))
    fi
fi

# ============================================================
# 3. Archive integrity
# ============================================================
check_tar() {  # $1=file  $2=decompress flag for tar
    local f="$1" flag="$2"
    [[ -s "$f" ]] || return 0
    if tar ${flag}tf "$f" >/dev/null 2>&1; then
        ok "$(basename "$f"): archive readable"
    else
        err "$(basename "$f"): archive CORRUPT (cannot list contents)."
        ISSUES=$((ISSUES+1))
    fi
}
check_tar "$DIR/configs.tar.gz" "z"
check_tar "$DIR/secrets.tar.gz" "z"
[[ -n "$SAMBA_ARCHIVE" ]] && check_tar "$SAMBA_ARCHIVE" "j"

# ============================================================
# 4. SSL CA present inside configs.tar.gz  (critical for PDN recovery)
# ============================================================
if [[ -s "$DIR/configs.tar.gz" ]]; then
    LISTING="$(tar tzf "$DIR/configs.tar.gz" 2>/dev/null)"
    HAVE_CACERT=$(echo "$LISTING" | grep -c 'etc/univention/ssl/ucsCA/CAcert.pem')
    HAVE_CAKEY=$(echo "$LISTING"  | grep -c 'etc/univention/ssl/ucsCA/private/CAkey.pem')
    if [[ "$HAVE_CACERT" -ge 1 && "$HAVE_CAKEY" -ge 1 ]]; then
        ok "SSL CA present (ucsCA CAcert.pem + private/CAkey.pem)."
    else
        err "SSL CA INCOMPLETE in configs.tar.gz (CAcert=${HAVE_CACERT}, CAkey=${HAVE_CAKEY})."
        err "  Without the domain CA, restored PDN loses trust with every joined host."
        ISSUES=$((ISSUES+1))
    fi
fi

# ============================================================
# 5. Checksums match MANIFEST.txt
# ============================================================
if [[ -s "$DIR/MANIFEST.txt" ]]; then
    SUMS="$(grep -E '^[0-9a-f]{64}  ' "$DIR/MANIFEST.txt")"
    if [[ -z "$SUMS" ]]; then
        warn "MANIFEST.txt has no sha256 lines to verify."
    else
        RESULT="$(cd "$DIR" && echo "$SUMS" | sha256sum -c - 2>&1)"
        BAD="$(echo "$RESULT" | grep -c ': FAILED$')"
        TOTAL="$(echo "$SUMS" | grep -c .)"
        if [[ "$BAD" -eq 0 ]]; then
            ok "checksums: all ${TOTAL} files match MANIFEST."
        else
            err "checksums: ${BAD} of ${TOTAL} file(s) FAILED verification:"
            echo "$RESULT" | grep ': FAILED$' | sed 's/^/     /'
            ISSUES=$((ISSUES+1))
        fi
    fi
fi

# ============================================================
# Summary
# ============================================================
echo
if [[ $ISSUES -eq 0 ]]; then
    ok "Snapshot looks complete and usable for recovery."
    exit 0
else
    err "Snapshot verification found ${ISSUES} issue(s) — do NOT rely on this snapshot until fixed."
    exit 1
fi
