#!/bin/bash
#
# UCS Attribute Rollback Tool (interactive)
# Author: Jason Cheng (Jason Tools)
# jason@jason.tools
# www.jason.tools
# ------------------------------------------------------------
# Purpose:
#   The object still EXISTS in LDAP, but one attribute was accidentally changed
#   or cleared (e.g. mailPrimaryAddress wiped, description overwritten, a group's
#   memberUid list truncated). This tool restores a SINGLE attribute's value(s)
#   from a chosen backup, leaving everything else untouched.
#
#   For a fully deleted object, use jt-ucs-user/computer/group-recovery.sh
#   instead — this tool only rolls back an attribute on a live object.
#
# Features:
#   - Multi-valued attributes are fully restored (replace with all backup values).
#   - Base64 (::) values are preserved verbatim.
#   - If the attribute was empty in the backup, offers to delete it (roll back to
#     empty).
#   - Shows a clear before/after diff and requires confirmation.
#
# Usage:
#   ./jt-ucs-attr-rollback.sh                          # fully interactive
#   ./jt-ucs-attr-rollback.sh "<DN>" <attribute>       # specify both
#
# Note: run as root on the Primary Directory Node.
# ------------------------------------------------------------

set -o pipefail

BACKUP_DIR="/var/univention-backup"
WORK_DIR="/root"
LDAP_SECRET="/etc/ldap.secret"

# ---- colors ----
C_RESET='\033[0m'
C_INFO='\033[1;34m'
C_OK='\033[1;32m'
C_WARN='\033[1;33m'
C_ERR='\033[1;31m'
C_ASK='\033[1;36m'

info()  { echo -e "${C_INFO}[INFO]${C_RESET} $*"; }
ok()    { echo -e "${C_OK}[ OK ]${C_RESET} $*"; }
warn()  { echo -e "${C_WARN}[WARN]${C_RESET} $*"; }
err()   { echo -e "${C_ERR}[FAIL]${C_RESET} $*" >&2; }

# ---- LDIF unfold (join RFC2849 continuation lines that start with a space) ----
unfold_ldif() {
    awk '
        /^ / { buf = buf substr($0, 2); next }
        NR > 1 { print buf }
        { buf = $0 }
        END { if (NR > 0) print buf }
    '
}

ask_yes_no() {
    local prompt="$1"
    local ans
    while true; do
        echo -ne "${C_ASK}[ASK ]${C_RESET} ${prompt} (y/n): "
        read -r ans
        case "$ans" in
            [Yy]|[Yy][Ee][Ss]) return 0 ;;
            [Nn]|[Nn][Oo])     return 1 ;;
            *) echo "  Please enter y or n." ;;
        esac
    done
}

# ============================================================
# Pre-checks
# ============================================================
if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root."
    exit 1
fi

for cmd in zcat awk grep ldapsearch ldapmodify ucr; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        err "Required command not found: ${cmd}"
        exit 1
    fi
done

if [[ ! -r "$LDAP_SECRET" ]]; then
    err "Cannot read ${LDAP_SECRET}. Ensure you run as root and the file exists."
    exit 1
fi

LDAP_BASE="$(ucr get ldap/base)"
if [[ -z "$LDAP_BASE" ]]; then
    err "Cannot obtain ldap/base. Is this a UCS Directory Node?"
    exit 1
fi
BIND_DN="cn=admin,${LDAP_BASE}"
LDAP_OPTS=(-x -D "$BIND_DN" -y "$LDAP_SECRET" -H ldapi:///)

# Attributes that are risky to roll back — warn (but still allow).
CRITICAL_ATTRS_RE='^(objectClass|cn|uid|dn|entryUUID|entryCSN|structuralObjectClass|creatorsName|modifiersName|createTimestamp|modifyTimestamp)$'

# ============================================================
# Step 1: obtain target DN
# ============================================================
TARGET_DN="$1"
if [[ -z "$TARGET_DN" ]]; then
    echo -ne "${C_ASK}[ASK ]${C_RESET} Enter the full DN of the object: "
    read -r TARGET_DN
fi
if [[ -z "$TARGET_DN" ]]; then
    err "No DN entered. Aborting."
    exit 1
fi

# The object MUST currently exist (this is a rollback, not a recovery).
if ! ldapsearch "${LDAP_OPTS[@]}" -b "$TARGET_DN" -s base dn >/dev/null 2>&1; then
    err "DN not found in LDAP: ${TARGET_DN}"
    warn "If the object was fully deleted, use the *-recovery.sh scripts instead."
    exit 1
fi
info "Target DN exists: ${TARGET_DN}"

# ============================================================
# Step 2: obtain attribute name
# ============================================================
ATTR="$2"
if [[ -z "$ATTR" ]]; then
    echo -ne "${C_ASK}[ASK ]${C_RESET} Enter the attribute name to roll back: "
    read -r ATTR
fi
if [[ -z "$ATTR" ]]; then
    err "No attribute entered. Aborting."
    exit 1
fi
info "Target attribute: ${ATTR}"
if [[ "$ATTR" =~ $CRITICAL_ATTRS_RE ]]; then
    warn "'${ATTR}' is a structural/critical attribute. Rolling it back can break"
    warn "the object or its identity. Proceed only if you are sure."
fi

# ============================================================
# Step 3: select backup file
# ============================================================
mapfile -t BACKUP_FILES < <(ls -1t "${BACKUP_DIR}"/ldap-backup_*.ldif.gz 2>/dev/null)
if [[ ${#BACKUP_FILES[@]} -eq 0 ]]; then
    err "No ldap-backup_*.ldif.gz found in ${BACKUP_DIR}."
    exit 1
fi

info "Available backups (newest first, up to 10):"
for i in "${!BACKUP_FILES[@]}"; do
    [[ $i -ge 10 ]] && break
    printf "   [%d] %s\n" "$i" "$(basename "${BACKUP_FILES[$i]}")"
done
echo -ne "${C_ASK}[ASK ]${C_RESET} Choose backup index (Enter = newest [0]): "
read -r BK_IDX
[[ -z "$BK_IDX" ]] && BK_IDX=0
if ! [[ "$BK_IDX" =~ ^[0-9]+$ ]] || [[ $BK_IDX -ge ${#BACKUP_FILES[@]} ]]; then
    err "Invalid index."
    exit 1
fi
BACKUP_FILE="${BACKUP_FILES[$BK_IDX]}"
info "Using backup: $(basename "$BACKUP_FILE")"

# ============================================================
# Step 4: extract the object's entry from the backup
# ============================================================
TMP_RAW="$(mktemp "${WORK_DIR}/attr-rollback.raw.XXXXXX.ldif")"
zcat "$BACKUP_FILE" | unfold_ldif | awk -v dn="dn: ${TARGET_DN}" '
    $0==dn {flag=1}
    flag {print}
    /^$/ {if(flag) exit}
' > "$TMP_RAW"

if [[ ! -s "$TMP_RAW" ]]; then
    err "This DN was not found in the selected backup."
    warn "Pick an older backup that still contained the object/attribute."
    rm -f "$TMP_RAW"
    exit 1
fi

# ============================================================
# Step 5: gather backup values (verbatim, preserving base64 ::) and current values
# ============================================================
# Match '<attr>: ' or '<attr>:: ' (base64), case-insensitive, exact attribute.
mapfile -t BK_LINES < <(grep -iE "^${ATTR}::? " "$TMP_RAW")
# The attribute name exactly as it appears in the backup (preserve case).
ACTUAL_ATTR="$ATTR"
if [[ ${#BK_LINES[@]} -gt 0 ]]; then
    ACTUAL_ATTR="$(echo "${BK_LINES[0]}" | sed -E 's/^([^:]+):.*/\1/')"
fi

echo
info "===== Backup value(s) of '${ATTR}' ====="
if [[ ${#BK_LINES[@]} -eq 0 ]]; then
    echo "   (attribute was ABSENT/empty in this backup)"
else
    printf '   %s\n' "${BK_LINES[@]}"
fi

echo
info "===== Current value(s) in LDAP ====="
CUR_OUT="$(ldapsearch "${LDAP_OPTS[@]}" -o ldif-wrap=no -b "$TARGET_DN" -s base "$ATTR" 2>/dev/null | grep -iE "^${ATTR}::? ")"
if [[ -z "$CUR_OUT" ]]; then
    echo "   (attribute currently ABSENT/empty)"
else
    echo "$CUR_OUT" | sed 's/^/   /'
fi

# ============================================================
# Step 6: decide the change and confirm
# ============================================================
echo
NORM_BK="$(printf '%s\n' "${BK_LINES[@]}" | sort)"
NORM_CUR="$(echo "$CUR_OUT" | sort)"
if [[ "$NORM_BK" == "$NORM_CUR" ]]; then
    ok "Current value already matches the backup. Nothing to roll back."
    rm -f "$TMP_RAW"
    exit 0
fi

TMP_MOD="$(mktemp "${WORK_DIR}/attr-rollback.mod.XXXXXX.ldif")"
if [[ ${#BK_LINES[@]} -eq 0 ]]; then
    # Backup had no value -> roll back to empty by deleting the attribute.
    warn "Backup had NO value for '${ATTR}'. Rolling back means DELETING it."
    {
        echo "dn: ${TARGET_DN}"
        echo "changetype: modify"
        echo "delete: ${ACTUAL_ATTR}"
    } > "$TMP_MOD"
else
    {
        echo "dn: ${TARGET_DN}"
        echo "changetype: modify"
        echo "replace: ${ACTUAL_ATTR}"
        printf '%s\n' "${BK_LINES[@]}"
    } > "$TMP_MOD"
fi

echo
info "===== Change to be applied (ldapmodify) ====="
sed 's/^/   /' "$TMP_MOD"
echo

if ! ask_yes_no "Apply this rollback to '${TARGET_DN}'?"; then
    warn "Cancelled. No changes made."
    rm -f "$TMP_RAW" "$TMP_MOD"
    exit 0
fi

# ============================================================
# Step 7: apply and verify
# ============================================================
if ldapmodify "${LDAP_OPTS[@]}" -f "$TMP_MOD"; then
    ok "Rollback applied."
else
    err "ldapmodify failed. See output above. Modify LDIF kept: $TMP_MOD"
    rm -f "$TMP_RAW"
    exit 1
fi

echo
info "===== New value(s) in LDAP ====="
ldapsearch "${LDAP_OPTS[@]}" -o ldif-wrap=no -b "$TARGET_DN" -s base "$ATTR" 2>/dev/null \
    | grep -iE "^${ATTR}::? " | sed 's/^/   /' || echo "   (now absent/empty)"

echo
info "Clean up temp files:"
echo "   shred -u ${TMP_RAW} ${TMP_MOD}"
echo
ok "Attribute rollback complete."
