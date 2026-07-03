#!/bin/bash
#
# UCS Deleted-Computer Recovery Tool (interactive)
# Author: Jason Cheng (Jason Tools)
# jason@jason.tools
# www.jason.tools
# ------------------------------------------------------------
# Features:
#   1. Enter only the computer name (cn); the script auto-searches the backup
#      for its OU/DN and filters by objectClass=univentionHost so it does NOT
#      pick up same-named DNS/DHCP/group objects.
#   2. After locating the DN, asks the user to confirm it is the target object.
#   3. On confirmation, asks whether to restore.
#   4. After restore, prints the object and auto-compares it against the backup
#      (verifies sambaSID / uidNumber / gidNumber / sambaPrimaryGroupSID).
#   5. If sambaSID differs from the backup, offers to force-fix it.
#
# Usage:
#   ./jt-ucs-computer-recovery.sh              # interactive, prompts for name
#   ./jt-ucs-computer-recovery.sh <name>       # specify computer name directly
#
# Note: run as root on the Primary Directory Node.
#
# IMPORTANT — machine account password:
#   Domain-joined Windows/Samba clients rotate their machine-account password
#   periodically. Restoring the old sambaNTPassword may no longer match the live
#   machine, so the client may need to be re-joined to the domain afterwards.
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

# ---- LDIF unfold ----
# RFC 2849 folds long lines; continuation lines start with a single space.
# Join them back so each attribute sits on one physical line. This is required
# before any per-line grep/awk filtering, otherwise stripping an attribute
# (Step 7) would leave orphaned continuation lines and break ldapadd.
unfold_ldif() {
    awk '
        /^ / { buf = buf substr($0, 2); next }
        NR > 1 { print buf }
        { buf = $0 }
        END { if (NR > 0) print buf }
    '
}

# ---- yes/no prompt ----
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

for cmd in zcat awk grep ldapadd ldapsearch ldapmodify ucr udm; do
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

# ============================================================
# Step 1: obtain computer name (cn)
# ============================================================
NAME_INPUT="$1"
if [[ -z "$NAME_INPUT" ]]; then
    echo -ne "${C_ASK}[ASK ]${C_RESET} Enter the computer name (cn) to recover: "
    read -r NAME_INPUT
fi

if [[ -z "$NAME_INPUT" ]]; then
    err "No computer name entered. Aborting."
    exit 1
fi
# Strip a trailing '$' if the user pasted the machine-account uid form.
NAME_INPUT="${NAME_INPUT%\$}"
info "Target computer name: ${NAME_INPUT}"

# ============================================================
# Step 2: select backup file (default: newest ldap-backup)
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
# Step 3: search for the computer DN (auto-detect OU, filter by univentionHost)
# ============================================================
info "Searching backup for computer object cn=${NAME_INPUT} ..."

# Scan record-by-record on the UNFOLDED stream. Only keep records whose RDN is
# cn=<name> AND that carry objectClass: univentionHost (the marker shared by
# every UCS computer role) — this excludes same-named DNS/DHCP/group objects.
# Literal (index-based) name matching avoids regex-metacharacter pitfalls.
mapfile -t FOUND_DNS < <(
    zcat "$BACKUP_FILE" | unfold_ldif | awk -v name="$NAME_INPUT" '
        BEGIN { target = tolower("dn: cn=" name ",") }
        /^dn:/  { dn=$0; low=tolower($0); rdn_ok=(index(low, target)==1); is_host=0 }
        tolower($0) == "objectclass: univentionhost" { is_host=1 }
        /^$/    { if (dn!="" && rdn_ok && is_host) print dn; dn=""; is_host=0; rdn_ok=0 }
        END     { if (dn!="" && rdn_ok && is_host) print dn }
    '
)

if [[ ${#FOUND_DNS[@]} -eq 0 ]]; then
    err "No computer object with cn=${NAME_INPUT} found in this backup."
    warn "Possible causes: different spelling, object did not span this backup,"
    warn "the value is base64-encoded, or it is not a univentionHost object."
    warn "Try another backup, or check manually:"
    echo "      zcat \"$BACKUP_FILE\" | grep -i \"cn=${NAME_INPUT},\""
    exit 1
fi

if [[ ${#FOUND_DNS[@]} -gt 1 ]]; then
    warn "Multiple matching computer DNs found. Please choose:"
    for i in "${!FOUND_DNS[@]}"; do
        printf "   [%d] %s\n" "$i" "${FOUND_DNS[$i]#dn: }"
    done
    echo -ne "${C_ASK}[ASK ]${C_RESET} Choose index: "
    read -r DN_IDX
    if ! [[ "$DN_IDX" =~ ^[0-9]+$ ]] || [[ $DN_IDX -ge ${#FOUND_DNS[@]} ]]; then
        err "Invalid index."
        exit 1
    fi
    TARGET_DN="${FOUND_DNS[$DN_IDX]#dn: }"
else
    TARGET_DN="${FOUND_DNS[0]#dn: }"
fi

ok "Found target DN: ${TARGET_DN}"

# ============================================================
# Step 4: show object summary and confirm target
# ============================================================
# Extract the whole entry by DN on the UNFOLDED stream (start at DN line, stop
# at the blank line). Unfolding keeps each attribute on one line so the later
# grep -v strip (Step 7) cannot leave orphaned continuation lines.
TMP_RAW="${WORK_DIR}/restore-comp-${NAME_INPUT}.raw.ldif"
zcat "$BACKUP_FILE" | unfold_ldif | awk -v dn="dn: ${TARGET_DN}" '
    $0==dn {flag=1}
    flag {print}
    /^$/ {if(flag) exit}
' > "$TMP_RAW"

if [[ ! -s "$TMP_RAW" ]]; then
    err "Failed to extract entry (empty result)."
    exit 1
fi

echo
info "===== Object summary from backup ====="
grep -iE '^(dn|cn|uid|uidNumber|gidNumber|macAddress|aRecord|operatingSystem|operatingSystemVersion|sambaSID|sambaPrimaryGroupSID|univentionObjectType|univentionServerRole):' "$TMP_RAW" \
    | sed 's/^/   /'
echo "   ---------------------------------"
echo "   (Full entry saved to: $TMP_RAW)"
echo

if ! ask_yes_no "Is this the object you want to recover?"; then
    warn "Cancelled. No changes made. Temp file: $TMP_RAW"
    exit 0
fi

# ============================================================
# Step 5: record original key attributes (for comparison)
# ============================================================
ORIG_SAMBASID="$(grep -i '^sambaSID:' "$TMP_RAW" | head -1 | awk '{print $2}')"
ORIG_UIDNUM="$(grep -i '^uidNumber:' "$TMP_RAW" | head -1 | awk '{print $2}')"
ORIG_GIDNUM="$(grep -i '^gidNumber:' "$TMP_RAW" | head -1 | awk '{print $2}')"
ORIG_PRIMSID="$(grep -i '^sambaPrimaryGroupSID:' "$TMP_RAW" | head -1 | awk '{print $2}')"

info "Recorded original key attributes:"
echo "   sambaSID             = ${ORIG_SAMBASID:-(none)}"
echo "   uidNumber            = ${ORIG_UIDNUM:-(none)}"
echo "   gidNumber            = ${ORIG_GIDNUM:-(none)}"
echo "   sambaPrimaryGroupSID = ${ORIG_PRIMSID:-(none)}"

# ============================================================
# Step 6: confirm restore
# ============================================================
echo
if ! ask_yes_no "Proceed to restore this computer object into LDAP?"; then
    warn "Restore cancelled. No changes made. Temp file: $TMP_RAW"
    exit 0
fi

# Check if DN already exists (avoid duplicate import)
if ldapsearch -x -D "$BIND_DN" -y "$LDAP_SECRET" -H ldapi:/// \
        -b "$TARGET_DN" -s base dn >/dev/null 2>&1; then
    err "This DN already exists in LDAP; the object may not be deleted (or already restored). Aborting."
    exit 1
fi

# ============================================================
# Step 7: strip operational attributes, keep identity attributes
# ============================================================
# TMP_RAW is already unfolded (see Step 4), so each attribute is on one line and
# grep -v removes the whole value cleanly — no orphaned continuation lines.
TMP_CLEAN="${WORK_DIR}/restore-comp-${NAME_INPUT}.clean.ldif"
grep -vi -E '^(entryUUID|entryCSN|creatorsName|createTimestamp|modifiersName|modifyTimestamp|structuralObjectClass|univentionObjectIdentifier|memberOf|subschemaSubentry|hasSubordinates|entryDN):' \
    "$TMP_RAW" > "$TMP_CLEAN"

info "Operational attributes stripped; sambaSID/uidNumber/gidNumber preserved."

# ============================================================
# Step 8: import into LDAP
# ============================================================
info "Importing into LDAP ..."
if ldapadd -x -D "$BIND_DN" -y "$LDAP_SECRET" -H ldapi:/// -f "$TMP_CLEAN"; then
    ok "Import succeeded."
else
    err "Import failed. Check ldapadd output above. Cleaned LDIF: $TMP_CLEAN"
    exit 1
fi

# ============================================================
# Step 9: show restored object (authoritative, via ldapsearch)
# ============================================================
# Computer UDM modules are per-role (computers/windows, computers/memberserver,
# computers/ipmanagedclient, ...) with no generic list, so query LDAP directly.
echo
info "===== Restored object (ldapsearch) ====="
ldapsearch -x -D "$BIND_DN" -y "$LDAP_SECRET" -H ldapi:/// \
    -b "$TARGET_DN" -s base \
    cn uid uidNumber gidNumber macAddress aRecord operatingSystem \
    operatingSystemVersion sambaSID sambaPrimaryGroupSID univentionObjectType \
    | sed 's/^/   /'

# ============================================================
# Step 10: auto-compare against backup
# ============================================================
echo
info "===== Auto-compare (LDAP actual vs backup original) ====="

RESTORED_ATTRS="$(ldapsearch -x -D "$BIND_DN" -y "$LDAP_SECRET" -H ldapi:/// \
    -b "$TARGET_DN" -s base sambaSID uidNumber gidNumber sambaPrimaryGroupSID 2>/dev/null)"

get_ldap_val() { echo "$RESTORED_ATTRS" | grep -i "^$1:" | head -1 | awk '{print $2}'; }

NEW_SAMBASID="$(get_ldap_val sambaSID)"
NEW_UIDNUM="$(get_ldap_val uidNumber)"
NEW_GIDNUM="$(get_ldap_val gidNumber)"
NEW_PRIMSID="$(get_ldap_val sambaPrimaryGroupSID)"

compare_attr() {
    local name="$1" orig="$2" new="$3"
    if [[ "$orig" == "$new" ]]; then
        echo -e "   ${C_OK}[MATCH]${C_RESET} ${name}: ${new:-empty}"
        return 0
    else
        echo -e "   ${C_ERR}[DIFF ]${C_RESET} ${name}: backup=${orig:-empty}  current=${new:-empty}"
        return 1
    fi
}

SID_MISMATCH=0
compare_attr "uidNumber           " "$ORIG_UIDNUM"  "$NEW_UIDNUM"
compare_attr "gidNumber           " "$ORIG_GIDNUM"  "$NEW_GIDNUM"
compare_attr "sambaPrimaryGroupSID" "$ORIG_PRIMSID" "$NEW_PRIMSID"
compare_attr "sambaSID            " "$ORIG_SAMBASID" "$NEW_SAMBASID" || SID_MISMATCH=1

# ============================================================
# Step 11: force-fix sambaSID if mismatched
# ============================================================
if [[ $SID_MISMATCH -eq 1 && -n "$ORIG_SAMBASID" ]]; then
    echo
    warn "sambaSID differs from backup (reassigned during import)."
    if ask_yes_no "Force-fix sambaSID back to original ${ORIG_SAMBASID}?"; then
        TMP_FIX="${WORK_DIR}/fix-sambasid-comp-${NAME_INPUT}.ldif"
        cat > "$TMP_FIX" <<EOF
dn: ${TARGET_DN}
changetype: modify
replace: sambaSID
sambaSID: ${ORIG_SAMBASID}
EOF
        if ldapmodify -x -D "$BIND_DN" -y "$LDAP_SECRET" -H ldapi:/// -f "$TMP_FIX"; then
            ok "sambaSID fixed. Re-comparing:"
            NEW_SAMBASID="$(ldapsearch -x -D "$BIND_DN" -y "$LDAP_SECRET" -H ldapi:/// \
                -b "$TARGET_DN" -s base sambaSID 2>/dev/null | grep -i '^sambaSID:' | awk '{print $2}')"
            compare_attr "sambaSID            " "$ORIG_SAMBASID" "$NEW_SAMBASID"
        else
            err "sambaSID fix failed (SID may be in use by another object). Handle manually. Fix LDIF: $TMP_FIX"
        fi
    else
        warn "Skipped sambaSID fix; current value remains ${NEW_SAMBASID}."
    fi
fi

# ============================================================
# Step 12: follow-up hints (groups / DNS / DHCP / domain re-join / cleanup)
# ============================================================
echo
info "===== Follow-up ====="
echo "   1. Group membership is NOT auto-restored. Machine accounts use the"
echo "      uid form '${NAME_INPUT}\$'. Find original groups:"
echo "        zcat \"$BACKUP_FILE\" | awk '/^dn: cn=/{dn=\$0} /memberUid: ${NAME_INPUT}\\\$\$/{print dn}'"
echo "      Then re-add with (computers use the 'hosts' property):"
echo "        udm groups/group modify --dn \"<group DN>\" --append hosts=\"${TARGET_DN}\""
echo "   2. DNS (A/PTR) and DHCP host entries are SEPARATE objects and are NOT"
echo "      restored here. Recreate them via UMC or udm dns/* and dhcp/host."
echo "   3. Machine-account password: a domain-joined Windows/Samba client rotates"
echo "      its password periodically. If the client can no longer authenticate,"
echo "      re-join it to the domain."
echo "   4. Clean up temp files (may contain machine-account hashes; secure-delete):"
echo "        shred -u ${TMP_RAW} ${TMP_CLEAN}${TMP_FIX:+ \$TMP_FIX}"
echo

ok "Recovery workflow complete."
