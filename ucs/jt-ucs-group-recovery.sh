#!/bin/bash
#
# UCS Deleted-Group Recovery Tool (interactive)
# Author: Jason Cheng (Jason Tools)
# jason@jason.tools
# www.jason.tools
# ------------------------------------------------------------
# Features:
#   1. Enter only the group name (cn); the script auto-searches the backup for
#      its OU/DN and filters by objectClass=univentionGroup so it does NOT pick
#      up same-named computer/DNS/container objects.
#   2. Restores the group object INCLUDING its members (uniqueMember/memberUid) —
#      this is the whole point of a group, unlike user/computer recovery.
#   3. Before import, checks every member still exists in LDAP and lets you keep
#      or drop dangling members whose target object is gone.
#   4. After restore, auto-compares gidNumber / sambaSID against the backup and
#      offers to force-fix sambaSID if it was reassigned.
#
# Usage:
#   ./jt-ucs-group-recovery.sh              # interactive, prompts for name
#   ./jt-ucs-group-recovery.sh <name>       # specify group name directly
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

# ---- LDIF unfold ----
# RFC 2849 folds long lines; continuation lines start with a single space.
# Join them back so each attribute sits on one physical line — required before
# any per-line grep/awk filtering (otherwise stripping an attribute would leave
# orphaned continuation lines and break ldapadd).
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

LDAP_OPTS=(-x -D "$BIND_DN" -y "$LDAP_SECRET" -H ldapi:///)

# ---- parse options (-u/--preserve-uuid) ----
# Preserving entryUUID keeps Microsoft 365 / Azure AD object mappings intact.
# Requires ldapadd '-e relax' to re-set the NO-USER-MODIFICATION attribute.
PRESERVE_UUID=0
POSARGS=()
for a in "$@"; do
    case "$a" in
        -u|--preserve-uuid) PRESERVE_UUID=1 ;;
        *) POSARGS+=("$a") ;;
    esac
done
set -- "${POSARGS[@]}"

# ============================================================
# Step 1: obtain group name (cn)
# ============================================================
NAME_INPUT="$1"
if [[ -z "$NAME_INPUT" ]]; then
    echo -ne "${C_ASK}[ASK ]${C_RESET} Enter the group name (cn) to recover: "
    read -r NAME_INPUT
fi

if [[ -z "$NAME_INPUT" ]]; then
    err "No group name entered. Aborting."
    exit 1
fi
info "Target group name: ${NAME_INPUT}"

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
# Step 3: search for the group DN (auto-detect OU, filter by univentionGroup)
# ============================================================
info "Searching backup for group object cn=${NAME_INPUT} ..."

# Scan record-by-record on the UNFOLDED stream. Only keep records whose RDN is
# cn=<name> AND that carry objectClass: univentionGroup — this excludes
# same-named computer/DNS/container objects. Literal name match (index) avoids
# regex-metacharacter pitfalls.
mapfile -t FOUND_DNS < <(
    zcat "$BACKUP_FILE" | unfold_ldif | awk -v name="$NAME_INPUT" '
        BEGIN { target = tolower("dn: cn=" name ",") }
        /^dn:/  { dn=$0; low=tolower($0); rdn_ok=(index(low, target)==1); is_grp=0 }
        tolower($0) == "objectclass: univentiongroup" { is_grp=1 }
        /^$/    { if (dn!="" && rdn_ok && is_grp) print dn; dn=""; is_grp=0; rdn_ok=0 }
        END     { if (dn!="" && rdn_ok && is_grp) print dn }
    '
)

if [[ ${#FOUND_DNS[@]} -eq 0 ]]; then
    err "No group object with cn=${NAME_INPUT} found in this backup."
    warn "Possible causes: different spelling, object did not span this backup,"
    warn "the value is base64-encoded, or it is not a univentionGroup object."
    warn "Try another backup, or check manually:"
    echo "      zcat \"$BACKUP_FILE\" | grep -i \"cn=${NAME_INPUT},\""
    exit 1
fi

if [[ ${#FOUND_DNS[@]} -gt 1 ]]; then
    warn "Multiple matching group DNs found. Please choose:"
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
# Step 4: extract entry and show summary (incl. member counts)
# ============================================================
TMP_RAW="${WORK_DIR}/restore-grp-${NAME_INPUT}.raw.ldif"
zcat "$BACKUP_FILE" | unfold_ldif | awk -v dn="dn: ${TARGET_DN}" '
    $0==dn {flag=1}
    flag {print}
    /^$/ {if(flag) exit}
' > "$TMP_RAW"

if [[ ! -s "$TMP_RAW" ]]; then
    err "Failed to extract entry (empty result)."
    exit 1
fi

MEMBERUID_COUNT="$(grep -ic '^memberUid:' "$TMP_RAW")"
UNIQMEM_COUNT="$(grep -ic '^uniqueMember:' "$TMP_RAW")"

echo
info "===== Object summary from backup ====="
grep -iE '^(dn|cn|gidNumber|sambaSID|sambaGroupType|description|univentionObjectType):' "$TMP_RAW" \
    | sed 's/^/   /'
echo "   memberUid (count)    : ${MEMBERUID_COUNT}"
echo "   uniqueMember (count) : ${UNIQMEM_COUNT}"
echo "   ---------------------------------"
echo "   (Full entry saved to: $TMP_RAW)"
echo

if ! ask_yes_no "Is this the group you want to recover?"; then
    warn "Cancelled. No changes made. Temp file: $TMP_RAW"
    exit 0
fi

# ============================================================
# Step 5: record original key attributes (for comparison)
# ============================================================
ORIG_GIDNUM="$(grep -i '^gidNumber:' "$TMP_RAW" | head -1 | awk '{print $2}')"
ORIG_SAMBASID="$(grep -i '^sambaSID:' "$TMP_RAW" | head -1 | awk '{print $2}')"

info "Recorded original key attributes:"
echo "   gidNumber = ${ORIG_GIDNUM:-(none)}"
echo "   sambaSID  = ${ORIG_SAMBASID:-(none)}"

# ============================================================
# Step 6: check members still exist; optionally drop dangling ones
# ============================================================
echo
info "===== Member existence check ====="
MISSING_UNIQMEM=()
MISSING_MEMBERUID=()

while IFS= read -r m; do
    [[ -z "$m" ]] && continue
    if ! ldapsearch "${LDAP_OPTS[@]}" -b "$m" -s base dn >/dev/null 2>&1; then
        MISSING_UNIQMEM+=("$m")
    fi
done < <(grep -i '^uniqueMember:' "$TMP_RAW" | sed 's/^[^:]*: //')

while IFS= read -r u; do
    [[ -z "$u" ]] && continue
    if ! ldapsearch "${LDAP_OPTS[@]}" -b "$LDAP_BASE" "(uid=${u})" dn 2>/dev/null | grep -qi '^dn:'; then
        MISSING_MEMBERUID+=("$u")
    fi
done < <(grep -i '^memberUid:' "$TMP_RAW" | sed 's/^[^:]*: //')

DROP_MISSING=0
if [[ ${#MISSING_UNIQMEM[@]} -gt 0 || ${#MISSING_MEMBERUID[@]} -gt 0 ]]; then
    warn "Some members no longer exist in LDAP:"
    for m in "${MISSING_UNIQMEM[@]}";  do echo "     [uniqueMember] $m"; done
    for u in "${MISSING_MEMBERUID[@]}"; do echo "     [memberUid]    $u"; done
    echo
    if ask_yes_no "Drop these dangling members from the restored group?"; then
        DROP_MISSING=1
        info "Dangling members will be dropped."
    else
        warn "Keeping all original members (dangling references will be restored as-is)."
    fi
else
    ok "All members still exist."
fi

# ============================================================
# Step 7: confirm restore
# ============================================================
echo
if ! ask_yes_no "Proceed to restore this group into LDAP?"; then
    warn "Restore cancelled. No changes made. Temp file: $TMP_RAW"
    exit 0
fi

# Check if DN already exists (avoid duplicate import)
if ldapsearch "${LDAP_OPTS[@]}" -b "$TARGET_DN" -s base dn >/dev/null 2>&1; then
    err "This DN already exists in LDAP; the group may not be deleted (or already restored). Aborting."
    exit 1
fi

# ============================================================
# Step 8: strip operational attributes (KEEP uniqueMember/memberUid)
# ============================================================
# Ask about entryUUID preservation unless already requested via flag.
if [[ $PRESERVE_UUID -eq 0 ]]; then
    if ask_yes_no "Preserve entryUUID (needed for Microsoft 365 / Azure AD synced objects)?"; then
        PRESERVE_UUID=1
    fi
fi

# TMP_RAW is unfolded, so grep -v removes whole values cleanly. Note memberOf is
# stripped (nested-group membership is operational) but the group's OWN members
# uniqueMember/memberUid are preserved. When preserving entryUUID we keep it in
# the LDIF (and add '-e relax' below).
TMP_CLEAN="${WORK_DIR}/restore-grp-${NAME_INPUT}.clean.ldif"
STRIP='^(entryUUID|entryCSN|creatorsName|createTimestamp|modifiersName|modifyTimestamp|structuralObjectClass|univentionObjectIdentifier|memberOf|subschemaSubentry|hasSubordinates|entryDN):'
if [[ $PRESERVE_UUID -eq 1 ]]; then
    STRIP='^(entryCSN|creatorsName|createTimestamp|modifiersName|modifyTimestamp|structuralObjectClass|univentionObjectIdentifier|memberOf|subschemaSubentry|hasSubordinates|entryDN):'
fi
grep -vi -E "$STRIP" "$TMP_RAW" > "$TMP_CLEAN"

# Drop dangling members if requested
if [[ $DROP_MISSING -eq 1 ]]; then
    for m in "${MISSING_UNIQMEM[@]}"; do
        grep -viF "uniqueMember: $m" "$TMP_CLEAN" > "${TMP_CLEAN}.tmp" && mv "${TMP_CLEAN}.tmp" "$TMP_CLEAN"
    done
    for u in "${MISSING_MEMBERUID[@]}"; do
        grep -viF "memberUid: $u" "$TMP_CLEAN" > "${TMP_CLEAN}.tmp" && mv "${TMP_CLEAN}.tmp" "$TMP_CLEAN"
    done
    ok "Dangling members removed from import file."
fi

if [[ $PRESERVE_UUID -eq 1 ]]; then
    info "Operational attributes stripped; entryUUID PRESERVED; members preserved."
else
    info "Operational attributes stripped; gidNumber/sambaSID and members preserved."
fi

# ============================================================
# Step 9: import into LDAP
# ============================================================
info "Importing into LDAP ..."
ADD_OPTS=()
[[ $PRESERVE_UUID -eq 1 ]] && ADD_OPTS+=(-e relax)   # allow re-setting entryUUID
if ldapadd "${LDAP_OPTS[@]}" "${ADD_OPTS[@]}" -f "$TMP_CLEAN"; then
    ok "Import succeeded."
else
    err "Import failed. Check ldapadd output above. Cleaned LDIF: $TMP_CLEAN"
    exit 1
fi

# ============================================================
# Step 10: show restored object
# ============================================================
echo
info "===== Restored object (ldapsearch) ====="
ldapsearch "${LDAP_OPTS[@]}" -b "$TARGET_DN" -s base \
    cn gidNumber sambaSID sambaGroupType description univentionObjectType \
    | sed 's/^/   /'
NEW_MEMBERUID_COUNT="$(ldapsearch "${LDAP_OPTS[@]}" -b "$TARGET_DN" -s base memberUid 2>/dev/null | grep -ic '^memberUid:')"
NEW_UNIQMEM_COUNT="$(ldapsearch "${LDAP_OPTS[@]}" -b "$TARGET_DN" -s base uniqueMember 2>/dev/null | grep -ic '^uniqueMember:')"
echo "   memberUid restored    : ${NEW_MEMBERUID_COUNT}"
echo "   uniqueMember restored : ${NEW_UNIQMEM_COUNT}"

# ============================================================
# Step 11: auto-compare against backup
# ============================================================
echo
info "===== Auto-compare (LDAP actual vs backup original) ====="

RESTORED_ATTRS="$(ldapsearch "${LDAP_OPTS[@]}" -b "$TARGET_DN" -s base gidNumber sambaSID 2>/dev/null)"
get_ldap_val() { echo "$RESTORED_ATTRS" | grep -i "^$1:" | head -1 | awk '{print $2}'; }

NEW_GIDNUM="$(get_ldap_val gidNumber)"
NEW_SAMBASID="$(get_ldap_val sambaSID)"

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
compare_attr "gidNumber" "$ORIG_GIDNUM"  "$NEW_GIDNUM"
compare_attr "sambaSID " "$ORIG_SAMBASID" "$NEW_SAMBASID" || SID_MISMATCH=1

# ============================================================
# Step 12: force-fix sambaSID if mismatched
# ============================================================
if [[ $SID_MISMATCH -eq 1 && -n "$ORIG_SAMBASID" ]]; then
    echo
    warn "sambaSID differs from backup (reassigned during import)."
    if ask_yes_no "Force-fix sambaSID back to original ${ORIG_SAMBASID}?"; then
        TMP_FIX="${WORK_DIR}/fix-sambasid-grp-${NAME_INPUT}.ldif"
        cat > "$TMP_FIX" <<EOF
dn: ${TARGET_DN}
changetype: modify
replace: sambaSID
sambaSID: ${ORIG_SAMBASID}
EOF
        if ldapmodify "${LDAP_OPTS[@]}" -f "$TMP_FIX"; then
            ok "sambaSID fixed. Re-comparing:"
            NEW_SAMBASID="$(ldapsearch "${LDAP_OPTS[@]}" -b "$TARGET_DN" -s base sambaSID 2>/dev/null | grep -i '^sambaSID:' | awk '{print $2}')"
            compare_attr "sambaSID " "$ORIG_SAMBASID" "$NEW_SAMBASID"
        else
            err "sambaSID fix failed (SID may be in use by another object). Handle manually. Fix LDIF: $TMP_FIX"
        fi
    else
        warn "Skipped sambaSID fix; current value remains ${NEW_SAMBASID}."
    fi
fi

# ============================================================
# Step 13: follow-up hints
# ============================================================
echo
info "===== Follow-up ====="
echo "   1. Verify the group and its members in UMC / via:"
echo "        udm groups/group list --filter cn=\"${NAME_INPUT}\""
echo "   2. If this group is nested inside other groups, that membership is NOT"
echo "      restored here — re-add it on the parent group if needed."
echo "   3. Clean up temp files:"
echo "        shred -u ${TMP_RAW} ${TMP_CLEAN}${TMP_FIX:+ \$TMP_FIX}"
echo

ok "Recovery workflow complete."
