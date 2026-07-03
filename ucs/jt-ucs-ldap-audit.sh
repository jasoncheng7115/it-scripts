#!/bin/bash
#
# UCS LDAP Consistency / Orphan Audit (read-only)
# Author: Jason Cheng (Jason Tools)
# jason@jason.tools
# www.jason.tools
# ------------------------------------------------------------
# Purpose:
#   Read-only health check of the UCS OpenLDAP directory (and, on a Samba4 AD
#   DC, the S4 Connector). It NEVER writes anything. Run it after a recovery, or
#   periodically, to catch corruption that silently breaks logins / ACLs.
#
# Checks:
#   1. Duplicate sambaSID   (must be globally unique)
#   2. Duplicate uidNumber  (across posixAccount objects)
#   3. Duplicate gidNumber  (across posixGroup objects)
#   4. Dangling memberUid   (group member uid with no matching object)
#   5. Dangling uniqueMember(group member DN that no longer exists)
#   6. Missing primary group(user gidNumber with no matching group)
#   7. S4 Connector rejected objects (Samba4 AD DC only)
#   8. LDAP vs Samba object-count drift (informational)
#
# Usage:
#   ./jt-ucs-ldap-audit.sh            # full audit
#   ./jt-ucs-ldap-audit.sh -q         # quiet: only warnings/failures + summary
#
# Exit code: 0 = clean, 1 = one or more issues found, 2 = setup error.
#
# Note: run as root on a UCS Directory Node (needs /etc/ldap.secret).
# ------------------------------------------------------------

set -o pipefail

LDAP_SECRET="/etc/ldap.secret"
LIST_CAP=25          # max items listed per finding before "... and N more"

C_RESET='\033[0m'; C_INFO='\033[1;34m'; C_OK='\033[1;32m'
C_WARN='\033[1;33m'; C_ERR='\033[1;31m'
info()  { echo -e "${C_INFO}[INFO]${C_RESET} $*"; }
ok()    { echo -e "${C_OK}[ OK ]${C_RESET} $*"; }
warn()  { echo -e "${C_WARN}[WARN]${C_RESET} $*"; }
err()   { echo -e "${C_ERR}[FAIL]${C_RESET} $*" >&2; }

QUIET=0
[[ "$1" == "-q" || "$1" == "--quiet" ]] && QUIET=1

# ---- pre-checks ----
if [[ $EUID -ne 0 ]]; then err "This script must be run as root."; exit 2; fi
for cmd in ldapsearch ucr awk sort; do
    command -v "$cmd" >/dev/null 2>&1 || { err "Required command not found: ${cmd}"; exit 2; }
done
[[ -r "$LDAP_SECRET" ]] || { err "Cannot read ${LDAP_SECRET}."; exit 2; }
LDAP_BASE="$(ucr get ldap/base)"
[[ -n "$LDAP_BASE" ]] || { err "Cannot obtain ldap/base. Is this a UCS Directory Node?"; exit 2; }
BIND_DN="cn=admin,${LDAP_BASE}"

# ldif-wrap=no keeps every attribute on one line (no RFC2849 folding to handle).
lsearch() { ldapsearch -x -D "$BIND_DN" -y "$LDAP_SECRET" -H ldapi:/// -o ldif-wrap=no -LLL "$@" 2>/dev/null; }

ISSUES=0

# Print a capped list of items, indented.
print_capped() {
    local n=0
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        n=$((n+1))
        [[ $n -le $LIST_CAP ]] && echo "     $line"
    done
    [[ $n -gt $LIST_CAP ]] && echo "     ... and $((n - LIST_CAP)) more"
}

# ---- gather base data once ----
info "Gathering directory data from ${LDAP_BASE} ..."
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# All DNs (for uniqueMember existence check)
lsearch -b "$LDAP_BASE" dn 2>/dev/null | awk '/^dn: /{print tolower(substr($0,5))}' | sort -u > "$TMP/all_dns"
# All uid values (users + computers) -> membership target set
lsearch -b "$LDAP_BASE" "(uid=*)" uid | awk '/^uid: /{print substr($0,6)}' | sort -u > "$TMP/all_uids"
# Group gidNumbers (valid primary-group targets)
lsearch -b "$LDAP_BASE" "(objectClass=posixGroup)" gidNumber | awk '/^gidNumber: /{print substr($0,11)}' | sort -u > "$TMP/group_gids"

TOTAL_DNS=$(wc -l < "$TMP/all_dns")
info "Total entries: ${TOTAL_DNS}"
echo

# ============================================================
# 1-3. Duplicate unique identifiers
# ============================================================
check_dup() {
    local title="$1" filter="$2" attr="$3"
    local dups
    dups="$(lsearch -b "$LDAP_BASE" "$filter" "$attr" dn \
        | awk -v a="${attr}: " '
            /^dn: /   {dn=substr($0,5)}
            $0 ~ "^" a {v=substr($0,length(a)+1); print v "\t" dn}
          ' \
        | sort | awk -F'\t' '{c[$1]=c[$1]"\n       "$2; n[$1]++} END{for(k in n) if(n[k]>1) print k n[k]}')"
    if [[ -n "$dups" ]]; then
        err "${title}: duplicate value(s) found"
        echo "$dups" | sed 's/^/   /'
        ISSUES=$((ISSUES+1))
    else
        [[ $QUIET -eq 0 ]] && ok "${title}: no duplicates"
    fi
}

check_dup "sambaSID"  "(sambaSID=*)"                "sambaSID"
check_dup "uidNumber" "(objectClass=posixAccount)"  "uidNumber"
check_dup "gidNumber" "(objectClass=posixGroup)"    "gidNumber"

# ============================================================
# 4. Dangling memberUid (group member uid with no object)
# ============================================================
DANGLING_MU="$(lsearch -b "$LDAP_BASE" "(objectClass=univentionGroup)" dn memberUid \
    | awk '
        /^dn: /       {dn=substr($0,5)}
        /^memberUid: /{print dn "\t" substr($0,12)}
      ' \
    | while IFS=$'\t' read -r dn uid; do
        grep -qxF "$uid" "$TMP/all_uids" || echo "group=${dn}  memberUid=${uid}"
      done)"
if [[ -n "$DANGLING_MU" ]]; then
    warn "Dangling memberUid (member object missing):"
    echo "$DANGLING_MU" | print_capped
    ISSUES=$((ISSUES+1))
else
    [[ $QUIET -eq 0 ]] && ok "memberUid: all group members resolve to an object"
fi

# ============================================================
# 5. Dangling uniqueMember (member DN no longer exists)
# ============================================================
DANGLING_UM="$(lsearch -b "$LDAP_BASE" "(uniqueMember=*)" dn uniqueMember \
    | awk '
        /^dn: /          {dn=substr($0,5)}
        /^uniqueMember: /{print dn "\t" tolower(substr($0,15))}
      ' \
    | while IFS=$'\t' read -r dn m; do
        [[ -z "$m" ]] && continue
        grep -qxF "$m" "$TMP/all_dns" || echo "container=${dn}  uniqueMember=${m}"
      done)"
if [[ -n "$DANGLING_UM" ]]; then
    warn "Dangling uniqueMember (referenced DN missing):"
    echo "$DANGLING_UM" | print_capped
    ISSUES=$((ISSUES+1))
else
    [[ $QUIET -eq 0 ]] && ok "uniqueMember: all references resolve to an existing DN"
fi

# ============================================================
# 6. Missing primary group (user gidNumber not a group gidNumber)
# ============================================================
MISSING_PG="$(lsearch -b "$LDAP_BASE" "(&(objectClass=posixAccount)(uid=*))" dn gidNumber \
    | awk '
        /^dn: /       {dn=substr($0,5)}
        /^gidNumber: /{print dn "\t" substr($0,11)}
      ' \
    | while IFS=$'\t' read -r dn gid; do
        grep -qxF "$gid" "$TMP/group_gids" || echo "account=${dn}  gidNumber=${gid}"
      done)"
if [[ -n "$MISSING_PG" ]]; then
    warn "Accounts whose primary gidNumber has no matching group:"
    echo "$MISSING_PG" | print_capped
    ISSUES=$((ISSUES+1))
else
    [[ $QUIET -eq 0 ]] && ok "primary group: every account's gidNumber matches a group"
fi

# ============================================================
# 7. S4 Connector rejected objects (Samba4 AD DC only)
# ============================================================
if command -v univention-s4connector-list-rejected >/dev/null 2>&1 \
        && [[ -n "$(ucr get connector/s4/autostart 2>/dev/null)" ]]; then
    # Real rejected entries are DN lines ending in the domain base; the section
    # headers ("UCS rejected"/"S4 rejected") and the "last synced USN" line do
    # not contain the base, so filtering on it avoids false positives.
    REJECTED="$(univention-s4connector-list-rejected 2>/dev/null | grep -iF "$LDAP_BASE")"
    if [[ -n "$REJECTED" ]]; then
        REJ_COUNT=$(echo "$REJECTED" | grep -c .)
        warn "S4 Connector has ${REJ_COUNT} rejected reference(s) — sync is not clean:"
        echo "$REJECTED" | print_capped
        echo "     (inspect with: univention-s4connector-list-rejected)"
        ISSUES=$((ISSUES+1))
    else
        [[ $QUIET -eq 0 ]] && ok "S4 Connector: no rejected objects"
    fi
else
    [[ $QUIET -eq 0 ]] && info "S4 Connector not present/enabled — skipping rejected-object check."
fi

# ============================================================
# 8. LDAP vs Samba object-count drift (informational)
# ============================================================
if command -v samba-tool >/dev/null 2>&1 && [[ -n "$(ucr get samba4/ldap/base 2>/dev/null)" ]]; then
    LDAP_USERS=$(lsearch -b "$LDAP_BASE" "(&(objectClass=posixAccount)(!(uid=*\$)))" dn | grep -c '^dn: ')
    SAMBA_USERS=$(samba-tool user list 2>/dev/null | grep -c .)
    LDAP_GROUPS=$(lsearch -b "$LDAP_BASE" "(objectClass=univentionGroup)" dn | grep -c '^dn: ')
    SAMBA_GROUPS=$(samba-tool group list 2>/dev/null | grep -c .)
    [[ $QUIET -eq 0 ]] && {
        info "Object-count drift (informational; small differences are normal):"
        echo "     users : LDAP=${LDAP_USERS}  Samba=${SAMBA_USERS}"
        echo "     groups: LDAP=${LDAP_GROUPS}  Samba=${SAMBA_GROUPS}"
    }
fi

# ============================================================
# Summary
# ============================================================
echo
if [[ $ISSUES -eq 0 ]]; then
    ok "Audit complete — no consistency issues found."
    exit 0
else
    err "Audit complete — ${ISSUES} category(ies) with issues. Review the [WARN]/[FAIL] items above."
    exit 1
fi
