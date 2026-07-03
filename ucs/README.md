# UCS Deleted-Object Recovery Tools

Interactive Bash tools to recover accidentally deleted objects on
**Univention Corporate Server (UCS)** from an LDAP backup, preserving the
original identity attributes (`sambaSID`, `uidNumber`, `gidNumber`,
`sambaPrimaryGroupSID`).

- **Author:** Jason Cheng (Jason Tools)
- **Contact:** jason@jason.tools · www.jason.tools

> 繁體中文說明請見 [README_zh-TW.md](./README_zh-TW.md)

---

## Scripts

| Script | Recovers | RDN | Notes |
|--------|----------|-----|-------|
| `jt-ucs-user-recovery.sh` | **User** account | `uid=<name>` | Restores the user object; group membership & OX mailbox are follow-ups. |
| `jt-ucs-computer-recovery.sh` | **Computer** object | `cn=<name>` | Filters by `objectClass=univentionHost`; DNS/DHCP records & domain re-join are follow-ups. |

Both share the same workflow, safety prompts, and comparison/force-fix logic.

---

## Install / Download

Download both scripts to `/opt/` (run as root):

```bash
curl -Lo /opt/jt-ucs-user-recovery.sh     "https://raw.githubusercontent.com/jasoncheng7115/it-scripts/refs/heads/master/ucs/jt-ucs-user-recovery.sh"
curl -Lo /opt/jt-ucs-computer-recovery.sh "https://raw.githubusercontent.com/jasoncheng7115/it-scripts/refs/heads/master/ucs/jt-ucs-computer-recovery.sh"
chmod +x /opt/jt-ucs-user-recovery.sh /opt/jt-ucs-computer-recovery.sh
```

Or with `wget`:

```bash
wget -O /opt/jt-ucs-user-recovery.sh     https://raw.githubusercontent.com/jasoncheng7115/it-scripts/refs/heads/master/ucs/jt-ucs-user-recovery.sh
wget -O /opt/jt-ucs-computer-recovery.sh https://raw.githubusercontent.com/jasoncheng7115/it-scripts/refs/heads/master/ucs/jt-ucs-computer-recovery.sh
chmod +x /opt/jt-ucs-user-recovery.sh /opt/jt-ucs-computer-recovery.sh
```

---

## What they do

1. You provide only the **name** (uid for users, cn for computers); the script
   auto-searches the backup for the object's DN/OU (it does **not** assume a
   fixed container such as `cn=users` / `cn=computers`).
   - The computer tool additionally filters candidates by
     `objectClass=univentionHost`, so it never picks up a same-named DNS, DHCP,
     or group object.
2. Shows a summary of the object found in the backup and asks you to confirm
   it is the correct target.
3. On confirmation, asks whether to restore it into LDAP.
4. After the restore, prints the object and **auto-compares** it against the
   backup (`sambaSID` / `uidNumber` / `gidNumber` / `sambaPrimaryGroupSID`).
5. If `sambaSID` was reassigned during import and no longer matches the backup,
   offers to **force-fix** it back to the original value.

---

## Requirements

- Run **as root** on the **Primary Directory Node** (PDN).
- Readable `/etc/ldap.secret` (the `cn=admin` password).
- LDAP backups present in `/var/univention-backup/` named
  `ldap-backup_*.ldif.gz` (UCS creates these automatically).
- Required commands (checked at start-up):
  `zcat`, `awk`, `grep`, `ldapadd`, `ldapsearch`, `ldapmodify`, `ucr`, `udm`.

---

## Usage

### User recovery

```bash
# Interactive — the script prompts for the uid
/opt/jt-ucs-user-recovery.sh

# Specify the uid directly
/opt/jt-ucs-user-recovery.sh jsmith
```

### Computer recovery

```bash
# Interactive — the script prompts for the computer name (cn)
/opt/jt-ucs-computer-recovery.sh

# Specify the computer name directly (a trailing '$' is stripped automatically)
/opt/jt-ucs-computer-recovery.sh PC01
```

---

## Workflow (step by step)

| Step | Action |
|------|--------|
| 1 | Obtain the target **name** (argument or prompt). |
| 2 | List available backups (newest first, up to 10). Press Enter for the newest `[0]`, or pick an index. |
| 3 | Search the chosen backup for the object's DN. Users match `dn: uid=<uid>,…`; computers match `dn: cn=<cn>,…` **and** `objectClass=univentionHost`. If multiple DNs match, you choose which one. |
| 4 | Show an **object summary** from the backup and ask you to confirm the target. The full entry is saved under `/root/`. |
| 5 | Record original key attributes for later comparison. |
| 6 | Confirm the restore. The script also checks the DN does **not** already exist in LDAP (to avoid duplicate import). |
| 7 | Strip operational attributes (`entryUUID`, `entryCSN`, `creatorsName`, `createTimestamp`, `modifiersName`, `modifyTimestamp`, `structuralObjectClass`, `univentionObjectIdentifier`, `memberOf`, `subschemaSubentry`, `hasSubordinates`, `entryDN`) while keeping identity attributes. |
| 8 | Import into LDAP with `ldapadd`. |
| 9 | Show the restored object (users via `udm users/user list`; computers via `ldapsearch`, because computer UDM modules are per-role). |
| 10 | **Auto-compare** LDAP actual values vs the backup originals. |
| 11 | If `sambaSID` differs, optionally **force-fix** it back to the original. |
| 12 | Print follow-up hints (see below). |

### LDIF line-folding is handled

LDIF (RFC 2849) folds long lines, with continuation lines starting with a
single space. Both scripts **unfold** the backup stream before any per-line
filtering, so stripping an attribute in Step 7 can never leave an orphaned
continuation line that would break `ldapadd` with a confusing parse error.
This matters most for long DN-valued attributes like `memberOf`, `creatorsName`,
and `entryDN`.

---

## After recovery — manual follow-up

The tools restore the **object itself only**. A few things are intentionally
left to you.

### User: group membership (NOT auto-restored)

```bash
zcat /var/univention-backup/ldap-backup_<...>.ldif.gz \
  | awk '/^dn: cn=/{dn=$0} /memberUid: <uid>$/{print dn}'

udm groups/group modify --dn "<group DN>" --append users="<user DN>"
```

Also verify the OX mailbox if the original `isOxUser` was enabled.

### Computer: group membership, DNS/DHCP, domain re-join

Machine accounts use the uid form `<name>$`:

```bash
zcat /var/univention-backup/ldap-backup_<...>.ldif.gz \
  | awk '/^dn: cn=/{dn=$0} /memberUid: <name>\$$/{print dn}'

# Computers are added to groups via the 'hosts' property
udm groups/group modify --dn "<group DN>" --append hosts="<computer DN>"
```

- **DNS (A/PTR) and DHCP host entries are separate objects** and are NOT
  restored — recreate them via UMC or `udm dns/* ` / `udm dhcp/host`.
- **Machine-account password:** a domain-joined Windows/Samba client rotates its
  password periodically. If the restored object's old `sambaNTPassword` no
  longer matches the live machine, re-join the client to the domain.

### Clean up temp files

The temporary LDIF files contain password / machine-account hashes. Securely
remove them:

```bash
shred -u /root/restore-*.raw.ldif /root/restore-*.clean.ldif
```

---

## Safety notes

- The scripts are **interactive** and ask for confirmation before any change.
- They refuse to import if the DN already exists in LDAP.
- Temp files under `/root/` contain sensitive material — shred them when done.
- Always test recovery on a non-production object first if you are unsure.

---

## License

Provided as-is, without warranty. Use at your own risk on your own systems.
