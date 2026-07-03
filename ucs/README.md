# UCS Disaster-Recovery Tools

Interactive Bash tools for **Univention Corporate Server (UCS)** disaster
recovery: restore accidentally deleted directory objects from LDAP backups,
roll back a mistakenly changed attribute, and take a consistent pre-change
snapshot. Recovery tools preserve identity attributes
(`sambaSID` / `uidNumber` / `gidNumber` / `sambaPrimaryGroupSID`) and,
optionally, `entryUUID` for Microsoft 365 / Azure AD synced objects.

- **Author:** Jason Cheng (Jason Tools)
- **Contact:** jason@jason.tools · www.jason.tools

> 繁體中文說明請見 [README_zh-TW.md](./README_zh-TW.md)

---

## Scripts

| Script | Purpose | Key notes |
|--------|---------|-----------|
| `jt-ucs-user-recovery.sh` | Restore a **deleted user** | RDN `uid=`; group membership / OX are follow-ups |
| `jt-ucs-computer-recovery.sh` | Restore a **deleted computer** | RDN `cn=` + `objectClass=univentionHost`; DNS/DHCP & domain re-join are follow-ups |
| `jt-ucs-group-recovery.sh` | Restore a **deleted group** | Restores members (`uniqueMember`/`memberUid`); checks members still exist |
| `jt-ucs-attr-rollback.sh` | **Roll back one attribute** on a still-existing object | Restores a single attribute's value(s) from a backup |
| `jt-ucs-snapshot.sh` | **Pre-change snapshot** (restore point) | Captures LDAP + Samba AD + config + secrets before risky work |
| `jt-ucs-ldap-audit.sh` | **Read-only consistency / orphan audit** | Finds duplicate IDs, dangling members, S4 rejects — writes nothing |

---

## Install / Download

Download to `/opt/` (run as root):

```bash
for s in jt-ucs-user-recovery jt-ucs-computer-recovery jt-ucs-group-recovery jt-ucs-attr-rollback jt-ucs-snapshot jt-ucs-ldap-audit; do
  curl -Lo "/opt/$s.sh" "https://raw.githubusercontent.com/jasoncheng7115/it-scripts/refs/heads/master/ucs/$s.sh"
done
chmod +x /opt/jt-ucs-*.sh
```

Or a single tool, e.g. with `wget`:

```bash
wget -O /opt/jt-ucs-user-recovery.sh https://raw.githubusercontent.com/jasoncheng7115/it-scripts/refs/heads/master/ucs/jt-ucs-user-recovery.sh
chmod +x /opt/jt-ucs-user-recovery.sh
```

---

## Requirements

- Run **as root** on the **Primary Directory Node** (PDN).
- Readable `/etc/ldap.secret` (the `cn=admin` password).
- LDAP backups in `/var/univention-backup/` named `ldap-backup_*.ldif.gz`
  (UCS creates these automatically every night; see note below).
- Commands checked at start-up (per tool): `zcat awk grep ldapadd ldapsearch
  ldapmodify ucr udm` (recovery), `slapcat gzip tar sha256sum dpkg` (snapshot).

> **UCS backups are automatic by default.** The `univention-ldap-server`
> package installs `/etc/cron.d/univention-ldap-server`, which runs
> `/usr/sbin/univention-ldap-backup` daily at 00:00 (UCR `slapd/backup/cron`).
> Samba's AD DB has a separate nightly backup (UCR `samba4/backup/cron`,
> default 03:00). Retention: keep at least `backup/clean/min_backups` (10);
> set `backup/clean/max_age` to also prune by age (unset = keep forever).

---

## Object recovery (user / computer / group)

All three share the same guided flow — you provide only the name, not the DN.

```bash
/opt/jt-ucs-user-recovery.sh                 # prompts for uid
/opt/jt-ucs-user-recovery.sh jsmith
/opt/jt-ucs-computer-recovery.sh PC01        # trailing '$' is stripped
/opt/jt-ucs-group-recovery.sh sales
```

### Workflow (step by step)

| Step | Action |
|------|--------|
| 1 | Obtain the target **name** (argument or prompt). |
| 2 | List backups (newest first, up to 10). Enter = newest `[0]`. |
| 3 | Find the DN. Users match `dn: uid=<uid>,…`; computers/groups match `dn: cn=<cn>,…` **and** `objectClass=univentionHost`/`univentionGroup`. Multiple matches → you choose. |
| 4 | Show an **object summary** and confirm the target. Full entry saved under `/root/`. |
| 5 | Record original key attributes for comparison. |
| 6 | *(group)* Check every member still exists; optionally drop dangling members. |
| 7 | Confirm restore; refuse if the DN already exists in LDAP. |
| 8 | Optionally **preserve `entryUUID`** (see below); strip operational attributes. |
| 9 | Import with `ldapadd` (`-e relax` when preserving `entryUUID`). |
| 10 | Show the restored object; **auto-compare** vs backup. |
| 11 | If `sambaSID`/`gidNumber` differs, optionally **force-fix** `sambaSID`. |
| 12 | Print follow-up hints. |

### `-u` / `--preserve-uuid` (Microsoft 365 / Azure AD)

By default the tools strip `entryUUID` and let LDAP regenerate it — fine for
pure UCS/Samba. But if the object is synced to **Microsoft 365 / Azure AD**, the
connector derives the cloud immutableID from `entryUUID`; regenerating it breaks
the mapping. Pass `-u` (or answer the interactive prompt) to keep the original
`entryUUID` via `ldapadd -e relax`:

```bash
/opt/jt-ucs-user-recovery.sh -u jsmith
```

### LDIF line-folding is handled

LDIF (RFC 2849) folds long lines, with continuation lines starting with a
space. The tools **unfold** the backup stream before any per-line filtering, so
stripping an attribute never leaves an orphaned continuation line that would
break `ldapadd` with a confusing parse error (matters for long DN-valued
attributes like `memberOf`, `creatorsName`, `entryDN`).

---

## Attribute rollback

For when the object still exists but one attribute was changed or cleared by
mistake (e.g. `mailPrimaryAddress` wiped, `description` overwritten).

```bash
/opt/jt-ucs-attr-rollback.sh                                   # fully interactive
/opt/jt-ucs-attr-rollback.sh "uid=jsmith,cn=users,dc=…" mailPrimaryAddress
```

- Restores **all** values of a multi-valued attribute; preserves base64 (`::`).
- If the attribute was empty in the backup, offers to delete it (roll back to empty).
- Shows a before/after diff and requires confirmation; does nothing if already equal.
- Refuses if the DN does not currently exist (use the recovery tools for that).

---

## Pre-change snapshot

Take a restore point **before** risky work (bulk edits, upgrades, connector
changes). Read-only w.r.t. running services — it only writes new files.

```bash
/opt/jt-ucs-snapshot.sh                 # auto timestamp
/opt/jt-ucs-snapshot.sh before-upgrade  # add a label
```

Captured into `/var/univention-backup/snapshots/snapshot_<ts>/`:

- `openldap.ldif.gz` — full OpenLDAP dump (slapcat)
- `ucr.txt` — UCR variables
- `configs.tar.gz` — `/etc/univention`, `/etc/ldap`, Samba sysvol
- `secrets.tar.gz` — `ldap.secret`, `machine.secret` (sensitive; dir is `0700`)
- `samba/` — `samba-tool domain backup offline` (Samba4 AD DCs)
- `packages.txt` — dpkg selections, UCS version, server role
- `MANIFEST.txt` — metadata + sha256 of every file

---

## Consistency / orphan audit

A **read-only** health check — it never writes anything. Run it after a recovery
or periodically to catch corruption that silently breaks logins / ACLs.

```bash
/opt/jt-ucs-ldap-audit.sh        # full audit
/opt/jt-ucs-ldap-audit.sh -q     # quiet: only warnings/failures + summary
```

Checks: duplicate `sambaSID` / `uidNumber` / `gidNumber`; dangling `memberUid`
and `uniqueMember` (members whose object is gone); accounts whose primary
`gidNumber` has no group; S4 Connector rejected objects (Samba4 AD DC); and an
informational LDAP-vs-Samba object-count drift. Exit code `0` = clean, `1` =
issues found, `2` = setup error (handy for cron/monitoring).

---

## After recovery — manual follow-up

Recovery restores the **object only**; a few things are intentionally manual.

- **User group membership** — `udm groups/group modify --dn "<grp>" --append users="<user DN>"`; verify OX mailbox if `isOxUser` was set.
- **Computer** — DNS (A/PTR) and DHCP host entries are separate objects (recreate via UMC / `udm dns/* dhcp/host`); and **AD trust is not restored** — a domain-joined client rotates its machine password, so a restored old `sambaNTPassword` usually no longer matches. Use `Reset-ComputerMachinePassword` / `Test-ComputerSecureChannel -Repair`, or re-join the domain. (The SID is preserved, so ACLs/group SIDs stay valid.)
- **Group** — nested-group membership (this group inside others) is not restored; re-add on the parent group.

### Clean up temp files

Recovery temp files under `/root/` contain password / machine hashes:

```bash
shred -u /root/restore-*.ldif /root/attr-rollback.*.ldif
```

---

## Safety notes

- All tools are **interactive** and confirm before any change.
- Recovery refuses to import if the DN already exists in LDAP.
- Temp files and snapshots contain sensitive material — shred/remove when done.
- Always test on a non-production object first if unsure.

---

## License

Provided as-is, without warranty. Use at your own risk on your own systems.
