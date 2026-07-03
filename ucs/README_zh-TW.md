# UCS 災難復原工具集

一組給 **Univention Corporate Server (UCS)** 用的互動式 Bash 災難復原工具：從
LDAP 備份還原誤刪的目錄物件、回滾被誤改的單一屬性、以及在動危險操作前建立一致性
快照。還原工具會保留身分屬性
（`sambaSID` / `uidNumber` / `gidNumber` / `sambaPrimaryGroupSID`），並可選擇保留
`entryUUID` 以維持 Microsoft 365 / Azure AD 同步物件的對應。

- **作者：** Jason Cheng (Jason Tools)
- **聯絡：** jason@jason.tools · www.jason.tools

> English version: [README.md](./README.md)

---

## 工具清單

| Script | 用途 | 重點 |
|--------|------|------|
| `jt-ucs-user-recovery.sh` | 還原**誤刪使用者** | RDN `uid=`；群組成員 / OX 需另行處理 |
| `jt-ucs-computer-recovery.sh` | 還原**誤刪電腦** | RDN `cn=` + `objectClass=univentionHost`；DNS/DHCP 與重新加入網域需另行處理 |
| `jt-ucs-group-recovery.sh` | 還原**誤刪群組** | 會還原成員（`uniqueMember`/`memberUid`）並檢查成員是否還存在 |
| `jt-ucs-attr-rollback.sh` | 對仍存在的物件**回滾單一屬性** | 從備份還原某個屬性的值 |
| `jt-ucs-snapshot.sh` | **變更前快照**（還原點） | 動危險操作前打包 LDAP + Samba AD + 設定 + secrets |
| `jt-ucs-ldap-audit.sh` | **唯讀一致性 / 殘留參照稽核** | 找重複 ID、失效成員參照、S4 rejects——完全不寫入 |
| `jt-ucs-listener-health.sh` | **唯讀 listener/notifier 健檢** | 偵測複寫管線卡住——完全不寫入 |
| `jt-ucs-snapshot-verify.sh` | **唯讀快照驗證器** | 確認快照可還原（含 SSL CA）——完全不寫入 |

---

## 安裝 / 下載

下載到 `/opt/`（以 root 執行）：

```bash
for s in jt-ucs-user-recovery jt-ucs-computer-recovery jt-ucs-group-recovery jt-ucs-attr-rollback jt-ucs-snapshot jt-ucs-ldap-audit jt-ucs-listener-health jt-ucs-snapshot-verify; do
  curl -Lo "/opt/$s.sh" "https://raw.githubusercontent.com/jasoncheng7115/it-scripts/refs/heads/master/ucs/$s.sh"
done
chmod +x /opt/jt-ucs-*.sh
```

或單獨抓一支（`wget`）：

```bash
wget -O /opt/jt-ucs-user-recovery.sh https://raw.githubusercontent.com/jasoncheng7115/it-scripts/refs/heads/master/ucs/jt-ucs-user-recovery.sh
chmod +x /opt/jt-ucs-user-recovery.sh
```

---

## 執行需求

- 必須以 **root** 身分在 **Primary Directory Node（主目錄節點）** 上執行。
- 可讀取 `/etc/ldap.secret`（`cn=admin` 密碼）。
- `/var/univention-backup/` 內有 `ldap-backup_*.ldif.gz` 備份（UCS 每晚自動產生，見下）。
- 啟動時檢查指令（依工具）：`zcat awk grep ldapadd ldapsearch ldapmodify ucr udm`
  （還原類）、`slapcat gzip tar sha256sum dpkg`（快照）。

> **UCS 備份預設就自動。** `univention-ldap-server` 套件內建
> `/etc/cron.d/univention-ldap-server`，每天 00:00 執行
> `/usr/sbin/univention-ldap-backup`（UCR `slapd/backup/cron`）。Samba AD DB 另有
> 獨立的每晚備份（UCR `samba4/backup/cron`，預設 03:00）。保留策略：至少留
> `backup/clean/min_backups`（10）份；設 `backup/clean/max_age` 才會依時間清除
> （未設 = 永久累積）。

---

## 物件還原（使用者 / 電腦 / 群組）

三者共用同一套引導流程——你只需輸入名稱，不必知道 DN。

```bash
/opt/jt-ucs-user-recovery.sh                 # 提示輸入 uid
/opt/jt-ucs-user-recovery.sh jsmith
/opt/jt-ucs-computer-recovery.sh PC01        # 結尾的 '$' 會自動去除
/opt/jt-ucs-group-recovery.sh sales
```

### 執行流程（逐步）

| 步驟 | 動作 |
|------|------|
| 1 | 取得目標**名稱**（參數或提示）。 |
| 2 | 列出備份（由新到舊，最多 10）。Enter = 最新 `[0]`。 |
| 3 | 找出 DN。使用者比對 `dn: uid=<uid>,…`；電腦/群組比對 `dn: cn=<cn>,…` **且** `objectClass=univentionHost`/`univentionGroup`。多筆相符由你選。 |
| 4 | 顯示**物件摘要**並確認目標。完整內容存到 `/root/`。 |
| 5 | 記錄原始關鍵屬性供比對。 |
| 6 | *（群組）* 檢查每個成員是否還存在；可選擇丟棄已失效的成員參照。 |
| 7 | 確認還原；DN 已存在則拒絕匯入。 |
| 8 | 可選擇**保留 `entryUUID`**（見下）；剝除 operational 屬性。 |
| 9 | 以 `ldapadd` 匯入（保留 entryUUID 時加 `-e relax`）。 |
| 10 | 顯示還原後物件；**自動比對**備份。 |
| 11 | 若 `sambaSID`/`gidNumber` 不符，可**強制修正** `sambaSID`。 |
| 12 | 印出後續提示。 |

### `-u` / `--preserve-uuid`（Microsoft 365 / Azure AD）

預設會剝除 `entryUUID` 讓 LDAP 重新產生——對純 UCS/Samba 沒問題。但若該物件有同步到
**Microsoft 365 / Azure AD**，連接器會以 `entryUUID` 推導雲端 immutableID，重生就會
**打斷對應**。加 `-u`（或回答互動提示）即可用 `ldapadd -e relax` 保留原始
`entryUUID`：

```bash
/opt/jt-ucs-user-recovery.sh -u jsmith
```

### 已處理 LDIF 折行

LDIF（RFC 2849）會把過長的行折行，續行以一個空格開頭。工具在做任何逐行過濾**之前**先
**unfold**，因此剝除屬性時不會留下殘留的續行害 `ldapadd` 報難懂錯誤（對 `memberOf`、
`creatorsName`、`entryDN` 這類長 DN 值最重要）。

---

## 屬性回滾

用於物件仍在、但某屬性被誤改或清空的情況（例如 `mailPrimaryAddress` 被清、
`description` 被覆蓋）。

```bash
/opt/jt-ucs-attr-rollback.sh                                   # 全互動
/opt/jt-ucs-attr-rollback.sh "uid=jsmith,cn=users,dc=…" mailPrimaryAddress
```

- 會還原多值屬性的**所有**值；保留 base64（`::`）。
- 若備份中該屬性為空，會詢問是否刪除（回滾成空）。
- 顯示 before/after 差異並要求確認；若已相同則不動作。
- 若 DN 目前不存在則拒絕（那種情況請用還原工具）。

---

## 變更前快照

在動危險操作（大量修改、升級、connector 變更）**之前**建立還原點。對執行中的服務為
唯讀——只新增檔案。

```bash
/opt/jt-ucs-snapshot.sh                 # 自動時間戳
/opt/jt-ucs-snapshot.sh before-upgrade  # 加標籤
```

存到 `/var/univention-backup/snapshots/snapshot_<時間>/`：

- `openldap.ldif.gz` — 完整 OpenLDAP dump（slapcat）
- `ucr.txt` — UCR 變數
- `configs.tar.gz` — `/etc/univention`、`/etc/ldap`、Samba sysvol
- `secrets.tar.gz` — `ldap.secret`、`machine.secret`（敏感；目錄權限 `0700`）
- `samba/` — `samba-tool domain backup offline`（Samba4 AD DC）
- `packages.txt` — dpkg 套件清單、UCS 版本、server role
- `MANIFEST.txt` — 中繼資料 + 每個檔案的 sha256

---

## 一致性 / 殘留參照稽核

一支**唯讀**健檢工具——完全不寫入。可在還原後或定期執行，抓出會默默弄壞登入 / ACL
的資料損壞。

```bash
/opt/jt-ucs-ldap-audit.sh        # 完整稽核
/opt/jt-ucs-ldap-audit.sh -q     # 安靜模式：只顯示警告/失敗與摘要
```

檢查項目：重複的 `sambaSID` / `uidNumber` / `gidNumber`；失效的 `memberUid` 與
`uniqueMember` 參照（成員物件已消失）；主要 `gidNumber` 找不到對應群組的帳號；
S4 Connector rejected 物件（Samba4 AD DC）；以及 LDAP 對 Samba 的物件數量落差
（資訊性）。離開碼 `0` = 乾淨、`1` = 有問題、`2` = 設定錯誤（方便搭 cron/監控）。

---

## 健康 / DR 就緒檢查

另外兩支**唯讀**檢查（離開碼 `0`/`1`/`2`，適合搭 cron）：

```bash
/opt/jt-ucs-listener-health.sh          # Listener/Notifier 複寫健康
/opt/jt-ucs-snapshot-verify.sh          # 驗證最新快照可還原
/opt/jt-ucs-snapshot-verify.sh <dir>    # 驗證指定快照
```

- **`jt-ucs-listener-health.sh`** — 檢查 Univention Directory Listener / Notifier
  服務，並比對 notifier 交易 ID 與本機 listener 最後處理的 ID（落後量），再重新取樣
  以區分*正在追上*與*卡住*，並標記失敗的 handler LDIF。listener 卡住時，UMC 的變更會
  默默失效、replica 會落後。
- **`jt-ucs-snapshot-verify.sh`** — 在你依賴某份 `jt-ucs-snapshot.sh` 還原點**之前**先
  確認它真的能用：檔案齊全、壓縮檔與 gzip 完整、sha256 與 `MANIFEST.txt` 相符，以及
  PDN 重建的經典地雷——**SSL CA**（`/etc/univention/ssl/ucsCA`）是否存在。少了網域 CA，
  重建的主節點會與所有已加入的主機失去信任。

---

## 還原後的手動後續作業

還原只還原**物件本身**，以下刻意保留手動處理。

- **使用者群組成員** — `udm groups/group modify --dn "<群組>" --append users="<使用者 DN>"`；若原本 `isOxUser` 有開，另確認 OX 信箱。
- **電腦** — DNS（A/PTR）與 DHCP host 是獨立物件（用 UMC 或 `udm dns/* dhcp/host` 重建）；且 **AD 信任不會被還原**——已加入網域的 client 會定期輪替機器密碼，還原的舊 `sambaNTPassword` 多半已對不上。請用 `Reset-ComputerMachinePassword` / `Test-ComputerSecureChannel -Repair`，或重新加入網域。（SID 有保留，ACL/群組 SID 仍有效。）
- **群組** — 巢狀群組成員（此群組被包在其他群組內）不會還原；需在父群組上重新加入。

### 清理暫存檔

還原留下的 `/root/` 暫存檔含密碼／機器雜湊：

```bash
shred -u /root/restore-*.ldif /root/attr-rollback.*.ldif
```

---

## 安全注意事項

- 所有工具皆為**互動式**，任何變更前都會先確認。
- 還原時若 DN 已存在則拒絕匯入。
- 暫存檔與快照含敏感資料，用完請 shred/移除。
- 若不確定，建議先拿非正式物件測試。

---

## 授權

本工具集依現狀（as-is）提供，不附任何擔保，請自行承擔在自有系統上使用的風險。
