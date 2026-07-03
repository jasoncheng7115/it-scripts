# UCS 誤刪物件還原工具集

一組互動式 Bash 工具，用於從 LDAP 備份中還原在
**Univention Corporate Server (UCS)** 上被誤刪的物件，並保留原始身分屬性
（`sambaSID`、`uidNumber`、`gidNumber`、`sambaPrimaryGroupSID`）。

- **作者：** Jason Cheng (Jason Tools)
- **聯絡：** jason@jason.tools · www.jason.tools

> English version: [README.md](./README.md)

---

## 工具清單

| Script | 還原對象 | RDN | 說明 |
|--------|----------|-----|------|
| `jt-ucs-user-recovery.sh` | **使用者**帳號 | `uid=<name>` | 還原使用者物件；群組成員與 OX 信箱需另行處理。 |
| `jt-ucs-computer-recovery.sh` | **電腦**物件 | `cn=<name>` | 以 `objectClass=univentionHost` 過濾；DNS/DHCP 紀錄與重新加入網域需另行處理。 |

兩支共用相同流程、確認提示、以及比對／強制修正邏輯。

---

## 安裝 / 下載

將兩支 script 下載到 `/opt/`（以 root 執行）：

```bash
curl -Lo /opt/jt-ucs-user-recovery.sh     "https://raw.githubusercontent.com/jasoncheng7115/it-scripts/refs/heads/master/ucs/jt-ucs-user-recovery.sh"
curl -Lo /opt/jt-ucs-computer-recovery.sh "https://raw.githubusercontent.com/jasoncheng7115/it-scripts/refs/heads/master/ucs/jt-ucs-computer-recovery.sh"
chmod +x /opt/jt-ucs-user-recovery.sh /opt/jt-ucs-computer-recovery.sh
```

或使用 `wget`：

```bash
wget -O /opt/jt-ucs-user-recovery.sh     https://raw.githubusercontent.com/jasoncheng7115/it-scripts/refs/heads/master/ucs/jt-ucs-user-recovery.sh
wget -O /opt/jt-ucs-computer-recovery.sh https://raw.githubusercontent.com/jasoncheng7115/it-scripts/refs/heads/master/ucs/jt-ucs-computer-recovery.sh
chmod +x /opt/jt-ucs-user-recovery.sh /opt/jt-ucs-computer-recovery.sh
```

---

## 功能說明

1. 你只需輸入**名稱**（使用者為 uid、電腦為 cn），script 會自動從備份中搜尋物件的
   DN/OU（**不會**假設一定在 `cn=users` / `cn=computers` 這種固定容器）。
   - 電腦工具會額外用 `objectClass=univentionHost` 過濾候選，因此**不會**誤抓同名的
     DNS、DHCP 或群組物件。
2. 顯示備份中找到的物件摘要，請你確認是否為目標。
3. 確認後，詢問是否要還原到 LDAP。
4. 還原後印出物件，並**自動比對**備份原值
   （`sambaSID` / `uidNumber` / `gidNumber` / `sambaPrimaryGroupSID`）。
5. 若匯入過程中 `sambaSID` 被重新配發、與備份不符，會詢問是否**強制修正**回原值。

---

## 執行需求

- 必須以 **root** 身分在 **Primary Directory Node（主目錄節點）** 上執行。
- 可讀取 `/etc/ldap.secret`（`cn=admin` 密碼）。
- `/var/univention-backup/` 底下存在名為 `ldap-backup_*.ldif.gz` 的 LDAP 備份
  （UCS 會自動產生）。
- 啟動時會檢查以下指令是否存在：
  `zcat`、`awk`、`grep`、`ldapadd`、`ldapsearch`、`ldapmodify`、`ucr`、`udm`。

---

## 使用方式

### 使用者還原

```bash
# 互動模式 — 由 script 提示輸入 uid
/opt/jt-ucs-user-recovery.sh

# 直接指定 uid
/opt/jt-ucs-user-recovery.sh jsmith
```

### 電腦還原

```bash
# 互動模式 — 由 script 提示輸入電腦名 (cn)
/opt/jt-ucs-computer-recovery.sh

# 直接指定電腦名（結尾的 '$' 會自動去除）
/opt/jt-ucs-computer-recovery.sh PC01
```

---

## 執行流程（逐步）

| 步驟 | 動作 |
|------|------|
| 1 | 取得目標**名稱**（由參數或提示輸入）。 |
| 2 | 列出可用備份（由新到舊，最多 10 筆）。按 Enter 使用最新 `[0]`，或自行選編號。 |
| 3 | 在所選備份中搜尋物件 DN。使用者比對 `dn: uid=<uid>,…`；電腦比對 `dn: cn=<cn>,…` **且** `objectClass=univentionHost`。若有多筆相符，由你挑選其一。 |
| 4 | 顯示備份中的**物件摘要**並請你確認目標。完整內容存到 `/root/` 底下。 |
| 5 | 記錄原始關鍵屬性，供之後比對。 |
| 6 | 確認還原。此步驟同時檢查該 DN 是否**尚未**存在於 LDAP（避免重複匯入）。 |
| 7 | 剝除 operational 屬性（`entryUUID`、`entryCSN`、`creatorsName`、`createTimestamp`、`modifiersName`、`modifyTimestamp`、`structuralObjectClass`、`univentionObjectIdentifier`、`memberOf`、`subschemaSubentry`、`hasSubordinates`、`entryDN`），保留身分屬性。 |
| 8 | 以 `ldapadd` 匯入 LDAP。 |
| 9 | 顯示還原後的物件（使用者用 `udm users/user list`；電腦因 UDM 模組依角色分，改用 `ldapsearch`）。 |
| 10 | **自動比對** LDAP 實際值與備份原值。 |
| 11 | 若 `sambaSID` 不符，可選擇**強制修正**回原值。 |
| 12 | 印出後續提示（見下）。 |

### 已處理 LDIF 折行（line folding）

LDIF（RFC 2849）會把過長的行「折行」，續行以一個空格開頭。兩支 script 在做任何
逐行過濾**之前**都會先 **unfold** 備份串流，因此 Step 7 剝除屬性時，絕不會留下孤兒續行
而害 `ldapadd` 報出難懂的解析錯誤。這對 `memberOf`、`creatorsName`、`entryDN` 這類
長 DN 值的屬性最重要。

---

## 還原後的手動後續作業

工具只還原**物件本身**，以下項目刻意保留給你手動處理。

### 使用者：群組成員（不會自動還原）

```bash
zcat /var/univention-backup/ldap-backup_<...>.ldif.gz \
  | awk '/^dn: cn=/{dn=$0} /memberUid: <uid>$/{print dn}'

udm groups/group modify --dn "<群組 DN>" --append users="<使用者 DN>"
```

若原本 `isOxUser` 為啟用狀態，另需到 OX 端確認信箱。

### 電腦：群組成員、DNS/DHCP、重新加入網域

機器帳號的 uid 形式為 `<name>$`：

```bash
zcat /var/univention-backup/ldap-backup_<...>.ldif.gz \
  | awk '/^dn: cn=/{dn=$0} /memberUid: <name>\$$/{print dn}'

# 電腦是透過 'hosts' 屬性加入群組
udm groups/group modify --dn "<群組 DN>" --append hosts="<電腦 DN>"
```

- **DNS（A/PTR）與 DHCP host 紀錄是獨立物件**，不會被還原——請透過 UMC 或
  `udm dns/*` / `udm dhcp/host` 重新建立。
- **機器帳號密碼：** 已加入網域的 Windows/Samba client 會定期輪替密碼。若還原的舊
  `sambaNTPassword` 與線上機器已對不上，請把 client 重新加入網域。

### 清理暫存檔

暫存的 LDIF 檔含有密碼／機器帳號雜湊，請安全刪除：

```bash
shred -u /root/restore-*.raw.ldif /root/restore-*.clean.ldif
```

---

## 安全注意事項

- 兩支 script 皆為**互動式**，任何變更前都會先詢問確認。
- 若該 DN 已存在於 LDAP，會拒絕匯入。
- `/root/` 底下的暫存檔含敏感資料，用完請以 `shred` 刪除。
- 若不確定，建議先拿非正式物件測試還原流程。

---

## 授權

本工具集依現狀（as-is）提供，不附任何擔保，請自行承擔在自有系統上使用的風險。
