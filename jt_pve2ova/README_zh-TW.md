# JT_PVE2OVA 

Proxmox VE 虛擬機打包成為 ESXi 可匯入的 OVA 檔案
磁碟自動轉成 **Thin-Provisioned VMDK**，支援 RBD / dir / ZFS / LVM-thin 等多種儲存來源。

---

## 提供功能

- **一行完成**：轉換 VMDK → 產生 VMX → 打包 OVA  
- **精簡配置**：使用 `streamOptimized` 子格式 + `--diskMode=thin`
- **自動判斷**：RBD 直接走 `qemu-img`，其它走 `pvesm path` 取得磁碟路徑
- **暫存清理**：`MODE=clean`（預設）轉完自動刪除 VMX/VMDK  
- **版本對應**：`virtualHW.version` 依傳入 ESXi 版本自動比對  
- **開機模式**：讀取 `bios:` 欄位，產生對應 `firmware=`  

---

## 系統需求

| 軟體                | 最低版本 | 備註                                   |
|---------------------|---------|----------------------------------------|
| Proxmox VE / Debian | 8.x ↑   | 內附 `pvesm`、`ceph-common`…           |
| **qemu-img**        | 8.0 ↑   | 建議 8.x 以支援 `subformat=vmfs`       |
| **VMware OVF Tool** | 4.x ↑   | 安裝至 `/opt/ovftool/` 之下         |
| bash、numfmt、uuidgen|         | 標準 GNU coreutils                     |

> **Ceph RBD** 需確保 `/etc/pve/ceph.conf` 與金鑰可用。  

---

## 安裝工具


OVF Tool
```bash
# 下載與安裝 OVF Tool
# 需要事先取得 VMware-ovftool-x.x.x-xxxxxxxx-lin.x86_64.zip 檔案
# 下載點 https://developer.broadcom.com/tools/open-virtualization-format-ovf-tool/latest
unzip VMware-ovftool-x.x.x-xxxxxxxx-lin.x86_64.zip
```

JT_PVE2OVA
```bash
# 下載與安裝 jt_pve2ova
curl -Lo /opt/jt_pve2ova.sh "https://raw.githubusercontent.com/jasoncheng7115/it-scripts/refs/heads/master/jt_pve2ova/jt_pve2ova.sh"
chmod +x /opt/jt_pve2ova.sh
```

---

## 使用方法

```bash
jt_pve2ova.sh <VMID> <WORK_DIR> <ESXI_VERSION> [MODE]
```

| 參數             | 說明                                                 |
| -------------- | -------------------------------------------------- |
| `VMID`         | PVE VM ID（ex. `203`）                               |
| `WORK_DIR`     | 暫存 / 輸出目錄（必須有足夠空間，程式會自動估算並檢查）          |
| `ESXI_VERSION` | 目標 ESXi 版本：`8.0` / `7.0u3` / `7.0` / `6.7` / `6.5` |
| `MODE`         | `keep` 保留轉換後的 VMX/VMDK；`clean` 轉換完成後刪除，僅留 OVA（預設）                |

### 快速範例

```bash
# 1. 建立 OVA 並自動清暫存檔
jt_pve2ova.sh 203 /vmimage/tmp 8.0

# 2. 建立 OVA 並留下 VMX / VMDK 供手動測試
jt_pve2ova.sh 105 /export/ova 7.0u3 keep
```

完成後會在 `WORK_DIR` 看到如下，檔名自動取用 Proxmox VE 的 VM 名稱：

```
graylog5-customer.ova   ← 可直接在拿到 vSphere Client Deploy
```

---

## 執行結果


自動讀取 VM 設定，並將存放在 QCOW2 的磁碟轉換後打包為 OVA
```bash
root@host-108:/opt# ./jt_pve2ova.sh 203 /vmimage/temp 8.0
INFO: Detected qemu-img 9.2.0
2003–2024
INFO: Target ESXi 8.0  -> virtualHW 20
INFO: VM 'graylog5-customer'  BIOS=bios  vCPU=4  RAM=8192MB
INFO: Skip optical: ide2: none,media=cdrom
INFO: Added disk /vmimage/images/203/vm-203-disk-0.qcow2 (42G)
INFO: Added disk /vmimage/images/203/vm-203-disk-1.qcow2 (64G)
INFO: Required space ~128G, Free 1.4T
INFO: Converting disks to streamOptimized VMDK...
INFO: [0/2] /vmimage/images/203/vm-203-disk-0.qcow2 -> disk0.vmdk (100.00/100%)
INFO: [1/2] /vmimage/images/203/vm-203-disk-1.qcow2 -> disk1.vmdk (100.00/100%)
INFO: All disks converted.
INFO: VMX generated -> /vmimage/temp/graylog5-customer.vmx
INFO: Packing OVA with ovftool...
Opening VMX source: /vmimage/temp/graylog5-customer.vmx
Opening OVA target: /vmimage/temp/graylog5-customer.ova
Writing OVA package: /vmimage/temp/graylog5-customer.ova
Transfer Completed
Completed successfully
SUCCESS: OVA ready -> /vmimage/temp/graylog5-customer.ova
```

自動讀取 VM 設定，並將存放在 Ceph 的磁碟轉換後打包為 OVA
```
root@host-108:/opt# ./jt_pve2ova.sh 203 /vmimage/temp 8.0
INFO: Detected qemu-img 9.2.0
2003-2024
INFO: Target ESXi 8.0 -> virtualHW 20
INFO: VM 'graylog5-customer' BIOS=bios vCPU=4 RAM=8192MB
INFO: Skip optical: ide2: none,media=cdrom
INFO: Added disk rbd:ceph1/vm-203-disk-0:conf=/etc/pve/ceph.conf:id=admin:keyring=/etc/pve/priv/ceph/ceph1.keyring (42G)
INFO: Added disk rbd:ceph1/vm-203-disk-1:conf=/etc/pve/ceph.conf:id=admin:keyring=/etc/pve/priv/ceph/ceph1.keyring (64G)
INFO: Required space ~128G, Free 1.4T
INFO: Converting disks to streamOptimized VMDK...
INFO: [0/2] rbd:ceph1/vm-203-disk-0:conf=/etc/pve/ceph.conf:id=admin:keyring=/etc/pve/priv/ceph/ceph1.keyring -> disk0.vmdk
    (100.00/100%)
INFO: [1/2] rbd:ceph1/vm-203-disk-1:conf=/etc/pve/ceph.conf:id=admin:keyring=/etc/pve/priv/ceph/ceph1.keyring -> disk1.vmdk
    (100.00/100%)
INFO: All disks converted.
INFO: VMX generated -> /vmimage/temp/graylog5-customer.vmx
INFO: Packing OVA with ovftool...
Opening VMX source: /vmimage/temp/graylog5-customer.vmx
Opening OVA target: /vmimage/temp/graylog5-customer.ova
Writing OVA package: /vmimage/temp/graylog5-customer.ova
Transfer Completed                    
Completed successfully
SUCCESS: OVA ready -> /vmimage/temp/graylog5-customer.ova
INFO: Cleaning temporary VMX/VMDK files...
INFO: Temporary files removed.
```

---

## 工作流程

1. **驗證環境** – 檢查 `ovftool` / `qemu-img` / PVE config
2. **解析 VM 設定** – CPU、RAM、UUID、UEFI/Bios、磁碟列表
3. **磁碟路徑判定**

   * **RBD** → `rbd:<pool>/<image>`
   * 其他 → `pvesm path …` / fallback `/var/lib/vz/images`
4. **容量預估** – 加 20 % buffer，空間不足將停止與提醒
5. **`qemu-img convert`** → `streamOptimized, adapter=lsilogic, compat6`
6. **產生 VMX** – here-doc 寫入，正確 `virtualHW.version`
7. **`ovftool --diskMode=thin`** 打包 OVA
8. **清理暫存** (`MODE=clean`) 或保留 (`MODE=keep`)

---

## 常見問題

| 現象 / 訊息                              | 解決方案                                             |
| ------------------------------------ | ------------------------------------------------ |
| `ovftool not found`                  | 確認 `/opt/ovftool/ovftool` 可執行                    |
| `unsupported or invalid disk type 7` | 確認 `streamOptimized` + `ovftool --diskMode=thin` |
| 匯入後無法開機 (IDE 介面)                     | ESXi 會自動套用 LSI SAS；若仍 IDE，手動改控制器                 |
| RBD 權限拒絕                             | 檢查 `/etc/pve/ceph.conf` 與 keyring 讀取權限           |

---

## TODO / Roadmap

* [ ] 自動上傳至 ESXi datastore (需要 govc)
* [ ] 支援多網卡 / 自訂 MAC
* [ ] 轉檔進度條整合進 `pv` 友善顯示

目標：讓 Proxmox VE 與 ESXi 互轉檔更輕鬆！

