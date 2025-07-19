> 本程式與說明由 ChatGPT o3 撰寫

## 功能總覽

下面列出 **`oomkill_java.sh`** 腳本的主要功能與設計亮點，方便你快速掌握它能做到哪些事、如何使用，以及執行流程中的安全機制。

### 1. 目標程序鎖定

* **名稱或 PID 兩種方式**

  * `--name <關鍵字>`：以 JAR 檔名或主類別名稱模糊比對，自動抓到第一個或讓你挑選 PID。
  * `--pid <PID>`：已知目標時可直接指定。

### 2. 自動偵測 cgroup 版本

* **v1**：使用 `cgcreate/cgset/cgexec`；建立 `memory` cgroup、寫入 tasks。
* **v2**：透過 `systemd-run --scope` 動態產生 slice/scope；等效設定記憶體與 swap 上限。

### 3. 記憶體與 swap 限制

* **MemoryMax / memory.limit\_in\_bytes**：可用 `--mem <MB>` 自訂（預設 512 MB）。
* **完全禁止 swap**

  * v1 透過 `memory.memsw.limit_in_bytes == memory.limit_in_bytes` 達成。
  * v2 使用 `MemorySwapMax=0` 真正阻止頁面換出。

### 4. OOM 優先等級

* 對目標 PID 寫入 `oom_score_adj=1000`，保證缺記憶體時第一個被 OOM Killer 砍掉。

### 5. 一鍵產生記憶體壓力（可開關）

* 預設開啟：在背景跑一段 Python 迴圈不斷配置 1 MB 字串。
* 可選擇 `--no-stress` 關閉，或 `--stress-in-cgroup` 讓壓力程式與 Java 同組，加速用光配額。

### 6. 逾時與監控

* `--timeout <秒>` 設定等待 OOM 的最長秒數（預設 30s）。
* 期間每秒檢查 `/proc/<PID>` 是否消失，並於結束時列出近 50 行 kernel log 中的 OOM / killed 訊息。

### 7. 自動清理

* 結束後會：

  1. 強制終止壓力程式（若仍存活）。
  2. 刪除 cgroup（v1）或停止 systemd scope（v2），避免殘留資源。

### 8. 使用者介面友善

* 中文提示、錯誤訊息與說明 (`-h/--help`)。
* 參數皆可選，預設值已適合常見測試場景。

### 9. 相依與相容性

* **必要**：`bash 4+`, `sudo`, `python3`。
* **v1 系統** 需安裝 `cgroup-tools`（Ubuntu/Debian：`sudo apt install cgroup-tools`）。
* **v2 系統** 只要 `systemd-run` 可用即可。

---

### 快速範例

```bash
# 1) 以 JAR 名稱鎖定，512MB 上限，等待 40 秒
sudo ./oomkill_java.sh --name MyApp.jar --mem 512 --timeout 40

# 2) 已知 PID，禁用壓力程式，只驗證 cgroup 限制
sudo ./oomkill_java.sh --pid 12345 --no-stress

# 3) 壓力程式與 Java 同 cgroup，加快觸發 OOM
sudo ./oomkill_java.sh -n com.example.Main --stress-in-cgroup
```

---

> 如需進一步客製（例如改寫為 systemd 服務檔、整合日誌收集），隨時告訴我！
