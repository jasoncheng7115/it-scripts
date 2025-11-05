# Graylog Nutanix Pipeline 完整設定工具

**作者：** Jason Cheng (Jason Tools)  
**協作：** Claude Code Sonnet 4.5  
**版本：** 1.2.0  
**最後更新：** 2025-10-31   

**最新更新（v1.2.0）：**
- ✅ 新增帳號權限檢查功能
- ✅ 確認所有請求包含必要的 `X-Requested-By` header（Graylog 2.5+ 必要）
- ✅ 新增詳細的 Debug 資訊（headers、URL、錯誤訊息）
- ✅ 更清楚的錯誤提示（區分權限不足 vs API 限制）
- 自動建立所有 rules 和 pipeline，**僅需手動連接最後一步**

✅ **已完成測試並成功運行於 Graylog 6.3.4**

## 快速使用

這是最終完整版本，執行一次即可完成所有設定！

### 前置需求

**帳號權限**：執行腳本的帳號需要以下權限：
- `pipeline:read/create/edit/delete`
- `pipeline_rule:read/create/edit/delete`
- `pipeline_connection:read/edit`

建議使用 **admin** 帳號執行，或確保自訂角色包含上述權限。

**API Headers**：腳本已自動設定
- `Content-Type: application/json`
- `X-Requested-By: python-script`（Graylog 2.5+ 必要）

### 步驟 1：安裝依賴套件

```bash
cd /opt/ntnx_pipeline
pip3 install -r requirements.txt
```

或使用 sudo（如果遇到權限問題）：
```bash
sudo pip3 install -r requirements.txt
```

驗證安裝：
```bash
python3 -c "import requests; print(f'requests version: {requests.__version__}')"
```

### 步驟 2：執行腳本

```bash
python3 setup_ntnx_pipeline.py
```

**腳本會自動完成：**
1. ✅ 清理所有現有的 ntnx 相關 rules 和 pipelines
2. ✅ 建立 31 個 pipeline rules
3. ✅ 建立 pipeline 並正確綁定 rules 到 3 個 stages
4. ⚠️ 嘗試連接 pipeline（Graylog 6.3.4 API 限制，需手動完成）

**僅需手動完成最後一步**：在 Web UI 勾選 pipeline（約 10 秒）

### 腳本功能

1. **自動清理**：刪除所有現有的 ntnx 相關 rules 和 pipelines
2. **重新建立**：建立完整的 31 個 pipeline rules
3. **建立 pipeline**：建立「Nutanix Prism Central Processing」pipeline
4. **自動連接**：嘗試將 pipeline 連接到 "All messages" stream

### 建立內容

**Stage 0（6 個 rules）- 共通標記＋基礎擷取**
- ntnx_common_tag（protobuf 格式）
- ntnx_iam_base（protobuf 格式）
- ntnx_login_base（protobuf 格式）
- ntnx_vm_anomaly_base（protobuf 格式）
- ntnx_license_base（protobuf 格式）
- ntnx_consolidated_audit_base（JSON 格式）

**Stage 1（14 個 rules）- 時間戳記覆寫、事件分類、登入狀態、VM 參數、IAM 細拆與 Login 動作**
- ntnx_timestamp_override（protobuf 格式時間戳記）
- ntnx_consolidated_timestamp_override（JSON 格式時間戳記）
- ntnx_consolidated_login_category（JSON Login 分類）
- ntnx_consolidated_iam_category（JSON IAM 分類）
- ntnx_consolidated_login_success（JSON 登入成功標記）
- ntnx_consolidated_login_failed（JSON 登入失敗標記）
- ntnx_consolidated_vm_params（JSON VM 參數擷取）
- ntnx_iam_from_message_full
- ntnx_iam_from_message_basic
- ntnx_iam_from_message_emptyperm
- ntnx_login_action_login
- ntnx_login_action_logout
- ntnx_login_action_fail
- ntnx_login_suffix_version

**Stage 2（11 個 rules）- Task/Op、Zeus、補強**
- ntnx_task_op_completed_ms
- ntnx_task_op_completed_us
- ntnx_add_alerts_success
- ntnx_zeus_shuffle_started
- ntnx_zeus_shuffle_done
- ntnx_zeus_shuffle_next_schedule
- ntnx_pc_registration_discard
- ntnx_pc_registration_set
- ntnx_alert_notification_skipped
- ntnx_receive_notif_generic
- ntnx_vm_anomaly_more_fields

**總計：31 個 rules + 1 個 pipeline**

## 執行結果範例

```
============================================================
Graylog Nutanix Pipeline Rules 完整設定腳本
============================================================

測試 Graylog 連線...
✓ Graylog 連線成功
  版本: 6.3.4+73b7fca
  Timezone: Asia/Taipei

正在探測 Graylog API 端點...
✓ 找到可用的 API 端點: /api/system/pipelines

使用的 API 端點:
  Rules: http://192.168.1.127:9000/api/system/pipelines/rule
  Pipelines: http://192.168.1.127:9000/api/system/pipelines/pipeline
  Connections: http://192.168.1.127:9000/api/system/pipelines/connections

============================================================
清理現有的 Nutanix 相關資源
============================================================
  刪除 pipeline: Nutanix Prism Central Processing (...)
    ✓ 已刪除

✓ 已刪除 1 個 pipelines

  刪除 rule: ntnx_common_tag (...)
    ✓ 已刪除
  ...

✓ 已刪除 31 個 rules

✓ 清理完成

------------------------------------------------------------
Step 1: 建立 Stage 0 Rules (共通標記＋基礎擷取)
------------------------------------------------------------
✓ 建立 rule: ntnx_common_tag (ID: ...)
...

✓ Stage 0 完成，共建立 6 個 rules

[繼續建立 Stage 1, 2...]

============================================================
✓ 設定流程完成！
============================================================

總計建立:
  - Stage 0 Rules: 6
  - Stage 1 Rules: 14
  - Stage 2 Rules: 11
  - 總 Rules: 31
  - Pipeline: 1

請前往 Graylog Web UI 查看:
  Rules: http://192.168.1.127:9000/system/pipelines/rules
  Pipelines: http://192.168.1.127:9000/system/pipelines/pipelines
  Connections: http://192.168.1.127:9000/system/pipelines/connections
```

## Pipeline 連接說明

### ⚠️ Graylog 6.3.4 API 限制

經過實際測試，Graylog 6.3.4 的 Connections API 有以下限制：

| API 端點 | 方法 | 結果 | 說明 |
|---------|------|------|------|
| `/connections/to_stream/{stream_id}` | POST/PUT | HTTP 404 | 端點不存在 |
| `/connections` | POST/PUT | HTTP 405 | 唯讀，不允許修改 |

**結論：** Graylog 6.3.4 必須透過 **Web UI** 手動連接 Pipeline 到 Stream。

### 手動連接步驟（必要操作，約 10 秒）⏱️

1. 開啟 http://192.168.1.127:9000/system/pipelines/connections
2. 找到 **"All messages"** stream
3. 在下拉選單勾選 **"Nutanix Prism Central Processing"**
4. 點擊 **"Update connections"** 按鈕
5. ✅ 完成！

**提示：** 腳本執行完成後會顯示此步驟的詳細說明。

### 驗證連接成功

連接成功後，在 Connections 頁面應該會看到：
```
Stream: All messages
└─ Pipeline: Nutanix Prism Central Processing
   ├─ Stage 0 (6 rules)
   ├─ Stage 1 (14 rules)
   └─ Stage 2 (11 rules)
```

## 驗證設定

1. **檢查 Rules**：http://192.168.1.127:9000/system/pipelines/rules
   - 應該看到 31 個 ntnx_ 開頭的 rules

2. **檢查 Pipeline**：http://192.168.1.127:9000/system/pipelines/pipelines
   - 應該看到「Nutanix Prism Central Processing」
   - 點擊編輯，確認三個 stages 都有對應的 rules

3. **檢查 Connection**：http://192.168.1.127:9000/system/pipelines/connections
   - 確認「All messages」stream 已連接到「Nutanix Prism Central Processing」

4. **測試訊息處理**：
   - 前往 Search 頁面
   - 搜尋 `vendor:Nutanix`
   - 應該可以看到處理後的欄位，如 `ntnx.*`

## 疑難排解

### 問題：權限檢查失敗（HTTP 403）

**症狀**：
```
✗ 權限不足：帳號 'xxx' 無法存取 Pipeline API
```

**解決方法**：
1. 確認使用的是 **admin** 帳號
2. 如使用自訂角色，確認包含以下權限：
   - `pipeline:read/create/edit/delete`
   - `pipeline_rule:read/create/edit/delete`
   - `pipeline_connection:read/edit`
3. 在 Graylog Web UI：**System → Users → Roles** 檢查角色權限

### 問題：部分 rules 建立失敗

**解決方法**：
- 查看錯誤訊息中的語法錯誤
- 前往 Web UI 手動建立失敗的 rule
- 或重新執行腳本

### 問題：缺少 X-Requested-By header（HTTP 400）

**症狀**：
```
HTTP 400: 缺少 CSRF header
```

**解決方法**：
- 腳本已自動設定此 header（v1.2.0+）
- 如仍出現此錯誤，請回報 issue

### 問題：Pipeline 未連接到 stream

**解決方法**：
- Graylog 6.3.4 的 Connections API 為唯讀
- 必須按照上方「手動連接 Pipeline」步驟操作（約 10 秒）

### 問題：API 端點探測失敗

**解決方法**：
- 確認 Graylog 版本支援 Pipeline Processor
- 確認帳號有 admin 權限
- 查看 Graylog 日誌檔

## 技術細節

### API 安全性要求（Graylog 2.5+）

根據 Graylog 官方文件，從 2.5 版本開始，所有**非 GET** 的 API 請求都必須包含：

```
X-Requested-By: <any-value>
```

此為 CSRF 保護機制。本腳本已自動設定此 header。

### API 版本相容性

腳本自動探測以下 API 端點格式：
- Graylog 6.x: `/api/system/pipelines`
- Graylog 4-5.x: `/api/plugins/org.graylog.plugins.pipelineprocessor/system/pipelines`
- 其他版本: 自動嘗試多種格式

### 所需權限

執行腳本的帳號必須擁有以下權限：
- **pipeline:read/create/edit/delete** - 建立和編輯 pipelines
- **pipeline_rule:read/create/edit/delete** - 建立和編輯 pipeline rules
- **pipeline_connection:read/edit** - 連接 pipeline 到 streams

建議使用 Admin 帳號，或在 **System → Users → Roles** 中建立包含上述權限的自訂角色。

### Graylog 6.x 特殊要求

在 Graylog 6.x 中綁定 rules 到 pipeline stages 需要同時更新兩個欄位：

1. **`stages` 欄位**（JSON 格式）：
   ```json
   {
     "stage": 0,
     "match": "EITHER",
     "rules": ["rule_name1", "rule_name2"]
   }
   ```
   - 使用 rule 的 **title**（名稱），而不是 ID
   - `match` 可以是 `EITHER` 或 `ALL`

2. **`source` 欄位**（文字格式）：
   ```
   pipeline "Pipeline Name"
   stage 0 match either
   rule "rule_name1"
   rule "rule_name2"
   stage 1 match either
   rule "rule_name3"
   end
   ```
   - Rules 必須緊接在所屬 stage 定義之後
   - 順序很重要！

### Pipeline 設計原則

1. **Stage 分層處理**
   - Stage 0: 基礎欄位擷取
   - Stage 1: 依據擷取欄位做細部解析
   - Stage 2: 補強和特殊處理

2. **欄位命名規範**
   - 統一使用 `ntnx.*` 前綴
   - 分類清楚：`ntnx.iam.*`, `ntnx.login.*`, `ntnx.vm.*` 等

3. **效能優化**
   - 使用 `has_field()` 和 `contains()` 快速過濾
   - 避免複雜的正則表達式
   - Stage 依序處理，避免重複運算

## 相關檔案

- `setup_ntnx_pipeline.py` - 主要腳本（完整版，含清理+重建+連接）
- `requirements.txt` - Python 依賴套件
- `README.md` - 本說明文件

## 授權與支援

此工具為內部使用，如有問題請聯繫系統管理員。
