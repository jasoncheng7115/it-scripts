#!/usr/bin/env python3
"""
Graylog Nutanix Pipeline Rules 完整設定腳本

作者：Jason Cheng (Jason Tools)
協作：Claude Code Sonnet 4.5
版本：1.2.0
最後更新：2025-10-31

重要說明：
- 根據 Graylog 官方文件，所有非 GET 請求必須包含 X-Requested-By header
- 需要的權限：pipeline:read/create/edit/delete, pipeline_rule:read/create/edit/delete, pipeline_connection:read/edit
- Graylog 6.3.4 的 Connections API 為唯讀，必須透過 Web UI 手動連接

功能：
1. 清理所有現有的 ntnx 相關 rules 和 pipelines
2. 重新建立所有 Nutanix Prism Central Pipeline Rules
3. 建立 pipeline 並連接到 stream
"""

import requests
import json
import sys
import time
from typing import Dict, List, Optional

# Graylog 設定
GRAYLOG_URL = "http://192.168.1.127:9000"
GRAYLOG_USER = "admin"
GRAYLOG_PASSWORD = "yourpassword"

# 設定 requests session
session = requests.Session()
session.auth = (GRAYLOG_USER, GRAYLOG_PASSWORD)
session.headers.update({
    "Content-Type": "application/json",
    "X-Requested-By": "python-script"
})

# 全域變數儲存正確的端點
RULE_ENDPOINT = None
PIPELINE_ENDPOINT = None
CONNECTION_ENDPOINT = None


def check_permissions() -> bool:
    """
    檢查目前使用者是否有 Pipeline 相關權限

    Returns:
        True if 有足夠權限，False otherwise
    """
    try:
        # 嘗試讀取 pipelines 來確認權限
        response = session.get(f"{GRAYLOG_URL}/api/system/pipelines/pipeline")

        if response.status_code == 200:
            print(f"✓ 帳號權限確認：可存取 Pipeline API")
            return True
        elif response.status_code == 403:
            print(f"✗ 權限不足：帳號 '{GRAYLOG_USER}' 無法存取 Pipeline API")
            print(f"  需要的權限：")
            print(f"    - pipeline:read/create/edit/delete")
            print(f"    - pipeline_rule:read/create/edit/delete")
            print(f"    - pipeline_connection:read/edit")
            print(f"  請確認帳號是 Admin 或已指派上述權限")
            return False
        else:
            print(f"⚠ 權限檢查異常：HTTP {response.status_code}")
            return True  # 繼續執行，可能是其他問題

    except Exception as e:
        print(f"⚠ 權限檢查失敗：{str(e)}")
        return True  # 繼續執行


def detect_api_endpoints() -> bool:
    """
    自動探測正確的 API 端點

    Returns:
        成功回傳 True，失敗回傳 False
    """
    global RULE_ENDPOINT, PIPELINE_ENDPOINT, CONNECTION_ENDPOINT

    print("正在探測 Graylog API 端點...")

    possible_patterns = [
        "/api/system/pipelines",
        "/api/plugins/org.graylog.plugins.pipelineprocessor/system/pipelines",
        "/plugins/org.graylog.plugins.pipelineprocessor/system/pipelines",
        "/system/pipelines",
    ]

    for pattern in possible_patterns:
        rule_url = f"{GRAYLOG_URL}{pattern}/rule"

        try:
            response = session.get(rule_url)

            if response.status_code == 200:
                print(f"✓ 找到可用的 API 端點: {pattern}")
                RULE_ENDPOINT = rule_url
                PIPELINE_ENDPOINT = f"{GRAYLOG_URL}{pattern}/pipeline"
                CONNECTION_ENDPOINT = f"{GRAYLOG_URL}{pattern}/connections"
                return True
            elif response.status_code in [401, 403]:
                print(f"  認證問題: {pattern}")
                continue
            elif response.status_code == 404:
                continue

        except Exception as e:
            continue

    return False


def cleanup_existing_resources():
    """
    清理所有現有的 ntnx 相關 rules 和 pipelines
    """
    print("\n" + "=" * 60)
    print("清理現有的 Nutanix 相關資源")
    print("=" * 60)

    # 1. 刪除 pipelines
    try:
        response = session.get(PIPELINE_ENDPOINT)
        if response.status_code == 200:
            pipelines = response.json()
            deleted_pipelines = 0

            for pipeline in pipelines:
                title = pipeline.get("title", "")
                if "nutanix" in title.lower() or "ntnx" in title.lower():
                    pipeline_id = pipeline.get("id")
                    print(f"  刪除 pipeline: {title} ({pipeline_id})")

                    delete_response = session.delete(f"{PIPELINE_ENDPOINT}/{pipeline_id}")
                    if delete_response.status_code in [200, 204]:
                        print(f"    ✓ 已刪除")
                        deleted_pipelines += 1
                    else:
                        print(f"    ✗ 刪除失敗: HTTP {delete_response.status_code}")

            if deleted_pipelines > 0:
                print(f"\n✓ 已刪除 {deleted_pipelines} 個 pipelines")
            else:
                print("\n  (沒有找到需要刪除的 pipelines)")

    except Exception as e:
        print(f"✗ 清理 pipelines 時發生錯誤: {str(e)}")

    # 2. 刪除 rules
    try:
        response = session.get(RULE_ENDPOINT)
        if response.status_code == 200:
            rules = response.json()
            deleted_rules = 0

            for rule in rules:
                title = rule.get("title", "")
                if title.startswith("ntnx_"):
                    rule_id = rule.get("id")
                    print(f"  刪除 rule: {title} ({rule_id})")

                    delete_response = session.delete(f"{RULE_ENDPOINT}/{rule_id}")
                    if delete_response.status_code in [200, 204]:
                        print(f"    ✓ 已刪除")
                        deleted_rules += 1
                    else:
                        print(f"    ✗ 刪除失敗: HTTP {delete_response.status_code}")

            if deleted_rules > 0:
                print(f"\n✓ 已刪除 {deleted_rules} 個 rules")
            else:
                print("\n  (沒有找到需要刪除的 rules)")

    except Exception as e:
        print(f"✗ 清理 rules 時發生錯誤: {str(e)}")

    print("\n✓ 清理完成")


# Stage 1: 共通標記＋基礎擷取
STAGE1_RULES = [
    {
        "title": "ntnx_common_tag",
        "description": "Nutanix 共通標記與基礎欄位",
        "source": """rule "ntnx_common_tag"
when
  has_field("message") &&
  contains(to_string($message.message), "audit-alert_manager")
then
  set_field("vendor",  "Nutanix");
  set_field("product", "Prism Central");

  let mname = regex("notification_name:\\\\s*\\"([^\\"]+)\\"", to_string($message.message));
  let mts   = regex("timestamp_usecs:\\\\s*(\\\\d+)",         to_string($message.message));
  set_field("ntnx_notification_name", to_string(mname["0"]));
  set_field("ntnx_timestamp_usecs",   to_string(mts["0"]));
end"""
    },
    {
        "title": "ntnx_iam_base",
        "description": "IAM 事件基礎欄位擷取",
        "source": """rule "ntnx_iam_base"
when
  has_field("message") &&
  contains(to_string($message.message), "IAMAdministrationEventAudit")
then
  let raw = to_string($message.message);

  let u = regex("member_name:\\\\s*\\"audit_user\\"\\\\s*member_value\\\\s*\\\\{\\\\s*string_value:\\\\s*\\"([^\\"]*)\\"", raw);
  let i = regex("member_name:\\\\s*\\"ip_address\\"\\\\s*member_value\\\\s*\\\\{\\\\s*string_value:\\\\s*\\"([^\\"]*)\\"", raw);
  let m = regex("member_name:\\\\s*\\"message\\"\\\\s*member_value\\\\s*\\\\{\\\\s*string_value:\\\\s*\\"([^\\"]+)\\"",  raw);

  set_field("ntnx_iam_user",       lowercase(to_string(u["0"])));
  set_field("ntnx_iam_src_ip",     to_string(i["0"]));
  set_field("ntnx_iam_message",    to_string(m["0"]));
  set_field("ntnx_event_category", "iam");
end"""
    },
    {
        "title": "ntnx_login_base",
        "description": "Login 事件基礎欄位擷取",
        "source": """rule "ntnx_login_base"
when
  has_field("message") &&
  contains(to_string($message.message), "LoginInfoAudit")
then
  let raw = to_string($message.message);

  let u = regex("member_name:\\\\s*\\"audit_user\\"\\\\s*member_value\\\\s*\\\\{\\\\s*string_value:\\\\s*\\"([^\\"]+)\\"", raw);
  let i = regex("member_name:\\\\s*\\"ip_address\\"\\\\s*member_value\\\\s*\\\\{\\\\s*string_value:\\\\s*\\"([^\\"]+)\\"", raw);
  let m = regex("member_name:\\\\s*\\"message\\"\\\\s*member_value\\\\s*\\\\{\\\\s*string_value:\\\\s*\\"([^\\"]+)\\"",  raw);

  set_field("ntnx_login_user",     lowercase(to_string(u["0"])));
  set_field("ntnx_login_src_ip",   to_string(i["0"]));
  set_field("ntnx_login_message",  to_string(m["0"]));
  set_field("ntnx_event_category", "login");
end"""
    },
    {
        "title": "ntnx_vm_anomaly_base",
        "description": "VM Anomaly 事件基礎欄位",
        "source": """rule "ntnx_vm_anomaly_base"
when
  has_field("message") &&
  contains(to_string($message.message), "VMAnomalyAudit")
then
  let raw = to_string($message.message);

  let vm  = regex("member_name:\\\\s*\\"vm_name\\"\\\\s*member_value\\\\s*\\\\{\\\\s*string_value:\\\\s*\\"([^\\"]+)\\"",      raw);
  let ttl = regex("member_name:\\\\s*\\"title\\"\\\\s*member_value\\\\s*\\\\{\\\\s*string_value:\\\\s*\\"([^\\"]+)\\"",        raw);
  let cl  = regex("member_name:\\\\s*\\"cluster_name\\"\\\\s*member_value\\\\s*\\\\{\\\\s*string_value:\\\\s*\\"([^\\"]+)\\"", raw);

  set_field("ntnx_vm_name",        to_string(vm["0"]));
  set_field("ntnx_title",          to_string(ttl["0"]));
  set_field("ntnx_cluster_name",   to_string(cl["0"]));
end"""
    },
    {
        "title": "ntnx_license_base",
        "description": "License 到期事件擷取",
        "source": """rule "ntnx_license_base"
when
  has_field("message") &&
  (contains(to_string($message.message), "License Expiry")
   || contains(to_string($message.message), "PC License Expiry"))
then
  let raw = to_string($message.message);

  let uid = regex("alert_uid:\\\\s*\\"([^\\"]+)\\"", raw);
  let sev = regex("severity:\\\\s*k(\\\\w+)",       raw);
  let ttl = regex("title:\\\\s*\\"([^\\"]+)\\"",     raw);
  let cu1 = regex("cluster_uuid:\\\\s*\\"([0-9a-f-]{36})\\"", raw);
  let cu2 = regex("member_name:\\\\s*\\"cluster_uuid\\"\\\\s*member_value\\\\s*\\\\{\\\\s*string_value:\\\\s*\\"([^\\"]+)\\"", raw);

  set_field("ntnx_alert_uid",    to_string(uid["0"]));
  set_field("ntnx_severity",     lowercase(to_string(sev["0"])));
  set_field("ntnx_title",        to_string(ttl["0"]));
  set_field("ntnx_cluster_uuid", to_string(cu1["0"]));
  set_field("ntnx_cluster_uuid", to_string(cu2["0"]));
end"""
    },
    {
        "title": "ntnx_consolidated_audit_base",
        "description": "Consolidated Audit JSON 格式基礎解析",
        "source": """rule "ntnx_consolidated_audit_base"
when
  has_field("message") &&
  contains(to_string($message.message), "consolidated_audit:") &&
  contains(to_string($message.message), "\\"recordType\\":\\"Audit\\"")
then
  set_field("vendor",  "Nutanix");
  set_field("product", "Prism Central");

  let raw = to_string($message.message);

  // 使用正則表達式直接擷取各個欄位值
  let alert_uid = regex("\\"alertUid\\":\\"([^\\"]+)\\"", raw);
  let op_type = regex("\\"operationType\\":\\"([^\\"]+)\\"", raw);
  let username = regex("\\"userName\\":\\"([^\\"]+)\\"", raw);
  let sev = regex("\\"severity\\":\\"([^\\"]+)\\"", raw);
  let msg = regex("\\"defaultMsg\\":\\"([^\\"]+)\\"", raw);
  let ts = regex("\\"creationTimestampUsecs\\":\\"(\\\\d+)\\"", raw);
  let cluster = regex("\\"originatingClusterUuid\\":\\"([^\\"]+)\\"", raw);
  let uid = regex("\\"uuid\\":\\"([0-9a-f-]+)\\"", raw);

  // 擷取 params 內的欄位
  let audit_user = regex("\\"audit_user\\":\\"([^\\"]+)\\"", raw);
  let ip_addr = regex("\\"ip_address\\":\\"([^\\"]+)\\"", raw);
  let browser = regex("\\"browser_info\\":\\"([^\\"]+)\\"", raw);
  let param_op = regex("params.*?\\"operation_type\\":\\"([^\\"]+)\\"", raw);

  // 設定欄位
  set_field("ntnx_alert_uid",              to_string(alert_uid["0"]));
  set_field("ntnx_operation_type",         to_string(op_type["0"]));
  set_field("ntnx_user_name",              lowercase(to_string(username["0"])));
  set_field("ntnx_severity",               lowercase(to_string(sev["0"])));
  set_field("ntnx_default_msg",            to_string(msg["0"]));
  set_field("ntnx_creation_timestamp_usecs", to_string(ts["0"]));
  set_field("ntnx_cluster_uuid",           to_string(cluster["0"]));
  set_field("ntnx_uuid",                   to_string(uid["0"]));
  set_field("ntnx_params_audit_user",      lowercase(to_string(audit_user["0"])));
  set_field("ntnx_params_ip_address",      to_string(ip_addr["0"]));
  set_field("ntnx_params_operation_type",  to_string(param_op["0"]));
  set_field("ntnx_params_browser_info",    to_string(browser["0"]));
end"""
    }
]

# Stage 2: IAM 三種句型；Login 動作與版本
STAGE2_RULES = [
    {
        "title": "ntnx_timestamp_override",
        "description": "覆寫 timestamp 為事件實際發生時間（protobuf 格式）",
        "source": """rule "ntnx_timestamp_override"
when
  has_field("ntnx_timestamp_usecs") &&
  to_long($message.ntnx_timestamp_usecs, 0) > 0
then
  // timestamp_usecs 是微秒，需除以 1000 轉為毫秒
  let ts_usecs = to_long($message.ntnx_timestamp_usecs);
  let ts_msecs = ts_usecs / 1000;
  let event_time = parse_unix_milliseconds(ts_msecs);
  set_field("timestamp", event_time);
end"""
    },
    {
        "title": "ntnx_consolidated_timestamp_override",
        "description": "覆寫 timestamp 為事件實際發生時間（JSON 格式）",
        "source": """rule "ntnx_consolidated_timestamp_override"
when
  has_field("ntnx_creation_timestamp_usecs") &&
  to_long($message.ntnx_creation_timestamp_usecs, 0) > 0
then
  // creationTimestampUsecs 是微秒，需除以 1000 轉為毫秒
  let ts_usecs = to_long($message.ntnx_creation_timestamp_usecs);
  let ts_msecs = ts_usecs / 1000;
  let event_time = parse_unix_milliseconds(ts_msecs);
  set_field("timestamp", event_time);
end"""
    },
    {
        "title": "ntnx_consolidated_login_category",
        "description": "Consolidated Audit Login 事件類別標記",
        "source": """rule "ntnx_consolidated_login_category"
when
  has_field("ntnx_alert_uid") &&
  contains(lowercase(to_string($message.ntnx_alert_uid)), "login")
then
  set_field("ntnx_event_category", "login");
end"""
    },
    {
        "title": "ntnx_consolidated_iam_category",
        "description": "Consolidated Audit IAM 事件類別標記",
        "source": """rule "ntnx_consolidated_iam_category"
when
  has_field("ntnx_alert_uid") &&
  contains(lowercase(to_string($message.ntnx_alert_uid)), "iam")
then
  set_field("ntnx_event_category", "iam");
end"""
    },
    {
        "title": "ntnx_consolidated_login_success",
        "description": "Consolidated Audit 登入成功標記",
        "source": """rule "ntnx_consolidated_login_success"
when
  has_field("ntnx_default_msg") &&
  contains(to_string($message.ntnx_default_msg), "has logged in from")
then
  set_field("ntnx_login_status", "success");
  set_field("ntnx_login_action", "login");
end"""
    },
    {
        "title": "ntnx_consolidated_login_failed",
        "description": "Consolidated Audit 登入失敗標記",
        "source": """rule "ntnx_consolidated_login_failed"
when
  has_field("ntnx_default_msg") &&
  contains(to_string($message.ntnx_default_msg), "failed to log in from")
then
  set_field("ntnx_login_status", "failed");
  set_field("ntnx_login_action", "login");
end"""
    },
    {
        "title": "ntnx_consolidated_vm_params",
        "description": "Consolidated Audit VM 參數擷取",
        "source": """rule "ntnx_consolidated_vm_params"
when
  has_field("ntnx_alert_uid") &&
  contains(to_string($message.ntnx_alert_uid), "VmUpdate")
then
  let raw = to_string($message.message);

  // 擷取 VM 相關參數
  let vm_name = regex("\\"vm_name\\":\\"([^\\"]+)\\"", raw);
  let old_name = regex("\\"old_name\\":\\"([^\\"]+)\\"", raw);
  let memory = regex("\\"memory_mb\\":\\"(\\\\d+)\\"", raw);
  let vcpus = regex("\\"num_vcpus\\":\\"(\\\\d+)\\"", raw);
  let cores = regex("\\"num_cores_per_vcpu\\":\\"(\\\\d+)\\"", raw);
  let machine = regex("\\"machine_type\\":\\"([^\\"]+)\\"", raw);
  let boot_order = regex("\\"boot_device_order\\":\\"([^\\"]+)\\"", raw);
  let timezone = regex("\\"hardware_clock_timezone\\":\\"([^\\"]+)\\"", raw);
  let is_uefi = regex("\\"is_uefi_boot\\":\\"([^\\"]+)\\"", raw);
  let is_secure = regex("\\"is_secure_boot\\":\\"([^\\"]+)\\"", raw);
  let is_agent = regex("\\"is_agent_vm\\":\\"([^\\"]+)\\"", raw);

  // 設定 VM 參數欄位
  set_field("ntnx_vm_name", to_string(vm_name["0"]));
  set_field("ntnx_vm_old_name", to_string(old_name["0"]));
  set_field("ntnx_vm_memory_mb", to_string(memory["0"]));
  set_field("ntnx_vm_num_vcpus", to_string(vcpus["0"]));
  set_field("ntnx_vm_cores_per_vcpu", to_string(cores["0"]));
  set_field("ntnx_vm_machine_type", to_string(machine["0"]));
  set_field("ntnx_vm_boot_device_order", to_string(boot_order["0"]));
  set_field("ntnx_vm_timezone", to_string(timezone["0"]));
  set_field("ntnx_vm_is_uefi_boot", to_string(is_uefi["0"]));
  set_field("ntnx_vm_is_secure_boot", to_string(is_secure["0"]));
  set_field("ntnx_vm_is_agent_vm", to_string(is_agent["0"]));

  // 設定事件類別
  set_field("ntnx_event_category", "vm");
end"""
    },
    {
        "title": "ntnx_iam_from_message_full",
        "description": "IAM 訊息解析（含 attributes）",
        "source": """rule "ntnx_iam_from_message_full"
when
  has_field("ntnx_iam_message") &&
  contains(to_string($message."ntnx_iam_message"), "granted permission to ") &&
  contains(to_string($message."ntnx_iam_message"), " on ") &&
  contains(to_string($message."ntnx_iam_message"), " from ") &&
  contains(to_string($message."ntnx_iam_message"), "attributes {")
then
  let msg = to_string($message."ntnx_iam_message");
  let r   = regex(
    "User\\\\s+(\\\\S+)\\\\s+granted\\\\s+permission\\\\s+to\\\\s+(.+?)\\\\s+on\\\\s+(\\\\w+)\\\\s+with\\\\s+attributes\\\\s+\\\\{([^}]*)\\\\}\\\\s+from\\\\s+([\\\\d.]+)",
    msg
  );

  set_field("ntnx_iam_user",      lowercase(to_string(r["0"])));

  let pr0 = replace(to_string(r["1"]), "[\\\\[\\\\]\\\\(\\\\)\\\\\\\\'`]", "");
  let pr  = replace(pr0, "^\\\\s+|\\\\s+$", "");
  set_field("ntnx_iam_permission", pr);

  set_field("ntnx_iam_target",    to_string(r["2"]));
  set_field("ntnx_iam_attrs_raw", to_string(r["3"]));
  set_field("ntnx_iam_source_ip", to_string(r["4"]));

  let au = regex("([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", to_string(r["3"]));
  set_field("ntnx_iam_target_uuid", to_string(au["0"]));
end"""
    },
    {
        "title": "ntnx_iam_from_message_basic",
        "description": "IAM 訊息解析（一般句型）",
        "source": """rule "ntnx_iam_from_message_basic"
when
  has_field("ntnx_iam_message") &&
  contains(to_string($message."ntnx_iam_message"), "granted permission to ") &&
  contains(to_string($message."ntnx_iam_message"), " on ") &&
  contains(to_string($message."ntnx_iam_message"), " from ") &&
  !contains(to_string($message."ntnx_iam_message"), "attributes {")
then
  let msg = to_string($message."ntnx_iam_message");
  let r   = regex(
    "User\\\\s+(\\\\S+)\\\\s+granted\\\\s+permission\\\\s+to\\\\s+(.+?)\\\\s+on\\\\s+(\\\\w+)\\\\s+from\\\\s+([\\\\d.]+)",
    msg
  );

  set_field("ntnx_iam_user",      lowercase(to_string(r["0"])));

  let pr0 = replace(to_string(r["1"]), "[\\\\[\\\\]\\\\(\\\\)\\\\\\\\'`]", "");
  let pr  = replace(pr0, "^\\\\s+|\\\\s+$", "");
  set_field("ntnx_iam_permission", pr);

  set_field("ntnx_iam_target",    to_string(r["2"]));
  set_field("ntnx_iam_source_ip", to_string(r["3"]));
end"""
    },
    {
        "title": "ntnx_iam_from_message_emptyperm",
        "description": "IAM 訊息解析（空權限）",
        "source": """rule "ntnx_iam_from_message_emptyperm"
when
  has_field("ntnx_iam_message") &&
  contains(to_string($message."ntnx_iam_message"), "granted permission to  on ") &&
  contains(to_string($message."ntnx_iam_message"), " from ")
then
  let msg = to_string($message."ntnx_iam_message");
  let r   = regex(
    "User\\\\s+(\\\\S+)\\\\s+granted\\\\s+permission\\\\s+to\\\\s+\\\\s+on\\\\s+(\\\\w+)\\\\s+from\\\\s+([\\\\d.]+)",
    msg
  );

  set_field("ntnx_iam_user",       lowercase(to_string(r["0"])));
  set_field("ntnx_iam_permission", "");
  set_field("ntnx_iam_target",     to_string(r["1"]));
  set_field("ntnx_iam_source_ip",  to_string(r["2"]));
end"""
    },
    {
        "title": "ntnx_login_action_login",
        "description": "Login 動作：登入",
        "source": """rule "ntnx_login_action_login"
when
  has_field("ntnx_login_message") &&
  contains(to_string($message."ntnx_login_message"), "has logged in from ")
then
  set_field("ntnx_login_action", "login");
end"""
    },
    {
        "title": "ntnx_login_action_logout",
        "description": "Login 動作：登出",
        "source": """rule "ntnx_login_action_logout"
when
  has_field("ntnx_login_message") &&
  contains(to_string($message."ntnx_login_message"), "has logged out from ")
then
  set_field("ntnx_login_action", "logout");
end"""
    },
    {
        "title": "ntnx_login_action_fail",
        "description": "Login 動作：失敗",
        "source": """rule "ntnx_login_action_fail"
when
  has_field("ntnx_login_message") &&
  contains(to_string($message."ntnx_login_message"), "failed to log in from ")
then
  set_field("ntnx_login_action", "fail");
end"""
    },
    {
        "title": "ntnx_login_suffix_version",
        "description": "Login 版本號擷取",
        "source": """rule "ntnx_login_suffix_version"
when
  has_field("ntnx_login_message") &&
  contains(to_string($message."ntnx_login_message"), ": v")
then
  let v = regex(":\\\\s*v(\\\\d+)\\\\s*$", to_string($message."ntnx_login_message"));
  set_field("ntnx_login_version", to_string(v["0"]));
end"""
    }
]

# Stage 3: Task/Op、Zeus、PC 註冊、Alert 跳過、泛用通知、VM Anomaly 補強
STAGE3_RULES = [
    {
        "title": "ntnx_task_op_completed_ms",
        "description": "Task/Op 完成時間（毫秒）",
        "source": """rule "ntnx_task_op_completed_ms"
when
  has_field("message") &&
  contains(to_string($message.message), " op completed in ") &&
  contains(to_string($message.message), " ms")
then
  let raw = to_string($message.message);
  let r1 = regex("\\\\)\\\\s+(\\\\w+)\\\\s+op\\\\s+completed\\\\s+in\\\\s+(\\\\d+)\\\\s+ms", raw);

  set_field("ntnx_task_op",          to_string(r1["0"]));
  set_field("ntnx_task_duration_ms", to_string(r1["1"]));
  set_field("ntnx_task_duration_us", to_string(to_long(r1["1"]) * 1000));
end"""
    },
    {
        "title": "ntnx_task_op_completed_us",
        "description": "Task/Op 完成時間（微秒）",
        "source": """rule "ntnx_task_op_completed_us"
when
  has_field("message") &&
  contains(to_string($message.message), " op completed in ") &&
  ( contains(to_string($message.message), " us")
    || contains(to_string($message.message), " usecs") )
then
  let raw = to_string($message.message);
  let r1 = regex("\\\\)\\\\s+(\\\\w+)\\\\s+op\\\\s+completed\\\\s+in\\\\s+(\\\\d+)\\\\s+u?se?cs?", raw);

  set_field("ntnx_task_op",        to_string(r1["0"]));
  set_field("ntnx_task_duration_us", to_string(r1["1"]));
end"""
    },
    {
        "title": "ntnx_add_alerts_success",
        "description": "Alert 新增成功",
        "source": """rule "ntnx_add_alerts_success"
when
  has_field("message") &&
  contains(to_string($message.message), "Alert with uuid") &&
  contains(to_string($message.message), "added successfully into insights")
then
  let raw = to_string($message.message);
  let r  = regex("Alert\\\\s+with\\\\s+uuid\\\\s+([0-9a-f-]{36}).*?in\\\\s+(\\\\d+)\\\\s+u?se?cs?", raw);
  set_field("ntnx_alert_added_uuid", to_string(r["0"]));
  set_field("ntnx_alert_added_us",   to_string(r["1"]));
end"""
    },
    {
        "title": "ntnx_zeus_shuffle_started",
        "description": "Zeus Leadership Shuffle 開始",
        "source": """rule "ntnx_zeus_shuffle_started"
when
  has_field("message") &&
  contains(to_string($message.message), "zeus.cc") &&
  contains(to_string($message.message), "Started ShuffleLeadershipIntentOp")
then
  let raw = to_string($message.message);
  let r = regex("Started\\\\s+ShuffleLeadershipIntentOp\\\\((\\\\d+)\\\\)\\\\[(\\\\w+)\\\\]", raw);
  set_field("ntnx_cluster_leadership_intent_id", to_string(r["0"]));
  set_field("ntnx_cluster_leadership_mode",      to_string(r["1"]));
end"""
    },
    {
        "title": "ntnx_zeus_shuffle_done",
        "description": "Zeus Leadership Shuffle 完成",
        "source": """rule "ntnx_zeus_shuffle_done"
when
  has_field("message") &&
  contains(to_string($message.message), "zeus.cc") &&
  contains(to_string($message.message), "Shuffled ") &&
  contains(to_string($message.message), " leadership intents")
then
  let raw = to_string($message.message);
  let r = regex("Shuffled\\\\s+(\\\\d+)\\\\s+leadership\\\\s+intents", raw);
  set_field("ntnx_cluster_leadership_shuffled", to_string(r["0"]));
end"""
    },
    {
        "title": "ntnx_zeus_shuffle_next_schedule",
        "description": "Zeus Leadership 下次排程",
        "source": """rule "ntnx_zeus_shuffle_next_schedule"
when
  has_field("message") &&
  contains(to_string($message.message), "zeus.cc") &&
  contains(to_string($message.message), "Scheduling next shuffle leadership intent routine after ")
then
  let raw = to_string($message.message);
  let r = regex("after\\\\s+(\\\\d+)\\\\s+seconds", raw);
  set_field("ntnx_cluster_leadership_next_after_s", to_string(r["0"]));
end"""
    },
    {
        "title": "ntnx_pc_registration_discard",
        "description": "PC 註冊資訊捨棄",
        "source": """rule "ntnx_pc_registration_discard"
when
  has_field("message") &&
  contains(to_string($message.message), "PC registration timestamp for cluster with uuid") &&
  contains(to_string($message.message), "Discarding the data.")
then
  let raw = to_string($message.message);
  let r = regex("cluster\\\\s+with\\\\s+uuid\\\\s+([0-9a-f-]{36})\\\\s+was\\\\s+read\\\\s+more\\\\s+than\\\\s+one\\\\s+minute\\\\s+ago", raw);
  set_field("ntnx_pc_reg_cluster_uuid", to_string(r["0"]));
  set_field("ntnx_pc_reg_action",       "discard_old_timestamp");
end"""
    },
    {
        "title": "ntnx_pc_registration_set",
        "description": "PC 註冊時間戳記設定",
        "source": """rule "ntnx_pc_registration_set"
when
  has_field("message") &&
  contains(to_string($message.message), "PC registration timestamp for cluster") &&
  contains(to_string($message.message), "is being set to")
then
  let raw = to_string($message.message);
  let r1 = regex("cluster\\\\s+([0-9a-f-]{36})\\\\s+is\\\\s+being\\\\s+set\\\\s+to\\\\s+(\\\\d+)", raw);
  set_field("ntnx_pc_reg_cluster_uuid", to_string(r1["0"]));
  set_field("ntnx_pc_reg_set_to_usecs", to_string(r1["1"]));
end"""
    },
    {
        "title": "ntnx_alert_notification_skipped",
        "description": "Alert 通知略過",
        "source": """rule "ntnx_alert_notification_skipped"
when
  has_field("message") &&
  contains(to_string($message.message), "Not sending notification for alert with uuid")
then
  let raw = to_string($message.message);
  let r1 = regex("alert\\\\s+with\\\\s+uuid\\\\s+([0-9a-f-]{36})\\\\s+,\\\\s+uid\\\\s+(\\\\S+)\\\\s+and\\\\s+severity\\\\s+(\\\\w+)\\\\s+and\\\\s+resolved\\\\s+(\\\\d+)", raw);
  set_field("ntnx_alert_skip_uuid",     to_string(r1["0"]));
  set_field("ntnx_alert_skip_uid",      to_string(r1["1"]));
  set_field("ntnx_alert_skip_severity", lowercase(to_string(r1["2"])));
  set_field("ntnx_alert_skip_resolved", to_string(r1["3"]));
end"""
    },
    {
        "title": "ntnx_receive_notif_generic",
        "description": "ReceiveNotification 泛用處理",
        "source": """rule "ntnx_receive_notif_generic"
when
  has_field("message") &&
  contains(to_string($message.message), "ReceiveNotification RPC received with component_name:")
then
  let raw = to_string($message.message);
  let cname = regex("component_name:\\\\s*\\"([^\\"]+)\\"", raw);
  let nname = regex("notification_name:\\\\s*\\"([^\\"]+)\\"", raw);

  set_field("ntnx_notif_component", to_string(cname["0"]));
  set_field("ntnx_notif_name",      to_string(nname["0"]));
end"""
    },
    {
        "title": "ntnx_vm_anomaly_more_fields",
        "description": "VM Anomaly 補強欄位",
        "source": """rule "ntnx_vm_anomaly_more_fields"
when
  has_field("message") &&
  contains(to_string($message.message), "VMAnomalyAudit")
then
  let raw = to_string($message.message);

  let vm_uuid = regex("member_name:\\\\s*\\"vm_uuid\\"\\\\s*member_value\\\\s*\\\\{\\\\s*string_value:\\\\s*\\"([^\\"]+)\\"", raw);
  let lb     = regex("member_name:\\\\s*\\"lower_bound\\"\\\\s*member_value\\\\s*\\\\{\\\\s*int64_value:\\\\s*(\\\\d+)", raw);
  let ub     = regex("member_name:\\\\s*\\"upper_bound\\"\\\\s*member_value\\\\s*\\\\{\\\\s*int64_value:\\\\s*(\\\\d+)", raw);
  let intv   = regex("member_name:\\\\s*\\"interval_secs\\"\\\\s*member_value\\\\s*\\\\{\\\\s*int64_value:\\\\s*(\\\\d+)", raw);
  let msg    = regex("member_name:\\\\s*\\"message\\"\\\\s*member_value\\\\s*\\\\{\\\\s*string_value:\\\\s*\\"([^\\"]*)\\"", raw);

  set_field("ntnx_vm_uuid",            to_string(vm_uuid["0"]));
  set_field("ntnx_anomaly_lower",      to_string(lb["0"]));
  set_field("ntnx_anomaly_upper",      to_string(ub["0"]));
  set_field("ntnx_anomaly_interval_s", to_string(intv["0"]));
  set_field("ntnx_anomaly_message",    to_string(msg["0"]));
end"""
    }
]


def create_rule(rule_data: Dict) -> Optional[str]:
    """
    建立單一 pipeline rule

    Args:
        rule_data: 包含 title, description, source 的字典

    Returns:
        成功回傳 rule title（用於 pipeline stages），失敗回傳 None
    """
    try:
        response = session.post(
            RULE_ENDPOINT,
            json={
                "title": rule_data["title"],
                "description": rule_data.get("description", ""),
                "source": rule_data["source"]
            }
        )

        if response.status_code in [200, 201]:
            result = response.json()
            rule_id = result.get("id")
            rule_title = rule_data["title"]
            print(f"✓ 建立 rule: {rule_title} (ID: {rule_id})")
            # 回傳 title 而不是 ID，因為 pipeline stages 使用 title
            return rule_title
        else:
            print(f"✗ 建立 rule 失敗: {rule_data['title']}")
            print(f"  Status: {response.status_code}")
            if response.status_code == 400:
                errors = response.json()
                print(f"  語法錯誤，請檢查 rule source")
                # 只顯示前 3 個錯誤訊息
                for i, error in enumerate(errors[:3]):
                    print(f"    - {error.get('type')}: {error.get('reason')}")
                if len(errors) > 3:
                    print(f"    ... 還有 {len(errors) - 3} 個錯誤")
            else:
                print(f"  Response: {response.text[:200]}")
            return None

    except Exception as e:
        print(f"✗ 建立 rule 時發生錯誤: {rule_data['title']}")
        print(f"  錯誤: {str(e)}")
        return None


def create_pipeline(pipeline_name: str, pipeline_desc: str, stages: List[Dict]) -> Optional[str]:
    """
    建立 pipeline 並設定 stages

    Args:
        pipeline_name: Pipeline 名稱
        pipeline_desc: Pipeline 描述
        stages: Stage 列表，每個包含 stage number 和 rule IDs

    Returns:
        成功回傳 pipeline ID，失敗回傳 None
    """
    try:
        # Step 1: 建立 pipeline
        response = session.post(
            PIPELINE_ENDPOINT,
            json={
                "title": pipeline_name,
                "description": pipeline_desc,
                "source": f"""pipeline "{pipeline_name}"
stage 0 match either
stage 1 match either
stage 2 match either
end"""
            }
        )

        if response.status_code not in [200, 201]:
            print(f"✗ 建立 pipeline 失敗: {pipeline_name}")
            print(f"  Status: {response.status_code}")
            print(f"  Response: {response.text}")
            return None

        result = response.json()
        pipeline_id = result.get("id")
        print(f"✓ 建立 pipeline: {pipeline_name} (ID: {pipeline_id})")

        # Step 2: 更新 pipeline stages 以綁定 rules
        # 先取得完整的 pipeline 資料
        get_response = session.get(f"{PIPELINE_ENDPOINT}/{pipeline_id}")
        if get_response.status_code != 200:
            print(f"⚠ 無法取得 pipeline 詳細資料，請手動綁定 rules")
            return pipeline_id

        pipeline_data = get_response.json()

        # 更新 stages（Graylog 6.x 格式）
        pipeline_data["stages"] = stages

        # 重要：同時更新 source 欄位！
        # source 的格式：每個 stage 定義後緊接著該 stage 的 rules
        source_lines = [f'pipeline "{pipeline_name}"']

        # 按照 stage 順序生成
        for stage_data in stages:
            stage_num = stage_data["stage"]
            match_type = stage_data["match"].lower()  # EITHER -> either

            # stage 定義
            source_lines.append(f"stage {stage_num} match {match_type}")

            # 該 stage 的所有 rules（緊接在 stage 定義後）
            for rule_name in stage_data["rules"]:
                source_lines.append(f'rule "{rule_name}"')

        source_lines.append("end")

        pipeline_data["source"] = "\n".join(source_lines)

        # 移除可能造成問題的唯讀欄位
        for field in ["created_at", "modified_at", "id", "errors"]:
            pipeline_data.pop(field, None)

        # 用 PUT 更新 pipeline
        print(f"  綁定 rules 到 stages...")

        update_response = session.put(
            f"{PIPELINE_ENDPOINT}/{pipeline_id}",
            json=pipeline_data
        )

        if update_response.status_code in [200, 201]:
            print(f"  ✓ Rules 已成功綁定到 stages")
        else:
            print(f"  ✗ 綁定 rules 失敗: HTTP {update_response.status_code}")
            print(f"    Response: {update_response.text[:500]}")
            print(f"  ⚠ Pipeline 已建立，但需要手動綁定 rules")

        return pipeline_id

    except Exception as e:
        print(f"✗ 建立 pipeline 時發生錯誤: {pipeline_name}")
        print(f"  錯誤: {str(e)}")
        return None


def connect_pipeline_to_stream(pipeline_id: str, stream_id: str = "000000000000000000000001") -> bool:
    """
    將 pipeline 連接到 stream（預設為 All messages）

    Args:
        pipeline_id: Pipeline ID
        stream_id: Stream ID (預設 All messages stream)

    Returns:
        成功回傳 True，失敗回傳 False
    """
    try:
        # 先取得現有的 connections
        response = session.get(CONNECTION_ENDPOINT)

        if response.status_code != 200:
            print(f"✗ 取得現有 connections 失敗: HTTP {response.status_code}")
            return False

        connections_data = response.json()

        # Graylog 6.x 回傳列表格式
        if isinstance(connections_data, list):
            # 找到 All messages stream 的連接
            stream_connection = None
            for conn in connections_data:
                if conn.get("stream_id") == stream_id:
                    stream_connection = conn
                    break

            # 取得現有的 pipeline IDs（如果有的話）
            existing_pipeline_ids = []
            if stream_connection:
                existing_pipeline_ids = stream_connection.get("pipeline_ids", [])

            # 只加入新的 pipeline ID（如果還沒有的話）
            pipeline_ids = existing_pipeline_ids.copy()
            if pipeline_id not in pipeline_ids:
                pipeline_ids.append(pipeline_id)

            # 如果沒有變化，表示已經連接了
            if pipeline_id in existing_pipeline_ids:
                print(f"✓ Pipeline 已經連接到 stream (All messages)")
                return True

            # 準備更新所有 connections
            new_connections = []
            for conn in connections_data:
                if conn.get("stream_id") == stream_id:
                    # 更新這個 stream 的 pipeline 列表
                    new_connections.append({
                        "stream_id": stream_id,
                        "pipeline_ids": pipeline_ids
                    })
                else:
                    # 保留其他 stream 的設定
                    new_connections.append(conn)

            # 如果原本沒有這個 stream，加入新的
            if not any(c.get("stream_id") == stream_id for c in connections_data):
                new_connections.append({
                    "stream_id": stream_id,
                    "pipeline_ids": pipeline_ids
                })

            # 先保存當前格式用於調試
            print(f"  嘗試連接 Pipeline：")
            print(f"    Stream ID: {stream_id}")
            print(f"    現有 Pipelines: {len(existing_pipeline_ids)} 個")
            print(f"    新增 Pipeline: {pipeline_id}")
            print(f"    更新後總數: {len(pipeline_ids)} 個")

            # 確認 headers
            print(f"\n  🔍 Debug 資訊：")
            print(f"    Headers: {dict(session.headers)}")
            print(f"    Auth: {GRAYLOG_USER}:***")

            # 方法 1: POST 到 /to_stream/{stream_id} (正確格式，根據官方文件)
            endpoint_url = f"{CONNECTION_ENDPOINT}/to_stream/{stream_id}"
            print(f"    URL: {endpoint_url}")

            response = session.post(
                endpoint_url,
                json={
                    "pipeline_ids": pipeline_ids
                }
            )

            if response.status_code in [200, 201, 204]:
                print(f"✓ Pipeline 已連接到 stream (All messages)")
                return True

            # 詳細錯誤訊息
            error_msg = f"  方法 1 失敗 (POST to_stream): HTTP {response.status_code}"
            if response.status_code == 403:
                error_msg += " - 權限不足！請檢查帳號是否有 pipeline_connection:edit 權限"
            elif response.status_code == 404:
                error_msg += " - 端點不存在（Graylog 6.x 可能不支援此 API）"
            elif response.status_code == 400:
                try:
                    error_detail = response.json()
                    error_msg += f" - {error_detail.get('message', '請求格式錯誤')}"
                except:
                    error_msg += " - 請求格式錯誤"
            print(error_msg)

            # 方法 2: POST 更新所有 connections
            response = session.post(
                CONNECTION_ENDPOINT,
                json=new_connections
            )

            if response.status_code in [200, 201, 204]:
                print(f"✓ Pipeline 已連接到 stream (All messages)")
                return True
            print(f"  方法 2 失敗 (POST all connections): {response.status_code}")

            # 方法 3: PUT 到 /to_stream/{stream_id} (另一種可能的格式)
            response = session.put(
                f"{CONNECTION_ENDPOINT}/to_stream/{stream_id}",
                json={
                    "pipeline_ids": pipeline_ids
                }
            )

            if response.status_code in [200, 201, 204]:
                print(f"✓ Pipeline 已連接到 stream (All messages)")
                return True
            print(f"  方法 3 失敗 (PUT to_stream with stream_id in path): {response.status_code}")

            # 方法 4: PUT 所有 connections
            response = session.put(
                CONNECTION_ENDPOINT,
                json=new_connections
            )

            if response.status_code in [200, 201, 204]:
                print(f"✓ Pipeline 已連接到 stream (All messages)")
                return True
            print(f"  方法 4 失敗 (PUT all connections): {response.status_code}")

            print(f"\n  所有連接方法都失敗了")
            print(f"\n⚠ Graylog 6.3.4 的 Connections API 限制：")
            print(f"  - /to_stream/{{stream_id}} 端點：HTTP 404（端點不存在）")
            print(f"  - /connections 端點：HTTP 405（唯讀，不允許修改）")
            print(f"  ➜ 結論：必須透過 Web UI 手動連接")

            print(f"\n📋 連接資訊：")
            print(f"  - Pipeline ID: {pipeline_id}")
            print(f"  - Pipeline 名稱: Nutanix Prism Central Processing")
            print(f"  - Stream ID: {stream_id} (All messages)")
            print(f"  - 現有 Pipelines: {len(existing_pipeline_ids)} 個")
            print(f"  - 連接後總數: {len(pipeline_ids)} 個")

        print(f"\n✗ 自動連接 pipeline 到 stream 失敗")
        print(f"\n📝 手動連接步驟：")
        print(f"  1. 開啟瀏覽器前往：{GRAYLOG_URL}/system/pipelines/connections")
        print(f"  2. 在「All messages」stream 的下拉選單中")
        print(f"  3. 勾選「Nutanix Prism Central Processing」")
        print(f"  4. 點擊「Update connections」按鈕")
        return False

    except Exception as e:
        print(f"✗ 連接 pipeline 時發生錯誤: {str(e)}")
        return False


def main():
    """主程式"""
    print("=" * 60)
    print("Graylog Nutanix Pipeline Rules 完整設定腳本")
    print("=" * 60)
    print()

    # 測試連線
    print("測試 Graylog 連線...")
    try:
        response = session.get(f"{GRAYLOG_URL}/api/system")
        if response.status_code == 200:
            system_info = response.json()
            print(f"✓ Graylog 連線成功")
            print(f"  版本: {system_info.get('version', 'unknown')}")
            print(f"  Timezone: {system_info.get('timezone', 'unknown')}")
        else:
            print(f"✗ Graylog 連線失敗 (Status: {response.status_code})")
            sys.exit(1)
    except Exception as e:
        print(f"✗ 無法連接到 Graylog: {str(e)}")
        sys.exit(1)

    print()

    # 檢查權限
    if not check_permissions():
        print("\n✗ 權限檢查失敗，請確認帳號權限後重試")
        sys.exit(1)

    print()

    # 自動探測 API 端點
    if not detect_api_endpoints():
        print("\n✗ 無法找到可用的 API 端點")
        print("\n建議：")
        print(f"1. 前往 {GRAYLOG_URL}/api/api-browser 查看 API 文件")
        print("2. 確認 Pipeline Processor plugin 已啟用")
        print("3. 確認帳號有足夠權限")
        sys.exit(1)

    print()
    print(f"使用的 API 端點:")
    print(f"  Rules: {RULE_ENDPOINT}")
    print(f"  Pipelines: {PIPELINE_ENDPOINT}")
    print(f"  Connections: {CONNECTION_ENDPOINT}")

    # 清理現有資源
    cleanup_existing_resources()

    print()
    print("-" * 60)
    print("Step 1: 建立 Stage 0 Rules (共通標記＋基礎擷取)")
    print("-" * 60)

    stage1_rule_names = []  # 儲存 rule titles
    for rule in STAGE1_RULES:
        rule_name = create_rule(rule)
        if rule_name:
            stage1_rule_names.append(rule_name)

    print(f"\n✓ Stage 1 完成，共建立 {len(stage1_rule_names)} 個 rules")

    print()
    print("-" * 60)
    print("Step 2: 建立 Stage 2 Rules (IAM 細拆、Login 動作)")
    print("-" * 60)

    stage2_rule_names = []  # 儲存 rule titles
    for rule in STAGE2_RULES:
        rule_name = create_rule(rule)
        if rule_name:
            stage2_rule_names.append(rule_name)

    print(f"\n✓ Stage 2 完成，共建立 {len(stage2_rule_names)} 個 rules")

    print()
    print("-" * 60)
    print("Step 3: 建立 Stage 3 Rules (Task/Op、Zeus、補強)")
    print("-" * 60)

    stage3_rule_names = []  # 儲存 rule titles
    for rule in STAGE3_RULES:
        rule_name = create_rule(rule)
        if rule_name:
            stage3_rule_names.append(rule_name)

    print(f"\n✓ Stage 3 完成，共建立 {len(stage3_rule_names)} 個 rules")

    print()
    print("-" * 60)
    print("Step 4: 建立 Pipeline 並綁定 Stages")
    print("-" * 60)

    # Graylog 6.x stages 格式 - rules 使用 rule title 而不是 ID
    stages = [
        {
            "stage": 0,
            "match": "EITHER",  # EITHER 或 ALL
            "rules": stage1_rule_names
        },
        {
            "stage": 1,
            "match": "EITHER",
            "rules": stage2_rule_names
        },
        {
            "stage": 2,
            "match": "EITHER",
            "rules": stage3_rule_names
        }
    ]

    pipeline_id = create_pipeline(
        "Nutanix Prism Central Processing",
        "處理 Nutanix Prism Central 的所有事件類型（IAM、Login、VM Anomaly、License 等）",
        stages
    )

    if not pipeline_id:
        print("\n✗ Pipeline 建立失敗，程式終止")
        sys.exit(1)

    print()
    print("-" * 60)
    print("Step 5: 連接 Pipeline 到 Stream")
    print("-" * 60)

    connection_success = connect_pipeline_to_stream(pipeline_id)

    print("\n" + "=" * 60)
    print("✓ Pipeline Rules 建立完成！")
    print("=" * 60)
    print(f"\n總計建立:")
    print(f"  - Stage 0 Rules: {len(stage1_rule_names)}")
    print(f"  - Stage 1 Rules: {len(stage2_rule_names)}")
    print(f"  - Stage 2 Rules: {len(stage3_rule_names)}")
    print(f"  - 總 Rules: {len(stage1_rule_names) + len(stage2_rule_names) + len(stage3_rule_names)}")
    print(f"  - Pipeline: 1")

    if not connection_success:
        print(f"\n⏱️  最後一步：手動連接 Pipeline（約 10 秒）")
        print(f"\n📝 簡易步驟：")
        print(f"  1. 開啟：{GRAYLOG_URL}/system/pipelines/connections")
        print(f"  2. 找到「All messages」stream")
        print(f"  3. 勾選「Nutanix Prism Central Processing」")
        print(f"  4. 點擊「Update connections」")
        print(f"  5. ✅ 完成！")
    else:
        print(f"\n✅ Pipeline 已自動連接到 All messages stream")

    print(f"\n📊 查看設定結果：")
    print(f"  Rules: {GRAYLOG_URL}/system/pipelines/rules")
    print(f"  Pipelines: {GRAYLOG_URL}/system/pipelines/pipelines")
    print(f"  Connections: {GRAYLOG_URL}/system/pipelines/connections")
    print(f"\n🔍 測試搜尋：")
    print(f"  搜尋 vendor:Nutanix 來查看處理後的 log")
    print()


if __name__ == "__main__":
    main()
