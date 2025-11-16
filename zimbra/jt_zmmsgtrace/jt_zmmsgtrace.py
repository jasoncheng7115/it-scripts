#!/usr/bin/env python3
"""
jt_zmmsgtrace.py - Trace emails using postfix and amavis syslog data

This is a Python rewrite of the original Perl zmmsgtrace with improvements:
- Handles Zimbra deduplication correctly by extracting all recipients from Amavis logs
- Shows recipients even if they don't have individual Postfix delivery records
- Properly tracks multi-hop mail delivery through recursive queue traversal
- Better data structures and code organization

Original zmmsgtrace:
  Copyright (C) 2011-2016 Synacor, Inc. (Zimbra Collaboration Suite)
  Licensed under GNU GPL v2

Python rewrite (jt_zmmsgtrace):
  Author: Jason Cheng (Jason Tools) (Collaborated with Claude Code)
  Date: 2025-11-16
  Version: 2.3.3
  License: GNU GPL v2
"""

import re
import sys
import gzip
import bz2
import argparse
import html
import json
import urllib.parse
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from email.header import decode_header
import threading

VERSION = "2.3.2"
DEFAULT_LOGFILE = "/var/log/zimbra.log"

# Language translations
TRANSLATIONS = {
    'zh_TW': {
        # Login page
        'app_title': 'jt_zmmsgtrace',
        'app_subtitle': 'Zimbra Email Message Tracer v{version} by Jason Cheng (Jason Tools)',
        'login_title': '登入',
        'username': '使用者名稱',
        'password': '密碼',
        'language': '語言',
        'login_button': '登入',
        'login_failed': '登入失敗',
        'invalid_credentials': '使用者名稱或密碼錯誤',
        'return_to_login': '返回登入頁面',

        # Language names
        'lang_zh_TW': '繁體中文',
        'lang_en': 'English',

        # Navigation
        'logout': '登出',
        'switch_language': '切換語言',

        # Search form
        'sender': '寄件者',
        'recipient': '收件者',
        'message_id': '郵件 ID',
        'source_host': '來源主機',
        'time_range': '時間範圍',
        'start_time': '開始時間',
        'end_time': '結束時間',
        'include_history': '查詢歷史記錄檔案',
        'include_history_desc': '包含已輪替的壓縮檔 (.gz)',
        'search_button': '搜尋',
        'clear_button': '清除',
        'or_input': '或輸入: YYYYMM,YYYYMM',

        # Search hints
        'hint_sender': '例: user@domain.com',
        'hint_recipient': '例: user@domain.com',
        'hint_msgid': '例: ABC123@domain.com',
        'hint_srchost': '例: mail.example.com',
        'hint_time': '例: 202501,202501',
        'regex_supported': '支援正則表達式',
        'includes_dedup': '包含被去重的收件者',

        # Search results
        'search_criteria': '搜尋條件',
        'search_results': '搜尋結果',
        'showing_all_messages': '顯示所有郵件',
        'found_messages': '找到 {count} 封郵件',
        'showing_range': '(目前顯示 {start}/{end} 封)',
        'no_results': '沒有找到符合條件的郵件',
        'try_adjust': '請嘗試調整左側搜尋條件',
        'load_more': '載入更多 (Load More)',
        'showing_pagination': '顯示第 {end}/{total} 封郵件',

        # Message details
        'arrive_time': '到達時間',
        'from': '寄件者',
        'to': '收件者',
        'cc': '副本',
        'date': '日期',
        'subject': '主旨',
        'log': '記錄檔',
        'view_email': '檢視郵件',
        'view_headers': '檢視標頭',
        'download_eml': '下載 .eml',
        'download_email': '下載郵件',
        'delivery_flow': '遞送流程',
        'badge_dedup': '去重',
        'badge_forward_prefix': '原: ',
        'show_details': '展開詳細資訊',
        'hide_details': '收合',

        # Delivery status
        'status': '狀態',
        'delivered': '已送達',
        'sent': '已發送',
        'deferred': '延遲',
        'bounced': '退回',
        'rejected': '拒絕',
        'expired': '過期',
        'removed': '移除',
        'relay': '轉送',
        'other': '其他',
        'unknown': '不明',

        # Email viewer
        'email_content': '郵件內容',
        'email_headers': '郵件標頭',
        'raw_headers': '原始標頭',
        'full_email_headers': '完整郵件標頭',
        'email_body': '郵件本文',
        'close': '關閉',
        'loading': '載入中...',
        'preparing_download': '準備下載中...',
        'preparing_eml': '正在準備 .eml 檔案',

        # Security checks
        'security_checks': '安全性檢查',
        'dkim': 'DKIM (DomainKeys Identified Mail)',
        'spf': 'SPF (Sender Policy Framework)',
        'dmarc': 'DMARC (Domain-based Message Authentication)',
        'spam_check': 'SPAM 檢查',
        'spam_tests': 'SPAM 測試細節',
        'spam_tests_count': 'SPAM 測試細節 ({count} 項)',
        'total_score': '總分',
        'email_routing': '郵件路由',
        'routing_hop': 'Hop {n}',
        'from_server': '從',
        'to_server': '到',
        'protocol': '協定',
        'recipient_for': '收件者',
        'timestamp': '時間戳',

        # Tips
        'tips_title': '💡 使用提示',
        'tip_regex': '<strong>正則表達式</strong>: 支援 Perl 正則表達式，例如 <code>^admin</code> 搜尋以 admin 開頭的地址',
        'tip_dedup': '<strong>去重收件者</strong>: 新版可以找到被 Zimbra 去重的收件者',
        'tip_multihop': '<strong>多階段追蹤</strong>: 自動顯示郵件經過多個 queue 的完整流程',
        'tip_timeformat': '<strong>時間格式</strong>: 可以只指定日期 (20250110) 或精確到秒 (20250110120000)',
        'welcome_message': '歡迎使用 jt_zmmsgtrace',
        'welcome_desc': '請在左側輸入搜尋條件，開始追蹤郵件',

        # Footer
        'log_files': '記錄檔案',
        'and_more': '+ {count} more',

        # Loading overlay
        'searching': '正在搜尋...',
        'searching_desc': '正在解析記錄檔並查詢郵件',
        'downloading': '準備下載中...',

        # Error messages
        'login_attempts_exceeded': '登入失敗次數過多！伺服器將關閉。請等待 {wait_time} 秒後重新啟動。',
        'remaining_attempts': '剩餘嘗試次數: {count}',
        'authenticating': '認證中...',
        'verifying_credentials': '正在驗證管理者憑證',
        'admin_login': '管理者登入',
        'zimbra_admin_account': 'Zimbra 管理者帳號',
        'enter_password': '請輸入密碼',
        'security_notice': '安全提示',
        'failed_attempts_warning': '連續 {count} 次登入失敗將導致系統自動關閉',
        'time_window': '時間區間: {minutes} 分鐘',

        # Email loading page
        'loading_email_title': '載入郵件中...',
        'loading_email_heading': '正在載入郵件...',
        'connecting_server': '正在連接伺服器...',
        'loading_timeout': '載入逾時，正在重試...',
        'connection_error': '連接錯誤，正在重試...',
        'checking_accounts': '正在檢查帳號',
        'and_x_more_accounts': '等 {count} 個帳號',

        # Email view errors
        'invalid_msgid_format': '無效的 Message-ID 格式',
        'msgid_format_incorrect': 'Message-ID 格式不正確，請確認搜尋結果是否正確。',
        'missing_recipients': '缺少收件者資訊',
        'cannot_determine_mailbox': '無法確定要查詢哪個信箱，請返回搜尋頁面重新查詢。',
        'invalid_email_format': '無效的郵件帳號格式',
        'all_recipients_invalid': '所有收件者帳號格式都不正確。',
        'getting_internal_domains': '正在取得內部 domain 列表...',
        'no_internal_accounts': '找不到內部帳號',
        'external_domain': '外部 domain',
        'external_mailbox': '外部信箱',
        'accounts_not_in_zimbra': '以下帳號都不在 Zimbra 系統中：',
        'accounts_domain_not_in_zimbra': '以下帳號的 domain 都不在 Zimbra 系統中：',
        'internal_accounts_only': '只能查詢 Zimbra 內部帳號的郵件。',
        'if_outbound_check_sender': '如果這是寄出的郵件，請確認寄件者是內部帳號。',
        'if_inbound_check_recipient': '如果是收到的郵件，請確認收件者是內部帳號',
        'checking_x_internal_accounts': '正在檢查 {count} 個內部帳號...',
        'checking_account_x_of_y': '正在檢查帳號 {current}/{total}: {account}',
        'searching_x_accounts': '開始從 {count} 個帳號搜尋郵件...',
        'searching_account_x_of_y': '正在從帳號 {current}/{total} 搜尋郵件: {account}',
        'account_x_search_failed': '帳號 {account}: 查詢失敗',
        'account_x_email_not_found': '帳號 {account}: 郵件不存在於此信箱',
        'reading_email_from_x': '正在從 {account} 讀取郵件內容...',
        'account_x_no_admin_auth': '帳號 {account}: 無法取得管理員認證',
        'account_x_no_delegate_auth': '帳號 {account}: 無法取得委派認證',
        'account_x_cannot_get_from_url': '帳號 {account}: 無法從 URL 取得郵件內容',
        'account_x_cannot_parse': '帳號 {account}: 無法解析郵件內容',
        'account_x_cannot_get_content': '帳號 {account}: 無法取得郵件內容',
        'account_x_cannot_read_headers': '帳號 {account}: 無法讀取郵件標頭',
        'preparing_file': '準備下載檔案...',
        'rendering_email': '正在渲染郵件顯示頁面...',
        'explanation': '說明',

        # Email view page
        'hops_count': '{count} 個節點',
        'download_button': '下載郵件',
        'test_name': '測試名稱',
        'score': '分數',
        'authentication_results': '認證結果',
        'rendered_content': '渲染內容',
        'raw_content': '原始內容',
        'copy_to_clipboard': '複製到剪貼簿',
        'copied': '已複製',
        'close_window': '關閉視窗',
        'mailbox_account': '信箱帳號',

        # Error messages for email not found
        'email_not_found': '找不到郵件',
        'checked_internal_mailboxes': '已查詢的內部信箱：',
        'skipped_external_mailboxes': '跳過的外部信箱：',
        'external_mailbox_skipped': '外部信箱，已跳過',
        'last_error': '最後錯誤',
        'possible_reasons': '可能原因',
        'email_may_be_deleted': '郵件可能已被刪除',
        'outbound_check_sender': '如果是寄出的郵件，請確認寄件者是內部帳號',
        'inbound_check_recipient': '如果是收到的郵件，請確認收件者是內部帳號',
        'forward_no_local_copy': '可能該帳號有設定郵件自動轉寄並且不儲存',
        'insufficient_permissions': '系統權限不足（請確認 sudo 設定）',
    },
    'en': {
        # Login page
        'app_title': 'jt_zmmsgtrace',
        'app_subtitle': 'Zimbra Email Message Tracer v{version} by Jason Cheng (Jason Tools)',
        'login_title': 'Login',
        'username': 'Username',
        'password': 'Password',
        'language': 'Language',
        'login_button': 'Login',
        'login_failed': 'Login Failed',
        'invalid_credentials': 'Invalid username or password',
        'return_to_login': 'Return to Login',

        # Language names
        'lang_zh_TW': '繁體中文',
        'lang_en': 'English',

        # Navigation
        'logout': 'Logout',
        'switch_language': 'Switch Language',

        # Search form
        'sender': 'Sender',
        'recipient': 'Recipient',
        'message_id': 'Message ID',
        'source_host': 'Source Host',
        'time_range': 'Time Range',
        'start_time': 'Start Time',
        'end_time': 'End Time',
        'include_history': 'Include History Logs',
        'include_history_desc': 'Include rotated compressed files (.gz)',
        'search_button': 'Search',
        'clear_button': 'Clear',
        'or_input': 'Or enter: YYYYMM,YYYYMM',

        # Search hints
        'hint_sender': 'e.g.: user@domain.com',
        'hint_recipient': 'e.g.: user@domain.com',
        'hint_msgid': 'e.g.: ABC123@domain.com',
        'hint_srchost': 'e.g.: mail.example.com',
        'hint_time': 'e.g.: 202501,202501',
        'regex_supported': 'Regular expressions supported',
        'includes_dedup': 'Includes deduplicated recipients',

        # Search results
        'search_criteria': 'Search Criteria',
        'search_results': 'Search Results',
        'showing_all_messages': 'Showing all messages',
        'found_messages': 'Found {count} messages',
        'showing_range': '(Showing {start}/{end})',
        'no_results': 'No messages found',
        'try_adjust': 'Please adjust search criteria on the left',
        'load_more': 'Load More',
        'showing_pagination': 'Showing {end}/{total} messages',

        # Message details
        'arrive_time': 'Arrival Time',
        'from': 'From',
        'to': 'To',
        'cc': 'Cc',
        'date': 'Date',
        'subject': 'Subject',
        'log': 'Log',
        'view_email': 'View Email',
        'view_headers': 'View Headers',
        'download_eml': 'Download .eml',
        'download_email': 'Download Email',
        'delivery_flow': 'Delivery Flow',
        'badge_dedup': 'Dedup',
        'badge_forward_prefix': 'Orig: ',
        'show_details': 'Show Details',
        'hide_details': 'Hide',

        # Delivery status
        'status': 'Status',
        'delivered': 'Delivered',
        'sent': 'Sent',
        'deferred': 'Deferred',
        'bounced': 'Bounced',
        'rejected': 'Rejected',
        'expired': 'Expired',
        'removed': 'Removed',
        'relay': 'Relay',
        'other': 'Other',
        'unknown': 'Unknown',

        # Email viewer
        'email_content': 'Email Content',
        'email_headers': 'Email Headers',
        'raw_headers': 'Raw Headers',
        'full_email_headers': 'Full Email Headers',
        'email_body': 'Email Body',
        'close': 'Close',
        'loading': 'Loading...',
        'preparing_download': 'Preparing Download...',
        'preparing_eml': 'Preparing .eml file',

        # Security checks
        'security_checks': 'Security Checks',
        'dkim': 'DKIM (DomainKeys Identified Mail)',
        'spf': 'SPF (Sender Policy Framework)',
        'dmarc': 'DMARC (Domain-based Message Authentication)',
        'spam_check': 'SPAM Check',
        'spam_tests': 'SPAM Test Details',
        'spam_tests_count': 'SPAM Test Details ({count} items)',
        'total_score': 'Total Score',
        'email_routing': 'Email Routing',
        'routing_hop': 'Hop {n}',
        'from_server': 'From',
        'to_server': 'To',
        'protocol': 'Protocol',
        'recipient_for': 'Recipient',
        'timestamp': 'Timestamp',

        # Tips
        'tips_title': '💡 Tips',
        'tip_regex': '<strong>Regular Expressions</strong>: Perl regex supported, e.g. <code>^admin</code> searches addresses starting with admin',
        'tip_dedup': '<strong>Deduplicated Recipients</strong>: Can find recipients removed by Zimbra deduplication',
        'tip_multihop': '<strong>Multi-hop Tracking</strong>: Automatically shows complete mail flow through multiple queues',
        'tip_timeformat': '<strong>Time Format</strong>: Can specify date only (20250110) or precise to seconds (20250110120000)',
        'welcome_message': 'Welcome to jt_zmmsgtrace',
        'welcome_desc': 'Enter search criteria on the left to start tracing emails',

        # Footer
        'log_files': 'Log Files',
        'and_more': '+ {count} more',

        # Loading overlay
        'searching': 'Searching...',
        'searching_desc': 'Parsing logs and searching messages',
        'downloading': 'Preparing Download...',

        # Error messages
        'login_attempts_exceeded': 'Too many failed login attempts! Server will shutdown. Please wait {wait_time} seconds and restart.',
        'remaining_attempts': 'Remaining attempts: {count}',
        'authenticating': 'Authenticating...',
        'verifying_credentials': 'Verifying admin credentials',
        'admin_login': 'Admin Login',
        'zimbra_admin_account': 'Zimbra Admin Account',
        'enter_password': 'Enter password',
        'security_notice': 'Security Notice',
        'failed_attempts_warning': '{count} consecutive failed login attempts will cause system shutdown',
        'time_window': 'Time window: {minutes} minutes',

        # Email loading page
        'loading_email_title': 'Loading Email...',
        'loading_email_heading': 'Loading Email...',
        'connecting_server': 'Connecting to server...',
        'loading_timeout': 'Loading timeout, retrying...',
        'connection_error': 'Connection error, retrying...',
        'checking_accounts': 'Checking accounts',
        'and_x_more_accounts': 'and {count} more accounts',

        # Email view errors
        'invalid_msgid_format': 'Invalid Message-ID Format',
        'msgid_format_incorrect': 'Message-ID format is incorrect, please verify search results.',
        'missing_recipients': 'Missing Recipients',
        'cannot_determine_mailbox': 'Cannot determine which mailbox to query, please return to search page.',
        'invalid_email_format': 'Invalid Email Format',
        'all_recipients_invalid': 'All recipient addresses are invalid.',
        'getting_internal_domains': 'Getting internal domain list...',
        'no_internal_accounts': 'No Internal Accounts Found',
        'external_domain': 'external domain',
        'external_mailbox': 'external mailbox',
        'accounts_not_in_zimbra': 'The following accounts are not in Zimbra system:',
        'accounts_domain_not_in_zimbra': 'The following account domains are not in Zimbra system:',
        'internal_accounts_only': 'Can only query emails from Zimbra internal accounts.',
        'if_outbound_check_sender': 'If this is an outbound email, please verify the sender is an internal account.',
        'if_inbound_check_recipient': 'If this is an inbound email, please verify the recipient is an internal account',
        'checking_x_internal_accounts': 'Checking {count} internal accounts...',
        'checking_account_x_of_y': 'Checking account {current}/{total}: {account}',
        'searching_x_accounts': 'Searching email from {count} accounts...',
        'searching_account_x_of_y': 'Searching account {current}/{total}: {account}',
        'account_x_search_failed': 'Account {account}: Search failed',
        'account_x_email_not_found': 'Account {account}: Email not found in this mailbox',
        'reading_email_from_x': 'Reading email from {account}...',
        'account_x_no_admin_auth': 'Account {account}: Cannot obtain admin authentication',
        'account_x_no_delegate_auth': 'Account {account}: Cannot obtain delegate authentication',
        'account_x_cannot_get_from_url': 'Account {account}: Cannot get email content from URL',
        'account_x_cannot_parse': 'Account {account}: Cannot parse email content',
        'account_x_cannot_get_content': 'Account {account}: Cannot get email content',
        'account_x_cannot_read_headers': 'Account {account}: Cannot read email headers',
        'preparing_file': 'Preparing file...',
        'rendering_email': 'Rendering email display page...',
        'explanation': 'Explanation',

        # Email view page
        'hops_count': '{count} hops',
        'download_button': 'Download Email',
        'test_name': 'Test Name',
        'score': 'Score',
        'authentication_results': 'Authentication Results',
        'rendered_content': 'Rendered Content',
        'raw_content': 'Raw Content',
        'copy_to_clipboard': 'Copy to Clipboard',
        'copied': 'Copied',
        'close_window': 'Close Window',
        'mailbox_account': 'Mailbox Account',

        # Error messages for email not found
        'email_not_found': 'Email Not Found',
        'checked_internal_mailboxes': 'Checked Internal Mailboxes:',
        'skipped_external_mailboxes': 'Skipped External Mailboxes:',
        'external_mailbox_skipped': 'External mailbox, skipped',
        'last_error': 'Last Error',
        'possible_reasons': 'Possible Reasons',
        'email_may_be_deleted': 'Email may have been deleted',
        'outbound_check_sender': 'If outbound email, please verify sender is an internal account',
        'inbound_check_recipient': 'If inbound email, please verify recipient is an internal account',
        'forward_no_local_copy': 'Account may have email forwarding enabled without keeping local copy',
        'insufficient_permissions': 'Insufficient system permissions (please check sudo configuration)',
    }
}

def get_translation(lang: str, key: str, **kwargs) -> str:
    """Get translated string for given language and key"""
    # Default to English if language not found
    if lang not in TRANSLATIONS:
        lang = 'en'

    # Get translation or return key if not found
    text = TRANSLATIONS.get(lang, {}).get(key, key)

    # Format with any provided arguments
    if kwargs:
        try:
            text = text.format(**kwargs)
        except (KeyError, ValueError):
            pass

    return text

# Postfix Queue ID patterns
SF_QID_CHAR = r'[A-F0-9]'
LF_QID_TIME_CHAR = r'[0-9BCDFGHJKLMNPQRSTVWXYZ]'
LF_QID_INODE_CHAR = r'[0-9BCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxy]'
POSTFIX_QID_PATTERN = f'(?:{SF_QID_CHAR}{{6,}}|{LF_QID_TIME_CHAR}{{10,}}z{LF_QID_INODE_CHAR}+)'

MONTH_MAP = {
    'Jan': '01', 'Feb': '02', 'Mar': '03', 'Apr': '04',
    'May': '05', 'Jun': '06', 'Jul': '07', 'Aug': '08',
    'Sep': '09', 'Oct': '10', 'Nov': '11', 'Dec': '12'
}


def debug_print(message: str, file=sys.stderr):
    """Print debug message with timestamp"""
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]  # Include milliseconds
    print(f"[{timestamp}] {message}", file=file)


def decode_header_value(value: str) -> str:
    """
    Decode RFC 2047 encoded email header value.

    Example:
        '=?utf-8?B?5ris6Kmm?=' -> '測試'
        '=?iso-8859-1?Q?Andr=E9?=' -> 'André'

    Args:
        value: Encoded header value

    Returns:
        Decoded string
    """
    if not value:
        return ''

    try:
        decoded_parts = decode_header(value)
        result = []
        for part, encoding in decoded_parts:
            if isinstance(part, bytes):
                if encoding:
                    result.append(part.decode(encoding, errors='replace'))
                else:
                    # Try UTF-8 first, fall back to latin1
                    try:
                        result.append(part.decode('utf-8'))
                    except UnicodeDecodeError:
                        result.append(part.decode('latin1', errors='replace'))
            else:
                result.append(str(part))
        return ''.join(result)
    except Exception:
        # If decoding fails, return the original value
        return value


@dataclass
class RecipientInfo:
    """Information about a recipient's delivery"""
    address: str
    orig_recip: Optional[str] = None
    leave_time: Optional[str] = None
    status: Optional[str] = None
    status_msg: Optional[str] = None
    next_host: Optional[str] = None
    next_ip: Optional[str] = None
    next_queue_id: Optional[str] = None
    amavis_id: Optional[str] = None
    # Flag to indicate if this recipient was only found in Amavis (likely deduplicated)
    from_amavis_only: bool = False


@dataclass
class AmavisRecord:
    """Amavis scan record"""
    log_date: str
    host: str
    pid: str
    disposition: str  # Passed or Blocked
    reason: str  # CLEAN, BAD-HEADER, etc.
    from_ip: str
    orig_ip: Optional[str]
    sender: str
    recipients: List[str]  # List of recipient addresses
    queue_id: Optional[str]
    message_id: Optional[str]
    hits: str
    ms: str


@dataclass
class Message:
    """Represents an email message"""
    message_id: str
    arrive_time: Optional[str] = None
    sender: Optional[str] = None
    subject: Optional[str] = None  # Email subject
    host: Optional[str] = None
    prev_host: Optional[str] = None
    prev_ip: Optional[str] = None
    bytes_size: Optional[int] = None
    recipients: Dict[str, RecipientInfo] = field(default_factory=dict)
    queue_ids: Set[str] = field(default_factory=set)
    source_file: Optional[str] = None  # Track which log file this message came from


class LogParser:
    """Parser for Zimbra mail logs"""

    def __init__(self, year: int, debug: int = 0):
        self.year = year
        self.debug = debug
        self.messages: Dict[str, Dict[str, Message]] = {}  # message_id -> queue_id -> Message
        self.postfix_tmp: Dict[str, Dict] = {}  # key: qid:host
        self.amavis_records: Dict[str, AmavisRecord] = {}
        self.saved_lines: Dict[str, str] = {}  # for multi-line amavis logs
        self.qid_to_msg: Dict[str, Tuple[str, Message]] = {}  # queue_id -> (message_id, Message)
        self.current_file: Optional[str] = None  # Track current file being parsed

        # Compile regex patterns
        self.log_pattern = re.compile(
            r'^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
            r'(?:<[^>]+>\s+)?'
            r'(\S+)\s+'
            r'([^\[]+)\[(\d+)\]:\s+'
            r'(?:\[ID\s+\d+\s+\w+\.\w+\]\s+)?'
            r'(.*)$'
        )
        self.postfix_qid_pattern = re.compile(f'^({POSTFIX_QID_PATTERN}|NOQUEUE): (.*)$')

    def logdate_to_number(self, timestamp: str) -> Optional[str]:
        """Convert log timestamp to YYYYMMDDHHMMSS format"""
        if not timestamp:
            return None
        try:
            parts = timestamp.split()
            month = MONTH_MAP.get(parts[0])
            if not month:
                return None
            day = parts[1]
            time_str = parts[2].replace(':', '')
            return f"{self.year}{month}{day.zfill(2)}{time_str}"
        except (IndexError, ValueError):
            return None

    def time_to_number(self, time_str: str, max_values: bool = False) -> Optional[str]:
        """Convert YYYYMM[DD[HH[MM[SS]]]] to YYYYMMDDHHMMSS"""
        if not time_str:
            return None

        # Default values: 0 for start, max for end
        defaults = [31, 23, 59, 59] if max_values else [1, 0, 0, 0]

        match = re.match(r'^(\d{4})(\d{2})(\d{2})?(\d{2})?(\d{2})?(\d{2})?$', time_str)
        if not match:
            return None

        groups = match.groups()
        year, month = groups[0], groups[1]
        day = groups[2] or str(defaults[0]).zfill(2)
        hour = groups[3] or str(defaults[1]).zfill(2)
        minute = groups[4] or str(defaults[2]).zfill(2)
        second = groups[5] or str(defaults[3]).zfill(2)

        return f"{year}{month}{day.zfill(2)}{hour.zfill(2)}{minute.zfill(2)}{second.zfill(2)}"

    def parse_postfix_line(self, log_date: str, host: str, app: str, pid: str, msg: str):
        """Parse a Postfix log line"""
        match = self.postfix_qid_pattern.match(msg)
        if not match:
            return

        qid, content = match.groups()
        key = f"{qid}:{host}"

        if self.debug > 1:
            print(f"DEBUG: Parsing postfix line for queue {qid}: {content[:60]}...", file=sys.stderr)

        if key not in self.postfix_tmp:
            self.postfix_tmp[key] = {
                'host': host,
                'qid': qid,
                'recipients': {}
            }

        obj = self.postfix_tmp[key]

        # Handle reject
        if content.startswith('reject: '):
            self._handle_postfix_reject(obj, qid, log_date, content[8:])
            return

        # Handle removed
        if content.startswith('removed'):
            self._finalize_postfix_message(obj, qid)
            return

        # message-id
        match = re.search(r'message-id=<([^>]+)>', content)
        if match:
            obj['message_id'] = match.group(1)
            obj['arrive_time'] = log_date
            return

        # subject
        match = re.search(r'header Subject:\s+(.+?)\s+from\s+', content)
        if match:
            # Decode RFC 2047 encoded subject (e.g., =?utf-8?B?5ris6Kmm?=)
            obj['subject'] = decode_header_value(match.group(1).strip())
            return

        # client
        match = re.search(r'client=([^\[]+)\[([^\]]+)\]', content)
        if match:
            obj['prev_host'] = match.group(1)
            obj['prev_ip'] = match.group(2)
            return

        # from
        match = re.search(r'from=<(.*)>, size=(\d+)', content)
        if match:
            obj['sender'] = match.group(1) or 'postmaster'
            obj['bytes'] = int(match.group(2))
            return

        # to (delivery record)
        match = re.search(
            r'to=<([^>]*)>(?:,\s+orig_to=<([^>]*)>)?,\s+'
            r'relay=([^\[,]+)(?:\[([^\]]*)\](:\d+))?,\s+'
            r'delay=\S+,\s+delays=\S+,\s+dsn=\S+\s+'
            r'status=(\S+)\s+(.*)',
            content
        )
        if match:
            recip = match.group(1)
            orig_recip = match.group(2)
            next_host = match.group(3) + (match.group(5) or '')
            next_ip = (match.group(4) or '') + (match.group(5) or '')
            status = match.group(6)
            status_msg = match.group(7)

            if recip not in obj['recipients']:
                obj['recipients'][recip] = {}

            recip_info = obj['recipients'][recip]
            recip_info['leave_time'] = log_date
            recip_info['status'] = status
            recip_info['status_msg'] = status_msg
            recip_info['next_host'] = next_host
            recip_info['next_ip'] = next_ip

            if orig_recip:
                recip_info['orig_recip'] = orig_recip

            # Extract amavis ID
            amav_match = re.search(r'id=([^ ,]+)', status_msg)
            if amav_match:
                recip_info['amavis_id'] = amav_match.group(1)

            # Extract next queue ID
            queue_match = re.search(r'queued as ([^ )]+)', status_msg)
            if queue_match:
                recip_info['next_queue_id'] = queue_match.group(1)

            # Finalize if connection error
            if 'connect to' in status_msg:
                self._finalize_postfix_message(obj, qid)

    def _handle_postfix_reject(self, obj: Dict, qid: str, log_date: str, content: str):
        """Handle rejected message"""
        match = re.search(
            r'RCPT\s+from\s+([^\[]+)\[([^\]]+)\]:\s+([^;]+);\s+'
            r'from=<(.*?)>\s+to=<(.*?)>',
            content
        )
        if match:
            obj['prev_host'] = match.group(1)
            obj['prev_ip'] = match.group(2)
            status_msg = match.group(3)
            obj['sender'] = match.group(4) or 'postmaster'
            recip = match.group(5)

            if recip:
                obj['recipients'][recip] = {
                    'leave_time': log_date,
                    'status': 'reject',
                    'status_msg': status_msg
                }

        obj['arrive_time'] = log_date
        obj.setdefault('message_id', f"[reject:{qid}]")
        self._finalize_postfix_message(obj, qid)

    def _finalize_postfix_message(self, obj: Dict, qid: str):
        """Finalize and store a postfix message (one Message per queue_id)"""
        msg_id = obj.get('message_id', f"[unknown:{qid}]")

        # Create message_id entry if not exists
        if msg_id not in self.messages:
            self.messages[msg_id] = {}

        # Create a separate Message object for this queue_id
        msg = Message(message_id=msg_id)
        msg.arrive_time = obj.get('arrive_time')
        msg.sender = obj.get('sender')
        msg.subject = obj.get('subject')
        msg.host = obj.get('host')
        msg.prev_host = obj.get('prev_host')
        msg.prev_ip = obj.get('prev_ip')
        msg.bytes_size = obj.get('bytes')
        msg.queue_ids.add(qid)
        msg.source_file = self.current_file  # Record source file

        # Add recipients for this specific queue stage
        for recip_addr, recip_data in obj.get('recipients', {}).items():
            recip_info = RecipientInfo(address=recip_addr)
            recip_info.leave_time = recip_data.get('leave_time')
            recip_info.status = recip_data.get('status')
            recip_info.status_msg = recip_data.get('status_msg')
            recip_info.next_host = recip_data.get('next_host')
            recip_info.next_ip = recip_data.get('next_ip')
            recip_info.next_queue_id = recip_data.get('next_queue_id')
            recip_info.amavis_id = recip_data.get('amavis_id')
            recip_info.orig_recip = recip_data.get('orig_recip')
            msg.recipients[recip_addr] = recip_info

        # Store in two-dimensional structure
        self.messages[msg_id][qid] = msg
        self.qid_to_msg[qid] = (msg_id, msg)

        if self.debug > 1:
            print(f"DEBUG: Finalized queue {qid} for message {msg_id}, recipients: {list(msg.recipients.keys())}", file=sys.stderr)

    def parse_amavis_line(self, log_date: str, host: str, app: str, pid: str, msg: str):
        """Parse an Amavis log line"""
        # Extract amavis ID
        am_id_match = re.match(r'^\(([^)]+)\)\s', msg)
        if not am_id_match:
            return

        am_id = am_id_match.group(1)

        # Handle continuation lines
        if msg.startswith(f'({am_id}) ...'):
            saved = self.saved_lines.pop(am_id, '')
            msg = saved + msg[len(f'({am_id}) ...'):]

        # Handle lines to be continued
        if msg.endswith('...'):
            self.saved_lines[am_id] = msg[:-3]
            return

        # Only process Passed/Blocked lines
        if not re.search(r'(Passed|Blocked)', msg):
            return

        # Parse the full amavis log line
        pattern = re.compile(
            r'^\(([^)]+)\)\s+'  # 1: am_id
            r'(Passed|Blocked)\s+'  # 2: disposition
            r'([^,]+),\s+'  # 3: reason (CLEAN, BAD-HEADER, etc.)
            r'(?:[^\[]*)?\[([^\]]+)\]\s+'  # 4: from IP
            r'(?:\[([^\]]+)\]\s+)?'  # 5: orig IP (optional)
            r'<([^>]*)>\s+'  # 6: sender
            r'->\s+'
            r'(<[^>]+>(?:,<[^>]+>)*),\s*'  # 7: recipients (IMPORTANT!)
            r'(?:quarantine:\s+.+?,(?=\s\S*[Ii][Dd]:\s))?'
            r'(?:Queue-ID:\s+([^,]+),)?'  # 8: queue_id
            r'(?:Message-ID:\s+<([^>]+)>,)?'  # 9: message_id
            r'(?:Resent-Message-ID:\s+<[^>]+>,)?'
            r'\s+mail_id:\s+\S+,\s+'
            r'Hits:\s+(\S+),\s+'  # 10: hits
            r'size:\s+\d+,\s*'
            r'(?:dkim_id=\S+,)?'
            r'(?:queued_as:\s+\S+,)?'
            r'(?:dkim_id=\S+,)?'
            r'\s+(\d+)\s+ms',  # 11: ms
            re.VERBOSE
        )

        match = pattern.search(msg)
        if not match:
            if self.debug:
                print(f"DEBUG: Amavis line not matched: {msg[:100]}...", file=sys.stderr)
            return

        groups = match.groups()

        # Parse recipients - THIS IS THE KEY FIX!
        recipients_str = groups[6]  # "<a@x.com>,<b@x.com>,<c@x.com>"
        recipients = [r.strip('<>') for r in recipients_str.split(',')]

        record = AmavisRecord(
            log_date=log_date,
            host=host,
            pid=groups[0],
            disposition=groups[1],
            reason=groups[2],
            from_ip=groups[3],
            orig_ip=groups[4],
            sender=groups[5],
            recipients=recipients,  # Store as list
            queue_id=groups[7],
            message_id=groups[8],
            hits=groups[9],
            ms=groups[10]
        )

        # Store by queue_id or amavis_id
        record_id = record.queue_id or record.pid
        self.amavis_records[record_id] = record

        if self.debug > 1:
            print(f"DEBUG: Amavis record {record_id}: {len(recipients)} recipients", file=sys.stderr)

    def parse_file(self, filepath: str):
        """Parse a log file"""
        # Set current file for tracking
        self.current_file = filepath

        if self.debug:
            print(f"Reading '{filepath}'...", file=sys.stderr)

        # Determine file type and open appropriately
        path = Path(filepath)
        if not path.exists():
            print(f"Error: File '{filepath}' not found", file=sys.stderr)
            return

        if path.suffix == '.gz':
            fh = gzip.open(filepath, 'rt', encoding='utf-8', errors='ignore')
        elif path.suffix in ['.bz', '.bz2']:
            fh = bz2.open(filepath, 'rt', encoding='utf-8', errors='ignore')
        else:
            fh = open(filepath, 'r', encoding='utf-8', errors='ignore')

        try:
            for line in fh:
                line = line.strip()
                if not line:
                    continue

                match = self.log_pattern.match(line)
                if not match:
                    continue

                log_date, host, app, pid, msg = match.groups()

                if app.startswith('postfix'):
                    self.parse_postfix_line(log_date, host, app, pid, msg)
                elif app.startswith('amavis'):
                    self.parse_amavis_line(log_date, host, app, pid, msg)
        finally:
            fh.close()

        # Finalize remaining postfix messages
        for key in list(self.postfix_tmp.keys()):
            obj = self.postfix_tmp.pop(key)
            qid = obj['qid']
            self._finalize_postfix_message(obj, qid)

    def integrate_amavis_data(self):
        """
        Integrate Amavis data with messages.
        CRITICAL: Add recipients found in Amavis but not in Postfix (deduplication victims)
        """
        if self.debug:
            print(f"Integrating Amavis data...", file=sys.stderr)

        # qid_to_msg is already built in _finalize_postfix_message

        # Process each Amavis record
        for record_id, amav in self.amavis_records.items():
            # Find the corresponding message
            msg_id = None
            msg = None
            qid = None

            # Try to find by queue_id
            if amav.queue_id and amav.queue_id in self.qid_to_msg:
                msg_id, msg = self.qid_to_msg[amav.queue_id]
                qid = amav.queue_id

            # Try to find by message_id (use first queue_id)
            if not msg and amav.message_id and amav.message_id in self.messages:
                msg_id = amav.message_id
                queues = self.messages[amav.message_id]
                if queues:
                    qid = list(queues.keys())[0]
                    msg = queues[qid]

            # If still not found, create a new message entry
            if not msg and amav.message_id:
                msg_id = amav.message_id
                qid = amav.queue_id or f"amav-{record_id}"
                msg = Message(message_id=msg_id)
                msg.sender = amav.sender
                msg.arrive_time = amav.log_date
                msg.host = amav.host
                msg.prev_ip = amav.from_ip
                msg.source_file = self.current_file  # Record source file for Amavis-only messages
                if amav.queue_id:
                    msg.queue_ids.add(amav.queue_id)

                if msg_id not in self.messages:
                    self.messages[msg_id] = {}
                self.messages[msg_id][qid] = msg
                self.qid_to_msg[qid] = (msg_id, msg)

            if not msg:
                continue

            # KEY FIX: Add ALL recipients from Amavis
            for recip_addr in amav.recipients:
                if recip_addr not in msg.recipients:
                    # This recipient was not in Postfix logs (likely deduplicated)
                    msg.recipients[recip_addr] = RecipientInfo(
                        address=recip_addr,
                        from_amavis_only=True,
                        status='processed'  # Indicate it was processed by Amavis
                    )
                    if self.debug:
                        print(f"DEBUG: Added deduplicated recipient {recip_addr} from Amavis",
                              file=sys.stderr)

                # Store amavis association
                r = msg.recipients[recip_addr]
                if amav.queue_id:
                    r.amavis_id = record_id


class MessageFilter:
    """Filter messages based on search criteria"""

    def __init__(self, args):
        self.args = args
        # Safely compile regex patterns with error handling to prevent regex injection
        self.id_pattern = self._safe_compile(args.id, re.IGNORECASE if not args.id else 0) if args.id else None
        self.sender_pattern = self._safe_compile(args.sender, re.IGNORECASE) if args.sender else None
        self.recipient_pattern = self._safe_compile(args.recipient, re.IGNORECASE) if args.recipient else None
        self.srchost_pattern = self._safe_compile(args.srchost, re.IGNORECASE) if args.srchost else None
        self.desthost_pattern = self._safe_compile(args.desthost, re.IGNORECASE) if args.desthost else None

    def _safe_compile(self, pattern: str, flags: int = 0):
        """Safely compile regex pattern with error handling"""
        try:
            # Limit pattern length to prevent ReDoS
            if len(pattern) > 500:
                raise ValueError("Pattern too long (max 500 characters)")
            return re.compile(pattern, flags)
        except re.error as e:
            raise ValueError(f"Invalid regex pattern: {e}")
        except Exception as e:
            raise ValueError(f"Invalid pattern: {e}")

    def matches(self, msg: Message) -> bool:
        """Check if message matches all filter criteria"""
        parser = LogParser(self.args.year)

        # Message ID filter
        if self.id_pattern and not self.id_pattern.search(msg.message_id or ''):
            return False

        # Time filter
        if self.args.time:
            start_time, end_time = self.args.time
            if msg.arrive_time:
                msg_time = parser.logdate_to_number(msg.arrive_time)
                if msg_time:
                    if start_time and msg_time < start_time:
                        return False
                    if end_time and msg_time > end_time:
                        return False

        # Sender filter
        if self.sender_pattern and not self.sender_pattern.search(msg.sender or ''):
            return False

        # Recipient filter
        if self.recipient_pattern:
            matched = False
            for recip in msg.recipients.values():
                if self.recipient_pattern.search(recip.address):
                    matched = True
                    break
                if recip.orig_recip and self.recipient_pattern.search(recip.orig_recip):
                    matched = True
                    break
            if not matched:
                return False

        # Source host filter
        if self.srchost_pattern:
            hosts = [h for h in [msg.prev_host, msg.prev_ip] if h]
            if not any(self.srchost_pattern.search(h) for h in hosts):
                return False

        # Destination host filter
        if self.desthost_pattern:
            hosts = []
            for recip in msg.recipients.values():
                if recip.next_host:
                    hosts.append(recip.next_host.rstrip(':0123456789'))
                if recip.next_ip:
                    hosts.append(recip.next_ip.rstrip(':0123456789'))
            if not any(self.desthost_pattern.search(h) for h in hosts):
                return False

        return True


class OutputFormatter:
    """Format and display trace results"""

    def __init__(self, parser: LogParser, amavis_records: Dict[str, AmavisRecord], qid_to_msg: Dict[str, Message]):
        self.parser = parser
        self.amavis_records = amavis_records
        self.qid_to_msg = qid_to_msg

    def display_message(self, msg: Message, recipient_filter: Optional[re.Pattern] = None):
        """Display a single message trace"""
        # Display message ID
        print(f"Message ID: {msg.message_id}")

        # Display source file as separate field
        if msg.source_file:
            print(f"Log: {msg.source_file}")

        print(f"From: {msg.sender or 'unknown'}")

        # Display subject if available
        if msg.subject:
            print(f"Subject: {msg.subject}")

        # List all recipients
        print("To:")
        for recip in sorted(msg.recipients.values(), key=lambda r: r.address):
            suffix = ""
            if recip.orig_recip:
                suffix = f" (originally to {recip.orig_recip})"
            if recip.from_amavis_only:
                suffix += " [from Amavis - may be deduplicated]"
            print(f"  {recip.address}{suffix}")

        # Detail for each recipient
        for recip in sorted(msg.recipients.values(), key=lambda r: r.address):
            if recipient_filter and not recipient_filter.search(recip.address):
                if not (recip.orig_recip and recipient_filter.search(recip.orig_recip)):
                    continue

            print(f"  Recipient {recip.address}")
            self._display_recipient(msg, recip, indent="  ")

        print()

    def _display_recipient(self, msg: Message, recip: RecipientInfo, indent: str = "", recip_addr: str = ""):
        """Display delivery details for a recipient (recursively tracks through queue hops)"""
        at = msg.arrive_time or ""
        lt = recip.leave_time or ""
        ph = msg.prev_host or msg.host or ""
        pi = msg.prev_ip or ""

        # Don't show localhost for prev_ip, but keep the host name
        if pi in ['127.0.0.1', '::1']:
            pi = ""
            # If prev_host is also localhost, use msg.host instead
            if ph == 'localhost':
                ph = msg.host or "localhost"

        nh = recip.next_host or ""
        ni = recip.next_ip or ""
        st = recip.status or ""

        # Display delivery line
        parts = [at, "-", ph]
        if pi:
            parts.append(f"({pi})")
        if nh:
            parts.extend(["-->", nh])
        if ni:
            parts.append(f"({ni})")
        if st:
            parts.extend(["status", st])

        print(f"{indent}{' '.join(parts)}")

        # Display status message for non-sent or from_amavis_only
        if recip.status_msg and (not st or st != 'sent'):
            print(f"{indent}  {recip.status_msg}")

        # Show if recipient was only found in Amavis (deduplicated)
        if recip.from_amavis_only and not recip.status_msg:
            print(f"{indent}  Processed by Amavis but no individual Postfix delivery record")

        # Display Amavis info
        amav = None
        if recip.amavis_id and recip.amavis_id in self.amavis_records:
            amav = self.amavis_records[recip.amavis_id]
        elif recip.next_queue_id and recip.next_queue_id in self.amavis_records:
            amav = self.amavis_records[recip.next_queue_id]

        if amav:
            print(f"{indent}{amav.log_date} {amav.disposition} by amavisd on {amav.host} "
                  f"({amav.reason}) hits: {amav.hits} in {amav.ms} ms")

        # RECURSION: Follow next_queue_id to track multi-hop delivery
        if recip.next_queue_id and recip.next_queue_id in self.qid_to_msg:
            next_msg_id, next_msg = self.qid_to_msg[recip.next_queue_id]
            # Use recip_addr if provided, otherwise use recip.address
            addr = recip_addr or recip.address
            if addr in next_msg.recipients:
                next_recip = next_msg.recipients[addr]
                # Recursively display the next hop
                self._display_recipient(next_msg, next_recip, indent, addr)


def sort_files_by_mtime(files: List[str]) -> List[str]:
    """Sort files by modification time (newest first)"""
    file_paths = [(f, Path(f).stat().st_mtime if Path(f).exists() else 0) for f in files]
    return [f for f, _ in sorted(file_paths, key=lambda x: x[1], reverse=True)]


class WebUI:
    """Web interface for jt_zmmsgtrace"""

    def __init__(self, log_files: List[str], year: int, debug: int = 0,
                 login_attempts: int = 5, login_timeout: int = 10):
        self.log_files = log_files
        self.year = year
        self.debug = debug
        self.parser = None
        self.is_parsing = False
        self.parsed_with_history = False  # Track if current parser includes history files
        self.parsed_log_files_mtime = {}  # Track modification times of parsed log files
        self.progress_store = {}  # Store progress for ongoing email fetch operations
        self.admin_account = None  # Admin account for DelegateAuth
        self.admin_password = None  # Admin password for DelegateAuth
        self.zimbra_public_hostname = None  # Zimbra public service hostname
        self.zimbra_public_port = None  # Zimbra public service port
        self.sessions = {}  # Session management: {session_id: {'admin_account': ..., 'admin_password': ...}}
        self.failed_logins = []  # Track failed login attempts: [(timestamp, ip_address), ...]
        self.login_attempts = login_attempts  # Max failed attempts before shutdown
        self.login_timeout = login_timeout  # Time window in minutes

    def set_admin_credentials(self, admin_account: str, admin_password: str):
        """Set admin credentials for DelegateAuth"""
        self.admin_account = admin_account
        self.admin_password = admin_password

    def verify_admin_credentials(self, admin_account: str, admin_password: str):
        """Verify admin credentials using zmsoap AuthRequest and return token info"""
        try:
            cmd = [
                'sudo', '-u', 'zimbra',
                '/opt/zimbra/bin/zmsoap',
                '-a', admin_account,
                '-p', admin_password,
                'AuthRequest'
            ]

            if self.debug:
                debug_print(f"Verifying admin credentials for {admin_account}...")

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                token_match = re.search(r'<authToken>([^<]+)</authToken>', result.stdout)
                lifetime_match = re.search(r'<lifetime>(\d+)</lifetime>', result.stdout)

                if token_match:
                    auth_token = token_match.group(1)
                    # Get lifetime from response, or use Zimbra default (12 hours = 43200 seconds)
                    token_lifetime = int(lifetime_match.group(1)) if lifetime_match else 43200

                    if self.debug:
                        debug_print(f"✓ Admin credentials verified for {admin_account}")
                        debug_print(f"  Token lifetime: {token_lifetime} seconds ({token_lifetime/3600:.1f} hours)")

                    return {
                        'valid': True,
                        'token': auth_token,
                        'lifetime': token_lifetime
                    }
            else:
                if self.debug:
                    debug_print(f"✗ Admin auth failed: {result.stderr}")
        except Exception as e:
            if self.debug:
                debug_print(f"Exception verifying admin credentials: {e}")

        return {'valid': False}

    def create_session(self, admin_account: str, admin_password: str, auth_token: str, token_lifetime: int):
        """Create a new session with token and expiry time"""
        import uuid
        import time
        from datetime import datetime, timedelta

        session_id = str(uuid.uuid4())
        created_at = time.time()
        expires_at = created_at + token_lifetime

        self.sessions[session_id] = {
            'admin_account': admin_account,
            'admin_password': admin_password,
            'auth_token': auth_token,
            'created_at': created_at,
            'expires_at': expires_at,
            'lifetime': token_lifetime
        }

        if self.debug:
            expire_time = datetime.fromtimestamp(expires_at).strftime('%Y-%m-%d %H:%M:%S')
            debug_print(f"Created session {session_id} for {admin_account}")
            debug_print(f"  Expires at: {expire_time} (in {token_lifetime/3600:.1f} hours)")

        return session_id

    def get_session(self, session_id: str):
        """Get session data by session ID and check if expired"""
        import time
        from datetime import datetime

        session = self.sessions.get(session_id)
        if not session:
            return None

        # Check if session has expired
        if time.time() > session['expires_at']:
            if self.debug:
                expire_time = datetime.fromtimestamp(session['expires_at']).strftime('%Y-%m-%d %H:%M:%S')
                debug_print(f"Session {session_id} expired at {expire_time}")
            # Remove expired session
            del self.sessions[session_id]
            return None

        return session

    def set_session_credentials(self, session_id: str):
        """Set admin credentials from session"""
        session = self.get_session(session_id)
        if session:
            self.admin_account = session['admin_account']
            self.admin_password = session['admin_password']
            return True
        return False

    def delete_session(self, session_id: str):
        """Delete a session (logout)"""
        if session_id in self.sessions:
            if self.debug:
                debug_print(f"Deleting session {session_id}")
            del self.sessions[session_id]
            return True
        return False

    def cleanup_expired_sessions(self):
        """Remove all expired sessions"""
        import time
        from datetime import datetime

        expired_sessions = []
        current_time = time.time()

        for session_id, session in self.sessions.items():
            if current_time > session['expires_at']:
                expired_sessions.append(session_id)

        for session_id in expired_sessions:
            if self.debug:
                expire_time = datetime.fromtimestamp(self.sessions[session_id]['expires_at']).strftime('%Y-%m-%d %H:%M:%S')
                debug_print(f"Cleaned up expired session {session_id} (expired at {expire_time})")
            del self.sessions[session_id]

        return len(expired_sessions)

    def record_failed_login(self, ip_address: str):
        """Record a failed login attempt"""
        import time

        current_time = time.time()
        self.failed_logins.append((current_time, ip_address))

        if self.debug:
            debug_print(f"⚠️  Failed login attempt from {ip_address} (total: {len(self.failed_logins)})")

        # Clean up old entries outside the time window
        timeout_seconds = self.login_timeout * 60
        self.failed_logins = [(t, ip) for t, ip in self.failed_logins
                              if current_time - t < timeout_seconds]

    def check_login_attempts(self, ip_address: str = None):
        """
        Check if failed login attempts exceed the limit within the time window.
        Returns (exceeded, remaining_attempts, next_attempt_time)
        - exceeded: True if limit exceeded
        - remaining_attempts: Number of attempts remaining before lockout
        - next_attempt_time: Time when oldest attempt will expire (for lockout message)
        """
        import time

        current_time = time.time()
        timeout_seconds = self.login_timeout * 60

        # Clean up old entries
        self.failed_logins = [(t, ip) for t, ip in self.failed_logins
                              if current_time - t < timeout_seconds]

        # Count recent failed attempts
        recent_count = len(self.failed_logins)

        if ip_address:
            # Count for specific IP
            recent_count = len([1 for t, ip in self.failed_logins if ip == ip_address])

        exceeded = recent_count >= self.login_attempts
        remaining = max(0, self.login_attempts - recent_count)

        # Calculate when the oldest attempt will expire
        next_attempt_time = None
        if exceeded and self.failed_logins:
            oldest_time = min(t for t, _ in self.failed_logins)
            next_attempt_time = oldest_time + timeout_seconds

        return exceeded, remaining, next_attempt_time

    def shutdown_due_to_failed_logins(self):
        """Shutdown the server due to too many failed login attempts"""
        print("\n" + "="*60, file=sys.stderr)
        print("🚨 SECURITY ALERT: Too many failed login attempts!", file=sys.stderr)
        print(f"   Maximum attempts ({self.login_attempts}) exceeded within {self.login_timeout} minutes", file=sys.stderr)
        print("   Server is shutting down for security reasons.", file=sys.stderr)
        print("="*60 + "\n", file=sys.stderr)

        # Gracefully shutdown
        import os
        import signal
        os.kill(os.getpid(), signal.SIGTERM)

    def get_zimbra_config(self):
        """Get Zimbra public service hostname and port from first domain"""
        if self.zimbra_public_hostname and self.zimbra_public_port:
            return  # Already cached

        try:
            cmd = ['sudo', '-u', 'zimbra', '/opt/zimbra/bin/zmsoap', '-z', 'GetAllDomainsRequest']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                # Extract zimbraPublicServiceHostname and zimbraPublicServicePort from first domain
                hostname_match = re.search(r'<a n="zimbraPublicServiceHostname">([^<]+)</a>', result.stdout)
                port_match = re.search(r'<a n="zimbraPublicServicePort">([^<]+)</a>', result.stdout)

                if hostname_match:
                    self.zimbra_public_hostname = hostname_match.group(1)
                if port_match:
                    self.zimbra_public_port = port_match.group(1)

                if self.debug:
                    print(f"Zimbra config: {self.zimbra_public_hostname}:{self.zimbra_public_port}", file=sys.stderr)
        except Exception as e:
            if self.debug:
                print(f"Failed to get Zimbra config: {e}", file=sys.stderr)
            # Fallback to hostname -f
            try:
                hostname_result = subprocess.run(['hostname', '-f'], capture_output=True, text=True, timeout=5)
                self.zimbra_public_hostname = hostname_result.stdout.strip() if hostname_result.returncode == 0 else 'localhost'
                self.zimbra_public_port = '443'  # Default HTTPS port
            except:
                self.zimbra_public_hostname = 'localhost'
                self.zimbra_public_port = '443'

    def get_admin_token(self):
        """Get admin auth token using stored credentials"""
        if not self.admin_account or not self.admin_password:
            return None

        try:
            cmd = [
                'sudo', '-u', 'zimbra',
                '/opt/zimbra/bin/zmsoap',
                '-a', self.admin_account,
                '-p', self.admin_password,
                'AuthRequest'
            ]

            if self.debug:
                print(f"Getting admin token for {self.admin_account}...", file=sys.stderr)

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                token_match = re.search(r'<authToken>([^<]+)</authToken>', result.stdout)
                if token_match:
                    token = token_match.group(1)
                    if self.debug:
                        print(f"Got admin token (first 20 chars): {token[:20]}...", file=sys.stderr)
                    return token
            else:
                if self.debug:
                    print(f"Admin auth failed: {result.stderr}", file=sys.stderr)
        except Exception as e:
            if self.debug:
                print(f"Exception getting admin token: {e}", file=sys.stderr)

        return None

    def get_delegate_token(self, admin_token: str, account: str):
        """Get delegated auth token for a user account using admin token"""
        try:
            # Build SOAP request for DelegateAuthRequest
            soap_request = f'''<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
<soap:Header><context xmlns="urn:zimbra"><authToken>{admin_token}</authToken></context></soap:Header>
<soap:Body><DelegateAuthRequest xmlns="urn:zimbraAdmin"><account by="name">{account}</account></DelegateAuthRequest></soap:Body>
</soap:Envelope>'''

            cmd = [
                'sudo', '-u', 'zimbra',
                'curl', '-s', '-k',
                '-H', 'Content-Type: application/soap+xml',
                '-H', f'Cookie: ZM_AUTH_TOKEN={admin_token}',
                '-d', soap_request,
                'https://localhost:7071/service/admin/soap/'
            ]

            if self.debug:
                print(f"Getting delegate token for {account}...", file=sys.stderr)

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                token_match = re.search(r'<authToken>([^<]+)</authToken>', result.stdout)
                if token_match:
                    token = token_match.group(1)
                    if self.debug:
                        print(f"Got delegate token (first 20 chars): {token[:20]}...", file=sys.stderr)
                    return token
            else:
                if self.debug:
                    print(f"DelegateAuth curl failed: {result.stderr}", file=sys.stderr)
        except Exception as e:
            if self.debug:
                print(f"Exception getting delegate token: {e}", file=sys.stderr)

        return None

    def format_log_date(self, log_date: str) -> str:
        """Convert log date format from 'Nov 12 00:21:56' to 'YYYY/MM/DD HH:MM:SS'"""
        if not log_date or not log_date.strip():
            return log_date

        try:
            from datetime import datetime
            # Parse log date format: "Nov 12 00:21:56"
            parsed_date = datetime.strptime(f"{self.year} {log_date}", "%Y %b %d %H:%M:%S")
            # Format as YYYY/MM/DD HH:MM:SS
            return parsed_date.strftime("%Y/%m/%d %H:%M:%S")
        except Exception:
            # If parsing fails, return original
            return log_date

    def get_login_form_html(self, lang: str = 'zh_TW', error_message: str = None, remaining_attempts: int = None) -> str:
        """Generate the login form HTML"""
        t = lambda key, **kwargs: get_translation(lang, key, **kwargs)

        error_html = ""
        if error_message:
            error_html = f'<div class="error-message">{html.escape(error_message)}</div>'

        attempts_html = ""
        if remaining_attempts is not None and remaining_attempts > 0:
            attempts_text = t('remaining_attempts', count=remaining_attempts) if 'remaining_attempts' in TRANSLATIONS[lang] else f'剩餘嘗試次數: {remaining_attempts}'
            attempts_html = f'<div class="attempts-warning">{attempts_text}</div>'

        # Set html lang attribute
        html_lang = 'zh-TW' if lang == 'zh_TW' else 'en'

        return f"""
<!DOCTYPE html>
<html lang="{html_lang}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{t('login_title')} - {t('app_title')}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }}
        .login-container {{
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            padding: 40px;
            width: 100%;
            max-width: 450px;
        }}
        .login-header {{
            text-align: center;
            margin-bottom: 30px;
        }}
        .login-header h1 {{
            font-size: 2em;
            color: #2c3e50;
            margin-bottom: 10px;
        }}
        .login-header p {{
            font-size: 0.95em;
            color: #7f8c8d;
        }}
        .form-group {{
            margin-bottom: 20px;
        }}
        label {{
            display: block;
            font-weight: 600;
            color: #333;
            margin-bottom: 8px;
            font-size: 0.95em;
        }}
        input[type="text"], input[type="password"] {{
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 1em;
            transition: all 0.3s;
        }}
        input[type="text"]:focus, input[type="password"]:focus {{
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }}
        .login-button {{
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 1.05em;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
            margin-top: 10px;
        }}
        .login-button:hover {{
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4);
        }}
        .login-button:active {{
            transform: translateY(0);
        }}
        .error-message {{
            background: #fee;
            border: 2px solid #fcc;
            color: #c33;
            padding: 12px 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 0.95em;
            text-align: center;
        }}
        .attempts-warning {{
            background: #fef3cd;
            border: 2px solid #ffc107;
            color: #856404;
            padding: 10px 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 0.9em;
            text-align: center;
            font-weight: 600;
        }}
        .security-info {{
            margin-top: 25px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 8px;
            font-size: 0.85em;
            color: #6c757d;
            text-align: center;
        }}
        .security-info strong {{
            color: #495057;
        }}
        .login-button:disabled {{
            opacity: 0.6;
            cursor: not-allowed;
            transform: none !important;
        }}
        /* Loading overlay */
        .loading-overlay {{
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
            z-index: 9999;
            justify-content: center;
            align-items: center;
        }}
        .loading-overlay.active {{
            display: flex;
        }}
        .loading-content {{
            background: white;
            padding: 50px 70px;
            border-radius: 15px;
            text-align: center;
            box-shadow: 0 20px 60px rgba(0,0,0,0.5);
        }}
        .loading-spinner {{
            border: 6px solid #f3f3f3;
            border-top: 6px solid #667eea;
            border-radius: 50%;
            width: 70px;
            height: 70px;
            animation: spin 1s linear infinite;
            margin: 0 auto 25px;
        }}
        @keyframes spin {{
            0% {{ transform: rotate(0deg); }}
            100% {{ transform: rotate(360deg); }}
        }}
        .loading-text {{
            font-size: 1.3em;
            color: #333;
            margin-bottom: 12px;
            font-weight: 600;
        }}
        .loading-subtext {{
            font-size: 0.95em;
            color: #666;
        }}
    </style>
</head>
<body>
    <!-- Loading overlay -->
    <div class="loading-overlay" id="loadingOverlay">
        <div class="loading-content">
            <div class="loading-spinner"></div>
            <div class="loading-text">🔐 {t('authenticating')}</div>
            <div class="loading-subtext">{t('verifying_credentials')}</div>
        </div>
    </div>

    <div class="login-container">
        <div class="login-header">
            <h1>🔐 {t('admin_login')}</h1>
            <p>{t('app_title')} Email Tracer</p>
        </div>
        {error_html}
        {attempts_html}
        <form method="POST" action="/do_login" id="loginForm" onsubmit="handleLoginSubmit(event)">
            <div class="form-group">
                <label for="lang">{t('language')}</label>
                <select id="lang" name="lang" onchange="handleLanguageChange(this.value)" style="width: 100%; padding: 12px 15px; border: 2px solid #e0e0e0; border-radius: 8px; font-size: 1em;">
                    <option value="zh_TW" {"selected" if lang == "zh_TW" else ""}>{t('lang_zh_TW')}</option>
                    <option value="en" {"selected" if lang == "en" else ""}>{t('lang_en')}</option>
                </select>
            </div>
            <div class="form-group">
                <label for="admin_account">{t('zimbra_admin_account')}</label>
                <input type="text" id="admin_account" name="admin_account"
                       placeholder="admin@domain.com" required autofocus>
            </div>
            <div class="form-group">
                <label for="admin_password">{t('password')}</label>
                <input type="password" id="admin_password" name="admin_password"
                       placeholder="{t('enter_password')}" required>
            </div>
            <button type="submit" class="login-button" id="loginButton">🔓 {t('login_button')}</button>
        </form>
        <div class="security-info">
            <strong>🔒 {t('security_notice')}</strong><br>
            {t('failed_attempts_warning', count=self.login_attempts)}<br>
            ({t('time_window', minutes=self.login_timeout)})
        </div>
    </div>

    <script>
        function handleLanguageChange(newLang) {{
            // Set language cookie
            document.cookie = 'lang=' + newLang + '; path=/; max-age=31536000';
            // Reload page to show new language
            window.location.reload();
        }}

        function handleLoginSubmit(event) {{
            // Prevent double submission
            const form = document.getElementById('loginForm');
            const button = document.getElementById('loginButton');
            const overlay = document.getElementById('loadingOverlay');

            // Check if already submitted
            if (button.disabled) {{
                event.preventDefault();
                return false;
            }}

            // Disable button and show loading
            button.disabled = true;
            button.innerHTML = '⏳ {t('authenticating')}';
            overlay.classList.add('active');

            // Allow form to submit
            return true;
        }}
    </script>
</body>
</html>
"""

    def get_search_form_html(self, lang: str = 'zh_TW') -> str:
        """Generate the search form HTML with two-column layout"""
        t = lambda key, **kwargs: get_translation(lang, key, **kwargs)
        html_lang = 'zh-TW' if lang == 'zh_TW' else 'en'

        return f"""
<!DOCTYPE html>
<html lang="{html_lang}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{t('app_title')} - Email Tracer</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 20px 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .header-content {{
            flex: 1;
        }}
        .header h1 {{
            font-size: 1.8em;
            margin-bottom: 5px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }}
        .header p {{
            font-size: 0.9em;
            opacity: 0.9;
            text-shadow: 1px 1px 2px rgba(0,0,0,0.2);
        }}
        .logout-btn {{
            padding: 10px 20px;
            background: #e74c3c;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            font-weight: 500;
            transition: all 0.3s;
            border: none;
            cursor: pointer;
        }}
        .logout-btn:hover {{
            background: #c0392b;
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.2);
        }}
        .language-selector {{
            position: relative;
            display: inline-block;
        }}
        .language-btn {{
            padding: 8px 15px;
            background: rgba(255,255,255,0.2);
            color: white;
            border: 1px solid rgba(255,255,255,0.3);
            border-radius: 5px;
            font-size: 0.9em;
            cursor: pointer;
            transition: all 0.3s;
            display: flex;
            align-items: center;
            gap: 5px;
        }}
        .language-btn:hover {{
            background: rgba(255,255,255,0.3);
        }}
        .language-dropdown {{
            display: none;
            position: absolute;
            top: 100%;
            right: 0;
            margin-top: 5px;
            background: white;
            border: 1px solid #ddd;
            border-radius: 5px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            min-width: 150px;
            z-index: 1000;
        }}
        .language-dropdown.show {{
            display: block;
        }}
        .language-option {{
            padding: 10px 15px;
            color: #333;
            text-decoration: none;
            display: flex;
            align-items: center;
            gap: 8px;
            transition: background 0.2s;
            cursor: pointer;
            border-bottom: 1px solid #f0f0f0;
        }}
        .language-option:last-child {{
            border-bottom: none;
        }}
        .language-option:hover {{
            background: #f8f9fa;
        }}
        .language-option.active {{
            background: #e8f4f8;
            font-weight: 600;
        }}
        .main-content {{
            display: flex;
            min-height: calc(100vh - 200px);
        }}
        .left-panel {{
            width: 380px;
            background: #f8f9fa;
            border-right: 1px solid #e0e0e0;
            padding: 25px;
            overflow-y: auto;
        }}
        .right-panel {{
            flex: 1;
            padding: 30px;
            background: white;
            overflow-y: auto;
        }}
        .form-group {{
            margin-bottom: 20px;
        }}
        label {{
            display: block;
            font-weight: 600;
            color: #333;
            margin-bottom: 6px;
            font-size: 0.9em;
        }}
        input[type="text"], input[type="date"], input[type="time"] {{
            width: 100%;
            padding: 10px 12px;
            border: 2px solid #e0e0e0;
            border-radius: 6px;
            font-size: 0.95em;
            transition: all 0.3s;
        }}
        input[type="text"]:focus, input[type="date"], input[type="time"]:focus {{
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }}
        .small-text {{
            font-size: 0.8em;
            color: #666;
            margin-top: 4px;
            line-height: 1.3;
        }}
        .button-group {{
            display: flex;
            gap: 10px;
            margin-top: 25px;
        }}
        button {{
            flex: 1;
            padding: 12px 20px;
            font-size: 1em;
            font-weight: 600;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.3s;
        }}
        .btn-search {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }}
        .btn-search:hover {{
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }}
        .btn-reset {{
            background: #e0e0e0;
            color: #333;
        }}
        .btn-reset:hover {{
            background: #d0d0d0;
        }}
        .info-box {{
            background: white;
            border: 1px solid #e0e0e0;
            border-radius: 10px;
            padding: 25px;
            margin-top: 20px;
        }}
        .info-box h3 {{
            color: #667eea;
            margin-bottom: 15px;
            font-size: 1.3em;
        }}
        .info-box ul {{
            margin-left: 20px;
            color: #555;
            line-height: 1.8;
        }}
        .info-box li {{
            margin-bottom: 10px;
        }}
        .welcome-message {{
            text-align: center;
            padding: 50px 20px;
            color: #666;
        }}
        .welcome-message h2 {{
            color: #667eea;
            margin-bottom: 15px;
            font-size: 1.8em;
        }}
        .footer {{
            background: #f5f5f5;
            padding: 15px 20px;
            text-align: center;
            color: #666;
            font-size: 0.85em;
            border-top: 1px solid #e0e0e0;
        }}
        /* Loading overlay */
        .loading-overlay {{
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.7);
            z-index: 9999;
            justify-content: center;
            align-items: center;
        }}
        .loading-overlay.active {{
            display: flex;
        }}
        .loading-content {{
            background: white;
            padding: 40px 60px;
            border-radius: 15px;
            text-align: center;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
        }}
        .loading-spinner {{
            border: 6px solid #f3f3f3;
            border-top: 6px solid #667eea;
            border-radius: 50%;
            width: 60px;
            height: 60px;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }}
        @keyframes spin {{
            0% {{ transform: rotate(0deg); }}
            100% {{ transform: rotate(360deg); }}
        }}
        .loading-text {{
            font-size: 1.2em;
            color: #333;
            margin-bottom: 10px;
        }}
        .loading-subtext {{
            font-size: 0.9em;
            color: #666;
        }}
    </style>
</head>
<body>
    <!-- Loading overlay -->
    <div class="loading-overlay" id="loadingOverlay">
        <div class="loading-content">
            <div class="loading-spinner"></div>
            <div class="loading-text">🔍 {t('searching')}</div>
            <div class="loading-subtext">{t('searching_desc')}</div>
        </div>
    </div>

    <!-- Download overlay -->
    <div class="loading-overlay" id="downloadOverlay">
        <div class="loading-content">
            <div class="loading-spinner"></div>
            <div class="loading-text">📥 {t('preparing_download')}</div>
            <div class="loading-subtext">{t('preparing_eml')}</div>
        </div>
    </div>

    <div class="container">
        <div class="header">
            <div class="header-content">
                <h1>📧 {t('app_title')}</h1>
                <p>{t('app_subtitle', version=VERSION)}</p>
            </div>
            <div style="display: flex; gap: 10px; align-items: center;">
                <div class="language-selector">
                    <button class="language-btn" onclick="toggleLanguageDropdown(event)">
                        🌐 {t('language')} ▼
                    </button>
                    <div class="language-dropdown" id="languageDropdown">
                        <a href="/set_language?lang=zh_TW&redirect=/" class="language-option {'active' if lang == 'zh_TW' else ''}">
                            {t('lang_zh_TW')}
                        </a>
                        <a href="/set_language?lang=en&redirect=/" class="language-option {'active' if lang == 'en' else ''}">
                            {t('lang_en')}
                        </a>
                    </div>
                </div>
                <a href="/logout" class="logout-btn">◄ {t('logout')}</a>
            </div>
        </div>
        <script>
        function toggleLanguageDropdown(event) {{
            event.stopPropagation();
            const dropdown = document.getElementById('languageDropdown');
            dropdown.classList.toggle('show');
        }}
        // Close dropdown when clicking outside
        window.addEventListener('click', function(event) {{
            const dropdown = document.getElementById('languageDropdown');
            if (dropdown && dropdown.classList.contains('show')) {{
                dropdown.classList.remove('show');
            }}
        }});
        </script>

        <div class="main-content">
            <!-- Left Panel: Search Form -->
            <div class="left-panel">
                <form action="/search" method="get" onsubmit="document.getElementById('loadingOverlay').classList.add('active'); return true;">
                    <div class="form-group">
                        <label for="sender">📤 {t('sender')}</label>
                        <input type="text" id="sender" name="sender" placeholder="{t('hint_sender')}">
                        <div class="small-text">{t('regex_supported')}</div>
                    </div>

                    <div class="form-group">
                        <label for="recipient">📥 {t('recipient')}</label>
                        <input type="text" id="recipient" name="recipient" placeholder="{t('hint_recipient')}">
                        <div class="small-text">{t('includes_dedup')}</div>
                    </div>

                    <div class="form-group">
                        <label for="msgid">🆔 {t('message_id')}</label>
                        <input type="text" id="msgid" name="id" placeholder="{t('hint_msgid')}">
                    </div>

                    <div class="form-group">
                        <label for="srchost">🖥️ {t('source_host')}</label>
                        <input type="text" id="srchost" name="srchost" placeholder="{t('hint_srchost')}">
                    </div>

                    <div class="form-group">
                        <label for="time_start">📅 {t('time_range')}</label>
                        <div style="display: grid; grid-template-columns: 1fr; gap: 8px; margin-bottom: 8px;">
                            <div>
                                <label style="font-size: 0.8em; font-weight: normal; color: #666;">{t('start_time')}</label>
                                <div style="display: grid; grid-template-columns: 2fr 60px 60px; gap: 5px; align-items: center;">
                                    <input type="date" id="time_start_date" name="time_start_date">
                                    <select id="time_start_hour" style="padding: 10px 8px;">
                                        {''.join([f'<option value="{h:02d}">{h:02d}</option>' for h in range(24)])}
                                    </select>
                                    <select id="time_start_minute" style="padding: 10px 8px;">
                                        <option value="00">00</option>
                                        <option value="30">30</option>
                                    </select>
                                </div>
                            </div>
                            <div>
                                <label style="font-size: 0.8em; font-weight: normal; color: #666;">{t('end_time')}</label>
                                <div style="display: grid; grid-template-columns: 2fr 60px 60px; gap: 5px; align-items: center;">
                                    <input type="date" id="time_end_date" name="time_end_date">
                                    <select id="time_end_hour" style="padding: 10px 8px;">
                                        {''.join([f'<option value="{h:02d}" {"selected" if h == 23 else ""}>{h:02d}</option>' for h in range(24)])}
                                    </select>
                                    <select id="time_end_minute" style="padding: 10px 8px;">
                                        <option value="00">00</option>
                                        <option value="30">30</option>
                                        <option value="59" selected>59</option>
                                    </select>
                                </div>
                            </div>
                        </div>
                        <div class="small-text">{t('or_input')}</div>
                        <input type="text" id="time" name="time" placeholder="{t('hint_time')}" style="margin-top: 5px;">
                    </div>

                    <div class="form-group">
                        <label style="display: flex; align-items: center; cursor: pointer; user-select: none;">
                            <input type="checkbox" id="include_history" name="include_history" value="1" style="width: auto; margin-right: 8px; cursor: pointer;">
                            <span style="font-weight: normal; font-size: 0.9em;">📚 {t('include_history')}</span>
                        </label>
                        <div class="small-text">{t('include_history_desc')}</div>
                    </div>

                    <div class="button-group">
                        <button type="submit" class="btn-search">🔍 {t('search_button')}</button>
                        <button type="button" class="btn-reset" onclick="window.location.href='/';">🔄 {t('clear_button')}</button>
                    </div>
                </form>
            </div>

            <!-- Right Panel: Welcome / Results Area -->
            <div class="right-panel">
                <div class="welcome-message">
                    <h2>{t('welcome_message') if 'welcome_message' in TRANSLATIONS[lang] else ('歡迎使用 ' + t('app_title'))}</h2>
                    <p style="font-size: 1.1em; margin-bottom: 30px;">{t('welcome_desc') if 'welcome_desc' in TRANSLATIONS[lang] else '請在左側輸入搜尋條件，開始追蹤郵件'}</p>
                </div>

                <div class="info-box">
                    <h3>{t('tips_title')}</h3>
                    <ul>
                        <li>{t('tip_regex')}</li>
                        <li>{t('tip_dedup')}</li>
                        <li>{t('tip_multihop')}</li>
                        <li>{t('tip_timeformat')}</li>
                    </ul>
                </div>
            </div>
        </div>

        <div class="footer">
            {t('log_files')}: {', '.join(self.log_files) if len(self.log_files) <= 3 else f'{self.log_files[0]} {t("and_more", count=len(self.log_files)-1)}'}
        </div>
    </div>
    <script>
        // Combine date and time inputs before form submission
        document.addEventListener('DOMContentLoaded', function() {{
            const form = document.querySelector('form');
            if (form) {{
                form.addEventListener('submit', function(e) {{
                    // Combine start date and time
                    const startDate = document.getElementById('time_start_date').value;
                    const startHour = document.getElementById('time_start_hour').value;
                    const startMinute = document.getElementById('time_start_minute').value;
                    if (startDate && startHour && startMinute) {{
                        const combined = startDate + 'T' + startHour + ':' + startMinute;
                        let input = document.createElement('input');
                        input.type = 'hidden';
                        input.name = 'time_start';
                        input.value = combined;
                        form.appendChild(input);
                    }}

                    // Combine end date and time
                    const endDate = document.getElementById('time_end_date').value;
                    const endHour = document.getElementById('time_end_hour').value;
                    const endMinute = document.getElementById('time_end_minute').value;
                    if (endDate && endHour && endMinute) {{
                        const combined = endDate + 'T' + endHour + ':' + endMinute;
                        let input = document.createElement('input');
                        input.type = 'hidden';
                        input.name = 'time_end';
                        input.value = combined;
                        form.appendChild(input);
                    }}
                }});
            }}
        }});
    </script>
</body>
</html>
"""

    def format_results_html(self, messages: List[Message], search_params: dict, filter_obj,
                           offset: int = 0, limit: int = 50, total_count: int = 0, has_more: bool = False,
                           lang: str = 'zh_TW') -> str:
        """Format search results as HTML with pagination support"""
        t = lambda key, **kwargs: get_translation(lang, key, **kwargs)
        html_lang = 'zh-TW' if lang == 'zh_TW' else 'en'

        # Build search summary
        search_summary = []
        if search_params.get('sender'):
            search_summary.append(f"{t('sender')}: {html.escape(search_params['sender'])}")
        if search_params.get('recipient'):
            search_summary.append(f"{t('recipient')}: {html.escape(search_params['recipient'])}")
        if search_params.get('id'):
            search_summary.append(f"{t('message_id')}: {html.escape(search_params['id'])}")
        if search_params.get('srchost'):
            search_summary.append(f"{t('source_host')}: {html.escape(search_params['srchost'])}")
        if search_params.get('time'):
            search_summary.append(f"{t('time_range')}: {html.escape(search_params['time'])}")

        summary_text = " | ".join(search_summary) if search_summary else t('showing_all_messages') if 'showing_all_messages' in TRANSLATIONS[lang] else '顯示所有郵件'

        # Build next page URL for "Load More" button
        next_offset = offset + limit
        # Build query string for next page (preserve all search parameters)
        import urllib.parse
        next_params = search_params.copy()
        next_params['offset'] = str(next_offset)
        next_params['limit'] = str(limit)
        # Remove empty params
        next_params = {k: v for k, v in next_params.items() if v}
        next_url = '/search?' + urllib.parse.urlencode(next_params)

        # Generate results HTML
        results_html = []
        for msg in messages:
            # Prepare subject display
            subject_html = ""
            if msg.subject:
                subject_html = f"""
                    <div class="field-row">
                        <div class="field-label">{t('subject')}:</div>
                        <div class="field-value" style="font-style: italic;">{html.escape(msg.subject)}</div>
                    </div>"""

            # Prepare source file display
            source_html = ""
            if msg.source_file:
                source_html = f"""
                    <div class="field-row">
                        <div class="field-label">{t('log')}:</div>
                        <div class="field-value">{html.escape(msg.source_file)}</div>
                    </div>"""

            results_html.append(f"""
                <div class="message-block">
                    <div class="field-row">
                        <div class="field-label">{t('message_id')}:</div>
                        <div class="field-value message-id">{html.escape(msg.message_id)}</div>
                    </div>{source_html}
                    <div class="field-row">
                        <div class="field-label">{t('from')}:</div>
                        <div class="field-value">{html.escape(msg.sender or 'unknown')}</div>
                    </div>{subject_html}
                    <div class="field-row">
                        <div class="field-label">{t('to')}:</div>
                        <div class="field-value">
                            <ul style="margin: 0; padding-left: 20px;">
            """)

            # Recipients list
            for recip in sorted(msg.recipients.values(), key=lambda r: r.address):
                badge = ""
                if recip.from_amavis_only:
                    badge = f' <span class="badge badge-dedup">{t("badge_dedup")}</span>'
                if recip.orig_recip:
                    badge += f' <span class="badge badge-forward">{t("badge_forward_prefix")}{html.escape(recip.orig_recip)}</span>'

                results_html.append(f"<li>{html.escape(recip.address)}{badge}</li>")

            results_html.append("</ul></div></div>")

            # Delivery details
            recipient_pattern = filter_obj.recipient_pattern if hasattr(filter_obj, 'recipient_pattern') else None

            for recip in sorted(msg.recipients.values(), key=lambda r: r.address):
                if recipient_pattern and not recipient_pattern.search(recip.address):
                    if not (recip.orig_recip and recipient_pattern.search(recip.orig_recip)):
                        continue

                results_html.append(f'<div class="recipient-detail"><strong>→ {html.escape(recip.address)}</strong>')

                # Collect delivery path
                delivery_path = self._collect_delivery_path(msg, recip, recip.address)

                for stage in delivery_path:
                    status_class = "status-sent" if stage.get('status') == 'sent' else "status-other"
                    # Format the timestamp
                    formatted_time = self.format_log_date(stage.get('time', ''))
                    results_html.append(f"""
                        <div class="delivery-stage">
                            <div class="stage-time">{html.escape(formatted_time)}</div>
                            <div class="stage-path">
                                {html.escape(stage.get('from_host', ''))}
                                {f" ({html.escape(stage.get('from_ip', ''))})" if stage.get('from_ip') else ''}
                                {f" → {html.escape(stage.get('to_host', ''))}" if stage.get('to_host') else ''}
                                {f" ({html.escape(stage.get('to_ip', ''))})" if stage.get('to_ip') else ''}
                            </div>
                            <div class="stage-status {status_class}">
                                {html.escape(stage.get('status', ''))}
                            </div>
                        </div>
                    """)

                    if stage.get('status_msg') and stage.get('status') != 'sent':
                        results_html.append(f'<div class="status-message">{html.escape(stage["status_msg"])}</div>')

                    if stage.get('amavis_info'):
                        amav = stage['amavis_info']
                        results_html.append(f"""
                            <div class="amavis-info">
                                🛡️ Amavis: {html.escape(amav['disposition'])} ({html.escape(amav['reason'])})
                                | Hits: {html.escape(amav['hits'])} | {html.escape(amav['ms'])} ms
                            </div>
                        """)

                results_html.append('</div>')

            # Add email action buttons at the end of message block
            # Build a list of accounts to try (internal accounts only)
            import urllib.parse
            accounts_to_try = []

            # Add sender first (if it's an internal account - likely in "Sent" folder)
            if msg.sender:
                accounts_to_try.append(msg.sender)

            # Add all recipients
            if msg.recipients:
                for recip in msg.recipients.values():
                    if recip.address not in accounts_to_try:
                        accounts_to_try.append(recip.address)

            if accounts_to_try:
                accounts_param = ','.join(accounts_to_try)

                results_html.append(f"""
                    <div class="email-actions">
                        <a href="/loading_email?id={urllib.parse.quote(msg.message_id)}&accounts={urllib.parse.quote(accounts_param)}"
                           class="btn-action btn-view-email" target="_blank"
                           onclick="var btn=this; btn.innerHTML='⏳ {t("loading")}'; btn.style.opacity='0.6'; setTimeout(function(){{btn.innerHTML='📧 {t("view_email")}'; btn.style.opacity='1';}}, 2000);">
                            📧 {t("view_email")}
                        </a>
                        <a href="javascript:void(0);"
                           class="btn-action btn-download"
                           onclick="handleDownload('/view_email?id={urllib.parse.quote(msg.message_id)}&accounts={urllib.parse.quote(accounts_param)}&download=1');">
                            💾 {t("download_email")}
                        </a>
                    </div>
                """)

            results_html.append('</div>')

        # Prepare search_params for URL encoding (convert boolean to string '1' for include_history)
        url_search_params = search_params.copy()
        if url_search_params.get('include_history'):
            url_search_params['include_history'] = '1'
        else:
            url_search_params.pop('include_history', None)  # Remove if False

        html_content = f"""
<!DOCTYPE html>
<html lang="{html_lang}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{t('search_results') if 'search_results' in TRANSLATIONS[lang] else '搜尋結果'} - {t('app_title')}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 20px 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .header-content {{
            flex: 1;
        }}
        .header h1 {{
            font-size: 1.6em;
            margin-bottom: 5px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }}
        .header p {{
            font-size: 0.85em;
            opacity: 0.9;
        }}
        .logout-btn {{
            padding: 10px 20px;
            background: #e74c3c;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            font-weight: 500;
            transition: all 0.3s;
            border: none;
            cursor: pointer;
        }}
        .logout-btn:hover {{
            background: #c0392b;
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.2);
        }}
        .language-selector {{
            position: relative;
            display: inline-block;
        }}
        .language-btn {{
            padding: 8px 15px;
            background: rgba(255,255,255,0.2);
            color: white;
            border: 1px solid rgba(255,255,255,0.3);
            border-radius: 5px;
            font-size: 0.9em;
            cursor: pointer;
            transition: all 0.3s;
            display: flex;
            align-items: center;
            gap: 5px;
        }}
        .language-btn:hover {{
            background: rgba(255,255,255,0.3);
        }}
        .language-dropdown {{
            display: none;
            position: absolute;
            top: 100%;
            right: 0;
            margin-top: 5px;
            background: white;
            border: 1px solid #ddd;
            border-radius: 5px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            min-width: 150px;
            z-index: 1000;
        }}
        .language-dropdown.show {{
            display: block;
        }}
        .language-option {{
            padding: 10px 15px;
            color: #333;
            text-decoration: none;
            display: flex;
            align-items: center;
            gap: 8px;
            transition: background 0.2s;
            cursor: pointer;
            border-bottom: 1px solid #f0f0f0;
        }}
        .language-option:last-child {{
            border-bottom: none;
        }}
        .language-option:hover {{
            background: #f8f9fa;
        }}
        .language-option.active {{
            background: #e8f4f8;
            font-weight: 600;
        }}
        .main-content {{
            display: flex;
            min-height: calc(100vh - 180px);
        }}
        .left-panel {{
            width: 380px;
            background: #f8f9fa;
            border-right: 1px solid #e0e0e0;
            padding: 25px;
            overflow-y: auto;
        }}
        .right-panel {{
            flex: 1;
            background: white;
            overflow-y: auto;
        }}
        .search-summary {{
            background: #e8f4f8;
            padding: 15px 25px;
            border-bottom: 2px solid #667eea;
            font-size: 0.9em;
        }}
        .search-summary strong {{
            color: #667eea;
            font-weight: 600;
        }}
        .results-container {{
            padding: 25px;
        }}
        .results-count {{
            font-size: 1em;
            color: #333;
            margin-bottom: 20px;
            font-weight: 600;
            padding: 10px 15px;
            background: #f0f7ff;
            border-left: 4px solid #667eea;
            border-radius: 4px;
        }}
        .form-group {{
            margin-bottom: 18px;
        }}
        label {{
            display: block;
            font-weight: 600;
            color: #333;
            margin-bottom: 6px;
            font-size: 0.85em;
        }}
        input[type="text"], input[type="date"], input[type="time"] {{
            width: 100%;
            padding: 9px 11px;
            border: 2px solid #e0e0e0;
            border-radius: 6px;
            font-size: 0.9em;
            transition: all 0.3s;
        }}
        input[type="text"]:focus, input[type="date"], input[type="time"]:focus {{
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }}
        .small-text {{
            font-size: 0.75em;
            color: #666;
            margin-top: 3px;
            line-height: 1.3;
        }}
        .button-group {{
            display: flex;
            gap: 8px;
            margin-top: 20px;
        }}
        button {{
            flex: 1;
            padding: 10px 18px;
            font-size: 0.95em;
            font-weight: 600;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.3s;
        }}
        .btn-search {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }}
        .btn-search:hover {{
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }}
        .btn-reset {{
            background: #e0e0e0;
            color: #333;
        }}
        .btn-reset:hover {{
            background: #d0d0d0;
        }}
        .message-block {{
            background: #f9f9f9;
            border-left: 4px solid #667eea;
            padding: 18px;
            margin-bottom: 20px;
            border-radius: 5px;
        }}
        .field-row {{
            display: flex;
            margin-bottom: 8px;
            font-size: 0.95em;
            align-items: baseline;
        }}
        .field-label {{
            min-width: 100px;
            font-weight: bold;
            color: #333;
            flex-shrink: 0;
        }}
        .field-value {{
            color: #555;
            flex-grow: 1;
            word-break: break-all;
        }}
        .field-value.message-id {{
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }}
        .message-subject {{
            color: #333;
            margin-bottom: 8px;
            font-style: italic;
            background: #fff;
            padding: 8px;
            border-radius: 4px;
            border-left: 3px solid #667eea;
            font-size: 0.95em;
        }}
        .badge {{
            display: inline-block;
            padding: 2px 7px;
            border-radius: 3px;
            font-size: 0.7em;
            font-weight: 600;
            margin-left: 5px;
        }}
        .badge-dedup {{
            background: #fff3cd;
            color: #856404;
        }}
        .badge-forward {{
            background: #d1ecf1;
            color: #0c5460;
        }}
        .recipient-detail {{
            background: white;
            padding: 12px;
            margin-top: 12px;
            border-radius: 5px;
            border: 1px solid #e0e0e0;
            font-size: 0.9em;
        }}
        .delivery-stage {{
            display: grid;
            grid-template-columns: 180px 1fr 100px;
            gap: 10px;
            padding: 8px;
            background: #f9f9f9;
            margin: 4px 0;
            border-radius: 3px;
            align-items: center;
        }}
        .stage-time {{
            font-family: 'Courier New', monospace;
            color: #666;
            font-size: 0.85em;
        }}
        .stage-path {{
            color: #333;
            font-size: 0.9em;
        }}
        .stage-status {{
            text-align: right;
            font-weight: 600;
            padding: 4px 8px;
            border-radius: 3px;
            font-size: 0.85em;
        }}
        .status-sent {{
            background: #d4edda;
            color: #155724;
        }}
        .status-other {{
            background: #f8d7da;
            color: #721c24;
        }}
        .status-message {{
            color: #721c24;
            background: #f8d7da;
            padding: 8px;
            margin: 4px 0;
            border-radius: 3px;
            font-size: 0.85em;
        }}
        .amavis-info {{
            background: #e7f3ff;
            color: #004085;
            padding: 8px;
            margin: 4px 0;
            border-radius: 3px;
            font-size: 0.85em;
        }}
        .no-results {{
            text-align: center;
            padding: 50px 20px;
            color: #666;
        }}
        .no-results h2 {{
            font-size: 1.5em;
            margin-bottom: 15px;
        }}
        .pagination-info {{
            text-align: center;
            padding: 15px;
            color: #666;
            font-size: 0.9em;
            background: #f8f9fa;
            border-radius: 5px;
            margin: 15px 0;
        }}
        .load-more-container {{
            text-align: center;
            padding: 20px;
        }}
        .btn-load-more {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 12px 35px;
            font-size: 1em;
            font-weight: 600;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s;
            text-decoration: none;
            display: inline-block;
        }}
        .btn-load-more:hover {{
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4);
        }}
        .email-actions {{
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid #e0e0e0;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }}
        .btn-action {{
            padding: 8px 16px;
            font-size: 0.85em;
            font-weight: 600;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.3s;
            text-decoration: none;
            display: inline-block;
        }}
        .btn-view-email {{
            background: linear-gradient(135deg, #1e88e5 0%, #1565c0 100%);
            color: white;
        }}
        .btn-view-email:hover {{
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(30, 136, 229, 0.4);
        }}
        .btn-view-headers {{
            background: linear-gradient(135deg, #43a047 0%, #2e7d32 100%);
            color: white;
        }}
        .btn-view-headers:hover {{
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(67, 160, 71, 0.4);
        }}
        .btn-download {{
            background: linear-gradient(135deg, #f57c00 0%, #e65100 100%);
            color: white;
        }}
        .btn-download:hover {{
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(245, 124, 0, 0.4);
        }}
        /* Loading overlay */
        .loading-overlay {{
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.7);
            z-index: 9999;
            justify-content: center;
            align-items: center;
        }}
        .loading-overlay.active {{
            display: flex;
        }}
        .loading-content {{
            background: white;
            padding: 40px 60px;
            border-radius: 15px;
            text-align: center;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
        }}
        .loading-spinner {{
            border: 6px solid #f3f3f3;
            border-top: 6px solid #667eea;
            border-radius: 50%;
            width: 60px;
            height: 60px;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }}
        @keyframes spin {{
            0% {{ transform: rotate(0deg); }}
            100% {{ transform: rotate(360deg); }}
        }}
        .loading-text {{
            font-size: 1.2em;
            color: #333;
            margin-bottom: 10px;
        }}
        .loading-subtext {{
            font-size: 0.9em;
            color: #666;
        }}
    </style>
</head>
<body>
    <!-- Loading overlay -->
    <div class="loading-overlay" id="loadingOverlay">
        <div class="loading-content">
            <div class="loading-spinner"></div>
            <div class="loading-text">🔍 {t('searching')}</div>
            <div class="loading-subtext">{t('searching_desc')}</div>
        </div>
    </div>

    <!-- Download overlay -->
    <div class="loading-overlay" id="downloadOverlay">
        <div class="loading-content">
            <div class="loading-spinner"></div>
            <div class="loading-text">📥 {t('preparing_download')}</div>
            <div class="loading-subtext">{t('preparing_eml')}</div>
        </div>
    </div>

    <div class="container">
        <div class="header">
            <div class="header-content">
                <h1>📧 {t('app_title')}</h1>
                <p>{t('app_subtitle', version=VERSION)}</p>
            </div>
            <div style="display: flex; gap: 10px; align-items: center;">
                <div class="language-selector">
                    <button class="language-btn" onclick="toggleLanguageDropdown2(event)">
                        🌐 {t('language')} ▼
                    </button>
                    <div class="language-dropdown" id="languageDropdown2">
                        <a href="/set_language?lang=zh_TW&redirect={urllib.parse.quote(f'/search?{urllib.parse.urlencode(url_search_params)}')}" class="language-option {'active' if lang == 'zh_TW' else ''}">
                            {t('lang_zh_TW')}
                        </a>
                        <a href="/set_language?lang=en&redirect={urllib.parse.quote(f'/search?{urllib.parse.urlencode(url_search_params)}')}" class="language-option {'active' if lang == 'en' else ''}">
                            {t('lang_en')}
                        </a>
                    </div>
                </div>
                <a href="/logout" class="logout-btn">◄ {t('logout')}</a>
            </div>
        </div>
        <script>
        function toggleLanguageDropdown2(event) {{
            event.stopPropagation();
            const dropdown = document.getElementById('languageDropdown2');
            dropdown.classList.toggle('show');
        }}
        // Close dropdown when clicking outside
        window.addEventListener('click', function(event) {{
            const dropdown = document.getElementById('languageDropdown2');
            if (dropdown && dropdown.classList.contains('show')) {{
                dropdown.classList.remove('show');
            }}
        }});
        </script>

        <div class="main-content">
            <!-- Left Panel: Search Form -->
            <div class="left-panel">
                <form action="/search" method="get" onsubmit="document.getElementById('loadingOverlay').classList.add('active'); return true;">
                    <div class="form-group">
                        <label for="sender">📤 {t('sender')}</label>
                        <input type="text" id="sender" name="sender" value="{html.escape(search_params.get('sender', ''))}" placeholder="{t('hint_sender')}">
                        <div class="small-text">{t('regex_supported')}</div>
                    </div>

                    <div class="form-group">
                        <label for="recipient">📥 {t('recipient')}</label>
                        <input type="text" id="recipient" name="recipient" value="{html.escape(search_params.get('recipient', ''))}" placeholder="{t('hint_recipient')}">
                        <div class="small-text">{t('includes_dedup')}</div>
                    </div>

                    <div class="form-group">
                        <label for="msgid">🆔 {t('message_id')}</label>
                        <input type="text" id="msgid" name="id" value="{html.escape(search_params.get('id', ''))}" placeholder="{t('hint_msgid')}">
                    </div>

                    <div class="form-group">
                        <label for="srchost">🖥️ {t('source_host')}</label>
                        <input type="text" id="srchost" name="srchost" value="{html.escape(search_params.get('srchost', ''))}" placeholder="{t('hint_srchost')}">
                    </div>

                    <div class="form-group">
                        <label for="time_start">📅 {t('time_range')}</label>
                        <div style="display: grid; grid-template-columns: 1fr; gap: 6px; margin-bottom: 6px;">
                            <div>
                                <label style="font-size: 0.75em; font-weight: normal; color: #666;">{t('start_time')}</label>
                                <div style="display: grid; grid-template-columns: 2fr 50px 50px; gap: 4px; align-items: center;">
                                    <input type="date" id="time_start_date" name="time_start_date" value="{html.escape(search_params.get('time_start', '').split('T')[0] if search_params.get('time_start') else '')}">
                                    <select id="time_start_hour" style="padding: 9px 6px; font-size: 0.9em;" data-default="{html.escape(search_params.get('time_start', '').split('T')[1][:2] if search_params.get('time_start') and 'T' in search_params.get('time_start') else '00')}">
                                        {''.join([f'<option value="{h:02d}">{h:02d}</option>' for h in range(24)])}
                                    </select>
                                    <select id="time_start_minute" style="padding: 9px 6px; font-size: 0.9em;" data-default="{html.escape(search_params.get('time_start', '').split('T')[1].split(':')[1] if search_params.get('time_start') and 'T' in search_params.get('time_start') and ':' in search_params.get('time_start').split('T')[1] else '00')}">
                                        <option value="00">00</option>
                                        <option value="30">30</option>
                                    </select>
                                </div>
                            </div>
                            <div>
                                <label style="font-size: 0.75em; font-weight: normal; color: #666;">{t('end_time')}</label>
                                <div style="display: grid; grid-template-columns: 2fr 50px 50px; gap: 4px; align-items: center;">
                                    <input type="date" id="time_end_date" name="time_end_date" value="{html.escape(search_params.get('time_end', '').split('T')[0] if search_params.get('time_end') else '')}">
                                    <select id="time_end_hour" style="padding: 9px 6px; font-size: 0.9em;" data-default="{html.escape(search_params.get('time_end', '').split('T')[1][:2] if search_params.get('time_end') and 'T' in search_params.get('time_end') else '23')}">
                                        {''.join([f'<option value="{h:02d}">{h:02d}</option>' for h in range(24)])}
                                    </select>
                                    <select id="time_end_minute" style="padding: 9px 6px; font-size: 0.9em;" data-default="{html.escape(search_params.get('time_end', '').split('T')[1].split(':')[1][:2] if search_params.get('time_end') and 'T' in search_params.get('time_end') and ':' in search_params.get('time_end').split('T')[1] else '59')}">
                                        <option value="00">00</option>
                                        <option value="30">30</option>
                                        <option value="59">59</option>
                                    </select>
                                </div>
                            </div>
                        </div>
                        <div class="small-text">{t('or_input')}</div>
                        <input type="text" id="time" name="time" value="{html.escape(search_params.get('time', ''))}" placeholder="{t('hint_time')}" style="margin-top: 5px;">
                    </div>

                    <div class="form-group">
                        <label style="display: flex; align-items: center; cursor: pointer; user-select: none;">
                            <input type="checkbox" id="include_history" name="include_history" value="1" {"checked" if search_params.get('include_history') else ""} style="width: auto; margin-right: 8px; cursor: pointer;">
                            <span style="font-weight: normal; font-size: 0.85em;">📚 {t('include_history')}</span>
                        </label>
                        <div class="small-text">{t('include_history_desc')}</div>
                    </div>

                    <div class="button-group">
                        <button type="submit" class="btn-search">🔍 {t('search_button')}</button>
                        <button type="button" class="btn-reset" onclick="window.location.href='/';">🔄 {t('clear_button')}</button>
                    </div>
                </form>
            </div>

            <!-- Right Panel: Search Results -->
            <div class="right-panel">
                <div class="search-summary">
                    <strong>{t('search_criteria')}:</strong> {summary_text}
                </div>

                <div class="results-container">
                    {f'<div class="results-count">{t("found_messages", count=total_count)} <span style="color: #666; font-size: 0.9em;">{t("showing_range", start=offset + 1, end=min(offset + len(messages), total_count))}</span></div>' if total_count > 0 else ''}

                    {"".join(results_html) if messages else f'<div class="no-results"><h2>😔 {t("no_results")}</h2><p>{t("try_adjust")}</p></div>'}

                    {f'<div class="pagination-info">{t("showing_pagination", start=offset + 1, end=min(offset + len(messages), total_count), total=total_count)}</div>' if total_count > 0 else ''}

                    {f'<div class="load-more-container"><a href="{html.escape(next_url)}" class="btn-load-more">📥 {t("load_more")}</a></div>' if has_more else ''}
                </div>
            </div>
        </div>
    </div>
    <script>
        // Set default values for time selects and combine inputs before form submission
        document.addEventListener('DOMContentLoaded', function() {{
            // Set default values from data-default attributes
            const startHour = document.getElementById('time_start_hour');
            const startMinute = document.getElementById('time_start_minute');
            const endHour = document.getElementById('time_end_hour');
            const endMinute = document.getElementById('time_end_minute');

            if (startHour && startHour.getAttribute('data-default')) {{
                startHour.value = startHour.getAttribute('data-default');
            }}
            if (startMinute && startMinute.getAttribute('data-default')) {{
                const defaultMin = startMinute.getAttribute('data-default');
                // Round to nearest available option (00 or 30)
                const roundedMin = parseInt(defaultMin) < 15 ? '00' : '30';
                startMinute.value = roundedMin;
            }}
            if (endHour && endHour.getAttribute('data-default')) {{
                endHour.value = endHour.getAttribute('data-default');
            }}
            if (endMinute && endMinute.getAttribute('data-default')) {{
                const defaultMin = endMinute.getAttribute('data-default');
                // Round to nearest available option (00, 30, or 59)
                const minInt = parseInt(defaultMin);
                let roundedMin = '00';
                if (minInt >= 45) {{
                    roundedMin = '59';
                }} else if (minInt >= 15) {{
                    roundedMin = '30';
                }}
                endMinute.value = roundedMin;
            }}

            // Combine date and time inputs before form submission
            const form = document.querySelector('form[action="/search"]');
            if (form) {{
                form.addEventListener('submit', function(e) {{
                    // Combine start date and time
                    const startDate = document.getElementById('time_start_date').value;
                    const startHourVal = document.getElementById('time_start_hour').value;
                    const startMinuteVal = document.getElementById('time_start_minute').value;
                    if (startDate && startHourVal && startMinuteVal) {{
                        const combined = startDate + 'T' + startHourVal + ':' + startMinuteVal;
                        let input = document.createElement('input');
                        input.type = 'hidden';
                        input.name = 'time_start';
                        input.value = combined;
                        form.appendChild(input);
                    }}

                    // Combine end date and time
                    const endDate = document.getElementById('time_end_date').value;
                    const endHourVal = document.getElementById('time_end_hour').value;
                    const endMinuteVal = document.getElementById('time_end_minute').value;
                    if (endDate && endHourVal && endMinuteVal) {{
                        const combined = endDate + 'T' + endHourVal + ':' + endMinuteVal;
                        let input = document.createElement('input');
                        input.type = 'hidden';
                        input.name = 'time_end';
                        input.value = combined;
                        form.appendChild(input);
                    }}
                }});
            }}
        }});

        // Handle download with loading overlay
        function handleDownload(url) {{
            // Show loading overlay
            document.getElementById('downloadOverlay').classList.add('active');

            // Clear any existing cookie
            document.cookie = 'downloadComplete=; Path=/; Max-Age=0';

            // Create hidden iframe to trigger download
            const iframe = document.createElement('iframe');
            iframe.style.display = 'none';
            iframe.src = url;
            document.body.appendChild(iframe);

            // Check for download completion cookie
            let attempts = 0;
            const maxAttempts = 60; // 30 seconds max (500ms interval)

            const checkDownload = setInterval(function() {{
                attempts++;

                // Check if download completion cookie exists
                if (document.cookie.indexOf('downloadComplete=true') !== -1) {{
                    // Download started, hide overlay
                    document.getElementById('downloadOverlay').classList.remove('active');
                    clearInterval(checkDownload);
                    // Clean up iframe
                    setTimeout(function() {{
                        document.body.removeChild(iframe);
                    }}, 1000);
                }} else if (attempts >= maxAttempts) {{
                    // Timeout - hide overlay anyway
                    document.getElementById('downloadOverlay').classList.remove('active');
                    clearInterval(checkDownload);
                    document.body.removeChild(iframe);
                }}
            }}, 500);
        }}
    </script>
</body>
</html>
"""
        return html_content

    def _collect_delivery_path(self, msg: Message, recip: RecipientInfo, recip_addr: str) -> List[dict]:
        """Recursively collect delivery path for a recipient (no loop detection needed as Postfix queue_id chain is unidirectional)"""
        stages = []

        # Current stage
        stage = {
            'time': msg.arrive_time or '',
            'from_host': msg.prev_host or msg.host or '',
            'from_ip': msg.prev_ip or '',
            'to_host': recip.next_host or '',
            'to_ip': recip.next_ip or '',
            'status': recip.status or '',
            'status_msg': recip.status_msg or ''
        }

        # Filter localhost IPs
        if stage['from_ip'] in ['127.0.0.1', '::1']:
            stage['from_ip'] = ''
            if stage['from_host'] == 'localhost':
                stage['from_host'] = msg.host or 'localhost'

        # Add Amavis info if available
        if recip.amavis_id and recip.amavis_id in self.parser.amavis_records:
            amav = self.parser.amavis_records[recip.amavis_id]
            stage['amavis_info'] = {
                'disposition': amav.disposition,
                'reason': amav.reason,
                'hits': amav.hits,
                'ms': amav.ms
            }

        stages.append(stage)

        # Recursively follow next_queue_id
        if recip.next_queue_id:
            if self.debug:
                print(f"DEBUG: Checking next_queue_id: {recip.next_queue_id}", file=sys.stderr)
                print(f"DEBUG: Is in qid_to_msg? {recip.next_queue_id in self.parser.qid_to_msg}", file=sys.stderr)

            if recip.next_queue_id in self.parser.qid_to_msg:
                next_msg_id, next_msg = self.parser.qid_to_msg[recip.next_queue_id]
                if self.debug:
                    print(f"DEBUG: Found next message: {next_msg_id}", file=sys.stderr)
                    print(f"DEBUG: Looking for recipient: {recip_addr}", file=sys.stderr)
                    print(f"DEBUG: Available recipients: {list(next_msg.recipients.keys())}", file=sys.stderr)

                if recip_addr in next_msg.recipients:
                    next_recip = next_msg.recipients[recip_addr]
                    if self.debug:
                        print(f"DEBUG: Recursing with next recipient", file=sys.stderr)
                    stages.extend(self._collect_delivery_path(next_msg, next_recip, recip_addr))
                elif self.debug:
                    print(f"DEBUG: Recipient {recip_addr} not found in next message", file=sys.stderr)

        return stages


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread"""
    pass


class JtZmmsgtraceRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for jt_zmmsgtrace web UI"""

    web_ui: WebUI = None

    def log_message(self, format, *args):
        """Suppress default logging"""
        if self.web_ui and self.web_ui.debug:
            sys.stderr.write(f"{self.address_string()} - {format % args}\n")

    def get_session_id(self) -> str:
        """Extract session ID from cookie"""
        cookie_header = self.headers.get('Cookie')
        if not cookie_header:
            return None

        # Parse cookies
        import http.cookies
        cookies = http.cookies.SimpleCookie()
        cookies.load(cookie_header)

        if 'session_id' in cookies:
            return cookies['session_id'].value
        return None

    def get_language(self) -> str:
        """Get current language from cookie or detect from browser"""
        # Try to get from cookie first
        cookie_header = self.headers.get('Cookie')
        if cookie_header:
            import http.cookies
            cookies = http.cookies.SimpleCookie()
            cookies.load(cookie_header)
            if 'lang' in cookies:
                return cookies['lang'].value

        # Detect from Accept-Language header
        accept_lang = self.headers.get('Accept-Language', '')
        # Check if Chinese (any variant)
        if 'zh' in accept_lang.lower():
            return 'zh_TW'
        # Default to English
        return 'en'

    def set_language_cookie(self, lang: str) -> str:
        """Generate Set-Cookie header for language"""
        import http.cookies
        cookie = http.cookies.SimpleCookie()
        cookie['lang'] = lang
        cookie['lang']['path'] = '/'
        cookie['lang']['max-age'] = 31536000  # 1 year
        return cookie['lang'].OutputString()

    def check_auth(self) -> bool:
        """Check if user is authenticated (has valid session)"""
        session_id = self.get_session_id()
        if not session_id:
            return False

        session = self.web_ui.get_session(session_id)
        if not session:
            return False

        # Set credentials from session for this request
        self.web_ui.set_session_credentials(session_id)
        return True

    def redirect_to_login(self):
        """Redirect to login page"""
        self.send_response(302)
        self.send_header('Location', '/login')
        self.end_headers()

    def do_GET(self):
        """Handle GET requests"""
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path
        query = urllib.parse.parse_qs(parsed_path.query)

        # Public routes (no authentication required)
        if path == '/login':
            # Show login form with language detection
            lang = self.get_language()
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.send_header('Set-Cookie', self.set_language_cookie(lang))
            self.end_headers()
            self.wfile.write(self.web_ui.get_login_form_html(lang).encode('utf-8'))
            return

        if path == '/set_language':
            # Handle language change
            new_lang = query.get('lang', ['en'])[0]
            if new_lang not in TRANSLATIONS:
                new_lang = 'en'

            # Redirect back with language cookie
            redirect_to = query.get('redirect', ['/'])[0]
            self.send_response(302)
            self.send_header('Location', redirect_to)
            self.send_header('Set-Cookie', self.set_language_cookie(new_lang))
            self.end_headers()
            return

        if path == '/logout':
            # Handle logout
            session_id = self.get_session_id()
            if session_id:
                self.web_ui.delete_session(session_id)
                if self.web_ui.debug:
                    print(f"User logged out, session {session_id} deleted", file=sys.stderr)

            # Clear cookie and redirect to login
            self.send_response(302)
            self.send_header('Location', '/login')
            self.send_header('Set-Cookie', 'session_id=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0')
            self.end_headers()
            return

        # Protected routes (authentication required)
        if not self.check_auth():
            self.redirect_to_login()
            return

        if path == '/':
            # Show search form
            lang = self.get_language()
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(self.web_ui.get_search_form_html(lang).encode('utf-8'))

        elif path == '/search':
            # Perform search
            self.handle_search(query)

        elif path == '/loading_email':
            # Show loading page for email
            self.handle_loading_email(query)

        elif path == '/view_email':
            # View email content
            self.handle_view_email(query)

        elif path == '/progress':
            # Get progress status
            self.handle_progress(query)

        elif path == '/view_headers':
            # View email headers
            self.handle_view_headers(query)

        else:
            self.send_error(404, 'Not Found')

    def do_POST(self):
        """Handle POST requests"""
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path

        if path == '/do_login':
            # Handle login form submission
            self.handle_login()
        else:
            self.send_error(404, 'Not Found')

    def handle_login(self):
        """Handle login form submission"""
        # Get language from cookie for error messages
        lang = self.get_language()

        # Get client IP address
        client_ip = self.client_address[0]

        # Check if login attempts exceeded before processing
        exceeded, remaining, next_attempt_time = self.web_ui.check_login_attempts()
        if exceeded:
            # Shutdown the server
            import time
            wait_time = int(next_attempt_time - time.time()) if next_attempt_time else 0
            error_msg = get_translation(lang, 'login_attempts_exceeded', wait_time=wait_time)

            self.send_response(403)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(self.web_ui.get_login_form_html(lang, error_message=error_msg).encode('utf-8'))

            # Shutdown server after sending response
            import threading
            threading.Timer(1.0, self.web_ui.shutdown_due_to_failed_logins).start()
            return

        # Parse form data
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        form_data = urllib.parse.parse_qs(post_data)

        admin_account = form_data.get('admin_account', [''])[0].strip()
        admin_password = form_data.get('admin_password', [''])[0]
        # Get language from form (overrides cookie if specified)
        form_lang = form_data.get('lang', [''])[0]
        if form_lang and form_lang in TRANSLATIONS:
            lang = form_lang

        # Validate credentials
        auth_result = self.web_ui.verify_admin_credentials(admin_account, admin_password)
        if auth_result['valid']:
            # Successful login - create session with token and lifetime
            session_id = self.web_ui.create_session(
                admin_account,
                admin_password,
                auth_result['token'],
                auth_result['lifetime']
            )

            if self.web_ui.debug:
                print(f"✓ Login successful for {admin_account} from {client_ip}", file=sys.stderr)

            # Set session cookie with Max-Age matching token lifetime
            cookie_max_age = auth_result['lifetime']
            self.send_response(302)
            self.send_header('Location', '/')
            self.send_header('Set-Cookie', f'session_id={session_id}; Path=/; HttpOnly; SameSite=Strict; Max-Age={cookie_max_age}')
            self.send_header('Set-Cookie', self.set_language_cookie(lang))
            self.end_headers()
        else:
            # Failed login - record attempt
            self.web_ui.record_failed_login(client_ip)

            if self.web_ui.debug:
                print(f"✗ Login failed for {admin_account} from {client_ip}", file=sys.stderr)

            # Check if we should shutdown after this failed attempt
            exceeded, remaining, next_attempt_time = self.web_ui.check_login_attempts()
            if exceeded:
                # Shutdown the server
                import time
                wait_time = int(next_attempt_time - time.time()) if next_attempt_time else 0
                error_msg = get_translation(lang, 'login_attempts_exceeded', wait_time=wait_time)

                self.send_response(403)
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(self.web_ui.get_login_form_html(lang, error_message=error_msg).encode('utf-8'))

                # Shutdown server after sending response
                import threading
                threading.Timer(1.0, self.web_ui.shutdown_due_to_failed_logins).start()
            else:
                # Show error with remaining attempts
                error_msg = get_translation(lang, 'invalid_credentials')

                self.send_response(401)
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(self.web_ui.get_login_form_html(
                    lang,
                    error_message=error_msg,
                    remaining_attempts=remaining
                ).encode('utf-8'))

    def handle_search(self, query: dict):
        """Handle search request"""
        # Extract and sanitize search parameters
        def sanitize_input(value, max_length=500):
            """Sanitize user input to prevent injection attacks"""
            if not value:
                return ''
            # Truncate to max length
            value = str(value)[:max_length]
            # Remove null bytes
            value = value.replace('\x00', '')
            return value

        search_params = {
            'id': sanitize_input(query.get('id', [''])[0]),
            'sender': sanitize_input(query.get('sender', [''])[0]),
            'recipient': sanitize_input(query.get('recipient', [''])[0]),
            'srchost': sanitize_input(query.get('srchost', [''])[0]),
            'desthost': sanitize_input(query.get('desthost', [''])[0]),
            'time': sanitize_input(query.get('time', [''])[0], 50),
            'time_start': sanitize_input(query.get('time_start', [''])[0], 30),
            'time_end': sanitize_input(query.get('time_end', [''])[0], 30),
            'include_history': query.get('include_history', [''])[0] == '1',
            'offset': sanitize_input(query.get('offset', ['0'])[0], 10),
            'limit': sanitize_input(query.get('limit', ['50'])[0], 10),
        }

        # Save original search_params for display (preserve all parameters for form repopulation)
        display_params = search_params.copy()

        # Convert datetime-local to time format if provided
        if search_params['time_start'] or search_params['time_end']:
            # datetime-local format: "2025-01-10T12:00"
            # Convert to YYYYMMDDHHMMSS
            def convert_datetime_local(dt_str):
                if not dt_str:
                    return ''
                try:
                    # Parse "2025-01-10T12:00" -> "20250110120000"
                    dt_str = dt_str.replace('T', '').replace(':', '').replace('-', '')
                    # Ensure we have seconds (pad with 00 if needed)
                    if len(dt_str) == 12:  # YYYYMMDDHHMM
                        dt_str += '00'
                    return dt_str
                except:
                    return ''

            start = convert_datetime_local(search_params['time_start'])
            end = convert_datetime_local(search_params['time_end'])
            if start or end:
                search_params['time'] = f"{start},{end}" if start and end else start or end

        # Extract include_history for log file selection
        include_history = search_params['include_history']

        # Create filter_params (clean params for filtering, removing empty values)
        filter_params = {k: v for k, v in search_params.items() if v and k not in ['include_history', 'time_start', 'time_end', 'offset', 'limit']}

        # Determine which log files to use
        import glob
        import os
        if include_history:
            log_files = sorted(glob.glob('/var/log/zimbra*'))
            if not log_files:
                log_files = [DEFAULT_LOGFILE]
        else:
            log_files = [DEFAULT_LOGFILE]

        # Check if log files have been modified since last parse
        log_files_changed = False
        if self.web_ui.parser:
            # Get current modification times
            current_mtimes = {}
            for filepath in log_files:
                try:
                    if os.path.exists(filepath):
                        current_mtimes[filepath] = os.path.getmtime(filepath)
                except:
                    pass

            # Compare with stored modification times
            if current_mtimes != self.web_ui.parsed_log_files_mtime:
                log_files_changed = True
                if self.web_ui.debug:
                    print(f"📝 Log files have been modified, reloading...", file=sys.stderr)

        # Parse logs if not already done, or if history setting changed, or if log files changed
        need_reparse = (not self.web_ui.parser) or (self.web_ui.parsed_with_history != include_history) or log_files_changed

        if need_reparse:
            # Parse logs (移除 Loading 訊息，直接解析)
            if self.web_ui.debug:
                files_info = f"{len(log_files)} files" if include_history else "current log file"
                print(f"Parsing {files_info}...", file=sys.stderr)

            self.web_ui.parser = LogParser(self.web_ui.year, self.web_ui.debug)
            self.web_ui.parsed_with_history = include_history
            for filepath in log_files:
                self.web_ui.parser.parse_file(filepath)
            self.web_ui.parser.integrate_amavis_data()

            # Store modification times after parsing
            self.web_ui.parsed_log_files_mtime = {}
            for filepath in log_files:
                try:
                    if os.path.exists(filepath):
                        self.web_ui.parsed_log_files_mtime[filepath] = os.path.getmtime(filepath)
                except:
                    pass

        # Create filter object
        class Args:
            pass

        args = Args()
        args.id = filter_params.get('id')
        args.sender = filter_params.get('sender')
        args.recipient = filter_params.get('recipient')
        args.srchost = filter_params.get('srchost')
        args.desthost = filter_params.get('desthost')
        args.year = self.web_ui.year

        # Parse time
        if filter_params.get('time'):
            parts = filter_params['time'].split(',')
            parser_obj = LogParser(self.web_ui.year)
            start_time = parser_obj.time_to_number(parts[0].strip()) if len(parts) > 0 and parts[0].strip() else None
            end_time = parser_obj.time_to_number(parts[1].strip(), max_values=True) if len(parts) > 1 and parts[1].strip() else None
            args.time = (start_time, end_time)
        else:
            args.time = None

        # Parse pagination parameters with validation
        try:
            offset = int(search_params.get('offset', 0))
            limit = int(search_params.get('limit', 50))
            # Limit to reasonable values
            offset = max(0, min(offset, 100000))
            limit = max(1, min(limit, 500))
        except (ValueError, TypeError):
            offset = 0
            limit = 50

        # Create filter with error handling
        try:
            msg_filter = MessageFilter(args)
        except ValueError as e:
            # Return error page for invalid regex
            error_html = f"""
<!DOCTYPE html>
<html lang="zh-TW">
<head><title>Error - jt_zmmsgtrace</title></head>
<body style="font-family: sans-serif; padding: 20px;">
    <h1>❌ Invalid Search Parameters</h1>
    <p style="color: red;">{html.escape(str(e))}</p>
    <p><a href="/">← Return to search</a></p>
</body>
</html>"""
            self.send_response(400)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(error_html.encode('utf-8'))
            return

        # Filter messages
        matching_messages = []
        for msg_id, queue_dict in self.web_ui.parser.messages.items():
            if not queue_dict:
                continue

            # Get root queue
            all_qids = set(queue_dict.keys())
            referenced_qids = set()
            for msg in queue_dict.values():
                for recip in msg.recipients.values():
                    if recip.next_queue_id:
                        referenced_qids.add(recip.next_queue_id)

            root_qids = all_qids - referenced_qids
            if root_qids:
                first_qid = sorted(root_qids)[0]
            else:
                first_qid = sorted(queue_dict.keys())[0]

            first_msg = queue_dict[first_qid]

            if msg_filter.matches(first_msg):
                matching_messages.append(first_msg)

        # Filter out invalid/incomplete messages (unknown or reject with no useful data)
        valid_messages = []
        for msg in matching_messages:
            # Skip if message_id is unknown/reject AND has no sender AND has no recipients
            is_unknown = msg.message_id.startswith('[unknown:') or msg.message_id.startswith('[reject:')
            has_no_data = not msg.sender and not msg.recipients
            if is_unknown and has_no_data:
                continue
            valid_messages.append(msg)

        # Sort by arrive_time (newest first)
        valid_messages.sort(key=lambda m: m.arrive_time or '', reverse=True)

        # Pagination
        total_count = len(valid_messages)
        paginated_messages = valid_messages[offset:offset + limit]
        has_more = (offset + limit) < total_count

        # Generate HTML response (use display_params to preserve all original search parameters)
        lang = self.get_language()
        html_content = self.web_ui.format_results_html(
            paginated_messages, display_params, msg_filter,
            offset=offset, limit=limit, total_count=total_count, has_more=has_more,
            lang=lang
        )

        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(html_content.encode('utf-8'))

    def _get_internal_domains(self) -> set:
        """Get all Zimbra internal domains"""
        try:
            import subprocess
            # Get all domains using zmprov
            cmd = ['sudo', '-u', 'zimbra', '/opt/zimbra/bin/zmprov', 'gad']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                # Parse domain list (one domain per line)
                domains = set(line.strip() for line in result.stdout.splitlines() if line.strip())
                if self.web_ui.debug:
                    debug_print(f"Found {len(domains)} internal domains: {', '.join(sorted(domains))}")
                return domains
            else:
                if self.web_ui.debug:
                    debug_print(f"Failed to get domains: {result.stderr}")
                return set()
        except Exception as e:
            if self.web_ui.debug:
                debug_print(f"Error getting internal domains: {e}")
            return set()

    def _check_account_exists(self, account: str) -> bool:
        """Check if a Zimbra account exists using zmsoap"""
        try:
            import subprocess
            # Use zmsoap SearchRequest to check if account exists (simpler and more reliable)
            # Just search for any message in the account - if it works, account exists
            check_cmd = [
                'sudo', '-u', 'zimbra',
                '/opt/zimbra/bin/zmsoap', '-z', '-m', account, '-t', 'mail',
                'SearchRequest', '@types=message', '@query=in:inbox', '@limit=1'
            ]
            result = subprocess.run(check_cmd, capture_output=True, text=True, timeout=10)
            # If account exists, zmsoap returns 0 (even if no messages found)
            # If account doesn't exist, returns error
            return result.returncode == 0
        except Exception as e:
            if self.web_ui.debug:
                print(f"Error checking account {account}: {e}", file=sys.stderr)
            return False

    def handle_loading_email(self, query: dict):
        """Show loading page that will load the actual email content"""
        import urllib.parse
        import uuid

        # Get current language
        lang = self.get_language()
        t = lambda key, **kwargs: get_translation(lang, key, **kwargs)
        html_lang = 'zh-TW' if lang == 'zh_TW' else 'en'

        # Generate unique progress ID for this request
        progress_id = str(uuid.uuid4())

        # Add progress_id to query
        query_with_progress = dict(query)
        query_with_progress['progress_id'] = [progress_id]

        # Build the actual view_email URL with all query parameters including progress_id
        view_url = f"/view_email?{urllib.parse.urlencode(query_with_progress, doseq=True)}"

        # Extract accounts for display
        accounts_str = query.get('accounts', [''])[0]
        accounts = [a.strip() for a in accounts_str.split(',') if a.strip()]
        accounts_display = ', '.join(accounts[:2])  # Show first 2 accounts
        if len(accounts) > 2:
            accounts_display += f' {t("and_x_more_accounts", count=len(accounts))}'

        html_content = f"""
<!DOCTYPE html>
<html lang="{html_lang}">
<head>
    <meta charset="UTF-8">
    <title>{t('loading_email_title')}</title>
    <style>
        body {{
            font-family: 'Segoe UI', sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background: #f5f5f5;
        }}
        .loading-container {{
            text-align: center;
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
        }}
        .spinner {{
            border: 5px solid #f3f3f3;
            border-top: 5px solid #667eea;
            border-radius: 50%;
            width: 60px;
            height: 60px;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }}
        @keyframes spin {{
            0% {{ transform: rotate(0deg); }}
            100% {{ transform: rotate(360deg); }}
        }}
        h2 {{
            color: #333;
            margin: 0 0 10px 0;
        }}
        p {{
            color: #666;
            margin: 0;
        }}
    </style>
</head>
<body>
    <div class="loading-container">
        <div class="spinner"></div>
        <h2>📧 {t('loading_email_heading')}</h2>
        <p id="loading-status">{t('connecting_server')}</p>
    </div>
    <script>
        const statusEl = document.getElementById('loading-status');
        const progressId = '{progress_id}';
        let checkCount = 0;
        const maxChecks = 120; // Maximum 60 seconds (500ms * 120)

        // Poll progress API
        function checkProgress() {{
            fetch('/progress?id=' + progressId)
                .then(response => response.json())
                .then(data => {{
                    if (data.status) {{
                        statusEl.textContent = data.status;
                    }}

                    if (data.complete) {{
                        // Operation complete, redirect using replace to avoid back button issues
                        window.location.replace("{view_url}");
                    }} else {{
                        // Continue checking
                        checkCount++;
                        if (checkCount < maxChecks) {{
                            setTimeout(checkProgress, 500);
                        }} else {{
                            // Timeout, redirect anyway
                            statusEl.textContent = '{t("loading_timeout")}';
                            window.location.replace("{view_url}");
                        }}
                    }}
                }})
                .catch(error => {{
                    console.error('Progress check error:', error);
                    // On error, continue checking
                    checkCount++;
                    if (checkCount < maxChecks) {{
                        setTimeout(checkProgress, 500);
                    }} else {{
                        statusEl.textContent = '{t("connection_error")}';
                        window.location.replace("{view_url}");
                    }}
                }});
        }}

        // Create hidden iframe to start loading email immediately
        const iframe = document.createElement('iframe');
        iframe.style.display = 'none';
        iframe.src = "{view_url}";
        document.body.appendChild(iframe);

        // Start checking progress immediately
        statusEl.textContent = '{t("checking_accounts")}: {accounts_display}';
        setTimeout(checkProgress, 100);
    </script>
</body>
</html>
"""
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(html_content.encode('utf-8'))

    def handle_progress(self, query: dict):
        """Handle progress status request"""
        import json

        progress_id = query.get('id', [''])[0]

        if progress_id and progress_id in self.web_ui.progress_store:
            progress_data = self.web_ui.progress_store[progress_id]
        else:
            progress_data = {'status': '正在初始化...', 'complete': False}

        self.send_response(200)
        self.send_header('Content-type', 'application/json; charset=utf-8')
        self.send_header('Cache-Control', 'no-cache')
        self.end_headers()
        self.wfile.write(json.dumps(progress_data).encode('utf-8'))

    def handle_view_email(self, query: dict):
        """Handle view email request"""
        import subprocess
        import re

        # Get current language
        lang = self.get_language()
        t = lambda key, **kwargs: get_translation(lang, key, **kwargs)

        # Extract and validate parameters
        message_id = query.get('id', [''])[0]
        accounts_str = query.get('accounts', [''])[0]
        is_download = query.get('download', [''])[0] == '1'
        progress_id = query.get('progress_id', [''])[0]

        # Helper function to update progress
        def update_progress(status, complete=False):
            if progress_id:
                self.web_ui.progress_store[progress_id] = {
                    'status': status,
                    'complete': complete
                }

        # Validate message_id format (RFC 822 Message-ID)
        # Allow common characters in Message-ID: letters, numbers, @ . _ - + ~ ! = ? # $ % & * /
        if not message_id or not re.match(r'^[a-zA-Z0-9@._+~!=?#$%&*/-]+$', message_id) or len(message_id) > 200:
            self._send_error_html(t('invalid_msgid_format'), t('msgid_format_incorrect'), lang=lang)
            return

        # Parse and validate account list
        if not accounts_str:
            self._send_error_html(t('missing_recipients'), t('cannot_determine_mailbox'), lang=lang)
            return

        accounts = [a.strip() for a in accounts_str.split(',') if a.strip()]
        valid_accounts = []
        for account in accounts:
            if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', account) and len(account) <= 200:
                valid_accounts.append(account)

        if not valid_accounts:
            self._send_error_html(t('invalid_email_format'), t('all_recipients_invalid'), lang=lang)
            return

        # Pre-filter accounts: check which ones exist in Zimbra
        # Optimization: first get all internal domains, then only check accounts from internal domains
        existing_accounts = []
        skipped_accounts = []

        update_progress(t('getting_internal_domains'))

        # Get all internal domains
        internal_domains = self._get_internal_domains()

        if self.web_ui.debug:
            debug_print(f"Checking {len(valid_accounts)} accounts against {len(internal_domains)} internal domains...")

        # First pass: filter by domain
        internal_domain_accounts = []
        for account in valid_accounts:
            domain = account.split('@')[-1] if '@' in account else ''
            if domain in internal_domains:
                internal_domain_accounts.append(account)
                if self.web_ui.debug:
                    debug_print(f"✓ {account} - domain '{domain}' is internal")
            else:
                skipped_accounts.append(account)
                if self.web_ui.debug:
                    debug_print(f"✗ {account} - domain '{domain}' is external")

        if not internal_domain_accounts:
            # All accounts are from external domains
            skipped_list = '<br>'.join([f'• {acc} ({t("external_domain")})' for acc in skipped_accounts])
            self._send_error_html(
                t('no_internal_accounts'),
                f'{t("accounts_domain_not_in_zimbra")}<br><br>{skipped_list}<br><br>'
                f'<strong>{t("explanation")}</strong>: {t("internal_accounts_only")}<br>'
                f'{t("if_outbound_check_sender")}',
                lang=lang
            )
            return

        # Second pass: verify each internal domain account actually exists
        update_progress(t('checking_x_internal_accounts', count=len(internal_domain_accounts)))

        for i, account in enumerate(internal_domain_accounts, 1):
            update_progress(t('checking_account_x_of_y', current=i, total=len(internal_domain_accounts), account=account))
            if self._check_account_exists(account):
                existing_accounts.append(account)
                if self.web_ui.debug:
                    debug_print(f"✓ {account} exists")
            else:
                skipped_accounts.append(account)
                if self.web_ui.debug:
                    debug_print(f"✗ {account} does not exist (但 domain 是內部的)")

        if not existing_accounts:
            # All accounts are external
            skipped_list = '<br>'.join([f'• {acc} ({t("external_mailbox")})' for acc in skipped_accounts])
            self._send_error_html(
                t('no_internal_accounts'),
                f'{t("accounts_not_in_zimbra")}<br><br>{skipped_list}<br><br>'
                f'<strong>{t("explanation")}</strong>: {t("internal_accounts_only")}<br>'
                f'{t("if_outbound_check_sender")}',
                lang=lang
            )
            return

        # Try each existing account until we find the email
        update_progress(t('searching_x_accounts', count=len(existing_accounts)))
        last_error = None
        tried_accounts = []

        for i, account in enumerate(existing_accounts, 1):
            tried_accounts.append(account)
            update_progress(t('searching_account_x_of_y', current=i, total=len(existing_accounts), account=account))
            try:
                # Search for the email using zmsoap SearchRequest
                # Use correct syntax: field[Message-ID]:"<message-id>"
                search_query = f'field[Message-ID]:"<{message_id}>"'

                search_cmd = [
                    'sudo', '-u', 'zimbra',
                    '/opt/zimbra/bin/zmsoap', '-z', '-m', account, '-t', 'mail',
                    'SearchRequest',
                    f'@types=message',
                    f'@query={search_query}'
                ]

                if self.web_ui.debug:
                    debug_print(f"Trying account: {account}")
                    debug_print(f"Running: {' '.join(search_cmd)}")

                search_result = subprocess.run(search_cmd, capture_output=True, text=True, timeout=30)

                if search_result.returncode != 0:
                    last_error = t('account_x_search_failed', account=account)
                    if self.web_ui.debug:
                        print(f"Search failed: {search_result.stderr}", file=sys.stderr)
                    continue

                # Parse search result to get the internal message ID
                # zmsoap returns XML like: <m rev="..." id="12345" .../>
                # id attribute may not be the first attribute
                match = re.search(r'<m[^>]*\sid="(\d+)"', search_result.stdout)
                if not match:
                    last_error = t('account_x_email_not_found', account=account)
                    if self.web_ui.debug:
                        print(f"Message not found in {account}", file=sys.stderr)
                    continue

                internal_id = match.group(1)

                update_progress(t('reading_email_from_x', account=account))

                # Get the email content using zmsoap GetMsgRequest
                # Correct syntax: GetMsgRequest m (not /m) with attributes
                # Try to force inline content with useContentUrl=0
                get_cmd = [
                    'sudo', '-u', 'zimbra',
                    '/opt/zimbra/bin/zmsoap', '-z', '-m', account, '-t', 'mail',
                    'GetMsgRequest', 'm',
                    f'@id={internal_id}',
                    '@raw=1',
                    '@useContentUrl=0'
                ]

                if self.web_ui.debug:
                    debug_print(f"Getting email from account: {account}, ID: {internal_id}")
                    debug_print(f"Running: {' '.join(get_cmd)}")

                get_result = subprocess.run(get_cmd, capture_output=True, text=True, timeout=30)

                if get_result.returncode == 0:
                    if self.web_ui.debug:
                        print(f"GetMsg stdout length: {len(get_result.stdout)} chars", file=sys.stderr)
                        print(f"GetMsg stdout (first 500 chars): {get_result.stdout[:500]}", file=sys.stderr)

                    # Success! Extract email content from XML
                    # zmsoap returns: <m ...><content>BASE64_OR_TEXT</content></m>
                    # With @raw=1, it should return the raw RFC822 message in <content>
                    # However, some Zimbra versions return <content url="..."/> instead

                    # Check if content is returned as URL (need to fetch via URL)
                    email_content = None
                    url_match = re.search(r'<content\s+url="([^"]+)"\s*/>', get_result.stdout)
                    if url_match:
                        # Content is a URL, need to fetch it with authentication
                        content_url = url_match.group(1)
                        if self.web_ui.debug:
                            print(f"zmsoap returned URL, fetching content from: {content_url}", file=sys.stderr)

                        # Get admin token
                        admin_token = self.web_ui.get_admin_token()
                        if not admin_token:
                            last_error = t('account_x_no_admin_auth', account=account)
                            if self.web_ui.debug:
                                debug_print(f"Failed to get admin token")
                            continue

                        # Get delegate token for the account
                        user_token = self.web_ui.get_delegate_token(admin_token, account)
                        if not user_token:
                            last_error = t('account_x_no_delegate_auth', account=account)
                            if self.web_ui.debug:
                                debug_print(f"Failed to get delegate token for {account}")
                            continue

                        # Get Zimbra public service config
                        self.web_ui.get_zimbra_config()

                        # Add fmt=raw to get full RFC822 content
                        download_url = content_url
                        if '?' in download_url:
                            download_url += '&fmt=raw'
                        else:
                            download_url += '?fmt=raw'

                        # Build full URL with correct hostname and port
                        full_url = f'https://{self.web_ui.zimbra_public_hostname}:{self.web_ui.zimbra_public_port}{download_url}'
                        curl_cmd = [
                            'sudo', '-u', 'zimbra',
                            'curl', '-s', '-k',
                            '-H', f'Cookie: ZM_AUTH_TOKEN={user_token}',
                            full_url
                        ]

                        if self.web_ui.debug:
                            print(f"Downloading from: {full_url}", file=sys.stderr)

                        curl_result = subprocess.run(curl_cmd, capture_output=True, text=True, timeout=30)
                        if self.web_ui.debug:
                            print(f"curl returncode: {curl_result.returncode}", file=sys.stderr)
                            print(f"curl stdout length: {len(curl_result.stdout)}", file=sys.stderr)
                            if curl_result.stderr:
                                print(f"curl stderr: {curl_result.stderr[:200]}", file=sys.stderr)

                        if curl_result.returncode == 0 and curl_result.stdout and not 'HTTP ERROR' in curl_result.stdout:
                            email_content = curl_result.stdout
                        else:
                            last_error = t('account_x_cannot_get_from_url', account=account)
                            continue
                    else:
                        # Try to extract content from XML
                        content_match = re.search(r'<content>(.*?)</content>', get_result.stdout, re.DOTALL)
                        if content_match:
                            email_content = content_match.group(1).strip()
                            # Unescape XML/HTML entities (zmsoap escapes special characters in XML)
                            email_content = html.unescape(email_content)
                        else:
                            last_error = t('account_x_cannot_parse', account=account)
                            if self.web_ui.debug:
                                print(f"Cannot parse email content from XML", file=sys.stderr)
                                print(f"XML response (full): {get_result.stdout}", file=sys.stderr)
                            continue

                    # At this point, email_content should be set (either from zmsoap or zmmailbox)
                    if not email_content:
                        last_error = t('account_x_cannot_get_content', account=account)
                        continue

                    # Handle both download and view modes
                    self.send_response(200)
                    if is_download:
                        # Download mode: return as .eml file
                        update_progress(t('preparing_file'), complete=True)
                        self.send_header('Content-Type', 'message/rfc822')
                        self.send_header('Content-Disposition', f'attachment; filename="{message_id}.eml"')
                        # Set a cookie to signal download completion
                        self.send_header('Set-Cookie', 'downloadComplete=true; Path=/; Max-Age=10')
                        self.end_headers()
                        self.wfile.write(email_content.encode('utf-8'))
                        return  # Success - download complete
                    else:
                        # View mode: Parse email and return HTML with nice formatting
                        from email import message_from_string
                        from email.header import decode_header
                        import quopri
                        import base64

                        # Parse email
                        try:
                            update_progress(t('rendering_email'), complete=True)
                            msg = message_from_string(email_content)

                            # Extract headers (using global decode_header_value function)
                            email_from = decode_header_value(msg.get('From', ''))
                            email_to = decode_header_value(msg.get('To', ''))
                            email_cc = decode_header_value(msg.get('Cc', ''))
                            email_subject = decode_header_value(msg.get('Subject', ''))
                            email_date = msg.get('Date', '')

                            # Extract security headers
                            auth_results = msg.get('Authentication-Results', '')
                            spf_result = msg.get('Received-SPF', '')
                            dmarc_result = ''
                            dkim_result = ''

                            # Extract email routing information (Received headers)
                            received_headers = msg.get_all('Received', [])
                            mail_route = []

                            if received_headers:
                                # Parse each Received header (in reverse order, oldest first)
                                for idx, received in enumerate(reversed(received_headers)):
                                    # Clean up the received header (remove line breaks)
                                    received_clean = ' '.join(received.split())

                                    # Parse components
                                    from_match = re.search(r'from\s+([^\s]+(?:\s+\([^)]+\))?)', received_clean, re.IGNORECASE)

                                    # Extract 'by' hostname only (without program info)
                                    by_match = re.search(r'by\s+([^\s]+)', received_clean, re.IGNORECASE)

                                    # Look for program info: any parenthesis after 'by hostname (...)'
                                    # Format: by hostname (IP/hostname) (program info)
                                    # Or: by hostname (program info) - if parenthesis doesn't contain IP/hostname
                                    program_match = None

                                    # First try: match second parenthesis after 'by'
                                    second_paren_match = re.search(r'by\s+[^\s]+\s+\([^)]+\)\s*(\([^)]+\))', received_clean, re.IGNORECASE)
                                    if second_paren_match:
                                        program_match = second_paren_match
                                    else:
                                        # Second try: single parenthesis that doesn't look like IP/hostname
                                        single_paren_match = re.search(r'by\s+[^\s]+\s+(\([^)]+\))(?:\s+with|\s+id|;)', received_clean, re.IGNORECASE)
                                        if single_paren_match:
                                            content = single_paren_match.group(1)
                                            # If doesn't contain IP characteristics ([, numbers.numbers), likely a program name
                                            if not re.search(r'\[|\d+\.\d+', content):
                                                program_match = single_paren_match

                                    with_match = re.search(r'with\s+([^\s]+)', received_clean, re.IGNORECASE)
                                    for_match = re.search(r'for\s+<([^>]+)>', received_clean, re.IGNORECASE)
                                    date_match = re.search(r';\s*(.+)$', received_clean)

                                    hop_info = {
                                        'hop': idx + 1,
                                        'from': from_match.group(1).strip() if from_match else 'Unknown',
                                        'by': by_match.group(1).strip() if by_match else 'Unknown',
                                        'program': program_match.group(1).strip() if program_match else '',
                                        'with': with_match.group(1).strip() if with_match else '',
                                        'for': for_match.group(1).strip() if for_match else '',
                                        'date': date_match.group(1).strip() if date_match else '',
                                        'raw': received_clean[:200]  # Keep first 200 chars for tooltip
                                    }
                                    mail_route.append(hop_info)

                            # Parse Authentication-Results for DKIM, SPF, DMARC
                            if auth_results:
                                # Extract DKIM
                                dkim_match = re.search(r'dkim=([^;]+)', auth_results, re.IGNORECASE)
                                if dkim_match:
                                    dkim_result = dkim_match.group(1).strip()

                                # Extract DMARC
                                dmarc_match = re.search(r'dmarc=([^;]+)', auth_results, re.IGNORECASE)
                                if dmarc_match:
                                    dmarc_result = dmarc_match.group(1).strip()

                            # Extract SPAM information
                            spam_score = msg.get('X-Spam-Score', '') or msg.get('X-Spam-Level', '')
                            spam_status = msg.get('X-Spam-Status', '')
                            spam_tests = []

                            # Parse spam score as float for classification
                            spam_score_float = 0.0
                            if spam_score:
                                try:
                                    spam_score_float = float(spam_score.replace(',', '.'))
                                except (ValueError, AttributeError):
                                    spam_score_float = 0.0

                            # Parse X-Spam-Status for detailed test results
                            spam_required = ''
                            if spam_status:
                                # Remove line breaks and extra spaces (RFC 822 header folding)
                                spam_status_clean = ' '.join(spam_status.split())

                                if self.web_ui.debug:
                                    print(f"DEBUG: X-Spam-Status (original) = {spam_status[:200]}...", file=sys.stderr)
                                    print(f"DEBUG: X-Spam-Status (cleaned) = {spam_status_clean[:200]}...", file=sys.stderr)

                                # Format: No, score=0.202 required=6.6 tests=[TEST1=score1,TEST2=score2,...]
                                # Extract required threshold
                                required_match = re.search(r'required=([\d.]+)', spam_status_clean)
                                if required_match:
                                    spam_required = required_match.group(1)

                                # Also support: tests=TEST1=score1,TEST2=score2 (without brackets)
                                tests_match = re.search(r'tests=\[(.*?)\]', spam_status_clean)
                                if not tests_match:
                                    # Try without brackets
                                    tests_match = re.search(r'tests=([A-Z_].*?)(?:\s+autolearn=|\s+$|$)', spam_status_clean)

                                if tests_match:
                                    tests_str = tests_match.group(1)
                                    if self.web_ui.debug:
                                        print(f"DEBUG: tests string = {tests_str[:200]}...", file=sys.stderr)

                                    # Split by comma, but be careful with nested structures
                                    # Match patterns like: TEST_NAME=score or TEST_NAME=-score
                                    test_items = re.findall(r'([A-Z_][A-Z0-9_.]*)=([-\d.]+)', tests_str)

                                    if self.web_ui.debug:
                                        print(f"DEBUG: Found {len(test_items)} test items", file=sys.stderr)

                                    for test_name, test_score in test_items:
                                        try:
                                            spam_tests.append({
                                                'name': test_name,
                                                'score': test_score,
                                                'score_float': float(test_score)
                                            })
                                        except ValueError:
                                            if self.web_ui.debug:
                                                print(f"DEBUG: Could not parse score for {test_name}={test_score}", file=sys.stderr)

                                    # Sort by score descending (highest/most positive first)
                                    spam_tests.sort(key=lambda x: x['score_float'], reverse=True)

                                    if self.web_ui.debug:
                                        print(f"DEBUG: Parsed {len(spam_tests)} spam tests", file=sys.stderr)
                                else:
                                    if self.web_ui.debug:
                                        print(f"DEBUG: No tests found in X-Spam-Status", file=sys.stderr)

                            # Extract email body
                            email_body_text = ''
                            email_body_html = ''

                            # Extract headers-only content and raw body content
                            raw_headers_content = ''
                            raw_body_content = ''
                            try:
                                # Find the blank line separator between headers and body
                                body_start = email_content.find('\n\n')
                                if body_start == -1:
                                    body_start = email_content.find('\r\n\r\n')
                                    if body_start != -1:
                                        # For \r\n\r\n, skip 4 chars
                                        raw_headers_content = email_content[:body_start]
                                        raw_body_content = email_content[body_start + 4:]
                                else:
                                    # For \n\n, skip 2 chars
                                    raw_headers_content = email_content[:body_start]
                                    raw_body_content = email_content[body_start + 2:]

                                if not raw_headers_content:
                                    # Fallback: use email parser to get headers
                                    headers_list = []
                                    for header_name in msg.keys():
                                        values = msg.get_all(header_name)
                                        for value in values:
                                            headers_list.append(f"{header_name}: {value}")
                                    raw_headers_content = '\n'.join(headers_list)

                                if not raw_body_content:
                                    # Fallback: use get_payload to get body
                                    raw_body_content = msg.get_payload()
                                    if isinstance(raw_body_content, list):
                                        raw_body_content = '\n'.join([str(part) for part in raw_body_content])
                                    else:
                                        raw_body_content = str(raw_body_content)
                            except Exception as e:
                                if self.web_ui.debug:
                                    print(f"Error extracting headers/body: {e}", file=sys.stderr)
                                raw_headers_content = ''
                                raw_body_content = ''

                            # Dictionary to store inline images (CID -> data URI)
                            inline_images = {}

                            if msg.is_multipart():
                                for part in msg.walk():
                                    content_type = part.get_content_type()
                                    content_disposition = str(part.get('Content-Disposition', ''))
                                    content_id = part.get('Content-ID', '')

                                    # Skip attachments (but process inline images)
                                    if 'attachment' in content_disposition and 'inline' not in content_disposition:
                                        continue

                                    # Handle inline images (Content-ID exists and is image type)
                                    if content_id and content_type.startswith('image/'):
                                        try:
                                            import base64
                                            # Get image data
                                            image_data = part.get_payload(decode=True)
                                            if image_data:
                                                # Convert to base64 data URI
                                                b64_data = base64.b64encode(image_data).decode('ascii')
                                                data_uri = f"data:{content_type};base64,{b64_data}"

                                                # Extract CID (remove < > brackets if present)
                                                cid = content_id.strip('<>')
                                                inline_images[cid] = data_uri

                                                if self.web_ui.debug:
                                                    print(f"Found inline image: CID={cid}, type={content_type}, size={len(image_data)} bytes", file=sys.stderr)
                                        except Exception as e:
                                            if self.web_ui.debug:
                                                print(f"Error processing inline image {content_id}: {e}", file=sys.stderr)

                                    if content_type == 'text/plain' and not email_body_text:
                                        try:
                                            # Get charset from part, default to utf-8
                                            charset = part.get_content_charset() or 'utf-8'
                                            payload = part.get_payload(decode=True)
                                            if payload:
                                                email_body_text = payload.decode(charset, errors='replace')
                                        except Exception as e:
                                            if self.web_ui.debug:
                                                print(f"Error decoding text/plain: {e}", file=sys.stderr)
                                            email_body_text = str(part.get_payload())

                                    elif content_type == 'text/html' and not email_body_html:
                                        try:
                                            # Get charset from part, default to utf-8
                                            charset = part.get_content_charset() or 'utf-8'
                                            payload = part.get_payload(decode=True)
                                            if payload:
                                                email_body_html = payload.decode(charset, errors='replace')
                                        except Exception as e:
                                            if self.web_ui.debug:
                                                print(f"Error decoding text/html: {e}", file=sys.stderr)
                                            email_body_html = str(part.get_payload())

                                # Replace CID references in HTML with data URIs
                                if email_body_html and inline_images:
                                    for cid, data_uri in inline_images.items():
                                        # Replace cid: references
                                        email_body_html = email_body_html.replace(f'cid:{cid}', data_uri)
                                        if self.web_ui.debug:
                                            print(f"Replaced cid:{cid} in HTML", file=sys.stderr)
                            else:
                                # Not multipart - single body
                                try:
                                    # Get charset from message, default to utf-8
                                    charset = msg.get_content_charset() or 'utf-8'
                                    payload = msg.get_payload(decode=True)
                                    if payload:
                                        email_body_text = payload.decode(charset, errors='replace')
                                    else:
                                        email_body_text = str(msg.get_payload())
                                except Exception as e:
                                    if self.web_ui.debug:
                                        print(f"Error decoding single part: {e}", file=sys.stderr)
                                    email_body_text = str(msg.get_payload())

                        except Exception as e:
                            if self.web_ui.debug:
                                print(f"Error parsing email: {e}", file=sys.stderr)
                            # Fallback to showing raw content
                            email_from = ''
                            email_to = ''
                            email_cc = ''
                            email_subject = ''
                            email_date = ''
                            auth_results = ''
                            dkim_result = ''
                            dmarc_result = ''
                            spf_result = ''
                            spam_score = ''
                            spam_score_float = 0.0
                            spam_status = ''
                            spam_tests = []
                            mail_route = []
                            email_body_text = ''
                            email_body_html = ''
                            raw_headers_content = ''
                            raw_body_content = ''

                        # Calculate CSS classes for security items
                        dkim_css_class = 'security-neutral'
                        if dkim_result:
                            if 'pass' in dkim_result.lower():
                                dkim_css_class = 'security-pass'
                            elif 'fail' in dkim_result.lower():
                                dkim_css_class = 'security-fail'

                        spf_css_class = 'security-neutral'
                        if spf_result:
                            if 'pass' in spf_result.lower():
                                spf_css_class = 'security-pass'
                            elif 'fail' in spf_result.lower():
                                spf_css_class = 'security-fail'

                        dmarc_css_class = 'security-neutral'
                        if dmarc_result:
                            if 'pass' in dmarc_result.lower():
                                dmarc_css_class = 'security-pass'
                            elif 'fail' in dmarc_result.lower():
                                dmarc_css_class = 'security-fail'

                        # Calculate spam score CSS class
                        spam_score_css = 'spam-score-neutral'
                        if spam_score_float > 0:
                            spam_score_css = 'spam-score-positive'
                        elif spam_score_float < 0:
                            spam_score_css = 'spam-score-negative'

                        # Build SPAM tests table HTML
                        spam_tests_html = ''
                        if spam_tests:
                            rows_html = []
                            for test in spam_tests:
                                test_score_css = 'spam-score-neutral'
                                if test['score_float'] > 0:
                                    test_score_css = 'spam-score-positive'
                                elif test['score_float'] < 0:
                                    test_score_css = 'spam-score-negative'
                                rows_html.append(f'''<tr>
                                    <td>{html.escape(test['name'])}</td>
                                    <td class="{test_score_css}">{html.escape(test['score'])}</td>
                                </tr>''')

                            spam_tests_html = f'''<div class="collapsible-section" style="margin-top: 10px;">
                                <div class="collapsible-header" onclick="toggleCollapsible(this)" style="background: white; border: 1px solid #dee2e6;">
                                    <h4 style="margin: 0; font-size: 0.95em; color: #495057;">📊 {t('spam_tests_count', count=len(spam_tests))}</h4>
                                    <span class="collapsible-toggle collapsed">▼</span>
                                </div>
                                <div class="collapsible-content">
                                    <div class="collapsible-inner" style="padding: 0;">
                                        <table class="spam-tests-table">
                                            <thead>
                                                <tr>
                                                    <th>{t('test_name')}</th>
                                                    <th>{t('score')}</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {''.join(rows_html)}
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                            </div>'''

                        # Build security info HTML sections
                        dkim_html = ''
                        if dkim_result:
                            dkim_html = f'''<div class="security-item {dkim_css_class}">
                            <div class="security-item-label">{t('dkim')}</div>
                            <div class="security-item-value">{html.escape(dkim_result)}</div>
                        </div>'''

                        spf_html = ''
                        if spf_result:
                            spf_html = f'''<div class="security-item {spf_css_class}">
                            <div class="security-item-label">{t('spf')}</div>
                            <div class="security-item-value">{html.escape(spf_result)}</div>
                        </div>'''

                        dmarc_html = ''
                        if dmarc_result:
                            dmarc_html = f'''<div class="security-item {dmarc_css_class}">
                            <div class="security-item-label">{t('dmarc')}</div>
                            <div class="security-item-value">{html.escape(dmarc_result)}</div>
                        </div>'''

                        spam_html = ''
                        if spam_score or spam_status:
                            spam_status_summary = ''
                            spam_is_clean = False
                            if spam_status:
                                if 'tests=' in spam_status:
                                    spam_status_summary = html.escape(spam_status.split('tests=')[0].strip())
                                else:
                                    spam_status_summary = html.escape(spam_status)
                                # Check if spam status starts with "No" (clean email)
                                spam_is_clean = spam_status.strip().lower().startswith('no')

                            # Use green border for clean emails, yellow for others
                            spam_border_css = 'security-pass' if spam_is_clean else 'security-neutral'

                            # Build score display with required threshold
                            spam_score_display = html.escape(spam_score) if spam_score else '0'
                            if spam_required:
                                spam_score_display += f'/{html.escape(spam_required)}'

                            spam_html = f'''<div class="security-item {spam_border_css}">
                            <div style="display: flex; align-items: center; gap: 15px;">
                                <div style="flex: 1;">
                                    <div class="security-item-label" style="margin-bottom: 5px;">{t('spam_check')}</div>
                                    <div style="font-size: 0.85em; color: #6c757d; line-height: 1.4;">{spam_status_summary}</div>
                                </div>
                                <div style="white-space: nowrap; flex-shrink: 0;">
                                    <strong>{t('total_score')}:</strong>
                                    <span class="spam-summary-score {spam_score_css}">{spam_score_display}</span>
                                </div>
                            </div>
                            {spam_tests_html}
                        </div>'''

                        security_info_html = ''
                        if dkim_result or spf_result or dmarc_result or spam_score or spam_status:
                            security_info_html = f'''<div class="security-info">
                        <h3 style="margin-top: 0; color: #2196F3;">🔒 {t('security_checks')}</h3>
                        {dkim_html}
                        {spf_html}
                        {dmarc_html}
                        {spam_html}
                    </div>'''

                        # Build mail routing HTML
                        mail_route_html = ''
                        if mail_route:
                            route_hops_html = []
                            for hop in mail_route:
                                # Clean display names
                                from_display = html.escape(hop['from'])
                                by_display = html.escape(hop['by'])
                                program_display = html.escape(hop['program']) if hop.get('program') else ''
                                with_display = html.escape(hop['with']) if hop['with'] else ''
                                for_display = html.escape(hop['for']) if hop['for'] else ''
                                date_display = html.escape(hop['date']) if hop['date'] else ''

                                # Combine 'by' and 'program' for display
                                by_full_display = f"{by_display} {program_display}" if program_display else by_display

                                hop_html = f'''<div class="route-hop">
                                <div class="route-hop-number">{hop['hop']}</div>
                                <div class="route-hop-content">
                                    <div class="route-hop-main">
                                        <div class="route-hop-from">
                                            <span class="route-label">{t('from_server')}:</span> {from_display}
                                        </div>
                                        <div class="route-arrow">→</div>
                                        <div class="route-hop-by">
                                            <span class="route-label">{t('to_server')}:</span> {by_full_display}
                                        </div>
                                    </div>
                                    <div class="route-hop-details">
                                        {f'<span class="route-detail"><strong>{t("protocol")}:</strong> {with_display}</span>' if with_display else ''}
                                        {f'<span class="route-detail"><strong>{t("recipient_for")}:</strong> {for_display}</span>' if for_display else ''}
                                        {f'<span class="route-detail"><strong>{t("timestamp")}:</strong> {date_display}</span>' if date_display else ''}
                                    </div>
                                </div>
                            </div>'''
                                route_hops_html.append(hop_html)

                            mail_route_html = f'''<div class="mail-route-info">
                            <div class="collapsible-section">
                                <div class="collapsible-header" onclick="toggleCollapsible(this)">
                                    <h3 style="margin: 0; color: #ff6b6b;">📮 {t('email_routing')} ({t('hops_count', count=len(mail_route))})</h3>
                                    <span class="collapsible-toggle collapsed">▼</span>
                                </div>
                                <div class="collapsible-content">
                                    <div class="collapsible-inner">
                                        <div class="route-timeline">
                                            {''.join(route_hops_html)}
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>'''

                        html_lang = 'zh-TW' if lang == 'zh_TW' else 'en'
                        html_content = f"""
<!DOCTYPE html>
<html lang="{html_lang}">
<head>
    <meta charset="UTF-8">
    <title>{t('email_content')} - {html.escape(message_id)}</title>
    <style>
        body {{
            font-family: 'Segoe UI', sans-serif;
            padding: 20px;
            background: #f5f5f5;
            margin: 0;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .header-title {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 2px solid #e0e0e0;
        }}
        h1 {{
            color: #333;
            font-size: 1.5em;
            margin: 0;
        }}
        .toolbar {{
            display: flex;
            gap: 10px;
        }}
        .btn-toggle {{
            padding: 8px 16px;
            font-size: 0.85em;
            font-weight: 600;
            border: 2px solid #667eea;
            background: white;
            color: #667eea;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.3s;
        }}
        .btn-toggle.active {{
            background: #667eea;
            color: white;
        }}
        .btn-toggle:hover {{
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.3);
        }}
        .btn-download {{
            padding: 10px 20px;
            font-size: 0.9em;
            font-weight: 600;
            border: none;
            background: linear-gradient(135deg, #f57c00 0%, #e65100 100%);
            color: white;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.3s;
            text-decoration: none;
            display: inline-block;
        }}
        .btn-download:hover {{
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(245, 124, 0, 0.4);
        }}
        /* Loading overlay */
        .loading-overlay {{
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.7);
            z-index: 9999;
            justify-content: center;
            align-items: center;
        }}
        .loading-overlay.active {{
            display: flex;
        }}
        .loading-content {{
            background: white;
            padding: 40px 60px;
            border-radius: 15px;
            text-align: center;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
        }}
        .loading-spinner {{
            border: 6px solid #f3f3f3;
            border-top: 6px solid #f57c00;
            border-radius: 50%;
            width: 60px;
            height: 60px;
            animation: spin-download 1s linear infinite;
            margin: 0 auto 20px;
        }}
        @keyframes spin-download {{
            0% {{ transform: rotate(0deg); }}
            100% {{ transform: rotate(360deg); }}
        }}
        .loading-text {{
            font-size: 1.2em;
            color: #333;
            margin-bottom: 10px;
        }}
        .loading-subtext {{
            font-size: 0.9em;
            color: #666;
        }}
        .header-info {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            border: 1px solid #e0e0e0;
            margin-bottom: 20px;
        }}
        .header-row {{
            display: grid;
            grid-template-columns: 120px 1fr;
            gap: 10px;
            padding: 8px 0;
            border-bottom: 1px solid #e0e0e0;
        }}
        .header-row:last-child {{
            border-bottom: none;
        }}
        .header-label {{
            font-weight: 600;
            color: #555;
        }}
        .header-value {{
            color: #333;
            word-break: break-all;
        }}
        .security-info {{
            background: #e8f4f8;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #2196F3;
            margin-bottom: 20px;
        }}
        .security-row {{
            display: grid;
            grid-template-columns: 150px 1fr;
            gap: 10px;
            padding: 8px 0;
            border-bottom: 1px solid rgba(33, 150, 243, 0.1);
        }}
        .security-row:last-child {{
            border-bottom: none;
        }}
        .security-label {{
            font-weight: 600;
            color: #1976D2;
        }}
        .security-value {{
            color: #333;
            word-break: break-word;
        }}
        .view-section {{
            display: none;
        }}
        .view-section.active {{
            display: block;
        }}
        .email-body {{
            background: white;
            padding: 20px;
            border: 1px solid #e0e0e0;
            border-radius: 5px;
            min-height: 300px;
            line-height: 1.6;
        }}
        .email-body iframe {{
            width: 100%;
            min-height: 500px;
            border: none;
        }}
        pre {{
            background: #f8f8f8;
            padding: 15px;
            border-radius: 5px;
            border: 1px solid #ddd;
            overflow-x: auto;
            overflow-y: auto;
            max-height: 1200px;
            white-space: pre-wrap;
            word-wrap: break-word;
            line-height: 1.5;
            font-size: 0.85em;
            font-family: 'Courier New', monospace;
        }}
        .back-link {{
            display: inline-block;
            margin-top: 20px;
            padding: 10px 20px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            transition: all 0.3s;
        }}
        .back-link:hover {{
            background: #5568d3;
            transform: translateY(-1px);
        }}
        .badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 0.85em;
            font-weight: 600;
        }}
        .badge-pass {{
            background: #d4edda;
            color: #155724;
        }}
        .badge-fail {{
            background: #f8d7da;
            color: #721c24;
        }}
        .badge-neutral {{
            background: #e2e3e5;
            color: #383d41;
        }}
        .collapsible-section {{
            margin-bottom: 20px;
        }}
        .collapsible-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px 15px;
            background: #f8f9fa;
            border: 1px solid #e0e0e0;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.3s;
            user-select: none;
        }}
        .collapsible-header:hover {{
            background: #e9ecef;
        }}
        .collapsible-header h3 {{
            margin: 0;
            font-size: 1.1em;
        }}
        .collapsible-toggle {{
            font-size: 1.2em;
            color: #667eea;
            transition: transform 0.3s;
        }}
        .collapsible-toggle.collapsed {{
            transform: rotate(-90deg);
        }}
        .collapsible-content {{
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease-out;
        }}
        .collapsible-content.expanded {{
            max-height: none;
            overflow: visible;
        }}
        .collapsible-inner {{
            padding: 15px;
            border: 1px solid #e0e0e0;
            border-top: none;
            border-radius: 0 0 5px 5px;
            background: white;
        }}
        .spam-tests-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
            font-size: 0.9em;
        }}
        .spam-tests-table th {{
            background: #f8f9fa;
            padding: 8px 12px;
            text-align: left;
            font-weight: 600;
            border-bottom: 2px solid #dee2e6;
        }}
        .spam-tests-table th:nth-child(2) {{
            text-align: right;
            width: 80px;
        }}
        .spam-tests-table td {{
            padding: 6px 12px;
            border-bottom: 1px solid #e9ecef;
        }}
        .spam-tests-table td:nth-child(2) {{
            text-align: right;
            font-family: 'Courier New', monospace;
            font-weight: 600;
        }}
        .spam-tests-table tr:hover {{
            background: #f8f9fa;
        }}
        .spam-score-positive {{
            color: #dc3545;
        }}
        .spam-score-negative {{
            color: #28a745;
        }}
        .spam-score-neutral {{
            color: #6c757d;
        }}
        .spam-summary {{
            padding: 8px 12px;
            background: #f8f9fa;
            border-radius: 5px;
            margin-bottom: 10px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 15px;
            flex-wrap: nowrap;
        }}
        .spam-summary > div {{
            flex-shrink: 0;
        }}
        .spam-summary-score {{
            font-size: 1.1em;
            font-weight: 700;
        }}
        .security-item {{
            padding: 10px 15px;
            background: #f8f9fa;
            border-left: 4px solid #2196F3;
            margin-bottom: 10px;
            border-radius: 3px;
        }}
        .security-item-label {{
            font-weight: 600;
            color: #495057;
            margin-bottom: 5px;
        }}
        .security-item-value {{
            color: #212529;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }}
        .security-pass {{
            border-left-color: #28a745;
        }}
        .security-fail {{
            border-left-color: #dc3545;
        }}
        .security-neutral {{
            border-left-color: #ffc107;
        }}
        .mail-route-info {{
            margin-bottom: 20px;
        }}
        .route-timeline {{
            position: relative;
            padding-left: 20px;
        }}
        .route-hop {{
            display: flex;
            gap: 15px;
            margin-bottom: 20px;
            position: relative;
        }}
        .route-hop:not(:last-child)::after {{
            content: '';
            position: absolute;
            left: 19px;
            top: 45px;
            bottom: -20px;
            width: 2px;
            background: linear-gradient(180deg, #667eea 0%, #e0e0e0 100%);
        }}
        .route-hop-number {{
            flex-shrink: 0;
            width: 38px;
            height: 38px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 0.95em;
            box-shadow: 0 2px 8px rgba(102, 126, 234, 0.3);
            z-index: 1;
            position: relative;
        }}
        .route-hop-content {{
            flex: 1;
            background: #f8f9fa;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            padding: 15px;
            transition: all 0.3s;
        }}
        .route-hop-content:hover {{
            background: #fff;
            box-shadow: 0 2px 12px rgba(0,0,0,0.08);
            border-color: #667eea;
        }}
        .route-hop-main {{
            display: flex;
            align-items: center;
            gap: 15px;
            margin-bottom: 10px;
            flex-wrap: wrap;
        }}
        .route-hop-from,
        .route-hop-by {{
            font-size: 0.95em;
            color: #333;
        }}
        .route-label {{
            font-weight: 600;
            color: #667eea;
            margin-right: 5px;
        }}
        .route-arrow {{
            font-size: 1.5em;
            color: #667eea;
            font-weight: 700;
        }}
        .route-hop-details {{
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            font-size: 0.85em;
            color: #666;
            padding-top: 10px;
            border-top: 1px solid #e9ecef;
        }}
        .route-detail {{
            display: flex;
            align-items: center;
        }}
        .route-detail strong {{
            color: #495057;
            margin-right: 5px;
        }}
    </style>
</head>
<body>
    <!-- Download overlay -->
    <div class="loading-overlay" id="downloadOverlay">
        <div class="loading-content">
            <div class="loading-spinner"></div>
            <div class="loading-text">📥 {t('preparing_download')}</div>
            <div class="loading-subtext">{t('preparing_eml')}</div>
        </div>
    </div>

    <div class="container">
        <!-- Title with Download Button -->
        <div class="header-title">
            <h1>📧 {t('email_content')}</h1>
            <div class="toolbar">
                <a href="javascript:void(0);" class="btn-download" onclick="handleDownloadEmail();">💾 {t('download_button')}</a>
            </div>
        </div>

        <!-- Header Information (shown in both views) -->
        <div class="header-info">
            <h3 style="margin-top: 0; color: #667eea;">📋 {t('email_headers')}</h3>
            <div class="header-row">
                <div class="header-label">{t('message_id')}:</div>
                <div class="header-value">{html.escape(message_id)}</div>
            </div>
            <div class="header-row">
                <div class="header-label">{t('mailbox_account')}:</div>
                <div class="header-value">{html.escape(account)}</div>
            </div>
            {f'''<div class="header-row">
                <div class="header-label">{t('subject')}:</div>
                <div class="header-value">{html.escape(email_subject)}</div>
            </div>''' if email_subject else ''}
            {f'''<div class="header-row">
                <div class="header-label">{t('from')}:</div>
                <div class="header-value">{html.escape(email_from)}</div>
            </div>''' if email_from else ''}
            {f'''<div class="header-row">
                <div class="header-label">{t('to')}:</div>
                <div class="header-value">{html.escape(email_to)}</div>
            </div>''' if email_to else ''}
            {f'''<div class="header-row">
                <div class="header-label">{t('cc')}:</div>
                <div class="header-value">{html.escape(email_cc)}</div>
            </div>''' if email_cc else ''}
            {f'''<div class="header-row">
                <div class="header-label">{t('date')}:</div>
                <div class="header-value">{html.escape(email_date)}</div>
            </div>''' if email_date else ''}
        </div>

        <!-- Security Information -->
        {security_info_html}

        <!-- Mail Routing Information -->
        {mail_route_html}

        <!-- Full Headers (Collapsible, default collapsed) -->
        <div class="collapsible-section">
            <div class="collapsible-header" onclick="toggleCollapsible(this)">
                <h3 style="margin: 0; color: #667eea;">📋 {t('full_email_headers')}</h3>
                <span class="collapsible-toggle collapsed">▼</span>
            </div>
            <div class="collapsible-content">
                <div class="collapsible-inner">
                    <textarea readonly style="width: 100%; max-width: 100%; box-sizing: border-box; min-height: 400px; max-height: 800px; background: #f8f9fa; padding: 15px; border: 1px solid #e0e0e0; border-radius: 5px; font-family: 'Courier New', monospace; font-size: 0.9em; resize: vertical; white-space: pre-wrap; overflow-wrap: break-word; word-wrap: break-word; overflow-x: auto; overflow-y: auto;">{raw_headers_content}</textarea>
                </div>
            </div>
        </div>

        <!-- Email Body with toggle buttons -->
        <div class="collapsible-section">
            <div class="collapsible-header" onclick="toggleCollapsible(this)">
                <h3 style="margin: 0; color: #667eea;">📨 {t('email_body')}</h3>
                <div style="display: flex; align-items: center; gap: 10px;">
                    <button class="btn-toggle active" onclick="event.stopPropagation(); switchView('rendered')">🎨 {t('rendered_content')}</button>
                    <button class="btn-toggle" onclick="event.stopPropagation(); switchView('raw')">📄 {t('raw_content')}</button>
                    <span class="collapsible-toggle">▼</span>
                </div>
            </div>
            <div class="collapsible-content expanded">
                <div class="collapsible-inner">
                    <!-- Rendered View -->
                    <div id="rendered-view" class="view-section active">
                        <div class="email-body">
                            {'<iframe id="email-html-frame" style="width: 100%; min-height: 500px; border: 1px solid #e0e0e0; border-radius: 5px; background: white;"></iframe>' if email_body_html else f'<pre style="border: none; background: white; margin: 0; max-height: 1200px; overflow-y: auto; overflow-x: auto;">{email_body_text}</pre>' if email_body_text else '<p style="color: #999;">無法取得郵件內容</p>'}
                        </div>
                    </div>
                    <!-- Raw View -->
                    <div id="raw-view" class="view-section">
                        <textarea readonly style="width: 100%; box-sizing: border-box; min-height: 600px; max-height: 1200px; background: #f8f9fa; padding: 15px; border: 1px solid #e0e0e0; border-radius: 5px; font-family: 'Courier New', monospace; font-size: 0.9em; resize: vertical; white-space: pre-wrap; overflow-wrap: break-word; word-wrap: break-word; overflow-x: auto; overflow-y: auto;">{raw_body_content}</textarea>
                    </div>
                </div>
            </div>
        </div>

        <a href="javascript:window.close()" class="back-link">✕ {t('close_window')}</a>
    </div>

    <script>
        // Wait for DOM to be ready, then render HTML email in iframe
        document.addEventListener('DOMContentLoaded', function() {{
            const iframe = document.getElementById('email-html-frame');
            if (iframe) {{
                const htmlContent = {repr(email_body_html) if email_body_html else 'null'};
                if (htmlContent) {{
                    // Wait for iframe to be ready
                    setTimeout(function() {{
                        try {{
                            const iframeDoc = iframe.contentDocument || iframe.contentWindow.document;
                            iframeDoc.open();
                            // Ensure UTF-8 charset is set (content was decoded to UTF-8 string)
                            iframeDoc.write('<meta charset="UTF-8">');
                            iframeDoc.write(htmlContent);
                            iframeDoc.close();

                            // Adjust iframe height to content after rendering
                            setTimeout(function() {{
                                try {{
                                    const iframeBody = iframe.contentDocument.body;
                                    const iframeHtml = iframe.contentDocument.documentElement;
                                    const height = Math.max(
                                        iframeBody ? iframeBody.scrollHeight : 0,
                                        iframeHtml ? iframeHtml.scrollHeight : 0,
                                        500
                                    );
                                    iframe.style.height = height + 'px';
                                }} catch(e) {{
                                    console.error('Error adjusting iframe height:', e);
                                }}
                            }}, 100);
                        }} catch(e) {{
                            console.error('Error writing to iframe:', e);
                        }}
                    }}, 100);
                }}
            }}
        }});

        function switchView(view) {{
            // Update buttons
            const buttons = document.querySelectorAll('.btn-toggle');
            buttons.forEach(btn => btn.classList.remove('active'));

            // Update views
            if (view === 'rendered') {{
                document.getElementById('rendered-view').classList.add('active');
                document.getElementById('raw-view').classList.remove('active');
                buttons[0].classList.add('active');
            }} else {{
                document.getElementById('rendered-view').classList.remove('active');
                document.getElementById('raw-view').classList.add('active');
                buttons[1].classList.add('active');
            }}
        }}

        function toggleCollapsible(header) {{
            const content = header.nextElementSibling;
            const toggle = header.querySelector('.collapsible-toggle');

            if (content.classList.contains('expanded')) {{
                // Collapse
                content.classList.remove('expanded');
                toggle.classList.add('collapsed');
            }} else {{
                // Expand
                content.classList.add('expanded');
                toggle.classList.remove('collapsed');
            }}
        }}

        function handleDownloadEmail() {{
            // Get current URL parameters
            const urlParams = new URLSearchParams(window.location.search);

            // Add download=1 parameter
            urlParams.set('download', '1');

            // Build download URL
            const downloadUrl = '/view_email?' + urlParams.toString();

            // Show loading overlay
            document.getElementById('downloadOverlay').classList.add('active');

            // Clear any existing cookie
            document.cookie = 'downloadComplete=; Path=/; Max-Age=0';

            // Create hidden iframe to trigger download
            const iframe = document.createElement('iframe');
            iframe.style.display = 'none';
            iframe.src = downloadUrl;
            document.body.appendChild(iframe);

            // Check for download completion cookie
            let attempts = 0;
            const maxAttempts = 60; // 30 seconds max (500ms interval)

            const checkDownload = setInterval(function() {{
                attempts++;

                // Check if downloadComplete cookie is set
                if (document.cookie.indexOf('downloadComplete=true') !== -1) {{
                    // Download complete, hide overlay
                    document.getElementById('downloadOverlay').classList.remove('active');
                    clearInterval(checkDownload);

                    // Clean up
                    setTimeout(function() {{
                        if (iframe.parentNode) {{
                            iframe.parentNode.removeChild(iframe);
                        }}
                    }}, 1000);
                }} else if (attempts >= maxAttempts) {{
                    // Timeout, hide overlay anyway
                    document.getElementById('downloadOverlay').classList.remove('active');
                    clearInterval(checkDownload);
                    alert('下載可能失敗，請重試');

                    // Clean up
                    if (iframe.parentNode) {{
                        iframe.parentNode.removeChild(iframe);
                    }}
                }}
            }}, 500);
        }}
    </script>
</body>
</html>
"""
                        self.send_header('Content-type', 'text/html; charset=utf-8')
                        self.end_headers()
                        self.wfile.write(html_content.encode('utf-8'))
                        return  # Success, exit
                else:
                    last_error = f"帳號 {account}: 無法讀取郵件內容"
                    if self.web_ui.debug:
                        print(f"GetMsg failed: {get_result.stderr}", file=sys.stderr)
                    continue

            except subprocess.TimeoutExpired:
                last_error = f"帳號 {account}: 請求逾時"
                continue
            except Exception as e:
                if self.web_ui.debug:
                    print(f"Error with account {account}: {e}", file=sys.stderr)
                last_error = f"帳號 {account}: 發生錯誤"
                continue

        # If we got here, all accounts failed
        error_details = []

        if tried_accounts:
            tried_list = '<br>'.join([f'• {acc}' for acc in tried_accounts])
            error_details.append(f'<strong>{t("checked_internal_mailboxes")}</strong><br>{tried_list}')

        if skipped_accounts:
            skipped_list = '<br>'.join([f'• {acc} ({t("external_mailbox_skipped")})' for acc in skipped_accounts])
            error_details.append(f'<strong>{t("skipped_external_mailboxes")}</strong><br>{skipped_list}')

        error_msg = '<br><br>'.join(error_details)

        if last_error:
            error_msg += f'<br><br><strong>{t("last_error")}</strong>: {html.escape(last_error)}'

        error_msg += f'''<br><br><strong>{t("possible_reasons")}</strong>:<br>
            • {t("email_may_be_deleted")}<br>
            • {t("outbound_check_sender")}<br>
            • {t("inbound_check_recipient")}<br>
            • {t("forward_no_local_copy")}<br>
            • {t("insufficient_permissions")}'''

        self._send_error_html(t('email_not_found'), error_msg, lang=lang)

    def handle_view_headers(self, query: dict):
        """Handle view email headers request"""
        import subprocess
        import re

        # Get current language
        lang = self.get_language()
        t = lambda key, **kwargs: get_translation(lang, key, **kwargs)

        # Extract and validate parameters
        message_id = query.get('id', [''])[0]
        accounts_str = query.get('accounts', [''])[0]

        # Validate message_id format (RFC 822 Message-ID)
        # Allow common characters in Message-ID: letters, numbers, @ . _ - + ~ ! = ? # $ % & * /
        if not message_id or not re.match(r'^[a-zA-Z0-9@._+~!=?#$%&*/-]+$', message_id) or len(message_id) > 200:
            self._send_error_html(t('invalid_msgid_format'), t('msgid_format_incorrect'), lang=lang)
            return

        # Parse and validate account list
        if not accounts_str:
            self._send_error_html(t('missing_recipients'), t('cannot_determine_mailbox'), lang=lang)
            return

        accounts = [a.strip() for a in accounts_str.split(',') if a.strip()]
        valid_accounts = []
        for account in accounts:
            if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', account) and len(account) <= 200:
                valid_accounts.append(account)

        if not valid_accounts:
            self._send_error_html(t('invalid_email_format'), t('all_recipients_invalid'), lang=lang)
            return

        # Pre-filter accounts: check which ones exist in Zimbra
        existing_accounts = []
        skipped_accounts = []

        if self.web_ui.debug:
            debug_print(f"Checking {len(valid_accounts)} accounts...")

        for account in valid_accounts:
            if self._check_account_exists(account):
                existing_accounts.append(account)
                if self.web_ui.debug:
                    debug_print(f"✓ {account} exists")
            else:
                skipped_accounts.append(account)
                if self.web_ui.debug:
                    debug_print(f"✗ {account} does not exist (external)")

        if not existing_accounts:
            # All accounts are external
            skipped_list = '<br>'.join([f'• {acc} ({t("external_mailbox")})' for acc in skipped_accounts])
            self._send_error_html(
                t('no_internal_accounts'),
                f'{t("accounts_not_in_zimbra")}<br><br>{skipped_list}<br><br>'
                f'<strong>{t("explanation")}</strong>: {t("internal_accounts_only")}<br>'
                f'{t("if_outbound_check_sender")}',
                lang=lang
            )
            return

        # Try each existing account until we find the email
        last_error = None
        tried_accounts = []

        for account in existing_accounts:
            tried_accounts.append(account)
            try:
                # Search for the email using zmsoap SearchRequest
                # Use correct syntax: field[Message-ID]:"<message-id>"
                search_query = f'field[Message-ID]:"<{message_id}>"'

                search_cmd = [
                    'sudo', '-u', 'zimbra',
                    '/opt/zimbra/bin/zmsoap', '-z', '-m', account, '-t', 'mail',
                    'SearchRequest',
                    f'@types=message',
                    f'@query={search_query}'
                ]

                if self.web_ui.debug:
                    debug_print(f"Trying account: {account}")
                    debug_print(f"Running: {' '.join(search_cmd)}")

                search_result = subprocess.run(search_cmd, capture_output=True, text=True, timeout=30)

                if search_result.returncode != 0:
                    last_error = t('account_x_search_failed', account=account)
                    if self.web_ui.debug:
                        print(f"Search failed: {search_result.stderr}", file=sys.stderr)
                    continue

                # Parse search result to get the internal message ID
                # zmsoap returns XML like: <m rev="..." id="12345" .../>
                # id attribute may not be the first attribute
                match = re.search(r'<m[^>]*\sid="(\d+)"', search_result.stdout)
                if not match:
                    last_error = t('account_x_email_not_found', account=account)
                    if self.web_ui.debug:
                        print(f"Message not found in {account}", file=sys.stderr)
                    continue

                internal_id = match.group(1)

                # Get the email headers using zmsoap GetMsgRequest
                # Correct syntax: GetMsgRequest m (not /m) with attributes
                # Try to force inline content with useContentUrl=0
                get_cmd = [
                    'sudo', '-u', 'zimbra',
                    '/opt/zimbra/bin/zmsoap', '-z', '-m', account, '-t', 'mail',
                    'GetMsgRequest', 'm',
                    f'@id={internal_id}',
                    '@raw=1',
                    '@useContentUrl=0'
                ]

                if self.web_ui.debug:
                    print(f"Getting headers from account: {account}, ID: {internal_id}", file=sys.stderr)
                    print(f"Running: {' '.join(get_cmd)}", file=sys.stderr)

                get_result = subprocess.run(get_cmd, capture_output=True, text=True, timeout=30)

                if get_result.returncode == 0:
                    if self.web_ui.debug:
                        print(f"GetMsg stdout length: {len(get_result.stdout)} chars", file=sys.stderr)
                        print(f"GetMsg stdout (first 500 chars): {get_result.stdout[:500]}", file=sys.stderr)

                    # Check if content is returned as URL (need to fetch via URL)
                    email_content = None
                    url_match = re.search(r'<content\s+url="([^"]+)"\s*/>', get_result.stdout)
                    if url_match:
                        # Content is a URL, need to fetch it with authentication
                        content_url = url_match.group(1)
                        if self.web_ui.debug:
                            print(f"zmsoap returned URL, fetching content from: {content_url}", file=sys.stderr)

                        # Get admin token
                        admin_token = self.web_ui.get_admin_token()
                        if not admin_token:
                            last_error = t('account_x_no_admin_auth', account=account)
                            if self.web_ui.debug:
                                debug_print(f"Failed to get admin token")
                            continue

                        # Get delegate token for the account
                        user_token = self.web_ui.get_delegate_token(admin_token, account)
                        if not user_token:
                            last_error = t('account_x_no_delegate_auth', account=account)
                            if self.web_ui.debug:
                                debug_print(f"Failed to get delegate token for {account}")
                            continue

                        # Get Zimbra public service config
                        self.web_ui.get_zimbra_config()

                        # Add fmt=raw to get full RFC822 content
                        download_url = content_url
                        if '?' in download_url:
                            download_url += '&fmt=raw'
                        else:
                            download_url += '?fmt=raw'

                        # Build full URL with correct hostname and port
                        full_url = f'https://{self.web_ui.zimbra_public_hostname}:{self.web_ui.zimbra_public_port}{download_url}'
                        curl_cmd = [
                            'sudo', '-u', 'zimbra',
                            'curl', '-s', '-k',
                            '-H', f'Cookie: ZM_AUTH_TOKEN={user_token}',
                            full_url
                        ]

                        if self.web_ui.debug:
                            print(f"Downloading from: {full_url}", file=sys.stderr)

                        curl_result = subprocess.run(curl_cmd, capture_output=True, text=True, timeout=30)
                        if self.web_ui.debug:
                            print(f"curl returncode: {curl_result.returncode}", file=sys.stderr)
                            print(f"curl stdout length: {len(curl_result.stdout)}", file=sys.stderr)
                            if curl_result.stderr:
                                print(f"curl stderr: {curl_result.stderr[:200]}", file=sys.stderr)

                        if curl_result.returncode == 0 and curl_result.stdout and not 'HTTP ERROR' in curl_result.stdout:
                            email_content = curl_result.stdout
                        else:
                            last_error = t('account_x_cannot_get_from_url', account=account)
                            continue
                    else:
                        # Try to extract content from XML
                        content_match = re.search(r'<content>(.*?)</content>', get_result.stdout, re.DOTALL)
                        if content_match:
                            email_content = content_match.group(1).strip()
                            # Unescape XML/HTML entities (zmsoap escapes special characters in XML)
                            email_content = html.unescape(email_content)
                        else:
                            last_error = t('account_x_cannot_parse', account=account)
                            if self.web_ui.debug:
                                print(f"Cannot parse email content from XML", file=sys.stderr)
                                print(f"XML response (full): {get_result.stdout}", file=sys.stderr)
                            continue

                    # At this point, email_content should be set
                    if not email_content:
                        last_error = t('account_x_cannot_get_content', account=account)
                        continue

                    # Extract only headers (RFC 822: headers and body separated by blank line)
                    # DETAILED DEBUG: Analyze email content structure
                    if self.web_ui.debug:
                        print(f"\n{'='*80}", file=sys.stderr)
                        print(f"DEBUG: Email content analysis for headers extraction", file=sys.stderr)
                        print(f"{'='*80}", file=sys.stderr)
                        print(f"Total length: {len(email_content)} characters", file=sys.stderr)

                        # Show first 1000 chars with visible whitespace
                        preview = email_content[:1000].replace('\r', '\\r').replace('\n', '\\n\n')
                        print(f"\nFirst 1000 chars (with visible \\r\\n):\n{preview}", file=sys.stderr)

                        # Show first 20 lines
                        lines = email_content.split('\n')[:20]
                        print(f"\nFirst 20 lines:", file=sys.stderr)
                        for i, line in enumerate(lines, 1):
                            print(f"  {i:2d}: {repr(line)[:100]}", file=sys.stderr)

                        # Search for various blank line patterns
                        nn_pos = email_content.find('\n\n')
                        rnrn_pos = email_content.find('\r\n\r\n')
                        print(f"\nBlank line search results:", file=sys.stderr)
                        print(f"  \\n\\n position: {nn_pos}", file=sys.stderr)
                        print(f"  \\r\\n\\r\\n position: {rnrn_pos}", file=sys.stderr)

                        # If found, show context around blank line
                        if nn_pos != -1:
                            context_start = max(0, nn_pos - 100)
                            context_end = min(len(email_content), nn_pos + 100)
                            context = email_content[context_start:context_end].replace('\r', '\\r').replace('\n', '\\n\n')
                            print(f"\nContext around \\n\\n (pos {nn_pos}):\n{context}", file=sys.stderr)

                    # Search for blank line separator in original content
                    headers_end = email_content.find('\n\n')

                    if headers_end == -1:
                        headers_end = email_content.find('\r\n\r\n')

                    if headers_end != -1:
                        headers = email_content[:headers_end]

                        if self.web_ui.debug:
                            print(f"\nHeaders extracted: {len(headers)} characters", file=sys.stderr)

                            # Detailed check for body content in headers
                            has_boundary = '--_' in headers
                            has_content_type = 'Content-Type: text/' in headers
                            has_transfer_encoding = 'Content-Transfer-Encoding:' in headers
                            has_base64 = 'base64' in headers.lower()

                            print(f"\nBody content indicators in headers:", file=sys.stderr)
                            print(f"  Has multipart boundary (--_): {has_boundary}", file=sys.stderr)
                            print(f"  Has 'Content-Type: text/': {has_content_type}", file=sys.stderr)
                            print(f"  Has 'Content-Transfer-Encoding:': {has_transfer_encoding}", file=sys.stderr)
                            print(f"  Has 'base64': {has_base64}", file=sys.stderr)

                            if has_boundary or has_base64:
                                print(f"⚠️  WARNING: Headers contain body parts! Extraction FAILED!", file=sys.stderr)

                            print(f"\nHeaders last 500 chars:\n{headers[-500:]}", file=sys.stderr)
                            print(f"{'='*80}\n", file=sys.stderr)
                    else:
                        # No blank line found - use email parser as fallback
                        if self.web_ui.debug:
                            print(f"No blank line found, using email parser fallback", file=sys.stderr)

                        try:
                            from email import message_from_string
                            msg_for_headers = message_from_string(email_content)

                            # Build headers manually from parsed message
                            headers_list = []
                            for header_name in msg_for_headers.keys():
                                values = msg_for_headers.get_all(header_name)
                                for value in values:
                                    headers_list.append(f"{header_name}: {value}")
                            headers = '\n'.join(headers_list)

                            if self.web_ui.debug:
                                print(f"Parser fallback: extracted {len(headers)} characters", file=sys.stderr)
                        except Exception as e:
                            if self.web_ui.debug:
                                print(f"Parser fallback failed: {e}", file=sys.stderr)
                            # Last resort: take first 3000 characters
                            headers = email_content[:3000]

                    # Return headers in HTML format with syntax highlighting
                    html_lang = 'zh-TW' if lang == 'zh_TW' else 'en'
                    html_content = f"""
<!DOCTYPE html>
<html lang="{html_lang}">
<head>
    <meta charset="UTF-8">
    <title>{t('email_headers')} - {html.escape(message_id)}</title>
    <style>
        * {{
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Courier New', monospace;
            padding: 20px;
            background: #f5f5f5;
            margin: 0;
            overflow-x: hidden;
            max-width: 100vw;
        }}
        .container {{
            max-width: 1400px;
            width: 100%;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        h1 {{
            color: #333;
            font-family: 'Segoe UI', sans-serif;
            font-size: 1.5em;
            margin-bottom: 20px;
        }}
        .info {{
            font-family: 'Segoe UI', sans-serif;
            margin-bottom: 20px;
            padding: 10px;
            background: #e8f4f8;
            border-left: 4px solid #43a047;
            border-radius: 4px;
        }}
        .info p {{
            word-break: break-all;
            margin: 5px 0;
        }}
        pre {{
            background: #f8f8f8;
            padding: 15px;
            margin: 0;
            border-radius: 5px;
            border: 1px solid #ddd;
            overflow-x: auto;
            overflow-y: auto;
            max-height: 80vh;
            width: 100%;
            max-width: 100%;
            min-width: 0;
            white-space: pre-wrap;
            word-wrap: break-word;
            word-break: break-all;
            overflow-wrap: anywhere;
            line-height: 1.5;
            font-size: 0.9em;
        }}
        .back-link {{
            display: inline-block;
            margin-top: 20px;
            padding: 10px 20px;
            background: #667eea;
            color: white;
            text-decoration: none;
            font-family: 'Segoe UI', sans-serif;
            border-radius: 5px;
            transition: all 0.3s;
        }}
        .back-link:hover {{
            background: #5568d3;
            transform: translateY(-1px);
        }}
        .header-row {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }}
        .copy-btn {{
            padding: 8px 16px;
            background: #43a047;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-family: 'Segoe UI', sans-serif;
            font-size: 0.9em;
            transition: all 0.3s;
        }}
        .copy-btn:hover {{
            background: #388e3c;
            transform: translateY(-1px);
        }}
        .copy-btn.copied {{
            background: #1976d2;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header-row">
            <h1>📋 {t('email_headers')}</h1>
            <button class="copy-btn" onclick="copyHeaders()">📋 {t('copy_to_clipboard')}</button>
        </div>
        <div class="info">
            <p><strong>{t('message_id')}:</strong> {html.escape(message_id)}</p>
            <p><strong>{t('mailbox_account')}:</strong> {html.escape(account)}</p>
        </div>
        <pre id="headers-content">{html.escape(headers)}</pre>
        <a href="javascript:window.close()" class="back-link">✕ {t('close_window')}</a>
    </div>
    <script>
        function copyHeaders() {{
            const headersText = document.getElementById('headers-content').textContent;
            const btn = document.querySelector('.copy-btn');

            navigator.clipboard.writeText(headersText).then(function() {{
                // Success feedback
                const originalText = btn.innerHTML;
                btn.innerHTML = '✓ {t("copied")}';
                btn.classList.add('copied');

                setTimeout(function() {{
                    btn.innerHTML = originalText;
                    btn.classList.remove('copied');
                }}, 2000);
            }}).catch(function(err) {{
                // Fallback for older browsers
                const textArea = document.createElement('textarea');
                textArea.value = headersText;
                textArea.style.position = 'fixed';
                textArea.style.left = '-999999px';
                document.body.appendChild(textArea);
                textArea.select();
                try {{
                    document.execCommand('copy');
                    const originalText = btn.innerHTML;
                    btn.innerHTML = '✓ 已複製';
                    btn.classList.add('copied');
                    setTimeout(function() {{
                        btn.innerHTML = originalText;
                        btn.classList.remove('copied');
                    }}, 2000);
                }} catch (err) {{
                    alert('無法複製到剪貼簿，請手動選擇並複製');
                }}
                document.body.removeChild(textArea);
            }});
        }}
    </script>
</body>
</html>
"""
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(html_content.encode('utf-8'))
                    return  # Success, exit
                else:
                    last_error = f"帳號 {account}: 無法讀取郵件標頭"
                    if self.web_ui.debug:
                        print(f"GetMsg failed: {get_result.stderr}", file=sys.stderr)
                    continue

            except subprocess.TimeoutExpired:
                last_error = f"帳號 {account}: 請求逾時"
                continue
            except Exception as e:
                if self.web_ui.debug:
                    print(f"Error with account {account}: {e}", file=sys.stderr)
                last_error = f"帳號 {account}: 發生錯誤"
                continue

        # If we got here, all accounts failed
        error_details = []

        if tried_accounts:
            tried_list = '<br>'.join([f'• {acc}' for acc in tried_accounts])
            error_details.append(f'<strong>{t("checked_internal_mailboxes")}</strong><br>{tried_list}')

        if skipped_accounts:
            skipped_list = '<br>'.join([f'• {acc} ({t("external_mailbox_skipped")})' for acc in skipped_accounts])
            error_details.append(f'<strong>{t("skipped_external_mailboxes")}</strong><br>{skipped_list}')

        error_msg = '<br><br>'.join(error_details)

        if last_error:
            error_msg += f'<br><br><strong>{t("last_error")}</strong>: {html.escape(last_error)}'

        error_msg += f'''<br><br><strong>{t("possible_reasons")}</strong>:<br>
            • {t("email_may_be_deleted")}<br>
            • {t("outbound_check_sender")}<br>
            • {t("inbound_check_recipient")}<br>
            • {t("forward_no_local_copy")}<br>
            • {t("insufficient_permissions")}'''

        self._send_error_html(t('email_not_found'), error_msg, lang=lang)

    def _send_error_html(self, title: str, message: str, lang: str = 'zh_TW'):
        """Send a friendly error page"""
        t = lambda key, **kwargs: get_translation(lang, key, **kwargs)
        html_lang = 'zh-TW' if lang == 'zh_TW' else 'en'
        html_content = f"""
<!DOCTYPE html>
<html lang="{html_lang}">
<head>
    <meta charset="UTF-8">
    <title>{html.escape(title)} - jt_zmmsgtrace</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }}
        .error-container {{
            max-width: 600px;
            background: white;
            border-radius: 15px;
            padding: 40px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            text-align: center;
        }}
        .error-icon {{
            font-size: 4em;
            margin-bottom: 20px;
        }}
        h1 {{
            color: #e74c3c;
            font-size: 1.8em;
            margin-bottom: 20px;
        }}
        .error-message {{
            color: #555;
            line-height: 1.8;
            margin-bottom: 30px;
            text-align: left;
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #e74c3c;
        }}
        .back-link {{
            display: inline-block;
            padding: 12px 30px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 600;
            transition: all 0.3s;
        }}
        .back-link:hover {{
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4);
        }}
    </style>
</head>
<body>
    <div class="error-container">
        <div class="error-icon">❌</div>
        <h1>{html.escape(title)}</h1>
        <div class="error-message">{message}</div>
        <a href="javascript:window.close()" class="back-link">✕ {t('close_window')}</a>
    </div>
</body>
</html>
"""
        self.send_response(404)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(html_content.encode('utf-8'))


def start_web_server(log_files: List[str], year: int, port: int = 8989, debug: int = 0,
                     login_attempts: int = 5, login_timeout: int = 10):
    """Start the web server"""
    web_ui = WebUI(log_files, year, debug, login_attempts, login_timeout)

    if debug:
        print(f"🔒 Login security: max {login_attempts} attempts within {login_timeout} minutes", file=sys.stderr)

    JtZmmsgtraceRequestHandler.web_ui = web_ui

    server = ThreadedHTTPServer(('0.0.0.0', port), JtZmmsgtraceRequestHandler)

    # Start background thread for cleaning expired sessions
    import threading
    import time

    def cleanup_sessions_periodically():
        """Background thread to cleanup expired sessions every 10 minutes"""
        while True:
            time.sleep(600)  # Wait 10 minutes
            try:
                count = web_ui.cleanup_expired_sessions()
                if count > 0 and debug:
                    print(f"🧹 Cleaned up {count} expired session(s)", file=sys.stderr)
            except Exception as e:
                if debug:
                    print(f"Error cleaning up sessions: {e}", file=sys.stderr)

    cleanup_thread = threading.Thread(target=cleanup_sessions_periodically, daemon=True)
    cleanup_thread.start()

    print(f"🌐 jt_zmmsgtrace Web UI started")
    print(f"📡 Server running on http://0.0.0.0:{port}/")
    print(f"🔗 Access from browser: http://localhost:{port}/ or http://<server-ip>:{port}/")
    print(f"📁 Log files ({len(log_files)}): {', '.join(log_files[:3])}")
    if len(log_files) > 3:
        print(f"    ... and {len(log_files) - 3} more files")
    print(f"🔐 Session lifetime: 12 hours (matches Zimbra auth token)")
    print(f"\n⌨️  Press Ctrl+C to stop the server\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n\n👋 Shutting down server...")
        server.shutdown()


def main():
    parser = argparse.ArgumentParser(
        description='Trace emails using postfix and amavis syslog data (Python version)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s
  %(prog)s -s phil
  %(prog)s -sender "phil.pearl" -srchost localhost -time 20110217,20110221
  %(prog)s -s "^p" -r "@usc.edu$" /var/log/zimbra*
        """
    )

    parser.add_argument('-i', '--id',
                        help='Search by Message ID (supports regex). Example: "ABC123@domain.com"')
    parser.add_argument('-s', '--sender',
                        help='Search by sender email address (supports regex). Example: "user@domain.com" or "^admin"')
    parser.add_argument('-r', '--recipient',
                        help='Search by recipient email address (supports regex). Includes deduplicated recipients!')
    parser.add_argument('-F', '--srchost',
                        help='Search by source hostname or IP address (supports regex)')
    parser.add_argument('-D', '--desthost',
                        help='Search by destination hostname or IP address (supports regex)')
    parser.add_argument('-t', '--time',
                        help='Time range filter: YYYYMM[DD[HH[MM[SS]]]],YYYYMM[DD[HH[MM[SS]]]]. '
                             'Example: 20250101,20250131 or 202501')
    parser.add_argument('--year', type=int, default=datetime.now().year,
                        help='Specify the year for log entries (default: current year). '
                             'IMPORTANT: Zimbra logs use "Jan 15 10:30:00" format without year. '
                             'Use --year 2024 when reading old log files from 2024.')
    parser.add_argument('--nosort', action='store_true',
                        help='Do not sort log files by modification time (process in command-line order)')
    parser.add_argument('--debug', action='count', default=0,
                        help='Increase debug output verbosity (can be used multiple times: --debug --debug)')
    parser.add_argument('--web', action='store_true',
                        help='Start Web UI mode for browser-based email searching (recommended!)')
    parser.add_argument('--port', type=int, default=8989,
                        help='Web UI port number (default: 8989). Use with --web option.')
    parser.add_argument('--all-logs', action='store_true',
                        help='Load all /var/log/zimbra* files including archived logs. '
                             'Default: only /var/log/zimbra.log. Works in both CLI and Web UI mode.')
    parser.add_argument('--login-attempts', type=int, default=5,
                        help='Maximum failed login attempts before Web UI shutdown (default: 5). Security feature.')
    parser.add_argument('--login-timeout', type=int, default=10,
                        help='Time window in minutes for tracking failed login attempts (default: 10)')
    parser.add_argument('-v', '--version', action='version',
                        version=f'%(prog)s {VERSION}')
    parser.add_argument('files', nargs='*', default=[DEFAULT_LOGFILE],
                        help=f'Log files to process. Supports .gz and .bz2 compressed files. '
                             f'Default: {DEFAULT_LOGFILE}. Example: /var/log/zimbra.log*')

    args = parser.parse_args()

    # Check if web mode is requested
    if args.web:
        # Determine which log files to load
        if args.all_logs:
            # Use glob to get all zimbra log files
            import glob
            log_files = glob.glob('/var/log/zimbra*')
            if not log_files:
                log_files = [DEFAULT_LOGFILE]
        elif args.files == [DEFAULT_LOGFILE]:
            # Default case: only use current zimbra.log
            log_files = [DEFAULT_LOGFILE]
        else:
            # User specified files
            log_files = args.files

        start_web_server(log_files, args.year, args.port, args.debug,
                         args.login_attempts, args.login_timeout)
        return

    # Determine which log files to load for CLI mode
    if args.all_logs:
        # Use glob to get all zimbra log files
        import glob
        files = glob.glob('/var/log/zimbra*')
        if not files:
            files = [DEFAULT_LOGFILE]
        # Sort files if needed
        if not args.nosort:
            files = sort_files_by_mtime(files)
    elif args.files == [DEFAULT_LOGFILE]:
        # Default case: only use current zimbra.log
        files = [DEFAULT_LOGFILE]
    else:
        # User specified files
        files = args.files if args.nosort else sort_files_by_mtime(args.files)

    # Parse time range
    if args.time:
        parts = args.time.split(',')
        log_parser = LogParser(args.year)
        start_time = log_parser.time_to_number(parts[0].strip()) if len(parts) > 0 and parts[0].strip() else None
        end_time = log_parser.time_to_number(parts[1].strip(), max_values=True) if len(parts) > 1 and parts[1].strip() else None
        args.time = (start_time, end_time)
    else:
        args.time = None

    # Display search criteria
    print("Tracing messages")
    if args.id:
        print(f"\tID {args.id}")
    if args.sender:
        print(f"\tfrom {args.sender}")
    if args.recipient:
        print(f"\tto {args.recipient}")
    if args.srchost:
        print(f"\treceived from host {args.srchost}")
    if args.desthost:
        print(f"\tdelivered to host {args.desthost}")
    if args.time:
        print(f"\tduring window (start,end) {args.time[0] or 'any'},{args.time[1] or 'any'}")
    print()

    if args.debug:
        print(f"Processing {len(files)} file(s)...", file=sys.stderr)

    # Parse all log files
    log_parser = LogParser(args.year, args.debug)
    for filepath in files:
        log_parser.parse_file(filepath)

    # Integrate Amavis data (KEY STEP!)
    log_parser.integrate_amavis_data()

    if args.debug:
        total_msgs = sum(len(queues) for queues in log_parser.messages.values())
        print(f"Total messages parsed: {len(log_parser.messages)} unique message-ids, {total_msgs} queue stages", file=sys.stderr)

    # Filter and display messages
    msg_filter = MessageFilter(args)
    formatter = OutputFormatter(log_parser, log_parser.amavis_records, log_parser.qid_to_msg)

    recipient_pattern = re.compile(args.recipient, re.IGNORECASE) if args.recipient else None

    displayed = 0
    # Iterate through message_id -> queue_dict
    for msg_id, queue_dict in log_parser.messages.items():
        if not queue_dict:
            continue

        # Find the root queue (not referenced by any other queue's next_queue_id)
        all_qids = set(queue_dict.keys())
        referenced_qids = set()
        for msg in queue_dict.values():
            for recip in msg.recipients.values():
                if recip.next_queue_id:
                    referenced_qids.add(recip.next_queue_id)

        # Root queues are those not referenced by others
        root_qids = all_qids - referenced_qids

        # Use the first root queue (or first queue if no root found)
        if root_qids:
            first_qid = sorted(root_qids)[0]  # Use first root in alphabetical order
        else:
            first_qid = sorted(queue_dict.keys())[0]

        first_msg = queue_dict[first_qid]

        # Skip messages without recipients (e.g., NOQUEUE without actual delivery)
        if not first_msg.recipients:
            continue

        if msg_filter.matches(first_msg):
            # Display using the root queue as entry point
            formatter.display_message(first_msg, recipient_pattern)
            displayed += 1

    if args.debug:
        print(f"Displayed {displayed} message(s)", file=sys.stderr)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if '--debug' in sys.argv:
            raise
        sys.exit(1)
