# Changelog

All notable changes to MCP HTTP Proxy will be documented in this file.

## [1.0.1] - 2026-02-09

### Changed

- 將 `Claude_Desktop_MCP_Network_Fix.md` 的根因分析內容整併至 `README.md`
- 移除文件中的真實內網 IP，改用通用範例
- 刪除 `Claude_Desktop_MCP_Network_Fix.md`（內容已整併，不再需要）

## [1.0.0] - 2026-01-13

### Added

- 初始版本發布
- `mcp_proxy.py`：基於 Python asyncio 的 HTTP/HTTPS 代理程式
  - 支援 HTTPS CONNECT tunnel（雙向透明隧道）
  - 支援 HTTP 正向代理（GET/POST/PUT/DELETE/HEAD/OPTIONS）
  - 自動過濾 `Proxy-` 開頭的 header
  - 連線逾時 30 秒保護
  - Port 佔用偵測（macOS errno 48 / Linux errno 98）
  - 預設監聽 `127.0.0.1:28080`，可透過命令列參數自訂
- `start_proxy.command`：macOS 雙擊啟動腳本，自動清除舊程序後啟動
- `README.md`：操作手冊（快速設置、開機自啟、管理命令、故障排除）
- `Claude_Desktop_MCP_Network_Fix.md`：完整問題分析文件（診斷過程、根因分析、解決方案）
