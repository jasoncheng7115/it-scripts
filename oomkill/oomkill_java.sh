#!/usr/bin/env bash
# oomkill_java.sh
# 讓指定 Java 程式在受限記憶體下被 OOM Killer 優先殺死
# author: Jason Tools (2025-07)

set -euo pipefail

############################
# 參數預設
############################
TARGET_NAME=""
TARGET_PID=""
MEM_LIMIT_MB=512
TIMEOUT_SEC=30
USE_STRESS=true
STRESS_IN_CG=false
CGROUP_NAME="oom_java_cg"
UNIT_NAME="oom-java-scope"

############################
# 參數解析
############################
show_help() {
cat << EOF
用法: sudo $0 [選項]

必要 (二擇一):
  -n, --name <string>    Java 程式名稱 (jar/主類名關鍵詞)
  -p, --pid  <pid>       已知的 Java PID

可選:
  -m, --mem <MB>         記憶體上限 (預設 512)
  -t, --timeout <sec>    觀察 OOM 的等待秒數 (預設 30)
      --no-stress        不產生額外壓力程式
      --stress-in-cgroup 壓力程式與 Java 放在同一 cgroup
  -h, --help             顯示說明並退出
EOF
}

ARGS=$(getopt -o n:p:m:t:h --long name:,pid:,mem:,timeout:,no-stress,stress-in-cgroup,help -n "$0" -- "$@")
eval set -- "$ARGS"

while true; do
  case "$1" in
    -n|--name)    TARGET_NAME="$2"; shift 2;;
    -p|--pid)     TARGET_PID="$2"; shift 2;;
    -m|--mem)     MEM_LIMIT_MB="$2"; shift 2;;
    -t|--timeout) TIMEOUT_SEC="$2"; shift 2;;
    --no-stress)  USE_STRESS=false; shift;;
    --stress-in-cgroup) STRESS_IN_CG=true; shift;;
    -h|--help)    show_help; exit 0;;
    --) shift; break;;
    *) echo "未知選項 $1"; exit 1;;
  esac
done

if [[ -z "$TARGET_NAME" && -z "$TARGET_PID" ]]; then
  echo "❌ 必須指定 --name 或 --pid"; exit 1
fi

############################
# 找 PID
############################
if [[ -z "$TARGET_PID" ]]; then
  MAPFILE -t PID_LIST < <(pgrep -f "$TARGET_NAME")
  if (( ${#PID_LIST[@]} == 0 )); then
    echo "❌ 找不到 Java 程式 '$TARGET_NAME'"; exit 2
  elif (( ${#PID_LIST[@]} > 1 )); then
    echo "⚠️  找到多個符合 PID: ${PID_LIST[*]}"
    read -rp "請輸入要限制的 PID: " TARGET_PID
  else
    TARGET_PID="${PID_LIST[0]}"
  fi
fi
echo "✅ 目標 PID = $TARGET_PID"

############################
# 偵測 cgroup 版本
############################
if [[ $(stat -fc %T /sys/fs/cgroup) == "cgroup2fs" ]]; then
  CG_VER=2
else
  CG_VER=1
fi
echo "📂 使用 cgroup v$CG_VER"

MEM_LIMIT_BYTES=$((MEM_LIMIT_MB * 1024 * 1024))

############################
# 佈署限制
############################
if (( CG_VER == 1 )); then
  echo "🧱 建立 cgroup v1: $CGROUP_NAME"
  cgcreate -g memory:/"$CGROUP_NAME"

  cgset -r memory.limit_in_bytes="$MEM_LIMIT_BYTES" "$CGROUP_NAME"
  cgset -r memory.memsw.limit_in_bytes="$MEM_LIMIT_BYTES" "$CGROUP_NAME"
  cgset -r memory.swappiness=0 "$CGROUP_NAME"

  echo "$TARGET_PID" > "/sys/fs/cgroup/memory/$CGROUP_NAME/tasks"
  echo 1000 > "/proc/$TARGET_PID/oom_score_adj"

else
  echo "🧱 建立 systemd scope: $UNIT_NAME"
  systemd-run --scope --unit="$UNIT_NAME" \
    -p MemoryMax="${MEM_LIMIT_MB}M" \
    -p MemorySwapMax=0 \
    -p OOMScoreAdjust=1000 \
    --pid="$TARGET_PID" \
    /bin/true
fi

############################
# 啟動壓力程式 (可選)
############################
STRESS_PID=""
if $USE_STRESS; then
  echo "💣 啟動壓力程式以觸發 OOM ..."
  if $STRESS_IN_CG && (( CG_VER == 1 )); then
    cgexec -g memory:/"$CGROUP_NAME" \
      python3 - <<'PY' &
a=[]; import time
while True:
    a.append("A"*1024*1024)
    time.sleep(0.01)
PY
    STRESS_PID=$!
  else
    python3 - <<'PY' &
a=[]; import time
while True:
    a.append("A"*1024*1024)
    time.sleep(0.01)
PY
    STRESS_PID=$!
  fi
fi

############################
# 觀察 OOM
############################
echo "⏳ 等待 $TIMEOUT_SEC 秒觀察 OOM ..."
END=$((SECONDS + TIMEOUT_SEC))
while (( SECONDS < END )); do
  if [[ ! -e /proc/$TARGET_PID ]]; then
    echo "🎉 Java 程式 (PID $TARGET_PID) 已不在，可能被 OOM Killer 殺死"
    break
  fi
  sleep 1
done

echo "🔍 顯示最近 OOM / killed 訊息"
journalctl -k -n 50 --no-pager | grep -iE "killed process|oom" || true

############################
# 清理
############################
echo "🧹 清理環境 ..."
[[ -n "$STRESS_PID" ]] && kill "$STRESS_PID" 2>/dev/null || true

if (( CG_VER == 1 )); then
  cgdelete -g memory:/"$CGROUP_NAME" || true
else
  systemctl stop "$UNIT_NAME".scope 2>/dev/null || true
fi

echo "✅ 完成"
