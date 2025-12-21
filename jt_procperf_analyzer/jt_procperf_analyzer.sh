#!/bin/bash

################################################################################
# JT Process Performance Analyzer for Linux
################################################################################
#
# Name:     JT Process Performance Analyzer (Linux Version)
# Version:  1.0.16
# Author:   Jason Cheng (Jason Tools)
# Date:     2025-12-21
# Purpose:  Linux Process performance monitoring and analysis tool
#
# Description:
#   This tool collects Linux process performance metrics including CPU,
#   memory, I/O, threads, file descriptors, and provides memory leak detection.
#
# Compatibility:
#   - Uses /proc filesystem, compatible with all Linux distributions
#   - Requires Bash 4.0+ (for associative arrays)
#   - Recommended to run as root for complete information
#
# Differences from Windows version:
#   - Field mapping: HandleCount -> FdCount, PriorityClass -> Nice
#   - Windows-specific fields filled with N/A: PagedMemoryMB, CompanyName, etc.
#   - Linux-specific fields: Nice, State, RssFileMB, SwapUsageMB, etc.
#
################################################################################

# Version information
readonly VERSION="1.0.16"
readonly VERSION_NOTE="Remove bc dependency - use only POSIX standard tools"
readonly VERSION_DATE="2025-12-21"
readonly AUTHOR="Jason Cheng (Jason Tools)"

# Color definitions
readonly COLOR_RESET="\033[0m"
readonly COLOR_RED="\033[31m"
readonly COLOR_GREEN="\033[32m"
readonly COLOR_YELLOW="\033[33m"
readonly COLOR_BLUE="\033[34m"
readonly COLOR_GRAY="\033[90m"

# Global variables
DURATION_MINUTES=60
INTERVAL_SECONDS=60
OUTPUT_FORMAT="CSV"
OUTPUT_PATH=""
OUTPUT_FILENAME=""
INCLUDE_PROCESSES=()
EXCLUDE_PROCESSES=()
MATCH_MODE="wildcard"
MINIMUM_CPU=0.1
MINIMUM_MEMORY_MB=0
QUIET_MODE=false
DEBUG_MODE=false
GROUP_BY_NAME=false

# Performance data storage (associative arrays)
declare -A LAST_CPU_MEASUREMENTS
declare -A LAST_IO_MEASUREMENTS
declare -A LAST_MEMORY_MEASUREMENTS

# Cache for repeated lookups
declare -A USERNAME_CACHE
BOOT_TIME=""
NUM_PROCESSORS=""

# Return values for functions (to avoid subshell issues with command substitution)
RETURN_VALUE=""
RETURN_IO_READ_KB_SEC=""
RETURN_IO_WRITE_KB_SEC=""
RETURN_IO_READ_OPS_SEC=""
RETURN_IO_WRITE_OPS_SEC=""
RETURN_MEMORY_GROWTH=""
RETURN_FD_GROWTH=""
RETURN_POSSIBLE_LEAK=""

# Statistics
TOTAL_ITERATIONS=0
CURRENT_ITERATION=0
START_TIME=""
ERROR_COUNT=0

################################################################################
# Helper Functions
################################################################################

# Fast division (avoid bc for simple calculations)
# Usage: fast_div numerator denominator decimals
fast_div() {
    local num="$1"
    local den="$2"
    local dec="${3:-2}"

    if [[ $den -eq 0 ]]; then
        echo "0"
        return
    fi

    # For integer division with decimals
    local multiplier=1
    case $dec in
        1) multiplier=10 ;;
        2) multiplier=100 ;;
        3) multiplier=1000 ;;
        *) multiplier=100 ;;
    esac

    local result=$(( (num * multiplier) / den ))
    local int_part=$((result / multiplier))
    local dec_part=$((result % multiplier))

    printf "%d.%0${dec}d" "$int_part" "$dec_part"
}

# Print colored messages
print_message() {
    local type="$1"
    local message="$2"
    local timestamp=$(date '+%H:%M:%S.%3N')

    case "$type" in
        "info")
            echo -e "${COLOR_GRAY}[$timestamp]${COLOR_RESET} ${COLOR_BLUE}[INFO]${COLOR_RESET} $message"
            ;;
        "success")
            echo -e "${COLOR_GRAY}[$timestamp]${COLOR_RESET} ${COLOR_GREEN}[OK]${COLOR_RESET} $message"
            ;;
        "warning")
            echo -e "${COLOR_GRAY}[$timestamp]${COLOR_RESET} ${COLOR_YELLOW}[WARN]${COLOR_RESET} $message"
            ;;
        "error")
            echo -e "${COLOR_GRAY}[$timestamp]${COLOR_RESET} ${COLOR_RED}[ERROR]${COLOR_RESET} $message" >&2
            ;;
        "debug")
            [[ "$DEBUG_MODE" == true ]] && echo -e "${COLOR_GRAY}[$timestamp] [DEBUG] $message${COLOR_RESET}"
            ;;
    esac
}

# Show help
show_help() {
    cat << 'EOF'
================================================================================
  JT Process Performance Analyzer (Linux) v1.0.7
  Author: Jason Cheng (Jason Tools)
================================================================================

Purpose:
  Linux process performance monitoring and analysis tool supporting CPU,
  memory, I/O, and memory leak detection

Usage:
  ./jt_procperf_analyzer.sh [options...]

Common Options:
  -d, --duration <minutes>     Monitoring duration (default: 60)
  -i, --interval <seconds>     Sampling interval (default: 60)
  -f, --format <format>        Output format: csv, json, tsv (default: csv)
  -o, --output <path>          Output directory (default: script directory)

  --include <name>             Include process (can be repeated)
  --exclude <name>             Exclude process (can be repeated)
  --match-mode <mode>          Match mode: exact, wildcard, regex (default: wildcard)

  --min-cpu <percent>          Only collect CPU > N% processes (no default, collects all)
  --min-memory <MB>            Only collect memory > N MB processes (no default, collects all)

  --group-by-name              Merge multiple instances by process name
  --quiet                      Quiet mode (no progress output)
  --debug                      Debug mode (verbose output)
  -h, --help                   Show this help

Examples:
  # Basic usage (monitor 60 minutes, sample every 60 seconds)
  ./jt_procperf_analyzer.sh

  # Monitor specific process (nginx) for 30 minutes
  ./jt_procperf_analyzer.sh -d 30 -i 10 --include nginx

  # Exclude system processes, output JSON format
  ./jt_procperf_analyzer.sh --exclude "systemd" --exclude "kworker*" -f json

  # Only monitor high CPU processes (>5%)
  ./jt_procperf_analyzer.sh --min-cpu 5 -d 120

Field Description:
  Common fields (compatible with Windows version):
    CPU: CPUPercent, CPUTimeTotalSec, UserTimeSec, PrivilegedTimeSec
    Memory: WorkingSetMB, PrivateMemoryMB, VirtualMemoryMB, PeakWorkingSetMB
    I/O: IOReadKBSec, IOWriteKBSec, IOReadOpsSec, IOWriteOpsSec
    Other: ThreadCount, HandleCount(FD), Owner, SessionID

  Linux-specific fields:
    Nice: Scheduling priority (-20 to 19)
    State: Process state (R/S/D/Z/T)
    RssFileMB: File-backed RSS
    RssShmemMB: Shared memory RSS
    SwapUsageMB: Swap usage
    VoluntaryCtxtSwitches: Voluntary context switches
    NonvoluntaryCtxtSwitches: Involuntary context switches

Notes:
  - Recommended to run as root for complete process information
  - Requires Bash 4.0+ (associative arrays support)
  - Output file is created immediately and written in real-time

================================================================================
EOF
}

# Check environment
check_environment() {
    print_message "info" "Checking environment..."

    # Check Bash version
    if [[ "${BASH_VERSINFO[0]}" -lt 4 ]]; then
        print_message "error" "Bash 4.0 or newer required (current: $BASH_VERSION)"
        exit 1
    fi

    # Check /proc filesystem
    if [[ ! -d /proc ]]; then
        print_message "error" "/proc filesystem not found"
        exit 1
    fi

    # Check required tools (only POSIX standard tools)
    local required_tools=("awk" "date")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            print_message "error" "Missing required tool: $tool"
            exit 1
        fi
    done

    # Check permissions
    if [[ $EUID -ne 0 ]]; then
        print_message "warning" "Not running as root, some process info may be unavailable"
    fi

    # Check output directory
    if [[ -z "$OUTPUT_PATH" ]]; then
        OUTPUT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    fi

    if [[ ! -d "$OUTPUT_PATH" ]]; then
        mkdir -p "$OUTPUT_PATH" 2>/dev/null || {
            print_message "error" "Cannot create output directory: $OUTPUT_PATH"
            exit 1
        }
        print_message "success" "Created output directory: $OUTPUT_PATH"
    fi

    if [[ ! -w "$OUTPUT_PATH" ]]; then
        print_message "error" "Output directory not writable: $OUTPUT_PATH"
        exit 1
    fi

    # Check disk space (at least 100MB)
    local available_mb=$(df -BM "$OUTPUT_PATH" | awk 'NR==2 {print $4}' | sed 's/M//')
    if [[ $available_mb -lt 100 ]]; then
        print_message "warning" "Low disk space: ${available_mb}MB available"
    fi

    print_message "success" "Environment check completed"
}

# Get output file path
get_output_filepath() {
    local extension
    case "${OUTPUT_FORMAT,,}" in
        json) extension="json" ;;
        tsv)  extension="tsv" ;;
        *)    extension="csv" ;;
    esac

    if [[ -n "$OUTPUT_FILENAME" ]]; then
        echo "${OUTPUT_PATH}/${OUTPUT_FILENAME}.${extension}"
    else
        local timestamp=$(date '+%Y%m%d_%H%M%S')
        echo "${OUTPUT_PATH}/process_metrics_${timestamp}.${extension}"
    fi
}

################################################################################
# Process Information Reading Functions
################################################################################

# Read /proc/[pid]/stat
read_proc_stat() {
    local pid="$1"
    local stat_file="/proc/$pid/stat"

    [[ ! -f "$stat_file" ]] && return 1

    # Read entire line
    local stat_line
    stat_line=$(cat "$stat_file" 2>/dev/null) || return 1

    # Parse using pure bash (handle parentheses in comm)
    # Format: pid (comm) state ppid ...
    # comm can contain spaces and special chars, enclosed in ()

    # Extract PID (first field before '(')
    local extracted_pid="${stat_line%% (*}"

    # Find comm (between first '(' and last ')')
    local temp="${stat_line#*(}"
    local comm="(${temp%)*})"

    # Get fields after last ')'
    local rest="${stat_line##*) }"

    # Parse remaining fields into array
    local fields=($rest)

    # Output required fields (matching awk version)
    printf "%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n" \
        "$extracted_pid" \
        "$comm" \
        "${fields[0]}" \
        "${fields[1]}" \
        "${fields[10]}" \
        "${fields[11]}" \
        "${fields[12]}" \
        "${fields[13]}" \
        "${fields[15]}" \
        "${fields[16]}" \
        "${fields[17]}" \
        "${fields[19]}" \
        "${fields[8]}" \
        "${fields[10]}" \
        "${fields[3]}"
}

# Read /proc/[pid]/status
read_proc_status() {
    local pid="$1"
    local status_file="/proc/$pid/status"

    [[ ! -f "$status_file" ]] && return 1

    # Use pure bash to parse (much faster than awk subprocess)
    local name="" state="" uid="0" gid="0"
    local vmsize="0" vmrss="0" vmhwm="0" vmswap="0"
    local rssanon="0" rssfile="0" rssshmem="0" threads="0"
    local vol_cs="0" nonvol_cs="0"

    local line key value
    while IFS=$':\t ' read -r key value _ ; do
        case "$key" in
            Name) name="$value" ;;
            State) state="$value" ;;
            Uid) uid="$value" ;;
            Gid) gid="$value" ;;
            VmSize) vmsize="$value" ;;
            VmRSS) vmrss="$value" ;;
            VmHWM) vmhwm="$value" ;;
            VmSwap) vmswap="$value" ;;
            RssAnon) rssanon="$value" ;;
            RssFile) rssfile="$value" ;;
            RssShmem) rssshmem="$value" ;;
            Threads) threads="$value" ;;
            voluntary_ctxt_switches) vol_cs="$value" ;;
            nonvoluntary_ctxt_switches) nonvol_cs="$value" ;;
        esac
    done < "$status_file" 2>/dev/null

    # Output in same order as before
    printf "%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n" \
        "$name" "$state" "$uid" "$gid" "$vmsize" "$vmrss" "$vmhwm" "$vmswap" \
        "$rssanon" "$rssfile" "$rssshmem" "$threads" "$vol_cs" "$nonvol_cs"
}

# Read /proc/[pid]/io
read_proc_io() {
    local pid="$1"
    local io_file="/proc/$pid/io"

    [[ ! -f "$io_file" ]] && return 1

    # Use pure bash to parse (much faster than awk subprocess)
    local read_bytes="0" write_bytes="0" syscr="0" syscw="0"

    local line key value
    while IFS=$': \t' read -r key value _ ; do
        case "$key" in
            read_bytes) read_bytes="$value" ;;
            write_bytes) write_bytes="$value" ;;
            syscr) syscr="$value" ;;
            syscw) syscw="$value" ;;
        esac
    done < "$io_file" 2>/dev/null

    printf "%s\n%s\n%s\n%s\n" "$read_bytes" "$write_bytes" "$syscr" "$syscw"
}

# Get process full path
get_process_path() {
    local pid="$1"
    local exe_link="/proc/$pid/exe"

    if [[ -L "$exe_link" ]]; then
        readlink "$exe_link" 2>/dev/null || echo ""
    else
        echo ""
    fi
}

# Get process command line
get_process_cmdline() {
    local pid="$1"
    local cmdline_file="/proc/$pid/cmdline"

    if [[ -f "$cmdline_file" ]]; then
        # Use tr to replace null bytes with spaces (avoids bash warning)
        local cmdline=$(tr '\0' ' ' < "$cmdline_file" 2>/dev/null | sed 's/ $//')
        echo "$cmdline"
    else
        echo ""
    fi
}

# Get file descriptor count (optimized)
get_fd_count() {
    local pid="$1"
    local fd_dir="/proc/$pid/fd"

    if [[ -d "$fd_dir" ]]; then
        # Use array expansion (much faster than ls | wc)
        local fds=("$fd_dir"/*)
        # Check if files actually exist (glob may return pattern if no match)
        if [[ -e "${fds[0]}" ]]; then
            echo "${#fds[@]}"
        else
            echo "0"
        fi
    else
        echo "0"
    fi
}

# Get username from UID (cached)
get_username() {
    local uid="$1"

    # Check cache first
    if [[ -n "${USERNAME_CACHE[$uid]}" ]]; then
        echo "${USERNAME_CACHE[$uid]}"
        return
    fi

    # Lookup and cache
    local username=$(getent passwd "$uid" 2>/dev/null | cut -d: -f1)
    if [[ -z "$username" ]]; then
        username="uid:$uid"
    fi

    USERNAME_CACHE[$uid]="$username"
    echo "$username"
}

# Calculate CPU percentage
calculate_cpu_percent() {
    local pid="$1"
    local current_utime="$2"
    local current_stime="$3"
    local current_time="$4"

    local cpu_percent=0
    local key="cpu_${pid}"

    if [[ -n "${LAST_CPU_MEASUREMENTS[$key]}" ]]; then
        IFS=',' read -r last_time last_total <<< "${LAST_CPU_MEASUREMENTS[$key]}"

        local current_total=$((current_utime + current_stime))
        # Use awk for decimal subtraction (current_time has decimals from date +%s.%N)
        local time_diff=$(awk "BEGIN {printf \"%.0f\", $current_time - $last_time}")
        local cpu_diff=$((current_total - last_total))

        # DEBUG: Log CPU calculation for PID 1
        if [[ "$pid" == "1" ]] && [[ "$DEBUG_MODE" == "true" ]]; then
            echo "DEBUG CPU: current_time=$current_time, last_time=$last_time, time_diff=$time_diff" >&2
            echo "DEBUG CPU: current_total=$current_total, last_total=$last_total, cpu_diff=$cpu_diff" >&2
            echo "DEBUG CPU: NUM_PROCESSORS=${NUM_PROCESSORS:-unset}" >&2
        fi

        # Check for PID reuse (CPU time decreased)
        if [[ $cpu_diff -lt 0 ]]; then
            print_message "debug" "PID $pid reuse detected (CPU time decreased), resetting measurements"
            unset "LAST_CPU_MEASUREMENTS[$key]"
            cpu_percent=0
        elif [[ $time_diff -gt 0 ]]; then
            # CPU percent calculation:
            # - cpu_diff is in jiffies (USER_HZ=100, i.e., 100 jiffies = 1 second)
            # - time_diff is in seconds (from date +%s.%N, but truncated to integer)
            # - Formula: CPU% = (cpu_diff / USER_HZ / time_diff) * 100 / num_processors
            #          = (cpu_diff / 100 / time_diff) * 100 / num_processors
            #          = cpu_diff / (time_diff * num_processors)
            # Cache num_processors (doesn't change during execution)
            if [[ -z "$NUM_PROCESSORS" ]]; then
                NUM_PROCESSORS=$(nproc)
            fi
            cpu_percent=$(fast_div "$cpu_diff" "$((time_diff * NUM_PROCESSORS))" 2)

            # DEBUG: Log calculated CPU
            if [[ "$pid" == "1" ]] && [[ "$DEBUG_MODE" == "true" ]]; then
                echo "DEBUG CPU: Calculated cpu_percent=$cpu_percent" >&2
            fi
        else
            # DEBUG: time_diff is 0
            if [[ "$pid" == "1" ]] && [[ "$DEBUG_MODE" == "true" ]]; then
                echo "DEBUG CPU: time_diff is 0, cannot calculate CPU%" >&2
            fi
        fi
    fi

    # Store current measurement
    local new_value="$current_time,$((current_utime + current_stime))"
    LAST_CPU_MEASUREMENTS[$key]="$new_value"

    # Return via global variable to avoid subshell issues with command substitution
    RETURN_VALUE="$cpu_percent"
}

# Calculate I/O rates
calculate_io_rates() {
    local pid="$1"
    local current_read_bytes="$2"
    local current_write_bytes="$3"
    local current_syscr="$4"
    local current_syscw="$5"
    local current_time="$6"

    local read_kb_sec=0
    local write_kb_sec=0
    local read_ops_sec=0
    local write_ops_sec=0
    local key="io_${pid}"

    if [[ -n "${LAST_IO_MEASUREMENTS[$key]}" ]]; then
        IFS=',' read -r last_time last_read last_write last_syscr last_syscw <<< "${LAST_IO_MEASUREMENTS[$key]}"

        # Use awk for decimal subtraction (current_time has decimals from date +%s.%N)
        local time_diff=$(awk "BEGIN {printf \"%.0f\", $current_time - $last_time}")
        local read_diff=$((current_read_bytes - last_read))
        local write_diff=$((current_write_bytes - last_write))
        local syscr_diff=$((current_syscr - last_syscr))
        local syscw_diff=$((current_syscw - last_syscw))

        # Check for PID reuse (I/O counters decreased)
        if [[ $read_diff -lt 0 ]] || [[ $write_diff -lt 0 ]]; then
            print_message "debug" "PID $pid reuse detected (I/O counters decreased), resetting measurements"
            unset "LAST_IO_MEASUREMENTS[$key]"
        elif [[ $time_diff -gt 0 ]]; then
            if [[ $read_diff -gt 0 ]]; then
                read_kb_sec=$(fast_div "$read_diff" "$((1024 * time_diff))" 1)
            fi
            if [[ $write_diff -gt 0 ]]; then
                write_kb_sec=$(fast_div "$write_diff" "$((1024 * time_diff))" 1)
            fi
            if [[ $syscr_diff -gt 0 ]]; then
                read_ops_sec=$(fast_div "$syscr_diff" "$time_diff" 1)
            fi
            if [[ $syscw_diff -gt 0 ]]; then
                write_ops_sec=$(fast_div "$syscw_diff" "$time_diff" 1)
            fi
        fi
    fi

    # Store current measurement
    LAST_IO_MEASUREMENTS[$key]="$current_time,$current_read_bytes,$current_write_bytes,$current_syscr,$current_syscw"

    # Return via global variables to avoid subshell issues with command substitution
    RETURN_IO_READ_KB_SEC="$read_kb_sec"
    RETURN_IO_WRITE_KB_SEC="$write_kb_sec"
    RETURN_IO_READ_OPS_SEC="$read_ops_sec"
    RETURN_IO_WRITE_OPS_SEC="$write_ops_sec"
}

# Calculate memory leak indicators
calculate_memory_leak_indicators() {
    local pid="$1"
    local current_rss_mb="$2"
    local current_fd_count="$3"
    local current_time="$4"

    local memory_growth_mb_per_min=0
    local fd_growth_per_min=0
    local possible_leak=false
    local key="mem_${pid}"

    if [[ -n "${LAST_MEMORY_MEASUREMENTS[$key]}" ]]; then
        IFS=',' read -r last_time last_rss last_fd <<< "${LAST_MEMORY_MEASUREMENTS[$key]}"

        # Use awk for decimal subtraction (current_time has decimals from date +%s.%N)
        local time_diff_sec=$(awk "BEGIN {printf \"%.0f\", $current_time - $last_time}")
        local fd_diff=$((current_fd_count - last_fd))

        # Check for PID reuse or calculate growth rates
        if [[ $time_diff_sec -gt 0 ]]; then
            # Calculate RSS diff (may have decimals from fast_div)
            local rss_diff=$(awk "BEGIN {printf \"%.2f\", $current_rss_mb - $last_rss}")

            # Check for PID reuse (memory significantly decreased)
            local rss_int=${rss_diff%.*}  # Get integer part
            if [[ ${rss_int#-} -gt 100 ]] && [[ $rss_int -lt 0 ]]; then
                print_message "debug" "PID $pid reuse detected (memory significantly decreased), resetting measurements"
                unset "LAST_MEMORY_MEASUREMENTS[$key]"
            else
                # Calculate growth per minute: (growth / seconds) * 60
                memory_growth_mb_per_min=$(awk "BEGIN {printf \"%.2f\", ($rss_diff / $time_diff_sec) * 60}")
                fd_growth_per_min=$(awk "BEGIN {printf \"%.2f\", ($fd_diff / $time_diff_sec) * 60}")

                # Memory leak detection logic (compare integer parts for speed)
                local mem_growth_int=${memory_growth_mb_per_min%.*}
                local fd_growth_int=${fd_growth_per_min%.*}
                if [[ ${mem_growth_int#-} -gt 5 ]] && [[ $mem_growth_int -gt 0 ]]; then
                    possible_leak=true
                elif [[ ${fd_growth_int#-} -gt 10 ]] && [[ $fd_growth_int -gt 0 ]]; then
                    possible_leak=true
                fi
            fi
        fi
    fi

    # Store current measurement
    LAST_MEMORY_MEASUREMENTS[$key]="$current_time,$current_rss_mb,$current_fd_count"

    # Return via global variables to avoid subshell issues with command substitution
    RETURN_MEMORY_GROWTH="$memory_growth_mb_per_min"
    RETURN_FD_GROWTH="$fd_growth_per_min"
    RETURN_POSSIBLE_LEAK="$possible_leak"
}

################################################################################
# Process Filtering Functions
################################################################################

# Check if process should be included
should_include_process() {
    local process_name="$1"

    # If include list exists, must match
    if [[ ${#INCLUDE_PROCESSES[@]} -gt 0 ]]; then
        local matched=false
        for pattern in "${INCLUDE_PROCESSES[@]}"; do
            if match_pattern "$process_name" "$pattern"; then
                matched=true
                break
            fi
        done
        [[ "$matched" == false ]] && return 1
    fi

    # Check exclude list
    for pattern in "${EXCLUDE_PROCESSES[@]}"; do
        if match_pattern "$process_name" "$pattern"; then
            return 1
        fi
    done

    return 0
}

# Pattern matching
match_pattern() {
    local text="$1"
    local pattern="$2"

    case "$MATCH_MODE" in
        "exact")
            [[ "$text" == "$pattern" ]]
            ;;
        "wildcard")
            # Bash pattern matching
            [[ "$text" == $pattern ]]
            ;;
        "regex")
            [[ "$text" =~ $pattern ]]
            ;;
        *)
            [[ "$text" == $pattern ]]
            ;;
    esac
}

################################################################################
# Main Collection Function
################################################################################

# Collect metrics for a single process
# Writes directly to file to avoid subshell overhead
collect_process_metrics() {
    local pid="$1"
    local is_warmup="$2"
    local current_time="$3"
    local cached_timestamp="$4"
    local cached_current_epoch="$5"
    local output_file="$6"

    # Read /proc/[pid]/stat directly (avoid function call overhead)
    local stat_file="/proc/$pid/stat"
    [[ ! -f "$stat_file" ]] && return 1

    local stat_line
    stat_line=$(cat "$stat_file" 2>/dev/null)

    # Check if stat_line is empty
    if [[ -z "$stat_line" ]]; then
        echo "ERROR: Empty stat_line for PID $pid" >&2
        return 1
    fi

    # Parse stat format: pid (comm) state ppid ...
    # Extract fields using bash string manipulation
    local extracted_pid="${stat_line%% (*}"
    local temp="${stat_line#*(}"
    local comm="${temp%%)*}"  # Remove trailing ) and everything after
    local rest="${stat_line##*) }"

    # Verify parsing succeeded
    if [[ -z "$comm" ]] || [[ -z "$rest" ]]; then
        echo "ERROR: Parsing failed for PID $pid - comm=[$comm], rest_len=${#rest}" >&2
        return 1
    fi

    # DEBUG: Check if parsing worked
    if [[ "$DEBUG_MODE" == "true" ]] && [[ "$pid" == "1" ]]; then
        echo "DEBUG: stat_line=[$stat_line]" >&2
        echo "DEBUG: comm=[$comm]" >&2
        echo "DEBUG: rest=[$rest]" >&2
    fi

    # Parse remaining fields into array
    # After "pid (comm) ", fields are: state ppid pgrp session tty_nr tpgid flags minflt cminflt majflt cmajflt utime stime cutime cstime priority nice num_threads itrealvalue starttime ...
    local stat_fields=($rest)
    local state="${stat_fields[0]}"
    local ppid="${stat_fields[1]}"
    local session="${stat_fields[3]}"
    local minflt="${stat_fields[7]}"
    local majflt="${stat_fields[9]}"
    local utime="${stat_fields[11]}"
    local stime="${stat_fields[12]}"
    local priority="${stat_fields[15]}"
    local nice="${stat_fields[16]}"
    local num_threads="${stat_fields[17]}"
    local starttime="${stat_fields[19]}"

    # DEBUG: Check parsed values
    if [[ "$DEBUG_MODE" == "true" ]] && [[ "$pid" == "1" ]]; then
        echo "DEBUG: state=[$state], nice=[$nice], priority=[$priority], num_threads=[$num_threads]" >&2
    fi

    # Read /proc/[pid]/status directly (inline parsing)
    local status_file="/proc/$pid/status"
    local uid="0" vmsize_kb="0" vmrss_kb="0" vmhwm_kb="0" vmswap_kb="0"
    local rssanon_kb="0" rssfile_kb="0" rssshmem_kb="0"
    local vol_cs="0" nonvol_cs="0"

    if [[ -f "$status_file" ]]; then
        local line key value
        while IFS=$':\t ' read -r key value _ ; do
            case "$key" in
                Uid) uid="$value" ;;
                VmSize) vmsize_kb="$value" ;;
                VmRSS) vmrss_kb="$value" ;;
                VmHWM) vmhwm_kb="$value" ;;
                VmSwap) vmswap_kb="$value" ;;
                RssAnon) rssanon_kb="$value" ;;
                RssFile) rssfile_kb="$value" ;;
                RssShmem) rssshmem_kb="$value" ;;
                voluntary_ctxt_switches) vol_cs="$value" ;;
                nonvoluntary_ctxt_switches) nonvol_cs="$value" ;;
            esac
        done < "$status_file" 2>/dev/null
    fi

    # Read /proc/[pid]/io directly (inline parsing)
    local io_file="/proc/$pid/io"
    local read_bytes="0" write_bytes="0" syscr="0" syscw="0"

    if [[ -f "$io_file" ]]; then
        local line key value
        while IFS=$': \t' read -r key value _ ; do
            case "$key" in
                read_bytes) read_bytes="$value" ;;
                write_bytes) write_bytes="$value" ;;
                syscr) syscr="$value" ;;
                syscw) syscw="$value" ;;
            esac
        done < "$io_file" 2>/dev/null
    fi

    # Get other information
    local process_path=$(get_process_path "$pid")
    local cmdline=$(get_process_cmdline "$pid")
    local fd_count=$(get_fd_count "$pid")
    local username=$(get_username "$uid")

    # Calculate derived values
    # IMPORTANT: Call directly without $() to avoid subshell that would lose LAST_CPU_MEASUREMENTS updates
    calculate_cpu_percent "$pid" "$utime" "$stime" "$current_time"
    local cpu_percent="$RETURN_VALUE"
    local cpu_total_sec=$(fast_div $((utime + stime)) 100 2)
    local user_time_sec=$(fast_div "$utime" 100 2)
    local kernel_time_sec=$(fast_div "$stime" 100 2)

    local vmsize_mb=$(fast_div "$vmsize_kb" 1024 2)
    local vmrss_mb=$(fast_div "$vmrss_kb" 1024 2)
    local vmhwm_mb=$(fast_div "$vmhwm_kb" 1024 2)
    local vmswap_mb=$(fast_div "$vmswap_kb" 1024 2)
    local rssanon_mb=$(fast_div "$rssanon_kb" 1024 2)
    local rssfile_mb=$(fast_div "$rssfile_kb" 1024 2)
    local rssshmem_mb=$(fast_div "$rssshmem_kb" 1024 2)

    # IMPORTANT: Call directly without $() to avoid subshell that would lose LAST_IO_MEASUREMENTS updates
    calculate_io_rates "$pid" "$read_bytes" "$write_bytes" "$syscr" "$syscw" "$current_time"
    local read_kb_sec="$RETURN_IO_READ_KB_SEC"
    local write_kb_sec="$RETURN_IO_WRITE_KB_SEC"
    local read_ops_sec="$RETURN_IO_READ_OPS_SEC"
    local write_ops_sec="$RETURN_IO_WRITE_OPS_SEC"

    # Calculate total I/O (handle decimal values)
    local data_kb_sec
    if [[ "$read_kb_sec" == "0" ]] && [[ "$write_kb_sec" == "0" ]]; then
        data_kb_sec="0"
    else
        # Use awk for decimal addition (faster than bc)
        data_kb_sec=$(awk "BEGIN {printf \"%.1f\", $read_kb_sec + $write_kb_sec}")
    fi

    # IMPORTANT: Call directly without $() to avoid subshell that would lose LAST_MEMORY_MEASUREMENTS updates
    calculate_memory_leak_indicators "$pid" "$vmrss_mb" "$fd_count" "$current_time"
    local memory_growth="$RETURN_MEMORY_GROWTH"
    local fd_growth="$RETURN_FD_GROWTH"
    local possible_leak="$RETURN_POSSIBLE_LEAK"

    # Calculate uptime (cache boot_time)
    if [[ -z "$BOOT_TIME" ]]; then
        BOOT_TIME=$(awk '/btime/ {print $2}' /proc/stat)
    fi
    local start_epoch=$((BOOT_TIME + starttime / 100))
    local uptime_seconds=$((cached_current_epoch - start_epoch))
    local uptime_hours=$(fast_div "$uptime_seconds" 3600 2)
    local start_time=$(date -d "@$start_epoch" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "")

    # Get parent process name
    local parent_name=""
    if [[ $ppid -gt 0 ]] && [[ -f "/proc/$ppid/comm" ]]; then
        parent_name=$(cat "/proc/$ppid/comm" 2>/dev/null)
        parent_name=${parent_name%$'\n'}  # Remove trailing newline
    fi

    # Calculate page faults/sec (if previous measurement exists)
    local pagefaults_sec=0
    # TODO: Implement page faults rate calculation

    # Output all fields (47 fields, hybrid mode specification)
    # Write directly to file in one operation to avoid subshell overhead
    local timestamp="$cached_timestamp"

    # Build complete CSV line (all 47 fields) and write once
    echo "$timestamp,$comm,$pid,$ppid,$parent_name,$process_path,$cmdline,$is_warmup,$cpu_percent,$cpu_total_sec,$user_time_sec,$kernel_time_sec,$nice,$priority,$vmrss_mb,$rssanon_mb,$vmsize_mb,N/A,N/A,$vmhwm_mb,$pagefaults_sec,$memory_growth,$fd_growth,$possible_leak,$read_kb_sec,$write_kb_sec,0,$read_ops_sec,$write_ops_sec,$data_kb_sec,$num_threads,$fd_count,$start_time,$uptime_hours,$state,$session,$username,N/A,N/A,N/A,$nice,$state,$rssfile_mb,$rssshmem_mb,$vmswap_mb,$vol_cs,$nonvol_cs" >> "$output_file"

    return 0
}

################################################################################
# Output Functions
################################################################################

# Write CSV header
write_csv_header() {
    local filepath="$1"

    cat > "$filepath" << 'EOF'
Timestamp,ProcessName,ProcessID,ParentProcessID,ParentProcessName,ProcessPath,CommandLine,IsWarmup,CPUPercent,CPUTimeTotalSec,UserTimeSec,PrivilegedTimeSec,PriorityClass,BasePriority,WorkingSetMB,PrivateMemoryMB,VirtualMemoryMB,PagedMemoryMB,NonPagedMemoryMB,PeakWorkingSetMB,PageFaultsSec,MemoryGrowthMBPerMin,HandleGrowthPerMin,PossibleMemoryLeak,IOReadKBSec,IOWriteKBSec,IOOtherKBSec,IOReadOpsSec,IOWriteOpsSec,IODataKBSec,ThreadCount,HandleCount,StartTime,UptimeHours,Responding,SessionID,Owner,CompanyName,ProductVersion,ServiceNames,Nice,State,RssFileMB,RssShmemMB,SwapUsageMB,VoluntaryCtxtSwitches,NonvoluntaryCtxtSwitches
EOF
}

# Write TSV header
write_tsv_header() {
    local filepath="$1"

    cat > "$filepath" << 'EOF'
Timestamp	ProcessName	ProcessID	ParentProcessID	ParentProcessName	ProcessPath	CommandLine	IsWarmup	CPUPercent	CPUTimeTotalSec	UserTimeSec	PrivilegedTimeSec	PriorityClass	BasePriority	WorkingSetMB	PrivateMemoryMB	VirtualMemoryMB	PagedMemoryMB	NonPagedMemoryMB	PeakWorkingSetMB	PageFaultsSec	MemoryGrowthMBPerMin	HandleGrowthPerMin	PossibleMemoryLeak	IOReadKBSec	IOWriteKBSec	IOOtherKBSec	IOReadOpsSec	IOWriteOpsSec	IODataKBSec	ThreadCount	HandleCount	StartTime	UptimeHours	Responding	SessionID	Owner	CompanyName	ProductVersion	ServiceNames	Nice	State	RssFileMB	RssShmemMB	SwapUsageMB	VoluntaryCtxtSwitches	NonvoluntaryCtxtSwitches
EOF
}

# Write JSON metadata
write_json_metadata() {
    local filepath="$1"

    local metadata_json=$(cat <<METADATA_JSON
{
  "CollectionStart": "$START_TIME",
  "DurationMinutes": $DURATION_MINUTES,
  "IntervalSeconds": $INTERVAL_SECONDS,
  "Version": "$VERSION",
  "Platform": "Linux",
  "Hostname": "$(hostname)",
  "KernelVersion": "$(uname -r)"
}
METADATA_JSON
    )

    echo "# METADATA: $metadata_json" > "$filepath"
}

################################################################################
# Main Execution Flow
################################################################################

# Parse arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                show_help
                exit 0
                ;;
            -d|--duration)
                DURATION_MINUTES="$2"
                shift 2
                ;;
            -i|--interval)
                INTERVAL_SECONDS="$2"
                shift 2
                ;;
            -f|--format)
                OUTPUT_FORMAT="${2^^}"
                shift 2
                ;;
            -o|--output)
                OUTPUT_PATH="$2"
                shift 2
                ;;
            --include)
                INCLUDE_PROCESSES+=("$2")
                shift 2
                ;;
            --exclude)
                EXCLUDE_PROCESSES+=("$2")
                shift 2
                ;;
            --match-mode)
                MATCH_MODE="$2"
                shift 2
                ;;
            --min-cpu)
                MINIMUM_CPU="$2"
                shift 2
                ;;
            --min-memory)
                MINIMUM_MEMORY_MB="$2"
                shift 2
                ;;
            --group-by-name)
                GROUP_BY_NAME=true
                shift
                ;;
            --quiet)
                QUIET_MODE=true
                shift
                ;;
            --debug)
                DEBUG_MODE=true
                shift
                ;;
            *)
                print_message "error" "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done

    # Validate parameters
    if [[ $DURATION_MINUTES -lt 1 ]] || [[ $DURATION_MINUTES -gt 1440 ]]; then
        print_message "error" "Duration must be between 1-1440 minutes"
        exit 1
    fi

    if [[ $INTERVAL_SECONDS -lt 1 ]] || [[ $INTERVAL_SECONDS -gt 3600 ]]; then
        print_message "error" "Interval must be between 1-3600 seconds"
        exit 1
    fi

    case "${OUTPUT_FORMAT^^}" in
        CSV|JSON|TSV) ;;
        *)
            print_message "error" "Output format must be CSV, JSON, or TSV"
            exit 1
            ;;
    esac
}

# Main collection loop
main_collection_loop() {
    local output_filepath=$(get_output_filepath)
    TOTAL_ITERATIONS=$((DURATION_MINUTES * 60 / INTERVAL_SECONDS))
    START_TIME=$(date '+%Y-%m-%d %H:%M:%S')

    print_message "info" "Starting performance data collection (real-time write mode)..."
    print_message "info" "Output file: $output_filepath"

    # Write header
    case "${OUTPUT_FORMAT^^}" in
        CSV)
            write_csv_header "$output_filepath"
            ;;
        TSV)
            write_tsv_header "$output_filepath"
            ;;
        JSON)
            write_json_metadata "$output_filepath"
            ;;
    esac

    # Main loop
    for ((i=1; i<=TOTAL_ITERATIONS; i++)); do
        CURRENT_ITERATION=$i
        local interval_start=$(date +%s.%N)
        local current_time="$interval_start"
        local is_warmup=false
        [[ $i -le 2 ]] && is_warmup=true

        # Cache timestamp and epoch for this iteration (avoid calling date for every process)
        local cached_timestamp=$(date '+%Y-%m-%d %H:%M:%S')
        local cached_current_epoch=$(date +%s)

        # Collect all processes
        local collected_count=0
        for pid_dir in /proc/[0-9]*; do
            [[ ! -d "$pid_dir" ]] && continue

            local pid="${pid_dir##*/}"
            local comm=""

            # Read process name
            if [[ -f "/proc/$pid/comm" ]]; then
                comm=$(cat "/proc/$pid/comm" 2>/dev/null)
                comm=${comm%$'\n'}  # Remove trailing newline
            else
                continue
            fi

            # Check filtering conditions
            should_include_process "$comm" || continue

            # Collect metrics (writes directly to file, no subshell)
            if collect_process_metrics "$pid" "$is_warmup" "$current_time" "$cached_timestamp" "$cached_current_epoch" "$output_filepath"; then
                ((collected_count++))
            fi
        done

        # Calculate elapsed time for this interval (using awk instead of bc)
        local interval_end=$(date +%s.%N)
        local elapsed=$(awk "BEGIN {printf \"%.2f\", $interval_end - $interval_start}")
        local elapsed_int=$(printf "%.0f" "$elapsed")

        # Show progress
        if [[ "$QUIET_MODE" == false ]]; then
            local progress=$((i * 100 / TOTAL_ITERATIONS))
            local timestamp=$(date '+%H:%M:%S')
            print_message "info" "[$timestamp] Progress: $i/$TOTAL_ITERATIONS ($progress%) - Collected $collected_count processes (${elapsed_int}s)"
        fi

        # Wait for next interval with dynamic sleep adjustment (using awk for float operations)
        if [[ $i -lt $TOTAL_ITERATIONS ]]; then
            local sleep_time=$(awk "BEGIN {printf \"%.2f\", $INTERVAL_SECONDS - $elapsed}")

            if [[ $(awk "BEGIN {print ($sleep_time > 0.1)}") -eq 1 ]]; then
                sleep "$sleep_time"
            elif [[ $(awk "BEGIN {print ($elapsed > $INTERVAL_SECONDS)}") -eq 1 ]]; then
                print_message "warning" "Collection took ${elapsed_int}s (exceeds ${INTERVAL_SECONDS}s interval)"
                # No sleep, continue immediately to next iteration
            fi
        fi
    done

    print_message "success" "Collection completed! Output file: $output_filepath"
}

################################################################################
# Program Entry Point
################################################################################

main() {
    # Parse arguments
    parse_arguments "$@"

    # Check environment
    check_environment

    # Show configuration
    echo ""
    echo "========================================"
    echo "  JT Process Performance Analyzer"
    echo "  Version: $VERSION (Linux)"
    echo "========================================"
    echo ""
    echo "  Duration:         $DURATION_MINUTES minutes"
    echo "  Interval:         $INTERVAL_SECONDS seconds"
    echo "  Total iterations: $((DURATION_MINUTES * 60 / INTERVAL_SECONDS))"
    echo "  Output format:    $OUTPUT_FORMAT"
    echo "  Output path:      $OUTPUT_PATH"
    echo ""
    echo "========================================"
    echo ""

    # Start collection
    main_collection_loop

    # Show summary
    echo ""
    echo "========================================"
    echo "  Execution Summary"
    echo "========================================"
    echo ""
    echo "  Completed at:     $(date '+%Y-%m-%d %H:%M:%S')"
    echo "  Error count:      $ERROR_COUNT"
    echo ""
    echo "========================================"
}

# Execute main program
main "$@"
