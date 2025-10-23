#!/bin/sh

# ============================================================================
# Health Checker Script
# Author: Li Yuxin
# Purpose: Monitor system health and output to stdout for piping
# Version: 1.3
# Run via: curl -s https://raw.githubusercontent.com/unixlotus/Unix-Health-Checker/refs/heads/main/health-checker.sh | sudo bash
# ============================================================================

# Configuration
LOG_DIR="/var/log/health-checker"
REPORT_DIR="$LOG_DIR/reports"
TMP_DIR="$LOG_DIR/tmp"
MAX_LOG_AGE_DAYS=7
DATE=$(date '+%Y-%m-%d %H:%M:%S')
TIMESTAMP=$(date '+%s')
HOSTNAME=$(hostname -f)
IP_ADDR=$(hostname -I | awk '{print $1}')

# Ensure directories exist
mkdir -p "$LOG_DIR" "$REPORT_DIR" "$TMP_DIR" 2>/dev/null || {
    echo "ERROR: Cannot create log directories." >&2
    exit 1
}

# Set ownership and permissions
chown root:root "$LOG_DIR" "$REPORT_DIR" "$TMP_DIR" 2>/dev/null || true
chmod 755 "$LOG_DIR" "$REPORT_DIR" "$TMP_DIR" 2>/dev/null || true

# Function: Log to stdout (for piping)
log_message() {
    local level="$1"
    local message="$2"
    echo "$DATE | $HOSTNAME | $level | $message" >&1
}

# Function: Check if disk usage exceeds threshold
check_disk_usage() {
    local mount_point="$1"
    local threshold="${2:-90}"
    local usage_percent=$(df "$mount_point" | tail -1 | awk '{print $5}' | tr -d '%')
    local device=$(df "$mount_point" | tail -1 | awk '{print $1}')
    if [ "$usage_percent" -ge "$threshold" ]; then
        log_message "WARNING" "Disk usage high on $device ($mount_point): $usage_percent%"
        echo "DISK_USAGE_HIGH|device=$device|mount=$mount_point|usage=$usage_percent%|threshold=$threshold"
    else
        echo "DISK_USAGE_OK|device=$device|mount=$mount_point|usage=$usage_percent%"
    fi
}

# Function: Check CPU load (no bc)
check_load_average() {
    local load1=$(cat /proc/loadavg | awk '{print $1}')
    local load5=$(cat /proc/loadavg | awk '{print $2}')
    local load15=$(cat /proc/loadavg | awk '{print $3}')
    local cpu_count=$(nproc 2>/dev/null || echo 1)
    local threshold=$(echo "$cpu_count * 1.0" | awk '{print int($1*100)/100}')
    local load1_int=$(echo "$load1 * 100" | awk '{print int($1)}')
    local threshold_int=$(echo "$threshold * 100" | awk '{print int($1)}')
    if [ "$load1_int" -gt "$threshold_int" ]; then
        log_message "WARNING" "High load average (1min): $load1 (threshold: $threshold)"
        echo "LOAD_HIGH|1min=$load1|5min=$load5|15min=$load15|cpu_count=$cpu_count"
    else
        echo "LOAD_OK|1min=$load1|5min=$load5|15min=$load15"
    fi
}

# Function: Check memory usage (no bc)
check_memory_usage() {
    local mem_total=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local mem_free=$(grep MemFree /proc/meminfo | awk '{print $2}')
    local mem_cached=$(grep Cached /proc/meminfo | awk '{print $2}')
    local mem_buffers=$(grep Buffers /proc/meminfo | awk '{print $2}')
    local mem_used=$((mem_total - mem_free - mem_cached - mem_buffers))
    local mem_used_percent=$(( (mem_used * 10000) / mem_total ))
    local mem_used_percent_float=$(printf "%.2f" $((mem_used_percent / 100.0)))
    if [ "$(echo "$mem_used_percent_float > 85.00" | awk '{print $1>85.00}') " = "1" ]; then
        log_message "WARNING" "High memory usage: $mem_used_percent_float%"
        echo "MEMORY_HIGH|used=$mem_used_percent_float%|available=$mem_used_percent_float%"
    else
        echo "MEMORY_OK|used=$mem_used_percent_float%|available=$mem_used_percent_float%"
    fi
}

# Function: Check process count
check_process_count() {
    local process_count=$(ps aux | wc -l)
    local threshold=200
    if [ "$process_count" -gt "$threshold" ]; then
        log_message "WARNING" "High process count: $process_count (threshold: $threshold)"
        echo "PROCESS_HIGH|count=$process_count|threshold=$threshold"
    else
        echo "PROCESS_OK|count=$process_count"
    fi
}

# Function: Check network
check_network_status() {
    local interfaces=$(ip -o link show | awk -F': ' '{print $2}' | grep -v 'lo' | grep -v 'docker' | grep -v 'br-' | grep -v 'veth')
    local failures=0
    for iface in $interfaces; do
        if ip link show "$iface" | grep -q 'state DOWN'; then
            log_message "ERROR" "Network interface $iface is DOWN"
            echo "NETWORK_DOWN|interface=$iface"
            failures=$((failures + 1))
        fi
    done
    if [ "$failures" -eq 0 ]; then
        echo "NETWORK_OK|interfaces=$(echo "$interfaces" | wc -w)"
    else
        echo "NETWORK_WARNING|down_interfaces=$failures"
    fi
}

# Function: Check services
check_services() {
    local services="sshd cron systemd-logind"
    local failed=0
    for svc in $services; do
        if ! systemctl is-active --quiet "$svc" 2>/dev/null; then
            log_message "ERROR" "Service $svc is not active"
            echo "SERVICE_DOWN|service=$svc"
            failed=$((failed + 1))
        fi
    done
    if [ "$failed" -eq 0 ]; then
        echo "SERVICES_OK|count=$(echo "$services" | wc -w)"
    else
        echo "SERVICES_WARNING|failed=$failed"
    fi
}

# Function: Generate JSON report
generate_report() {
    local report_file="$REPORT_DIR/health-report-$(date '+%Y-%m-%d').json"
    local temp_json=$(mktemp)

    cat > "$temp_json" << EOF
{
  "timestamp": "$DATE",
  "hostname": "$HOSTNAME",
  "ip_address": "$IP_ADDR",
  "system": {
    "cpu_load_1min": "$(awk '{print $1}' /proc/loadavg)",
    "cpu_load_5min": "$(awk '{print $2}' /proc/loadavg)",
    "cpu_load_15min": "$(awk '{print $3}' /proc/loadavg)",
    "cpu_cores": "$(nproc 2>/dev/null || echo 1)",
    "memory_total_kb": "$(grep MemTotal /proc/meminfo | awk '{print $2}')",
    "memory_used_percent": "$(printf "%.2f" $(( ( $(grep MemUsed /proc/meminfo | awk '{print $2}') * 10000 ) / $(grep MemTotal /proc/meminfo | awk '{print $2}') / 100.0 )))",
    "disk_usage": {
EOF

    df -h | tail -n +2 | while read dev mount size used avail usep mountpoint; do
        if [ "$mountpoint" != "tmpfs" ] && [ "$mountpoint" != "devtmpfs" ]; then
            echo "    \"${mountpoint}\": {"
            echo "      \"size\": \"$size\","
            echo "      \"used\": \"$used\","
            echo "      \"available\": \"$avail\","
            echo "      \"usage_percent\": \"$usep\""
            echo "    },"
        fi
    done >> "$temp_json"

    sed -i '$s/,$//' "$temp_json"
    echo "  }"
    echo "}"
    echo "}" >> "$temp_json"

    mv "$temp_json" "$report_file"
    chown root:root "$report_file" 2>/dev/null || true
    chmod 644 "$report_file" 2>/dev/null || true
    log_message "INFO" "Generated health report: $report_file"
}

# Function: Cleanup old logs
cleanup_old_logs() {
    local cutoff=$(date -d "-$MAX_LOG_AGE_DAYS days" +%Y-%m-%d)
    if [ -f "$LOG_DIR/health-checker.log" ]; then
        mv "$LOG_DIR/health-checker.log" "$LOG_DIR/health-checker.$cutoff.log" 2>/dev/null || true
    fi
    find "$LOG_DIR" -name "health-checker-*.log" -mtime +$MAX_LOG_AGE_DAYS -delete 2>/dev/null || true
    find "$REPORT_DIR" -name "health-report-*.json" -mtime +$MAX_LOG_AGE_DAYS -delete 2>/dev/null || true
}

# Main Execution
main() {
    log_message "INFO" "Starting health check on $HOSTNAME"
    echo "$TIMESTAMP" > "$TMP_DIR/last-check.timestamp" 2>/dev/null || true

    # Run checks
    local results=()
    results+=("CPU Load: $(check_load_average)")
    results+=("Memory: $(check_memory_usage)")
    results+=("Disk Usage: $(check_disk_usage /)")
    results+=("Processes: $(check_process_count)")
    results+=("Network: $(check_network_status)")
    results+=("Services: $(check_services)")

    # Output results
    for result in "${results[@]}"; do
        case "$result" in
            *WARNING*|*ERROR*) log_message "WARNING" "$result" ;;
            *ERROR*) log_message "ERROR" "$result" ;;
            *OK*) log_message "INFO" "$result" ;;
        esac
    done

    # Generate report
    generate_report

    # Clean up
    cleanup_old_logs

    log_message "INFO" "Health check completed successfully"
}

# Run main
main "$@"
