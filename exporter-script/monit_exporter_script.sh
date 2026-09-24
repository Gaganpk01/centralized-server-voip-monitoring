#!/usr/bin/env bash
#
# setup_monit_metrics.sh — Steps 1-10 of the remote-server runbook.
#
# Structured as one function per step, orchestrated by main() at the bottom.
# Every function is independently callable, so you can source this file and run
# a single step while debugging:
#
#   source ./setup_monit_metrics.sh --source-only
#   detect_node_exporter
#   run_metrics_once
#   lint_prom_file
#
# Assumes monit is already installed (see install_monit.sh). Wires monit and a
# list of systemd units into Prometheus via the node_exporter textfile collector.
#
#   Step 1   verify monit is installed, active and enabled
#   Step 2   detect node_exporter, its textfile directory and its user
#   Step 3   enable --collector.textfile.directory (systemd drop-in)
#   Step 4   create the textfile directory, both levels traversable at 0755
#   Step 5   install /usr/local/bin/monit_metrics.sh
#   Step 6   validate it (bash -n + the chmod paste-truncation check)
#   Step 7   run once, check ownership/readability, lint the exposition format
#   Step 8   install monit-metrics.service and .timer with AccuracySec=1s
#   Step 9   verify the mode SURVIVES a timer run, then scrape :PORT/metrics
#   Step 10  open the firewall for the monitoring server
#
# Safe to re-run. Every step is idempotent.
#
# The monitoring server IP is always asked for interactively -- there is no
# flag for it and no default. A run with no terminal attached aborts rather
# than guess; pass --no-firewall to skip the firewall step on purpose.
#
# Usage:
#   sudo ./setup_monit_metrics.sh                      # asks for the IP
#   sudo ./setup_monit_metrics.sh --port 9101 \
#        --services "nginx redis-server freeswitch mongod cdrpost claim_agent"
#   sudo ./setup_monit_metrics.sh --interval 30s
#   sudo ./setup_monit_metrics.sh --no-firewall        # no rule, no prompt
#   sudo ./setup_monit_metrics.sh --uninstall
#
set -euo pipefail

# ===========================================================================
# Configuration
# ===========================================================================
MONITOR_IP=""
EXPORTER_PORT="9101"
TEXTFILE_DIR="/var/lib/node_exporter/textfile_collector"
METRICS_SCRIPT="/usr/local/bin/monit_metrics.sh"
INTERVAL="15s"
SKIP_FIREWALL=0
UNINSTALL=0
SOURCE_ONLY=0

SERVICES="nginx redis-server freeswitch mongod cdrpost claim_agent"

SERVICE_UNIT="/etc/systemd/system/monit-metrics.service"
TIMER_UNIT="/etc/systemd/system/monit-metrics.timer"
DROPIN_DIR="/etc/systemd/system/node_exporter.service.d"
DROPIN_FILE="${DROPIN_DIR}/10-textfile-collector.conf"

# Runtime state shared between steps.
M_ACTIVE=""; M_ENABLED=""
NE_PID=""; NE_UNIT=""; NE_USER="root"; RUNNING_DIR=""
PARENT_DIR=""; PROM=""; MODE=""

# ===========================================================================
# Output helpers
# ===========================================================================
init_colors() {
    if [ -t 1 ]; then
        C_RESET=$'\033[0m'; C_BLUE=$'\033[1;34m'; C_GREEN=$'\033[1;32m'
        C_YELLOW=$'\033[1;33m'; C_RED=$'\033[1;31m'
    else
        C_RESET=""; C_BLUE=""; C_GREEN=""; C_YELLOW=""; C_RED=""
    fi
}
step() { printf '\n%s==> %s%s\n' "$C_BLUE" "$*" "$C_RESET"; }
ok()   { printf '%s  [ok]%s %s\n'   "$C_GREEN"  "$C_RESET" "$*"; }
warn() { printf '%s  [warn]%s %s\n' "$C_YELLOW" "$C_RESET" "$*"; }
die()  { printf '%s  [fail]%s %s\n' "$C_RED"    "$C_RESET" "$*" >&2; exit 1; }
indent() { sed 's/^/    /'; }

# ===========================================================================
# Small utilities
# ===========================================================================

usage() { sed -n '3,40p' "$0" | sed 's/^# \{0,1\}//'; }

is_number() { case "$1" in ''|*[!0-9]*) return 1 ;; esac; return 0; }

need_arg() {
    # Turns a missing or empty flag value into a readable message instead of
    # bash's "parameter null or not set" from ${2:?}.
    [ -n "${2:-}" ] || die "${1} needs a value."
}

valid_ip() {
    # Accepts a bare IPv4 address or IPv4/CIDR. Rejects octets above 255.
    local ip="${1%%/*}" cidr="${1#*/}" o
    case "$1" in
        */*) is_number "$cidr" || return 1
             [ "$cidr" -ge 0 ] && [ "$cidr" -le 32 ] || return 1 ;;
    esac
    case "$ip" in *.*.*.*) ;; *) return 1 ;; esac
    local IFS=.
    set -- $ip
    [ $# -eq 4 ] || return 1
    for o in "$@"; do
        is_number "$o" || return 1
        [ "${#o}" -le 3 ] || return 1
        [ "$o" -le 255 ] || return 1
    done
    return 0
}

interval_to_seconds() {
    # "15s" -> 15, "2m" -> 120. Used to size the Step 9 wait, which the
    # original hardcoded at 25s and so was wrong for any other interval.
    local n
    n="$(printf '%s' "$1" | tr -dc '0-9')"
    is_number "$n" || { printf '15'; return 0; }
    case "$1" in *m|*min) n=$((n * 60)) ;; esac
    printf '%s' "$n"
}

service_list_lines() {
    # One service per line, as the generated loop expects.
    printf '%s\n' $SERVICES
}

prompt_ip() {
    # Echoes a validated IP on stdout, or nothing if the user chose to skip.
    # Everything else goes to stderr: warn() writes to stdout, so an
    # un-redirected retry message would land inside the captured value.
    local answer attempt=0
    while [ "$attempt" -lt 3 ]; do
        attempt=$((attempt + 1))
        printf '    Monitoring server IP (blank to skip): ' >&2
        read -r answer || answer=""
        answer="$(printf '%s' "$answer" | tr -d '[:space:]')"
        [ -z "$answer" ] && return 0
        if valid_ip "$answer"; then printf '%s' "$answer"; return 0; fi
        warn "'${answer}' is not a valid IPv4 address or CIDR (attempt ${attempt} of 3)." >&2
    done
    die "No valid address after 3 attempts."
}

# ===========================================================================
# Argument parsing and preflight
# ===========================================================================

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --port)         need_arg "$1" "${2:-}"; EXPORTER_PORT="$2"; shift 2 ;;
            --services)     need_arg "$1" "${2:-}"; SERVICES="$2"; shift 2 ;;
            --textfile-dir) need_arg "$1" "${2:-}"; TEXTFILE_DIR="$2"; shift 2 ;;
            --interval)     need_arg "$1" "${2:-}"; INTERVAL="$2"; shift 2 ;;
            --no-firewall)  SKIP_FIREWALL=1; shift ;;
            --uninstall)    UNINSTALL=1; shift ;;
            --source-only)  SOURCE_ONLY=1; shift ;;
            -h|--help)      usage; exit 0 ;;
            *) die "Unknown option: $1 (try --help)" ;;
        esac
    done
    is_number "$EXPORTER_PORT" || die "--port must be numeric (got '$EXPORTER_PORT')."
    [ -n "$SERVICES" ] || die "--services cannot be empty."
    return 0
}

require_root() {
    [ "$(id -u)" -eq 0 ] || die "Must run as root (use sudo)."
    command -v systemctl >/dev/null 2>&1 || die "systemd required; systemctl not found."
}

# ===========================================================================
# Uninstall
# ===========================================================================

do_uninstall() {
    step "Removing the metrics exporter"
    systemctl disable --now monit-metrics.timer >/dev/null 2>&1 || true
    systemctl stop monit-metrics.service >/dev/null 2>&1 || true
    rm -f "$TIMER_UNIT" "$SERVICE_UNIT" "$METRICS_SCRIPT" "${TEXTFILE_DIR}/monit.prom"
    systemctl daemon-reload
    ok "Removed timer, service, metrics script and monit.prom."
    warn "Left alone: monit, the node_exporter drop-in, firewall rules."
}

# ===========================================================================
# Monitoring server address
# ===========================================================================

ask_monitor_ip() {
    # Asked up front rather than at Step 10 so the run doesn't stall for input
    # after the timer wait.
    [ "$SKIP_FIREWALL" -eq 1 ] && return 0
    [ -t 0 ] || die "No terminal to ask for the monitoring server IP on. Run this interactively, or pass --no-firewall to skip the firewall step deliberately."

    step "Monitoring server address"
    cat <<'EOF'
    The IP that Prometheus will scrape this host FROM. Must be the address the
    traffic actually arrives from, which is not always the one you SSH to --
    if Prometheus sits behind NAT, use its public egress IP.

    On the Prometheus server:  hostname -I | awk '{print $1}'

    Leave blank to skip the firewall rule and add it yourself later.
EOF
    MONITOR_IP="$(prompt_ip)"
    if [ -z "$MONITOR_IP" ]; then
        SKIP_FIREWALL=1
        warn "Skipping the firewall rule. Open ${EXPORTER_PORT}/tcp for the monitoring server yourself."
    else
        ok "Will allow ${MONITOR_IP} to reach port ${EXPORTER_PORT}/tcp"
    fi
}

# ===========================================================================
# Step 1 — monit status
# ===========================================================================

verify_monit() {
    step "Step 1: Verify monit status"

    command -v monit >/dev/null 2>&1 \
        || die "monit is not installed. Run install_monit.sh first."
    monit --version 2>&1 | head -1 | indent

    M_ACTIVE="$(systemctl is-active monit 2>/dev/null || true)"
    M_ENABLED="$(systemctl is-enabled monit 2>/dev/null || true)"
    printf '    is-active  : %s\n    is-enabled : %s\n' "$M_ACTIVE" "$M_ENABLED"

    # Not fatal — monit_up reporting 0 is legitimate output, and the exporter
    # should be installed even while monit is down.
    [ "$M_ACTIVE" = "active" ] || warn "monit is not active; monit_up will report 0."
    case "$M_ENABLED" in
        enabled|enabled-runtime|static|indirect) ok "monit verified" ;;
        *) warn "monit is not enabled at boot (state: ${M_ENABLED:-unknown})." ;;
    esac
}

# ===========================================================================
# Step 2 — detect node_exporter
# ===========================================================================

find_node_exporter_unit() {
    local u
    for u in node_exporter prometheus-node-exporter; do
        if systemctl list-unit-files "${u}.service" --no-legend 2>/dev/null | grep -q .; then
            printf '%s' "$u"; return 0
        fi
    done
}

running_textfile_dir() {
    # Read the flag off the live process rather than the unit file — the unit
    # may have been edited without a restart.
    [ -n "$NE_PID" ] || return 0
    tr '\0' '\n' < "/proc/${NE_PID}/cmdline" 2>/dev/null \
        | grep -m1 '^--collector.textfile.directory=' | cut -d= -f2- || true
}

exporter_user() {
    local u
    if [ -n "$NE_PID" ]; then
        ps -o user= -p "$NE_PID" | tr -d ' '
    elif [ -n "$NE_UNIT" ]; then
        u="$(systemctl show "$NE_UNIT" -p User --value 2>/dev/null || true)"
        printf '%s' "${u:-root}"
    else
        printf 'root'
    fi
}

detect_node_exporter() {
    step "Step 2: Detect node_exporter"

    # pgrep -x, not -f: -f would also match this installer when it is saved
    # under a filename containing node_exporter, and after a restart the script
    # has the lower PID so head -1 picks the wrong process.
    NE_PID="$(pgrep -x node_exporter | head -1 || true)"
    NE_UNIT="$(find_node_exporter_unit)"

    if [ -z "$NE_PID" ] && [ -z "$NE_UNIT" ]; then
        warn "node_exporter not found. The .prom file will be written but nothing"
        warn "will scrape it until an exporter points at ${TEXTFILE_DIR}."
    else
        ok "unit: ${NE_UNIT:-<none>}   pid: ${NE_PID:-<not running>}"
    fi

    RUNNING_DIR="$(running_textfile_dir)"
    NE_USER="$(exporter_user)"
    id "$NE_USER" >/dev/null 2>&1 || {
        warn "User '$NE_USER' missing; using root."; NE_USER="root"
    }
    ok "exporter user: $NE_USER"
}

# ===========================================================================
# Step 3 — enable the textfile collector
# ===========================================================================

write_dropin() {
    # Join backslash continuations, then lift the whole ExecStart out.
    local cur_exec
    cur_exec="$(systemctl cat "$NE_UNIT" 2>/dev/null \
        | sed -e ':a' -e '/\\$/{N; s/\\\n[[:space:]]*/ /; ba}' \
        | grep -m1 '^ExecStart=' | sed 's/^ExecStart=//' || true)"
    [ -n "$cur_exec" ] || die "Could not read ExecStart from ${NE_UNIT}.service."

    # A drop-in instead of editing the unit: survives package upgrades and
    # leaves the vendor file pristine.
    mkdir -p "$DROPIN_DIR"
    {
        echo "# Managed by setup_monit_metrics.sh"
        echo "[Service]"
        echo "ExecStart="
        echo "ExecStart=${cur_exec} --collector.textfile.directory=${TEXTFILE_DIR}"
    } > "$DROPIN_FILE"
    chmod 0644 "$DROPIN_FILE"
}

enable_textfile_collector() {
    step "Step 3: Enable textfile collector"

    if [ -n "$RUNNING_DIR" ]; then
        ok "Already enabled at: $RUNNING_DIR"
        if [ "$RUNNING_DIR" != "$TEXTFILE_DIR" ]; then
            warn "Live exporter uses '$RUNNING_DIR'; following it instead of '$TEXTFILE_DIR'."
            TEXTFILE_DIR="$RUNNING_DIR"
        fi
        return 0
    fi

    if [ -z "$NE_UNIT" ]; then
        warn "No exporter unit to modify; skipping."
        return 0
    fi

    write_dropin
    systemctl daemon-reload
    systemctl restart "$NE_UNIT"
    sleep 2
    systemctl is-active --quiet "$NE_UNIT" \
        || die "$NE_UNIT failed to restart. Check: journalctl -u $NE_UNIT -n 50"
    ok "Drop-in written and $NE_UNIT restarted"
}

# ===========================================================================
# Step 4 — textfile directory
# ===========================================================================

create_textfile_dir() {
    step "Step 4: Create textfile directory"

    PARENT_DIR="$(dirname "$TEXTFILE_DIR")"
    mkdir -p "$TEXTFILE_DIR"
    chown "${NE_USER}:${NE_USER}" "$PARENT_DIR" "$TEXTFILE_DIR" 2>/dev/null || true
    # Both levels need 0755. An unprivileged process cannot traverse a 0700
    # parent no matter what the file's own mode is.
    chmod 0755 "$PARENT_DIR" "$TEXTFILE_DIR"
    ls -ld "$PARENT_DIR" "$TEXTFILE_DIR" | indent

    local d m
    for d in "$PARENT_DIR" "$TEXTFILE_DIR"; do
        m="$(stat -c '%a' "$d")"
        [ "$m" = "755" ] || die "$d is mode $m, expected 755."
    done
    ok "Both levels traversable"
}

# ===========================================================================
# Step 5 — install the metrics script
# ===========================================================================

emit_metrics_script() {
    # Quoted heredoc: nothing below is expanded at install time.
    cat > "$METRICS_SCRIPT" <<'METRICS_EOF'
#!/bin/bash
#
# Emits monit + per-service metrics for the node_exporter textfile collector.
# Installed by setup_monit_metrics.sh.

OUTPUT="__TEXTFILE_DIR__/monit.prom"
OWNER="__NE_USER__"
TMPFILE="$(mktemp "${OUTPUT}.XXXXXX")"
trap 'rm -f "$TMPFILE"' EXIT

SERVICES="
__SERVICES_LIST__
"

NOW=$(date +%s)
SYS_UP=$(cut -d. -f1 /proc/uptime)
BOOT=$((NOW - SYS_UP))

# systemd reports ActiveEnterTimestampMonotonic in microseconds since boot.
# Converting via boot time avoids parsing systemd's locale-dependent date string.
unit_start_epoch() {
    local mono
    mono=$(systemctl show "$1" -p ActiveEnterTimestampMonotonic 2>/dev/null | cut -d= -f2)
    case "$mono" in
        ''|*[!0-9]*) echo 0; return ;;
    esac
    [ "$mono" -gt 0 ] || { echo 0; return; }
    echo $((BOOT + mono / 1000000))
}

unit_exists() {
    systemctl list-unit-files "${1}.service" --no-legend 2>/dev/null | grep -q .
}

# ---------- monit itself ----------
MONIT_UP=0
MONIT_START=0
MONIT_UPTIME=0

if systemctl is-active --quiet monit; then
    MONIT_UP=1
    MONIT_START=$(unit_start_epoch monit)
    if [ "$MONIT_START" -gt 0 ]; then
        MONIT_UPTIME=$((NOW - MONIT_START))
        [ "$MONIT_UPTIME" -lt 0 ] && MONIT_UPTIME=0
    fi
fi

# ---------- per service ----------
FAILED_CHECKS=0
DOWN_LINES=""
START_LINES=""
UPTIME_LINES=""
INSTALLED_LINES=""

for SERVICE in $SERVICES; do

    if ! unit_exists "$SERVICE"; then
        INSTALLED_LINES="${INSTALLED_LINES}monit_service_installed{service=\"${SERVICE}\"} 0
"
        continue
    fi

    INSTALLED_LINES="${INSTALLED_LINES}monit_service_installed{service=\"${SERVICE}\"} 1
"

    if systemctl is-active --quiet "$SERVICE"; then
        DOWN_LINES="${DOWN_LINES}monit_service_down{service=\"${SERVICE}\"} 0
"
        S_START=$(unit_start_epoch "$SERVICE")
        S_UPTIME=0
        if [ "$S_START" -gt 0 ]; then
            S_UPTIME=$((NOW - S_START))
            [ "$S_UPTIME" -lt 0 ] && S_UPTIME=0
        fi
        START_LINES="${START_LINES}monit_service_start_time_seconds{service=\"${SERVICE}\"} ${S_START}
"
        UPTIME_LINES="${UPTIME_LINES}monit_service_uptime_seconds{service=\"${SERVICE}\"} ${S_UPTIME}
"
    else
        DOWN_LINES="${DOWN_LINES}monit_service_down{service=\"${SERVICE}\"} 1
"
        START_LINES="${START_LINES}monit_service_start_time_seconds{service=\"${SERVICE}\"} 0
"
        UPTIME_LINES="${UPTIME_LINES}monit_service_uptime_seconds{service=\"${SERVICE}\"} 0
"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi

done

# ---------- emit ----------
{
    echo "# HELP monit_up Monit service status (1=up, 0=down)"
    echo "# TYPE monit_up gauge"
    echo "monit_up ${MONIT_UP}"
    echo

    echo "# HELP monit_start_time_seconds Unix timestamp when monit became active (0=unknown)"
    echo "# TYPE monit_start_time_seconds gauge"
    echo "monit_start_time_seconds ${MONIT_START}"
    echo

    echo "# HELP monit_uptime_seconds Seconds monit has been continuously active"
    echo "# TYPE monit_uptime_seconds gauge"
    echo "monit_uptime_seconds ${MONIT_UPTIME}"
    echo

    echo "# HELP monit_failed_checks Installed services that are not active"
    echo "# TYPE monit_failed_checks gauge"
    echo "monit_failed_checks ${FAILED_CHECKS}"
    echo

    echo "# HELP monit_service_installed Whether a systemd unit exists (1=yes, 0=no)"
    echo "# TYPE monit_service_installed gauge"
    printf '%s' "$INSTALLED_LINES"
    echo

    echo "# HELP monit_service_down Service status (1=down, 0=up)"
    echo "# TYPE monit_service_down gauge"
    printf '%s' "$DOWN_LINES"
    echo

    echo "# HELP monit_service_start_time_seconds Unix timestamp when the service became active"
    echo "# TYPE monit_service_start_time_seconds gauge"
    printf '%s' "$START_LINES"
    echo

    echo "# HELP monit_service_uptime_seconds Seconds the service has been continuously active"
    echo "# TYPE monit_service_uptime_seconds gauge"
    printf '%s' "$UPTIME_LINES"

} > "$TMPFILE"

chmod 0644 "$TMPFILE"
mv "$TMPFILE" "$OUTPUT"
chmod 0644 "$OUTPUT"
chown "${OWNER}:${OWNER}" "$OUTPUT" 2>/dev/null || true
METRICS_EOF
}

substitute_placeholders() {
    sed -i "s|__TEXTFILE_DIR__|${TEXTFILE_DIR}|g; s|__NE_USER__|${NE_USER}|g" "$METRICS_SCRIPT"
    # awk, not sed: the service list is multi-line and sed cannot insert
    # newlines portably in a replacement.
    awk -v list="$(service_list_lines)" \
        '$0 == "__SERVICES_LIST__" { print list; next } { print }' \
        "$METRICS_SCRIPT" > "${METRICS_SCRIPT}.new"
    mv "${METRICS_SCRIPT}.new" "$METRICS_SCRIPT"
}

write_metrics_script() {
    step "Step 5: Install $METRICS_SCRIPT"
    emit_metrics_script
    substitute_placeholders
    ok "Written for $(service_list_lines | wc -l) services"
}

# ===========================================================================
# Step 6 — validate
# ===========================================================================

validate_metrics_script() {
    step "Step 6: Validate"

    chmod +x "$METRICS_SCRIPT"

    # A truncated write loses the trailing chmod lines — exactly how the 0600
    # permission bug reappears. Count chmod COMMANDS at line start: a bare
    # `grep -c chmod` also matches prose in comments and would miscount.
    local chmod_count
    chmod_count="$(grep -c '^chmod ' "$METRICS_SCRIPT" || true)"
    [ "$chmod_count" = "2" ] \
        || die "Expected 2 chmod commands, found ${chmod_count} — the file is truncated. Re-run."
    ok "chmod commands present: $chmod_count"

    bash -n "$METRICS_SCRIPT" || die "Syntax error in $METRICS_SCRIPT"
    ok "Syntax OK — $(wc -l < "$METRICS_SCRIPT") lines"

    if grep -q '__TEXTFILE_DIR__\|__SERVICES_LIST__\|__NE_USER__' "$METRICS_SCRIPT"; then
        die "Placeholder substitution failed."
    fi
    ok "Placeholders substituted"
}

# ===========================================================================
# Step 7 — run once and lint
# ===========================================================================

lint_prom_file() {
    # One malformed line makes node_exporter discard every .prom in the
    # directory, so this has to be exact.
    local bad
    bad="$(grep -v '^#' "$PROM" \
        | grep -v '^[[:space:]]*$' \
        | grep -vE '^[a-zA-Z_:][a-zA-Z0-9_:]*(\{[^}]*\})? -?[0-9]+(\.[0-9]+)?$' || true)"
    if [ -n "$bad" ]; then
        printf '%s\n' "$bad" | indent
        die "Malformed metric lines above."
    fi
    ok "Exposition format clean"
}

check_readable_by_exporter() {
    [ "$NE_USER" = "root" ] && return 0
    sudo -u "$NE_USER" head -1 "$PROM" >/dev/null 2>&1 \
        && ok "$NE_USER can read the file" \
        || die "$NE_USER cannot read $PROM — check directory traversal."
}

report_not_installed() {
    # monit_service_installed 0 means the unit does not exist on this host,
    # which is worth surfacing now rather than as an empty Grafana panel.
    local missing
    missing="$(awk '/^monit_service_installed\{/ && $2 == 0 {
        gsub(/.*service="|"\}.*/, ""); print }' "$PROM" || true)"
    [ -n "$missing" ] || { ok "Every listed service has a systemd unit."; return 0; }
    warn "No systemd unit for: $(printf '%s' "$missing" | tr '\n' ' ')"
    warn "Those report installed=0 and are excluded from monit_failed_checks."
}

run_metrics_once() {
    step "Step 7: Manual run"

    "$METRICS_SCRIPT" || die "Metrics script exited non-zero."
    PROM="${TEXTFILE_DIR}/monit.prom"
    [ -s "$PROM" ] || die "$PROM missing or empty."

    ls -l "$PROM" | indent
    head -3 "$PROM" | indent

    check_readable_by_exporter
    lint_prom_file
    report_not_installed
}

# ===========================================================================
# Step 8 — timer
# ===========================================================================

install_timer() {
    step "Step 8: Install service and timer (every $INTERVAL)"

    cat > "$SERVICE_UNIT" <<EOF
[Unit]
Description=Monit Prometheus Metrics
After=monit.service

[Service]
Type=oneshot
ExecStart=${METRICS_SCRIPT}
EOF

    # AccuracySec=1s is required — systemd defaults to 1 minute, which would
    # stretch a 15s interval into minute-long gaps.
    cat > "$TIMER_UNIT" <<EOF
[Unit]
Description=Run Monit Prometheus metrics every ${INTERVAL}

[Timer]
OnBootSec=${INTERVAL}
OnUnitActiveSec=${INTERVAL}
AccuracySec=1s
Unit=monit-metrics.service

[Install]
WantedBy=timers.target
EOF

    chmod 0644 "$SERVICE_UNIT" "$TIMER_UNIT"
    systemctl daemon-reload
    systemctl enable --now monit-metrics.timer >/dev/null 2>&1
    systemctl is-enabled --quiet monit-metrics.timer || die "Timer not enabled."
    systemctl list-timers --all 2>/dev/null | grep -i monit | indent || true
    ok "monit-metrics.timer enabled and started"
}

# ===========================================================================
# Step 9 — verify after a timer run
# ===========================================================================

check_scrape_error() {
    command -v curl >/dev/null 2>&1 || return 0
    local err count
    err="$(curl -sf "localhost:${EXPORTER_PORT}/metrics" 2>/dev/null \
        | awk '/^node_textfile_scrape_error/ {print $2; exit}' || true)"
    case "$err" in
        0)  ok "node_textfile_scrape_error = 0" ;;
        "") warn "Could not reach localhost:${EXPORTER_PORT}/metrics — check the port." ;;
        *)  warn "node_textfile_scrape_error = ${err} — a .prom file was rejected." ;;
    esac
    count="$(curl -sf "localhost:${EXPORTER_PORT}/metrics" 2>/dev/null | grep -c '^monit_' || true)"
    [ "${count:-0}" -gt 0 ] \
        && ok "${count} monit_* series exposed on :${EXPORTER_PORT}" \
        || warn "No monit_* series on :${EXPORTER_PORT} yet."
}

verify_after_timer() {
    # Derived from the interval rather than hardcoded at 25s, which was wrong
    # for anything other than the 15s default.
    local wait_secs pre post
    wait_secs=$(( $(interval_to_seconds "$INTERVAL") + 5 ))

    step "Step 9: Verify after a timer-driven run (waiting ${wait_secs}s)"

    pre="$(stat -c '%Y' "$PROM")"
    sleep "$wait_secs"
    post="$(stat -c '%Y' "$PROM")"

    [ "$post" != "$pre" ] \
        && ok "Timer rewrote the file" \
        || warn "File not rewritten. Check: journalctl -u monit-metrics.service -n 30"

    ls -l "$PROM" | indent
    MODE="$(stat -c '%a' "$PROM")"
    # THE decisive check. A manual run passing proves nothing — the failure mode
    # is the timer rewriting the file at 0600 one interval later.
    [ "$MODE" = "644" ] || die "$PROM is mode $MODE after the timer run, expected 644."
    ok "Mode survived the timer run: $MODE"

    check_scrape_error
}

# ===========================================================================
# Step 10 — firewall
# ===========================================================================

configure_firewall() {
    step "Step 10: Firewall"

    if [ "$SKIP_FIREWALL" -eq 1 ]; then
        ok "Skipped (--no-firewall)."; return 0
    fi
    if [ -z "$MONITOR_IP" ]; then
        warn "No monitoring server IP was given. Open ${EXPORTER_PORT}/tcp manually."; return 0
    fi

    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi '^Status: active'; then
        ufw allow from "$MONITOR_IP" to any port "$EXPORTER_PORT" proto tcp >/dev/null
        ufw reload >/dev/null
        ok "ufw: ${MONITOR_IP} -> ${EXPORTER_PORT}/tcp"
        # A blanket rule on the same port makes the targeted one decorative.
        if ufw status 2>/dev/null | grep -E "^${EXPORTER_PORT}/tcp" | grep -q 'Anywhere'; then
            warn "An existing rule already allows ${EXPORTER_PORT}/tcp from Anywhere."
            warn "The targeted rule adds nothing until you remove that one:"
            warn "  ufw status numbered   then   ufw delete <number>"
        fi
    elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=${MONITOR_IP} port port=${EXPORTER_PORT} protocol=tcp accept" >/dev/null
        firewall-cmd --reload >/dev/null
        ok "firewalld: ${MONITOR_IP} -> ${EXPORTER_PORT}/tcp"
    else
        warn "No active ufw/firewalld. Open ${EXPORTER_PORT}/tcp for ${MONITOR_IP} manually."
    fi
}

# ===========================================================================
# Summary
# ===========================================================================

print_summary() {
    step "Done"
    cat <<EOF
  monit            : ${M_ACTIVE} / ${M_ENABLED}
  exporter         : ${NE_UNIT:-<none>} as ${NE_USER}
  textfile dir     : ${TEXTFILE_DIR}
  output           : ${PROM} (mode ${MODE})
  timer            : monit-metrics.timer every ${INTERVAL}
  services         : ${SERVICES}
  local address    : $(hostname -I 2>/dev/null | awk '{print $1}'):${EXPORTER_PORT}
                     (behind NAT? Prometheus needs the address it can reach,
                      not this one -- verify with a curl from the monitor)

Note monit_service_down is inverted: 1 means down. For an "UP" panel use
1 - monit_service_down{...}.

Next, on the monitoring server: add this target to prometheus.yml, install the
alert rules, promtool check config, then 'systemctl reload prometheus'.
EOF
}

# ===========================================================================
# Orchestration
# ===========================================================================

phase_interactive() {
    ask_monitor_ip
    verify_monit
}

phase_unattended() {
    detect_node_exporter
    enable_textfile_collector
    create_textfile_dir
    write_metrics_script
    validate_metrics_script
    run_metrics_once
    install_timer
    verify_after_timer
    configure_firewall
}

main() {
    init_colors
    parse_args "$@"
    require_root

    if [ "$UNINSTALL" -eq 1 ]; then
        do_uninstall
        exit 0
    fi

    phase_interactive
    phase_unattended
    print_summary
}

# Allow `source ./setup_monit_metrics.sh --source-only` to load the functions
# without running anything, for step-by-step debugging.
case "${1:-}" in
    --source-only) init_colors; SOURCE_ONLY=1 ;;
    *) main "$@" ;;
esac
