#!/usr/bin/env bash
#
# setup_fail2ban_metrics.sh — Steps 1-10 of the remote-server runbook.
#
# Structured as one function per step, orchestrated by main() at the bottom.
# Every function is independently callable, so you can source this file and run
# a single step while debugging:
#
#   source ./setup_fail2ban_metrics.sh --source-only
#   detect_node_exporter
#   run_metrics_once
#   lint_prom_file
#
# Assumes fail2ban is already installed (see install_fail2ban.sh). Wires
# fail2ban into Prometheus via the node_exporter textfile collector.
#
#   Step 1   verify fail2ban is installed, active and answering on its socket
#   Step 2   detect node_exporter, its textfile directory and its user
#   Step 3   enable --collector.textfile.directory (systemd drop-in)
#   Step 4   create the textfile directory, both levels traversable at 0755
#   Step 5   install /usr/local/bin/fail2ban_metrics.sh
#   Step 6   validate it (bash -n + the chmod paste-truncation check)
#   Step 7   run once, check ownership/readability, lint the exposition format
#   Step 8   install fail2ban-metrics.service and .timer with AccuracySec=1s
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
#   sudo ./setup_fail2ban_metrics.sh                   # asks for the IP
#   sudo ./setup_fail2ban_metrics.sh --port 9100
#   sudo ./setup_fail2ban_metrics.sh --interval 30s
#   sudo ./setup_fail2ban_metrics.sh --no-firewall     # no rule, no prompt
#   sudo ./setup_fail2ban_metrics.sh --uninstall
#
set -euo pipefail

# ===========================================================================
# Configuration
# ===========================================================================
MONITOR_IP=""
EXPORTER_PORT="9101"
TEXTFILE_DIR="/var/lib/node_exporter/textfile_collector"
METRICS_SCRIPT="/usr/local/bin/fail2ban_metrics.sh"
INTERVAL="30s"
SKIP_FIREWALL=0
UNINSTALL=0
SOURCE_ONLY=0

SERVICE_UNIT="/etc/systemd/system/fail2ban-metrics.service"
TIMER_UNIT="/etc/systemd/system/fail2ban-metrics.timer"
DROPIN_DIR="/etc/systemd/system/node_exporter.service.d"
DROPIN_FILE="${DROPIN_DIR}/10-textfile-collector.conf"

# Runtime state shared between steps.
F2B_ACTIVE=""; F2B_ENABLED=""
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
    # "30s" -> 30, "2m" -> 120. Used to size the Step 9 wait.
    local n
    n="$(printf '%s' "$1" | tr -dc '0-9')"
    is_number "$n" || { printf '30'; return 0; }
    case "$1" in
        *m|*min) n=$((n * 60)) ;;
    esac
    printf '%s' "$n"
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
            --port)         EXPORTER_PORT="${2:?}"; shift 2 ;;
            --textfile-dir) TEXTFILE_DIR="${2:?}"; shift 2 ;;
            --interval)     INTERVAL="${2:?}"; shift 2 ;;
            --no-firewall)  SKIP_FIREWALL=1; shift ;;
            --uninstall)    UNINSTALL=1; shift ;;
            --source-only)  SOURCE_ONLY=1; shift ;;
            -h|--help)      usage; exit 0 ;;
            *) die "Unknown option: $1 (try --help)" ;;
        esac
    done
    is_number "$EXPORTER_PORT" || die "--port must be numeric (got '$EXPORTER_PORT')."
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
    systemctl disable --now fail2ban-metrics.timer >/dev/null 2>&1 || true
    systemctl stop fail2ban-metrics.service >/dev/null 2>&1 || true
    rm -f "$TIMER_UNIT" "$SERVICE_UNIT" "$METRICS_SCRIPT" "${TEXTFILE_DIR}/fail2ban.prom"
    systemctl daemon-reload
    ok "Removed timer, service, metrics script and fail2ban.prom."
    warn "Left alone: fail2ban, the node_exporter drop-in, firewall rules."
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
# Step 1 — fail2ban status
# ===========================================================================

fail2ban_jail_list() {
    fail2ban-client status 2>/dev/null \
        | sed -n 's/.*Jail list:[[:space:]]*//p' | tr ',' ' '
}

verify_fail2ban() {
    step "Step 1: Verify fail2ban status"

    command -v fail2ban-client >/dev/null 2>&1 \
        || die "fail2ban is not installed. Run install_fail2ban.sh first."
    fail2ban-server --version 2>&1 | head -1 | indent

    F2B_ACTIVE="$(systemctl is-active fail2ban 2>/dev/null || true)"
    F2B_ENABLED="$(systemctl is-enabled fail2ban 2>/dev/null || true)"
    printf '    is-active  : %s\n    is-enabled : %s\n' "$F2B_ACTIVE" "$F2B_ENABLED"

    # Not fatal — fail2ban_up reporting 0 is legitimate output, and the exporter
    # should be installed even while fail2ban is down.
    if [ "$F2B_ACTIVE" != "active" ]; then
        warn "fail2ban is not active; fail2ban_up will report 0."
        return 0
    fi

    if ! fail2ban-client status >/dev/null 2>&1; then
        # The socket can lag the unit; metrics read 0 jails until it answers.
        warn "Unit is active but the fail2ban socket is not answering yet."
        return 0
    fi

    local jails count
    jails="$(fail2ban_jail_list)"
    count="$(printf '%s' "$jails" | wc -w | tr -d ' ')"
    printf '    jails      : %s\n' "${jails:-<none>}"
    [ "${count:-0}" -gt 0 ] \
        && ok "fail2ban verified, ${count} jail(s)" \
        || warn "No active jails — per-jail metrics will be empty."
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
    # under a filename containing node_exporter.
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
        echo "# Managed by setup_fail2ban_metrics.sh"
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

write_metrics_script() {
    step "Step 5: Install $METRICS_SCRIPT"

    # Quoted heredoc: nothing below is expanded at install time.
    cat > "$METRICS_SCRIPT" <<'METRICS_EOF'
#!/bin/bash
#
# Fail2Ban metrics for the node_exporter textfile collector.
# Installed by setup_fail2ban_metrics.sh.
#

OUT="__TEXTFILE_DIR__/fail2ban.prom"
OWNER="__NE_USER__"

mkdir -p "$(dirname "$OUT")"

# Unique temp file. A fixed .tmp name lets two overlapping runs truncate
# each other mid-write and publish a partial file.
TMP="$(mktemp "${OUT}.XXXXXX")"
trap 'rm -f "$TMP"' EXIT

FAIL2BAN_UP=0
ACTIVE_JAILS=0
JAIL_LIST=""

if systemctl is-active --quiet fail2ban; then
    FAIL2BAN_UP=1
fi

# Keep only a clean integer; anything else becomes 0. A non-numeric value
# makes node_exporter discard this entire file, fail2ban_up included.
number_or_zero() {
    case "$1" in
        ''|*[!0-9]*) printf '0' ;;
        *)           printf '%s' "$1" ;;
    esac
}

if [ "$FAIL2BAN_UP" -eq 1 ]; then
    # 'Jail list:' is tab separated and comma delimited.
    # timeout guards against a hung fail2ban socket blocking the timer.
    JAIL_LIST=$(timeout 5 fail2ban-client status 2>/dev/null \
        | sed -n 's/.*Jail list:[[:space:]]*//p' \
        | tr ',' ' ')

    if [ -n "$JAIL_LIST" ]; then
        ACTIVE_JAILS=$(printf '%s' "$JAIL_LIST" | wc -w | tr -d ' ')
    fi
fi

ACTIVE_JAILS=$(number_or_zero "$ACTIVE_JAILS")

# Group by metric family so each family is contiguous in the output
CURRENT_LINES=""
TOTAL_LINES=""

for JAIL in $JAIL_LIST; do
    STATUS=$(timeout 5 fail2ban-client status "$JAIL" 2>/dev/null || true)
    CURRENT=$(printf '%s' "$STATUS" | grep 'Currently banned:' | grep -oE '[0-9]+' | head -1)
    TOTAL=$(printf '%s' "$STATUS"   | grep 'Total banned:'     | grep -oE '[0-9]+' | head -1)
    CURRENT=$(number_or_zero "$CURRENT")
    TOTAL=$(number_or_zero "$TOTAL")

    CURRENT_LINES="${CURRENT_LINES}fail2ban_currently_banned_ips{jail=\"${JAIL}\"} ${CURRENT}
"
    TOTAL_LINES="${TOTAL_LINES}fail2ban_banned_total{jail=\"${JAIL}\"} ${TOTAL}
"
done

{
    echo "# HELP fail2ban_up Fail2Ban service status (1=up, 0=down)"
    echo "# TYPE fail2ban_up gauge"
    echo "fail2ban_up ${FAIL2BAN_UP}"
    echo

    echo "# HELP fail2ban_active_jails Number of active Fail2Ban jails"
    echo "# TYPE fail2ban_active_jails gauge"
    echo "fail2ban_active_jails ${ACTIVE_JAILS}"
    echo

    echo "# HELP fail2ban_currently_banned_ips Currently banned IPs by jail"
    echo "# TYPE fail2ban_currently_banned_ips gauge"
    printf '%s' "$CURRENT_LINES"
    echo

    echo "# HELP fail2ban_banned_total Cumulative bans by jail"
    echo "# TYPE fail2ban_banned_total counter"
    printf '%s' "$TOTAL_LINES"

} > "$TMP"

# mktemp creates 0600; node_exporter runs unprivileged and needs read
chmod 0644 "$TMP"
mv "$TMP" "$OUT"
chmod 0644 "$OUT"
chown "${OWNER}:${OWNER}" "$OUT" 2>/dev/null || true

trap - EXIT
METRICS_EOF

    sed -i "s|__TEXTFILE_DIR__|${TEXTFILE_DIR}|g; s|__NE_USER__|${NE_USER}|g" "$METRICS_SCRIPT"
    ok "Metrics script written"
}

# ===========================================================================
# Step 6 — validate the metrics script
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

    if grep -q '__TEXTFILE_DIR__\|__NE_USER__' "$METRICS_SCRIPT"; then
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

run_metrics_once() {
    step "Step 7: Manual run"

    "$METRICS_SCRIPT" || die "Metrics script exited non-zero."
    PROM="${TEXTFILE_DIR}/fail2ban.prom"
    [ -s "$PROM" ] || die "$PROM missing or empty."

    ls -l "$PROM" | indent
    head -3 "$PROM" | indent

    check_readable_by_exporter
    lint_prom_file
}

# ===========================================================================
# Step 8 — timer
# ===========================================================================

install_timer() {
    step "Step 8: Install service and timer (every $INTERVAL)"

    cat > "$SERVICE_UNIT" <<EOF
[Unit]
Description=Fail2Ban Prometheus Metrics
After=fail2ban.service

[Service]
Type=oneshot
ExecStart=${METRICS_SCRIPT}
EOF

    # AccuracySec=1s is required — systemd defaults to 1 minute, which would
    # stretch a 30s interval into minute-long gaps.
    cat > "$TIMER_UNIT" <<EOF
[Unit]
Description=Run Fail2Ban Prometheus metrics every ${INTERVAL}

[Timer]
OnBootSec=${INTERVAL}
OnUnitActiveSec=${INTERVAL}
AccuracySec=1s
Unit=fail2ban-metrics.service

[Install]
WantedBy=timers.target
EOF

    chmod 0644 "$SERVICE_UNIT" "$TIMER_UNIT"
    systemctl daemon-reload
    systemctl enable --now fail2ban-metrics.timer >/dev/null 2>&1
    systemctl is-enabled --quiet fail2ban-metrics.timer || die "Timer not enabled."
    systemctl list-timers --all 2>/dev/null | grep -i fail2ban | indent || true
    ok "fail2ban-metrics.timer enabled and started"
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
    count="$(curl -sf "localhost:${EXPORTER_PORT}/metrics" 2>/dev/null | grep -c '^fail2ban' || true)"
    [ "${count:-0}" -gt 0 ] \
        && ok "${count} fail2ban* series exposed on :${EXPORTER_PORT}" \
        || warn "No fail2ban* series on :${EXPORTER_PORT} yet."
}

verify_after_timer() {
    # Wait past one full interval so the check lands after a timer-driven run.
    local wait_secs pre post
    wait_secs=$(( $(interval_to_seconds "$INTERVAL") + 5 ))

    step "Step 9: Verify after a timer-driven run (waiting ${wait_secs}s)"

    pre="$(stat -c '%Y' "$PROM")"
    sleep "$wait_secs"
    post="$(stat -c '%Y' "$PROM")"

    [ "$post" != "$pre" ] \
        && ok "Timer rewrote the file" \
        || warn "File not rewritten. Check: journalctl -u fail2ban-metrics.service -n 30"

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
  fail2ban         : ${F2B_ACTIVE} / ${F2B_ENABLED}
  exporter         : ${NE_UNIT:-<none>} as ${NE_USER}
  textfile dir     : ${TEXTFILE_DIR}
  output           : ${PROM} (mode ${MODE})
  timer            : fail2ban-metrics.timer every ${INTERVAL}
  local address    : $(hostname -I 2>/dev/null | awk '{print $1}'):${EXPORTER_PORT}
                     (behind NAT? Prometheus needs the address it can reach,
                      not this one -- verify with a curl from the monitor)

Next, on the monitoring server: add this target to prometheus.yml, install the
alert rules, promtool check config, then 'systemctl reload prometheus'.
EOF
}

# ===========================================================================
# Orchestration
# ===========================================================================

phase_interactive() {
    ask_monitor_ip
    verify_fail2ban
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

# Allow `source ./setup_fail2ban_metrics.sh --source-only` to load the
# functions without running anything, for step-by-step debugging.
case "${1:-}" in
    --source-only) init_colors; SOURCE_ONLY=1 ;;
    *) main "$@" ;;
esac
