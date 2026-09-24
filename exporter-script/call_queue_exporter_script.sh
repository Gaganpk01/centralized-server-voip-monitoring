#!/usr/bin/env bash
#
# install_call_queue_metrics.sh — the whole Call Queue runbook, Steps 1-14.
#
# Structured as one function per step, orchestrated by main() at the bottom.
# Every function is independently callable, so you can source this file and run
# a single step while debugging:
#
#   source ./install_call_queue_metrics.sh --source-only
#   probe_queue_schema
#   probe_agent_codes
#   run_metrics_once
#
# call_queue is not a package you install; it is your own service. This script
# does everything around it: identifies the unit, stores Mongo credentials,
# discovers the schema and agent status codes, indexes the queried fields,
# installs the metrics script and timer, and opens the firewall.
#
#   Step 1   identify the unit, confirm active, report NRestarts
#   Step 2   find the Mongo URI in the call agent source, verify it connects
#   Step 7   store MONGO_URI in a 0600 file, out of the script and history
#   Step 3   discover the schema across the four queue collections
#   Step 4   discover agent status codes and breakcode mappings
#   Step 12  index the queried fields (offered, not forced)
#   Step 5   detect node_exporter and enable the textfile collector
#   Step 6   create the textfile directory, both levels traversable at 0755
#   Step 8   install /usr/local/bin/call_queue_metrics.sh
#   Step 9   validate it (bash -n, chmod count, and the HELP-block count)
#   Step 10  run once, time it, check readability, lint the format
#   Step 13  install call-queue-metrics.service and .timer, AccuracySec=1s
#   Step 14  verify the mode SURVIVES a timer run, then scrape :PORT/metrics
#   Step 14b open the firewall for the monitoring server
#
# VARIANTS
#   minimal  service up / uptime only. No Mongo queries, no python3 needed.
#   full     adds live queue depth, longest wait, agents by status code,
#            inbound/outbound/answered/abandoned counters, service level,
#            and cumulative handle / wait / ring seconds.
#   auto     use full if Mongo answers and python3 exists (default).
#
# The timer defaults to 15s because queue depth and longest wait are live
# values. If the metrics script takes over 3s, the interval is raised to 30s
# automatically -- a collector that overruns its own timer is worse than a
# slightly staler number.
#
# Every prompt happens in the first phase, so the slow part runs unattended.
# Safe to re-run. Existing credentials are reused unless --reset-creds.
#
# Usage:
#   sudo ./install_call_queue_metrics.sh
#   sudo ./install_call_queue_metrics.sh --sl-threshold 30 --interval 30s
#   sudo ./install_call_queue_metrics.sh --variant minimal --no-mongo
#   sudo ./install_call_queue_metrics.sh --no-firewall --create-indexes
#   sudo ./install_call_queue_metrics.sh --uninstall
#
set -euo pipefail

# ===========================================================================
# Configuration
# ===========================================================================
SERVICE="call_queue"
DB="db_pbxcc"
COLLECTION="cdrs"
CREDS="/etc/default/call-queue-metrics"
AGENT_SRC="/usr/share/freeswitch/scripts/cdrs/call_agent.py"
SL_THRESHOLD="20"

MONITOR_IP=""
EXPORTER_PORT="9101"
TEXTFILE_DIR="/var/lib/node_exporter/textfile_collector"
METRICS_SCRIPT="/usr/local/bin/call_queue_metrics.sh"
INTERVAL="15s"
INTERVAL_EXPLICIT=0
VARIANT="auto"

SKIP_FIREWALL=0
SKIP_MONGO=0
RESET_CREDS=0
CREATE_INDEXES=0
PURGE_CREDS=0
UNINSTALL=0
SOURCE_ONLY=0

SERVICE_UNIT="/etc/systemd/system/call-queue-metrics.service"
TIMER_UNIT="/etc/systemd/system/call-queue-metrics.timer"
DROPIN_DIR="/etc/systemd/system/node_exporter.service.d"
DROPIN_FILE="${DROPIN_DIR}/10-textfile-collector.conf"

# Runtime state shared between steps.
Q_ACTIVE=""; Q_ENABLED=""; NRESTARTS="0"; SVC_USER="root"
HAVE_CREDS=0; TOTAL_CDRS="n/a"
EXPECTED_HELP=0; RUN_MS=0
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
indent()  { sed 's/^/    /'; }
indent6() { sed 's/^/      /'; }

# ===========================================================================
# Small utilities
# ===========================================================================

usage() { sed -n '3,54p' "$0" | sed 's/^# \{0,1\}//'; }

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
    # "15s" -> 15, "2m" -> 120. Used to size the Step 14 wait.
    local n
    n="$(printf '%s' "$1" | tr -dc '0-9')"
    is_number "$n" || { printf '15'; return 0; }
    case "$1" in *m|*min) n=$((n * 60)) ;; esac
    printf '%s' "$n"
}

redact_uri() {
    # mongodb://user:secret@host -> mongodb://user:***@host
    sed -E 's#(mongodb://[^:]*:)[^@]*@#\1***@#g'
}

urlenc() {
    # Percent-encode a password for safe use inside a mongodb:// URI.
    python3 -c 'import sys,urllib.parse;sys.stdout.write(urllib.parse.quote(sys.argv[1],safe=""))' "$1"
}

mongo_eval() {
    # Single place for the mongosh invocation so every caller is consistent.
    mongosh "$MONGO_URI" --quiet --eval "$1" 2>/dev/null
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
            --service)        SERVICE="${2:?}"; shift 2 ;;
            --variant)        VARIANT="${2:?}"; shift 2 ;;
            --db)             DB="${2:?}"; shift 2 ;;
            --collection)     COLLECTION="${2:?}"; shift 2 ;;
            --creds-file)     CREDS="${2:?}"; shift 2 ;;
            --agent-src)      AGENT_SRC="${2:?}"; shift 2 ;;
            --sl-threshold)   SL_THRESHOLD="${2:?}"; shift 2 ;;
            --port)           EXPORTER_PORT="${2:?}"; shift 2 ;;
            --textfile-dir)   TEXTFILE_DIR="${2:?}"; shift 2 ;;
            --interval)       INTERVAL="${2:?}"; INTERVAL_EXPLICIT=1; shift 2 ;;
            --reset-creds)    RESET_CREDS=1; shift ;;
            --create-indexes) CREATE_INDEXES=1; shift ;;
            --no-mongo)       SKIP_MONGO=1; shift ;;
            --no-firewall)    SKIP_FIREWALL=1; shift ;;
            --purge-creds)    PURGE_CREDS=1; shift ;;
            --uninstall)      UNINSTALL=1; shift ;;
            --source-only)    SOURCE_ONLY=1; shift ;;
            -h|--help)        usage; exit 0 ;;
            *) die "Unknown option: $1 (try --help)" ;;
        esac
    done

    case "$VARIANT" in auto|minimal|full) ;; *) die "--variant must be auto, minimal or full." ;; esac
    is_number "$SL_THRESHOLD"  || die "--sl-threshold must be an integer (seconds)."
    is_number "$EXPORTER_PORT" || die "--port must be numeric (got '$EXPORTER_PORT')."
    [ "$SKIP_MONGO" -eq 1 ] && [ "$VARIANT" = "full" ] \
        && die "--no-mongo and --variant full are contradictory."
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
    step "Removing the Call Queue metrics exporter"
    systemctl disable --now call-queue-metrics.timer >/dev/null 2>&1 || true
    systemctl stop call-queue-metrics.service >/dev/null 2>&1 || true
    rm -f "$TIMER_UNIT" "$SERVICE_UNIT" "$METRICS_SCRIPT" "${TEXTFILE_DIR}/call_queue.prom"
    systemctl daemon-reload
    ok "Removed timer, service, metrics script and call_queue.prom."
    if [ "$PURGE_CREDS" -eq 1 ]; then
        rm -f "$CREDS"; ok "Removed ${CREDS}."
    else
        warn "Kept ${CREDS} (pass --purge-creds to delete it)."
    fi
    warn "Left alone: ${SERVICE}, the node_exporter drop-in, Mongo indexes, firewall rules."
}

# ===========================================================================
# Step 1 — identify the unit
# ===========================================================================

warn_if_flapping() {
    case "${NRESTARTS:-0}" in
        ''|0) return 0 ;;
    esac
    is_number "$NRESTARTS" || return 0
    [ "$NRESTARTS" -ge 5 ] || return 0
    warn "${NRESTARTS} restarts — the service is flapping."
    warn "Metrics will show queue_service_up 1 between crashes, which hides it."
    warn "Check: journalctl -u ${SERVICE} -n 50"
}

identify_unit() {
    step "Step 1: Identify the Call Queue unit"

    local matches
    matches="$(systemctl list-unit-files 2>/dev/null | grep -i queue | awk '{print $1}' || true)"
    if [ -n "$matches" ]; then
        printf '    units matching "queue":\n'
        printf '%s\n' "$matches" | indent6
    else
        warn "No unit files matching 'queue' found."
    fi

    systemctl list-unit-files "${SERVICE}.service" --no-legend 2>/dev/null | grep -q . \
        || die "Unit '${SERVICE}.service' does not exist. Pick one from the list above and pass --service."

    Q_ACTIVE="$(systemctl is-active "$SERVICE" 2>/dev/null || true)"
    Q_ENABLED="$(systemctl is-enabled "$SERVICE" 2>/dev/null || true)"
    NRESTARTS="$(systemctl show "$SERVICE" -p NRestarts --value 2>/dev/null || true)"
    NRESTARTS="${NRESTARTS:-0}"
    printf '    unit       : %s.service\n    is-active  : %s\n    is-enabled : %s\n    NRestarts  : %s\n' \
        "$SERVICE" "$Q_ACTIVE" "$Q_ENABLED" "$NRESTARTS"

    # Not fatal — queue_service_up reporting 0 is legitimate output.
    [ "$Q_ACTIVE" = "active" ] || warn "${SERVICE} is not active; queue_service_up will report 0."
    case "$Q_ENABLED" in
        enabled|enabled-runtime|static|indirect) ;;
        *) warn "${SERVICE} is not enabled at boot (state: ${Q_ENABLED:-unknown})." ;;
    esac
    warn_if_flapping

    printf '    ExecStart:\n'
    systemctl cat "$SERVICE" 2>/dev/null | grep -E '^(ExecStart|Environment)' | indent6 || true
    SVC_USER="$(systemctl show "$SERVICE" -p User --value 2>/dev/null || true)"
    SVC_USER="${SVC_USER:-root}"
}

# ===========================================================================
# Step 2 — Mongo URI in the source
# ===========================================================================

check_source_permissions() {
    # These sources hold a plaintext DB password. Report only: a blind chmod
    # can break a service running as a different user.
    local mode
    mode="$(stat -c '%a' "$AGENT_SRC")"
    printf '    %s  mode %s  owner %s\n' "$AGENT_SRC" "$mode" "$(stat -c '%U:%G' "$AGENT_SRC")"
    case "$mode" in
        *[04567])
            warn "World-readable and it contains a plaintext DB password."
            warn "The service runs as '${SVC_USER}'. Tighten it yourself once sure:"
            warn "  chown ${SVC_USER}:${SVC_USER} ${AGENT_SRC} && chmod 600 ${AGENT_SRC}"
            ;;
        *) ok "Not world-readable." ;;
    esac
}

inspect_agent_source() {
    [ "$SKIP_MONGO" -eq 1 ] && return 0
    step "Step 2: Mongo URI in the call agent source"

    if [ ! -r "$AGENT_SRC" ]; then
        warn "${AGENT_SRC} not readable (see --agent-src)."
        return 0
    fi

    local found
    found="$(grep -n 'mongodb://\|MongoClient' "$AGENT_SRC" 2>/dev/null | head -3 || true)"
    if [ -n "$found" ]; then
        printf '%s\n' "$found" | redact_uri | indent6
    else
        warn "No connection string found in ${AGENT_SRC}."
    fi

    check_source_permissions
}

# ===========================================================================
# Monitoring server address
# ===========================================================================

ask_monitor_ip() {
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
# Step 7 — credentials
# ===========================================================================

build_mongo_uri() {
    # Echoes the URI on stdout; prompts go to stderr so nothing leaks in.
    local host port db user pass
    printf '    Host [127.0.0.1]: ' >&2;    read -r host; host="${host:-127.0.0.1}"
    printf '    Port [27017]: ' >&2;        read -r port; port="${port:-27017}"
    printf '    Database [%s]: ' "$DB" >&2; read -r db;   db="${db:-$DB}"
    printf '    Username (blank for no auth): ' >&2; read -r user
    DB="$db"
    if [ -z "$user" ]; then
        printf 'mongodb://%s:%s/%s' "$host" "$port" "$db"
        return 0
    fi
    printf '    Password (hidden): ' >&2; read -rs pass; printf '\n' >&2
    [ -n "$pass" ] || die "Password cannot be empty for user ${user}."
    printf 'mongodb://%s:%s@%s:%s/%s' "$user" "$(urlenc "$pass")" "$host" "$port" "$db"
}

write_creds_file() {
    local uri="$1"
    # Parentheses, not braces: a brace group runs in the current shell and the
    # umask would leak into every later file this script writes.
    ( umask 077; printf 'MONGO_URI=%s\n' "$uri" > "$CREDS" )
    chmod 0600 "$CREDS"
    chown root:root "$CREDS" 2>/dev/null || true
}

store_credentials() {
    step "Step 7: Mongo credentials"

    if [ "$SKIP_MONGO" -eq 1 ]; then
        ok "Skipped (--no-mongo)."
        VARIANT="minimal"
        return 0
    fi

    command -v mongosh >/dev/null 2>&1 \
        || die "mongosh is not installed. Install it, or use --no-mongo --variant minimal."
    # The full metrics script parses the aggregation result with python3.
    command -v python3 >/dev/null 2>&1 \
        || die "python3 is required by the full variant. Install it, or use --no-mongo --variant minimal."

    if [ -f "$CREDS" ] && [ "$RESET_CREDS" -eq 0 ]; then
        ok "Reusing existing ${CREDS} (pass --reset-creds to replace it)."
    elif [ ! -t 0 ]; then
        die "No terminal to ask for credentials on. Create ${CREDS} with a MONGO_URI= line, or use --no-mongo."
    else
        cat <<'EOF'
    Press Enter to build the URI from parts -- the password is not echoed and
    gets percent-encoded, so characters like @ : / # cannot corrupt it.
    Pasting a full URI works too, but it stays in your shell scrollback.
EOF
        local pasted uri
        printf '    MONGO_URI (blank to build): '
        read -r pasted
        pasted="$(printf '%s' "$pasted" | tr -d '[:space:]')"
        if [ -n "$pasted" ]; then
            uri="$pasted"
            warn "Pasted URI is now in your terminal history. Consider rotating the password."
        else
            uri="$(build_mongo_uri)"
        fi
        write_creds_file "$uri"
        unset uri pasted
        ok "Wrote ${CREDS}"
    fi

    ls -l "$CREDS" | indent
    local m
    m="$(stat -c '%a' "$CREDS")"
    [ "$m" = "600" ] || { chmod 0600 "$CREDS"; warn "Tightened ${CREDS} from ${m} to 600."; }

    # shellcheck disable=SC1090
    . "$CREDS"
    [ -n "${MONGO_URI:-}" ] || die "${CREDS} does not define MONGO_URI."
    HAVE_CREDS=1
}

verify_connection() {
    [ "$HAVE_CREDS" -eq 1 ] || return 0
    step "Verifying the connection"

    TOTAL_CDRS="$(mongosh "$MONGO_URI" --quiet \
        --eval "db.getCollection('${COLLECTION}').countDocuments({})" 2>&1 || true)"
    if ! is_number "$TOTAL_CDRS"; then
        printf '%s\n' "$TOTAL_CDRS" | head -5 | indent6
        die "Could not query ${COLLECTION}. Fix the URI first — this surfaces later as queue_mongo_up 0."
    fi
    ok "${COLLECTION} reachable: ${TOTAL_CDRS} documents"
}

# ===========================================================================
# Step 3 — queue schema
# ===========================================================================

print_duration_samples() {
    printf '\n    duration fields on recent calls (all values are SECONDS):\n'
    mongo_eval 'db.getCollection("'"$COLLECTION"'").find({}, {billsecond:1,
        hold_time:1, queue_time:1, total_duration:1, call_status:1,
        direction:1, _id:0}).limit(3).forEach(d => print("      " + JSON.stringify(d)))' || true
}

probe_queue_schema() {
    [ "$HAVE_CREDS" -eq 1 ] || return 0
    step "Step 3: Discover the queue schema"

    mongo_eval '
    ["call_queue","call_queue_agent","agent_live_report","'"$COLLECTION"'"].forEach(n => {
        let c, n_docs;
        try { c = db.getCollection(n); n_docs = c.countDocuments({}); }
        catch (e) { print("    === " + n + " (not readable)"); return; }
        print("    === " + n + " (" + n_docs + " docs)");
        const d = c.findOne();
        if (d) { Object.keys(d).sort().forEach(k => print("        " + k)); }
        else   { print("        <empty>"); }
    });' || warn "Schema probe failed."

    if [ "$TOTAL_CDRS" != "0" ]; then
        print_duration_samples
    else
        warn "${COLLECTION} is EMPTY — duration fields cannot be sampled and all"
        warn "counters will read 0 until calls flow. That is correct, not a fault."
    fi
}

# ===========================================================================
# Step 4 — agent status codes
# ===========================================================================

probe_agent_codes() {
    [ "$HAVE_CREDS" -eq 1 ] || return 0
    step "Step 4: Agent status codes"

    local codes breaks
    printf '    distinct agent_live_report.status values:\n'
    codes="$(mongo_eval 'db.agent_live_report.distinct("status")
        .forEach(v => print(JSON.stringify(v)))' || true)"
    if [ -n "$codes" ]; then
        printf '%s\n' "$codes" | indent6
    else
        warn "No agent status values yet (no agents have logged in)."
    fi

    printf '    breakcode documents:\n'
    breaks="$(mongo_eval 'db.breakcode.find().limit(10)
        .forEach(d => print(JSON.stringify(d)))' || true)"
    if [ -n "$breaks" ]; then
        printf '%s\n' "$breaks" | indent6
    else
        warn "breakcode is empty — you will have to observe codes live to map them."
    fi

    # Raw codes are exported as labels; naming them is a Grafana concern, so a
    # new code never breaks this collector.
    ok "Codes are exported raw as status_code labels; map them in Grafana."
}

resolve_variant() {
    if [ "$VARIANT" = "auto" ]; then
        if [ "$HAVE_CREDS" -eq 1 ]; then
            VARIANT="full"; ok "Mongo answered — using the full variant."
        else
            VARIANT="minimal"; warn "Mongo unavailable — using the minimal variant."
        fi
    fi
    [ "$VARIANT" = "full" ] && [ "$HAVE_CREDS" -eq 0 ] \
        && die "The full variant needs MONGO_URI in ${CREDS}."
    return 0
}

# ===========================================================================
# Step 12 — indexes
# ===========================================================================

list_indexes() {
    mongo_eval '
    ["'"$COLLECTION"'","call_queue","agent_live_report"].forEach(n => {
        try {
            db.getCollection(n).getIndexes().forEach(i =>
                print(n + ": " + JSON.stringify(i.key)));
        } catch (e) {}
    });' || true
}

missing_index_prefixes() {
    # An index only serves a query when the query fields match a LEADING PREFIX
    # of it, so checking whether a field appears anywhere in any index is not
    # enough — {user_uuid,direction,createdAt} cannot serve {direction,...},
    # and {call_status,createdAt} does not help a direction-led query either.
    mongo_eval '
    function firstKeys(n) {
        try { return db.getCollection(n).getIndexes().map(i => Object.keys(i.key)[0]); }
        catch (e) { return []; }
    }
    const miss = [];
    if (!firstKeys("'"$COLLECTION"'").includes("direction")) miss.push("'"$COLLECTION"'{direction,...}");
    if (!firstKeys("call_queue").includes("enqueued_at"))    miss.push("call_queue{enqueued_at}");
    if (!firstKeys("agent_live_report").includes("status"))  miss.push("agent_live_report{status}");
    print(miss.join(" "));' || true
}

create_indexes() {
    # background:true so the build does not block reads on a live box.
    mongosh "$MONGO_URI" --quiet --eval '
    db.getCollection("'"$COLLECTION"'").createIndex(
        { direction: 1, call_status: 1, queue_time: 1 }, { background: true });
    db.call_queue.createIndex({ enqueued_at: 1 }, { background: true });
    db.agent_live_report.createIndex({ status: 1 }, { background: true });
    print("indexes created");' 2>&1 | indent6
}

ensure_indexes() {
    step "Step 12: Indexes on the queried fields"

    if [ "$VARIANT" = "minimal" ]; then
        ok "The minimal variant runs no Mongo queries; no indexes needed."
        return 0
    fi

    printf '    existing indexes:\n'
    list_indexes | indent6

    local need
    need="$(missing_index_prefixes)"
    if [ -z "$need" ]; then
        ok "All three queried prefixes lead an index."
        return 0
    fi

    warn "Missing index prefix: ${need}"
    warn "This collector runs ~8 mongo ops per cycle including an aggregation"
    warn "over every answered call — unindexed, that is a full scan each time."

    local do_it="$CREATE_INDEXES" ans
    if [ "$do_it" -eq 0 ] && [ -t 0 ]; then
        printf '    Create them now? [y/N]: '
        read -r ans
        case "$ans" in [yY]*) do_it=1 ;; esac
    fi
    if [ "$do_it" -eq 1 ]; then
        create_indexes
        ok "Indexes created."
    else
        warn "Skipped. Create them before call volume arrives."
    fi
}

# ===========================================================================
# Step 5 — node_exporter
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
    step "Step 5: Detect node_exporter"

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
        echo "# Managed by install_call_queue_metrics.sh"
        echo "[Service]"
        echo "ExecStart="
        echo "ExecStart=${cur_exec} --collector.textfile.directory=${TEXTFILE_DIR}"
    } > "$DROPIN_FILE"
    chmod 0644 "$DROPIN_FILE"
}

enable_textfile_collector() {
    step "Step 5b: Enable textfile collector"

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
# Step 6 — textfile directory
# ===========================================================================

create_textfile_dir() {
    step "Step 6: Create textfile directory"

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
# Step 8 — write the metrics script
# ===========================================================================

emit_minimal_metrics_script() {
    cat > "$METRICS_SCRIPT" <<'METRICS_EOF'
#!/bin/bash
#
# Call queue metrics (minimal variant) for the node_exporter textfile
# collector. Service state only -- no Mongo queries, no python3 needed.
#

OUTPUT="__TEXTFILE_DIR__/call_queue.prom"
SERVICE="__SERVICE__"
OWNER="__NE_USER__"

mkdir -p "$(dirname "$OUTPUT")"
TMPFILE="$(mktemp "${OUTPUT}.XXXXXX")"
trap 'rm -f "$TMPFILE"' EXIT

NOW=$(date +%s)
BOOT=$((NOW - $(cut -d. -f1 /proc/uptime)))
UP=0; UPTIME=0

if systemctl is-active --quiet "${SERVICE}.service"; then
    UP=1
    MONO=$(systemctl show "${SERVICE}.service" \
        -p ActiveEnterTimestampMonotonic 2>/dev/null | cut -d= -f2)
    case "$MONO" in ''|*[!0-9]*) MONO=0 ;; esac
    if [ "$MONO" -gt 0 ]; then
        UPTIME=$((NOW - (BOOT + MONO / 1000000)))
        [ "$UPTIME" -lt 0 ] && UPTIME=0
    fi
fi

{
    echo "# HELP queue_service_up Call queue service status (1=up, 0=down)"
    echo "# TYPE queue_service_up gauge"
    echo "queue_service_up ${UP}"
    echo
    echo "# HELP queue_service_uptime_seconds Seconds the service has been active"
    echo "# TYPE queue_service_uptime_seconds gauge"
    echo "queue_service_uptime_seconds ${UPTIME}"
} > "$TMPFILE"

chmod 0644 "$TMPFILE"
mv "$TMPFILE" "$OUTPUT"
chmod 0644 "$OUTPUT"
chown "${OWNER}:${OWNER}" "$OUTPUT" 2>/dev/null || true
trap - EXIT
METRICS_EOF
}

emit_full_metrics_script() {
    cat > "$METRICS_SCRIPT" <<'METRICS_EOF'
#!/bin/bash
#
# Call queue and agent metrics for the node_exporter textfile collector.
#
# All duration fields in this schema are SECONDS.
#   queue_time  = wait in queue (waitsec in cdrs_posting.py)
#   billsecond  = talk time
#   hold_time   = hold duration
# There is no per-call wrap time; wrapped_by is a user id, not a duration.
#

OUTPUT="__TEXTFILE_DIR__/call_queue.prom"
DB="__DB__"
COLLECTION="__COLLECTION__"
SERVICE="__SERVICE__"
OWNER="__NE_USER__"
SL_THRESHOLD=__SL_THRESHOLD__

[ -r __CREDS__ ] && . __CREDS__
MONGO_TARGET="${MONGO_URI:-$DB}"

mkdir -p "$(dirname "$OUTPUT")"
TMPFILE="$(mktemp "${OUTPUT}.XXXXXX")"
trap 'rm -f "$TMPFILE"' EXIT

NOW=$(date +%s)
BOOT=$((NOW - $(cut -d. -f1 /proc/uptime)))
UP=0; UPTIME=0; MONGO_UP=0; AGENT_LINES=""

if systemctl is-active --quiet "${SERVICE}.service"; then
    UP=1
    MONO=$(systemctl show "${SERVICE}.service" \
        -p ActiveEnterTimestampMonotonic 2>/dev/null | cut -d= -f2)
    case "$MONO" in ''|*[!0-9]*) MONO=0 ;; esac
    if [ "$MONO" -gt 0 ]; then
        UPTIME=$((NOW - (BOOT + MONO / 1000000)))
        [ "$UPTIME" -lt 0 ] && UPTIME=0
    fi
fi

JSON=$(mongosh "$MONGO_TARGET" --quiet --eval '
try {
    const out = {};
    const SL = '"$SL_THRESHOLD"';
    const CDRS = db.getCollection("'"$COLLECTION"'");

    // Raw status codes; mapped to names in Grafana so a new code
    // never breaks this collector.
    out.agents = {};
    db.agent_live_report.aggregate([
        { $group: { _id: "$status", n: { $sum: 1 } } }
    ]).forEach(r => {
        out.agents[r._id === null ? "unknown" : String(r._id)] = r.n;
    });

    // Live queue - empty today, correct once populated
    const waiting = db.call_queue.find({}).toArray();
    out.waiting = waiting.length;
    let longest = 0;
    waiting.forEach(w => {
        const t = w.enqueued_at || w.createdAt;
        if (t) {
            const age = Math.floor((Date.now() - t.getTime()) / 1000);
            if (age > longest) longest = age;
        }
    });
    out.longest_wait = longest;

    // Cumulative counters
    out.inbound_total   = CDRS.countDocuments({ direction: "inbound" });
    out.outbound_total  = CDRS.countDocuments({ direction: "outbound" });
    out.answered_total  = CDRS.countDocuments({ direction: "inbound",
                                                call_status: "Answered" });
    out.abandoned_total = CDRS.countDocuments({ direction: "inbound",
                                                call_status: "Abandoned" });
    out.answered_in_sl  = CDRS.countDocuments({ direction: "inbound",
                                                call_status: "Answered",
                                                queue_time: { $lte: SL } });

    // Cumulative seconds so PromQL derives AHT/AWT over any window
    const s = CDRS.aggregate([
        { $match: { call_status: "Answered" } },
        { $group: { _id: null,
            handle: { $sum: { $add: [
                { $ifNull: ["$billsecond", 0] },
                { $ifNull: ["$hold_time",  0] } ] } },
            queue:  { $sum: { $ifNull: ["$queue_time", 0] } },
            ring:   { $sum: { $subtract: [
                { $ifNull: ["$total_duration", 0] },
                { $ifNull: ["$billsecond", 0] } ] } } } }
    ]).toArray();

    out.handle_seconds_total = s.length ? s[0].handle : 0;
    out.queue_seconds_total  = s.length ? s[0].queue  : 0;
    out.ring_seconds_total   = s.length ? Math.max(0, s[0].ring) : 0;

    print(JSON.stringify(out));
} catch (e) { print("ERR"); }
' 2>/dev/null)

get() { printf '%s' "$JSON" | python3 -c "
import sys,json
try:
    v=json.load(sys.stdin).get('$1',0)
    print(v if isinstance(v,(int,float)) else 0)
except Exception: print(0)"; }

if printf '%s' "$JSON" | python3 -c 'import sys,json; json.load(sys.stdin)' 2>/dev/null; then
    MONGO_UP=1
    WAITING=$(get waiting);             LONGEST=$(get longest_wait)
    INBOUND=$(get inbound_total);       OUTBOUND=$(get outbound_total)
    ANSWERED=$(get answered_total);     ABANDONED=$(get abandoned_total)
    IN_SL=$(get answered_in_sl)
    HANDLE=$(get handle_seconds_total); QUEUE=$(get queue_seconds_total)
    RING=$(get ring_seconds_total)

    AGENT_LINES=$(printf '%s' "$JSON" | python3 -c "
import sys,json
for k,v in sorted(json.load(sys.stdin).get('agents',{}).items()):
    print('queue_agents{status_code=\"%s\"} %d' % (k, v))")
fi

{
    echo "# HELP queue_service_up Call queue service status (1=up, 0=down)"
    echo "# TYPE queue_service_up gauge"
    echo "queue_service_up ${UP}"
    echo
    echo "# HELP queue_service_uptime_seconds Seconds the service has been active"
    echo "# TYPE queue_service_uptime_seconds gauge"
    echo "queue_service_uptime_seconds ${UPTIME}"
    echo
    echo "# HELP queue_mongo_up MongoDB reachable and queries succeeded"
    echo "# TYPE queue_mongo_up gauge"
    echo "queue_mongo_up ${MONGO_UP}"
    echo

    if [ "$MONGO_UP" -eq 1 ]; then
        echo "# HELP queue_agents Agents by raw status code"
        echo "# TYPE queue_agents gauge"
        [ -n "$AGENT_LINES" ] && printf '%s\n' "$AGENT_LINES"
        echo
        echo "# HELP queue_calls_waiting Calls currently waiting in queue"
        echo "# TYPE queue_calls_waiting gauge"
        echo "queue_calls_waiting ${WAITING}"
        echo
        echo "# HELP queue_longest_wait_seconds Age of the longest waiting call"
        echo "# TYPE queue_longest_wait_seconds gauge"
        echo "queue_longest_wait_seconds ${LONGEST}"
        echo
        echo "# HELP queue_calls_inbound_total Cumulative inbound calls"
        echo "# TYPE queue_calls_inbound_total counter"
        echo "queue_calls_inbound_total ${INBOUND}"
        echo
        echo "# HELP queue_calls_outbound_total Cumulative outbound calls"
        echo "# TYPE queue_calls_outbound_total counter"
        echo "queue_calls_outbound_total ${OUTBOUND}"
        echo
        echo "# HELP queue_calls_answered_total Cumulative inbound calls answered"
        echo "# TYPE queue_calls_answered_total counter"
        echo "queue_calls_answered_total ${ANSWERED}"
        echo
        echo "# HELP queue_calls_abandoned_total Cumulative inbound calls abandoned"
        echo "# TYPE queue_calls_abandoned_total counter"
        echo "queue_calls_abandoned_total ${ABANDONED}"
        echo
        echo "# HELP queue_answered_within_sl_total Cumulative calls answered within the SL threshold"
        echo "# TYPE queue_answered_within_sl_total counter"
        echo "queue_answered_within_sl_total ${IN_SL}"
        echo
        echo "# HELP queue_sl_threshold_seconds Service level target in seconds"
        echo "# TYPE queue_sl_threshold_seconds gauge"
        echo "queue_sl_threshold_seconds ${SL_THRESHOLD}"
        echo
        echo "# HELP queue_handle_seconds_total Cumulative handle time (billsecond + hold_time)"
        echo "# TYPE queue_handle_seconds_total counter"
        echo "queue_handle_seconds_total ${HANDLE}"
        echo
        echo "# HELP queue_wait_seconds_total Cumulative queue wait time"
        echo "# TYPE queue_wait_seconds_total counter"
        echo "queue_wait_seconds_total ${QUEUE}"
        echo
        echo "# HELP queue_ring_seconds_total Cumulative ring time (total_duration - billsecond)"
        echo "# TYPE queue_ring_seconds_total counter"
        echo "queue_ring_seconds_total ${RING}"
    fi
} > "$TMPFILE"

chmod 0644 "$TMPFILE"
mv "$TMPFILE" "$OUTPUT"
chmod 0644 "$OUTPUT"
chown "${OWNER}:${OWNER}" "$OUTPUT" 2>/dev/null || true
trap - EXIT
METRICS_EOF
}

substitute_placeholders() {
    sed -i \
        -e "s|__TEXTFILE_DIR__|${TEXTFILE_DIR}|g" \
        -e "s|__NE_USER__|${NE_USER}|g" \
        -e "s|__SERVICE__|${SERVICE}|g" \
        -e "s|__DB__|${DB}|g" \
        -e "s|__COLLECTION__|${COLLECTION}|g" \
        -e "s|__SL_THRESHOLD__|${SL_THRESHOLD}|g" \
        -e "s|__CREDS__|${CREDS}|g" \
        "$METRICS_SCRIPT"
}

write_metrics_script() {
    step "Step 8: Install ${METRICS_SCRIPT} (${VARIANT})"

    if [ "$VARIANT" = "minimal" ]; then
        EXPECTED_HELP=2
        emit_minimal_metrics_script
    else
        EXPECTED_HELP=15
        emit_full_metrics_script
    fi
    substitute_placeholders
    ok "Metrics script written (${VARIANT})"
}

# ===========================================================================
# Step 9 — validate
# ===========================================================================

validate_metrics_script() {
    step "Step 9: Validate"

    chmod +x "$METRICS_SCRIPT"

    # A truncated write loses the trailing chmod lines — exactly how the 0600
    # permission bug reappears. Count chmod COMMANDS at line start: a bare
    # `grep -c chmod` also matches prose in comments and would miscount.
    local chmod_count help_count
    chmod_count="$(grep -c '^chmod ' "$METRICS_SCRIPT" || true)"
    [ "$chmod_count" = "2" ] \
        || die "Expected 2 chmod commands, found ${chmod_count} — the file is truncated. Re-run."
    ok "chmod commands present: $chmod_count"

    # Independent truncation check: a partial write is far more likely to lose
    # emit blocks in the middle than the shebang at the top.
    help_count="$(grep -c 'echo "# HELP' "$METRICS_SCRIPT" || true)"
    [ "$help_count" = "$EXPECTED_HELP" ] \
        || die "Expected ${EXPECTED_HELP} HELP blocks, found ${help_count} — the file is truncated. Re-run."
    ok "HELP blocks present: ${help_count}"

    bash -n "$METRICS_SCRIPT" || die "Syntax error in $METRICS_SCRIPT"
    ok "Syntax OK — $(wc -l < "$METRICS_SCRIPT") lines"

    if grep -q '__TEXTFILE_DIR__\|__NE_USER__\|__SERVICE__\|__DB__\|__COLLECTION__\|__SL_THRESHOLD__\|__CREDS__' "$METRICS_SCRIPT"; then
        die "Placeholder substitution failed."
    fi
    ok "Placeholders substituted"
}

# ===========================================================================
# Step 10 — run once, time it, lint
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

check_mongo_up_metric() {
    [ "$VARIANT" = "full" ] || return 0
    local mu
    mu="$(awk '/^queue_mongo_up/ {print $2; exit}' "$PROM")"
    [ "$mu" = "1" ] \
        && ok "queue_mongo_up = 1" \
        || warn "queue_mongo_up = ${mu:-?} — queries failed; only service metrics present."
}

maybe_back_off_interval() {
    # A collector that overruns its own timer is worse than a staler number, so
    # back the interval off rather than stacking overlapping runs.
    [ "$RUN_MS" -gt 3000 ] || return 0
    if [ "$INTERVAL" = "15s" ] && [ "$INTERVAL_EXPLICIT" -eq 0 ]; then
        INTERVAL="30s"
        warn "Runtime ${RUN_MS} ms exceeds 3s — raising the interval to 30s."
        warn "Add the Step 12 indexes, then re-run with --interval 15s."
    else
        warn "Runtime ${RUN_MS} ms exceeds 3s at a ${INTERVAL} interval — add the indexes."
    fi
}

run_metrics_once() {
    step "Step 10: Manual run"

    local t0 t1
    t0="$(date +%s%N)"
    "$METRICS_SCRIPT" || die "Metrics script exited non-zero."
    t1="$(date +%s%N)"
    RUN_MS=$(( (t1 - t0) / 1000000 ))
    printf '    runtime: %s ms\n' "$RUN_MS"

    PROM="${TEXTFILE_DIR}/call_queue.prom"
    [ -s "$PROM" ] || die "$PROM missing or empty."

    ls -l "$PROM" | indent
    head -3 "$PROM" | indent

    check_readable_by_exporter
    lint_prom_file
    check_mongo_up_metric
    maybe_back_off_interval
}

# ===========================================================================
# Step 13 — timer
# ===========================================================================

install_timer() {
    step "Step 13: Install service and timer (every $INTERVAL)"

    cat > "$SERVICE_UNIT" <<EOF
[Unit]
Description=Call Queue Prometheus Metrics
After=mongod.service

[Service]
Type=oneshot
EnvironmentFile=-${CREDS}
ExecStart=${METRICS_SCRIPT}
EOF

    # AccuracySec=1s is required — systemd defaults to 1 minute, which would
    # stretch a 15s interval into minute-long gaps.
    cat > "$TIMER_UNIT" <<EOF
[Unit]
Description=Run Call Queue Prometheus metrics every ${INTERVAL}

[Timer]
OnBootSec=${INTERVAL}
OnUnitActiveSec=${INTERVAL}
AccuracySec=1s
Unit=call-queue-metrics.service

[Install]
WantedBy=timers.target
EOF

    chmod 0644 "$SERVICE_UNIT" "$TIMER_UNIT"
    systemctl daemon-reload
    systemctl enable --now call-queue-metrics.timer >/dev/null 2>&1
    systemctl is-enabled --quiet call-queue-metrics.timer || die "Timer not enabled."
    systemctl list-timers --all 2>/dev/null | grep -i call-queue | indent || true
    ok "call-queue-metrics.timer enabled and started"
}

# ===========================================================================
# Step 14 — verify after a timer run
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
    count="$(curl -sf "localhost:${EXPORTER_PORT}/metrics" 2>/dev/null | grep -c '^queue_' || true)"
    [ "${count:-0}" -gt 0 ] \
        && ok "${count} queue_* series exposed on :${EXPORTER_PORT}" \
        || warn "No queue_* series on :${EXPORTER_PORT} yet."
}

verify_after_timer() {
    local wait_secs pre post
    wait_secs=$(( $(interval_to_seconds "$INTERVAL") + 5 ))

    step "Step 14: Verify after a timer-driven run (waiting ${wait_secs}s)"

    pre="$(stat -c '%Y' "$PROM")"
    sleep "$wait_secs"
    post="$(stat -c '%Y' "$PROM")"

    [ "$post" != "$pre" ] \
        && ok "Timer rewrote the file" \
        || warn "File not rewritten. Check: journalctl -u call-queue-metrics.service -n 30"

    ls -l "$PROM" | indent
    MODE="$(stat -c '%a' "$PROM")"
    # THE decisive check. A manual run passing proves nothing — the failure mode
    # is the timer rewriting the file at 0600 one interval later.
    [ "$MODE" = "644" ] || die "$PROM is mode $MODE after the timer run, expected 644."
    ok "Mode survived the timer run: $MODE"

    check_scrape_error
}

# ===========================================================================
# Step 14b — firewall
# ===========================================================================

configure_firewall() {
    step "Step 14b: Firewall"

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
  unit             : ${SERVICE}.service (${Q_ACTIVE} / ${Q_ENABLED}, ${NRESTARTS} restarts)
  variant          : ${VARIANT}
  database         : ${DB}.${COLLECTION} (${TOTAL_CDRS} documents)
  SL threshold     : ${SL_THRESHOLD}s
  credentials      : ${CREDS}
  exporter         : ${NE_UNIT:-<none>} as ${NE_USER}
  textfile dir     : ${TEXTFILE_DIR}
  output           : ${PROM} (mode ${MODE})
  collector runtime: ${RUN_MS} ms
  timer            : call-queue-metrics.timer every ${INTERVAL}
  local address    : $(hostname -I 2>/dev/null | awk '{print $1}'):${EXPORTER_PORT}
                     (behind NAT? Prometheus needs the address it can reach,
                      not this one -- verify with a curl from the monitor)

Agent status codes are exported raw as status_code labels. Map them to names in
Grafana with label_replace once you know what each code means.

Next, on the monitoring server: add this target to prometheus.yml, install the
alert rules, promtool check config, then 'systemctl reload prometheus'.
EOF
}

# ===========================================================================
# Orchestration
# ===========================================================================

phase_interactive() {
    identify_unit
    inspect_agent_source
    ask_monitor_ip
    store_credentials
    verify_connection
    probe_queue_schema
    probe_agent_codes
    resolve_variant
    ensure_indexes
    ok "No further input needed — the rest runs unattended."
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

# Allow `source ./install_call_queue_metrics.sh --source-only` to load the
# functions without running anything, for step-by-step debugging.
case "${1:-}" in
    --source-only) init_colors; SOURCE_ONLY=1 ;;
    *) main "$@" ;;
esac
