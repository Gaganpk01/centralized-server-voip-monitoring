#!/usr/bin/env bash
#
# install_cdr_metrics.sh — CDR Prometheus exporter installer, Steps 1-12.
#
# Structured as one function per step, orchestrated by main() at the bottom.
# Every function is independently callable, so you can source this file and run
# a single step while debugging:
#
#   source ./install_cdr_metrics.sh --source-only
#   probe_values
#   run_metrics_once
#   lint_prom_file
#
# cdrpost is not a package you install; it is your own service. This script
# does everything around it: identifies the unit, stores the Mongo and fs_cli
# credentials, verifies the queried values actually exist, indexes the queried
# fields, installs the metrics script and timer, and opens the firewall.
#
#   Step 1   identify the unit, confirm active/enabled, find any Mongo URI
#   Step 5   store MONGO_URI in a 0600 file, out of the script and history
#   Step 1b  verify the queried values return non-zero counts
#   Step 9   index the queried fields (offered, not forced)
#   Step 2   detect node_exporter, its textfile directory and its user
#   Step 3   enable --collector.textfile.directory (systemd drop-in)
#   Step 4   create the textfile directory, both levels traversable at 0755
#   Step 6   install /usr/local/bin/cdr_metrics.sh
#   Step 7   validate it (bash -n + the chmod truncation check)
#   Step 8   run once, check readability, lint the exposition format
#   Step 10  install cdr-metrics.service and .timer, AccuracySec=1s
#   Step 11  verify the mode SURVIVES a timer run, then scrape :PORT/metrics
#   Step 12  open the firewall for the monitoring server
#
# METRICS  (this list is exhaustive — nothing else is exported)
#   cdr_post_up                                    gauge  service active (1/0)
#   cdr_post_start_time_seconds                    gauge  unix ts of activation
#   cdr_post_uptime_seconds                        gauge  seconds active
#   cdr_post_mongo_up                              gauge  queries succeeded
#   cdr_campaign_reports_count                     gauge  campaign_report docs
#   cdr_calls_direction_count{direction="inbound"}   gauge
#   cdr_calls_direction_count{direction="outbound"}  gauge
#   cdr_calls_status_count{call_status="Answered"}   gauge
#   cdr_calls_status_count{call_status="Abandoned"}  gauge
#   cdr_calls_status_count{call_status="Drop"}       gauge
#   cdr_calls_status_count{call_status="Ringing"}    gauge
#   cdr_agents_count                               gauge  SIP registrations
#
#   The counts are gauges, not counters. They are countDocuments() over a live
#   collection: a purge, an archive job or a TTL index makes them fall, and a
#   counter that falls is read by PromQL as a reset. Use delta() over a window.
#
# VARIANTS
#   minimal  service up / start time / uptime only. No Mongo, no fs_cli.
#   full     everything above (default).
#
# FREESWITCH PASSWORD
#   FS_CLI_PASSWORD is set in the Configuration block below and is copied into
#   /usr/local/bin/cdr_metrics.sh, which is therefore mode 0700, root-owned.
#   Two consequences worth knowing:
#     - fs_cli -p puts it in the process list for the length of each call, so
#       `ps aux` from any local account can read it every interval.
#     - anyone with read access to this installer has it too. Keep it 0600.
#   To avoid both, blank FS_CLI_PASSWORD and put the password in a [default]
#   section of /etc/fs_cli.conf instead. An FS_CLI_PASSWORD= line in the creds
#   file overrides the baked-in value at runtime, for rotation without a
#   reinstall.
#
# Every prompt happens in the first phase, so the slow part runs unattended.
# Safe to re-run. Existing credentials are reused unless --reset-creds.
#
# Usage:
#   sudo ./install_cdr_metrics.sh
#   sudo ./install_cdr_metrics.sh --variant minimal --no-mongo
#   sudo ./install_cdr_metrics.sh --service cdrpost --interval 60s
#   sudo ./install_cdr_metrics.sh --fs-password 'newpassword'
#   sudo ./install_cdr_metrics.sh --fs-command 'show channels count'
#   sudo ./install_cdr_metrics.sh --no-fscli --create-indexes
#   sudo ./install_cdr_metrics.sh --no-firewall
#   sudo ./install_cdr_metrics.sh --uninstall
#
set -euo pipefail

# ===========================================================================
# Configuration
# ===========================================================================
SERVICE="cdrpost"
DB="db_pbxcc"
COLLECTION="cdrs"
CAMPAIGN_COLLECTION="campaign_report"
CREDS="/etc/default/cdr-metrics"
CDR_SCRIPT_DIR="/usr/share/freeswitch/scripts/cdrs/"

# FreeSWITCH event socket password, baked into the generated metrics script.
# Override per-run with --fs-password, or leave empty to fall back to
# /etc/fs_cli.conf. An FS_CLI_PASSWORD= line in the creds file still wins over
# this at runtime, so you can rotate without regenerating anything.
FS_CLI_PASSWORD="X5ISJYqncYxFnUwcU18y"

# The fs_cli command behind cdr_agents_count. Must answer with an "N total."
# line -- that is what the parser anchors on. Any `show <thing> count` works:
# "show registrations count", "show channels count", "show calls count".
FS_CLI_COMMAND="show registrations count"

MONITOR_IP=""
EXPORTER_PORT="9101"
TEXTFILE_DIR="/var/lib/node_exporter/textfile_collector"
METRICS_SCRIPT="/usr/local/bin/cdr_metrics.sh"
PROM_NAME="cdrs_post.prom"
INTERVAL="30s"
VARIANT="full"

SKIP_FIREWALL=0
SKIP_MONGO=0
SKIP_FSCLI=0
RESET_CREDS=0
CREATE_INDEXES=0
PURGE_CREDS=0
UNINSTALL=0
SOURCE_ONLY=0

SERVICE_UNIT="/etc/systemd/system/cdr-metrics.service"
TIMER_UNIT="/etc/systemd/system/cdr-metrics.timer"
DROPIN_DIR="/etc/systemd/system/node_exporter.service.d"
DROPIN_FILE="${DROPIN_DIR}/10-textfile-collector.conf"

# The queried values, exactly as requested. These are NOT discovered at
# runtime: an aggregation that groups over the whole collection is a full
# scan every interval, while countDocuments on one indexed equality match is
# a counted index scan. Step 1b checks each one returns something.
DIRECTION_VALUES=(inbound outbound)
CALL_STATUS_VALUES=(Answered Abandoned Drop Ringing)

# Runtime state shared between steps.
CDR_ACTIVE=""; CDR_ENABLED=""
HAVE_CREDS=0; DOC_COUNT="n/a"; CAMPAIGN_COUNT="n/a"
HAS_CAMPAIGNS=0; HAS_AGENTS=0; AGENT_COUNT="n/a"; SCHEMA_UNKNOWN=0
FS_CLI_BIN=""
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

usage() {
    # BASH_SOURCE, not $0: when the file is sourced for debugging, $0 is the
    # interactive shell and sed would read the wrong file (or nothing).
    sed -n '3,/^set -euo pipefail$/p' "${BASH_SOURCE[0]}" \
        | sed -e '$d' -e 's/^# \{0,1\}//' -e 's/^#$//'
}

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
    # "30s" -> 30, "2m" -> 120. Used to size the Step 11 wait.
    local n
    n="$(printf '%s' "$1" | tr -dc '0-9')"
    is_number "$n" || { printf '30'; return 0; }
    case "$1" in *m|*min) n=$((n * 60)) ;; esac
    printf '%s' "$n"
}

redact_uri() {
    # mongodb://user:secret@host -> mongodb://user:***@host
    sed -E 's#(mongodb(\+srv)?://[^:/]*:)[^@]*@#\1***@#g'
}

urlenc() {
    # Percent-encode a password for safe use inside a mongodb:// URI.
    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import sys,urllib.parse;sys.stdout.write(urllib.parse.quote(sys.argv[1],safe=""))' "$1"
    else
        printf '%s' "$1" | sed -e 's/%/%25/g' -e 's/@/%40/g' -e 's/:/%3A/g' \
            -e 's#/#%2F#g' -e 's/?/%3F/g' -e 's/#/%23/g' \
            -e 's/\[/%5B/g' -e 's/\]/%5D/g'
    fi
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
            --service)         SERVICE="${2:?}"; shift 2 ;;
            --variant)         VARIANT="${2:?}"; shift 2 ;;
            --db)              DB="${2:?}"; shift 2 ;;
            --collection)      COLLECTION="${2:?}"; shift 2 ;;
            --campaign-collection) CAMPAIGN_COLLECTION="${2:?}"; shift 2 ;;
            --fs-password)     FS_CLI_PASSWORD="${2:?}"; shift 2 ;;
            --fs-command)      FS_CLI_COMMAND="${2:?}"; shift 2 ;;
            --creds-file)      CREDS="${2:?}"; shift 2 ;;
            --cdr-script-dir)  CDR_SCRIPT_DIR="${2:?}"; shift 2 ;;
            --port)            EXPORTER_PORT="${2:?}"; shift 2 ;;
            --textfile-dir)    TEXTFILE_DIR="${2:?}"; shift 2 ;;
            --interval)        INTERVAL="${2:?}"; shift 2 ;;
            --reset-creds)     RESET_CREDS=1; shift ;;
            --create-indexes)  CREATE_INDEXES=1; shift ;;
            --no-mongo)        SKIP_MONGO=1; shift ;;
            --no-fscli)        SKIP_FSCLI=1; shift ;;
            --no-firewall)     SKIP_FIREWALL=1; shift ;;
            --purge-creds)     PURGE_CREDS=1; shift ;;
            --uninstall)       UNINSTALL=1; shift ;;
            --source-only)     SOURCE_ONLY=1; shift ;;
            -h|--help)         usage; exit 0 ;;
            *) die "Unknown option: $1 (try --help)" ;;
        esac
    done

    case "$VARIANT" in
        minimal|full) ;;
        *) die "--variant must be minimal or full (got '$VARIANT')." ;;
    esac
    is_number "$EXPORTER_PORT" || die "--port must be numeric (got '$EXPORTER_PORT')."
    [ "$EXPORTER_PORT" -ge 1 ] && [ "$EXPORTER_PORT" -le 65535 ] \
        || die "--port out of range (got '$EXPORTER_PORT')."
    [ "$(interval_to_seconds "$INTERVAL")" -ge 5 ] \
        || die "--interval below 5s is not useful; Prometheus scrapes far less often."
    [ "$SKIP_MONGO" -eq 1 ] && [ "$VARIANT" = "full" ] \
        && die "--no-mongo and --variant full are contradictory (use --variant minimal)."
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
    step "Removing the CDR metrics exporter"
    systemctl disable --now cdr-metrics.timer >/dev/null 2>&1 || true
    systemctl stop cdr-metrics.service >/dev/null 2>&1 || true
    rm -f "$TIMER_UNIT" "$SERVICE_UNIT" "$METRICS_SCRIPT" "${TEXTFILE_DIR}/${PROM_NAME}"
    systemctl daemon-reload
    ok "Removed timer, service, metrics script and ${PROM_NAME}."
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

show_cdr_script_uris() {
    [ "$SKIP_MONGO" -eq 1 ] && return 0
    printf '    Mongo URIs referenced by the CDR scripts:\n'
    local found
    found="$(grep -rn 'mongodb://\|MongoClient' "$CDR_SCRIPT_DIR" 2>/dev/null | head -3 || true)"
    if [ -n "$found" ]; then
        # Redact the password before printing it to a terminal or a log.
        printf '%s\n' "$found" | redact_uri | indent6
    else
        warn "Nothing found under ${CDR_SCRIPT_DIR} (path may differ; see --cdr-script-dir)."
    fi
    return 0
}

identify_unit() {
    step "Step 1: Identify the CDR-post unit"

    local matches
    matches="$(systemctl list-unit-files 2>/dev/null | grep -i cdr | awk '{print $1}' || true)"
    if [ -n "$matches" ]; then
        printf '    units matching "cdr":\n'
        printf '%s\n' "$matches" | indent6
    else
        warn "No unit files matching 'cdr' found."
    fi

    systemctl list-unit-files "${SERVICE}.service" --no-legend 2>/dev/null | grep -q . \
        || die "Unit '${SERVICE}.service' does not exist. Pick one from the list above and pass --service."

    CDR_ACTIVE="$(systemctl is-active "$SERVICE" 2>/dev/null || true)"
    CDR_ENABLED="$(systemctl is-enabled "$SERVICE" 2>/dev/null || true)"
    printf '    unit       : %s.service\n    is-active  : %s\n    is-enabled : %s\n' \
        "$SERVICE" "$CDR_ACTIVE" "$CDR_ENABLED"

    # Not fatal — cdr_post_up reporting 0 is legitimate output, and the exporter
    # should be installed even while the service is down.
    [ "$CDR_ACTIVE" = "active" ] || warn "${SERVICE} is not active; cdr_post_up will report 0."
    case "$CDR_ENABLED" in
        enabled|enabled-runtime|static|indirect) ;;
        *) warn "${SERVICE} is not enabled at boot (state: ${CDR_ENABLED:-unknown})." ;;
    esac

    printf '    ExecStart / Environment:\n'
    systemctl cat "$SERVICE" 2>/dev/null | grep -E '^(ExecStart|Environment)' | indent6 || true

    show_cdr_script_uris
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
# Step 5 — credentials
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
    # Parentheses, not braces: a brace group runs in the current shell and the
    # umask would leak into every later file this script writes.
    local uri="$1"
    ( umask 077; printf 'MONGO_URI=%s\n' "$uri" > "$CREDS" )
    chmod 0600 "$CREDS"
    chown root:root "$CREDS" 2>/dev/null || true
}

store_credentials() {
    step "Step 5: Credentials"

    if [ "$SKIP_MONGO" -eq 1 ]; then
        ok "Mongo skipped (--no-mongo)."
        VARIANT="minimal"
        return 0
    fi

    command -v mongosh >/dev/null 2>&1 \
        || die "mongosh is not installed. Install it, or use --no-mongo --variant minimal."

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

    DOC_COUNT="$(mongosh "$MONGO_URI" --quiet \
        --eval "db.getCollection('${COLLECTION}').countDocuments({})" 2>&1 || true)"
    if ! is_number "$DOC_COUNT"; then
        printf '%s\n' "$DOC_COUNT" | head -5 | redact_uri | indent6
        die "Could not query ${COLLECTION}. Fix the URI first — this surfaces later as cdr_post_mongo_up 0."
    fi
    ok "${COLLECTION} reachable: ${DOC_COUNT} documents"
}

# ===========================================================================
# Step 1b — verify the queried values
# ===========================================================================

# Every value is hardcoded, so the one failure that matters is a value that is
# spelled differently in the data: the series then reads 0 forever while
# cdr_post_mongo_up cheerfully reports 1. Check each one now, loudly.
check_queried_values() {
    local field="$1"; shift
    local v n zero=""
    for v in "$@"; do
        n="$(mongo_eval 'print(db.getCollection("'"$COLLECTION"'").countDocuments({ '"$field"': "'"$v"'" }))' || true)"
        is_number "$n" || n="?"
        printf '      %-12s %-12s %s\n' "$field" "$v" "$n"
        [ "$n" = "0" ] && zero="${zero} ${v}"
    done
    if [ -n "$zero" ]; then
        warn "Zero documents for${zero} — check the exact spelling and case in your data."
        warn "These series will exist but sit at 0 until the application writes that value."
    fi
    return 0
}

show_distinct() {
    local field="$1"
    printf '    distinct %s values actually present:\n' "$field"
    mongo_eval '
    db.getCollection("'"$COLLECTION"'").distinct("'"$field"'")
      .filter(v => v !== null && v !== undefined)
      .map(v => String(v)).sort()
      .forEach(v => print("      " + JSON.stringify(v)));' || true
    return 0
}

probe_campaign_collection() {
    # estimatedDocumentCount reads collection metadata; countDocuments({}) on a
    # large collection is a full scan for a number nobody needs to be exact.
    # The metric itself uses countDocuments() as requested -- this is only the
    # install-time reachability check.
    CAMPAIGN_COUNT="$(mongo_eval '
    try { print(db.getCollection("'"$CAMPAIGN_COLLECTION"'").estimatedDocumentCount()); }
    catch (e) { print("ERR"); }' || true)"
    if is_number "$CAMPAIGN_COUNT"; then
        HAS_CAMPAIGNS=1
        ok "${CAMPAIGN_COLLECTION}: ~${CAMPAIGN_COUNT} documents"
    else
        CAMPAIGN_COUNT="n/a"
        warn "${CAMPAIGN_COLLECTION} is not readable in this database."
        warn "cdr_campaign_reports_count will be omitted (see --campaign-collection)."
    fi
    return 0
}

probe_values() {
    [ "$HAVE_CREDS" -eq 1 ] || return 0
    step "Step 1b: Verify the queried values"

    if [ "$DOC_COUNT" = "0" ]; then
        warn "${COLLECTION} is EMPTY — every count would read 0."
        warn "The exporter still installs; re-check once CDRs exist."
        SCHEMA_UNKNOWN=1
        probe_campaign_collection
        return 0
    fi

    printf '    document counts for the values this exporter queries:\n'
    check_queried_values direction   ${DIRECTION_VALUES[@]+"${DIRECTION_VALUES[@]}"}
    check_queried_values call_status ${CALL_STATUS_VALUES[@]+"${CALL_STATUS_VALUES[@]}"}

    printf '\n'
    show_distinct direction
    show_distinct call_status

    printf '\n'
    probe_campaign_collection
    return 0
}

# ===========================================================================
# Step 1c — fs_cli agent count
# ===========================================================================

detect_fs_cli() {
    [ "$SKIP_FSCLI" -eq 1 ] && { ok "fs_cli skipped (--no-fscli)."; return 0; }
    [ "$VARIANT" = "minimal" ] && return 0

    step "Step 1c: FreeSWITCH registration count"

    FS_CLI_BIN="$(command -v fs_cli 2>/dev/null || true)"
    if [ -z "$FS_CLI_BIN" ]; then
        warn "fs_cli not found in PATH. cdr_agents_count will be omitted."
        return 0
    fi
    ok "fs_cli: ${FS_CLI_BIN}"
    [ -n "${FS_CLI_PASSWORD:-}" ] \
        && ok "using the password compiled into this installer" \
        || ok "no password set; falling back to /etc/fs_cli.conf"

    local args=() raw
    [ -n "${FS_CLI_PASSWORD:-}" ] && args=(-p "$FS_CLI_PASSWORD")
    # timeout, because fs_cli against a wedged or unreachable event socket
    # blocks indefinitely -- and this runs on a timer.
    raw="$(timeout 5 "$FS_CLI_BIN" ${args[@]+"${args[@]}"} \
        -x "$FS_CLI_COMMAND" 2>/dev/null || true)"

    printf '    raw output of "%s":\n' "$FS_CLI_COMMAND"
    printf '%s\n' "$raw" | head -3 | indent6

    case "$raw" in
        ''|*-ERR*)
            warn "fs_cli returned nothing usable. Check the event socket password"
            warn "and that the SIP profile is up. cdr_agents_count will read as absent."
            return 0
            ;;
    esac

    # "show <x> count" answers with a single "N total." line. Matching on the
    # word 'total' is what separates a real zero (no phones registered right
    # now, a legitimate reading) from a failed call that printed nothing --
    # a bare "is it a number" test would turn every failure into a false 0.
    AGENT_COUNT="$(printf '%s\n' "$raw" \
        | grep -m1 -oE '[0-9]+[[:space:]]+total' | grep -oE '^[0-9]+' || true)"
    if ! is_number "${AGENT_COUNT:-}"; then
        AGENT_COUNT="n/a"
        warn "Could not find an 'N total.' line in the output above."
        warn "cdr_agents_count will be omitted. Try a different --fs-command."
        return 0
    fi
    HAS_AGENTS=1
    ok "registrations: ${AGENT_COUNT}"
    return 0
}

# ===========================================================================
# Step 9 — indexes
# ===========================================================================

list_indexes() {
    mongo_eval 'db.getCollection("'"$COLLECTION"'").getIndexes()
      .forEach(i => print(JSON.stringify(i.key)))' || true
    return 0
}

missing_index_prefixes() {
    # An index only serves a query when the query fields match a LEADING PREFIX
    # of it, so checking whether a field appears anywhere in any index is not
    # enough — {agent_id,call_status} cannot serve a {call_status} count.
    mongo_eval '
    function firstKeys(n) {
        try { return db.getCollection(n).getIndexes().map(i => Object.keys(i.key)[0]); }
        catch (e) { return []; }
    }
    const k = firstKeys("'"$COLLECTION"'");
    const miss = ["direction", "call_status"].filter(f => !k.includes(f));
    print(miss.join(" "));' || true
    return 0
}

create_indexes() {
    # background:true so the build does not block reads on a live box.
    mongosh "$MONGO_URI" --quiet --eval '
    const c = db.getCollection("'"$COLLECTION"'");
    c.createIndex({ direction: 1 },   { background: true });
    c.createIndex({ call_status: 1 }, { background: true });
    print("indexes created");' 2>&1 | indent6
}

ensure_indexes() {
    step "Step 9: Indexes on the queried fields"

    if [ "$VARIANT" = "minimal" ]; then
        ok "The minimal variant runs no Mongo queries; no indexes needed."
        return 0
    fi

    printf '    existing indexes:\n'
    list_indexes | indent6

    local need
    need="$(missing_index_prefixes)"
    if [ -z "$need" ]; then
        ok "direction and call_status each lead an index."
        return 0
    fi

    warn "Missing index prefix: ${need}"
    warn "Without these, every ${INTERVAL} run is a full scan of ${DOC_COUNT} documents,"
    warn "once per value. That is the most expensive thing this exporter can do."

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
        warn "Skipped. Create them soon, or the timer will scan the collection every ${INTERVAL}."
    fi
}

# ===========================================================================
# Step 2 — node_exporter
# ===========================================================================

find_node_exporter_unit() {
    # Prints nothing and returns 0 when there is no unit: returning non-zero
    # here would kill the installer under `set -e` on exactly the host where
    # the right behaviour is to warn and carry on.
    local u
    for u in node_exporter prometheus-node-exporter; do
        if systemctl list-unit-files "${u}.service" --no-legend 2>/dev/null | grep -q .; then
            printf '%s' "$u"; return 0
        fi
    done
    return 0
}

running_textfile_dir() {
    # Read the flag off the live process rather than the unit file — the unit
    # may have been edited without a restart.
    [ -n "$NE_PID" ] || return 0
    tr '\0' '\n' < "/proc/${NE_PID}/cmdline" 2>/dev/null \
        | grep -m1 '^--collector.textfile.directory=' | cut -d= -f2- || true
    return 0
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
    return 0
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
        echo "# Managed by install_cdr_metrics.sh"
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
# Step 6 — write the metrics script
# ===========================================================================

# The config block is generated with printf %q rather than substituted with
# sed. A sed placeholder breaks the moment a value contains the delimiter, and
# collection names and status strings are user data.
write_config_header() {
    local v
    {
        echo '#!/bin/bash'
        echo '#'
        echo '# GENERATED by install_cdr_metrics.sh — edit the installer, not this file.'
        echo '# Re-running the installer overwrites it.'
        echo '#'
        echo
        printf 'OUTPUT=%q\n'              "${TEXTFILE_DIR}/${PROM_NAME}"
        printf 'SERVICE=%q\n'             "$SERVICE"
        printf 'OWNER=%q\n'               "$NE_USER"
        printf 'COLLECTION=%q\n'          "$COLLECTION"
        printf 'CAMPAIGN_COLLECTION=%q\n' "$CAMPAIGN_COLLECTION"
        printf 'WANT_CAMPAIGNS=%q\n'      "$HAS_CAMPAIGNS"
        printf 'WANT_AGENTS=%q\n'         "$HAS_AGENTS"
        printf 'FS_CLI_BIN=%q\n'          "$FS_CLI_BIN"
        printf 'FS_CLI_COMMAND=%q\n'      "$FS_CLI_COMMAND"
        # %q keeps this intact whatever the password contains. It is why this
        # file is mode 0700 -- see the chmod in the installer's Step 7.
        printf 'FS_CLI_PASSWORD=%q\n'     "${FS_CLI_PASSWORD:-}"
        printf 'DB_NAME=%q\n'             "$DB"
        printf 'CREDS_FILE=%q\n'          "$CREDS"

        printf 'DIRECTION_VALUES=('
        for v in ${DIRECTION_VALUES[@]+"${DIRECTION_VALUES[@]}"}; do printf ' %q' "$v"; done
        printf ' )\n'

        printf 'CALL_STATUS_VALUES=('
        for v in ${CALL_STATUS_VALUES[@]+"${CALL_STATUS_VALUES[@]}"}; do printf ' %q' "$v"; done
        printf ' )\n'
        echo
    } > "$METRICS_SCRIPT"
}

emit_minimal_metrics_body() {
    cat >> "$METRICS_SCRIPT" <<'METRICS_EOF'
# Minimal variant: service state only. No Mongo, no fs_cli.

mkdir -p "$(dirname "$OUTPUT")"

TMPFILE="$(mktemp "${OUTPUT}.XXXXXX")"
trap 'rm -f "$TMPFILE"' EXIT

NOW=$(date +%s)
BOOT=$((NOW - $(cut -d. -f1 /proc/uptime)))

UP=0; START_TIME=0; UPTIME=0

if systemctl is-active --quiet "${SERVICE}.service"; then
    UP=1
    # ActiveEnterTimestampMonotonic is microseconds since boot; deriving the
    # epoch from boot time avoids parsing systemd's locale-dependent date.
    MONO=$(systemctl show "${SERVICE}.service" \
        -p ActiveEnterTimestampMonotonic 2>/dev/null | cut -d= -f2)
    case "$MONO" in ''|*[!0-9]*) MONO=0 ;; esac
    if [ "$MONO" -gt 0 ]; then
        START_TIME=$((BOOT + MONO / 1000000))
        UPTIME=$((NOW - START_TIME))
        [ "$UPTIME" -lt 0 ] && UPTIME=0
    fi
fi

{
    echo "# HELP cdr_post_up CDR post service status (1=up, 0=down)"
    echo "# TYPE cdr_post_up gauge"
    echo "cdr_post_up ${UP}"
    echo
    echo "# HELP cdr_post_start_time_seconds Unix timestamp when the service became active"
    echo "# TYPE cdr_post_start_time_seconds gauge"
    echo "cdr_post_start_time_seconds ${START_TIME}"
    echo
    echo "# HELP cdr_post_uptime_seconds Seconds the service has been continuously active"
    echo "# TYPE cdr_post_uptime_seconds gauge"
    echo "cdr_post_uptime_seconds ${UPTIME}"
} > "$TMPFILE"

# mktemp creates 0600; node_exporter runs unprivileged and must read this.
# Both mode fixes matter - this is the failure that silently kills the file.
chmod 0644 "$TMPFILE"
mv "$TMPFILE" "$OUTPUT"
chmod 0644 "$OUTPUT"
chown "${OWNER}:${OWNER}" "$OUTPUT" 2>/dev/null || true

trap - EXIT
METRICS_EOF
}

emit_full_metrics_body() {
    cat >> "$METRICS_SCRIPT" <<'METRICS_EOF'
# Full variant: service state, Mongo document counts, callcenter agent count.
#
# The counts are gauges, not counters. They are countDocuments() over a live
# collection: a purge, an archive job or a TTL index makes them fall, and a
# counter that falls is read by PromQL as a reset. Use delta() over a window.

[ -r "$CREDS_FILE" ] && . "$CREDS_FILE"
MONGO_TARGET="${MONGO_URI:-$DB_NAME}"

mkdir -p "$(dirname "$OUTPUT")"

# mktemp, not a fixed .tmp path: two overlapping runs would clobber each
# other and node_exporter could read a half-written file.
TMPFILE="$(mktemp "${OUTPUT}.XXXXXX")"
trap 'rm -f "$TMPFILE"' EXIT

NOW=$(date +%s)
BOOT=$((NOW - $(cut -d. -f1 /proc/uptime)))

UP=0; START_TIME=0; UPTIME=0; MONGO_UP=0
CAMPAIGNS=""; AGENTS=""
DIRECTION_LINES=""; STATUS_LINES=""


# ---------- service status and uptime ----------
if systemctl is-active --quiet "${SERVICE}.service"; then
    UP=1
    # ActiveEnterTimestampMonotonic is microseconds since boot; deriving
    # the epoch from boot time avoids parsing systemd's locale-dependent
    # date string.
    MONO=$(systemctl show "${SERVICE}.service" \
        -p ActiveEnterTimestampMonotonic 2>/dev/null | cut -d= -f2)
    case "$MONO" in ''|*[!0-9]*) MONO=0 ;; esac
    if [ "$MONO" -gt 0 ]; then
        START_TIME=$((BOOT + MONO / 1000000))
        UPTIME=$((NOW - START_TIME))
        [ "$UPTIME" -lt 0 ] && UPTIME=0
    fi
fi


# ---------- helpers ----------
js_string() {
    # A JSON string literal, safe to paste into the --eval body.
    printf '"%s"' "$(printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')"
}

js_array() {
    local first=1 v
    printf '['
    for v in "$@"; do
        [ "$first" -eq 1 ] || printf ','
        first=0
        js_string "$v"
    done
    printf ']'
}

prom_label() {
    # Prometheus label values escape backslash and double quote.
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}


# ---------- mongo: one invocation, all counts ----------
# One mongosh call, not seven: each start-up costs 200-500ms, which on a short
# timer is most of the interval.
#
# Note for anyone editing the JS below: this heredoc is UNQUOTED so the
# js_array substitutions expand, which means bash also expands $foo. Keep the
# JS free of dollar signs -- no aggregation operators, no template literals.

JS=$(cat <<EOF
const out = [];
try {
    const cdrs = db.getCollection($(js_string "$COLLECTION"));

    if ($WANT_CAMPAIGNS) {
        const camp = db.getCollection($(js_string "$CAMPAIGN_COLLECTION"));
        out.push("C\tcampaigns\t" + camp.countDocuments());
    }

    const dirs = $(js_array ${DIRECTION_VALUES[@]+"${DIRECTION_VALUES[@]}"});
    dirs.forEach(function (d) {
        out.push("D\t" + d + "\t" + cdrs.countDocuments({ direction: d }));
    });

    const stats = $(js_array ${CALL_STATUS_VALUES[@]+"${CALL_STATUS_VALUES[@]}"});
    stats.forEach(function (s) {
        out.push("S\t" + s + "\t" + cdrs.countDocuments({ call_status: s }));
    });

    out.push("OK");
    print(out.join("\n"));
} catch (e) {
    print("ERR");
}
EOF
)

MONGO_OUT=$(mongosh "$MONGO_TARGET" --quiet --eval "$JS" 2>/dev/null)

# A trailing OK sentinel, not a regex over the whole payload: it survives any
# label value, and it cannot be half-true the way a per-line match can.
if [ "${MONGO_OUT##*$'\n'}" = "OK" ]; then
    MONGO_UP=1
    while IFS=$'\t' read -r kind label value; do
        case "$value" in ''|*[!0-9]*) continue ;; esac
        case "$kind" in
            C) CAMPAIGNS="$value" ;;
            D) DIRECTION_LINES="${DIRECTION_LINES}cdr_calls_direction_count{direction=\"$(prom_label "$label")\"} ${value}"$'\n' ;;
            S) STATUS_LINES="${STATUS_LINES}cdr_calls_status_count{call_status=\"$(prom_label "$label")\"} ${value}"$'\n' ;;
        esac
    done <<< "$MONGO_OUT"
fi


# ---------- freeswitch: SIP registration count ----------
# The metric is omitted entirely when fs_cli fails: emitting 0 would be
# indistinguishable from every phone having deregistered.
if [ "$WANT_AGENTS" -eq 1 ] && [ -n "$FS_CLI_BIN" ]; then
    FS_ARGS=()
    [ -n "${FS_CLI_PASSWORD:-}" ] && FS_ARGS=(-p "$FS_CLI_PASSWORD")
    # timeout, because fs_cli against a wedged event socket blocks forever,
    # and this runs on a timer that would then pile up oneshot services.
    AGENT_RAW="$(timeout 5 "$FS_CLI_BIN" ${FS_ARGS[@]+"${FS_ARGS[@]}"} \
        -x "$FS_CLI_COMMAND" 2>/dev/null || true)"
    case "$AGENT_RAW" in
        ''|*-ERR*) ;;
        *)
            # "show <x> count" answers with "N total." -- anchoring on the word
            # 'total' is what keeps a genuine 0 (nobody registered) distinct
            # from a failed call, which must produce no series at all.
            AGENTS="$(printf '%s\n' "$AGENT_RAW" \
                | grep -m1 -oE '[0-9]+[[:space:]]+total' | grep -oE '^[0-9]+' || true)"
            case "$AGENTS" in ''|*[!0-9]*) AGENTS="" ;; esac
            ;;
    esac
fi


# ---------- emit ----------
{
    echo "# HELP cdr_post_up CDR post service status (1=up, 0=down)"
    echo "# TYPE cdr_post_up gauge"
    echo "cdr_post_up ${UP}"
    echo

    echo "# HELP cdr_post_start_time_seconds Unix timestamp when the service became active"
    echo "# TYPE cdr_post_start_time_seconds gauge"
    echo "cdr_post_start_time_seconds ${START_TIME}"
    echo

    echo "# HELP cdr_post_uptime_seconds Seconds the service has been continuously active"
    echo "# TYPE cdr_post_uptime_seconds gauge"
    echo "cdr_post_uptime_seconds ${UPTIME}"
    echo

    echo "# HELP cdr_post_mongo_up MongoDB reachable and queries succeeded (1=yes, 0=no)"
    echo "# TYPE cdr_post_mongo_up gauge"
    echo "cdr_post_mongo_up ${MONGO_UP}"
    echo

    # Counts are omitted when mongo fails. Emitting 0 would look like a real
    # drop to zero, and every dashboard would show a cliff on a blip.
    if [ "$MONGO_UP" -eq 1 ]; then

        if [ -n "$CAMPAIGNS" ]; then
            echo "# HELP cdr_campaign_reports_count Documents in the campaign report collection"
            echo "# TYPE cdr_campaign_reports_count gauge"
            echo "cdr_campaign_reports_count ${CAMPAIGNS}"
            echo
        fi

        if [ -n "$DIRECTION_LINES" ]; then
            echo "# HELP cdr_calls_direction_count CDRs by direction"
            echo "# TYPE cdr_calls_direction_count gauge"
            printf '%s' "$DIRECTION_LINES"
            echo
        fi

        if [ -n "$STATUS_LINES" ]; then
            echo "# HELP cdr_calls_status_count CDRs by call_status"
            echo "# TYPE cdr_calls_status_count gauge"
            printf '%s' "$STATUS_LINES"
            echo
        fi

    fi

    if [ -n "$AGENTS" ]; then
        echo "# HELP cdr_agents_count SIP registrations reported by fs_cli"
        echo "# TYPE cdr_agents_count gauge"
        echo "cdr_agents_count ${AGENTS}"
    fi

} > "$TMPFILE"

# mktemp creates 0600; node_exporter runs unprivileged and must read this.
# Both mode fixes matter - this is the failure that silently kills the file.
chmod 0644 "$TMPFILE"
mv "$TMPFILE" "$OUTPUT"
chmod 0644 "$OUTPUT"
chown "${OWNER}:${OWNER}" "$OUTPUT" 2>/dev/null || true

trap - EXIT
METRICS_EOF
}

write_metrics_script() {
    step "Step 6: Install ${METRICS_SCRIPT} (${VARIANT})"

    write_config_header
    if [ "$VARIANT" = "minimal" ]; then
        emit_minimal_metrics_body
    else
        emit_full_metrics_body
    fi
    ok "Metrics script written (${VARIANT})"
}

# ===========================================================================
# Step 7 — validate
# ===========================================================================

validate_metrics_script() {
    step "Step 7: Validate"

    # 0700, not the usual 0755: this file now contains the event socket
    # password in plain text. `chmod +x` would leave it world-readable, which
    # would hand the password to every account on the box. systemd runs the
    # oneshot as root, so root-only execute costs nothing.
    chown root:root "$METRICS_SCRIPT" 2>/dev/null || true
    chmod 0700 "$METRICS_SCRIPT"
    local sm
    sm="$(stat -c '%a' "$METRICS_SCRIPT")"
    [ "$sm" = "700" ] || die "$METRICS_SCRIPT is mode $sm, expected 700 — it holds a password."
    ok "Metrics script mode: $sm (root only)"

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

    # The config block is generated, so assert it actually landed rather than
    # discovering an unbound variable at 3am on the first timer run.
    local k
    for k in OUTPUT SERVICE OWNER COLLECTION; do
        grep -q "^${k}=" "$METRICS_SCRIPT" || die "Config key ${k} missing from the generated script."
    done
    ok "Config block present"
}

# ===========================================================================
# Step 8 — run once and lint
# ===========================================================================

lint_prom_file() {
    # One malformed line makes node_exporter discard every .prom in the
    # directory, so this has to be exact. Label values may contain anything
    # except an unescaped quote, hence the (\\.|[^"\\])* alternation.
    local bad
    bad="$(grep -v '^#' "$PROM" \
        | grep -v '^[[:space:]]*$' \
        | grep -vE '^[a-zA-Z_:][a-zA-Z0-9_:]*(\{[a-zA-Z_][a-zA-Z0-9_]*="(\\.|[^"\\])*"(,[a-zA-Z_][a-zA-Z0-9_]*="(\\.|[^"\\])*")*\})? -?[0-9]+(\.[0-9]+)?([eE][-+]?[0-9]+)?$' || true)"
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

check_expected_series() {
    [ "$VARIANT" = "full" ] || return 0
    local mu
    mu="$(awk '/^cdr_post_mongo_up/ {print $2; exit}' "$PROM")"
    if [ "$mu" = "1" ]; then
        ok "cdr_post_mongo_up = 1"
    else
        warn "cdr_post_mongo_up = ${mu:-?} — queries failed; only service metrics present."
        return 0
    fi

    local want got
    for want in cdr_calls_direction_count cdr_calls_status_count; do
        got="$(grep -c "^${want}{" "$PROM" || true)"
        [ "${got:-0}" -gt 0 ] \
            && ok "${want}: ${got} series" \
            || warn "${want}: no series emitted."
    done
    grep -q '^cdr_campaign_reports_count ' "$PROM" \
        && ok "cdr_campaign_reports_count present" \
        || warn "cdr_campaign_reports_count absent — ${CAMPAIGN_COLLECTION} unreadable."
    if [ "$HAS_AGENTS" -eq 1 ]; then
        grep -q '^cdr_agents_count ' "$PROM" \
            && ok "cdr_agents_count present" \
            || warn "cdr_agents_count absent — fs_cli failed inside the metrics script."
    fi
    return 0
}

run_metrics_once() {
    step "Step 8: Manual run"

    "$METRICS_SCRIPT" || die "Metrics script exited non-zero."
    PROM="${TEXTFILE_DIR}/${PROM_NAME}"
    [ -s "$PROM" ] || die "$PROM missing or empty."

    ls -l "$PROM" | indent
    grep -v '^#' "$PROM" | grep -v '^[[:space:]]*$' | indent

    check_readable_by_exporter
    lint_prom_file
    check_expected_series
}

# ===========================================================================
# Step 10 — timer
# ===========================================================================

install_timer() {
    step "Step 10: Install service and timer (every $INTERVAL)"

    cat > "$SERVICE_UNIT" <<EOF
[Unit]
Description=CDR Prometheus Metrics
After=mongod.service ${SERVICE}.service

[Service]
Type=oneshot
EnvironmentFile=-${CREDS}
ExecStart=${METRICS_SCRIPT}
EOF

    # AccuracySec=1s is required — systemd defaults to 1 minute, which would
    # stretch a 30s interval into minute-long gaps.
    cat > "$TIMER_UNIT" <<EOF
[Unit]
Description=Run CDR Prometheus metrics every ${INTERVAL}

[Timer]
OnBootSec=${INTERVAL}
OnUnitActiveSec=${INTERVAL}
AccuracySec=1s
Unit=cdr-metrics.service

[Install]
WantedBy=timers.target
EOF

    chmod 0644 "$SERVICE_UNIT" "$TIMER_UNIT"
    systemctl daemon-reload
    systemctl enable --now cdr-metrics.timer >/dev/null 2>&1
    systemctl is-enabled --quiet cdr-metrics.timer || die "Timer not enabled."
    systemctl list-timers --all 2>/dev/null | grep -i cdr | indent || true
    ok "cdr-metrics.timer enabled and started"
}

# ===========================================================================
# Step 11 — verify after a timer run
# ===========================================================================

check_scrape_error() {
    command -v curl >/dev/null 2>&1 || return 0
    local body err count
    body="$(curl -sf "localhost:${EXPORTER_PORT}/metrics" 2>/dev/null || true)"
    if [ -z "$body" ]; then
        warn "Could not reach localhost:${EXPORTER_PORT}/metrics — check the port."
        return 0
    fi
    err="$(printf '%s\n' "$body" | awk '/^node_textfile_scrape_error/ {print $2; exit}')"
    case "$err" in
        0)  ok "node_textfile_scrape_error = 0" ;;
        "") warn "node_textfile_scrape_error not exposed — is the textfile collector on?" ;;
        *)  warn "node_textfile_scrape_error = ${err} — a .prom file was rejected." ;;
    esac
    count="$(printf '%s\n' "$body" | grep -c '^cdr_' || true)"
    [ "${count:-0}" -gt 0 ] \
        && ok "${count} cdr_* series exposed on :${EXPORTER_PORT}" \
        || warn "No cdr_* series on :${EXPORTER_PORT} yet."
    return 0
}

verify_after_timer() {
    local wait_secs pre post
    wait_secs=$(( $(interval_to_seconds "$INTERVAL") + 5 ))

    step "Step 11: Verify after a timer-driven run (waiting ${wait_secs}s)"

    pre="$(stat -c '%Y' "$PROM")"
    sleep "$wait_secs"
    post="$(stat -c '%Y' "$PROM")"

    [ "$post" != "$pre" ] \
        && ok "Timer rewrote the file" \
        || warn "File not rewritten. Check: journalctl -u cdr-metrics.service -n 30"

    ls -l "$PROM" | indent
    MODE="$(stat -c '%a' "$PROM")"
    # THE decisive check. A manual run passing proves nothing — the failure mode
    # is the timer rewriting the file at 0600 one interval later.
    [ "$MODE" = "644" ] || die "$PROM is mode $MODE after the timer run, expected 644."
    ok "Mode survived the timer run: $MODE"

    check_scrape_error
}

# ===========================================================================
# Step 12 — firewall
# ===========================================================================

configure_firewall() {
    step "Step 12: Firewall"

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
  unit             : ${SERVICE}.service (${CDR_ACTIVE} / ${CDR_ENABLED})
  variant          : ${VARIANT}
  database         : ${DB}.${COLLECTION} (${DOC_COUNT} documents)
  campaigns        : ${DB}.${CAMPAIGN_COLLECTION} (~${CAMPAIGN_COUNT} documents)
  registrations    : ${AGENT_COUNT} via "${FS_CLI_COMMAND}"
  credentials      : ${CREDS} (Mongo)
  fs_cli password  : ${FS_CLI_PASSWORD:+in ${METRICS_SCRIPT}, mode 0700}${FS_CLI_PASSWORD:-<none; using /etc/fs_cli.conf>}
  exporter         : ${NE_UNIT:-<none>} as ${NE_USER}
  textfile dir     : ${TEXTFILE_DIR}
  output           : ${PROM} (mode ${MODE})
  timer            : cdr-metrics.timer every ${INTERVAL}
  local address    : $(hostname -I 2>/dev/null | awk '{print $1}'):${EXPORTER_PORT}
                     (behind NAT? Prometheus needs the address it can reach,
                      not this one -- verify with a curl from the monitor)

The counts are gauges over live collections. For a rate, use
delta(cdr_calls_status_count{call_status="Answered"}[5m]) -- not rate(), which
assumes a counter and would misread any purge as a reset.

The queried values are fixed at install time so each count rides an index. A
direction or call_status your application has never written before will not
appear on its own; edit DIRECTION_VALUES / CALL_STATUS_VALUES at the top of
this installer and re-run.

Next, on the monitoring server: add this target to prometheus.yml, install the
alert rules, promtool check config, then 'systemctl reload prometheus'.
EOF
}

# ===========================================================================
# Orchestration
# ===========================================================================

phase_interactive() {
    identify_unit
    ask_monitor_ip
    store_credentials
    verify_connection
    probe_values
    detect_fs_cli
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

# Allow `source ./install_cdr_metrics.sh --source-only` to load the functions
# without running anything, for step-by-step debugging.
case "${1:-}" in
    --source-only) init_colors; SOURCE_ONLY=1 ;;
    *) main "$@" ;;
esac
