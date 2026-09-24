#!/usr/bin/env bash
#
# install_claim_agent_metrics.sh — the whole Claim Agent runbook, Steps 1-12.
#
# Structured as one function per step, orchestrated by main() at the bottom.
# Every function is independently callable, so you can source this file and run
# a single step while debugging:
#
#   source ./install_claim_agent_metrics.sh --source-only
#   detect_node_exporter
#   probe_schema
#   run_metrics_once
#
# claim_agent is not a package you install; it is your own service. This script
# does everything around it: identifies the unit, stores Mongo credentials,
# discovers the schema to decide which metrics are possible, indexes the
# queried fields, installs the metrics script and timer, opens the firewall.
#
#   Step 1   identify the unit, confirm active/enabled, show ExecStart
#   Step 2   find the Mongo URI in the claim agent source, flag its permissions
#   Step 6   store MONGO_URI in a 0600 file, out of the script and history
#   Step 3   discover the schema and choose the counting scope
#   Step 9b  index the queried fields (offered, not forced)
#   Step 4   detect node_exporter and enable the textfile collector
#   Step 5   create the textfile directory, both levels traversable at 0755
#   Step 7   install /usr/local/bin/claim_agent_metrics.sh
#   Step 8   validate it (bash -n + the chmod truncation check)
#   Step 9   run once, check readability, lint the exposition format
#   Step 10  install claim-agent-metrics.service and .timer, AccuracySec=1s
#   Step 11  verify the mode SURVIVES a timer run, then scrape :PORT/metrics
#   Step 12  open the firewall for the monitoring server
#
# VARIANTS
#   minimal  service up / start time / uptime only. No Mongo queries.
#   full     adds dialed / answered / abandoned / failed counters and the
#            active-campaigns gauge. Needs Mongo access.
#   auto     use full if Mongo answers, minimal otherwise (default).
#
# SCOPE (full variant only) -- which CDRs count as dialer traffic
#   campaign  outbound calls carrying a campaign_uuid  (the runbook default)
#   outbound  every outbound call, campaign or not
#   auto      campaign if any campaign CDRs exist, else ask (default)
#
# Every prompt happens in the first phase, so the slow part runs unattended.
# Safe to re-run. Existing credentials are reused unless --reset-creds.
#
# Usage:
#   sudo ./install_claim_agent_metrics.sh
#   sudo ./install_claim_agent_metrics.sh --scope outbound
#   sudo ./install_claim_agent_metrics.sh --variant minimal --no-mongo
#   sudo ./install_claim_agent_metrics.sh --no-firewall --create-indexes
#   sudo ./install_claim_agent_metrics.sh --uninstall
#
set -euo pipefail

# ===========================================================================
# Configuration
# ===========================================================================
SERVICE="claim_agent"
DB="db_pbxcc"
COLLECTION="cdrs"
CAMPAIGN_COLL="outbound_campaign"
CREDS="/etc/default/claim-agent-metrics"
AGENT_SRC="/usr/share/freeswitch/scripts/claim_agent.py"

MONITOR_IP=""
EXPORTER_PORT="9101"
TEXTFILE_DIR="/var/lib/node_exporter/textfile_collector"
METRICS_SCRIPT="/usr/local/bin/claim_agent_metrics.sh"
INTERVAL="30s"
VARIANT="auto"
SCOPE="auto"

SKIP_FIREWALL=0
SKIP_MONGO=0
RESET_CREDS=0
CREATE_INDEXES=0
PURGE_CREDS=0
UNINSTALL=0
SOURCE_ONLY=0

SERVICE_UNIT="/etc/systemd/system/claim-agent-metrics.service"
TIMER_UNIT="/etc/systemd/system/claim-agent-metrics.timer"
DROPIN_DIR="/etc/systemd/system/node_exporter.service.d"
DROPIN_FILE="${DROPIN_DIR}/10-textfile-collector.conf"

# Runtime state shared between steps.
HAS_UNIT=0; AG_ACTIVE=""; AG_ENABLED=""; SVC_USER="root"
HAVE_CREDS=0; TOTAL_CDRS="n/a"
OUTBOUND=0; WITH_CAMPAIGN=0; CAMPAIGNS_DEFINED=0
CREATEDAT_DOCS=0; HAS_CREATEDAT=0
BASE_FILTER=""
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

usage() { sed -n '3,52p' "$0" | sed 's/^# \{0,1\}//'; }

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
    sed -E 's#(mongodb://[^:]*:)[^@]*@#\1***@#g'
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
            --service)        SERVICE="${2:?}"; shift 2 ;;
            --variant)        VARIANT="${2:?}"; shift 2 ;;
            --scope)          SCOPE="${2:?}"; shift 2 ;;
            --db)             DB="${2:?}"; shift 2 ;;
            --collection)     COLLECTION="${2:?}"; shift 2 ;;
            --creds-file)     CREDS="${2:?}"; shift 2 ;;
            --agent-src)      AGENT_SRC="${2:?}"; shift 2 ;;
            --port)           EXPORTER_PORT="${2:?}"; shift 2 ;;
            --textfile-dir)   TEXTFILE_DIR="${2:?}"; shift 2 ;;
            --interval)       INTERVAL="${2:?}"; shift 2 ;;
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
    case "$SCOPE" in auto|campaign|outbound) ;; *) die "--scope must be auto, campaign or outbound." ;; esac
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
    step "Removing the Claim Agent metrics exporter"
    systemctl disable --now claim-agent-metrics.timer >/dev/null 2>&1 || true
    systemctl stop claim-agent-metrics.service >/dev/null 2>&1 || true
    rm -f "$TIMER_UNIT" "$SERVICE_UNIT" "$METRICS_SCRIPT" "${TEXTFILE_DIR}/claim_agent.prom"
    systemctl daemon-reload
    ok "Removed timer, service, metrics script and claim_agent.prom."
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

identify_unit() {
    step "Step 1: Identify the Claim Agent unit"

    local matches
    matches="$(systemctl list-unit-files 2>/dev/null | grep -i claim | awk '{print $1}' || true)"
    if [ -n "$matches" ]; then
        printf '    units matching "claim":\n'
        printf '%s\n' "$matches" | indent6
    else
        warn "No unit files matching 'claim' found."
    fi

    if systemctl list-unit-files "${SERVICE}.service" --no-legend 2>/dev/null | grep -q .; then
        HAS_UNIT=1
    else
        HAS_UNIT=0
    fi

    if [ "$HAS_UNIT" -eq 0 ]; then
        # The metrics script falls back to a pgrep match, so this is survivable.
        AG_ACTIVE="no-unit"; AG_ENABLED="no-unit"; SVC_USER="root"
        warn "No '${SERVICE}.service' unit. The metrics script will fall back to a"
        warn "process match on 'claim[-_.]agent' for claim_agent_up."
        if pgrep -f 'claim[-_.]agent' >/dev/null 2>&1; then
            ok "A matching process is running."
        else
            warn "No matching process either — claim_agent_up will read 0."
        fi
        return 0
    fi

    AG_ACTIVE="$(systemctl is-active "$SERVICE" 2>/dev/null || true)"
    AG_ENABLED="$(systemctl is-enabled "$SERVICE" 2>/dev/null || true)"
    printf '    unit       : %s.service\n    is-active  : %s\n    is-enabled : %s\n' \
        "$SERVICE" "$AG_ACTIVE" "$AG_ENABLED"

    # Not fatal — claim_agent_up reporting 0 is legitimate output.
    [ "$AG_ACTIVE" = "active" ] || warn "${SERVICE} is not active; claim_agent_up will report 0."
    case "$AG_ENABLED" in
        enabled|enabled-runtime|static|indirect) ;;
        *) warn "${SERVICE} is not enabled at boot (state: ${AG_ENABLED:-unknown})." ;;
    esac

    printf '    ExecStart:\n'
    systemctl cat "$SERVICE" 2>/dev/null | grep -E '^(ExecStart|Environment)' | indent6 || true
    SVC_USER="$(systemctl show "$SERVICE" -p User --value 2>/dev/null || true)"
    SVC_USER="${SVC_USER:-root}"
}

# ===========================================================================
# Step 2 — Mongo URI in the source, and its permissions
# ===========================================================================

check_source_permissions() {
    # The source holds a plaintext DB password. World-readable is bad, but
    # chmod-ing it blind can break the service, so only report.
    local mode owner
    mode="$(stat -c '%a' "$AGENT_SRC")"
    owner="$(stat -c '%U:%G' "$AGENT_SRC")"
    printf '    %s  mode %s  owner %s\n' "$AGENT_SRC" "$mode" "$owner"
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
    step "Step 2: Mongo URI in the Claim Agent source"

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
# Step 6 — credentials
# ===========================================================================

build_mongo_uri() {
    # Echoes the URI on stdout; prompts go to stderr so nothing leaks in.
    local host port db user pass
    printf '    Host [127.0.0.1]: ' >&2;   read -r host; host="${host:-127.0.0.1}"
    printf '    Port [27017]: ' >&2;       read -r port; port="${port:-27017}"
    printf '    Database [%s]: ' "$DB" >&2; read -r db;  db="${db:-$DB}"
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
    step "Step 6: Mongo credentials"

    if [ "$SKIP_MONGO" -eq 1 ]; then
        ok "Skipped (--no-mongo)."
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

    TOTAL_CDRS="$(mongosh "$MONGO_URI" --quiet \
        --eval "db.getCollection('${COLLECTION}').countDocuments({})" 2>&1 || true)"
    if ! is_number "$TOTAL_CDRS"; then
        printf '%s\n' "$TOTAL_CDRS" | head -5 | indent6
        die "Could not query ${COLLECTION}. Fix the URI first — this surfaces later as claim_agent_mongo_up 0."
    fi
    ok "${COLLECTION} reachable: ${TOTAL_CDRS} documents"
}

# ===========================================================================
# Step 3 — schema discovery
# ===========================================================================

print_sample_fields() {
    printf '    fields on a sample document:\n'
    mongo_eval '
    const d = db.getCollection("'"$COLLECTION"'").findOne();
    if (d) { Object.keys(d).sort().forEach(k => print("      " + k)); }
    ' || warn "Sample document probe failed."
}

read_campaign_stats() {
    # One round trip for all four counts.
    mongo_eval '
    const c = db.getCollection("'"$COLLECTION"'");
    const out  = c.countDocuments({ direction: "outbound" });
    const camp = c.countDocuments({ direction: "outbound",
                                    campaign_uuid: { $nin: ["", null] } });
    let defined = -1;
    try { defined = db.getCollection("'"$CAMPAIGN_COLL"'").countDocuments({}); } catch (e) {}
    const cAt = c.countDocuments({ createdAt: { $exists: true } });
    print(out + " " + camp + " " + defined + " " + cAt);
    ' || true
}

probe_schema() {
    [ "$HAVE_CREDS" -eq 1 ] || return 0
    step "Step 3: Discover the schema"

    if [ "$TOTAL_CDRS" = "0" ]; then
        # Every $exists count returns 0 on an empty collection, so a field
        # probe here would report ABSENT for fields that may well exist.
        warn "${COLLECTION} is EMPTY — the schema cannot be determined."
        warn "Counters will read 0 and any field probe is not meaningful."
    else
        print_sample_fields
    fi

    printf '\n    campaign fields:\n'
    local stats
    stats="$(read_campaign_stats)"
    if printf '%s' "$stats" | grep -qE '^-?[0-9]+ -?[0-9]+ -?[0-9]+ -?[0-9]+$'; then
        read -r OUTBOUND WITH_CAMPAIGN CAMPAIGNS_DEFINED CREATEDAT_DOCS <<< "$stats"
        printf '      total cdrs        : %s\n' "$TOTAL_CDRS"
        printf '      outbound          : %s\n' "$OUTBOUND"
        printf '      with campaign     : %s\n' "$WITH_CAMPAIGN"
        if [ "$CAMPAIGNS_DEFINED" -ge 0 ]; then
            printf '      campaigns defined : %s\n' "$CAMPAIGNS_DEFINED"
        else
            printf '      campaigns defined : <%s not readable>\n' "$CAMPAIGN_COLL"
        fi
        printf '      docs w/ createdAt : %s\n' "$CREATEDAT_DOCS"
        [ "$CREATEDAT_DOCS" -gt 0 ] && HAS_CREATEDAT=1
    else
        warn "Campaign field probe failed; assuming zeros."
        CREATEDAT_DOCS=0
    fi

    if [ "$TOTAL_CDRS" != "0" ] && [ "$HAS_CREATEDAT" -eq 0 ]; then
        warn "No createdAt field — claim_agent_active_campaigns will stay 0 permanently."
    fi

    if [ "$TOTAL_CDRS" != "0" ]; then
        printf '\n    distinct call_status values:\n'
        mongo_eval 'db.getCollection("'"$COLLECTION"'").distinct("call_status")
          .forEach(v => print("      " + JSON.stringify(v)))' || true
    fi
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
# Counting scope
# ===========================================================================

resolve_scope() {
    if [ "$VARIANT" != "full" ]; then
        SCOPE="n/a"
        BASE_FILTER='{ direction: "outbound" }'
        return 0
    fi

    step "Counting scope"

    if [ "$SCOPE" = "auto" ]; then
        if [ "${WITH_CAMPAIGN:-0}" -gt 0 ]; then
            SCOPE="campaign"
            ok "${WITH_CAMPAIGN} campaign CDRs found — scoping to campaign traffic."
        elif [ "${OUTBOUND:-0}" -gt 0 ] && [ -t 0 ]; then
            warn "No CDR carries a campaign_uuid, but ${OUTBOUND} outbound calls exist."
            warn "Campaign scope is correct for a dialer, but every counter will"
            warn "read 0 until a campaign actually runs."
            local ans
            printf '    Count [c]ampaign only, or all [o]utbound? [C/o]: '
            read -r ans
            case "$ans" in [oO]*) SCOPE="outbound" ;; *) SCOPE="campaign" ;; esac
        else
            SCOPE="campaign"
            warn "No campaign CDRs; keeping campaign scope (counters will read 0)."
        fi
    fi

    case "$SCOPE" in
        campaign) BASE_FILTER='{ direction: "outbound", campaign_uuid: { $nin: ["", null] } }' ;;
        outbound) BASE_FILTER='{ direction: "outbound" }' ;;
    esac
    ok "Scope: ${SCOPE}"
}

# ===========================================================================
# Step 9b — indexes
# ===========================================================================

list_indexes() {
    mongo_eval 'db.getCollection("'"$COLLECTION"'").getIndexes()
      .forEach(i => print(JSON.stringify(i.key)))' || true
}

missing_index_prefixes() {
    # An index only serves a query when the query fields match a LEADING PREFIX
    # of it, so checking whether a field appears anywhere in any index is not
    # enough — {user_uuid,direction,createdAt} cannot serve {direction,...}.
    mongo_eval '
    function firstKeys(n) {
        try { return db.getCollection(n).getIndexes().map(i => Object.keys(i.key)[0]); }
        catch (e) { return []; }
    }
    const k = firstKeys("'"$COLLECTION"'");
    const miss = [];
    if (!k.includes("direction"))     miss.push("direction");
    if (!k.includes("campaign_uuid")) miss.push("campaign_uuid");
    print(miss.join(" "));' || true
}

create_indexes() {
    # background:true so the build does not block reads on a live box.
    mongosh "$MONGO_URI" --quiet --eval '
    const c = db.getCollection("'"$COLLECTION"'");
    c.createIndex({ direction: 1, campaign_uuid: 1, call_status: 1 }, { background: true });
    c.createIndex({ campaign_uuid: 1, createdAt: -1 }, { background: true });
    print("indexes created");' 2>&1 | indent6
}

ensure_indexes() {
    step "Indexes on the queried fields"

    if [ "$VARIANT" = "minimal" ]; then
        ok "The minimal variant runs no Mongo queries; no indexes needed."
        return 0
    fi

    printf '    existing indexes:\n'
    list_indexes | indent6

    local need
    need="$(missing_index_prefixes)"
    if [ -z "$need" ]; then
        ok "direction and campaign_uuid lead an index each."
        return 0
    fi

    warn "Missing index prefix: ${need}"
    warn "Without these, every ${INTERVAL} run is a full scan of ${TOTAL_CDRS} documents."

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
# Step 4 — node_exporter
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
    step "Step 4: Detect node_exporter"

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
        echo "# Managed by install_claim_agent_metrics.sh"
        echo "[Service]"
        echo "ExecStart="
        echo "ExecStart=${cur_exec} --collector.textfile.directory=${TEXTFILE_DIR}"
    } > "$DROPIN_FILE"
    chmod 0644 "$DROPIN_FILE"
}

enable_textfile_collector() {
    step "Step 4b: Enable textfile collector"

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
# Step 5 — textfile directory
# ===========================================================================

create_textfile_dir() {
    step "Step 5: Create textfile directory"

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
# Step 7 — write the metrics script
# ===========================================================================

emit_minimal_metrics_script() {
    cat > "$METRICS_SCRIPT" <<'METRICS_EOF'
#!/bin/bash
#
# Claim Agent metrics (minimal variant) for the node_exporter textfile
# collector. Service state only -- no Mongo queries.
#

OUTPUT="__TEXTFILE_DIR__/claim_agent.prom"
SERVICE="__SERVICE__"
OWNER="__NE_USER__"

mkdir -p "$(dirname "$OUTPUT")"

TMPFILE="$(mktemp "${OUTPUT}.XXXXXX")"
trap 'rm -f "$TMPFILE"' EXIT

NOW=$(date +%s)
BOOT=$((NOW - $(cut -d. -f1 /proc/uptime)))

UP=0
START_TIME=0
UPTIME=0

# systemctl is preferred over pgrep: pgrep -f matches editors,
# stale zombies, and even the grep itself.
if systemctl list-unit-files "${SERVICE}.service" --no-legend 2>/dev/null | grep -q .; then
    if systemctl is-active --quiet "${SERVICE}.service"; then
        UP=1
        MONO=$(systemctl show "${SERVICE}.service" \
            -p ActiveEnterTimestampMonotonic 2>/dev/null | cut -d= -f2)
        case "$MONO" in ''|*[!0-9]*) MONO=0 ;; esac
        if [ "$MONO" -gt 0 ]; then
            START_TIME=$((BOOT + MONO / 1000000))
            UPTIME=$((NOW - START_TIME))
            [ "$UPTIME" -lt 0 ] && UPTIME=0
        fi
    fi
else
    # No systemd unit - fall back to a process match
    pgrep -f 'claim[-_.]agent' >/dev/null 2>&1 && UP=1
fi

{
    echo "# HELP claim_agent_up Claim Agent service status (1=up, 0=down)"
    echo "# TYPE claim_agent_up gauge"
    echo "claim_agent_up ${UP}"
    echo

    echo "# HELP claim_agent_start_time_seconds Unix timestamp when the service became active"
    echo "# TYPE claim_agent_start_time_seconds gauge"
    echo "claim_agent_start_time_seconds ${START_TIME}"
    echo

    echo "# HELP claim_agent_uptime_seconds Seconds the service has been continuously active"
    echo "# TYPE claim_agent_uptime_seconds gauge"
    echo "claim_agent_uptime_seconds ${UPTIME}"

} > "$TMPFILE"

# mktemp creates 0600; node_exporter runs unprivileged and must read this
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
# Claim Agent metrics for the node_exporter textfile collector.
#
# Exports cumulative counters; rates are computed in PromQL with rate().
# This survives missed scrapes and lets you change the averaging window
# in Grafana without touching this host.
#

OUTPUT="__TEXTFILE_DIR__/claim_agent.prom"
DB="__DB__"
[ -r __CREDS__ ] && . __CREDS__
MONGO_TARGET="${MONGO_URI:-$DB}"
COLLECTION="__COLLECTION__"
SERVICE="__SERVICE__"
OWNER="__NE_USER__"

mkdir -p "$(dirname "$OUTPUT")"

TMPFILE="$(mktemp "${OUTPUT}.XXXXXX")"
trap 'rm -f "$TMPFILE"' EXIT

NOW=$(date +%s)
BOOT=$((NOW - $(cut -d. -f1 /proc/uptime)))

UP=0
START_TIME=0
UPTIME=0
MONGO_UP=0

DIALED=0
ANSWERED=0
ABANDONED=0
FAILED=0
ACTIVE=0


# ---------------------------------------------------------
# Service status and uptime
# ---------------------------------------------------------
# systemctl is preferred over pgrep: pgrep -f matches editors,
# stale zombies, and even the grep itself.

if systemctl list-unit-files "${SERVICE}.service" --no-legend 2>/dev/null | grep -q .; then

    if systemctl is-active --quiet "${SERVICE}.service"; then
        UP=1
        MONO=$(systemctl show "${SERVICE}.service" \
            -p ActiveEnterTimestampMonotonic 2>/dev/null | cut -d= -f2)
        case "$MONO" in ''|*[!0-9]*) MONO=0 ;; esac
        if [ "$MONO" -gt 0 ]; then
            START_TIME=$((BOOT + MONO / 1000000))
            UPTIME=$((NOW - START_TIME))
            [ "$UPTIME" -lt 0 ] && UPTIME=0
        fi
    fi

else
    # No systemd unit - fall back to a process match
    pgrep -f 'claim[-_.]agent' >/dev/null 2>&1 && UP=1
fi


# ---------------------------------------------------------
# MongoDB counters
# ---------------------------------------------------------
# One mongosh invocation instead of six. Each spawn costs
# 200-500ms; six of them on a short timer is most of the interval.

MONGO_OUT=$(mongosh "$MONGO_TARGET" --quiet --eval '
try {
    const base = __BASE_FILTER__;
    const c = db.getCollection("'"$COLLECTION"'");

    const dialed    = c.countDocuments(base);
    const answered  = c.countDocuments({ ...base, call_status: "Answered" });
    const abandoned = c.countDocuments({ ...base, call_status: "Abandoned" });
    const failed    = c.countDocuments({ ...base, $or: [
        { call_status: "Abandoned" },
        { hangup_cause: "DROP" },
        { disposition: { $in: [
            "NO_ROUTE_DESTINATION", "NO_USER_RESPONSE", "USER_BUSY" ] } }
    ]});

    // distinct campaigns seen in the last 15 minutes = "active"
    const since = new Date(Date.now() - 15 * 60 * 1000);
    const campaigns = c.distinct("campaign_uuid",
        { ...base, createdAt: { $gte: since } }).length;

    print([dialed, answered, abandoned, failed, campaigns].join(" "));
} catch (e) {
    print("ERR");
}
' 2>/dev/null)

if [[ "$MONGO_OUT" =~ ^[0-9]+\ [0-9]+\ [0-9]+\ [0-9]+\ [0-9]+$ ]]; then
    MONGO_UP=1
    read -r DIALED ANSWERED ABANDONED FAILED ACTIVE <<< "$MONGO_OUT"
fi


# ---------------------------------------------------------
# Write metrics
# ---------------------------------------------------------

{
    echo "# HELP claim_agent_up Claim Agent service status (1=up, 0=down)"
    echo "# TYPE claim_agent_up gauge"
    echo "claim_agent_up ${UP}"
    echo

    echo "# HELP claim_agent_start_time_seconds Unix timestamp when the service became active"
    echo "# TYPE claim_agent_start_time_seconds gauge"
    echo "claim_agent_start_time_seconds ${START_TIME}"
    echo

    echo "# HELP claim_agent_uptime_seconds Seconds the service has been continuously active"
    echo "# TYPE claim_agent_uptime_seconds gauge"
    echo "claim_agent_uptime_seconds ${UPTIME}"
    echo

    echo "# HELP claim_agent_mongo_up MongoDB reachable and queries succeeded (1=yes, 0=no)"
    echo "# TYPE claim_agent_mongo_up gauge"
    echo "claim_agent_mongo_up ${MONGO_UP}"
    echo

    # Only emit counters when mongo actually answered. Emitting 0 on
    # failure would look like a real drop to zero in Prometheus and
    # would make rate() report a counter reset.
    if [ "$MONGO_UP" -eq 1 ]; then

        echo "# HELP claim_agent_calls_dialed_total Cumulative campaign calls dialed"
        echo "# TYPE claim_agent_calls_dialed_total counter"
        echo "claim_agent_calls_dialed_total ${DIALED}"
        echo

        echo "# HELP claim_agent_calls_answered_total Cumulative campaign calls answered"
        echo "# TYPE claim_agent_calls_answered_total counter"
        echo "claim_agent_calls_answered_total ${ANSWERED}"
        echo

        echo "# HELP claim_agent_calls_abandoned_total Cumulative campaign calls abandoned"
        echo "# TYPE claim_agent_calls_abandoned_total counter"
        echo "claim_agent_calls_abandoned_total ${ABANDONED}"
        echo

        echo "# HELP claim_agent_calls_failed_total Cumulative failed or dropped dial attempts"
        echo "# TYPE claim_agent_calls_failed_total counter"
        echo "claim_agent_calls_failed_total ${FAILED}"
        echo

        echo "# HELP claim_agent_active_campaigns Distinct campaigns with activity in the last 15m"
        echo "# TYPE claim_agent_active_campaigns gauge"
        echo "claim_agent_active_campaigns ${ACTIVE}"

    fi

} > "$TMPFILE"

# mktemp creates 0600; node_exporter runs unprivileged and must read this
chmod 0644 "$TMPFILE"
mv "$TMPFILE" "$OUTPUT"
chmod 0644 "$OUTPUT"
chown "${OWNER}:${OWNER}" "$OUTPUT" 2>/dev/null || true

trap - EXIT
METRICS_EOF
}

substitute_placeholders() {
    # BASE_FILTER contains braces, quotes and $nin. None of those are sed
    # replacement metacharacters (only & and \ would be), so a plain s||| is safe.
    sed -i \
        -e "s|__BASE_FILTER__|${BASE_FILTER}|g" \
        -e "s|__TEXTFILE_DIR__|${TEXTFILE_DIR}|g" \
        -e "s|__NE_USER__|${NE_USER}|g" \
        -e "s|__SERVICE__|${SERVICE}|g" \
        -e "s|__DB__|${DB}|g" \
        -e "s|__COLLECTION__|${COLLECTION}|g" \
        -e "s|__CREDS__|${CREDS}|g" \
        "$METRICS_SCRIPT"
}

write_metrics_script() {
    step "Step 7: Install ${METRICS_SCRIPT} (${VARIANT})"

    if [ "$VARIANT" = "minimal" ]; then
        emit_minimal_metrics_script
    else
        emit_full_metrics_script
    fi
    substitute_placeholders
    ok "Metrics script written (${VARIANT}, scope ${SCOPE})"
}

# ===========================================================================
# Step 8 — validate
# ===========================================================================

validate_metrics_script() {
    step "Step 8: Validate"

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

    if grep -q '__TEXTFILE_DIR__\|__NE_USER__\|__SERVICE__\|__DB__\|__COLLECTION__\|__CREDS__\|__BASE_FILTER__' "$METRICS_SCRIPT"; then
        die "Placeholder substitution failed."
    fi
    ok "Placeholders substituted"
}

# ===========================================================================
# Step 9 — run once and lint
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
    mu="$(awk '/^claim_agent_mongo_up/ {print $2; exit}' "$PROM")"
    [ "$mu" = "1" ] \
        && ok "claim_agent_mongo_up = 1" \
        || warn "claim_agent_mongo_up = ${mu:-?} — queries failed; only service metrics present."
}

run_metrics_once() {
    step "Step 9: Manual run"

    "$METRICS_SCRIPT" || die "Metrics script exited non-zero."
    PROM="${TEXTFILE_DIR}/claim_agent.prom"
    [ -s "$PROM" ] || die "$PROM missing or empty."

    ls -l "$PROM" | indent
    head -3 "$PROM" | indent

    check_readable_by_exporter
    lint_prom_file
    check_mongo_up_metric
}

# ===========================================================================
# Step 10 — timer
# ===========================================================================

install_timer() {
    step "Step 10: Install service and timer (every $INTERVAL)"

    cat > "$SERVICE_UNIT" <<EOF
[Unit]
Description=Claim Agent Prometheus Metrics
After=mongod.service

[Service]
Type=oneshot
EnvironmentFile=-${CREDS}
ExecStart=${METRICS_SCRIPT}
EOF

    # AccuracySec=1s is required — systemd defaults to 1 minute, which would
    # stretch a 30s interval into minute-long gaps. 30s rather than 15s because
    # the mongo counts are the expensive part and rate() smooths anyway.
    cat > "$TIMER_UNIT" <<EOF
[Unit]
Description=Run Claim Agent Prometheus metrics every ${INTERVAL}

[Timer]
OnBootSec=${INTERVAL}
OnUnitActiveSec=${INTERVAL}
AccuracySec=1s
Unit=claim-agent-metrics.service

[Install]
WantedBy=timers.target
EOF

    chmod 0644 "$SERVICE_UNIT" "$TIMER_UNIT"
    systemctl daemon-reload
    systemctl enable --now claim-agent-metrics.timer >/dev/null 2>&1
    systemctl is-enabled --quiet claim-agent-metrics.timer || die "Timer not enabled."
    systemctl list-timers --all 2>/dev/null | grep -i claim | indent || true
    ok "claim-agent-metrics.timer enabled and started"
}

# ===========================================================================
# Step 11 — verify after a timer run
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
    count="$(curl -sf "localhost:${EXPORTER_PORT}/metrics" 2>/dev/null | grep -c '^claim_agent' || true)"
    [ "${count:-0}" -gt 0 ] \
        && ok "${count} claim_agent* series exposed on :${EXPORTER_PORT}" \
        || warn "No claim_agent* series on :${EXPORTER_PORT} yet."
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
        || warn "File not rewritten. Check: journalctl -u claim-agent-metrics.service -n 30"

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
  unit             : ${SERVICE}.service (${AG_ACTIVE} / ${AG_ENABLED})
  variant          : ${VARIANT}   scope: ${SCOPE}
  database         : ${DB}.${COLLECTION} (${TOTAL_CDRS} documents)
  credentials      : ${CREDS}
  exporter         : ${NE_UNIT:-<none>} as ${NE_USER}
  textfile dir     : ${TEXTFILE_DIR}
  output           : ${PROM} (mode ${MODE})
  timer            : claim-agent-metrics.timer every ${INTERVAL}
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
    identify_unit
    inspect_agent_source
    ask_monitor_ip
    store_credentials
    verify_connection
    probe_schema
    resolve_variant
    resolve_scope
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

# Allow `source ./install_claim_agent_metrics.sh --source-only` to load the
# functions without running anything, for step-by-step debugging.
case "${1:-}" in
    --source-only) init_colors; SOURCE_ONLY=1 ;;
    *) main "$@" ;;
esac
