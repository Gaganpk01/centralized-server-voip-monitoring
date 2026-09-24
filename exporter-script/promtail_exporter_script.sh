#!/usr/bin/env bash
#
# install_promtail.sh — Promtail on a PBX, shipping logs to Loki.
#
# Sources, each probed before it is configured:
#
#   nginx        /var/log/nginx/error.log
#   freeswitch   /var/log/freeswitch/freeswitch.log
#   fail2ban     /var/log/fail2ban.log
#   mongodb      /var/log/mongodb/mongod.log
#   monit        /var/log/monit.log
#   redis        /var/log/redis/redis-server.log
#   syslog       /var/log/syslog
#
# A source whose file is missing is skipped with a warning rather than
# breaking the install, so the same command works on every box regardless
# of what each one happens to run.
#
# FILTERING
#   Every source is filtered AT THE AGENT to error-level lines only, so
#   debug/info/notice never leave the PBX. This is not a display filter --
#   the dropped lines are gone and cannot be queried later. It cuts volume
#   enormously (a busy FreeSWITCH is mostly NOTICE) at the cost of being
#   unable to investigate anything that was not an error.
#
#   --keep-warnings also keeps warning-level lines. Worth using if you have
#   panels that query level=~"ERR|WARNING".
#
#   syslog is the exception: it carries no severity field, so it is
#   filtered by keyword rather than by level. That is approximate -- a
#   problem phrased in words the list does not contain gets discarded.
#
# HISTORY
#   On a FRESH install the agent starts at the END of every log, so only
#   new lines are shipped. Without this it would read each file from byte
#   zero and replay weeks of history into Loki -- entries timestamped from
#   the line itself, so they land in the past and a 15-minute dashboard
#   panel stays empty while the box grinds through gigabytes.
#
#   --backfill reads each file from the beginning instead. Reinstalling
#   over an existing positions file always resumes where it left off,
#   whichever flag is used.
#
# Run it bare and it asks for the monitoring server IP and this host's
# client name. Pass the flags to skip the questions.
#
# Usage:
#   sudo ./install_promtail.sh
#   sudo ./install_promtail.sh --loki http://5.161.81.122:3100 --server 'Telyo'
#   sudo ./install_promtail.sh --no-syslog
#   sudo ./install_promtail.sh --keep-warnings
#   sudo ./install_promtail.sh --backfill        (read existing logs too)
#   sudo ./install_promtail.sh --with-nginx-access
#   sudo ./install_promtail.sh --uninstall
#   sudo ./install_promtail.sh --uninstall --purge   (also deletes config)
#
# Per-source overrides: --nginx-error-log, --freeswitch-log,
# --fail2ban-log, --mongo-log, --monit-log, --redis-log, --syslog-path
#
# Skips: --no-nginx --no-freeswitch --no-fail2ban
#        --no-mongo --no-monit --no-redis --no-syslog
#
set -euo pipefail

# Promtail has been retired. Recent Loki releases publish the loki binary
# but no promtail archive, so resolving "latest" gives a 404. Left empty,
# the script resolves the newest release that still ships promtail (3.6.8
# at the time of writing) rather than pinning a version that ages badly.
# Grafana Alloy is the supported replacement when you migrate.
PROMTAIL_VERSION=""
PROMTAIL_FALLBACK="3.6.8"

LOKI_URL=""
SERVER_NAME=""

# ---- source paths ----------------------------------------------------
NGINX_ERROR_LOG="/var/log/nginx/error.log"
NGINX_ACCESS_GLOB="/var/log/nginx/*access*.log"
FS_LOG="/var/log/freeswitch/freeswitch.log"
FAIL2BAN_LOG="/var/log/fail2ban.log"
MONGO_LOG="/var/log/mongodb/mongod.log"
MONIT_LOG="/var/log/monit.log"
REDIS_LOG="/var/log/redis/redis-server.log"
SYSLOG_PATH="/var/log/syslog"

# ---- skips -----------------------------------------------------------
SKIP_NGINX=0
SKIP_FS=0
SKIP_FAIL2BAN=0
SKIP_MONGO=0
SKIP_MONIT=0
SKIP_REDIS=0
SKIP_SYSLOG=0
WANT_NGINX_ACCESS=0
KEEP_WARNINGS=0
BACKFILL=0
UNINSTALL=0
PURGE=0

CONFIG="/etc/promtail/promtail.yaml"
BIN="/usr/local/bin/promtail"
UNIT="/etc/systemd/system/promtail.service"
POSITIONS="/var/lib/promtail/positions.yaml"

C_R=$'\033[0m'; C_B=$'\033[1;34m'; C_G=$'\033[1;32m'; C_Y=$'\033[1;33m'; C_E=$'\033[1;31m'
[ -t 1 ] || { C_R=""; C_B=""; C_G=""; C_Y=""; C_E=""; }
step() { printf '\n%s==> %s%s\n' "$C_B" "$*" "$C_R"; }
ok()   { printf '%s  [ok]%s %s\n'   "$C_G" "$C_R" "$*"; }
warn() { printf '%s  [warn]%s %s\n' "$C_Y" "$C_R" "$*"; }
die()  { printf '%s  [fail]%s %s\n' "$C_E" "$C_R" "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --loki)             LOKI_URL="${2:?}"; shift 2 ;;
        --server)           SERVER_NAME="${2:?}"; shift 2 ;;
        --version)          PROMTAIL_VERSION="${2:?}"; shift 2 ;;
        --nginx-error-log)  NGINX_ERROR_LOG="${2:?}"; shift 2 ;;
        --freeswitch-log)   FS_LOG="${2:?}"; shift 2 ;;
        --fail2ban-log)     FAIL2BAN_LOG="${2:?}"; shift 2 ;;
        --mongo-log)        MONGO_LOG="${2:?}"; shift 2 ;;
        --monit-log)        MONIT_LOG="${2:?}"; shift 2 ;;
        --redis-log)        REDIS_LOG="${2:?}"; shift 2 ;;
        --syslog-path)      SYSLOG_PATH="${2:?}"; shift 2 ;;
        --with-nginx-access) WANT_NGINX_ACCESS=1; shift ;;
        --keep-warnings)    KEEP_WARNINGS=1; shift ;;
        --backfill)         BACKFILL=1; shift ;;
        --no-nginx)         SKIP_NGINX=1; shift ;;
        --no-freeswitch)    SKIP_FS=1; shift ;;
        --no-fail2ban)      SKIP_FAIL2BAN=1; shift ;;
        --no-mongo)         SKIP_MONGO=1; shift ;;
        --no-monit)         SKIP_MONIT=1; shift ;;
        --no-redis)         SKIP_REDIS=1; shift ;;
        --no-syslog)        SKIP_SYSLOG=1; shift ;;
        --uninstall)        UNINSTALL=1; shift ;;
        --purge)            PURGE=1; shift ;;
        -h|--help)          sed -n '3,55p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "Unknown option: $1" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "Run as root."

if [ "$UNINSTALL" -eq 1 ]; then
    step "Removing Promtail"
    systemctl disable --now promtail >/dev/null 2>&1 || true
    rm -f "$UNIT" "$BIN"; systemctl daemon-reload
    if [ "$PURGE" -eq 1 ]; then
        rm -rf /etc/promtail /var/lib/promtail
        ok "Removed binary, unit, config and positions."
    else
        ok "Removed binary and unit."
        # The positions file records how far into each log Promtail had read.
        # Keeping it means a reinstall resumes rather than re-shipping every
        # line already in Loki; --purge discards that and starts over.
        warn "Kept ${CONFIG} and ${POSITIONS} (pass --purge to delete them)."
    fi
    exit 0
fi

# ===========================================================================
# Prompts
# ===========================================================================

valid_ip() {
    local o
    case "$1" in *.*.*.*) ;; *) return 1 ;; esac
    local IFS=.
    set -- $1
    [ $# -eq 4 ] || return 1
    for o in "$@"; do
        case "$o" in ''|*[!0-9]*) return 1 ;; esac
        [ "${#o}" -le 3 ] && [ "$o" -le 255 ] || return 1
    done
    return 0
}

prompt_loki() {
    [ -t 0 ] || die "--loki is required when there is no terminal to ask on."
    local answer attempt=0
    cat >&2 <<'EOF'

    The IP of the MONITORING server -- the box running Grafana, Prometheus
    and Loki. Not this PBX. Logs collected here get pushed there.

    A bare IP is enough; port 3100 is assumed. A full http://host:port URL
    also works if Loki is on a non-default port.
EOF
    while [ "$attempt" -lt 3 ]; do
        attempt=$((attempt + 1))
        printf '    Monitoring server IP: ' >&2
        read -r answer || answer=""
        answer="$(printf '%s' "$answer" | tr -d '[:space:]')"
        [ -n "$answer" ] || { warn "Cannot be empty." >&2; continue; }
        case "$answer" in http://*|https://*) printf '%s' "$answer"; return 0 ;; esac
        if valid_ip "$answer"; then printf 'http://%s:3100' "$answer"; return 0; fi
        case "$answer" in
            *[!a-zA-Z0-9.-]*) warn "'${answer}' is not a valid IP, hostname or URL." >&2 ;;
            *) printf 'http://%s:3100' "$answer"; return 0 ;;
        esac
    done
    die "No valid address after 3 attempts."
}

prompt_server() {
    [ -t 0 ] || die "--server is required when there is no terminal to ask on."
    local answer attempt=0
    cat >&2 <<'EOF'

    The client name for THIS machine, exactly as it appears in the server
    label in prometheus.yml -- for example: Telyo, Web iCallify, VX-Telecom.

    Spelling, capitals and spaces must match. A mismatch is not an error
    anyone will see: metrics and logs simply arrive under two different
    names, and the dashboard dropdown shows one without the other.
EOF
    while [ "$attempt" -lt 3 ]; do
        attempt=$((attempt + 1))
        printf '    Server name for this host: ' >&2
        read -r answer || answer=""
        # Trim the ends but keep inner spaces: "Web iCallify" must survive.
        answer="$(printf '%s' "$answer" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
        [ -n "$answer" ] && { printf '%s' "$answer"; return 0; }
        warn "Cannot be empty." >&2
    done
    die "No server name given after 3 attempts."
}

[ -n "$LOKI_URL" ]    || LOKI_URL="$(prompt_loki)"
[ -n "$SERVER_NAME" ] || SERVER_NAME="$(prompt_server)"

LOKI_URL="${LOKI_URL%/}"
LOKI_URL="${LOKI_URL%/loki/api/v1/push}"
PUSH_URL="${LOKI_URL}/loki/api/v1/push"

ok "Pushing to  : ${PUSH_URL}"
ok "Server label: ${SERVER_NAME}"

# Fail here rather than after installing: an unreachable Loki means the
# agent starts, buffers, retries and eventually drops everything, which
# looks like a working install until someone checks the dashboard.
if ! curl -sf --max-time 10 "${LOKI_URL}/ready" 2>/dev/null | grep -qi ready; then
    warn "Cannot reach ${LOKI_URL}/ready from this host."
    warn "Either Loki is not installed there, or its firewall does not allow this IP."
    if [ -t 0 ]; then
        printf '    Continue anyway? [y/N]: '
        read -r _ans
        case "$_ans" in [yY]*) ;; *) die "Stopped. Install Loki first, or open the port." ;; esac
    else
        die "Stopped. Install Loki first, or open port 3100 to this host."
    fi
fi

# ===========================================================================
# Download
# ===========================================================================
step "Installing Promtail"

# The /releases/latest redirect is plain HTTP and not rate limited, unlike
# the API's 60 calls per hour per IP. Resolve first, then confirm the
# archive actually exists -- the newest release usually will NOT have it.
resolve_version() {
    local v=""
    v="$(curl -sI --max-time 15 https://github.com/grafana/loki/releases/latest 2>/dev/null \
        | grep -i '^location:' | sed 's|.*/tag/v||' | tr -d '\r[:space:]' || true)"
    if [ -z "$v" ]; then
        v="$(curl -sf --max-time 15 \
            https://api.github.com/repos/grafana/loki/releases/latest 2>/dev/null \
            | grep -m1 '"tag_name"' | cut -d'"' -f4 | sed 's/^v//' || true)"
    fi
    printf '%s' "$v"
}

asset_exists() {
    [ "$(curl -s -o /dev/null -w '%{http_code}' -L --max-time 30 "$1")" = "200" ]
}

case "$(uname -m)" in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    *) die "Unsupported architecture: $(uname -m)" ;;
esac

if [ -z "$PROMTAIL_VERSION" ]; then
    PROMTAIL_VERSION="$(resolve_version)"
    [ -n "$PROMTAIL_VERSION" ] || PROMTAIL_VERSION="$PROMTAIL_FALLBACK"
fi

URL="https://github.com/grafana/loki/releases/download/v${PROMTAIL_VERSION}/promtail-linux-${ARCH}.zip"
if ! asset_exists "$URL"; then
    warn "v${PROMTAIL_VERSION} does not ship promtail (retired upstream)."
    warn "Walking back to the newest release that still does."
    FOUND=""
    MAJ="${PROMTAIL_VERSION%%.*}"; REST="${PROMTAIL_VERSION#*.}"
    MIN="${REST%%.*}"; PATCH="${REST#*.}"
    for m in $(seq "$MIN" -1 0); do
        start="$PATCH"; [ "$m" -eq "$MIN" ] || start=9
        for p in $(seq "$start" -1 0); do
            cand="${MAJ}.${m}.${p}"
            if asset_exists "https://github.com/grafana/loki/releases/download/v${cand}/promtail-linux-${ARCH}.zip"; then
                FOUND="$cand"; break 2
            fi
        done
    done
    [ -n "$FOUND" ] || die "No release found with promtail-linux-${ARCH}.zip.
      Promtail may be fully withdrawn. Migrate to Grafana Alloy, or pass
      a known-good version with --version."
    PROMTAIL_VERSION="$FOUND"
    URL="https://github.com/grafana/loki/releases/download/v${PROMTAIL_VERSION}/promtail-linux-${ARCH}.zip"
fi
ok "Version: ${PROMTAIL_VERSION} (${ARCH})"

command -v unzip >/dev/null 2>&1 || { apt-get update -qq && apt-get install -y -qq unzip; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
curl -sfL --max-time 300 "$URL" -o "${TMP}/p.zip" || die "Download failed: $URL"
unzip -qo "${TMP}/p.zip" -d "$TMP"
install -m 0755 "${TMP}/promtail-linux-${ARCH}" "$BIN"
ok "Binary: $BIN"

mkdir -p /etc/promtail /var/lib/promtail

# ===========================================================================
# Probe
# ===========================================================================
step "Checking log sources"

# Sets HAVE_<name>=1 when the source is wanted AND present. A missing file
# is a warning, not a failure: the same command has to work on a box that
# runs FreeSWITCH and one that runs only nginx.
probe() {
    local skip="$1" name="$2" path="$3" varname="$4"
    if [ "$skip" -eq 1 ]; then
        printf -v "$varname" '%s' 0
        ok "$(printf '%-11s' "$name") skipped"
        return 0
    fi
    if [ -r "$path" ]; then
        printf -v "$varname" '%s' 1
        ok "$(printf '%-11s' "$name") ${path}"
    else
        printf -v "$varname" '%s' 0
        warn "$(printf '%-11s' "$name") ${path} not found -- skipped"
    fi
}

probe "$SKIP_NGINX"    nginx      "$NGINX_ERROR_LOG" HAVE_NGINX
probe "$SKIP_FS"       freeswitch "$FS_LOG"          HAVE_FS
probe "$SKIP_FAIL2BAN" fail2ban   "$FAIL2BAN_LOG"    HAVE_FAIL2BAN
probe "$SKIP_MONGO"    mongodb    "$MONGO_LOG"       HAVE_MONGO
probe "$SKIP_MONIT"    monit      "$MONIT_LOG"       HAVE_MONIT
probe "$SKIP_REDIS"    redis      "$REDIS_LOG"       HAVE_REDIS
probe "$SKIP_SYSLOG"   syslog     "$SYSLOG_PATH"     HAVE_SYSLOG

HAVE_NGINX_ACCESS=0
if [ "$WANT_NGINX_ACCESS" -eq 1 ] && [ "$SKIP_NGINX" -eq 0 ]; then
    HAVE_NGINX_ACCESS=1
    ok "$(printf '%-11s' nginx-acc) ${NGINX_ACCESS_GLOB}"
fi

# ===========================================================================
# Config
# ===========================================================================
step "Writing ${CONFIG}"

# One helper instead of nine near-identical heredocs. Extra pipeline YAML
# is passed as a single pre-indented string so each source can extract its
# own level format without the emitter knowing anything about it.
# Levels to DROP per source, assembled from the keep-warnings choice.
# Listing what to drop rather than what to keep is deliberate: Go's RE2 has
# no negative lookahead, so "everything except X" cannot be expressed as a
# regex here -- and an explicit drop list fails safe, keeping any level the
# list does not name rather than silently discarding it.
if [ "$KEEP_WARNINGS" -eq 1 ]; then
    DROP_NGINX='^(debug|info|notice)$'
    DROP_FS='^(DEBUG|INFO|NOTICE)$'
    DROP_F2B='^(DEBUG|INFO)$'
    DROP_MONGO='^(D|I)$'
    DROP_MONIT='^(info|debug)$'
    DROP_REDIS='^[.*-]$'
    ok "Keeping warning-level lines as well as errors."
else
    DROP_NGINX='^(debug|info|notice|warn)$'
    DROP_FS='^(DEBUG|INFO|NOTICE|WARNING)$'
    DROP_F2B='^(DEBUG|INFO|WARNING)$'
    DROP_MONGO='^(D|I|W)$'
    DROP_MONIT='^(info|debug|warning)$'
    DROP_REDIS='^[.*-]$'
    warn "Dropping everything below error level at the agent."
    warn "Those lines are discarded on this host and cannot be queried later."
    warn "Use --keep-warnings if any panel queries level=~\"ERR|WARNING\"."
fi

emit_job() {
    local job="$1" path="$2" stages="${3:-}"
    cat <<EOF

  - job_name: ${job}
    static_configs:
      - targets: [localhost]
        labels:
          job: ${job}
          server: '${SERVER_NAME}'
          __path__: ${path}
EOF
    [ -n "$stages" ] && printf '%s\n' "$stages"
    return 0
}

{
cat <<EOF
server:
  http_listen_port: 9080
  grpc_listen_port: 0
  log_level: warn

positions:
  filename: ${POSITIONS}

clients:
  - url: ${PUSH_URL}
    # A PBX that loses the link to Loki should keep retrying rather than
    # dropping the very logs you will want to read afterwards.
    backoff_config:
      min_period: 500ms
      max_period: 5m
      max_retries: 20
    batchwait: 1s
    batchsize: 1048576

scrape_configs:
EOF

# ---- nginx error:  2026/09/16 15:29:01 [error] 1234#0: ... ----
[ "$HAVE_NGINX" -eq 1 ] && emit_job nginx "$NGINX_ERROR_LOG" \
"    pipeline_stages:
      - regex:
          expression: '^\\d{4}/\\d{2}/\\d{2} \\d{2}:\\d{2}:\\d{2} \\[(?P<level>\\w+)\\]'
      - labels:
          level:
      # A line whose level did not parse is KEPT, not dropped -- that is
      # how continuation lines of a multi-line error survive.
      - drop:
          source: level
          expression: '${DROP_NGINX}'
          drop_counter_reason: nginx_below_error"

[ "$HAVE_NGINX_ACCESS" -eq 1 ] && emit_job nginx-access "$NGINX_ACCESS_GLOB"

# ---- freeswitch:  2026-09-16 15:29:01.123456 [ERR] switch_core.c:123 ... ----
[ "$HAVE_FS" -eq 1 ] && emit_job freeswitch "$FS_LOG" \
"    pipeline_stages:
      # FreeSWITCH stack traces span many lines. Without this each line
      # becomes its own entry and the trace is unreadable in Grafana.
      - multiline:
          firstline: '^\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}\\.\\d+'
          max_wait_time: 3s
      - regex:
          expression: '\\[(?P<level>DEBUG|INFO|NOTICE|WARNING|ERR|CRIT|ALERT|EMERG)\\]'
      - labels:
          level:
      - drop:
          source: level
          expression: '${DROP_FS}'
          drop_counter_reason: fs_below_error"

# ---- fail2ban:  2026-09-16 15:29:01,123 fail2ban.actions [123]: NOTICE ... ----
[ "$HAVE_FAIL2BAN" -eq 1 ] && emit_job fail2ban "$FAIL2BAN_LOG" \
"    pipeline_stages:
      - regex:
          expression: '^\\S+ \\S+ (?P<component>\\S+)\\s+\\[\\d+\\]: (?P<level>[A-Z]+)\\s+(?P<msg>.*)'
      - labels:
          level:
          component:
      # NOTICE is kept here by request -- it is the level fail2ban uses to
      # record an actual ban, which is the line you most want to see.
      - drop:
          source: level
          expression: '${DROP_F2B}'
          drop_counter_reason: f2b_below_notice"

# ---- mongodb ----
# Modern mongod logs structured JSON with severity in 's': F E W I D.
# Parsing it as JSON gives a real level label instead of a line filter.
[ "$HAVE_MONGO" -eq 1 ] && emit_job mongodb "$MONGO_LOG" \
"    pipeline_stages:
      - json:
          expressions:
            level: s
            component: c
      - labels:
          level:
          component:
      # mongod severities are single letters: F E W I D.
      - drop:
          source: level
          expression: '${DROP_MONGO}'
          drop_counter_reason: mongo_below_error"

# ---- monit:  [UTC Sep 16 15:29:01] error : ... ----
[ "$HAVE_MONIT" -eq 1 ] && emit_job monit "$MONIT_LOG" \
"    pipeline_stages:
      - regex:
          expression: '^\\[[^]]+\\]\\s+(?P<level>\\w+)\\s+:'
      - labels:
          level:
      - drop:
          source: level
          expression: '${DROP_MONIT}'
          drop_counter_reason: monit_below_error"

# ---- redis:  123:M 16 Sep 2026 15:29:01.123 * message ----
# The single character before the message is the level: . debug, - verbose,
# * notice, # warning. Captured raw; map it in Grafana if you want words.
[ "$HAVE_REDIS" -eq 1 ] && emit_job redis "$REDIS_LOG" \
"    pipeline_stages:
      - regex:
          expression: '^\\d+:\\w+ \\d+ \\w+ \\d{4} \\d{2}:\\d{2}:\\d{2}\\.\\d+ (?P<level>[.\\-*#])'
      - labels:
          level:
      # Redis has no error level. Its highest is # (warning), which is what
      # it uses for genuine faults, so # is what survives this filter.
      - drop:
          source: level
          expression: '${DROP_REDIS}'
          drop_counter_reason: redis_below_warning"

# ---- syslog ----
# No severity in the line itself, so label by program instead -- that is
# what you actually filter on when reading syslog.
[ "$HAVE_SYSLOG" -eq 1 ] && emit_job syslog "$SYSLOG_PATH" \
"    pipeline_stages:
      - regex:
          expression: '^\\w{3}\\s+\\d+ \\d{2}:\\d{2}:\\d{2} \\S+ (?P<program>[^\\[:]+)'
      - labels:
          program:
      # syslog carries no severity, so this is a keyword filter on the line.
      # Anything not matching is dropped, which will occasionally discard a
      # real problem phrased in words this list does not contain.
      - match:
          selector: '{job=\"syslog\"} !~ \"(?i)(error|fail|critical|panic|segfault|denied|refused|timed out|cannot|unable)\"'
          action: drop
          drop_counter_reason: syslog_not_error"

true
} > "$CONFIG"

chmod 0644 "$CONFIG"
JOBS="$(grep -c '^  - job_name:' "$CONFIG" || true)"
ok "${JOBS} scrape jobs written"

# ===========================================================================
# Positions
# ===========================================================================
# Promtail resumes from the byte offset recorded here. With no positions
# file it starts each log at byte zero and replays the whole history --
# and because Loki timestamps every entry from the line itself, weeks of
# old logs land in the past. A dashboard showing the last 15 minutes then
# stays empty for hours while the agent works through gigabytes it has
# already been told nobody wants.
#
# So on a fresh install, seed the offsets to the current end of each file.
# An existing positions file is never touched: a reinstall resumes where
# it left off, which is what you want when only the filters changed.
if [ -s "$POSITIONS" ]; then
    ok "Positions file exists -- resuming where the last run left off."
elif [ "$BACKFILL" -eq 1 ]; then
    warn "--backfill: reading every log from the beginning."
    warn "Expect old timestamps in Grafana until it catches up."
else
    seed_position() {
        [ "$1" -eq 1 ] || return 0
        [ -r "$2" ] || return 0
        printf '  %s: "%s"\n' "$2" "$(stat -c %s "$2")" >> "$POSITIONS"
    }
    printf 'positions:\n' > "$POSITIONS"
    seed_position "$HAVE_NGINX"    "$NGINX_ERROR_LOG"
    seed_position "$HAVE_FS"       "$FS_LOG"
    seed_position "$HAVE_FAIL2BAN" "$FAIL2BAN_LOG"
    seed_position "$HAVE_MONGO"    "$MONGO_LOG"
    seed_position "$HAVE_MONIT"    "$MONIT_LOG"
    seed_position "$HAVE_REDIS"    "$REDIS_LOG"
    seed_position "$HAVE_SYSLOG"   "$SYSLOG_PATH"
    chmod 0644 "$POSITIONS"
    SEEDED="$(grep -c ': "' "$POSITIONS" || true)"
    ok "Starting at the end of ${SEEDED} log files -- only new lines are shipped."
    ok "Pass --backfill to read existing history instead."
fi

"$BIN" -config.file="$CONFIG" -check-syntax 2>/dev/null \
    && ok "Config syntax OK" \
    || warn "Could not syntax-check (older Promtail); continuing."

# ===========================================================================
# systemd
# ===========================================================================
# Runs as root: most of /var/log is not readable by an
# unprivileged user without extra group juggling, and a log shipper that
# silently reads nothing is worse than one running with more privilege.
cat > "$UNIT" <<EOF
[Unit]
Description=Promtail log shipper
After=network-online.target
Wants=network-online.target

[Service]
User=root
ExecStart=${BIN} -config.file=${CONFIG}
Restart=on-failure
RestartSec=10s

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now promtail >/dev/null 2>&1
sleep 5
systemctl is-active --quiet promtail \
    || die "Promtail failed to start. Check: journalctl -u promtail -n 50"
ok "promtail.service running"

# ===========================================================================
# Verify
# ===========================================================================
step "Verifying delivery"

sleep 10
SENT="$(curl -sf localhost:9080/metrics 2>/dev/null \
    | awk '/^promtail_sent_entries_total/ {s+=$2} END {printf "%.0f", s+0}')"
DROPPED="$(curl -sf localhost:9080/metrics 2>/dev/null \
    | awk '/^promtail_dropped_entries_total/ {s+=$2} END {printf "%.0f", s+0}')"
ok "entries sent: ${SENT:-0}   dropped: ${DROPPED:-0}"
# The pipeline drop stage increments logentry_dropped_lines_total, NOT
# promtail_dropped_entries_total -- the latter counts delivery failures
# (rate limits, ingester errors) and stays at zero when filtering works.
printf '    filtered out by the level filter:\n'
FILTERED="$(curl -sf localhost:9080/metrics 2>/dev/null \
    | awk '/^logentry_dropped_lines_total\{/ {print "      " $0}')"
if [ -n "$FILTERED" ]; then
    printf '%s\n' "$FILTERED"
else
    printf '      (none yet -- counters appear once matching lines are read)\n'
fi
[ "${SENT:-0}" = "0" ] && warn "Nothing sent yet. Give it a minute, then: journalctl -u promtail -n 30"

cat <<EOF

$(printf '%s==> Done%s' "$C_B" "$C_R")

  server label : ${SERVER_NAME}
  pushing to   : ${PUSH_URL}
  config       : ${CONFIG}
  scrape jobs  : ${JOBS}
  promtail UI  : http://localhost:9080/targets

Try these in Grafana -> Explore -> Loki:

  {server="${SERVER_NAME}"}
  {server="${SERVER_NAME}", job="nginx"}
  {server="${SERVER_NAME}", job="freeswitch"}
  {server="${SERVER_NAME}", job="fail2ban"}
  {server="${SERVER_NAME}", job="mongodb"}
  {server="${SERVER_NAME}", job="monit"}
  {server="${SERVER_NAME}", job="redis"}
  {server="${SERVER_NAME}", job="syslog"}

Which jobs are which is easiest to see here:

  sum by (job) (count_over_time({server="${SERVER_NAME}"}[1h]))

Only error-level lines are shipped, so these selectors need no level
filter -- everything present is already an error.

If a query returns nothing, check http://localhost:9080/targets on this
host first -- it shows which files Promtail actually opened. A source that
is genuinely quiet and a source that is misconfigured look identical from
Grafana; the targets page tells them apart.
EOF
