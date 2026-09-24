#!/usr/bin/env bash
#
# install_redis_exporter.sh — install redis_exporter on a remote server.
#
# Structured as one function per step, orchestrated by main() at the bottom.
# Every function is independently callable, so you can source this file and run
# a single step while debugging:
#
#   source ./install_redis_exporter.sh --source-only
#   read_redis_config
#   verify_metrics
#   check_no_password_leak
#
# Covers the remote-server half of the runbook, Steps 1-13:
#
#   Step 1   verify redis-server is running and answering
#   Step 2   read the Redis port, bind address and requirepass from redis.conf
#   Step 3   create the redis_exporter system user and group
#   Step 4   resolve the version, detect the arch, download, VERIFY sha256,
#            extract and install the binary
#   Step 5   store REDIS_ADDR (and REDIS_PASSWORD if needed) in a 0600 file
#   Step 7   write the systemd unit with a hardened sandbox
#   Step 8   daemon-reload, enable, start
#   Step 9   verify the service is active and the port is listening
#   Step 10  scrape localhost and check redis_up
#   Step 11  confirm no password appears on the process command line
#   Step 12  open the firewall for the monitoring server
#   Step 13  report the kept download (nothing is deleted)
#
# The exporter listens on 9104 by default here, matching the scrape job in the
# runbook. Note upstream's own default is 9121, so any dashboard or example
# config you copy may need the port changed.
#
# The monitoring server IP is always asked for interactively -- there is no
# flag for it and no default. Pass --no-firewall to skip that step.
#
# Safe to re-run. On an existing install it stops the service, replaces the
# binary, and restarts -- so it doubles as an upgrade path.
#
# Usage:
#   sudo ./install_redis_exporter.sh
#   sudo ./install_redis_exporter.sh --port 9121
#   sudo ./install_redis_exporter.sh --redis-port 6380 --version v1.89.0
#   sudo ./install_redis_exporter.sh --no-firewall --clean-download
#   sudo ./install_redis_exporter.sh --uninstall
#
set -euo pipefail

# ===========================================================================
# Configuration
# ===========================================================================
REPO="oliver006/redis_exporter"
VERSION=""                    # empty = detect the latest release
FALLBACK_VERSION="v1.89.0"    # used only if detection fails
EXP_USER="redis_exporter"
LISTEN_PORT="9104"            # runbook's scrape job; upstream default is 9121
REDIS_HOST="127.0.0.1"
REDIS_PORT=""                 # empty = read from redis.conf, else 6379
REDIS_CONF="/etc/redis/redis.conf"
REDIS_UNIT="redis-server"
BIN_PATH="/usr/local/bin/redis_exporter"
ENVFILE="/etc/default/redis_exporter"
UNIT="/etc/systemd/system/redis_exporter.service"
WORKDIR="/usr/src/monitoring"

MONITOR_IP=""
REDIS_PASSWORD=""
SKIP_FIREWALL=0
SKIP_CHECKSUM=0
KEEP_DOWNLOAD=1               # keep downloads by default
RESET_ENV=0
UNINSTALL=0
PURGE_USER=0
SOURCE_ONLY=0

# Runtime state shared between steps.
EXISTING=""; R_ACTIVE=""; NEEDS_AUTH=0; HAS_REQUIREPASS=0
CONF_PORT=""; CONF_BIND=""; CONF_PROTECTED=""
ARCH=""; STEM=""; TARBALL=""; SUMFILE=""; BASE=""
E_ACTIVE=""; E_ENABLED=""; REDIS_UP=""

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
trim_wide() { tr -s ' ' | cut -c1-120; }

# ===========================================================================
# Small utilities
# ===========================================================================

usage() { sed -n '3,45p' "$0" | sed 's/^# \{0,1\}//'; }

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

service_main_pid() {
    # Ask systemd for the PID it started. pgrep -f 'redis_exporter' would also
    # match this installer when saved as redis_exporter.sh, and after a restart
    # the script has the lower PID.
    local pid
    pid="$(systemctl show redis_exporter -p MainPID --value 2>/dev/null || true)"
    case "$pid" in ''|0) pid="$(pgrep -x redis_exporter | head -1 || true)" ;; esac
    printf '%s' "$pid"
}

port_holder() {
    command -v ss >/dev/null 2>&1 || return 0
    ss -tulnp 2>/dev/null | grep ":${1} " | head -1 || true
}

scrape_metrics() {
    curl -sf --max-time 10 "localhost:${LISTEN_PORT}/metrics" 2>/dev/null || true
}

redact_password() {
    sed -E 's/^(REDIS_PASSWORD=).*/\1<redacted>/'
}

# ===========================================================================
# Argument parsing and preflight
# ===========================================================================

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --version)        need_arg "$1" "${2:-}"; VERSION="$2"; shift 2 ;;
            --user)           need_arg "$1" "${2:-}"; EXP_USER="$2"; shift 2 ;;
            --port)           need_arg "$1" "${2:-}"; LISTEN_PORT="$2"; shift 2 ;;
            --redis-host)     need_arg "$1" "${2:-}"; REDIS_HOST="$2"; shift 2 ;;
            --redis-port)     need_arg "$1" "${2:-}"; REDIS_PORT="$2"; shift 2 ;;
            --redis-conf)     need_arg "$1" "${2:-}"; REDIS_CONF="$2"; shift 2 ;;
            --redis-unit)     need_arg "$1" "${2:-}"; REDIS_UNIT="$2"; shift 2 ;;
            --envfile)        need_arg "$1" "${2:-}"; ENVFILE="$2"; shift 2 ;;
            --workdir)        need_arg "$1" "${2:-}"; WORKDIR="$2"; shift 2 ;;
            --reset-env)      RESET_ENV=1; shift ;;
            --skip-checksum)  SKIP_CHECKSUM=1; shift ;;
            --clean-download) KEEP_DOWNLOAD=0; shift ;;
            --no-firewall)    SKIP_FIREWALL=1; shift ;;
            --purge-user)     PURGE_USER=1; shift ;;
            --uninstall)      UNINSTALL=1; shift ;;
            --source-only)    SOURCE_ONLY=1; shift ;;
            -h|--help)        usage; exit 0 ;;
            *) die "Unknown option: $1 (try --help)" ;;
        esac
    done

    is_number "$LISTEN_PORT" || die "--port must be a number (got '$LISTEN_PORT')."
    if [ -n "$REDIS_PORT" ]; then
        is_number "$REDIS_PORT" || die "--redis-port must be a number (got '$REDIS_PORT')."
    fi
    return 0
}

require_root() {
    [ "$(id -u)" -eq 0 ] || die "Must run as root (use sudo)."
    command -v systemctl >/dev/null 2>&1 || die "systemd required; systemctl not found."
}

ensure_tools() {
    step "Required tools"
    local missing="" c
    for c in curl tar sha256sum; do
        command -v "$c" >/dev/null 2>&1 || missing="${missing} $c"
    done
    if [ -n "$missing" ]; then
        warn "Installing:${missing}"
        if command -v apt-get >/dev/null 2>&1; then
            DEBIAN_FRONTEND=noninteractive apt-get update -qq
            DEBIAN_FRONTEND=noninteractive apt-get install -y curl tar coreutils
        elif command -v dnf >/dev/null 2>&1; then dnf install -y curl tar coreutils
        elif command -v yum >/dev/null 2>&1; then yum install -y curl tar coreutils
        else die "Install these manually:${missing}"
        fi
    fi
    ok "curl, tar and sha256sum available"
}

# ===========================================================================
# Uninstall
# ===========================================================================

do_uninstall() {
    step "Removing redis_exporter"
    systemctl disable --now redis_exporter >/dev/null 2>&1 || true
    rm -f "$UNIT" "$BIN_PATH" "$ENVFILE"
    rm -rf /etc/systemd/system/redis_exporter.service.d
    systemctl daemon-reload
    ok "Removed unit, binary and ${ENVFILE}."
    if [ "$PURGE_USER" -eq 1 ]; then
        userdel "$EXP_USER" >/dev/null 2>&1 || true
        groupdel "$EXP_USER" >/dev/null 2>&1 || true
        ok "Removed the ${EXP_USER} user and group."
    else
        warn "Kept the ${EXP_USER} user (pass --purge-user to remove it)."
    fi
    warn "Kept firewall rules for port ${LISTEN_PORT}."
}

# ===========================================================================
# Preflight — existing install / port conflict
# ===========================================================================

check_existing_install() {
    step "Checking for an existing install"

    if [ -x "$BIN_PATH" ]; then
        EXISTING="$("$BIN_PATH" --version 2>&1 \
            | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
        ok "Found ${BIN_PATH} ${EXISTING:-(version unknown)}"
    else
        ok "No existing binary at ${BIN_PATH}."
    fi

    # 9104 is also the conventional mysqld_exporter port, and this box already
    # runs other exporters, so make sure nothing else owns it.
    local holder
    holder="$(port_holder "$LISTEN_PORT")"
    [ -n "$holder" ] || { ok "Port ${LISTEN_PORT} is free."; return 0; }
    printf '    port %s currently held by:\n' "$LISTEN_PORT"
    printf '%s\n' "$holder" | trim_wide | indent6
    printf '%s' "$holder" | grep -q 'redis_exporter' \
        || die "Port ${LISTEN_PORT} is held by something other than redis_exporter. Pick another with --port."
}

# ===========================================================================
# Step 1 — verify Redis
# ===========================================================================

verify_redis_running() {
    step "Step 1: Verify Redis"

    R_ACTIVE="$(systemctl is-active "$REDIS_UNIT" 2>/dev/null || true)"
    if [ "$R_ACTIVE" != "active" ] && systemctl is-active --quiet redis 2>/dev/null; then
        # Some distributions name the unit plain 'redis'.
        REDIS_UNIT="redis"
        R_ACTIVE="active"
        warn "Using unit name 'redis' instead of 'redis-server'."
    fi
    printf '    unit       : %s\n    is-active  : %s\n' "$REDIS_UNIT" "${R_ACTIVE:-unknown}"
    [ "$R_ACTIVE" = "active" ] || warn "Redis is not active; redis_up will report 0 until it starts."
}

# ===========================================================================
# Step 2 — read redis.conf, prove reachability
# ===========================================================================

read_redis_config() {
    step "Step 2: Redis configuration"

    if [ ! -r "$REDIS_CONF" ]; then
        warn "${REDIS_CONF} not readable (see --redis-conf); assuming defaults."
    else
        CONF_PORT="$(awk '/^[[:space:]]*port[[:space:]]+[0-9]+/ {print $2; exit}' "$REDIS_CONF" || true)"
        CONF_BIND="$(awk '/^[[:space:]]*bind[[:space:]]/ {$1=""; sub(/^ /,""); print; exit}' "$REDIS_CONF" || true)"
        CONF_PROTECTED="$(awk '/^[[:space:]]*protected-mode[[:space:]]/ {print $2; exit}' "$REDIS_CONF" || true)"
        # Only an uncommented requirepass counts — a commented-out one above
        # the live line is a classic false positive.
        grep -qE '^[[:space:]]*requirepass[[:space:]]+.+' "$REDIS_CONF" && HAS_REQUIREPASS=1
        printf '    config     : %s\n' "$REDIS_CONF"
        printf '    port       : %s\n' "${CONF_PORT:-<not set, default 6379>}"
        printf '    bind       : %s\n' "${CONF_BIND:-<not set>}"
        printf '    protected-mode: %s\n' "${CONF_PROTECTED:-<not set>}"
        printf '    requirepass: %s\n' "$([ "$HAS_REQUIREPASS" -eq 1 ] && echo 'SET' || echo 'not set')"
    fi

    # The runbook's env file said 6104, which is not a Redis port — it looks
    # like the exporter's 9104 mistyped. Derive the real one from the config.
    [ -n "$REDIS_PORT" ] || REDIS_PORT="${CONF_PORT:-6379}"
    is_number "$REDIS_PORT" || die "Redis port '${REDIS_PORT}' is not a number."
    ok "Redis address: ${REDIS_HOST}:${REDIS_PORT}"
}

probe_redis_auth() {
    # Prove reachability rather than trusting the config.
    if ! command -v redis-cli >/dev/null 2>&1; then
        warn "redis-cli not installed; cannot verify connectivity here."
        [ "$HAS_REQUIREPASS" -eq 1 ] && NEEDS_AUTH=1
        return 0
    fi

    local ping
    ping="$(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ping 2>&1 || true)"
    printf '    redis-cli ping: %s\n' "$ping"
    case "$ping" in
        PONG) ok "Redis answers without authentication." ;;
        *NOAUTH*|*NOPERM*)
            NEEDS_AUTH=1
            warn "Redis requires authentication." ;;
        *)  warn "Unexpected ping reply — the exporter may report redis_up 0." ;;
    esac
    [ "$HAS_REQUIREPASS" -eq 1 ] && NEEDS_AUTH=1
    return 0
}

# ===========================================================================
# Monitoring server address
# ===========================================================================

ask_monitor_ip() {
    # Asked before the slow download so the run does not stall for input later.
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
        warn "Skipping the firewall rule. Open ${LISTEN_PORT}/tcp for the monitoring server yourself."
    else
        ok "Will allow ${MONITOR_IP} to reach port ${LISTEN_PORT}/tcp"
    fi
}

# ===========================================================================
# Redis password
# ===========================================================================

password_from_envfile() {
    # shellcheck disable=SC1090
    ( . "$ENVFILE"; printf '%s' "${REDIS_PASSWORD:-}" )
}

verify_redis_password() {
    command -v redis-cli >/dev/null 2>&1 || return 0
    local reply
    # REDISCLI_AUTH keeps the password out of this process's own argv, unlike
    # redis-cli -a which would put it in ps for the life of the check.
    reply="$(REDISCLI_AUTH="$REDIS_PASSWORD" \
        redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ping 2>&1 || true)"
    case "$reply" in
        PONG) ok "Authenticated successfully." ;;
        *) printf '      %s\n' "$reply"
           die "Authentication failed. Fix the password before continuing." ;;
    esac
}

ask_redis_password() {
    [ "$NEEDS_AUTH" -eq 1 ] || return 0
    step "Redis password"

    if [ -r "$ENVFILE" ] && [ "$RESET_ENV" -eq 0 ] && grep -q '^REDIS_PASSWORD=' "$ENVFILE"; then
        ok "Reusing the password already in ${ENVFILE} (--reset-env to replace)."
        REDIS_PASSWORD="$(password_from_envfile)"
    elif [ ! -t 0 ]; then
        die "Redis needs a password and there is no terminal to ask on. Put REDIS_PASSWORD= in ${ENVFILE} first."
    else
        printf '    Redis password (hidden): '
        read -rs REDIS_PASSWORD; printf '\n'
        [ -n "$REDIS_PASSWORD" ] || die "Password cannot be empty when Redis requires auth."
    fi

    verify_redis_password
}

# ===========================================================================
# Step 3 — service user
# ===========================================================================

create_service_user() {
    step "Step 3: Service user"

    if id "$EXP_USER" >/dev/null 2>&1; then
        ok "User ${EXP_USER} already exists: $(id "$EXP_USER")"
    else
        # --system keeps the UID below the login range and marks it
        # non-interactive; a plain useradd hands out a normal login UID.
        useradd --system --no-create-home --shell /usr/sbin/nologin "$EXP_USER" \
            || die "Could not create the ${EXP_USER} user."
        ok "Created: $(id "$EXP_USER")"
    fi

    getent group "$EXP_USER" >/dev/null 2>&1 || {
        groupadd --system "$EXP_USER"
        usermod -g "$EXP_USER" "$EXP_USER"
        warn "Created the missing ${EXP_USER} group."
    }
    ok "Group ${EXP_USER} present"
}

# ===========================================================================
# Step 4a — version
# ===========================================================================

latest_version_via_redirect() {
    # The releases/latest redirect needs no API token and is not rate limited,
    # unlike api.github.com which returns 403 on shared or busy egress IPs.
    curl -fsI -o /dev/null -w '%{redirect_url}' \
        "https://github.com/${REPO}/releases/latest" 2>/dev/null \
        | sed -n 's#.*/tag/\(v[0-9][0-9.]*\)$#\1#p' || true
}

latest_version_via_api() {
    curl -fsS "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
        | grep '"tag_name"' | cut -d '"' -f4 || true
}

resolve_version() {
    step "Step 4a: Version"

    if [ -n "$VERSION" ]; then
        case "$VERSION" in v*) ;; *) VERSION="v${VERSION}" ;; esac
        ok "Using the requested version: ${VERSION}"
    else
        VERSION="$(latest_version_via_redirect)"
        if [ -z "$VERSION" ]; then
            warn "Redirect detection failed; trying the GitHub API."
            VERSION="$(latest_version_via_api)"
        fi
        # An empty VERSION would build .../download//redis_exporter-.linux-...
        # and fail confusingly, so refuse rather than continue.
        if [ -z "$VERSION" ]; then
            VERSION="$FALLBACK_VERSION"
            warn "Could not detect the latest release (no network, or rate limited)."
            warn "Falling back to the pinned version ${VERSION}."
        else
            ok "Latest release: ${VERSION}"
        fi
    fi

    case "$VERSION" in
        v[0-9]*.[0-9]*) ;;
        *) die "Version '${VERSION}' does not look like a release tag." ;;
    esac
}

# ===========================================================================
# Step 4b — architecture
# ===========================================================================

detect_arch() {
    step "Step 4b: Architecture"
    case "$(uname -m)" in
        x86_64)  ARCH=amd64 ;;
        aarch64) ARCH=arm64 ;;
        armv7l)  ARCH=armv7 ;;
        armv6l)  ARCH=armv6 ;;
        i386|i686) ARCH=386 ;;
        *) die "Unsupported architecture $(uname -m). Pick a build manually." ;;
    esac
    ok "$(uname -m) -> ${ARCH}"
}

# ===========================================================================
# Step 4c — download and verify
# ===========================================================================

set_download_names() {
    # Unlike node_exporter, this project keeps the leading v INSIDE the
    # filename as well as the tag. Getting that wrong is a 404, so it lives in
    # one place.
    STEM="redis_exporter-${VERSION}.linux-${ARCH}"
    TARBALL="${STEM}.tar.gz"
    # Named per release: several installers share ${WORKDIR}, and a plain
    # sha256sums.txt would be overwritten by whichever ran last, leaving a kept
    # tarball paired with the wrong checksum file.
    SUMFILE="sha256sums-redis_exporter-${VERSION}.txt"
    BASE="https://github.com/${REPO}/releases/download/${VERSION}"
}

download_release() {
    step "Step 4c: Download redis_exporter ${VERSION} (${ARCH})"
    set_download_names

    mkdir -p "$WORKDIR"
    chmod 0755 "$WORKDIR"
    cd "$WORKDIR"

    if [ -f "$TARBALL" ]; then
        ok "Reusing the already-downloaded ${TARBALL}"
    else
        curl -fSL --retry 3 --retry-delay 2 -o "$TARBALL" "${BASE}/${TARBALL}" \
            || die "Download failed: ${BASE}/${TARBALL}"
    fi
    ls -lh "$TARBALL" | indent
}

verify_checksum() {
    if [ "$SKIP_CHECKSUM" -eq 1 ]; then
        warn "Checksum verification skipped (--skip-checksum)."
        return 0
    fi
    if ! curl -fsSL --retry 3 -o "$SUMFILE" "${BASE}/sha256sums.txt"; then
        warn "Could not fetch sha256sums.txt; proceeding unverified."
        return 0
    fi
    # --ignore-missing so the file covering every OS/arch does not fail on the
    # builds we did not download.
    sha256sum -c "$SUMFILE" --ignore-missing 2>/dev/null | grep -F "$TARBALL" | indent || true
    sha256sum -c "$SUMFILE" --ignore-missing >/dev/null 2>&1 \
        || die "CHECKSUM MISMATCH on ${TARBALL}. Do not install this file."
    ok "sha256 verified"
}

extract_release() {
    rm -rf "${WORKDIR}/${STEM}"
    # This tarball carries its own versioned directory, so no -C is needed.
    tar -xzf "$TARBALL" || die "Extraction failed."
    [ -f "${WORKDIR}/${STEM}/redis_exporter" ] || die "Expected binary not found in ${STEM}."
    ls "${WORKDIR}/${STEM}" | indent
}

# ===========================================================================
# Step 4d — install the binary
# ===========================================================================

install_binary() {
    step "Step 4d: Install the binary"

    # A running binary cannot be overwritten in place.
    if systemctl is-active --quiet redis_exporter 2>/dev/null; then
        systemctl stop redis_exporter
        ok "Stopped the running service for the upgrade."
    fi

    install -o "$EXP_USER" -g "$EXP_USER" -m 0755 \
        "${WORKDIR}/${STEM}/redis_exporter" "$BIN_PATH" \
        || die "Could not install to ${BIN_PATH}."
    ls -l "$BIN_PATH" | indent
    # This binary prints its banner to stderr, in logfmt, not to stdout.
    "$BIN_PATH" --version 2>&1 | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1 \
        | sed 's/^/    version /' || true
    ok "Installed"
}

# ===========================================================================
# Step 5 — environment file
# ===========================================================================

write_env_file() {
    step "Step 5: Environment file"

    # The password goes in the environment, never in ExecStart: anything on the
    # command line is world-readable through ps and /proc for the process
    # lifetime. systemd reads EnvironmentFile as root before dropping to the
    # service user, so 0600 root:root is both sufficient and correct.
    # Parentheses, not braces: a brace group runs in the current shell and the
    # umask would leak into every later file this script writes.
    (
        umask 077
        {
            printf '# Managed by install_redis_exporter.sh\n'
            printf 'REDIS_ADDR=redis://%s:%s\n' "$REDIS_HOST" "$REDIS_PORT"
            [ -n "$REDIS_PASSWORD" ] && printf 'REDIS_PASSWORD=%s\n' "$REDIS_PASSWORD"
            exit 0
        } > "$ENVFILE"
    )
    chmod 0600 "$ENVFILE"
    chown root:root "$ENVFILE"
    ls -l "$ENVFILE" | indent
    # Show the keys without their values.
    redact_password < "$ENVFILE" | indent
    ok "Wrote ${ENVFILE}"
}

# ===========================================================================
# Step 7 — systemd unit
# ===========================================================================

build_exec_flags() {
    # ONE ExecStart line: a blank line from an empty conditional flag would end
    # a backslash continuation and turn later flags into unknown directives.
    # Note there is deliberately NO --redis.addr or --redis.password here; both
    # come from the EnvironmentFile so they never reach argv.
    printf '%s' "--web.listen-address=0.0.0.0:${LISTEN_PORT}"
}

write_systemd_unit() {
    step "Step 7: Systemd unit"

    cat > "$UNIT" <<EOF
[Unit]
Description=Redis Prometheus Exporter
Documentation=https://github.com/${REPO}
After=network-online.target ${REDIS_UNIT}.service
Wants=network-online.target

[Service]
Type=simple
User=${EXP_USER}
Group=${EXP_USER}
Restart=always
RestartSec=5
EnvironmentFile=${ENVFILE}
ExecStart=${BIN_PATH} $(build_exec_flags)

NoNewPrivileges=true
ProtectHome=yes
ProtectSystem=strict
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
EOF

    chmod 0644 "$UNIT"
    grep '^ExecStart=' "$UNIT" | indent
    ok "Wrote ${UNIT}"
}

# ===========================================================================
# Step 8 — enable and start
# ===========================================================================

start_service() {
    step "Step 8: Enable and start"
    systemctl daemon-reload
    systemctl enable redis_exporter >/dev/null 2>&1 || warn "Could not enable at boot."
    systemctl restart redis_exporter \
        || die "Failed to start. Check: journalctl -u redis_exporter -n 50"
    sleep 2
}

# ===========================================================================
# Step 9 — verify the service
# ===========================================================================

verify_service() {
    step "Step 9: Verify the service"

    E_ACTIVE="$(systemctl is-active redis_exporter 2>/dev/null || true)"
    E_ENABLED="$(systemctl is-enabled redis_exporter 2>/dev/null || true)"
    printf '    is-active  : %s\n    is-enabled : %s\n' "$E_ACTIVE" "$E_ENABLED"
    [ "$E_ACTIVE" = "active" ] \
        || die "redis_exporter is not active. Check: journalctl -u redis_exporter -n 50"
    ok "Service active"

    local holder
    holder="$(port_holder "$LISTEN_PORT")"
    [ -n "$holder" ] || die "Nothing is listening on ${LISTEN_PORT}."
    printf '%s\n' "$holder" | trim_wide | indent
    ok "Listening on ${LISTEN_PORT}"
}

# ===========================================================================
# Step 10 — verify metrics
# ===========================================================================

verify_metrics() {
    step "Step 10: Verify metrics"

    command -v curl >/dev/null 2>&1 || { warn "curl not available; skipping."; return 0; }
    local metrics count
    metrics="$(scrape_metrics)"
    count="$(printf '%s' "$metrics" | grep -c '^redis_' || true)"
    [ "${count:-0}" -gt 0 ] \
        && ok "${count} redis_* series exposed" \
        || die "Could not scrape localhost:${LISTEN_PORT}/metrics."

    REDIS_UP="$(printf '%s' "$metrics" | awk '/^redis_up / {print $2; exit}' || true)"
    printf '    redis_up %s\n' "${REDIS_UP:-<absent>}"
    case "$REDIS_UP" in
        1) ok "redis_up = 1 — the exporter is talking to Redis." ;;
        0) warn "redis_up = 0 — the exporter is running but cannot reach Redis."
           warn "Check REDIS_ADDR in ${ENVFILE} and: journalctl -u redis_exporter -n 30" ;;
        *) warn "redis_up not found in the output." ;;
    esac
}

# ===========================================================================
# Step 11 — confirm no password leak
# ===========================================================================

check_no_password_leak() {
    step "Step 11: Confirm no password on the command line"

    local pid cmdline leak=0
    pid="$(service_main_pid)"
    if [ -z "$pid" ] || [ ! -r "/proc/${pid}/cmdline" ]; then
        warn "Could not read the process command line to check for a leak."
        return 0
    fi

    cmdline="$(tr '\0' ' ' < "/proc/${pid}/cmdline")"
    printf '    %s\n' "$cmdline"
    printf '%s' "$cmdline" | grep -qiE -- '--redis.password|--redis.addr' && leak=1
    if [ -n "$REDIS_PASSWORD" ] && printf '%s' "$cmdline" | grep -qF -- "$REDIS_PASSWORD"; then
        leak=1
    fi
    [ "$leak" -eq 0 ] \
        && ok "Only --web.listen-address is on the command line." \
        || die "Credentials are visible in the process command line. Move them into ${ENVFILE}."
}

# ===========================================================================
# Step 12 — firewall
# ===========================================================================

warn_if_blanket_rule() {
    # A blanket "ALLOW Anywhere" rule on the same port makes the targeted rule
    # decorative, so say so rather than implying the port is restricted.
    ufw status 2>/dev/null | grep -E "^${LISTEN_PORT}/tcp" | grep -q 'Anywhere' || return 0
    warn "An existing rule already allows ${LISTEN_PORT}/tcp from Anywhere."
    warn "The targeted rule adds nothing until you remove that one:"
    warn "  ufw status numbered   then   ufw delete <number>"
}

warn_if_unrestricted() {
    # The exporter binds 0.0.0.0, so the firewall is the only thing limiting
    # who can read your Redis internals: keyspace sizes, client counts, config.
    [ "$SKIP_FIREWALL" -eq 1 ] || [ -z "$MONITOR_IP" ] || return 0
    warn "The exporter listens on 0.0.0.0:${LISTEN_PORT} with no rule restricting it."
}

configure_firewall() {
    step "Step 12: Firewall"

    if [ "$SKIP_FIREWALL" -eq 1 ]; then
        ok "Skipped (--no-firewall)."
    elif [ -z "$MONITOR_IP" ]; then
        warn "No monitoring server IP was given. Open ${LISTEN_PORT}/tcp manually."
    elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi '^Status: active'; then
        ufw allow from "$MONITOR_IP" to any port "$LISTEN_PORT" proto tcp >/dev/null
        ufw reload >/dev/null
        ok "ufw: ${MONITOR_IP} -> ${LISTEN_PORT}/tcp"
        warn_if_blanket_rule
        ufw status numbered 2>/dev/null | grep "$LISTEN_PORT" | indent || true
    elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=${MONITOR_IP} port port=${LISTEN_PORT} protocol=tcp accept" >/dev/null
        firewall-cmd --reload >/dev/null
        ok "firewalld: ${MONITOR_IP} -> ${LISTEN_PORT}/tcp"
    else
        warn "No active ufw/firewalld. Open ${LISTEN_PORT}/tcp for ${MONITOR_IP} manually."
    fi

    warn_if_unrestricted
}

# ===========================================================================
# Step 13 — downloads
# ===========================================================================

report_downloads() {
    step "Step 13: Downloaded files"
    if [ "$KEEP_DOWNLOAD" -eq 1 ]; then
        # Kept on purpose: re-installing or rolling back needs no second
        # download, and the checksum file beside it records what was verified.
        ls -lh "${WORKDIR}/${TARBALL}" 2>/dev/null | indent || true
        [ -n "${SUMFILE:-}" ] && [ -f "${WORKDIR}/${SUMFILE}" ] \
            && ls -lh "${WORKDIR}/${SUMFILE}" | indent
        ok "Kept in ${WORKDIR} (pass --clean-download to remove)."
    else
        rm -rf "${WORKDIR}/${STEM}" "${WORKDIR}/${TARBALL}"
        ok "Removed the download and extracted directory."
    fi
}

# ===========================================================================
# Summary
# ===========================================================================

print_summary() {
    step "Done"
    cat <<EOF
  version          : ${VERSION} (${ARCH})${EXISTING:+   upgraded from ${EXISTING}}
  binary           : ${BIN_PATH}
  user             : ${EXP_USER}
  status           : ${E_ACTIVE} / ${E_ENABLED}
  listen           : 0.0.0.0:${LISTEN_PORT}
  redis            : ${REDIS_HOST}:${REDIS_PORT}  (auth: $([ -n "$REDIS_PASSWORD" ] && echo yes || echo no))
  redis_up         : ${REDIS_UP:-unknown}
  env file         : ${ENVFILE} (0600 root:root)
  downloads        : ${WORKDIR}
  local address    : $(hostname -I 2>/dev/null | awk '{print $1}'):${LISTEN_PORT}
                     (behind NAT? Prometheus needs the address it can reach,
                      not this one -- verify with a curl from the monitor)

On the monitoring server:
  1. curl -s http://<this-host>:${LISTEN_PORT}/metrics | grep '^redis_up'
  2. add to /etc/prometheus/prometheus.yml:
         - job_name: "redis"
           static_configs:
             - targets: ["<this-host>:${LISTEN_PORT}"]
  3. promtool check config /etc/prometheus/prometheus.yml
  4. systemctl reload prometheus     # reload, not restart
  5. Grafana dashboard ID 763

  Note: dashboard 763 and most upstream examples assume port 9121. This install
  uses ${LISTEN_PORT}, so adjust any instance filter accordingly.
EOF
}

# ===========================================================================
# Orchestration
# ===========================================================================

phase_prepare() {
    check_existing_install
    verify_redis_running
    read_redis_config
    probe_redis_auth
    ask_monitor_ip
    ask_redis_password
}

phase_install() {
    ensure_tools
    create_service_user
    resolve_version
    detect_arch
    download_release
    verify_checksum
    extract_release
    install_binary
    write_env_file
    write_systemd_unit
    start_service
    verify_service
    verify_metrics
    check_no_password_leak
    configure_firewall
    report_downloads
}

main() {
    init_colors
    parse_args "$@"
    require_root

    if [ "$UNINSTALL" -eq 1 ]; then
        do_uninstall
        exit 0
    fi

    phase_prepare
    phase_install
    print_summary
}

# Allow `source ./install_redis_exporter.sh --source-only` to load the
# functions without running anything, for step-by-step debugging.
case "${1:-}" in
    --source-only) init_colors; SOURCE_ONLY=1 ;;
    *) main "$@" ;;
esac
