#!/usr/bin/env bash
#
# install_freeswitch_exporter.sh — the whole FreeSWITCH exporter runbook.
#
# Structured as one function per step, orchestrated by main() at the bottom.
# Every function is independently callable, so you can source this file and run
# a single step while debugging:
#
#   source ./install_freeswitch_exporter.sh --source-only
#   verify_esl_password
#   verify_metrics
#
# Asks for everything it needs up front (ESL password, monitoring server IP),
# then installs unattended.
#
#   Step 1   confirm FreeSWITCH is running
#   Step 2   note whether the Event Socket is loopback-only or network-wide
#   Step 3   read the ESL password from event_socket.conf.xml (and vars.xml)
#   Step 4   VERIFY the password with fs_cli before installing anything
#   Step 5   create the service user
#   Step 6   download to /usr/src/monitoring, verify, extract, prove it runs
#   Step 7   install the binary to /opt/freeswitch_exporter
#   Step 8   write the systemd unit (mode 0600 -- it holds the password)
#   Step 9   daemon-reload, enable, start
#   Step 10  confirm the real command line from /proc
#   Step 11  check the journal for auth errors
#   Step 12  verify freeswitch_up is 1, not merely that HTTP answered
#   Step 13  firewall: open 9282 to the monitor, deny 8021 externally
#   Step 14  report the kept download (nothing is deleted)
#
# VERSION: defaults to 1.0.6. Upstream's 1.0.7 amd64 tarball is CORRUPT --
# it decompresses to a truncated 491 KB binary that segfaults immediately,
# even though its sha256 matches what GitHub publishes. 1.0.6 is intact.
# Override with --version; the script proves the binary runs either way.
#
# Downloads are KEPT in /usr/src/monitoring so a reinstall needs no re-download.
# Safe to re-run; doubles as an upgrade path.
#
# Usage:
#   sudo ./install_freeswitch_exporter.sh
#   sudo ./install_freeswitch_exporter.sh --port 9282 --esl-port 8021
#   sudo ./install_freeswitch_exporter.sh --version 1.0.6
#   sudo ./install_freeswitch_exporter.sh --no-firewall --clean-download
#   sudo ./install_freeswitch_exporter.sh --uninstall
#
set -euo pipefail

# ===========================================================================
# Configuration
# ===========================================================================
VERSION="1.0.6"
EXP_USER="freeswitch_exporter"
LISTEN_PORT="9282"
ESL_HOST="127.0.0.1"
ESL_PORT="8021"
ESL_TIMEOUT="5s"
ESL_PASSWORD=""
INSTALL_DIR="/opt/freeswitch_exporter"
BIN_PATH="${INSTALL_DIR}/freeswitch_exporter"
UNIT="/etc/systemd/system/freeswitch-exporter.service"
WORKDIR="/usr/src/monitoring"
ES_CONF="/etc/freeswitch/autoload_configs/event_socket.conf.xml"
VARS_XML="/etc/freeswitch/vars.xml"
REPO="mroject/freeswitch_exporter"

MONITOR_IP=""
SKIP_FIREWALL=0
SKIP_CHECKSUM=0
KEEP_DOWNLOAD=1
DENY_ESL=1
UNINSTALL=0
PURGE_USER=0
SOURCE_ONLY=0

# Runtime state shared between steps.
ARCH=""; TARBALL=""; STEM=""; SRC_BIN=""
EXISTING=""; ESL_WIDE=0; CONF_PASS=""
FS_UP=""; FS_COUNT=0
E_ACTIVE=""; E_ENABLED=""

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

usage() { sed -n '3,44p' "$0" | sed 's/^# \{0,1\}//'; }

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

mask_password() {
    # Never let the ESL password reach the terminal or a log.
    sed -E 's/(--freeswitch\.password=)[^ ]*/\1<redacted>/'
}

strip_xml_comments() {
    # XML comments must go before grepping for a value: a plain grep happily
    # returns a commented-out password, and a disabled old value often sits
    # right above the live one. State machine so multi-line blocks work too.
    awk '
    { line = $0
      while (1) {
        if (incomment) {
            p = index(line, "-->")
            if (p == 0) { line = ""; break }
            incomment = 0; line = substr(line, p + 3); continue
        }
        p = index(line, "<!--")
        if (p == 0) { out = out line "\n"; break }
        out = out substr(line, 1, p - 1); incomment = 1; line = substr(line, p + 4)
      }
    }
    END { printf "%s", out }' "$1"
}

password_is_awkward() {
    # systemd expands %, splits on unquoted whitespace, and treats # as a
    # comment start. This exporter takes the password only as a CLI flag, so
    # these characters cause failures that read as auth errors.
    case "$1" in
        *%*|*'#'*|*' '*|*"'"*|*'"'*|*'\'*|*'$'*|*';'*) return 0 ;;
    esac
    return 1
}

service_main_pid() {
    # Ask systemd rather than pgrep: pgrep -f also matches this installer when
    # it is saved under a matching filename, and after a restart the script has
    # the lower PID.
    local pid
    pid="$(systemctl show freeswitch-exporter -p MainPID --value 2>/dev/null || true)"
    case "$pid" in ''|0) pid="$(pgrep -x freeswitch_exporter | head -1 || true)" ;; esac
    printf '%s' "$pid"
}

detect_arch() {
    case "$(uname -m)" in
        x86_64)  ARCH=amd64 ;;
        aarch64) ARCH=arm64 ;;
        *) die "Unsupported architecture $(uname -m); this project ships amd64 and arm64 only." ;;
    esac
}

prompt_ip() {
    # Echoes a validated IP on stdout, or nothing if the user chose to skip.
    # Everything else must go to stderr: warn() writes to stdout, so an
    # un-redirected retry message would end up inside the captured value.
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
            --version)        VERSION="${2:?}"; shift 2 ;;
            --user)           EXP_USER="${2:?}"; shift 2 ;;
            --port)           LISTEN_PORT="${2:?}"; shift 2 ;;
            --esl-host)       ESL_HOST="${2:?}"; shift 2 ;;
            --esl-port)       ESL_PORT="${2:?}"; shift 2 ;;
            --esl-conf)       ES_CONF="${2:?}"; shift 2 ;;
            --install-dir)    INSTALL_DIR="${2:?}"
                              BIN_PATH="${INSTALL_DIR}/freeswitch_exporter"; shift 2 ;;
            --workdir)        WORKDIR="${2:?}"; shift 2 ;;
            --skip-checksum)  SKIP_CHECKSUM=1; shift ;;
            --clean-download) KEEP_DOWNLOAD=0; shift ;;
            --no-firewall)    SKIP_FIREWALL=1; shift ;;
            --no-deny-esl)    DENY_ESL=0; shift ;;
            --purge-user)     PURGE_USER=1; shift ;;
            --uninstall)      UNINSTALL=1; shift ;;
            --source-only)    SOURCE_ONLY=1; shift ;;
            -h|--help)        usage; exit 0 ;;
            *) die "Unknown option: $1 (try --help)" ;;
        esac
    done

    is_number "$LISTEN_PORT" || die "--port must be numeric (got '$LISTEN_PORT')."
    is_number "$ESL_PORT"    || die "--esl-port must be numeric (got '$ESL_PORT')."
    VERSION="${VERSION#v}"   # this project tags without a leading v
}

require_root() {
    [ "$(id -u)" -eq 0 ] || die "Must run as root (use sudo)."
    command -v systemctl >/dev/null 2>&1 || die "systemd required; systemctl not found."
}

ensure_tools() {
    step "Required tools"
    local missing="" c
    for c in curl tar sha256sum gzip awk; do
        command -v "$c" >/dev/null 2>&1 || missing="${missing} $c"
    done
    if [ -n "$missing" ]; then
        warn "Installing:${missing}"
        if command -v apt-get >/dev/null 2>&1; then
            DEBIAN_FRONTEND=noninteractive apt-get update -qq
            DEBIAN_FRONTEND=noninteractive apt-get install -y curl tar gzip coreutils gawk
        elif command -v dnf >/dev/null 2>&1; then dnf install -y curl tar gzip coreutils gawk
        elif command -v yum >/dev/null 2>&1; then yum install -y curl tar gzip coreutils gawk
        else die "Install these manually:${missing}"
        fi
    fi
    ok "curl, tar, gzip, awk and sha256sum available"
}

# ===========================================================================
# Uninstall
# ===========================================================================

do_uninstall() {
    step "Removing freeswitch-exporter"
    systemctl disable --now freeswitch-exporter >/dev/null 2>&1 || true
    rm -f "$UNIT"
    rm -rf /etc/systemd/system/freeswitch-exporter.service.d
    rm -f "$BIN_PATH"
    rmdir "$INSTALL_DIR" 2>/dev/null || true
    systemctl daemon-reload
    ok "Removed unit and binary."
    if [ "$PURGE_USER" -eq 1 ]; then
        userdel "$EXP_USER" >/dev/null 2>&1 || true
        groupdel "$EXP_USER" >/dev/null 2>&1 || true
        ok "Removed the ${EXP_USER} user and group."
    else
        warn "Kept the ${EXP_USER} user (pass --purge-user to remove it)."
    fi
    warn "Kept firewall rules and the FreeSWITCH config untouched."
}

# ===========================================================================
# Preflight
# ===========================================================================

check_existing_install() {
    step "Checking for an existing install"

    if [ -x "$BIN_PATH" ]; then
        EXISTING="$("$BIN_PATH" --version 2>&1 \
            | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
        ok "Found ${BIN_PATH} ${EXISTING:-(version unknown)}"
    else
        ok "No existing binary at ${BIN_PATH}."
    fi

    command -v ss >/dev/null 2>&1 || return 0
    local holder
    holder="$(ss -lntp 2>/dev/null | grep ":${LISTEN_PORT} " | head -1 || true)"
    if [ -n "$holder" ]; then
        printf '    port %s currently held by:\n' "$LISTEN_PORT"
        printf '%s\n' "$holder" | tr -s ' ' | cut -c1-120 | sed 's/^/      /'
        printf '%s' "$holder" | grep -q 'freeswitch_exp' \
            || die "Port ${LISTEN_PORT} is held by something else. Pick another with --port."
    else
        ok "Port ${LISTEN_PORT} is free."
    fi
}

# ===========================================================================
# Step 1 — FreeSWITCH running
# ===========================================================================

check_freeswitch_running() {
    step "Step 1: Confirm FreeSWITCH is running"
    local active
    active="$(systemctl is-active freeswitch 2>/dev/null || true)"
    printf '    freeswitch is-active : %s\n' "${active:-unknown}"
    [ "$active" = "active" ] \
        || die "FreeSWITCH is not active. Start it before installing the exporter."
    ok "Running"
}

# ===========================================================================
# Step 2 — Event Socket exposure
# ===========================================================================

check_event_socket() {
    step "Step 2: Event Socket on ${ESL_PORT}"

    local line=""
    command -v ss >/dev/null 2>&1 && \
        line="$(ss -lntp 2>/dev/null | grep ":${ESL_PORT} " | head -1 || true)"

    [ -n "$line" ] \
        || die "Nothing is listening on ${ESL_PORT}. mod_event_socket is not loaded — check modules.conf.xml."
    printf '%s\n' "$line" | tr -s ' ' | cut -c1-110 | indent

    # A bind on * or :: means any host that guesses the password gets full API
    # access, including originating calls.
    if printf '%s' "$line" | grep -qE '(\*|\[?::\]?|0\.0\.0\.0):'"${ESL_PORT}"; then
        ESL_WIDE=1
        warn "The Event Socket is bound to ALL interfaces, not just loopback."
        warn "Anyone who guesses the password gets full FreeSWITCH API access."
        warn "Set listen-ip to 127.0.0.1 and uncomment apply-inbound-acl in:"
        warn "  ${ES_CONF}"
        warn "That needs a FreeSWITCH restart, so batch it with a maintenance window."
    else
        ESL_WIDE=0
        ok "Loopback-only, as it should be."
    fi
}

# ===========================================================================
# Step 3 — read the password from the config
# ===========================================================================

warn_if_config_newer_than_process() {
    # If the file was edited after FreeSWITCH started, the live process still
    # holds the OLD password and no reload can change that.
    local conf_mtime fs_pid fs_start
    conf_mtime="$(stat -c '%Y' "$ES_CONF" 2>/dev/null || echo 0)"
    fs_pid="$(pgrep -x freeswitch | head -1 || true)"
    [ -n "$fs_pid" ] || return 0
    fs_start="$(date -d "$(ps -o lstart= -p "$fs_pid")" +%s 2>/dev/null || echo 0)"
    if [ "$conf_mtime" -gt "$fs_start" ] && [ "$fs_start" -gt 0 ]; then
        warn "${ES_CONF} was modified AFTER FreeSWITCH started."
        warn "The running process still uses the password it loaded at startup."
        warn "Only a FreeSWITCH restart picks up the change — and that drops calls."
    fi
}

# Where a second copy of the config realistically lives. Searching / instead
# is both slow on a large host and unreliable: find exits non-zero the moment
# it meets one unreadable directory, and 2>/dev/null hides the message but not
# the status -- with pipefail and set -e that killed the whole script here.
CONFIG_SEARCH_PATHS="/etc /usr/local/etc /opt /usr/share/freeswitch"

find_config_copies() {
    local d
    for d in $CONFIG_SEARCH_PATHS; do
        [ -d "$d" ] || continue
        find "$d" -name 'event_socket.conf.xml' -not -path '*/.*' 2>/dev/null || true
    done
}

warn_if_duplicate_configs() {
    # Multiple copies on disk is a classic source of "the edit did nothing".
    local found copies
    found="$(find_config_copies || true)"
    copies="$(printf '%s' "$found" | grep -c . || true)"
    [ "${copies:-0}" -gt 1 ] || return 0
    warn "${copies} copies of event_socket.conf.xml exist on this host:"
    printf '%s\n' "$found" | sed 's/^/      /'
    warn "FreeSWITCH may not be reading the one you think."
    return 0
}

resolve_variable_password() {
    # $${default_password} indirection lives in vars.xml.
    local resolved
    resolved="$(grep -oE '<X-PRE-PROCESS[^>]*default_password=[^">]*"' "$VARS_XML" 2>/dev/null \
        | head -1 | sed -E 's/.*default_password=([^"]*)".*/\1/' || true)"
    printf '%s' "$resolved"
}

read_config_password() {
    step "Step 3: ESL password from the config"

    if [ ! -r "$ES_CONF" ]; then
        warn "${ES_CONF} not readable (see --esl-conf)."
        return 0
    fi

    CONF_PASS="$(strip_xml_comments "$ES_CONF" \
        | grep -oE '<param[[:space:]]+name="password"[[:space:]]+value="[^"]*"' \
        | head -1 | sed -E 's/.*value="([^"]*)".*/\1/' || true)"

    printf '    config : %s\n' "$ES_CONF"
    if [ -n "$CONF_PASS" ]; then
        # Never print the value itself.
        printf '    password entry found (%s characters)\n' "${#CONF_PASS}"
    else
        warn "No uncommented password param found."
    fi

    case "$CONF_PASS" in
        *'${'*)
            warn "The password is a variable reference; resolving from ${VARS_XML}."
            local resolved
            resolved="$(resolve_variable_password)"
            if [ -n "$resolved" ]; then
                CONF_PASS="$resolved"
                ok "Resolved from vars.xml (${#CONF_PASS} characters)."
            else
                CONF_PASS=""
                warn "Could not resolve it; you will be asked to type the password."
            fi
            ;;
    esac

    warn_if_duplicate_configs
    warn_if_config_newer_than_process
}

# ===========================================================================
# Step 4 — verify the password (the highest-value gate)
# ===========================================================================

esl_auth_works() {
    # fs_cli authenticates over the same socket, so a successful status call
    # proves the credential the LIVE process is using.
    fs_cli -p "$1" -x "status" 2>&1 \
        | grep -qiE 'UP .*(years|days|hours|minutes)|FreeSWITCH \(Version'
}

verify_esl_password() {
    step "Step 4: Verify the password with fs_cli"

    command -v fs_cli >/dev/null 2>&1 \
        || die "fs_cli not found. It is the only way to prove the credential before installing."

    local verified=0
    if [ -n "$CONF_PASS" ]; then
        printf '    trying the password from the config...\n'
        if esl_auth_works "$CONF_PASS"; then
            ESL_PASSWORD="$CONF_PASS"; verified=1
            ok "The config password authenticates."
        else
            warn "The config password does NOT authenticate."
            warn "The live FreeSWITCH is using something else — see the mtime note above."
        fi
    fi

    if [ "$verified" -eq 0 ]; then
        [ -t 0 ] || die "Could not verify a password and there is no terminal to ask on."
        cat <<'EOF'
    Enter the ESL password the RUNNING FreeSWITCH is using. It is not echoed.
    If you do not know it, stop here: editing the config and reloading will not
    help, because fs_cli authenticates over the same socket. Only a restart
    loads a new password, and that drops active calls.
EOF
        local attempt=0
        while [ "$attempt" -lt 3 ]; do
            attempt=$((attempt + 1))
            printf '    ESL password (hidden): '
            read -rs ESL_PASSWORD; printf '\n'
            [ -n "$ESL_PASSWORD" ] || { warn "Empty; try again."; continue; }
            if esl_auth_works "$ESL_PASSWORD"; then
                verified=1; ok "Authenticated."; break
            fi
            warn "Authentication failed (attempt ${attempt} of 3)."
        done
    fi

    [ "$verified" -eq 1 ] \
        || die "Never authenticated. Do not proceed — the exporter would report freeswitch_up 0 forever."

    if password_is_awkward "$ESL_PASSWORD"; then
        warn "This password contains characters systemd or the shell may mangle"
        warn "(% # whitespace quotes backslash \$ ;). The exporter accepts it only"
        warn "as a command-line flag, so this can surface as a bogus auth error."
        warn "Consider rotating to 24 alphanumeric characters:"
        warn "  tr -dc 'A-Za-z0-9' </dev/urandom | head -c 24; echo"
        warn "Change BOTH ${ES_CONF} and the unit file in the same window."
    fi
}

# ===========================================================================
# Monitoring server address
# ===========================================================================

ask_monitor_ip() {
    [ "$SKIP_FIREWALL" -eq 1 ] && return 0
    [ -t 0 ] || die "No terminal to ask for the monitoring server IP on. Run interactively, or pass --no-firewall."

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
        warn "Skipping the firewall rule. Open ${LISTEN_PORT}/tcp for the monitor yourself."
    else
        ok "Will allow ${MONITOR_IP} to reach port ${LISTEN_PORT}/tcp"
    fi
}

# ===========================================================================
# Step 5 — service user
# ===========================================================================

create_service_user() {
    step "Step 5: Service user"

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
# Step 6 — download, verify, extract, prove it runs
# ===========================================================================

download_release() {
    detect_arch
    step "Step 6: Download freeswitch_exporter ${VERSION} (${ARCH})"

    # The published asset name carries no version, so downloads for different
    # releases would overwrite each other. Store under a versioned name.
    local asset="freeswitch_exporter-linux-${ARCH}.tar.gz"
    TARBALL="freeswitch_exporter-${VERSION}-linux-${ARCH}.tar.gz"
    STEM="freeswitch_exporter-${VERSION}-linux-${ARCH}"
    local base="https://github.com/${REPO}/releases/download/${VERSION}"

    mkdir -p "$WORKDIR"
    chmod 0755 "$WORKDIR"
    cd "$WORKDIR"

    if [ -f "$TARBALL" ]; then
        ok "Reusing the already-downloaded ${TARBALL}"
    else
        curl -fSL --retry 3 --retry-delay 2 -o "$TARBALL" "${base}/${asset}" \
            || die "Download failed: ${base}/${asset}"
    fi
    ls -lh "$TARBALL" | indent
    printf '    sha256 %s\n' "$(sha256sum "$TARBALL" 2>/dev/null | cut -d' ' -f1 || true)"
}

verify_archive() {
    # This project publishes no checksum file, so integrity is checked
    # structurally. gzip -t catches exactly the corruption in the 1.0.7 asset,
    # whose sha256 matches upstream yet decompresses to a truncated binary.
    if [ "$SKIP_CHECKSUM" -eq 1 ]; then
        warn "Integrity check skipped (--skip-checksum)."
        return 0
    fi
    gzip -t "$TARBALL" 2>/dev/null \
        || die "The archive is CORRUPT (gzip integrity failed). Upstream's 1.0.7 amd64 asset has this exact defect — try --version 1.0.6."
    ok "gzip integrity OK"
}

extract_release() {
    rm -rf "${WORKDIR}/${STEM}"
    mkdir -p "${WORKDIR}/${STEM}"
    # The tarball holds a bare binary with no directory, so extract into one.
    tar -xzf "$TARBALL" -C "${WORKDIR}/${STEM}" \
        || die "Extraction failed — the archive is truncated. Try --version 1.0.6."

    # head -1 exits early and SIGPIPEs find; pipefail would report the whole
    # pipeline as failed. Capture first, then take the first line.
    SRC_BIN="$(find "${WORKDIR}/${STEM}" -name freeswitch_exporter -type f 2>/dev/null || true)"
    SRC_BIN="$(printf '%s' "$SRC_BIN" | head -1)"
    [ -n "$SRC_BIN" ] || die "No freeswitch_exporter binary inside the archive."
    chmod 0755 "$SRC_BIN"
    ls -l "$SRC_BIN" | indent
}

verify_binary_runs() {
    # Run it before installing. A truncated ELF passes every file-level check
    # and then segfaults on service start, which reads as a config problem.
    local out
    if out="$("$SRC_BIN" --version 2>&1)"; then
        printf '%s\n' "$out" | head -2 | indent
        ok "The binary executes"
    else
        printf '%s\n' "${out:-<no output>}" | head -3 | indent
        die "The extracted binary does not run (truncated or wrong arch). Try --version 1.0.6."
    fi
}

# ===========================================================================
# Step 7 — install the binary
# ===========================================================================

install_binary() {
    step "Step 7: Install the binary"

    # A running binary cannot be overwritten in place.
    if systemctl is-active --quiet freeswitch-exporter 2>/dev/null; then
        systemctl stop freeswitch-exporter
        ok "Stopped the running service for the upgrade."
    fi

    mkdir -p "$INSTALL_DIR"
    chmod 0755 "$INSTALL_DIR"
    # Left root-owned deliberately: the service only needs to execute the
    # binary and open a socket, not own its own code.
    install -o root -g root -m 0755 "$SRC_BIN" "$BIN_PATH" \
        || die "Could not install to ${BIN_PATH}."
    ls -l "$BIN_PATH" | indent
    ok "Installed"
}

# ===========================================================================
# Step 8 — systemd unit
# ===========================================================================

build_exec_flags() {
    # One ExecStart line: a blank line from an empty conditional flag would end
    # a backslash continuation and turn later flags into unknown directives.
    printf '%s' "--web.listen-address=0.0.0.0:${LISTEN_PORT}"
    printf '%s' " --web.telemetry-path=/metrics"
    printf '%s' " --freeswitch.scrape-uri=tcp://${ESL_HOST}:${ESL_PORT}"
    printf '%s' " --freeswitch.password=${ESL_PASSWORD}"
    printf '%s' " --freeswitch.timeout=${ESL_TIMEOUT}"
}

write_systemd_unit() {
    step "Step 8: Systemd unit"

    cat > "$UNIT" <<EOF
[Unit]
Description=FreeSWITCH Prometheus Exporter
Documentation=https://github.com/${REPO}
Wants=network-online.target
After=network-online.target freeswitch.service

[Service]
User=${EXP_USER}
Group=${EXP_USER}
Type=simple
ExecStart=${BIN_PATH} $(build_exec_flags)
Restart=on-failure
RestartSec=5

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
EOF

    # 0600, not the usual 0644: this file contains the ESL password in plain
    # text. systemd reads units as root, so nothing is lost by locking it down.
    chmod 0600 "$UNIT"
    chown root:root "$UNIT"
    ls -l "$UNIT" | indent
    grep '^ExecStart=' "$UNIT" | mask_password | fold -w 74 -s | indent
    ok "Wrote ${UNIT} (0600)"

    warn "The exporter takes the ESL password only as a CLI flag, so it is visible"
    warn "in ps and /proc/<pid>/cmdline to any local user. The mitigations are"
    warn "keeping the Event Socket loopback-only and limiting shell access here."
}

# ===========================================================================
# Step 9 — enable and start
# ===========================================================================

start_service() {
    step "Step 9: Enable and start"

    # Mandatory after every unit edit: without it systemd keeps the old command
    # line, which looks like a process stuck on the previous port.
    systemctl daemon-reload
    systemctl enable freeswitch-exporter >/dev/null 2>&1 || warn "Could not enable at boot."
    systemctl restart freeswitch-exporter \
        || die "Failed to start. Check: journalctl -u freeswitch-exporter -n 50"
    sleep 3

    E_ACTIVE="$(systemctl is-active freeswitch-exporter 2>/dev/null || true)"
    E_ENABLED="$(systemctl is-enabled freeswitch-exporter 2>/dev/null || true)"
    printf '    is-active  : %s\n    is-enabled : %s\n' "$E_ACTIVE" "$E_ENABLED"
    [ "$E_ACTIVE" = "active" ] \
        || die "Not active. Check: journalctl -u freeswitch-exporter -n 50"
    ok "Service active"
}

# ===========================================================================
# Step 10 — confirm the real command line
# ===========================================================================

verify_running_cmdline() {
    step "Step 10: Confirm the running command line"

    local pid running_port
    pid="$(service_main_pid)"
    if [ -n "$pid" ] && [ -r "/proc/${pid}/cmdline" ]; then
        # Shows values AFTER systemd parsing, where % and whitespace mangling
        # becomes visible.
        tr '\0' '\n' < "/proc/${pid}/cmdline" \
            | sed -E 's/(--freeswitch\.password=).*/\1<redacted>/' | sed 's/^/      /'
        running_port="$(tr '\0' '\n' < "/proc/${pid}/cmdline" \
            | grep -m1 'web.listen-address' | sed 's/.*://' | tr -dc '0-9' || true)"
        [ "$running_port" = "$LISTEN_PORT" ] \
            && ok "Listening port matches the unit: ${LISTEN_PORT}" \
            || die "Process is on port '${running_port}' but the unit says ${LISTEN_PORT}."
    fi

    command -v ss >/dev/null 2>&1 || return 0
    ss -lntp 2>/dev/null | grep ":${LISTEN_PORT} " | tr -s ' ' | cut -c1-120 | indent \
        || die "Nothing listening on ${LISTEN_PORT}."
}

# ===========================================================================
# Step 11 — journal
# ===========================================================================

check_journal() {
    step "Step 11: Journal check"
    local lines
    lines="$(journalctl -u freeswitch-exporter -n 30 --no-pager 2>/dev/null \
        | grep -iE 'error|auth' || true)"
    if [ -z "$lines" ]; then
        ok "No error or auth lines in the last 30 entries."
    else
        printf '%s\n' "$lines" | tail -8 | indent
        warn "Errors present — see the freeswitch_up check below."
    fi
}

# ===========================================================================
# Step 12 — metrics
# ===========================================================================

verify_metrics() {
    step "Step 12: Verify metrics"

    command -v curl >/dev/null 2>&1 || die "curl is required for verification."
    local metrics total failed
    metrics="$(curl -sf --max-time 10 "http://127.0.0.1:${LISTEN_PORT}/metrics" 2>/dev/null || true)"
    [ -n "$metrics" ] || die "No response from http://127.0.0.1:${LISTEN_PORT}/metrics"

    FS_COUNT="$(printf '%s' "$metrics" | grep -c '^freeswitch_' || true)"
    FS_UP="$(printf '%s' "$metrics" | awk '/^freeswitch_up / {print $2; exit}' || true)"
    total="$(printf '%s' "$metrics" | awk '/^freeswitch_exporter_total_scrapes/ {print $2; exit}' || true)"
    failed="$(printf '%s' "$metrics" | awk '/^freeswitch_exporter_failed_scrapes/ {print $2; exit}' || true)"

    printf '    freeswitch_* series : %s\n' "$FS_COUNT"
    printf '    freeswitch_up       : %s\n' "${FS_UP:-<absent>}"
    [ -n "$total" ] && printf '    total / failed      : %s / %s\n' "$total" "${failed:-0}"

    # HTTP 200 proves nothing: the exporter serves metrics happily while unable
    # to reach FreeSWITCH, emitting only up/total_scrapes/failed_scrapes.
    case "$FS_UP" in
        1) ok "freeswitch_up = 1 — the Event Socket connection works." ;;
        0) printf '%s\n' "$metrics" | grep '^freeswitch_' | head -5 | sed 's/^/      /'
           die "freeswitch_up = 0. The exporter serves HTTP but cannot talk to FreeSWITCH. Check: journalctl -u freeswitch-exporter -n 30" ;;
        *) die "freeswitch_up not present in the output." ;;
    esac

    [ "${FS_COUNT:-0}" -gt 20 ] \
        && ok "${FS_COUNT} series — a real scrape, not just the three failure metrics." \
        || warn "Only ${FS_COUNT} series; expected well over a hundred."

    printf '    sample gauges:\n'
    printf '%s' "$metrics" \
        | grep -E '^freeswitch_(uptime_seconds|current_calls|current_sessions|current_channels|registrations|time_synced) ' \
        | sed 's/^/      /' || true
}

# ===========================================================================
# Step 13 — firewall
# ===========================================================================

configure_firewall() {
    step "Step 13: Firewall"

    if [ "$SKIP_FIREWALL" -eq 1 ]; then
        ok "Skipped (--no-firewall)."; return 0
    fi
    if ! command -v ufw >/dev/null 2>&1; then
        warn "ufw not installed. Restrict ${LISTEN_PORT}/tcp to the monitor yourself."; return 0
    fi
    if ! ufw status 2>/dev/null | grep -qi '^Status: active'; then
        warn "ufw is inactive; no rule added. Port ${LISTEN_PORT} is open to anything routable."
        return 0
    fi

    if [ -n "$MONITOR_IP" ]; then
        ufw allow from "$MONITOR_IP" to any port "$LISTEN_PORT" proto tcp >/dev/null
        ok "ufw: ${MONITOR_IP} -> ${LISTEN_PORT}/tcp"
    fi
    if [ "$DENY_ESL" -eq 1 ]; then
        ufw deny "${ESL_PORT}/tcp" >/dev/null
        ok "ufw: deny ${ESL_PORT}/tcp (Event Socket stays off the network)"
    fi
    ufw reload >/dev/null

    # A blanket rule on the same port makes the targeted one decorative, and
    # this endpoint leaks gateway names, registration counts and call volumes.
    if ufw status 2>/dev/null | grep -E "^${LISTEN_PORT}/tcp" | grep -q 'Anywhere'; then
        warn "An existing rule allows ${LISTEN_PORT}/tcp from Anywhere."
        warn "Until you delete it, the endpoint is exposed to the internet:"
        warn "  ufw status numbered   then   ufw delete <number>"
    fi
    ufw status numbered 2>/dev/null | grep -E "${LISTEN_PORT}|${ESL_PORT}" | indent || true
}

# ===========================================================================
# Step 14 — downloads
# ===========================================================================

report_downloads() {
    step "Step 14: Downloaded files"
    if [ "$KEEP_DOWNLOAD" -eq 1 ]; then
        ls -lh "${WORKDIR}/${TARBALL}" 2>/dev/null | indent || true
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
  scrape uri       : tcp://${ESL_HOST}:${ESL_PORT}
  unit             : ${UNIT} (0600 — contains the ESL password)
  freeswitch_up    : ${FS_UP}
  series           : ${FS_COUNT}
  downloads        : ${WORKDIR}
  local address    : $(hostname -I 2>/dev/null | awk '{print $1}'):${LISTEN_PORT}
                     (behind NAT? Prometheus needs the address it can reach,
                      not this one -- verify with a curl from the monitor)

On the monitoring server:
  1. curl -s http://<this-host>:${LISTEN_PORT}/metrics | grep '^freeswitch_up'
  2. add to /etc/prometheus/prometheus.yml (real IP, never a placeholder):
         - job_name: 'freeswitch'
           scrape_interval: 15s
           static_configs:
             - targets: ['<this-host>:${LISTEN_PORT}']
  3. promtool check config /etc/prometheus/prometheus.yml
  4. systemctl reload prometheus     # reload, not restart
  5. alert on freeswitch_up == 0 as well as up == 0 — the exporter answers HTTP
     even when its FreeSWITCH connection is dead, so a green target lies.
EOF

    if [ "$ESL_WIDE" -eq 1 ]; then
        printf '\n'
        warn "Still outstanding: the Event Socket is bound to all interfaces."
        warn "Set listen-ip to 127.0.0.1 and apply-inbound-acl to loopback.auto in"
        warn "${ES_CONF}, then restart FreeSWITCH in a maintenance window."
    fi
}

# ===========================================================================
# Orchestration
# ===========================================================================

phase_interactive() {
    check_existing_install
    check_freeswitch_running
    check_event_socket
    read_config_password
    verify_esl_password
    ask_monitor_ip
    ok "No further input needed — the rest runs unattended."
}

phase_unattended() {
    ensure_tools
    create_service_user
    download_release
    verify_archive
    extract_release
    verify_binary_runs
    install_binary
    write_systemd_unit
    start_service
    verify_running_cmdline
    check_journal
    verify_metrics
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

    phase_interactive
    phase_unattended
    print_summary
}

# Allow `source ./install_freeswitch_exporter.sh --source-only` to load the
# functions without running anything, for step-by-step debugging.
case "${1:-}" in
    --source-only) init_colors; SOURCE_ONLY=1 ;;
    *) main "$@" ;;
esac
