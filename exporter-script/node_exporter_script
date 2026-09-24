#!/usr/bin/env bash
#
# install_node_exporter.sh — install node_exporter on a remote server.
#
# Structured as one function per step, orchestrated by main() at the bottom.
# Every function is independently callable, so you can source this file and run
# a single step while debugging:
#
#   source ./install_node_exporter.sh --source-only
#   resolve_version
#   verify_running_flags
#   scrape_locally
#
# Covers the remote-server half of the runbook, Steps 1-13:
#
#   Step 1   install curl / tar / sha256sum if missing
#   Step 2   create the node_exporter system user and group
#   Step 3   resolve the version to install
#   Step 4   detect the CPU architecture
#   Step 5   download the release and VERIFY its sha256
#   Step 6   extract
#   Step 7   install the binary to /usr/local/bin
#   Step 8   create the textfile directory, both levels traversable at 0755
#   Step 9   write the systemd unit with a hardened sandbox
#   Step 10  daemon-reload, enable, start
#   Step 11  verify the service is active
#   Step 12  verify the port is listening and the flags actually took
#   Step 12b scrape localhost and check node_textfile_scrape_error
#   Step 13  open the firewall for the monitoring server
#
# Downloads land in /usr/src/monitoring and are KEPT, so a reinstall or
# rollback needs no second download.
#
# The monitoring server IP is always asked for interactively -- there is no
# flag for it and no default. Pass --no-firewall to skip that step.
#
# Safe to re-run. On an existing install it stops the service, replaces the
# binary, and restarts -- so it doubles as an upgrade path.
#
# Usage:
#   sudo ./install_node_exporter.sh
#   sudo ./install_node_exporter.sh --version 1.9.1
#   sudo ./install_node_exporter.sh --port 9100 --no-systemd-collector
#   sudo ./install_node_exporter.sh --no-firewall --clean-download
#   sudo ./install_node_exporter.sh --uninstall
#
set -euo pipefail

# ===========================================================================
# Configuration
# ===========================================================================
REPO="prometheus/node_exporter"
VERSION=""                 # empty = detect the latest release
FALLBACK_VERSION="1.9.1"   # used only if detection fails and none is given
NE_USER="node_exporter"
LISTEN_PORT="9101"
TEXTFILE_DIR="/var/lib/node_exporter/textfile_collector"
BIN_PATH="/usr/local/bin/node_exporter"
UNIT="/etc/systemd/system/node_exporter.service"
WORKDIR="/usr/src/monitoring"

MONITOR_IP=""
SKIP_FIREWALL=0
SKIP_CHECKSUM=0
KEEP_DOWNLOAD=1            # keep downloads by default
WANT_SYSTEMD_COLLECTOR=1
UNINSTALL=0
PURGE_USER=0
SOURCE_ONLY=0

# Runtime state shared between steps.
EXISTING=""; ARCH=""; TARBALL=""; SUMFILE=""; SRCDIR=""; BASE=""
NE_ACTIVE=""; NE_ENABLED=""; PARENT_DIR=""

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
    # Ask systemd for the PID it actually started. pgrep -f 'node_exporter'
    # also matches this installer when it is saved as node_exporter.sh, and the
    # script has the LOWER pid after a restart, so head -1 picks the wrong one.
    # That is exactly what produced a false "flag did not take" failure once.
    local pid
    pid="$(systemctl show node_exporter -p MainPID --value 2>/dev/null || true)"
    case "$pid" in ''|0) pid="$(pgrep -x node_exporter | head -1 || true)" ;; esac
    printf '%s' "$pid"
}

port_holder() {
    command -v ss >/dev/null 2>&1 || return 0
    ss -tulnp 2>/dev/null | grep ":${1} " | head -1 || true
}

scrape_metrics() {
    curl -sf --max-time 10 "localhost:${LISTEN_PORT}/metrics" 2>/dev/null || true
}

ssh_session_port() {
    # The port THIS session arrived on, so enabling ufw cannot lock us out even
    # when sshd is not on 22.
    local p
    p="$(ss -tnp 2>/dev/null \
        | awk '/ESTAB/ && /sshd/ {split($4,a,":"); print a[length(a)]; exit}' || true)"
    is_number "$p" || p=22
    printf '%s' "$p"
}

# ===========================================================================
# Argument parsing and preflight
# ===========================================================================

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --version)              need_arg "$1" "${2:-}"; VERSION="$2"; shift 2 ;;
            --user)                 need_arg "$1" "${2:-}"; NE_USER="$2"; shift 2 ;;
            --port)                 need_arg "$1" "${2:-}"; LISTEN_PORT="$2"; shift 2 ;;
            --textfile-dir)         need_arg "$1" "${2:-}"; TEXTFILE_DIR="$2"; shift 2 ;;
            --workdir)              need_arg "$1" "${2:-}"; WORKDIR="$2"; shift 2 ;;
            --no-systemd-collector) WANT_SYSTEMD_COLLECTOR=0; shift ;;
            --skip-checksum)        SKIP_CHECKSUM=1; shift ;;
            --clean-download)       KEEP_DOWNLOAD=0; shift ;;
            --no-firewall)          SKIP_FIREWALL=1; shift ;;
            --purge-user)           PURGE_USER=1; shift ;;
            --uninstall)            UNINSTALL=1; shift ;;
            --source-only)          SOURCE_ONLY=1; shift ;;
            -h|--help)              usage; exit 0 ;;
            *) die "Unknown option: $1 (try --help)" ;;
        esac
    done

    is_number "$LISTEN_PORT" || die "--port must be a number (got '$LISTEN_PORT')."
    case "$TEXTFILE_DIR" in
        /*) ;;
        *) die "--textfile-dir must be an absolute path (got '$TEXTFILE_DIR')." ;;
    esac
    # Strip a leading v so both "1.9.1" and "v1.9.1" work; this project's
    # filenames use the bare number while the tag carries the v.
    VERSION="${VERSION#v}"
    return 0
}

require_root() {
    [ "$(id -u)" -eq 0 ] || die "Must run as root (use sudo)."
    command -v systemctl >/dev/null 2>&1 || die "systemd required; systemctl not found."
}

ensure_tools() {
    step "Step 1: Required tools"
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
    step "Removing node_exporter"
    systemctl disable --now node_exporter >/dev/null 2>&1 || true
    rm -f "$UNIT" "$BIN_PATH"
    rm -rf /etc/systemd/system/node_exporter.service.d
    systemctl daemon-reload
    ok "Removed unit, drop-ins and binary."
    if [ "$PURGE_USER" -eq 1 ]; then
        userdel "$NE_USER" >/dev/null 2>&1 || true
        groupdel "$NE_USER" >/dev/null 2>&1 || true
        ok "Removed the ${NE_USER} user and group."
    else
        warn "Kept the ${NE_USER} user (pass --purge-user to remove it)."
    fi
    warn "Kept ${TEXTFILE_DIR} — other collectors may still write .prom files there."
    warn "Kept firewall rules for port ${LISTEN_PORT}."
}

# ===========================================================================
# Preflight — existing install
# ===========================================================================

check_existing_install() {
    step "Checking for an existing install"

    if [ -x "$BIN_PATH" ]; then
        EXISTING="$("$BIN_PATH" --version 2>&1 | head -1 | awk '{print $3}' || true)"
        ok "Found ${BIN_PATH} version ${EXISTING:-unknown}"
    else
        ok "No existing binary at ${BIN_PATH}."
    fi

    # A different exporter already on the port would make the Step 12 check
    # pass for the wrong reason, so identify it now.
    local holder
    holder="$(port_holder "$LISTEN_PORT")"
    [ -n "$holder" ] || { ok "Port ${LISTEN_PORT} is free."; return 0; }
    printf '    port %s currently held by:\n' "$LISTEN_PORT"
    printf '%s\n' "$holder" | trim_wide | indent6
    printf '%s' "$holder" | grep -q 'node_exporter' \
        || warn "Something other than node_exporter holds port ${LISTEN_PORT}."
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
# Step 2 — service user
# ===========================================================================

create_service_user() {
    step "Step 2: Service user"

    if id "$NE_USER" >/dev/null 2>&1; then
        ok "User ${NE_USER} already exists: $(id "$NE_USER")"
    else
        # --system keeps the UID below the login range and marks it
        # non-interactive; a plain useradd hands out a normal login UID.
        useradd --system --no-create-home --shell /usr/sbin/nologin "$NE_USER" \
            || die "Could not create the ${NE_USER} user."
        ok "Created: $(id "$NE_USER")"
    fi

    # The unit sets Group=, so the group has to exist even where useradd did
    # not create one (USERGROUPS_ENAB no).
    getent group "$NE_USER" >/dev/null 2>&1 || {
        groupadd --system "$NE_USER"
        usermod -g "$NE_USER" "$NE_USER"
        warn "Created the missing ${NE_USER} group."
    }
    ok "Group ${NE_USER} present"
}

# ===========================================================================
# Step 3 — version
# ===========================================================================

latest_version_via_redirect() {
    # The releases/latest redirect needs no API token and is not rate limited,
    # unlike api.github.com which returns 403 on shared or busy egress IPs.
    curl -fsI -o /dev/null -w '%{redirect_url}' \
        "https://github.com/${REPO}/releases/latest" 2>/dev/null \
        | sed -n 's#.*/tag/v\([0-9][0-9.]*\)$#\1#p' || true
}

latest_version_via_api() {
    curl -fsS "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
        | grep '"tag_name"' | cut -d '"' -f4 | sed 's/^v//' || true
}

resolve_version() {
    step "Step 3: Version"

    if [ -n "$VERSION" ]; then
        ok "Using the requested version: ${VERSION}"
    else
        VERSION="$(latest_version_via_redirect)"
        if [ -z "$VERSION" ]; then
            warn "Redirect detection failed; trying the GitHub API."
            VERSION="$(latest_version_via_api)"
        fi
        # An empty VERSION would build .../download/v/node_exporter-.linux-...
        # and fail confusingly, so never continue on a silent failure.
        if [ -z "$VERSION" ]; then
            VERSION="$FALLBACK_VERSION"
            warn "Could not detect the latest release (no network, or rate limited)."
            warn "Falling back to the pinned version ${VERSION}."
        else
            ok "Latest release: ${VERSION}"
        fi
    fi

    case "$VERSION" in
        [0-9]*.[0-9]*) ;;
        *) die "Version '${VERSION}' does not look like a release number." ;;
    esac
}

# ===========================================================================
# Step 4 — architecture
# ===========================================================================

detect_arch() {
    step "Step 4: Architecture"
    case "$(uname -m)" in
        x86_64)  ARCH=amd64 ;;
        aarch64) ARCH=arm64 ;;
        armv7l)  ARCH=armv7 ;;
        armv6l)  ARCH=armv6 ;;
        i386|i686) ARCH=386 ;;
        *) die "Unsupported architecture $(uname -m). Pick a build manually from the releases page." ;;
    esac
    ok "$(uname -m) -> ${ARCH}"
}

# ===========================================================================
# Step 5 — download and verify
# ===========================================================================

set_download_names() {
    # node_exporter uses the BARE version in the filename but a v-prefixed tag
    # in the URL path. redis_exporter keeps the v in both; nginx-exporter uses
    # neither. Getting this wrong is a 404, so it lives in one place.
    TARBALL="node_exporter-${VERSION}.linux-${ARCH}.tar.gz"
    SRCDIR="${WORKDIR}/node_exporter-${VERSION}.linux-${ARCH}"
    # Named per release: several installers share ${WORKDIR}, and a plain
    # sha256sums.txt would be overwritten by whichever ran last, leaving a kept
    # tarball paired with the wrong checksum file.
    SUMFILE="sha256sums-node_exporter-${VERSION}.txt"
    BASE="https://github.com/${REPO}/releases/download/v${VERSION}"
}

download_release() {
    step "Step 5: Download node_exporter ${VERSION} (${ARCH})"
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
    # --ignore-missing so the file covering every arch does not fail on the
    # ones we did not download.
    sha256sum -c "$SUMFILE" --ignore-missing 2>/dev/null | grep -F "$TARBALL" | indent || true
    sha256sum -c "$SUMFILE" --ignore-missing >/dev/null 2>&1 \
        || die "CHECKSUM MISMATCH on ${TARBALL}. Do not install this file."
    ok "sha256 verified"
}

# ===========================================================================
# Step 6 — extract
# ===========================================================================

extract_release() {
    step "Step 6: Extract"
    rm -rf "$SRCDIR"
    # This tarball contains its own versioned directory, so no -C is needed.
    tar -xzf "$TARBALL" || die "Extraction failed."
    [ -f "${SRCDIR}/node_exporter" ] || die "Expected binary not found in ${SRCDIR}."
    ls "$SRCDIR" | indent
}

# ===========================================================================
# Step 7 — install the binary
# ===========================================================================

install_binary() {
    step "Step 7: Install the binary"

    # A running binary cannot be overwritten in place, so stop first if this is
    # an upgrade. Textfile collectors keep writing meanwhile; only scraping
    # pauses.
    if systemctl is-active --quiet node_exporter 2>/dev/null; then
        systemctl stop node_exporter
        ok "Stopped the running service for the upgrade."
    fi

    install -o "$NE_USER" -g "$NE_USER" -m 0755 "${SRCDIR}/node_exporter" "$BIN_PATH" \
        || die "Could not install to ${BIN_PATH}."
    ls -l "$BIN_PATH" | indent
    "$BIN_PATH" --version 2>&1 | head -1 | indent
    ok "Installed"
}

# ===========================================================================
# Step 8 — textfile directory
# ===========================================================================

create_textfile_dir() {
    step "Step 8: Textfile directory"

    PARENT_DIR="$(dirname "$TEXTFILE_DIR")"
    mkdir -p "$TEXTFILE_DIR"
    chown "${NE_USER}:${NE_USER}" "$PARENT_DIR" "$TEXTFILE_DIR"
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
# Step 9 — systemd unit
# ===========================================================================

build_exec_flags() {
    # ONE ExecStart line. Backslash continuations look tidier but break the
    # moment a conditional flag is empty: the blank line ends the continuation
    # and systemd reads the remaining flags as unknown directives.
    printf '%s' "--web.listen-address=:${LISTEN_PORT}"
    printf '%s' " --collector.processes"
    printf '%s' " --collector.interrupts"
    [ "$WANT_SYSTEMD_COLLECTOR" -eq 1 ] && printf '%s' " --collector.systemd"
    printf '%s' " --collector.textfile.directory=${TEXTFILE_DIR}"
    return 0
}

write_systemd_unit() {
    step "Step 9: Systemd unit"

    # ProtectSystem=strict makes the whole filesystem read-only for this unit,
    # which is what we want: node_exporter only ever reads. No ReadWritePaths
    # are needed for the textfile directory, since the .prom files are written
    # by separate root-owned timer units, not by this process.
    cat > "$UNIT" <<EOF
[Unit]
Description=Prometheus Node Exporter
Documentation=https://github.com/${REPO}
After=network-online.target
Wants=network-online.target

[Service]
User=${NE_USER}
Group=${NE_USER}
Type=simple
Restart=always
RestartSec=5
ExecStart=${BIN_PATH} $(build_exec_flags)

NoNewPrivileges=true
ProtectHome=yes
ProtectSystem=strict
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true
ReadOnlyPaths=${TEXTFILE_DIR}

[Install]
WantedBy=multi-user.target
EOF

    chmod 0644 "$UNIT"
    grep '^ExecStart=' "$UNIT" | fold -w 74 -s | indent
    if command -v systemd-analyze >/dev/null 2>&1; then
        systemd-analyze verify "$UNIT" 2>&1 | grep -v '^$' | indent || true
    fi
    ok "Wrote ${UNIT}"
}

# ===========================================================================
# Step 10 — enable and start
# ===========================================================================

start_service() {
    step "Step 10: Enable and start"
    systemctl daemon-reload
    systemctl enable node_exporter >/dev/null 2>&1 || warn "Could not enable at boot."
    systemctl restart node_exporter \
        || die "Failed to start. Check: journalctl -u node_exporter -n 50"
    sleep 2
}

# ===========================================================================
# Step 11 — verify the service
# ===========================================================================

verify_service() {
    step "Step 11: Verify the service"
    NE_ACTIVE="$(systemctl is-active node_exporter 2>/dev/null || true)"
    NE_ENABLED="$(systemctl is-enabled node_exporter 2>/dev/null || true)"
    printf '    is-active  : %s\n    is-enabled : %s\n' "$NE_ACTIVE" "$NE_ENABLED"
    [ "$NE_ACTIVE" = "active" ] \
        || die "node_exporter is not active. Check: journalctl -u node_exporter -n 50"
    ok "Service active"
}

# ===========================================================================
# Step 12 — port and flags
# ===========================================================================

verify_running_flags() {
    step "Step 12: Verify the port and flags"

    local holder pid flags
    holder="$(port_holder "$LISTEN_PORT")"
    [ -n "$holder" ] || die "Nothing is listening on ${LISTEN_PORT}."
    printf '%s\n' "$holder" | trim_wide | indent
    ok "Listening on ${LISTEN_PORT}"

    # Confirm from the live process, not the unit file: an editing mistake in
    # an ExecStart continuation silently drops every flag after the break.
    pid="$(service_main_pid)"
    [ -n "$pid" ] && [ -r "/proc/${pid}/cmdline" ] || {
        warn "Could not read the process command line to confirm the flags."
        return 0
    }
    flags="$(tr '\0' '\n' < "/proc/${pid}/cmdline" | grep '^--' || true)"
    printf '%s\n' "$flags" | indent6
    printf '%s' "$flags" | grep -q "^--collector.textfile.directory=${TEXTFILE_DIR}$" \
        && ok "textfile collector active at ${TEXTFILE_DIR}" \
        || die "The textfile.directory flag did not take. Check ${UNIT}."
}

# ===========================================================================
# Step 12b — scrape locally
# ===========================================================================

check_prom_file_modes() {
    # node_exporter reads these as an unprivileged user; anything not 0644 is
    # silently skipped, which looks like a collector bug rather than a mode bug.
    local count f m
    count="$(ls -1 "$TEXTFILE_DIR"/*.prom 2>/dev/null | wc -l | tr -d ' ')"
    [ "${count:-0}" -gt 0 ] || return 0
    ok "${count} .prom file(s) already present and being collected"
    for f in "$TEXTFILE_DIR"/*.prom; do
        m="$(stat -c '%a' "$f")"
        [ "$m" = "644" ] || warn "$(basename "$f") is mode ${m}; node_exporter needs 644."
    done
}

scrape_locally() {
    step "Step 12b: Scrape locally"

    command -v curl >/dev/null 2>&1 || { warn "curl not available; skipping."; return 0; }
    local metrics count err
    metrics="$(scrape_metrics)"
    count="$(printf '%s' "$metrics" | grep -c '^node_' || true)"
    [ "${count:-0}" -gt 0 ] \
        && ok "${count} node_* series exposed" \
        || die "Could not scrape localhost:${LISTEN_PORT}/metrics."

    err="$(printf '%s' "$metrics" | awk '/^node_textfile_scrape_error/ {print $2; exit}' || true)"
    case "$err" in
        0)  ok "node_textfile_scrape_error = 0" ;;
        "") warn "node_textfile_scrape_error absent — the textfile collector may be off." ;;
        *)  warn "node_textfile_scrape_error = ${err} — a .prom file in ${TEXTFILE_DIR} is malformed." ;;
    esac

    check_prom_file_modes
}

# ===========================================================================
# Step 13 — firewall
# ===========================================================================

enable_ufw_safely() {
    # Enabling a firewall over SSH is how people lock themselves out. Allow the
    # port this session actually arrived on, whatever it is, BEFORE enabling.
    local ssh_port
    ssh_port="$(ssh_session_port)"
    warn "ufw is inactive. Allowing SSH on ${ssh_port}/tcp BEFORE enabling it."
    ufw allow "${ssh_port}/tcp" >/dev/null
    ufw allow from "$MONITOR_IP" to any port "$LISTEN_PORT" proto tcp >/dev/null
    # --force because plain `ufw enable` prompts, which would hang a script.
    ufw --force enable >/dev/null
    ok "ufw enabled with SSH ${ssh_port}/tcp and ${MONITOR_IP} -> ${LISTEN_PORT}/tcp"
}

warn_if_blanket_rule() {
    # A blanket "ALLOW Anywhere" rule on the same port makes the targeted rule
    # decorative, so say so rather than implying the port is restricted.
    ufw status 2>/dev/null | grep -E "^${LISTEN_PORT}/tcp" | grep -q 'Anywhere' || return 0
    warn "An existing rule already allows ${LISTEN_PORT}/tcp from Anywhere."
    warn "The targeted rule adds nothing until you remove that one:"
    warn "  ufw status numbered   then   ufw delete <number>"
}

configure_firewall() {
    step "Step 13: Firewall"

    if [ "$SKIP_FIREWALL" -eq 1 ]; then
        ok "Skipped (--no-firewall)."; return 0
    fi
    if [ -z "$MONITOR_IP" ]; then
        warn "No monitoring server IP was given. Open ${LISTEN_PORT}/tcp manually."; return 0
    fi

    if command -v ufw >/dev/null 2>&1; then
        if ufw status 2>/dev/null | head -1 | grep -qi 'inactive'; then
            enable_ufw_safely
        else
            ufw allow from "$MONITOR_IP" to any port "$LISTEN_PORT" proto tcp >/dev/null
            ufw reload >/dev/null
            ok "ufw: ${MONITOR_IP} -> ${LISTEN_PORT}/tcp"
            warn_if_blanket_rule
        fi
        ufw status numbered 2>/dev/null | grep -E "${LISTEN_PORT}|Status" | indent || true
    elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=${MONITOR_IP} port port=${LISTEN_PORT} protocol=tcp accept" >/dev/null
        firewall-cmd --reload >/dev/null
        ok "firewalld: ${MONITOR_IP} -> ${LISTEN_PORT}/tcp"
    else
        warn "No ufw or firewalld found. Open ${LISTEN_PORT}/tcp for ${MONITOR_IP} manually."
    fi
}

# ===========================================================================
# Downloads
# ===========================================================================

report_downloads() {
    step "Downloaded files"
    if [ "$KEEP_DOWNLOAD" -eq 1 ]; then
        ls -lh "${WORKDIR}/${TARBALL}" 2>/dev/null | indent || true
        [ -n "${SUMFILE:-}" ] && [ -f "${WORKDIR}/${SUMFILE}" ] \
            && ls -lh "${WORKDIR}/${SUMFILE}" | indent
        ok "Kept in ${WORKDIR} (pass --clean-download to remove)."
    else
        rm -rf "$SRCDIR" "${WORKDIR}/${TARBALL}"
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
  user             : ${NE_USER}
  status           : ${NE_ACTIVE} / ${NE_ENABLED}
  listen           : :${LISTEN_PORT}
  textfile dir     : ${TEXTFILE_DIR}
  systemd collector: $([ "$WANT_SYSTEMD_COLLECTOR" -eq 1 ] && echo enabled || echo disabled)
  downloads        : ${WORKDIR}
  local address    : $(hostname -I 2>/dev/null | awk '{print $1}'):${LISTEN_PORT}
                     (behind NAT? Prometheus needs the address it can reach,
                      not this one -- verify with a curl from the monitor)

On the monitoring server:
  1. curl -s http://<this-host>:${LISTEN_PORT}/metrics | grep -c '^node_'
  2. add the target to /etc/prometheus/prometheus.yml
  3. promtool check config /etc/prometheus/prometheus.yml
  4. systemctl reload prometheus     # reload, not restart
  5. Grafana dashboard ID 1860
EOF
}

# ===========================================================================
# Orchestration
# ===========================================================================

phase_prepare() {
    check_existing_install
    ask_monitor_ip
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
    create_textfile_dir
    write_systemd_unit
    start_service
    verify_service
    verify_running_flags
    scrape_locally
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

# Allow `source ./install_node_exporter.sh --source-only` to load the
# functions without running anything, for step-by-step debugging.
case "${1:-}" in
    --source-only) init_colors; SOURCE_ONLY=1 ;;
    *) main "$@" ;;
esac
