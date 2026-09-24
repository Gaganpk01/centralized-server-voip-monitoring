#!/usr/bin/env bash
#
# install_nginx_exporter.sh — install nginx-prometheus-exporter on a remote server.
#
# Structured as one function per step, orchestrated by main() at the bottom.
# Every function is independently callable, so you can source this file and run
# a single step while debugging:
#
#   source ./install_nginx_exporter.sh --source-only
#   verify_stub_status
#   verify_metrics
#   resolve_version
#
# Covers the remote-server half of the runbook, Steps 1-16:
#
#   Step 1   verify nginx is running and has the stub_status module
#   Step 2   add a localhost-only stub_status server block
#   Step 3   nginx -t
#   Step 4   reload nginx
#   Step 5   verify stub_status answers, and is NOT reachable externally
#   Step 6   create the nginx_exporter system user and group
#   Step 7   resolve the version
#   Step 8   detect the architecture
#   Step 9   download, VERIFY sha256, extract
#   Step 10  install the binary
#   Step 11  write the systemd unit with a hardened sandbox
#   Step 12  daemon-reload, enable, start
#   Step 13  verify the service is active and the port is listening
#   Step 14  scrape localhost and check nginx_up
#   Step 15  open the firewall for the monitoring server
#   Step 16  report the kept download (nothing is deleted)
#
# Downloads land in /usr/src/monitoring and are KEPT, so a reinstall or
# rollback needs no second download.
#
# PORT: the runbook uses 9102 in the unit and scrape job but 9113 in the
# verification and firewall steps. This defaults to 9113 (upstream's own
# default, and what dashboard 12708 expects) but adopts the port from an
# existing nginx_exporter unit if one is already installed. Override with
# --port.
#
# The monitoring server IP is always asked for interactively -- there is no
# flag for it and no default. Pass --no-firewall to skip that step.
#
# Safe to re-run. On an existing install it stops the service, replaces the
# binary, and restarts -- so it doubles as an upgrade path.
#
# Usage:
#   sudo ./install_nginx_exporter.sh
#   sudo ./install_nginx_exporter.sh --port 9102
#   sudo ./install_nginx_exporter.sh --status-port 8081 --version v1.5.3
#   sudo ./install_nginx_exporter.sh --no-firewall --clean-download
#   sudo ./install_nginx_exporter.sh --uninstall
#
set -euo pipefail

# ===========================================================================
# Configuration
# ===========================================================================
REPO="nginx/nginx-prometheus-exporter"
VERSION=""                   # empty = detect the latest release
FALLBACK_VERSION="v1.5.3"    # used only if detection fails
EXP_USER="nginx_exporter"
LISTEN_PORT=""               # empty = adopt from an existing unit, else 9113
DEFAULT_PORT="9113"
STATUS_PORT="8081"
STATUS_PATH="/nginx_status"
BIN_PATH="/usr/local/bin/nginx-prometheus-exporter"
UNIT="/etc/systemd/system/nginx_exporter.service"
WORKDIR="/usr/src/monitoring"

MONITOR_IP=""
SKIP_FIREWALL=0
SKIP_CHECKSUM=0
KEEP_DOWNLOAD=1              # keep downloads by default
SKIP_STUB=0
UNINSTALL=0
PURGE_USER=0
SOURCE_ONLY=0

# Runtime state shared between steps.
STUB_CONF=""; STUB_URI=""
EXISTING=""; OLD_PORT=""; OLD_USER=""
ARCH=""; BARE=""; TARBALL=""; SUMFILE=""; STEM=""; BASE=""
E_ACTIVE=""; E_ENABLED=""; NGINX_UP=""

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

usage() { sed -n '3,53p' "$0" | sed 's/^# \{0,1\}//'; }

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
    # Ask systemd rather than pgrep: pgrep -f also matches this installer when
    # it is saved under a matching filename, and after a restart the script has
    # the lower PID.
    local pid
    pid="$(systemctl show nginx_exporter -p MainPID --value 2>/dev/null || true)"
    case "$pid" in ''|0) pid="$(pgrep -x nginx-prometheus-exporter | head -1 || true)" ;; esac
    printf '%s' "$pid"
}

port_holder() {
    command -v ss >/dev/null 2>&1 || return 0
    ss -tulnp 2>/dev/null | grep ":${1} " | head -1 || true
}

scrape_metrics() {
    curl -sf --max-time 10 "localhost:${LISTEN_PORT}/metrics" 2>/dev/null || true
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
            --status-port)    need_arg "$1" "${2:-}"; STATUS_PORT="$2"; shift 2 ;;
            --status-path)    need_arg "$1" "${2:-}"; STATUS_PATH="$2"; shift 2 ;;
            --workdir)        need_arg "$1" "${2:-}"; WORKDIR="$2"; shift 2 ;;
            --no-stub-config) SKIP_STUB=1; shift ;;
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

    is_number "$STATUS_PORT" || die "--status-port must be a number (got '$STATUS_PORT')."
    if [ -n "$LISTEN_PORT" ]; then
        is_number "$LISTEN_PORT" || die "--port must be a number (got '$LISTEN_PORT')."
    fi
    case "$STATUS_PATH" in
        /*) ;;
        *) die "--status-path must start with a slash (got '$STATUS_PATH')." ;;
    esac
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
    step "Removing nginx_exporter"
    systemctl disable --now nginx_exporter >/dev/null 2>&1 || true
    rm -f "$UNIT" "$BIN_PATH"
    rm -rf /etc/systemd/system/nginx_exporter.service.d
    systemctl daemon-reload
    ok "Removed unit and binary."
    if [ "$PURGE_USER" -eq 1 ]; then
        userdel "$EXP_USER" >/dev/null 2>&1 || true
        groupdel "$EXP_USER" >/dev/null 2>&1 || true
        ok "Removed the ${EXP_USER} user and group."
    else
        warn "Kept the ${EXP_USER} user (pass --purge-user to remove it)."
    fi
    warn "Kept the stub_status config and firewall rules."
}

# ===========================================================================
# Preflight — existing install, port adoption
# ===========================================================================

read_existing_unit() {
    [ -f "$UNIT" ] || return 0
    OLD_PORT="$(grep -oE 'web\.listen-address=[^ ]*' "$UNIT" \
        | head -1 | sed 's/.*://' | tr -dc '0-9' || true)"
    OLD_USER="$(grep -oE '^User=.*' "$UNIT" | head -1 | cut -d= -f2 || true)"
    printf '    existing unit : %s\n' "$UNIT"
    printf '    listen port   : %s\n' "${OLD_PORT:-unknown}"
    printf '    runs as       : %s\n' "${OLD_USER:-unknown}"
    case "${OLD_USER:-}" in
        nobody)
            warn "The existing unit runs as 'nobody' — systemd flags that as unsafe."
            warn "This install will switch it to a dedicated ${EXP_USER} account." ;;
    esac
}

resolve_listen_port() {
    # Adopt the port already in use rather than silently moving the endpoint;
    # Prometheus would keep scraping the old one and go stale.
    [ -n "$LISTEN_PORT" ] && { ok "Port forced to ${LISTEN_PORT}."; return 0; }
    if [ -n "$OLD_PORT" ]; then
        LISTEN_PORT="$OLD_PORT"
        ok "Keeping the port already in use: ${LISTEN_PORT}"
    else
        LISTEN_PORT="$DEFAULT_PORT"
        ok "Using the default port ${LISTEN_PORT} (override with --port)."
    fi
}

check_port_free() {
    local holder
    holder="$(port_holder "$LISTEN_PORT")"
    if [ -z "$holder" ]; then
        ok "Port ${LISTEN_PORT} is free."
        return 0
    fi
    printf '    port %s currently held by:\n' "$LISTEN_PORT"
    printf '%s\n' "$holder" | trim_wide | indent6
    # Something else on the port would make the later verification pass for the
    # wrong reason.
    printf '%s' "$holder" | grep -qE 'nginx-prometheus|nginx_export' \
        || die "Port ${LISTEN_PORT} is held by something else. Pick another with --port."
}

check_existing_install() {
    step "Checking for an existing install"

    if [ -x "$BIN_PATH" ]; then
        EXISTING="$("$BIN_PATH" --version 2>&1 \
            | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
        ok "Found ${BIN_PATH} ${EXISTING:-(version unknown)}"
    else
        ok "No existing binary at ${BIN_PATH}."
    fi

    read_existing_unit
    resolve_listen_port
    check_port_free
}

# ===========================================================================
# Step 1 — verify nginx
# ===========================================================================

verify_nginx() {
    step "Step 1: Verify nginx"

    command -v nginx >/dev/null 2>&1 || die "nginx is not installed."
    nginx -v 2>&1 | indent

    local active
    active="$(systemctl is-active nginx 2>/dev/null || true)"
    printf '    is-active : %s\n' "${active:-unknown}"
    [ "$active" = "active" ] || warn "nginx is not active; nginx_up will report 0."

    # stub_status is compiled in on most builds, but not all — without it the
    # config in Step 2 fails nginx -t with "unknown directive".
    if nginx -V 2>&1 | tr ' ' '\n' | grep -q 'http_stub_status_module'; then
        ok "http_stub_status_module is compiled in"
    else
        warn "http_stub_status_module not found in 'nginx -V'."
        warn "If nginx -t fails on the stub_status directive, that is why."
    fi
}

# ===========================================================================
# Step 2 — stub_status config
# ===========================================================================

resolve_stub_conf_path() {
    # Debian/Ubuntu use conf.d inside /etc/nginx; some builds only have
    # sites-available. Both are included by the default nginx.conf.
    if [ -d /etc/nginx/conf.d ]; then
        STUB_CONF="/etc/nginx/conf.d/stub_status.conf"
    elif [ -d /etc/nginx/sites-available ]; then
        STUB_CONF="/etc/nginx/sites-available/stub_status"
    else
        die "Cannot find an nginx include directory under /etc/nginx."
    fi
    STUB_URI="http://127.0.0.1:${STATUS_PORT}${STATUS_PATH}"
}

write_stub_conf() {
    # Bind to 127.0.0.1 explicitly, not just allow/deny: binding is enforced by
    # the kernel, while allow/deny alone still opens the port to the network.
    cat > "$STUB_CONF" <<EOF
# Managed by install_nginx_exporter.sh
server {
    listen 127.0.0.1:${STATUS_PORT};
    server_name localhost;

    location ${STATUS_PATH} {
        stub_status;
        access_log off;
        allow 127.0.0.1;
        deny all;
    }
}
EOF
    chmod 0644 "$STUB_CONF"
    ok "Wrote ${STUB_CONF}"

    if [ "$STUB_CONF" = "/etc/nginx/sites-available/stub_status" ]; then
        ln -sf "$STUB_CONF" /etc/nginx/sites-enabled/stub_status
        ok "Linked into sites-enabled."
    fi
}

configure_stub_status() {
    step "Step 2: stub_status endpoint"
    resolve_stub_conf_path

    if [ "$SKIP_STUB" -eq 1 ]; then
        ok "Skipped (--no-stub-config). Expecting ${STUB_URI} to already work."
        return 0
    fi
    if [ -f "$STUB_CONF" ] && grep -q 'stub_status' "$STUB_CONF"; then
        ok "Leaving existing ${STUB_CONF} untouched."
        grep -E 'listen|location' "$STUB_CONF" | indent6
        return 0
    fi
    write_stub_conf
}

# ===========================================================================
# Step 3 / 4 — test and reload
# ===========================================================================

test_nginx_config() {
    step "Step 3: nginx -t"
    nginx -t 2>&1 | indent || die "nginx config test failed — fix the errors above."
    ok "Config test passed"
}

reload_nginx() {
    step "Step 4: Reload nginx"
    # reload, not restart: a restart drops in-flight connections on a live server.
    systemctl reload nginx || die "nginx reload failed. Check: journalctl -u nginx -n 30"
    sleep 1
    systemctl is-active --quiet nginx || die "nginx is not active after reload."
    ok "Reloaded"
}

# ===========================================================================
# Step 5 — verify stub_status
# ===========================================================================

check_stub_not_external() {
    # The whole point of binding 127.0.0.1 is that this fails.
    local host_ip
    host_ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
    [ -n "$host_ip" ] || return 0
    if curl -fsS --max-time 3 "http://${host_ip}:${STATUS_PORT}${STATUS_PATH}" >/dev/null 2>&1; then
        warn "stub_status IS reachable on ${host_ip}:${STATUS_PORT} — it should not be."
        warn "Check for another server block listening on all interfaces."
    else
        ok "Correctly refused on ${host_ip}:${STATUS_PORT}"
    fi
}

verify_stub_status() {
    step "Step 5: Verify stub_status"

    local holder out
    holder="$(port_holder "$STATUS_PORT")"
    [ -n "$holder" ] \
        && printf '%s\n' "$holder" | trim_wide | indent \
        || warn "Nothing listening on ${STATUS_PORT}."

    command -v curl >/dev/null 2>&1 || die "curl is required to verify stub_status."
    out="$(curl -fsS --max-time 5 "$STUB_URI" 2>&1 || true)"
    printf '%s\n' "$out" | indent
    printf '%s' "$out" | grep -q 'Active connections' \
        || die "stub_status did not respond at ${STUB_URI}. The exporter cannot work without it."
    ok "stub_status is answering"

    check_stub_not_external
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
# Step 6 — service user
# ===========================================================================

create_service_user() {
    step "Step 6: Service user"

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
# Step 7 — version
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
    step "Step 7: Version"

    if [ -n "$VERSION" ]; then
        case "$VERSION" in v*) ;; *) VERSION="v${VERSION}" ;; esac
        ok "Using the requested version: ${VERSION}"
    else
        VERSION="$(latest_version_via_redirect)"
        if [ -z "$VERSION" ]; then
            warn "Redirect detection failed; trying the GitHub API."
            VERSION="$(latest_version_via_api)"
        fi
        # An empty VERSION would build a nonsense URL and fail confusingly.
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
    BARE="${VERSION#v}"
}

# ===========================================================================
# Step 8 — architecture
# ===========================================================================

detect_arch() {
    step "Step 8: Architecture"
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
# Step 9 — download, verify, extract
# ===========================================================================

set_download_names() {
    # This project uses the BARE version in filenames and underscores as
    # separators, unlike node_exporter's v-prefixed, dash-separated naming.
    TARBALL="nginx-prometheus-exporter_${BARE}_linux_${ARCH}.tar.gz"
    # And it publishes <name>_<version>_checksums.txt, not sha256sums.txt —
    # both of those return 404 here.
    SUMFILE="nginx-prometheus-exporter_${BARE}_checksums.txt"
    STEM="nginx-prometheus-exporter_${BARE}_linux_${ARCH}"
    BASE="https://github.com/${REPO}/releases/download/${VERSION}"
}

download_release() {
    step "Step 9: Download nginx-prometheus-exporter ${VERSION} (${ARCH})"
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
    if ! curl -fsSL --retry 3 -o "$SUMFILE" "${BASE}/${SUMFILE}"; then
        warn "Could not fetch ${SUMFILE}; proceeding unverified."
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
    # This tarball extracts FLAT — binary, LICENSE, README, completions and
    # manpages all land in the current directory. Extract into its own
    # subdirectory so the shared download folder stays readable.
    rm -rf "${WORKDIR}/${STEM}"
    mkdir -p "${WORKDIR}/${STEM}"
    tar -xzf "$TARBALL" -C "${WORKDIR}/${STEM}" || die "Extraction failed."
    [ -f "${WORKDIR}/${STEM}/nginx-prometheus-exporter" ] \
        || die "Expected binary not found in ${STEM}."
    ls -1 "${WORKDIR}/${STEM}" | indent
}

# ===========================================================================
# Step 10 — install the binary
# ===========================================================================

install_binary() {
    step "Step 10: Install the binary"

    # A running binary cannot be overwritten in place.
    if systemctl is-active --quiet nginx_exporter 2>/dev/null; then
        systemctl stop nginx_exporter
        ok "Stopped the running service for the upgrade."
    fi

    install -o "$EXP_USER" -g "$EXP_USER" -m 0755 \
        "${WORKDIR}/${STEM}/nginx-prometheus-exporter" "$BIN_PATH" \
        || die "Could not install to ${BIN_PATH}."
    ls -l "$BIN_PATH" | indent
    # Note it reports itself as "nginx_exporter", not by its binary name.
    "$BIN_PATH" --version 2>&1 | head -1 | indent
    ok "Installed"
}

# ===========================================================================
# Step 11 — systemd unit
# ===========================================================================

build_exec_flags() {
    # One ExecStart line: a blank line from an empty conditional flag would end
    # a backslash continuation and turn later flags into unknown directives.
    printf '%s' "--nginx.scrape-uri=${STUB_URI}"
    printf '%s' " --web.listen-address=0.0.0.0:${LISTEN_PORT}"
}

write_systemd_unit() {
    step "Step 11: Systemd unit"

    cat > "$UNIT" <<EOF
[Unit]
Description=Nginx Prometheus Exporter
Documentation=https://github.com/${REPO}
After=network-online.target nginx.service
Wants=network-online.target

[Service]
Type=simple
User=${EXP_USER}
Group=${EXP_USER}
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

[Install]
WantedBy=multi-user.target
EOF

    chmod 0644 "$UNIT"
    grep '^ExecStart=' "$UNIT" | fold -w 74 -s | indent
    ok "Wrote ${UNIT}"
}

# ===========================================================================
# Step 12 — enable and start
# ===========================================================================

start_service() {
    step "Step 12: Enable and start"
    systemctl daemon-reload
    systemctl enable nginx_exporter >/dev/null 2>&1 || warn "Could not enable at boot."
    systemctl restart nginx_exporter \
        || die "Failed to start. Check: journalctl -u nginx_exporter -n 50"
    sleep 2
}

# ===========================================================================
# Step 13 — verify the service
# ===========================================================================

show_running_flags() {
    # Confirm the scrape URI actually took, from the live process rather than
    # the unit file.
    local pid
    pid="$(service_main_pid)"
    [ -n "$pid" ] && [ -r "/proc/${pid}/cmdline" ] || return 0
    tr '\0' '\n' < "/proc/${pid}/cmdline" | grep '^--' | indent6
    tr '\0' '\n' < "/proc/${pid}/cmdline" | grep -q -- "--nginx.scrape-uri=${STUB_URI}" \
        && ok "scrape-uri matches the unit" \
        || warn "The running scrape-uri differs from ${STUB_URI}."
}

verify_service() {
    step "Step 13: Verify the service"

    E_ACTIVE="$(systemctl is-active nginx_exporter 2>/dev/null || true)"
    E_ENABLED="$(systemctl is-enabled nginx_exporter 2>/dev/null || true)"
    printf '    is-active  : %s\n    is-enabled : %s\n' "$E_ACTIVE" "$E_ENABLED"
    [ "$E_ACTIVE" = "active" ] \
        || die "nginx_exporter is not active. Check: journalctl -u nginx_exporter -n 50"
    ok "Service active"

    local holder
    holder="$(port_holder "$LISTEN_PORT")"
    [ -n "$holder" ] || die "Nothing is listening on ${LISTEN_PORT}."
    printf '%s\n' "$holder" | trim_wide | indent
    ok "Listening on ${LISTEN_PORT}"

    show_running_flags
}

# ===========================================================================
# Step 14 — verify metrics
# ===========================================================================

verify_metrics() {
    step "Step 14: Verify metrics"

    local metrics count
    metrics="$(scrape_metrics)"
    count="$(printf '%s' "$metrics" | grep -c '^nginx' || true)"
    [ "${count:-0}" -gt 0 ] \
        && ok "${count} nginx* series exposed" \
        || die "Could not scrape localhost:${LISTEN_PORT}/metrics."

    NGINX_UP="$(printf '%s' "$metrics" | awk '/^nginx_up / {print $2; exit}' || true)"
    printf '    nginx_up %s\n' "${NGINX_UP:-<absent>}"
    case "$NGINX_UP" in
        1) ok "nginx_up = 1 — the exporter is reading stub_status." ;;
        0) warn "nginx_up = 0 — the exporter runs but cannot read ${STUB_URI}."
           warn "Check: journalctl -u nginx_exporter -n 30" ;;
        *) warn "nginx_up not found in the output." ;;
    esac
}

# ===========================================================================
# Step 15 — firewall
# ===========================================================================

warn_if_blanket_rule() {
    # A blanket "ALLOW Anywhere" rule on the same port makes the targeted rule
    # decorative, so say so rather than implying the port is restricted.
    ufw status 2>/dev/null | grep -E "^${LISTEN_PORT}/tcp" | grep -q 'Anywhere' || return 0
    warn "An existing rule already allows ${LISTEN_PORT}/tcp from Anywhere."
    warn "The targeted rule adds nothing until you remove that one:"
    warn "  ufw status numbered   then   ufw delete <number>"
}

configure_firewall() {
    step "Step 15: Firewall"

    if [ "$SKIP_FIREWALL" -eq 1 ]; then
        ok "Skipped (--no-firewall)."; return 0
    fi
    if [ -z "$MONITOR_IP" ]; then
        warn "No monitoring server IP was given. Open ${LISTEN_PORT}/tcp manually."; return 0
    fi

    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi '^Status: active'; then
        ufw allow from "$MONITOR_IP" to any port "$LISTEN_PORT" proto tcp >/dev/null
        ufw reload >/dev/null
        ok "ufw: ${MONITOR_IP} -> ${LISTEN_PORT}/tcp"
        warn_if_blanket_rule
    elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=${MONITOR_IP} port port=${LISTEN_PORT} protocol=tcp accept" >/dev/null
        firewall-cmd --reload >/dev/null
        ok "firewalld: ${MONITOR_IP} -> ${LISTEN_PORT}/tcp"
    else
        warn "No active ufw/firewalld. Open ${LISTEN_PORT}/tcp for ${MONITOR_IP} manually."
    fi
}

# ===========================================================================
# Step 16 — downloads
# ===========================================================================

report_downloads() {
    step "Step 16: Downloaded files"
    if [ "$KEEP_DOWNLOAD" -eq 1 ]; then
        ls -lh "${WORKDIR}/${TARBALL}" 2>/dev/null | indent || true
        [ -f "${WORKDIR}/${SUMFILE}" ] && ls -lh "${WORKDIR}/${SUMFILE}" | indent
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
  scrape uri       : ${STUB_URI}
  stub config      : ${STUB_CONF}
  nginx_up         : ${NGINX_UP:-unknown}
  downloads        : ${WORKDIR}
  local address    : $(hostname -I 2>/dev/null | awk '{print $1}'):${LISTEN_PORT}
                     (behind NAT? Prometheus needs the address it can reach,
                      not this one -- verify with a curl from the monitor)

On the monitoring server:
  1. curl -s http://<this-host>:${LISTEN_PORT}/metrics | grep '^nginx_up'
  2. add to /etc/prometheus/prometheus.yml:
         - job_name: "nginx"
           static_configs:
             - targets: ["<this-host>:${LISTEN_PORT}"]
  3. promtool check config /etc/prometheus/prometheus.yml
  4. systemctl reload prometheus     # reload, not restart
  5. Grafana dashboard ID 12708 — note it assumes port 9121/9113 conventions,
     so adjust the instance filter if this install uses ${LISTEN_PORT}.
EOF
}

# ===========================================================================
# Orchestration
# ===========================================================================

phase_prepare() {
    check_existing_install
    verify_nginx
    configure_stub_status
    test_nginx_config
    reload_nginx
    verify_stub_status
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
    write_systemd_unit
    start_service
    verify_service
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

    phase_prepare
    phase_install
    print_summary
}

# Allow `source ./install_nginx_exporter.sh --source-only` to load the
# functions without running anything, for step-by-step debugging.
case "${1:-}" in
    --source-only) init_colors; SOURCE_ONLY=1 ;;
    *) main "$@" ;;
esac
