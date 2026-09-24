#!/usr/bin/env bash
#
# install-alertmanager.sh
#
# Installs Prometheus Alertmanager with Gmail SMTP notifications on a host
# that does NOT run Prometheus. Prometheus lives on a separate monitoring
# server and connects in over tcp/9093.
#
#     [ monitoring server ]                 [ this host ]
#       Prometheus          ---- 9093 -->     Alertmanager
#       evaluates rules                       sends the emails
#
# This is the scripted form of a setup verified working by hand:
#   - binds 0.0.0.0:9093
#   - loopback ACCEPT added BEFORE the DROP, or the local health check hangs
#   - port 9093 restricted to the monitoring server's IP, rules made persistent
#   - prints the alerting: block to paste into prometheus.yml on the other host
#
# Usage:
#   chmod +x install-alertmanager.sh
#   sudo ./install-alertmanager.sh
#
#   sudo ./install-alertmanager.sh --uninstall
#   sudo ./install-alertmanager.sh --help
#
# Tested on: Debian 11/12, Ubuntu 20.04/22.04/24.04
#

set -euo pipefail

# ============================================================================
# Static configuration
# ============================================================================

AM_VERSION="0.34.0"
LISTEN_PORT="9093"
LISTEN_ADDR="0.0.0.0:${LISTEN_PORT}"

AM_CONF_DIR="/etc/alertmanager"
AM_DATA_DIR="/var/lib/alertmanager"
AM_BIN_DIR="/usr/local/bin"
SNIPPET_DIR="/root/alertmanager-prometheus-snippets"

SRC_DIR="/usr/src"
TS="$(date +%Y%m%d-%H%M%S)"

# ============================================================================
# Helpers
# ============================================================================

C_RED=$'\033[0;31m'; C_GRN=$'\033[0;32m'; C_YEL=$'\033[1;33m'
C_BLU=$'\033[0;34m'; C_BLD=$'\033[1m';    C_RST=$'\033[0m'

step()  { printf '\n%s==> %s%s\n' "$C_BLU" "$*" "$C_RST"; }
ok()    { printf '%s  [ok]%s %s\n'   "$C_GRN" "$C_RST" "$*"; }
warn()  { printf '%s  [warn]%s %s\n' "$C_YEL" "$C_RST" "$*"; }
fail()  { printf '%s  [FAIL]%s %s\n' "$C_RED" "$C_RST" "$*" >&2; exit 1; }

backup() {
  [[ -f "$1" ]] || return 0
  cp -a "$1" "$1.bak-$TS"
  warn "existing $1 backed up to $1.bak-$TS"
}

is_email() { [[ "$1" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]]; }
is_host()  { [[ "$1" =~ ^[A-Za-z0-9._-]+:[0-9]{1,5}$ ]]; }

is_ipv4() {
  [[ "$1" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  local o
  for o in "${BASH_REMATCH[@]:1:4}"; do (( o >= 0 && o <= 255 )) || return 1; done
  return 0
}

is_addr() {
  is_ipv4 "$1" && return 0
  [[ "$1" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]]
}

is_email_list() {
  local IFS=','; local a
  for a in $1; do
    a="${a//[[:space:]]/}"
    [[ -n "$a" ]] || return 1
    is_email "$a" || return 1
  done
  return 0
}

ask() {
  local var="$1" prompt="$2" default="${3:-}" validator="${4:-}" input=""
  while :; do
    if [[ -n "$default" ]]; then
      read -rp "  ${prompt} [${default}]: " input || fail "aborted"
      input="${input:-$default}"
    else
      read -rp "  ${prompt}: " input || fail "aborted"
    fi
    input="${input#"${input%%[![:space:]]*}"}"
    input="${input%"${input##*[![:space:]]}"}"
    [[ -z "$input" ]] && { warn "value required"; continue; }
    if [[ -n "$validator" ]] && ! "$validator" "$input"; then
      warn "'$input' does not look valid — try again"
      continue
    fi
    break
  done
  declare -g "$var=$input"
}

ask_secret() {
  local var="$1" prompt="$2" want_len="${3:-0}" input=""
  while :; do
    read -rsp "  ${prompt}: " input || fail "aborted"; echo
    input="${input//[[:space:]]/}"
    [[ -z "$input" ]] && { warn "value required"; continue; }
    if [[ "$want_len" -gt 0 && ${#input} -ne "$want_len" ]]; then
      warn "expected $want_len characters, got ${#input}"
      confirm "  use it anyway?" || continue
    fi
    break
  done
  declare -g "$var=$input"
}

confirm() {
  local reply=""
  read -rp "  $1 [y/N] " reply || return 1
  [[ "$reply" =~ ^[Yy]$ ]]
}

guess_primary_ip() {
  ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}'
}

# ============================================================================
# Firewall
# ============================================================================

# Order matters. Loopback must be accepted before the catch-all DROP, or
# 127.0.0.1 -> 127.0.0.1 traffic is silently dropped: loopback packets
# traverse the INPUT chain too. That makes the health check and amtool hang
# in SYN retry rather than fail, which looks like the script freezing.
open_firewall() {
  local src="$1"

  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -qi '^Status: active'; then
    ufw allow from "$src" to any port "$LISTEN_PORT" proto tcp \
      comment "alertmanager from prometheus" >/dev/null
    ok "ufw: tcp/${LISTEN_PORT} allowed from ${src} only (persistent by default)"
    return
  fi

  if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --add-rich-rule=\
"rule family=\"ipv4\" source address=\"${src}\" port protocol=\"tcp\" port=\"${LISTEN_PORT}\" accept" >/dev/null
    firewall-cmd --reload >/dev/null
    ok "firewalld: tcp/${LISTEN_PORT} allowed from ${src} only (permanent)"
    return
  fi

  command -v iptables >/dev/null || {
    warn "no firewall tool found — tcp/${LISTEN_PORT} is world-open"
    warn "Alertmanager has NO authentication. Restrict it before leaving this host."
    return
  }

  iptables -C INPUT -i lo -j ACCEPT 2>/dev/null \
    || iptables -I INPUT 1 -i lo -j ACCEPT
  iptables -C INPUT -p tcp -s "$src" --dport "$LISTEN_PORT" -j ACCEPT 2>/dev/null \
    || iptables -I INPUT 2 -p tcp -s "$src" --dport "$LISTEN_PORT" -j ACCEPT
  iptables -C INPUT -p tcp ! -i lo --dport "$LISTEN_PORT" -j DROP 2>/dev/null \
    || iptables -A INPUT -p tcp ! -i lo --dport "$LISTEN_PORT" -j DROP
  ok "iptables: loopback allowed, accept from ${src}, drop all other tcp/${LISTEN_PORT}"

  persist_iptables
}

# iptables rules vanish on reboot unless saved. Without this, a restart
# leaves port 9093 wide open with no authentication behind it.
persist_iptables() {
  if command -v netfilter-persistent >/dev/null; then
    netfilter-persistent save >/dev/null 2>&1 && ok "rules saved (netfilter-persistent)"
    return
  fi

  if ! confirm "Install iptables-persistent so the rules survive reboot?"; then
    warn "rules are NOT persistent — after a reboot tcp/${LISTEN_PORT} is open to everyone"
    return
  fi

  # Preseed both answers, or the package opens an interactive dialog mid-script.
  echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections
  echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iptables-persistent >/dev/null 2>&1 \
    || { warn "iptables-persistent install failed — rules will not survive reboot"; return; }
  netfilter-persistent save >/dev/null 2>&1
  ok "iptables-persistent installed, rules saved"
}

close_firewall() {
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -qi '^Status: active'; then
    while ufw status numbered 2>/dev/null | grep -q "${LISTEN_PORT}/tcp"; do
      local n
      n="$(ufw status numbered | grep "${LISTEN_PORT}/tcp" | head -1 | sed 's/^\[ *\([0-9]*\).*/\1/')"
      [[ -n "$n" ]] || break
      yes | ufw delete "$n" >/dev/null 2>&1 || break
    done
    ok "ufw rules for tcp/${LISTEN_PORT} removed"
    return
  fi

  if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --list-rich-rules 2>/dev/null | grep "port=\"${LISTEN_PORT}\"" \
      | while read -r rule; do
          firewall-cmd --permanent --remove-rich-rule="$rule" >/dev/null 2>&1 || true
        done
    firewall-cmd --reload >/dev/null 2>&1 || true
    ok "firewalld rules for tcp/${LISTEN_PORT} removed"
    return
  fi

  command -v iptables >/dev/null || return 0

  while iptables -C INPUT -p tcp ! -i lo --dport "$LISTEN_PORT" -j DROP 2>/dev/null; do
    iptables -D INPUT -p tcp ! -i lo --dport "$LISTEN_PORT" -j DROP
  done
  while iptables -C INPUT -p tcp --dport "$LISTEN_PORT" -j DROP 2>/dev/null; do
    iptables -D INPUT -p tcp --dport "$LISTEN_PORT" -j DROP
  done
  iptables-save 2>/dev/null | grep -- "--dport ${LISTEN_PORT} -j ACCEPT" | sed 's/^-A /-D /' \
    | while read -r r; do
        # shellcheck disable=SC2086
        iptables $r 2>/dev/null || true
      done
  # The -i lo ACCEPT is left alone on purpose: it is correct to have, and
  # removing it could break unrelated local services.
  ok "iptables rules for tcp/${LISTEN_PORT} removed"
  command -v netfilter-persistent >/dev/null && netfilter-persistent save >/dev/null 2>&1 || true
}

# ============================================================================
# Arguments
# ============================================================================

usage() {
  cat <<USAGE
Usage: $(basename "$0") [OPTIONS]

  (no options)   Install and configure Alertmanager (interactive).
  --uninstall    Remove Alertmanager and its firewall rules.
  -h, --help     Show this text.
USAGE
}

ACTION="install"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --uninstall|--remove) ACTION="uninstall" ;;
    -h|--help)            usage; exit 0 ;;
    *) usage >&2; fail "unknown option: $1" ;;
  esac
  shift
done

# ============================================================================
# Uninstall
# ============================================================================

uninstall_all() {
  step "Uninstalling Alertmanager"
  [[ $EUID -eq 0 ]] || fail "must run as root (use sudo)"

  echo
  warn "This will stop and remove the service, binaries, firewall rules"
  warn "and ${SNIPPET_DIR}. You will be asked about config, data and the user."
  echo
  confirm "Proceed?" || { echo "  Aborted; nothing was changed."; exit 1; }

  step "Stopping the service"
  systemctl disable --now alertmanager >/dev/null 2>&1 || true
  # Stop the daemon before the unit file goes, or an orphan keeps port 9093
  # bound and userdel fails because a process still runs as that user.
  pkill -f "${AM_BIN_DIR}/alertmanager" 2>/dev/null || true
  sleep 2
  ok "service stopped"

  if [[ -f /etc/systemd/system/alertmanager.service ]]; then
    backup /etc/systemd/system/alertmanager.service
    rm -f /etc/systemd/system/alertmanager.service
    ok "unit file removed"
  fi
  systemctl daemon-reload
  systemctl reset-failed alertmanager >/dev/null 2>&1 || true

  step "Removing firewall rules"
  close_firewall

  step "Removing binaries and generated files"
  rm -f "${AM_BIN_DIR}/alertmanager" "${AM_BIN_DIR}/amtool"
  rm -f /etc/amtool/config.yml; rmdir /etc/amtool 2>/dev/null || true
  rm -rf "${SNIPPET_DIR:?}"
  ok "removed"

  step "Config, data and service user"
  if [[ -d "$AM_CONF_DIR" ]]; then
    confirm "Delete ${AM_CONF_DIR} (contains the SMTP password)?" \
      && { rm -rf "${AM_CONF_DIR:?}"; ok "deleted"; } || warn "kept ${AM_CONF_DIR}"
  fi
  if [[ -d "$AM_DATA_DIR" ]]; then
    confirm "Delete ${AM_DATA_DIR} (silences and state)?" \
      && { rm -rf "${AM_DATA_DIR:?}"; ok "deleted"; } || warn "kept ${AM_DATA_DIR}"
  fi
  if id alertmanager &>/dev/null; then
    if confirm "Remove the 'alertmanager' system user?"; then
      userdel alertmanager 2>/dev/null && ok "user removed" \
        || warn "userdel failed — check for leftover processes: pgrep -a alertmanager"
    fi
  fi

  cat <<EOF

${C_GRN}============================================================
 Alertmanager removed
============================================================${C_RST}

  Backups from this run: *.bak-${TS}

  Still to do ON THE MONITORING SERVER — remove the alerting: target
  pointing at this host from /etc/prometheus/prometheus.yml, then:
    promtool check config /etc/prometheus/prometheus.yml
    systemctl reload prometheus

  Otherwise Prometheus logs connection errors to a dead Alertmanager forever.

EOF
  exit 0
}

[[ "$ACTION" == "uninstall" ]] && uninstall_all

# ============================================================================
# Step 1 — Preflight
# ============================================================================

step "Step 1/10 — Preflight"

[[ $EUID -eq 0 ]] || fail "must run as root (use sudo)"
command -v systemctl >/dev/null || fail "systemd not found"

case "$(uname -m)" in
  x86_64)  AM_ARCH="amd64" ;;
  aarch64) AM_ARCH="arm64" ;;
  armv7l)  AM_ARCH="armv7" ;;
  *) fail "unsupported architecture: $(uname -m)" ;;
esac
ok "architecture: $AM_ARCH"

command -v apt-get >/dev/null || fail "this script targets Debian/Ubuntu (apt not found)"

# Alertmanager belongs next to Prometheus. If Prometheus is here, this is
# the wrong script — the co-located one binds loopback and needs no firewall.
if [[ -f /etc/prometheus/prometheus.yml ]]; then
  warn "Prometheus config found on THIS host — you are on the monitoring server."
  warn "This script is for the remote host. Alertmanager on the monitored box"
  warn "dies with it, so the outage email never sends."
  confirm "Continue anyway?" || exit 1
fi

# ============================================================================
# Step 2 — Topology
# ============================================================================

step "Step 2/10 — Topology"

DEFAULT_IP="$(guess_primary_ip || true)"

ask PROM_SERVER_IP    "Monitoring server IP (the only IP allowed to reach ${LISTEN_PORT})" \
                      ""             is_ipv4
ask AM_ADVERTISE_HOST "This host's IP as the monitoring server sees it" \
                      "${DEFAULT_IP}" is_addr

if [[ "$PROM_SERVER_IP" == "$AM_ADVERTISE_HOST" ]]; then
  warn "both addresses are the same — that means Prometheus and Alertmanager"
  warn "are on one box, and you want the co-located setup instead."
  confirm "Continue anyway?" || exit 1
fi

AM_EXTERNAL_URL="http://${AM_ADVERTISE_HOST}:${LISTEN_PORT}"
AM_TARGET="${AM_ADVERTISE_HOST}:${LISTEN_PORT}"
ok "Prometheus will be pointed at ${AM_TARGET}"

# ============================================================================
# Step 3 — Mail settings
# ============================================================================

step "Step 3/10 — Mail settings"

cat <<'NOTE'
  Gmail needs an App Password, not your account password:
    1. Enable 2FA:  https://myaccount.google.com/signinoptions/two-step-verification
    2. Create one:  https://myaccount.google.com/apppasswords
  It is 16 characters.

  Smarthosts:  smtp.gmail.com:587 (STARTTLS)  smtp.office365.com:587
NOTE
echo

ask MAIL_FROM "Sender address (smtp_from)"          ""                   is_email
ask ALERT_TO  "Send alerts to (comma-separated ok)" "$MAIL_FROM"         is_email_list
ask SMTP_HOST "SMTP smarthost (host:port)"          "smtp.gmail.com:587" is_host

SMTP_PORT="${SMTP_HOST##*:}"
SMTP_FQDN="${SMTP_HOST%:*}"

ask SMTP_USER "SMTP auth username" "$MAIL_FROM" is_email
if [[ "$SMTP_FQDN" == *gmail.com ]]; then
  ask_secret SMTP_PASS "SMTP password (hidden)" 16
else
  ask_secret SMTP_PASS "SMTP password (hidden)"
fi

# 465 is implicit TLS — Alertmanager dials TLS directly and require_tls must
# be false. 587 is STARTTLS, which is what require_tls: true means.
if [[ "$SMTP_PORT" == "465" ]]; then
  REQUIRE_TLS="false"
  warn "port 465 -> implicit TLS (smtp_require_tls: false)"
else
  REQUIRE_TLS="true"
fi

echo
printf '%s  Review:%s\n' "$C_BLD" "$C_RST"
printf '    From ................ %s\n' "$MAIL_FROM"
printf '    To .................. %s\n' "$ALERT_TO"
printf '    Smarthost ........... %s\n' "$SMTP_HOST"
printf '    Auth username ....... %s\n' "$SMTP_USER"
printf '    Password ............ %s (%d chars)\n' \
       "$(printf '%*s' ${#SMTP_PASS} '' | tr ' ' '*')" "${#SMTP_PASS}"
printf '    Require TLS ......... %s\n' "$REQUIRE_TLS"
printf '    Listen on ........... %s\n' "$LISTEN_ADDR"
printf '    Reachable at ........ %s\n' "$AM_EXTERNAL_URL"
printf '    Allowed source IP ... %s\n' "$PROM_SERVER_IP"
echo
confirm "Proceed with these settings?" || { echo "  Aborted; nothing was changed."; exit 1; }

# ============================================================================
# Step 4 — Packages and SMTP reachability
# ============================================================================

step "Step 4/10 — Base packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ca-certificates curl wget tar netcat-openbsd >/dev/null
update-ca-certificates >/dev/null 2>&1 || true
ok "packages installed"

# Mail leaves from HERE, not from the monitoring server. Most "configured
# fine but no emails" cases are this port being blocked.
step "Testing outbound SMTP to ${SMTP_HOST} from this host"
if timeout 8 nc -z "$SMTP_FQDN" "$SMTP_PORT" 2>/dev/null; then
  ok "${SMTP_HOST} reachable"
else
  warn "cannot reach ${SMTP_HOST} — many providers block outbound SMTP by default"
  warn "install will continue but no email will send until this is opened"
  confirm "Continue anyway?" || exit 1
fi

# ============================================================================
# Step 5 — Download and verify
# ============================================================================

step "Step 5/10 — Downloading Alertmanager v${AM_VERSION} (${AM_ARCH})"

TARBALL="alertmanager-${AM_VERSION}.linux-${AM_ARCH}.tar.gz"
BASE_URL="https://github.com/prometheus/alertmanager/releases/download/v${AM_VERSION}"

cd "$SRC_DIR"
curl -4 -fsSL -o "$TARBALL"       "${BASE_URL}/${TARBALL}"     || fail "download failed"
curl -4 -fsSL -o "sha256sums.txt" "${BASE_URL}/sha256sums.txt" || fail "checksum download failed"

grep "  ${TARBALL}\$" sha256sums.txt | sha256sum -c - >/dev/null 2>&1 \
  || fail "checksum mismatch — do NOT use this download"
ok "SHA256 verified"

EXTRACT="${SRC_DIR}/alertmanager-${AM_VERSION}.linux-${AM_ARCH}"
rm -rf "${EXTRACT:?}"
tar -xzf "$TARBALL"
[[ -x "${EXTRACT}/alertmanager" ]] || fail "binary missing after extract"
ok "extracted"

# ============================================================================
# Step 6 — User, directories, binaries
# ============================================================================

step "Step 6/10 — User, directories and binaries"

if id alertmanager &>/dev/null; then
  ok "user 'alertmanager' already exists"
else
  useradd --system --no-create-home --shell /usr/sbin/nologin alertmanager
  ok "created system user 'alertmanager'"
fi

mkdir -p "${AM_CONF_DIR}/templates" "$AM_DATA_DIR" "$SNIPPET_DIR"

systemctl is-active --quiet alertmanager && { systemctl stop alertmanager; warn "stopped for upgrade"; }

install -o root -g root -m 0755 "${EXTRACT}/alertmanager" "${AM_BIN_DIR}/alertmanager"
install -o root -g root -m 0755 "${EXTRACT}/amtool"       "${AM_BIN_DIR}/amtool"
ok "$("${AM_BIN_DIR}/alertmanager" --version 2>&1 | head -1)"

rm -rf "${EXTRACT:?}" "${SRC_DIR:?}/${TARBALL:?}" "${SRC_DIR:?}/sha256sums.txt"

mkdir -p /etc/amtool
echo "alertmanager.url: http://127.0.0.1:${LISTEN_PORT}" > /etc/amtool/config.yml
chmod 644 /etc/amtool/config.yml
ok "amtool defaults written (so 'amtool alert query' works with no flags)"

# ============================================================================
# Step 7 — Config and template
# ============================================================================

step "Step 7/10 — Writing config and email template"

backup "${AM_CONF_DIR}/alertmanager.yml"

# A literal ' inside a single-quoted YAML scalar must be doubled or the value
# silently truncates. Passwords are the usual victim.
esc() { printf '%s' "${1//\'/\'\'}"; }

cat > "${AM_CONF_DIR}/alertmanager.yml" <<EOF
global:
  smtp_smarthost: '$(esc "$SMTP_HOST")'
  smtp_from: '$(esc "$MAIL_FROM")'
  smtp_auth_username: '$(esc "$SMTP_USER")'
  smtp_auth_password: '$(esc "$SMTP_PASS")'
  smtp_require_tls: ${REQUIRE_TLS}

templates:
  - '${AM_CONF_DIR}/templates/email.tmpl'

route:
  # 'instance' is in the grouping key because the template prints it. A
  # CommonLabel only exists if every alert in the group shares it, so without
  # this a group spanning two hosts renders a blank Instance row.
  group_by:
    - alertname
    - service
    - server
    - instance

  group_wait: 10s
  group_interval: 30s
  repeat_interval: 4h

  receiver: gmail-alerts

receivers:

  - name: gmail-alerts

    email_configs:

      - to: '$(esc "$ALERT_TO")'
        send_resolved: true
        headers:
          Subject: '{{ template "email.subject" . }}'
        html: '{{ template "email.body" . }}'
EOF
ok "alertmanager.yml written"

backup "${AM_CONF_DIR}/templates/email.tmpl"

# Quoted heredoc — Go template syntax must pass through verbatim.
cat > "${AM_CONF_DIR}/templates/email.tmpl" <<'TMPL'
{{- /*
  The subject stays on ONE line on purpose. Go templates emit literal
  newlines, and a Subject header containing CR/LF is mangled or rejected.
*/ -}}
{{ define "email.subject" }}{{ if eq .Status "firing" }}[🚨] ALERT: {{ if .CommonLabels.service }}{{ .CommonLabels.service }}{{ else }}{{ .CommonLabels.alertname }}{{ end }} down on {{ .CommonLabels.server }}{{ else }}[✅] RESOLVED: {{ if .CommonLabels.service }}{{ .CommonLabels.service }}{{ else }}{{ .CommonLabels.alertname }}{{ end }} recovered on {{ .CommonLabels.server }}{{ end }}{{ end }}

{{ define "email.body" }}
{{- $a := index .Alerts 0 -}}
<html>
<body style="font-family: Arial, sans-serif; font-size: 14px; color: #333333;">

<p>Hello Team,</p>

{{ if eq .Status "firing" }}
<p>This is an automated notification. The following service is currently
<strong style="color: #d93025;">DOWN</strong> and is not responding normally.</p>
{{ else }}
<p>This is an automated notification. The following service has
<strong style="color: #188038;">RECOVERED</strong> and is running normally.</p>
{{ end }}

<h3>Service Details</h3>

<table cellpadding="8" cellspacing="0" border="1"
       style="border-collapse: collapse; border-color: #dddddd;">
<tr><td><strong>Service Name</strong></td><td>{{ .CommonLabels.service }}</td></tr>
<tr><td><strong>Server</strong></td><td>{{ .CommonLabels.server }}</td></tr>
<tr><td><strong>Instance</strong></td><td>{{ .CommonLabels.instance }}</td></tr>
<tr><td><strong>Status</strong></td>
<td>{{ if eq .Status "firing" }}<strong style="color: #d93025;">DOWN</strong>{{ else }}<strong style="color: #188038;">UP / RECOVERED</strong>{{ end }}</td></tr>
<tr><td><strong>{{ if eq .Status "firing" }}Down Since{{ else }}Recovered At{{ end }}</strong></td>
<td>{{ if eq .Status "firing" }}{{ $a.StartsAt.Format "2006-01-02 15:04:05 UTC" }}{{ else }}{{ $a.EndsAt.Format "2006-01-02 15:04:05 UTC" }}{{ end }}</td></tr>
<tr><td><strong>Previous Status</strong></td>
<td>{{ if eq .Status "firing" }}UP{{ else }}DOWN{{ end }}</td></tr>
<tr><td><strong>Severity</strong></td>
<td>{{ if eq .Status "firing" }}{{ .CommonLabels.severity }}{{ else }}Resolved{{ end }}</td></tr>
</table>

{{ if eq .Status "firing" }}
<p><strong style="color: #d93025;">Immediate attention is required</strong>
to check and restore the service.</p>
{{ else }}
<p>The service is operational again. No further action is required.</p>
{{ end }}

<p>Thanks &amp; Regards,<br><strong>Monitoring Team</strong></p>

</body>
</html>
{{ end }}
TMPL
ok "email.tmpl written"

chown -R alertmanager:alertmanager "$AM_CONF_DIR" "$AM_DATA_DIR"
chmod 700 "$AM_CONF_DIR"
chmod 600 "${AM_CONF_DIR}/alertmanager.yml"
chmod 644 "${AM_CONF_DIR}/templates/email.tmpl"
chmod 750 "$AM_DATA_DIR"
ok "alertmanager.yml is 0600 (it holds the SMTP password in cleartext)"

# ============================================================================
# Step 8 — systemd unit and firewall
# ============================================================================

step "Step 8/10 — systemd unit"

backup /etc/systemd/system/alertmanager.service

cat > /etc/systemd/system/alertmanager.service <<EOF
[Unit]
Description=Prometheus Alertmanager
Documentation=https://prometheus.io/docs/alerting/latest/alertmanager/
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=alertmanager
Group=alertmanager
Restart=on-failure
RestartSec=5s

ExecStart=${AM_BIN_DIR}/alertmanager \\
  --config.file=${AM_CONF_DIR}/alertmanager.yml \\
  --storage.path=${AM_DATA_DIR} \\
  --web.listen-address=${LISTEN_ADDR} \\
  --web.external-url=${AM_EXTERNAL_URL} \\
  --cluster.listen-address=

ExecReload=/bin/kill -HUP \$MAINPID

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ReadWritePaths=${AM_DATA_DIR}

[Install]
WantedBy=multi-user.target
EOF
ok "unit created (HA gossip disabled — a lone instance must not hunt for peers)"

step "Firewall — restricting tcp/${LISTEN_PORT} to ${PROM_SERVER_IP}"
open_firewall "$PROM_SERVER_IP"
warn "on a cloud VM also allow tcp/${LISTEN_PORT} from ${PROM_SERVER_IP} in the"
warn "provider's security group — the OS firewall is only half the path"

# ============================================================================
# Step 9 — Validate and start
# ============================================================================

step "Step 9/10 — Validating before starting"

"${AM_BIN_DIR}/amtool" check-config "${AM_CONF_DIR}/alertmanager.yml" \
  || fail "config validation failed — nothing was started; fix and re-run"
ok "config and templates parse cleanly"

systemctl daemon-reload
systemctl enable --now alertmanager >/dev/null 2>&1
sleep 3

systemctl is-active --quiet alertmanager || {
  journalctl -u alertmanager -n 30 --no-pager
  fail "alertmanager failed to start (logs above)"
}
ok "service active and enabled at boot"

# --max-time matters: a DROPped packet leaves curl in SYN retry for ~2
# minutes per attempt, which looks like the script hanging rather than failing.
for i in 1 2 3 4 5; do
  if curl -fsS --connect-timeout 3 --max-time 5 \
       "http://127.0.0.1:${LISTEN_PORT}/-/healthy" >/dev/null 2>&1; then
    ok "health endpoint responding"; break
  fi
  if [[ $i -eq 5 ]]; then
    warn "health endpoint not responding after 5 tries"
    warn "check: journalctl -u alertmanager -n 30 --no-pager"
    warn "and:   iptables -L INPUT -n -v --line-numbers"
  fi
  sleep 2
done

ss -ltn 2>/dev/null | grep -q ":${LISTEN_PORT}" \
  && ok "listening on $(ss -ltn | grep ":${LISTEN_PORT}" | awk '{print $4}' | head -1)"

# ============================================================================
# Step 10 — Snippet for the monitoring server
# ============================================================================

step "Step 10/10 — Generating the prometheus.yml snippet"

cat > "${SNIPPET_DIR}/alerting-block.yml" <<EOF
# Merge into /etc/prometheus/prometheus.yml on ${PROM_SERVER_IP}.
#
# If an 'alerting:' key already exists, add the target to it. Do NOT paste a
# second top-level 'alerting:' — duplicate keys make Prometheus refuse to load.
#
# One target only. Prometheus fans out to EVERY Alertmanager listed, and
# deduplication only happens between instances clustered via gossip. Two
# standalone instances means two emails for every alert.

alerting:
  alertmanagers:
    - static_configs:
        - targets:
            - '${AM_TARGET}'
EOF

cat > "${SNIPPET_DIR}/APPLY-ON-MONITORING-SERVER.txt" <<EOF
Run these ON ${PROM_SERVER_IP} (the Prometheus host), not here.

1. Check the link first. If this fails, fix the network before editing configs:

     curl -fsS http://${AM_TARGET}/-/healthy && echo REACHABLE

   Nothing back means the firewall on this host is allowing the wrong source
   IP. The rule permits ${PROM_SERVER_IP}; confirm that is the address the
   monitoring server actually egresses from:

     curl -s https://ifconfig.me

2. Back up, then merge the alerting: key from alerting-block.yml:

     cp -a /etc/prometheus/prometheus.yml /etc/prometheus/prometheus.yml.bak
     nano /etc/prometheus/prometheus.yml

3. Validate and reload:

     promtool check config /etc/prometheus/prometheus.yml
     systemctl reload prometheus || systemctl restart prometheus

4. Confirm Prometheus registered it — this should return 1:

     curl -s 'http://localhost:9090/api/v1/query?query=prometheus_notifications_alertmanagers_discovered'

   Also check http://${PROM_SERVER_IP}:9090/status under Alertmanagers.

5. Your rules must set 'service' and 'server' labels, or the email subject
   and two table rows render blank. The template reads:
     .CommonLabels.service, .CommonLabels.server, .CommonLabels.instance

     labels:
       severity: critical
       service: '{{ \$labels.job }}'
       server:  '{{ \$labels.instance }}'

6. End-to-end test — stop a watched service on a monitored host, wait for
   the rule's 'for:' duration plus ~25s, expect the email. Start it again
   for the RESOLVED message.

7. If an alert fires but no email arrives, ask Prometheus whether delivery
   failed — non-zero means a network problem, not a config problem:

     curl -s 'http://localhost:9090/api/v1/query?query=prometheus_notifications_errors_total'

Generated ${TS} by install-alertmanager.sh
EOF

chmod 700 "$SNIPPET_DIR"; chmod 600 "$SNIPPET_DIR"/*
ok "written to ${SNIPPET_DIR}"

# ============================================================================
# Optional test alert
# ============================================================================

step "Optional — synthetic test alert"

if confirm "Fire a test alert to verify email delivery?"; then
  # Each label quoted as a whole argument, or amtool's UTF-8 matcher parser
  # warns and falls back on any value containing a space.
  "${AM_BIN_DIR}/amtool" --alertmanager.url="http://127.0.0.1:${LISTEN_PORT}" alert add \
    TestAlert 'service="nginx"' "server=\"$(hostname -s)\"" \
    "instance=\"${AM_ADVERTISE_HOST}:9100\"" 'severity="critical"' \
    --annotation='summary="Synthetic test from install script"' \
    && ok "submitted — expect email within ~10s (group_wait)"

  echo
  echo "  Confirm it registered:  amtool alert query"
  echo "  Watch delivery:         journalctl -u alertmanager -f"
  echo
  echo "  Alertmanager logs notification FAILURES, not successes — silence in"
  echo "  the log plus an email in your inbox means it worked. Check spam; the"
  echo "  first message from a new App Password often lands there."
  echo
  echo "  This proves Alertmanager -> Gmail only. It does NOT test the link"
  echo "  from Prometheus; step 1 of the APPLY file covers that."
fi

# ============================================================================
# Summary
# ============================================================================

cat <<EOF

${C_GRN}============================================================
 Alertmanager v${AM_VERSION} installed
============================================================${C_RST}

  Config        ${AM_CONF_DIR}/alertmanager.yml        (mode 0600)
  Template      ${AM_CONF_DIR}/templates/email.tmpl
  Data          ${AM_DATA_DIR}
  Unit          /etc/systemd/system/alertmanager.service
  Snippet       ${SNIPPET_DIR}

  Smarthost     ${SMTP_HOST}  (require_tls: ${REQUIRE_TLS})
  From          ${MAIL_FROM}
  To            ${ALERT_TO}
  Listening     ${LISTEN_ADDR}
  Reachable at  ${AM_EXTERNAL_URL}
  Allowed from  ${PROM_SERVER_IP} only

${C_YEL}  NOT FINISHED.${C_RST} Prometheus is on another host and does not yet know
  this Alertmanager exists. Follow:

    ${SNIPPET_DIR}/APPLY-ON-MONITORING-SERVER.txt

  Commands here:
    systemctl status alertmanager --no-pager
    journalctl -u alertmanager -f
    amtool check-config ${AM_CONF_DIR}/alertmanager.yml
    amtool alert query
    amtool config routes show
    systemctl reload alertmanager        # after editing config or template

  Web UI — do not open port ${LISTEN_PORT} to the world. Tunnel instead:
    ssh -L ${LISTEN_PORT}:127.0.0.1:${LISTEN_PORT} root@${AM_ADVERTISE_HOST}
    then open http://localhost:${LISTEN_PORT}

  Rollback:
    *.bak-${TS} alongside each file
    sudo $(basename "$0") --uninstall

${C_YEL}  Single point of failure:${C_RST} if this host dies, Alertmanager dies with
  it and the outage email never sends. Mitigate by pointing a Watchdog alert
  (severity that routes to a webhook) at an external heartbeat monitor such
  as healthchecks.io, so a dead link is noticed rather than mistaken for calm.

${C_YEL}  Credentials:${C_RST} ${AM_CONF_DIR}/alertmanager.yml holds the SMTP password in
  cleartext. Exclude it from backups that leave this host, never commit it to
  git, and use a dedicated App Password you can revoke on its own.

EOF
