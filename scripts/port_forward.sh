#!/usr/bin/env bash
# UniFi Network – Create Port Forward (NAT) Rule via API
# -----------------------------------------------------
# • Minimal dependencies: bash + curl only
# • UniFi OS (443) and legacy controller (8443) supported
# • Configuration lives at the top of the file
#
# Edit only the USER CONFIGURATION section.

set -euo pipefail

# ============================
# USER CONFIGURATION
# ============================

# UniFi controller
CONSOLE_HOST="x.x.x.x"      # IP or DNS of UniFi console
USE_UNIFI_OS="true"          # "true" = UniFi OS (443), "false" = legacy controller (8443)
SITE="default"               # UniFi site name

# Credentials (leave blank to be prompted)
USERNAME="username"
PASSWORD="password"

# Port forward rule
RULE_NAME="Name of Rule"

# Source restriction (internet side)
SOURCE_IP="any"              # "any", single IP, or CIDR (e.g. 203.0.113.0/24)

# WAN interface
# • "wan" / "wan2"  = specific WAN
# • "all"           = all WANs (matches GUI behaviour in your HAR)
WAN_INTERFACE="all"          # wan | wan2 | all
ALL_WAN_LIST=("wan" "wan2")  # used only when WAN_INTERFACE="all"

# Protocol
PROTOCOL="tcp"               # tcp | udp | tcp_udp

# Ports
WAN_PORT="xxxx"              # External/WAN port (or "start-end")
FORWARD_PORT="xxxx"          # Internal port (or "start-end")

# Internal destination
FORWARD_IP="x.x.x.x"

# Rule behaviour
ENABLE_RULE="true"
ENABLE_LOGGING="true"        # Enables UniFi rule logging (not syslog export)
DEBUG="true"                 # Prints auth and CSRF diagnostics

# TLS handling
SKIP_CERT_CHECK="true"       # Required for self-signed UniFi certs

# ============================
# DO NOT EDIT BELOW
# ============================

need_bin() { command -v "$1" >/dev/null 2>&1 || { echo "Missing dependency: $1" >&2; exit 1; }; }
need_bin curl

if [[ -z "${USERNAME}" ]]; then
  read -r -p "UniFi Username: " USERNAME
fi

if [[ -z "${PASSWORD}" ]]; then
  read -r -s -p "UniFi Password: " PASSWORD
  echo
fi

log_debug() { [[ "$DEBUG" == "true" ]] && echo "[debug] $*" >&2 || true; }

CURL_TLS=()
if [[ "$SKIP_CERT_CHECK" == "true" ]]; then
  CURL_TLS=(-k)
fi

if [[ "$USE_UNIFI_OS" == "true" ]]; then
  BASE_URL="https://${CONSOLE_HOST}"
  LOGIN_URL="${BASE_URL}/api/auth/login"
  PF_URL="${BASE_URL}/proxy/network/api/s/${SITE}/rest/portforward"
  SELF_URL="${BASE_URL}/proxy/network/api/self"
else
  BASE_URL="https://${CONSOLE_HOST}:8443"
  LOGIN_URL="${BASE_URL}/api/login"
  PF_URL="${BASE_URL}/api/s/${SITE}/rest/portforward"
  SELF_URL="${BASE_URL}/api/self"
fi

TMP_DIR="$(mktemp -d)"
COOKIE_JAR="${TMP_DIR}/cookies.txt"
HDR_FILE="${TMP_DIR}/headers.txt"
RESP_FILE="${TMP_DIR}/resp.json"

cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

# JSON escaping for string values (minimal but safe for quotes/backslashes/newlines)
json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/\\r}"
  s="${s//$'\t'/\\t}"
  printf '%s' "$s"
}

# Extract CSRF token from response headers or cookie jar
get_csrf_token() {
  local csrf=""
  csrf="$(awk -F': ' 'tolower($1)=="x-csrf-token"{print $2}' "$HDR_FILE" | tr -d '\r' | tail -n 1 || true)"
  if [[ -n "$csrf" ]]; then
    printf '%s' "$csrf"
    return 0
  fi

  # Netscape cookie jar format: domain  flag  path  secure  expiry  name  value
  csrf="$(awk 'tolower($6) ~ /csrf/ {print $7}' "$COOKIE_JAR" | tail -n 1 || true)"
  printf '%s' "$csrf"
}

# Authenticate (cookies stored in cookie jar)
u_esc="$(json_escape "$USERNAME")"
p_esc="$(json_escape "$PASSWORD")"
LOGIN_BODY="{\"username\":\"${u_esc}\",\"password\":\"${p_esc}\"}"

log_debug "Logging in: $LOGIN_URL"
curl "${CURL_TLS[@]}" -sS \
  -D "$HDR_FILE" \
  -c "$COOKIE_JAR" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -H "Origin: ${BASE_URL}" \
  -H "Referer: ${BASE_URL}/" \
  -X POST \
  --data "$LOGIN_BODY" \
  "$LOGIN_URL" >/dev/null

# Headers expected by UniFi Network app
CSRF_TOKEN="$(get_csrf_token)"
log_debug "CSRF token present: $([[ -n "$CSRF_TOKEN" ]] && echo true || echo false)"

# Sanity check – confirms Network app access
if [[ "$DEBUG" == "true" ]]; then
  log_debug "Self-check: $SELF_URL"
  curl "${CURL_TLS[@]}" -sS \
    -b "$COOKIE_JAR" \
    -H "Accept: application/json" \
    -H "Origin: ${BASE_URL}" \
    -H "Referer: ${BASE_URL}/" \
    ${CSRF_TOKEN:+-H "X-CSRF-Token: ${CSRF_TOKEN}"} \
    "$SELF_URL" >"$RESP_FILE" || true

  # Avoid jq: just print the response if you want to inspect it
  log_debug "Self-check response:"
  log_debug "$(cat "$RESP_FILE" 2>/dev/null || true)"
fi

# Build destination_ips (GUI-style for "all")
if [[ "$WAN_INTERFACE" == "all" ]]; then
  dest_ips=""
  for ifc in "${ALL_WAN_LIST[@]}"; do
    ifc_esc="$(json_escape "$ifc")"
    src_esc="$(json_escape "$SOURCE_IP")"
    entry="{\"interface\":\"${ifc_esc}\",\"destination_ip\":\"${src_esc}\"}"
    if [[ -z "$dest_ips" ]]; then
      dest_ips="$entry"
    else
      dest_ips="${dest_ips},${entry}"
    fi
  done
  DEST_BLOCK="\"destination_ips\":[${dest_ips}]"
else
  src_esc="$(json_escape "$SOURCE_IP")"
  DEST_BLOCK="\"destination_ip\":\"${src_esc}\",\"destination_ips\":[]"
fi

# Create port forward payload
# • When WAN_INTERFACE="all": send pfwd_interface="all" + destination_ips[] (matches your HAR)
# • When WAN_INTERFACE="wan"/"wan2": send destination_ip + empty destination_ips
name_esc="$(json_escape "$RULE_NAME")"
pfwd_esc="$(json_escape "$WAN_INTERFACE")"
dst_esc="$(json_escape "$WAN_PORT")"
fwd_esc="$(json_escape "$FORWARD_IP")"
fwdp_esc="$(json_escape "$FORWARD_PORT")"
proto_esc="$(json_escape "$PROTOCOL")"

PAYLOAD=$(
  cat <<EOF
{
  "enabled": ${ENABLE_RULE},
  "name": "${name_esc}",
  "pfwd_interface": "${pfwd_esc}",
  ${DEST_BLOCK},
  "dst_port": "${dst_esc}",
  "fwd": "${fwd_esc}",
  "fwd_port": "${fwdp_esc}",
  "proto": "${proto_esc}",
  "src_limiting_enabled": false,
  "log": ${ENABLE_LOGGING}
}
EOF
)

# Submit rule
log_debug "Creating port forward: $PF_URL"
HTTP_CODE="$(
  curl "${CURL_TLS[@]}" -sS \
    -o "$RESP_FILE" \
    -w "%{http_code}" \
    -b "$COOKIE_JAR" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    -H "Origin: ${BASE_URL}" \
    -H "Referer: ${BASE_URL}/" \
    ${CSRF_TOKEN:+-H "X-CSRF-Token: ${CSRF_TOKEN}"} \
    -X POST \
    --data "$PAYLOAD" \
    "$PF_URL"
)"

if [[ "$HTTP_CODE" != "200" ]]; then
  echo "Port forward creation failed (HTTP $HTTP_CODE)" >&2
  echo "Response:" >&2
  cat "$RESP_FILE" >&2
  exit 1
fi

# Output result
echo "Port forward created:"
cat "$RESP_FILE"
