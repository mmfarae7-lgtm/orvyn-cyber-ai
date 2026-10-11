#!/usr/bin/env bash
#
# Orion Cyber AI - Universal Agent (Termux / Kali Linux / macOS / Linux)
# ====================================================================
# This agent runs on:
#   - Android (Termux)
#   - Kali Linux / Debian / Ubuntu
#   - macOS
#   - Any Linux distribution with bash
#
# It connects to the Orion backend, picks up scan tasks, runs real
# security tools (nmap, nuclei, nikto, yara, etc.), and sends results back.
#
# === Capabilities (v1.1) ===
#   - Tool discovery driven by the server's tool registry (no hardcoded
#     list): detect/version commands and install recipes are fetched
#     from GET /orion-agent/registry for this platform.
#   - Optional user login (ORION_USER_EMAIL / ORION_USER_PASSWORD) for
#     registration, heartbeats and capability-aware task dispatch.
#   - Stable agent key persisted in ~/.orion-agent-id (or ORION_AGENT_ID).
#   - Heartbeats every ~60s — including while a tool is running.
#   - Progress posts (GET /orion-agent/progress) while executing.
#   - Cancellation: long-running tasks are checked against
#     GET /orion-agent/status and killed when cancelled server-side.
#   - Install tasks (kind=install) execute ONLY the approved recipe
#     fetched from the registry for this platform, then re-discovers
#     and re-registers so the platform sees the new capability.
#
# === Installation ===
#
# --- Termux (Android) ---
#   pkg update && pkg install curl jq git
#   cp orion-config.sh.example orion-config.sh && $EDITOR orion-config.sh
#   chmod +x orion-agent.sh && ./orion-agent.sh
#   (missing scan tools are discovered and can be installed via the
#    platform's "Install" action — recipes come from the registry)
#
# --- Kali / Ubuntu / Debian / macOS ---
#   curl + jq required; everything else is discovered and optionally
#   installed through the platform's approved-recipe install tasks.
#
# === Usage ===
#   ./orion-agent.sh
#
# The agent polls for tasks every POLL_INTERVAL seconds and executes
# them. Press Ctrl+C to stop.
#
# === Environment Variables ===
#   ORION_SUPABASE_URL     - Override backend URL
#   ORION_ANON_KEY         - Override anon key
#   ORION_AGENT_ID         - Custom agent identifier (else ~/.orion-agent-id)
#   ORION_POLL_INTERVAL    - Poll interval in seconds (default: 5)
#   ORION_YARA_RULES       - Custom YARA rules file path
#   ORION_USER_EMAIL       - Platform user email (enables registration,
#   ORION_USER_PASSWORD    - Platform user password  heartbeats, scoped
#                            capability-aware dispatch — recommended)
#   ORION_TASK_TIMEOUT     - Max seconds per tool run (default: 1800)
# ====================================================================

set -euo pipefail

# === Configuration ===
# Resolved by orion-env.sh: env vars > ~/.orion-config.sh >
# ./orion-config.sh > ../.env. Refuses to start when unconfigured so it
# can never poll a backend that is not yours.
# shellcheck disable=SC1091
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/orion-env.sh"
orion_env_load
orion_require_config

AGENT_VERSION="1.1.0"
API_BASE="${SUPABASE_URL}/functions/v1/orion-agent"
TASK_TIMEOUT="${ORION_TASK_TIMEOUT:-1800}"

# --- Stable agent key -------------------------------------------------
# ORION_AGENT_ID (env/config) wins; otherwise reuse the key persisted in
# ~/.orion-agent-id so registration and capability records survive
# restarts (a hostname-timestamp key would orphan them every boot).
resolve_agent_id() {
  if [ -n "${AGENT_ID:-}" ]; then
    printf '%s' "$AGENT_ID"
    return
  fi
  local idfile="$HOME/.orion-agent-id"
  if [ -f "$idfile" ]; then
    local existing
    existing=$(cat "$idfile" 2>/dev/null || true)
    if [ -n "$existing" ]; then printf '%s' "$existing"; return; fi
  fi
  local generated
  generated="$(hostname 2>/dev/null || echo 'orion')-$(head -c 4 /dev/urandom 2>/dev/null | od -An -tx1 | tr -d ' \n' 2>/dev/null || echo "$(date +%s)")"
  printf '%s' "$generated" > "$idfile" 2>/dev/null || true
  printf '%s' "$generated"
}
AGENT_ID=$(resolve_agent_id)

# Detect platform
detect_platform() {
  if [ -d "/data/data/com.termux" ]; then
    echo "termux"
  elif [ -f "/etc/debian_version" ]; then
    echo "debian"
  elif [ -f "/etc/kali-rolling-version" ] || { [ -f "/etc/lsb-release" ] && grep -qi kali /etc/lsb-release 2>/dev/null; }; then
    echo "kali"
  elif [ "$(uname)" = "Darwin" ]; then
    echo "macos"
  else
    echo "linux"
  fi
}
PLATFORM=$(detect_platform)

detect_pkg_mgr() {
  case "$PLATFORM" in
    termux) echo "pkg" ;;
    kali|debian|linux) command -v apt-get >/dev/null 2>&1 && echo "apt" || echo "unknown" ;;
    macos) command -v brew >/dev/null 2>&1 && echo "brew" || echo "unknown" ;;
    *) echo "unknown" ;;
  esac
}
PKG_MGR=$(detect_pkg_mgr)

echo "============================================"
echo "  Orion Cyber AI - Universal Agent v${AGENT_VERSION}"
echo "============================================"
echo "Agent ID:   $AGENT_ID"
echo "Backend:    $SUPABASE_URL"
echo "Platform:   $PLATFORM ($PKG_MGR)"
echo "Poll:       every ${POLL_INTERVAL}s"
echo "Timeout:    ${TASK_TIMEOUT}s per tool run"
echo ""

# === State ============================================================
USER_TOKEN=""
TOOLS_JSON='[]'
REGISTRY_JSON='{"tools":[]}'
LAST_HEARTBEAT=0

# Check for required tools
check_tools() {
  local missing=()
  for tool in curl jq; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
  done
  if [ ${#missing[@]} -gt 0 ]; then
    echo "ERROR: Missing required tools: ${missing[*]}"
    echo ""
    echo "Install instructions:"
    case "$PLATFORM" in
      termux)
        echo "  pkg install curl jq"
        ;;
      kali|debian)
        echo "  sudo apt install curl jq"
        ;;
      macos)
        echo "  brew install curl jq"
        ;;
      *)
        echo "  Install curl and jq for your platform"
        ;;
    esac
    exit 1
  fi
}

# Get default YARA rules path based on platform
get_yara_rules_path() {
  if [ -n "${ORION_YARA_RULES:-}" ]; then
    echo "$ORION_YARA_RULES"
  elif [ "$PLATFORM" = "termux" ]; then
    echo "/data/data/com.termux/files/home/orion-yara-rules.yar"
  else
    echo "${HOME}/orion-yara-rules.yar"
  fi
}

# Get install hint for a tool — from the server registry only (the same
# approved recipes the platform's install tasks execute). Falls back to
# the registry URL when this platform has no recipe.
get_install_hint() {
  local tool="$1"
  local recipe url
  recipe=$(printf '%s' "$REGISTRY_JSON" | jq -r --arg t "$tool" --arg p "$PLATFORM" \
    '[.tools[] | select(.name==$t) | .install[$p]] | first // empty' 2>/dev/null || true)
  if [ -n "$recipe" ]; then
    echo "$recipe"
    return
  fi
  url=$(printf '%s' "$REGISTRY_JSON" | jq -r --arg t "$tool" \
    '[.tools[] | select(.name==$t) | .url] | first // empty' 2>/dev/null || true)
  if [ -n "$url" ]; then
    echo "see official page: $url (no approved recipe for $PLATFORM)"
  else
    echo "install $tool manually (see its official website)"
  fi
}

# === Backend communication ===========================================

auth_header() {
  if [ -n "$USER_TOKEN" ]; then
    printf '%s' "$USER_TOKEN"
  else
    printf '%s' "$SUPABASE_ANON_KEY"
  fi
}

api_get() {
  local u="$1"
  shift
  curl -s -m 25 -G "$u" -H "Authorization: Bearer $(auth_header)" "$@" 2>/dev/null || echo '{}'
}

api_post() {
  local u="$1"
  local payload="$2"
  curl -s -m 60 -X POST "$u" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $(auth_header)" \
    -d "$payload" 2>/dev/null || echo '{}'
}

# True when the JWT is within 60s of expiring (portable base64url decode).
jwt_expired() {
  local tok="$1" payload exp now
  payload=$(printf '%s' "$tok" | cut -d. -f2 2>/dev/null || true)
  payload=$(printf '%s' "$payload" | tr '_-' '/+')
  while [ $(( ${#payload} % 4 )) -ne 0 ]; do payload="${payload}="; done
  exp=$({ printf '%s' "$payload" | base64 -d 2>/dev/null || printf '%s' "$payload" | base64 -D 2>/dev/null; } \
    | jq -r '.exp // 0' 2>/dev/null || echo 0)
  case "$exp" in ''|*[!0-9]*) exp=0 ;; esac
  now=$(date +%s)
  [ "$now" -ge $((exp - 60)) ]
}

# Password-grant login (optional — only when user credentials are set).
login() {
  [ -n "${ORION_USER_EMAIL:-}" ] && [ -n "${ORION_USER_PASSWORD:-}" ] || return 1
  local resp tok
  resp=$(curl -s -m 25 -X POST "${SUPABASE_URL}/auth/v1/token?grant_type=password" \
    -H "apikey: ${SUPABASE_ANON_KEY}" \
    -H "Content-Type: application/json" \
    -d "$(jq -n --arg e "$ORION_USER_EMAIL" --arg p "$ORION_USER_PASSWORD" '{email:$e,password:$p}')" \
    2>/dev/null || echo '')
  tok=$(printf '%s' "$resp" | jq -r '.access_token // empty' 2>/dev/null || true)
  if [ -n "$tok" ]; then
    USER_TOKEN="$tok"
    return 0
  fi
  local reason
  reason=$(printf '%s' "$resp" | jq -r '.error_description // .msg // .error // "login failed"' 2>/dev/null || echo 'login failed')
  echo "WARNING: user login failed ($reason) — running in legacy anon mode (no registration/heartbeats)."
  return 1
}

ensure_token() {
  [ -n "${ORION_USER_EMAIL:-}" ] || return 1
  if [ -n "$USER_TOKEN" ]; then
    if jwt_expired "$USER_TOKEN"; then
      login || true
    fi
    [ -n "$USER_TOKEN" ] && return 0
  fi
  login
}

# === Tool registry + discovery =======================================

fetch_registry() {
  local resp
  resp=$(api_get "${API_BASE}/registry")
  if printf '%s' "$resp" | jq -e '.tools' >/dev/null 2>&1; then
    REGISTRY_JSON="$resp"
    return 0
  fi
  echo "WARNING: tool registry unreachable — discovery will be empty until it responds."
  REGISTRY_JSON='{"tools":[]}'
  return 1
}

# Discover every registry tool for this platform: run the registry's
# detect command (posix) for presence/path, then the version command and
# extract with the registry's version_regex. No hardcoded tool list.
discover_tools() {
  local items="" row name detect_cmd vcmd vregex installed path version vout first v obj
  while IFS= read -r row; do
    [ -z "$row" ] && continue
    name=$(jq -r '.name' <<<"$row" 2>/dev/null || echo "")
    [ -z "$name" ] && continue
    detect_cmd=$(jq -r '.detect.posix // empty' <<<"$row" 2>/dev/null || true)
    [ -z "$detect_cmd" ] && continue

    installed="false"; path=""; version=""
    if path=$(sh -c "$detect_cmd" 2>/dev/null); then
      installed="true"
      path=$(printf '%s' "$path" | head -1)
      vcmd=$(jq -r '.version.posix // empty' <<<"$row" 2>/dev/null || true)
      vregex=$(jq -r '.version_regex // empty' <<<"$row" 2>/dev/null || true)
      if [ -n "$vcmd" ]; then
        if command -v timeout >/dev/null 2>&1; then
          vout=$(timeout 20 sh -c "$vcmd" 2>&1 | head -3 || true)
        else
          vout=$(sh -c "$vcmd" 2>&1 | head -3 || true)
        fi
        if [ -n "$vregex" ]; then
          v=$(printf '%s' "$vout" | sed -nE "s|.*${vregex}.*|\1|p" 2>/dev/null | head -1 || true)
          [ -n "$v" ] && version="$v"
        fi
        if [ -z "$version" ]; then
          first=$(printf '%s' "$vout" | head -1 | cut -c1-80)
          case "$first" in
            *'not found'*|*'command not found'*) version="" ;;
            *) version="$first" ;;
          esac
        fi
      fi
    fi

    # Append as JSON object; retry once on transient jq write failures so
    # a single flaky invocation cannot silently drop a registry row.
    obj=$(jq -cn --arg name "$name" --argjson installed "$installed" \
      --arg version "$version" --arg path "$path" \
      '{name:$name, installed:$installed, version:$version, path:$path, executable:$installed}' 2>/dev/null) \
      || obj=$(jq -cn --arg name "$name" --argjson installed "$installed" \
      --arg version "$version" --arg path "$path" \
      '{name:$name, installed:$installed, version:$version, path:$path, executable:$installed}' 2>/dev/null) \
      || obj=""
    if [ -n "$obj" ]; then
      items="${items}${obj}"$'\n'
    else
      echo "WARNING: could not record discovery row for $name (jq failure)" >&2
    fi
  done <<< "$(printf '%s' "$REGISTRY_JSON" | jq -c '.tools[]?' 2>/dev/null || true)"

  TOOLS_JSON=$(printf '%s' "$items" | jq -sc '[.[] | select(type=="object")]' 2>/dev/null || echo '[]')

  # Completeness check: discovery must cover every registry row.
  local want got
  want=$(printf '%s' "$REGISTRY_JSON" | jq -r '.tools | length' 2>/dev/null || echo 0)
  got=$(printf '%s' "$TOOLS_JSON" | jq -r 'length' 2>/dev/null || echo 0)
  if [ "${got:-0}" -lt "${want:-0}" ] 2>/dev/null; then
    echo "WARNING: discovery covered ${got}/${want} registry tools — transient jq failure; tasks needing the missing tools will report honestly." >&2
  fi
}

tool_version_of() {
  printf '%s' "$TOOLS_JSON" | jq -r --arg t "$1" '[.[] | select(.name==$t) | .version] | first // empty' 2>/dev/null || true
}

tool_installed() {
  printf '%s' "$TOOLS_JSON" | jq -r --arg t "$1" '[.[] | select(.name==$t) | .installed] | first // false' 2>/dev/null || echo false
}

show_discovery() {
  local total=0 installed=0 name ver path
  echo "Tool discovery (from server registry, platform: $PLATFORM):"
  echo "-----------------------------------"
  while IFS= read -r row; do
    [ -z "$row" ] && continue
    total=$((total + 1))
    name=$(jq -r '.name' <<<"$row" 2>/dev/null || echo "?")
    if [ "$(jq -r '.installed' <<<"$row" 2>/dev/null || echo false)" = "true" ]; then
      installed=$((installed + 1))
      ver=$(jq -r '.version // "-"' <<<"$row" 2>/dev/null || echo "-")
      path=$(jq -r '.path // "-"' <<<"$row" 2>/dev/null || echo "-")
      printf '  [OK]   %-11s %-20s %s\n' "$name" "$ver" "$path"
    else
      printf '  [MISS] %-11s (no recipe executed — use the platform Install action)\n' "$name"
    fi
  done <<< "$(printf '%s' "$TOOLS_JSON" | jq -c '.[]' 2>/dev/null || true)"
  echo "  -> $installed/$total registry tools installed on this device"
  echo ""
}

# === Registration + heartbeats =======================================

register_agent() {
  [ -n "$USER_TOKEN" ] || return 1
  local caps payload
  caps=$(printf '%s' "$TOOLS_JSON" | jq -c '[.[] | select(.installed) | .name]')
  payload=$(jq -cn \
    --arg agentKey "$AGENT_ID" \
    --arg name "$(hostname 2>/dev/null || echo orion-agent)" \
    --arg platform "$PLATFORM" \
    --arg os "$(uname -srm 2>/dev/null || echo unknown)" \
    --arg architecture "$(uname -m 2>/dev/null || echo unknown)" \
    --arg agentVersion "$AGENT_VERSION" \
    --arg packageManager "$PKG_MGR" \
    --argjson tools "$TOOLS_JSON" \
    --argjson capabilities "$caps" \
    '{agentKey:$agentKey, name:$name, platform:$platform, os:$os,
      architecture:$architecture, agentVersion:$agentVersion,
      packageManager:$packageManager, tools:$tools, capabilities:$capabilities}')
  local resp
  resp=$(api_post "${API_BASE}/register" "$payload")
  if printf '%s' "$resp" | jq -e '.agent' >/dev/null 2>&1; then
    echo "Registered with platform (tools: $(printf '%s' "$caps" | jq -r 'length'))."
    return 0
  fi
  echo "WARNING: registration failed: $(printf '%s' "$resp" | jq -r '.error // .hint // "unknown"' 2>/dev/null || echo unknown)"
  return 1
}

maybe_heartbeat() {
  local status="${1:-online}"
  [ -n "$USER_TOKEN" ] || return 0
  local now
  now=$(date +%s)
  [ $((now - LAST_HEARTBEAT)) -lt 60 ] && return 0
  api_post "${API_BASE}/heartbeat" \
    "$(jq -cn --arg k "$AGENT_ID" --arg s "$status" '{agentKey:$k, status:$s}')" >/dev/null 2>&1 || true
  LAST_HEARTBEAT=$now
}

send_progress() {
  local task_id="$1" state="$2" note="${3:-}"
  api_post "${API_BASE}/progress" \
    "$(jq -cn --arg t "$task_id" --arg a "$AGENT_ID" --arg s "$state" --arg n "$note" \
      '{taskId:$t, agentId:$a, progress:{state:$s, note:$n, updated_at:(now|todate)}}')" \
    >/dev/null 2>&1 || true
}

task_cancelled() {
  local resp
  resp=$(api_get "${API_BASE}/status" --data-urlencode "task_id=$1")
  [ "$(printf '%s' "$resp" | jq -r '.task.status // empty' 2>/dev/null || true)" = "cancelled" ]
}

# === Task execution ===================================================

# Run a scan tool and capture output (stdout = raw output only;
# progress lines go to stderr so background capture stays clean)
run_tool() {
  local tool="$1"
  local target="$2"
  local options="$3"
  local raw_output=""

  # Normalize target
  local hostname="$target"
  hostname="${hostname#https://}"
  hostname="${hostname#http://}"
  hostname="${hostname%%/*}"

  local url="https://$target"
  if [[ "$target" == http* ]]; then
    url="$target"
  fi

  # Structured option: requested port scope (else full default sweep)
  local opt_ports=""
  opt_ports=$(printf '%s' "$options" | jq -r '.ports // empty' 2>/dev/null || true)

  echo "  -> Running $tool against $target..." >&2

  case "$tool" in
    nmap)
      if command -v nmap >/dev/null 2>&1; then
        if [ -n "$opt_ports" ]; then
          raw_output=$(nmap -sT -p "$opt_ports" --open -T4 "$hostname" 2>&1 || true)
        else
          raw_output=$(nmap -sT -p- --open -T4 "$hostname" 2>&1 || true)
        fi
      else
        raw_output="nmap not installed. Install with: $(get_install_hint nmap)"
      fi
      ;;
    masscan)
      if command -v masscan >/dev/null 2>&1; then
        if [ -n "$opt_ports" ]; then
          raw_output=$(masscan "$hostname" -p "$opt_ports" --rate=1000 2>&1 || true)
        else
          raw_output=$(masscan "$hostname" -p1-65535 --rate=1000 2>&1 || true)
        fi
      else
        raw_output="masscan not installed. Install with: $(get_install_hint masscan)"
      fi
      ;;
    nuclei)
      if command -v nuclei >/dev/null 2>&1; then
        raw_output=$(nuclei -u "$url" -silent 2>&1 || true)
      else
        raw_output="nuclei not installed. Install with: $(get_install_hint nuclei)"
      fi
      ;;
    nikto)
      if command -v nikto >/dev/null 2>&1; then
        raw_output=$(nikto -h "$url" -Format txt 2>&1 || true)
      else
        raw_output="nikto not installed. Install with: $(get_install_hint nikto)"
      fi
      ;;
    whatweb)
      if command -v whatweb >/dev/null 2>&1; then
        raw_output=$(whatweb -a 3 "$url" 2>&1 || true)
      else
        raw_output="whatweb not installed. Install with: $(get_install_hint whatweb)"
      fi
      ;;
    httpx)
      if command -v httpx >/dev/null 2>&1; then
        raw_output=$(httpx -u "$url" -status-code -title -tech-detect 2>&1 || true)
      else
        raw_output="httpx not installed. Install with: $(get_install_hint httpx)"
      fi
      ;;
    dns)
      if command -v dig >/dev/null 2>&1; then
        raw_output=$(dig +short "$hostname" A 2>&1 || true)
        raw_output+="$(printf '\n')"
        raw_output+=$(dig +short "$hostname" MX 2>&1 || true)
        raw_output+="$(printf '\n')"
        raw_output+=$(dig +short "$hostname" NS 2>&1 || true)
      elif command -v nslookup >/dev/null 2>&1; then
        raw_output=$(nslookup "$hostname" 2>&1 || true)
      else
        raw_output="Neither dig nor nslookup is installed"
      fi
      ;;
    sslyze)
      if command -v sslyze >/dev/null 2>&1; then
        raw_output=$(sslyze --regular "$hostname" 2>&1 || true)
      else
        raw_output="sslyze not installed. Install with: $(get_install_hint sslyze)"
      fi
      ;;
    zap)
      if command -v zap-cli >/dev/null 2>&1; then
        raw_output=$(zap-cli quick-scan "$url" 2>&1 || true)
      else
        raw_output="zap-cli not installed. Install with: $(get_install_hint zap)"
      fi
      ;;
    trivy)
      if command -v trivy >/dev/null 2>&1; then
        raw_output=$(trivy repo "$url" 2>&1 || true)
      else
        raw_output="trivy not installed. Install with: $(get_install_hint trivy)"
      fi
      ;;
    semgrep)
      if command -v semgrep >/dev/null 2>&1; then
        raw_output=$(semgrep --config auto "$url" 2>&1 || true)
      else
        raw_output="semgrep not installed. Install with: $(get_install_hint semgrep)"
      fi
      ;;
    gitleaks)
      if command -v gitleaks >/dev/null 2>&1; then
        raw_output=$(gitleaks detect --source "$url" 2>&1 || true)
      else
        raw_output="gitleaks not installed. Install with: $(get_install_hint gitleaks)"
      fi
      ;;
    yara)
      if command -v yara >/dev/null 2>&1; then
        local scan_path="$target"
        local rules_file
        rules_file=$(get_yara_rules_path)

        # Generate default rules if none exist
        if [ ! -f "$rules_file" ]; then
          cat > "$rules_file" << 'YARAEOF'
rule Orion_Malware_Generic
{
  meta:
    author = "Orion Cyber AI"
    description = "Generic malware indicators"
  strings:
    $s1 = "CreateProcess" nocase
    $s2 = "WriteProcessMemory" nocase
    $s3 = "VirtualAllocEx" nocase
    $s4 = "LoadLibrary" nocase
    $s5 = "GetProcAddress" nocase
    $s6 = "WinExec" nocase
    $s7 = "ShellExecute" nocase
    $s8 = "URLDownloadToFile" nocase
    $s9 = "InternetOpenUrl" nocase
    $s10 = /https?:\/\/[a-zA-Z0-9.-]+\.[a-z]{2,}/ nocase
  condition:
    3 of ($s*)
}

rule Orion_Suspicious_Strings
{
  meta:
    author = "Orion Cyber AI"
    description = "Suspicious strings often found in malware"
  strings:
    $a = "cmd.exe /c" nocase
    $b = "/bin/sh" nocase
    $c = "powershell -enc" nocase
    $d = "base64 -d" nocase
    $e = "wget http" nocase
    $f = "curl http" nocase
    $g = "chmod +x" nocase
    $h = "/tmp/" nocase
  condition:
    2 of ($a, $b, $c, $d, $e, $f, $g, $h)
}

rule Orion_Base64_Encoded
{
  meta:
    author = "Orion Cyber AI"
    description = "Detects potential base64 encoded payloads"
  strings:
    $b64 = /[A-Za-z0-9+\/]{40,}={0,2}/
  condition:
    #b64 > 3
}

rule Orion_C2_Indicators
{
  meta:
    author = "Orion Cyber AI"
    description = "Potential C2 communication indicators"
  strings:
    $c2_1 = /https?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ nocase
    $c2_2 = "User-Agent: Mozilla" nocase
    $c2_3 = "POST /gate" nocase
    $c2_4 = "POST /panel" nocase
    $c2_5 = "bot_id=" nocase
  condition:
    2 of ($c2_*)
}
YARAEOF
          echo "  -> Created default YARA rules at $rules_file" >&2
        fi

        if [ -e "$scan_path" ]; then
          raw_output=$(yara -r -s "$rules_file" "$scan_path" 2>&1 || true)
          if [ -z "$raw_output" ]; then
            raw_output="No YARA rule matches found in $scan_path"
          fi
        else
          raw_output="Path not found: $scan_path. Provide a valid file or directory path on your device."
        fi
      else
        raw_output="yara not installed. Install with: $(get_install_hint yara)"
      fi
      ;;
    *)
      raw_output="Unknown tool: $tool"
      ;;
  esac

  echo "$raw_output"
}

# Submit result back to backend (structured output for the merge layer)
submit_result() {
  local task_id="$1"
  local status="$2"
  local raw_output="$3"
  local error_msg="${4:-}"
  local tool_version="${5:-}"
  local summary="${6:-}"

  # keep the payload bounded (server also truncates at 400k)
  raw_output="${raw_output:0:400000}"

  local payload
  payload=$(jq -n \
    --arg taskId "$task_id" \
    --arg agentId "$AGENT_ID" \
    --arg status "$status" \
    --arg raw "$raw_output" \
    --arg err "$error_msg" \
    --arg toolVersion "$tool_version" \
    --arg summary "$summary" \
    '{taskId:$taskId, agentId:$agentId, status:$status,
      rawOutput:$raw, error:$err,
      toolVersion:(if $toolVersion=="" then null else $toolVersion end),
      output:{tool_output:$raw, summary:$summary}}')

  local resp
  resp=$(api_post "${API_BASE}/result" "$payload")
  if printf '%s' "$resp" | jq -e '.cancelled' >/dev/null 2>&1; then
    echo "  Server: result discarded (task was cancelled)."
  elif printf '%s' "$resp" | jq -e '.success' >/dev/null 2>&1; then
    echo "  Result accepted by platform."
  fi
}

# Install tasks execute ONLY the registry-approved recipe for this
# platform, then re-discover and re-register so the platform sees the
# new capability immediately.
handle_install() {
  local tool="$1"
  local task_id="$2"

  local recipe
  recipe=$(printf '%s' "$REGISTRY_JSON" | jq -r --arg t "$tool" --arg p "$PLATFORM" \
    '[.tools[] | select(.name==$t) | .install[$p]] | first // empty' 2>/dev/null || true)

  if [ -z "$recipe" ]; then
    echo "  No approved install recipe for '$tool' on '$PLATFORM' — refusing."
    submit_result "$task_id" "failed" \
      "No approved install recipe for $tool on $PLATFORM (registry lookup)." \
      "no_approved_recipe" "" ""
    return
  fi

  echo "  -> Approved recipe ($PLATFORM): $recipe"
  send_progress "$task_id" "installing" "$recipe"

  local out rc=0
  out=$(sh -c "$recipe" 2>&1) || rc=$?

  # Re-discover + re-register so capabilities reflect reality
  fetch_registry >/dev/null 2>&1 || true
  discover_tools
  if [ -n "$USER_TOKEN" ]; then
    register_agent || true
    maybe_heartbeat "online" || true
  fi

  local ver installed_now status="completed" err=""
  ver=$(tool_version_of "$tool")
  installed_now=$(tool_installed "$tool")
  if [ "$rc" -ne 0 ] || [ "$installed_now" != "true" ]; then
    status="failed"
    err="Install recipe exited with code $rc and tool was not detected afterwards"
  fi

  local summary
  summary="Installed $tool on $PLATFORM: installed=$installed_now version=${ver:-unknown} recipe=$recipe"
  echo "  $summary"
  submit_result "$task_id" "$status" "${summary}
${out}" "$err" "${ver:-}" "$summary"
}

# Execute a claimed scan task with heartbeat + progress + cancel checks
handle_scan_task() {
  local task="$1"
  local task_id tool target options
  task_id=$(jq -r '.id' <<<"$task")
  tool=$(jq -r '.tool // "unknown"' <<<"$task")
  target=$(jq -r '.target // ""' <<<"$task")
  options=$(jq -c '.options // {}' <<<"$task")

  echo "=========================================="
  echo "NEW TASK: $tool -> $target"
  echo "Task ID:  $task_id"
  echo "Options:  $options"
  echo "Time:     $(date)"
  echo "=========================================="

  local outfile
  outfile=$(mktemp 2>/dev/null || echo "/tmp/orion-task-${task_id}.out")

  send_progress "$task_id" "executing" "starting $tool"

  run_tool "$tool" "$target" "$options" >"$outfile" 2>/dev/null &
  local pid=$! elapsed=0 cancelled=0 timeout_hit=0

  while kill -0 "$pid" 2>/dev/null; do
    sleep 10
    elapsed=$((elapsed + 10))
    maybe_heartbeat "busy" || true
    send_progress "$task_id" "executing" "running for ${elapsed}s"

    if [ "$elapsed" -ge "$TASK_TIMEOUT" ]; then
      pkill -P "$pid" 2>/dev/null || true
      kill "$pid" 2>/dev/null || true
      timeout_hit=1
      break
    fi
    if task_cancelled "$task_id"; then
      pkill -P "$pid" 2>/dev/null || true
      kill "$pid" 2>/dev/null || true
      cancelled=1
      break
    fi
  done
  wait "$pid" 2>/dev/null || true

  if [ "$cancelled" -eq 1 ]; then
    echo "  Task $task_id cancelled — output discarded."
    rm -f "$outfile"
    maybe_heartbeat "online" || true
    return
  fi

  local raw_output status="completed" error_msg=""
  raw_output=$(head -c 400000 "$outfile" 2>/dev/null || true)
  rm -f "$outfile"

  if [ "$timeout_hit" -eq 1 ]; then
    raw_output="${raw_output}
[agent] TIMEOUT: process killed after ${TASK_TIMEOUT}s — output may be partial."
    status="failed"
    error_msg="Tool execution exceeded ${TASK_TIMEOUT}s and was killed"
  elif printf '%s' "$raw_output" | grep -qi "not installed"; then
    status="failed"
    error_msg="Required tool not available on agent"
  fi

  local ver
  ver=$(tool_version_of "$tool")
  submit_result "$task_id" "$status" "$raw_output" "$error_msg" "${ver:-}" ""

  echo ""
  echo "Task $task_id completed with status: $status"
  echo "Output preview (first 10 lines):"
  printf '%s\n' "$raw_output" | head -10
  echo "..."
  echo ""
  maybe_heartbeat "online" || true
}

# === Startup ==========================================================
check_tools
fetch_registry || true
discover_tools
show_discovery

if ensure_token; then
  echo "Logged in as: ${ORION_USER_EMAIL}"
  register_agent || true
else
  if [ -n "${ORION_USER_EMAIL:-}" ]; then
    echo "Continuing in legacy anon mode (registration/heartbeats unavailable)."
  else
    echo "NOTE: no ORION_USER_EMAIL/ORION_USER_PASSWORD set — legacy anon mode."
    echo "      Set them in orion-config.sh to enable registration, heartbeats"
    echo "      and capability-aware (per-agent) task dispatch."
  fi
fi
echo ""

# === Main loop ========================================================
echo "Agent started. Polling for tasks every ${POLL_INTERVAL}s..."
echo "Press Ctrl+C to stop."
echo ""

while true; do
  ensure_token || true
  maybe_heartbeat "online" || true

  # Poll for a task (user token when available → capability-aware
  # dispatch; anon key → legacy global queue, install tasks excluded)
  response=$(api_get "${API_BASE}/poll" --data-urlencode "agent_key=${AGENT_ID}")
  task=$(printf '%s' "$response" | jq -r '.task // empty' 2>/dev/null || true)

  if [ -n "$task" ] && [ "$task" != "null" ]; then
    kind=$(jq -r '.kind // "scan"' <<<"$task" 2>/dev/null || echo "scan")
    if [ "$kind" = "install" ]; then
      install_tool=$(jq -r '.tool // empty' <<<"$task" 2>/dev/null || echo "")
      install_id=$(jq -r '.id' <<<"$task" 2>/dev/null || echo "")
      echo "=========================================="
      echo "INSTALL TASK: $install_tool"
      echo "Task ID:      $install_id"
      echo "Time:         $(date)"
      echo "=========================================="
      if [ -n "$install_tool" ] && [ -n "$install_id" ]; then
        handle_install "$install_tool" "$install_id"
      fi
      echo ""
    else
      handle_scan_task "$task"
    fi
  fi

  sleep "$POLL_INTERVAL"
done
