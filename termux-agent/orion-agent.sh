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
# === Installation ===
#
# --- Termux (Android) ---
#   pkg update && pkg install nmap nikto whatweb curl jq yara git
#   pip install httpx sslyze
#   chmod +x orion-agent.sh
#   ./orion-agent.sh
#
# --- Kali Linux ---
#   sudo apt update && sudo apt install nmap nikto whatweb curl jq yara git
#   pip install httpx sslyze semgrep
#   sudo apt install masscan zaproxy trivy gitleaks
#   chmod +x orion-agent.sh
#   ./orion-agent.sh
#
# --- Ubuntu / Debian ---
#   sudo apt update && sudo apt install nmap nikto whatweb curl jq git
#   sudo apt install yara  # may need: sudo apt install yara-python
#   pip install httpx sslyze semgrep
#   chmod +x orion-agent.sh
#   ./orion-agent.sh
#
# --- macOS (with Homebrew) ---
#   brew install nmap nikto whatweb curl jq yara git
#   pip3 install httpx sslyze semgrep
#   chmod +x orion-agent.sh
#   ./orion-agent.sh
#
# === Optional Tools ===
#   Nuclei:  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
#   Masscan: sudo apt install masscan (Kali) / brew install masscan (macOS)
#   Gitleaks: go install github.com/gitleaks/gitleaks/v8@latest
#   Trivy:   https://github.com/aquasecurity/trivy/releases
#
# === Usage ===
#   ./orion-agent.sh
#
# The agent will poll for tasks every 5 seconds and execute them.
# Press Ctrl+C to stop.
#
# === Environment Variables ===
#   ORION_SUPABASE_URL   - Override backend URL
#   ORION_ANON_KEY        - Override anon key
#   ORION_AGENT_ID        - Custom agent identifier
#   ORION_POLL_INTERVAL   - Poll interval in seconds (default: 5)
#   ORION_YARA_RULES      - Custom YARA rules file path
# ====================================================================

set -euo pipefail

# === Configuration ===
SUPABASE_URL="${ORION_SUPABASE_URL:-https://xkracpgcmaaorhidymcc.supabase.co}"
SUPABASE_ANON_KEY="${ORION_ANON_KEY:-eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InhrcmFjcGdjbWFhb3JoaWR5bWNjIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODg0NTYzMDMsImV4cCI6MjEwNDAzMjMwM30.QYWe6EjHahs68V1R1Q1DzXlWOZXLOjqo_O4yem0-FaY}"
AGENT_ID="${ORION_AGENT_ID:-$(hostname 2>/dev/null || echo 'android')-$(date +%s)}"
POLL_INTERVAL="${ORION_POLL_INTERVAL:-5}"

API_BASE="${SUPABASE_URL}/functions/v1/orion-agent"

# Detect platform
detect_platform() {
  if [ -d "/data/data/com.termux" ]; then
    echo "termux"
  elif [ -f "/etc/debian_version" ]; then
    echo "debian"
  elif [ -f "/etc/kali-rolling-version" ] || [ -f "/etc/lsb-release" ]; then
    echo "kali"
  elif [ "$(uname)" = "Darwin" ]; then
    echo "macos"
  else
    echo "linux"
  fi
}

PLATFORM=$(detect_platform)

echo "============================================"
echo "  Orion Cyber AI - Universal Agent"
echo "============================================"
echo "Agent ID:   $AGENT_ID"
echo "Backend:    $SUPABASE_URL"
echo "Platform:   $PLATFORM"
echo "Poll:       every ${POLL_INTERVAL}s"
echo ""

# Check for required tools
check_tools() {
  local missing=()
  for tool in curl; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
  done
  if [ ${#missing[@]} -gt 0 ]; then
    echo "ERROR: Missing required tools: ${missing[*]}"
    echo ""
    echo "Install instructions:"
    case "$PLATFORM" in
      termux)
        echo "  pkg install curl"
        ;;
      kali|debian)
        echo "  sudo apt install curl"
        ;;
      macos)
        echo "  brew install curl"
        ;;
      *)
        echo "  Install curl for your platform"
        ;;
    esac
    exit 1
  fi

  # Check for jq (needed for JSON parsing)
  if ! command -v jq >/dev/null 2>&1; then
    echo "WARNING: jq not found. Installing..."
    case "$PLATFORM" in
      termux)
        pkg install -y jq 2>/dev/null || true
        ;;
      kali|debian)
        sudo apt install -y jq 2>/dev/null || true
        ;;
      macos)
        brew install jq 2>/dev/null || true
        ;;
    esac
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

# Get install hint for a tool based on platform
get_install_hint() {
  local tool="$1"
  case "$PLATFORM" in
    termux)
      case "$tool" in
        nmap) echo "pkg install nmap" ;;
        nikto) echo "pkg install nikto" ;;
        whatweb) echo "pkg install whatweb" ;;
        yara) echo "pkg install yara" ;;
        masscan) echo "pkg install masscan" ;;
        nuclei) echo "nuclei install or: pip install nuclei" ;;
        httpx) echo "pip install httpx" ;;
        sslyze) echo "pip install sslyze" ;;
        semgrep) echo "pip install semgrep" ;;
        gitleaks) echo "Download from https://github.com/gitleaks/gitleaks/releases" ;;
        trivy) echo "Download from https://github.com/aquasecurity/trivy/releases" ;;
        zap) echo "pkg install zaproxy" ;;
        *) echo "Install $tool for Termux" ;;
      esac
      ;;
    kali|debian)
      case "$tool" in
        nmap) echo "sudo apt install nmap" ;;
        nikto) echo "sudo apt install nikto" ;;
        whatweb) echo "sudo apt install whatweb" ;;
        yara) echo "sudo apt install yara" ;;
        masscan) echo "sudo apt install masscan" ;;
        nuclei) echo "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" ;;
        httpx) echo "pip install httpx" ;;
        sslyze) echo "pip install sslyze" ;;
        semgrep) echo "pip install semgrep" ;;
        gitleaks) echo "sudo apt install gitleaks" ;;
        trivy) echo "sudo apt install trivy" ;;
        zap) echo "sudo apt install zaproxy" ;;
        *) echo "sudo apt install $tool" ;;
      esac
      ;;
    macos)
      case "$tool" in
        nmap) echo "brew install nmap" ;;
        nikto) echo "brew install nikto" ;;
        whatweb) echo "brew install whatweb" ;;
        yara) echo "brew install yara" ;;
        masscan) echo "brew install masscan" ;;
        nuclei) echo "brew install nuclei" ;;
        httpx) echo "pip3 install httpx" ;;
        sslyze) echo "pip3 install sslyze" ;;
        semgrep) echo "pip3 install semgrep" ;;
        gitleaks) echo "brew install gitleaks" ;;
        trivy) echo "brew install trivy" ;;
        zap) echo "brew install zaproxy" ;;
        *) echo "brew install $tool" ;;
      esac
      ;;
    *)
      echo "Install $tool for your platform"
      ;;
  esac
}

# Run a scan tool and capture output
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

  echo "  -> Running $tool against $target..."

  case "$tool" in
    nmap)
      if command -v nmap >/dev/null 2>&1; then
        raw_output=$(nmap -sT -p- --open -T4 "$hostname" 2>&1 || true)
      else
        raw_output="nmap not installed. Install with: $(get_install_hint nmap)"
      fi
      ;;
    masscan)
      if command -v masscan >/dev/null 2>&1; then
        raw_output=$(masscan "$hostname" -p1-65535 --rate=1000 2>&1 || true)
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
          echo "  -> Created default YARA rules at $rules_file"
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

# Submit result back to backend
submit_result() {
  local task_id="$1"
  local status="$2"
  local raw_output="$3"
  local error_msg="$4"

  local payload
  payload=$(cat <<EOF
{
  "taskId": "$task_id",
  "agentId": "$AGENT_ID",
  "status": "$status",
  "rawOutput": $(echo "$raw_output" | jq -Rs . 2>/dev/null || echo '""'),
  "error": $(echo "$error_msg" | jq -Rs . 2>/dev/null || echo '""'),
  "output": {"tool_output": $(echo "$raw_output" | jq -Rs . 2>/dev/null || echo '""')}
}
EOF
)

  curl -s -X POST \
    "${API_BASE}/result" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${SUPABASE_ANON_KEY}" \
    -d "$payload" >/dev/null 2>&1
}

# Show available tools
show_available_tools() {
  echo "Available tools on this device:"
  echo "-----------------------------------"
  for tool in nmap masscan nuclei nikto whatweb httpx dig dns sslyze zap-cli trivy semgrep gitleaks yara; do
    if command -v "$tool" >/dev/null 2>&1; then
      echo "  [OK]   $tool"
    else
      echo "  [MISS] $tool"
    fi
  done
  echo ""
}

# Main loop
check_tools
show_available_tools
echo "Agent started. Polling for tasks every ${POLL_INTERVAL}s..."
echo "Press Ctrl+C to stop."
echo ""

while true; do
  # Poll for a task
  response=$(curl -s -G \
    "${API_BASE}/poll" \
    -H "Authorization: Bearer ${SUPABASE_ANON_KEY}" \
    --data-urlencode "agent_id=${AGENT_ID}" 2>/dev/null || echo '{"task":null}')

  task_id=$(echo "$response" | jq -r '.task.id // empty' 2>/dev/null || echo "")

  if [ -n "$task_id" ]; then
    tool=$(echo "$response" | jq -r '.task.tool // "unknown"')
    target=$(echo "$response" | jq -r '.task.target // "unknown"')
    options=$(echo "$response" | jq -r '.task.options // "{}"')

    echo "=========================================="
    echo "NEW TASK: $tool -> $target"
    echo "Task ID:  $task_id"
    echo "Time:     $(date)"
    echo "=========================================="

    raw_output=$(run_tool "$tool" "$target" "$options")
    status="completed"
    error_msg=""

    if echo "$raw_output" | grep -qi "not installed"; then
      status="failed"
      error_msg="Required tool not available on agent"
    fi

    submit_result "$task_id" "$status" "$raw_output" "$error_msg"

    echo ""
    echo "Task $task_id completed with status: $status"
    echo "Output preview (first 10 lines):"
    echo "$raw_output" | head -10
    echo "..."
    echo ""
  fi

  sleep "$POLL_INTERVAL"
done
