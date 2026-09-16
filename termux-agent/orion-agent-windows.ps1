# ============================================================
# Orion Cyber AI - Windows Agent (PowerShell)
# ============================================================
# This agent runs on Windows (PowerShell/CMD) and connects
# to the Orion backend to pick up and execute scan tasks.
#
# Installation:
#   1. Install tools you want to use:
#      - Nmap: https://nmap.org/download.html
#      - Git: https://git-scm.com/download/win (includes curl alternative)
#      - Python: https://python.org (for pip tools like httpx, sslyze)
#      - YARA: pip install yara-python (or download from https://github.com/VirusTotal/yara/releases)
#      - Nuclei: https://github.com/projectdiscovery/nuclei/releases
#      - Nikto: https://github.com/sullo/nikto
#      - Gitleaks: https://github.com/gitleaks/gitleaks/releases
#      - Trivy: https://github.com/aquasecurity/trivy/releases
#      - Semgrep: pip install semgrep
#   2. Add all tools to your PATH
#   3. Run: powershell -ExecutionPolicy Bypass -File orion-agent-windows.ps1
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File orion-agent-windows.ps1
#
# The agent will poll for tasks every 5 seconds and execute them.
# ============================================================

# === Configuration ===
$env:SUPABASE_URL = if ($env:ORION_SUPABASE_URL) { $env:ORION_SUPABASE_URL } else { "https://xkracpgcmaaorhidymcc.supabase.co" }
$env:SUPABASE_ANON_KEY = if ($env:ORION_ANON_KEY) { $env:ORION_ANON_KEY } else { "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InhrcmFjcGdjbWFhb3JoaWR5bWNjIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODg0NTYzMDMsImV4cCI6MjEwNDAzMjMwM30.QYWe6EjHahs68V1R1Q1DzXlWOZXLOjqo_O4yem0-FaY" }
$AgentId = if ($env:ORION_AGENT_ID) { $env:ORION_AGENT_ID } else { "$env:COMPUTERNAME-$(Get-Date -Format 'yyyyMMddHHmmss')" }
$PollInterval = if ($env:ORION_POLL_INTERVAL) { [int]$env:ORION_POLL_INTERVAL } else { 5 }

$ApiBase = "$($env:SUPABASE_URL)/functions/v1/orion-agent"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Orion Cyber AI - Windows Agent" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Agent ID: $AgentId"
Write-Host "Backend:  $($env:SUPABASE_URL)"
Write-Host ""

# === Check for required tools ===
function Check-Tools {
    $missing = @()
    try {
        $null = Get-Command curl -ErrorAction Stop
    } catch {
        $missing += "curl"
    }
    if ($missing.Count -gt 0) {
        Write-Host "ERROR: Missing required tools: $($missing -join ', ')" -ForegroundColor Red
        Write-Host "Install curl or use Windows 10+ which includes it."
        exit 1
    }
}

# === Run a scan tool ===
function Run-Tool {
    param($Tool, $Target, $Options)

    # Normalize target
    $hostname = $Target -replace '^https?://', '' -replace '/.*$',''
    $url = if ($Target -match '^http') { $Target } else { "https://$Target" }

    Write-Host "  -> Running $Tool against $Target..."

    $rawOutput = ""

    switch ($Tool) {
        'nmap' {
            if (Get-Command nmap -ErrorAction SilentlyContinue) {
                $rawOutput = & nmap -sT -p- --open -T4 $hostname 2>&1 | Out-String
            } else {
                $rawOutput = "nmap not installed. Download from https://nmap.org/download.html"
            }
        }
        'masscan' {
            if (Get-Command masscan -ErrorAction SilentlyContinue) {
                $rawOutput = & masscan $hostname -p1-65535 --rate=1000 2>&1 | Out-String
            } else {
                $rawOutput = "masscan not installed"
            }
        }
        'nuclei' {
            if (Get-Command nuclei -ErrorAction SilentlyContinue) {
                $rawOutput = & nuclei -u $url -silent 2>&1 | Out-String
            } else {
                $rawOutput = "nuclei not installed. Download from https://github.com/projectdiscovery/nuclei/releases"
            }
        }
        'nikto' {
            if (Get-Command nikto -ErrorAction SilentlyContinue) {
                $rawOutput = & nikto -h $url -Format txt 2>&1 | Out-String
            } else {
                $rawOutput = "nikto not installed. Download from https://github.com/sullo/nikto"
            }
        }
        'whatweb' {
            if (Get-Command whatweb -ErrorAction SilentlyContinue) {
                $rawOutput = & whatweb -a 3 $url 2>&1 | Out-String
            } else {
                $rawOutput = "whatweb not installed"
            }
        }
        'httpx' {
            if (Get-Command httpx -ErrorAction SilentlyContinue) {
                $rawOutput = & httpx -u $url -status-code -title -tech-detect 2>&1 | Out-String
            } else {
                $rawOutput = "httpx not installed"
            }
        }
        'dns' {
            try {
                $a = Resolve-DnsName -Name $hostname -Type A -ErrorAction SilentlyContinue
                $mx = Resolve-DnsName -Name $hostname -Type MX -ErrorAction SilentlyContinue
                $ns = Resolve-DnsName -Name $hostname -Type NS -ErrorAction SilentlyContinue
                $rawOutput = "A records:`n$($a | Format-Table | Out-String)`nMX records:`n$($mx | Format-Table | Out-String)`nNS records:`n$($ns | Format-Table | Out-String)"
            } catch {
                $rawOutput = "DNS lookup failed: $_"
            }
        }
        'sslyze' {
            if (Get-Command sslyze -ErrorAction SilentlyContinue) {
                $rawOutput = & sslyze --regular $hostname 2>&1 | Out-String
            } else {
                $rawOutput = "sslyze not installed. Install with: pip install sslyze"
            }
        }
        'zap' {
            if (Get-Command zap-cli -ErrorAction SilentlyContinue) {
                $rawOutput = & zap-cli quick-scan $url 2>&1 | Out-String
            } else {
                $rawOutput = "zap-cli not installed. Install OWASP ZAP from https://www.zaproxy.org/"
            }
        }
        'trivy' {
            if (Get-Command trivy -ErrorAction SilentlyContinue) {
                $rawOutput = & trivy repo $url 2>&1 | Out-String
            } else {
                $rawOutput = "trivy not installed. Download from https://github.com/aquasecurity/trivy/releases"
            }
        }
        'semgrep' {
            if (Get-Command semgrep -ErrorAction SilentlyContinue) {
                $rawOutput = & semgrep --config auto $url 2>&1 | Out-String
            } else {
                $rawOutput = "semgrep not installed. Install with: pip install semgrep"
            }
        }
        'gitleaks' {
            if (Get-Command gitleaks -ErrorAction SilentlyContinue) {
                $rawOutput = & gitleaks detect --source $url 2>&1 | Out-String
            } else {
                $rawOutput = "gitleaks not installed. Download from https://github.com/gitleaks/gitleaks/releases"
            }
        }
        'yara' {
            if (Get-Command yara -ErrorAction SilentlyContinue) {
                $scanPath = $Target
                $rulesFile = if ($env:ORION_YARA_RULES) { $env:ORION_YARA_RULES } else { "$env:USERPROFILE\orion-yara-rules.yar" }

                # Generate default rules if none exist
                if (-not (Test-Path $rulesFile)) {
                    $defaultRules = @"
rule Orion_Malware_Generic
{
  meta:
    author = "Orion Cyber AI"
    description = "Generic malware indicators"
  strings:
    `:s1 = "CreateProcess" nocase
    `:s2 = "WriteProcessMemory" nocase
    `:s3 = "VirtualAllocEx" nocase
    `:s4 = "LoadLibrary" nocase
    `:s5 = "GetProcAddress" nocase
    `:s6 = "WinExec" nocase
    `:s7 = "ShellExecute" nocase
    `:s8 = "URLDownloadToFile" nocase
    `:s9 = "InternetOpenUrl" nocase
    `:s10 = /https?:\/\/[a-zA-Z0-9.-]+\.[a-z]{2,}/ nocase
  condition:
    3 of (`:s*)
}

rule Orion_Suspicious_Strings
{
  meta:
    author = "Orion Cyber AI"
    description = "Suspicious strings often found in malware"
  strings:
    `:a = "cmd.exe /c" nocase
    `:b = "/bin/sh" nocase
    `:c = "powershell -enc" nocase
    `:d = "base64 -d" nocase
    `:e = "wget http" nocase
    `:f = "curl http" nocase
    `:g = "chmod +x" nocase
    `:h = "/tmp/" nocase
  condition:
    2 of (`:a, `:b, `:c, `:d, `:e, `:f, `:g, `:h)
}

rule Orion_C2_Indicators
{
  meta:
    author = "Orion Cyber AI"
    description = "Potential C2 communication indicators"
  strings:
    `:c2_1 = /https?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ nocase
    `:c2_2 = "User-Agent: Mozilla" nocase
    `:c2_3 = "POST /gate" nocase
    `:c2_4 = "POST /panel" nocase
    `:c2_5 = "bot_id=" nocase
  condition:
    2 of (`:c2_*)
}
"@
                    Set-Content -Path $rulesFile -Value $defaultRules
                    Write-Host "  -> Created default YARA rules at $rulesFile"
                }

                if (Test-Path $scanPath) {
                    $rawOutput = & yara -r -s $rulesFile $scanPath 2>&1 | Out-String
                    if ([string]::IsNullOrWhiteSpace($rawOutput)) {
                        $rawOutput = "No YARA rule matches found in $scanPath"
                    }
                } else {
                    $rawOutput = "Path not found: $scanPath. Provide a valid file or directory path on your computer."
                }
            } else {
                $rawOutput = "yara not installed. Download from https://github.com/VirusTotal/yara/releases"
            }
        }
        default {
            $rawOutput = "Unknown tool: $Tool"
        }
    }

    return $rawOutput
}

# === Submit result back to backend ===
function Submit-Result {
    param($TaskId, $Status, $RawOutput, $ErrorMsg)

    $payload = @{
        taskId = $TaskId
        agentId = $AgentId
        status = $Status
        rawOutput = $RawOutput
        error = $ErrorMsg
        output = @{ tool_output = $RawOutput }
    } | ConvertTo-Json -Depth 5

    try {
        Invoke-RestMethod -Uri "$ApiBase/result" `
            -Method Post `
            -ContentType "application/json" `
            -Headers @{ Authorization = "Bearer $($env:SUPABASE_ANON_KEY)" } `
            -Body $payload | Out-Null
    } catch {
        Write-Host "Failed to submit result: $_" -ForegroundColor Red
    }
}

# === Main loop ===
Check-Tools
Write-Host "Agent started. Polling for tasks every $PollInterval seconds..."
Write-Host "Press Ctrl+C to stop."
Write-Host ""

while ($true) {
    try {
        $response = Invoke-RestMethod -Uri "$ApiBase/poll?agent_id=$([uri]::EscapeDataString($AgentId))" `
            -Method Get `
            -Headers @{ Authorization = "Bearer $($env:SUPABASE_ANON_KEY)" }

        if ($response.task -and $response.task.id) {
            $taskId = $response.task.id
            $tool = if ($response.task.tool) { $response.task.tool } else { "unknown" }
            $target = if ($response.task.target) { $response.task.target } else { "unknown" }
            $options = if ($response.task.options) { $response.task.options } else { "{}" }

            Write-Host "==========================================" -ForegroundColor Yellow
            Write-Host "NEW TASK: $Tool -> $Target"
            Write-Host "Task ID:  $TaskId"
            Write-Host "Time:     $(Get-Date)"
            Write-Host "==========================================" -ForegroundColor Yellow

            $rawOutput = Run-Tool -Tool $tool -Target $target -Options $options
            $status = "completed"
            $errorMsg = ""

            if ($rawOutput -match "not installed") {
                $status = "failed"
                $errorMsg = "Required tool not available on agent"
            }

            Submit-Result -TaskId $taskId -Status $status -RawOutput $rawOutput -ErrorMsg $errorMsg

            Write-Host ""
            Write-Host "Task $taskId completed with status: $status"
            Write-Host "Output preview (first 10 lines):"
            $rawOutput -split "`n" | Select-Object -First 10 | ForEach-Object { Write-Host $_ }
            Write-Host "..."
            Write-Host ""
        }
    } catch {
        # Silently retry on next poll
    }

    Start-Sleep -Seconds $PollInterval
}
