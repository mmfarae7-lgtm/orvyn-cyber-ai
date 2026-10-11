# ============================================================
# Orion Cyber AI - Windows Agent (PowerShell)
# ============================================================
# This agent runs on Windows (PowerShell 5.1+) and connects to the
# Orion backend to pick up and execute real scan tasks.
#
# Capabilities (v1.1):
#   - Tool discovery driven by the server's tool registry (no hardcoded
#     tool list): detect/version commands and install recipes come from
#     GET /orion-agent/registry for the "windows" platform.
#   - Optional user login (ORION_USER_EMAIL / ORION_USER_PASSWORD) for
#     agent registration, heartbeats and capability-aware dispatch.
#   - Stable agent key persisted in %USERPROFILE%\.orion-agent-id
#     (or ORION_AGENT_ID).
#   - Heartbeats every ~60s, including while a tool is running.
#   - Progress posts while executing, and server-side cancellation:
#     a cancelled task is stopped and its result discarded.
#   - Install tasks (kind=install) execute ONLY the approved recipe
#     fetched from the registry for Windows, then re-discover and
#     re-register so the platform sees the new capability.
#
# Installation:
#   1. Install the tools you want (they are discovered automatically):
#        winget install --id Insecure.Nmap -e
#        winget install --id AquaSecurity.Trivy -e
#        winget install --id Gitleaks.Gitleaks -e
#        pip install semgrep sslyze
#        (nuclei/httpx via: go install github.com/projectdiscovery/...)
#   2. Run: powershell -ExecutionPolicy Bypass -File orion-agent-windows.ps1
#
# Environment variables:
#   ORION_SUPABASE_URL / ORION_ANON_KEY  (required, via orion-config.ps1)
#   ORION_USER_EMAIL / ORION_USER_PASSWORD (recommended - enables
#       registration, heartbeats and capability-aware dispatch)
#   ORION_AGENT_ID, ORION_POLL_INTERVAL, ORION_YARA_RULES,
#   ORION_TASK_TIMEOUT (default 1800s)
# ============================================================

$ErrorActionPreference = 'Stop'

# === Configuration ===
# Resolved by orion-env.ps1: env vars > ~/.orion-config.ps1 >
# ./orion-config.ps1. There is no hardcoded default project on purpose,
# so the agent can never silently poll a backend that is not yours.
$ConfigDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }

. (Join-Path $ConfigDir 'orion-env.ps1')
Import-OrionEnv -AgentDir $ConfigDir
Assert-OrionConfig

$AgentVersion = '1.1.0'
$PollInterval = if ($env:ORION_POLL_INTERVAL) { [int]$env:ORION_POLL_INTERVAL } else { 5 }
$TaskTimeout  = if ($env:ORION_TASK_TIMEOUT)  { [int]$env:ORION_TASK_TIMEOUT }  else { 1800 }
$ApiBase = "$($env:SUPABASE_URL)/functions/v1/orion-agent"

# --- Stable agent key ------------------------------------------------
function Resolve-AgentId {
    if ($env:ORION_AGENT_ID) { return $env:ORION_AGENT_ID }
    $idFile = Join-Path $env:USERPROFILE '.orion-agent-id'
    if (Test-Path $idFile) {
        $existing = (Get-Content $idFile -ErrorAction SilentlyContinue | Select-Object -First 1)
        if ($existing) { return $existing.Trim() }
    }
    $suffix = -join ((1..4) | ForEach-Object { '{0:x2}' -f (Get-Random -Minimum 0 -Maximum 256) })
    $generated = "$env:COMPUTERNAME-$suffix"
    try { Set-Content -Path $idFile -Value $generated } catch { }
    return $generated
}
$AgentId = Resolve-AgentId

# === State ===
$script:UserToken = $null
$script:Registry = @()
$script:Tools = @()
$script:LastHeartbeat = [DateTime]::MinValue

$Platform = 'windows'

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Orion Cyber AI - Windows Agent v$AgentVersion" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Agent ID: $AgentId"
Write-Host "Backend:  $($env:SUPABASE_URL)"
Write-Host "Poll:     every ${PollInterval}s"
Write-Host "Timeout:  ${TaskTimeout}s per tool run"
Write-Host ""

# === Check for required tools ===
function Check-Tools {
    # curl.exe ships with Windows 10+; PowerShell 5.1 is assumed present.
    if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) {
        Write-Host "WARNING: curl.exe not found. Install it or use Windows 10+ (which includes it)." -ForegroundColor Yellow
    }
}

# === HTTP helpers =====================================================
function Get-AuthToken {
    if ($script:UserToken) { return $script:UserToken }
    return $env:SUPABASE_ANON_KEY
}

function Test-JwtExpired {
    param([string]$Token)
    try {
        $parts = $Token.Split('.')
        if ($parts.Count -lt 2) { return $true }
        $payload = $parts[1].Replace('-', '+').Replace('_', '/')
        switch ($payload.Length % 4) {
            2 { $payload += '==' }
            3 { $payload += '=' }
        }
        $json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload)) | ConvertFrom-Json
        $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        return ($now -ge ([int64]$json.exp - 60))
    } catch {
        return $true
    }
}

function Connect-User {
    if (-not $env:ORION_USER_EMAIL -or -not $env:ORION_USER_PASSWORD) { return $false }
    try {
        $body = @{ email = $env:ORION_USER_EMAIL; password = $env:ORION_USER_PASSWORD } | ConvertTo-Json
        $resp = Invoke-RestMethod -Uri "$($env:SUPABASE_URL)/auth/v1/token?grant_type=password" `
            -Method Post -ContentType 'application/json' `
            -Headers @{ apikey = $env:SUPABASE_ANON_KEY } -Body $body -TimeoutSec 30
        if ($resp.access_token) {
            $script:UserToken = $resp.access_token
            return $true
        }
    } catch {
        Write-Host "WARNING: user login failed ($_) - running in legacy anon mode." -ForegroundColor Yellow
    }
    return $false
}

function Ensure-Token {
    if (-not $env:ORION_USER_EMAIL) { return $false }
    if ($script:UserToken) {
        if (Test-JwtExpired $script:UserToken) { [void](Connect-User) }
        return [bool]$script:UserToken
    }
    return (Connect-User)
}

function Invoke-ApiGet {
    param([string]$Path, [hashtable]$Query = @{})
    $uri = "$ApiBase/$Path"
    if ($Query.Count -gt 0) {
        $pairs = $Query.GetEnumerator() | ForEach-Object {
            "{0}={1}" -f [uri]::EscapeDataString([string]$_.Key), [uri]::EscapeDataString([string]$_.Value)
        }
        $uri = "$uri?" + ($pairs -join '&')
    }
    try {
        return Invoke-RestMethod -Uri $uri -Method Get -Headers @{ Authorization = "Bearer $(Get-AuthToken)" } -TimeoutSec 30
    } catch {
        return $null
    }
}

function Invoke-ApiPost {
    param([string]$Path, $Body)
    $json = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 10 }
    try {
        return Invoke-RestMethod -Uri "$ApiBase/$Path" -Method Post -ContentType 'application/json' `
            -Headers @{ Authorization = "Bearer $(Get-AuthToken)" } -Body $json -TimeoutSec 60
    } catch {
        return $null
    }
}

# === Tool registry + discovery =======================================
function Fetch-Registry {
    $resp = Invoke-ApiGet 'registry'
    if ($resp -and $resp.tools) {
        $script:Registry = @($resp.tools)
        return $true
    }
    Write-Host "WARNING: tool registry unreachable - discovery will be empty until it responds." -ForegroundColor Yellow
    $script:Registry = @()
    return $false
}

# Execute a registry "detect" snippet. The registry uses `exit 0/1`,
# which would terminate this session, so they are rewritten to returns.
function Test-Detect {
    param([string]$Detect)
    $script = $Detect -replace 'exit\s+0', 'return $true' -replace 'exit\s+1', 'return $false'
    if ($script -notmatch 'return\s+\$') {
        $script = "try { $script; return \$true } catch { return \$false }"
    }
    try {
        return [bool](& ([scriptblock]::Create($script)))
    } catch {
        return $false
    }
}

function Get-ToolPath {
    param([string]$Detect)
    $m = [regex]::Match($Detect, 'Get-Command\s+([A-Za-z0-9_\.\-]+)')
    if ($m.Success) {
        $cmd = Get-Command $m.Groups[1].Value -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($cmd -and $cmd.Source) { return $cmd.Source }
    }
    return ''
}

function Get-ToolDiscovery {
    $result = New-Object System.Collections.ArrayList
    foreach ($t in $script:Registry) {
        $installed = $false
        $detect = $t.detect.windows
        if ($detect) { $installed = Test-Detect $detect }

        $version = ''
        $path = ''
        if ($installed) {
            $path = Get-ToolPath $detect
            $vcmd = $t.version.windows
            if ($vcmd) {
                $out = ''
                try { $out = (& ([scriptblock]::Create($vcmd)) 2>&1 | Out-String) } catch { $out = '' }
                if ($t.version_regex) {
                    $m = [regex]::Match($out, $t.version_regex)
                    if ($m.Success -and $m.Groups.Count -gt 1 -and $m.Groups[1].Value) {
                        $version = $m.Groups[1].Value
                    }
                }
                if (-not $version) {
                    $first = ($out -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1)
                    if ($first) {
                        $trimmed = $first.Trim()
                        $version = $trimmed.Substring(0, [Math]::Min(80, $trimmed.Length))
                    }
                }
            }
        }

        [void]$result.Add([pscustomobject]@{
            name       = [string]$t.name
            installed  = [bool]$installed
            version    = [string]$version
            path       = [string]$path
            executable = [bool]$installed
        })
    }
    return @($result)
}

function Show-Discovery {
    param($Tools)
    $installedCount = @($Tools | Where-Object { $_.installed }).Count
    Write-Host "Tool discovery (from server registry, platform: $Platform):"
    Write-Host "-----------------------------------"
    foreach ($t in $Tools) {
        if ($t.installed) {
            Write-Host ("  [OK]   {0,-11} {1,-20} {2}" -f $t.name, $t.version, $t.path)
        } else {
            Write-Host ("  [MISS] {0,-11} (use the platform Install action)" -f $t.name)
        }
    }
    Write-Host "  -> $installedCount/$(@($Tools).Count) registry tools installed on this device"
    Write-Host ""
}

function Get-ToolVersion {
    param([string]$Tool)
    $entry = $script:Tools | Where-Object { $_.name -eq $Tool } | Select-Object -First 1
    if ($entry) { return $entry.version }
    return ''
}

function Get-ToolInstalled {
    param([string]$Tool)
    $entry = $script:Tools | Where-Object { $_.name -eq $Tool } | Select-Object -First 1
    if ($entry) { return [bool]$entry.installed }
    return $false
}

function Get-PackageManager {
    if (Get-Command winget -ErrorAction SilentlyContinue) { return 'winget' }
    if (Get-Command choco -ErrorAction SilentlyContinue) { return 'choco' }
    if (Get-Command scoop -ErrorAction SilentlyContinue) { return 'scoop' }
    return 'unknown'
}

# === Registration + heartbeats =======================================
function Register-Agent {
    if (-not $script:UserToken) { return $false }
    $caps = @($script:Tools | Where-Object { $_.installed } | ForEach-Object { $_.name })
    $body = @{
        agentKey      = $AgentId
        name          = $env:COMPUTERNAME
        platform      = $Platform
        os            = [System.Environment]::OSVersion.VersionString
        architecture  = $env:PROCESSOR_ARCHITECTURE
        agentVersion  = $AgentVersion
        packageManager = (Get-PackageManager)
        tools         = @($script:Tools)
        capabilities  = $caps
    }
    $resp = Invoke-ApiPost 'register' $body
    if ($resp -and $resp.agent) {
        Write-Host "Registered with platform (tools: $($caps.Count))." -ForegroundColor Green
        return $true
    }
    Write-Host "WARNING: registration failed." -ForegroundColor Yellow
    return $false
}

function Send-Heartbeat {
    param([string]$Status = 'online')
    if (-not $script:UserToken) { return }
    $now = Get-Date
    if (($now - $script:LastHeartbeat).TotalSeconds -lt 60) { return }
    [void](Invoke-ApiPost 'heartbeat' @{ agentKey = $AgentId; status = $Status })
    $script:LastHeartbeat = $now
}

function Send-Progress {
    param([string]$TaskId, [string]$State, [string]$Note = '')
    $body = @{
        taskId   = $TaskId
        agentId  = $AgentId
        progress = @{ state = $State; note = $Note; updated_at = (Get-Date).ToUniversalTime().ToString('o') }
    }
    [void](Invoke-ApiPost 'progress' $body)
}

function Test-TaskCancelled {
    param([string]$TaskId)
    $resp = Invoke-ApiGet 'status' @{ task_id = $TaskId }
    if ($resp -and $resp.task -and $resp.task.status -eq 'cancelled') { return $true }
    return $false
}

# === Run a scan tool ==================================================
function Run-Tool {
    param($Tool, $Target, $Options)

    # Normalize target
    $hostname = $Target -replace '^https?://', '' -replace '/.*$', ''
    $url = if ($Target -match '^http') { $Target } else { "https://$Target" }

    # Structured option: requested port scope (else full default sweep)
    $optPorts = ''
    try {
        $optObj = if ($Options -is [string]) { $Options | ConvertFrom-Json } else { $Options }
        if ($optObj -and $optObj.ports) { $optPorts = [string]$optObj.ports }
    } catch { $optPorts = '' }

    $rawOutput = ""

    switch ($Tool) {
        'nmap' {
            if (Get-Command nmap -ErrorAction SilentlyContinue) {
                if ($optPorts) {
                    $rawOutput = & nmap -sT -p $optPorts --open -T4 $hostname 2>&1 | Out-String
                } else {
                    $rawOutput = & nmap -sT -p- --open -T4 $hostname 2>&1 | Out-String
                }
            } else {
                $rawOutput = "nmap not installed. Install with the platform Install action or https://nmap.org/download.html"
            }
        }
        'masscan' {
            if (Get-Command masscan -ErrorAction SilentlyContinue) {
                if ($optPorts) {
                    $rawOutput = & masscan $hostname -p $optPorts --rate=1000 2>&1 | Out-String
                } else {
                    $rawOutput = & masscan $hostname -p1-65535 --rate=1000 2>&1 | Out-String
                }
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
                    $defaultRules = @'
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
'@
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

# === Submit result back to backend ===================================
function Submit-Result {
    param($TaskId, $Status, $RawOutput, $ErrorMsg = '', $ToolVersion = '', $Summary = '')

    if ($RawOutput -and $RawOutput.Length -gt 400000) {
        $RawOutput = $RawOutput.Substring(0, 400000)
    }

    $body = @{
        taskId      = $TaskId
        agentId     = $AgentId
        status      = $Status
        rawOutput   = [string]$RawOutput
        error       = [string]$ErrorMsg
        toolVersion = if ($ToolVersion) { [string]$ToolVersion } else { $null }
        output      = @{ tool_output = [string]$RawOutput; summary = [string]$Summary }
    }
    $resp = Invoke-ApiPost 'result' $body
    if ($resp -and $resp.cancelled) {
        Write-Host "  Server: result discarded (task was cancelled)." -ForegroundColor Yellow
    } elseif ($resp -and $resp.success) {
        Write-Host "  Result accepted by platform." -ForegroundColor Green
    } else {
        Write-Host "  Result submission was not confirmed." -ForegroundColor Yellow
    }
}

# === Install tasks (approved registry recipes only) ==================
function Invoke-InstallTask {
    param([string]$Tool, [string]$TaskId)

    $entry = $script:Registry | Where-Object { $_.name -eq $Tool } | Select-Object -First 1
    $recipe = $null
    if ($entry -and $entry.install -and $entry.install.windows) { $recipe = [string]$entry.install.windows }

    if (-not $recipe) {
        Write-Host "  No approved install recipe for '$Tool' on windows - refusing." -ForegroundColor Yellow
        Submit-Result -TaskId $TaskId -Status 'failed' `
            -RawOutput "No approved install recipe for $Tool on windows (registry lookup)." `
            -ErrorMsg 'no_approved_recipe'
        return
    }

    Write-Host "  -> Approved recipe (windows): $recipe"
    Send-Progress -TaskId $TaskId -State 'installing' -Note $recipe

    $out = ''
    try { $out = (& cmd.exe /c $recipe 2>&1 | Out-String) } catch { $out = "Install failed: $_" }

    # Re-discover + re-register so capabilities reflect reality
    [void](Fetch-Registry)
    $script:Tools = Get-ToolDiscovery
    if ($script:UserToken) { [void](Register-Agent); Send-Heartbeat 'online' }

    $ver = Get-ToolVersion $Tool
    $installedNow = Get-ToolInstalled $Tool
    $status = if ($installedNow) { 'completed' } else { 'failed' }
    $err = if ($installedNow) { '' } else { "Tool was not detected after running the install recipe" }
    $summary = "Installed $Tool on windows: installed=$installedNow version=$ver recipe=$recipe"

    Write-Host "  $summary"
    Submit-Result -TaskId $TaskId -Status $status -RawOutput "$summary`n$out" `
        -ErrorMsg $err -ToolVersion $ver -Summary $summary
}

# === Scan task execution (background job + heartbeat/progress/cancel) =
function Invoke-ScanTask {
    param($Task)

    $taskId = $Task.id
    $tool = if ($Task.tool) { [string]$Task.tool } else { 'unknown' }
    $target = if ($Task.target) { [string]$Task.target } else { '' }
    $options = if ($Task.options) { $Task.options } else { @{} }

    Write-Host "==========================================" -ForegroundColor Yellow
    Write-Host "NEW TASK: $tool -> $target"
    Write-Host "Task ID:  $taskId"
    Write-Host "Time:     $(Get-Date)"
    Write-Host "==========================================" -ForegroundColor Yellow

    Send-Progress -TaskId $taskId -State 'executing' -Note "starting $tool"

    $fnText = ${function:Run-Tool}.ToString()
    $job = Start-Job -ScriptBlock {
        param($fn, $t, $tgt, $opt)
        . ([scriptblock]::Create($fn))
        Run-Tool -Tool $t -Target $tgt -Options $opt
    } -ArgumentList $fnText, $tool, $target, $options

    $elapsed = 0
    $cancelled = $false
    $timedOut = $false
    while ($job.State -eq 'Running') {
        Start-Sleep -Seconds 10
        $elapsed += 10
        Send-Heartbeat 'busy'
        Send-Progress -TaskId $taskId -State 'executing' -Note "running for ${elapsed}s"

        if ($elapsed -ge $TaskTimeout) {
            $timedOut = $true
            Stop-Job $job -ErrorAction SilentlyContinue
            break
        }
        if (Test-TaskCancelled $taskId) {
            $cancelled = $true
            Stop-Job $job -ErrorAction SilentlyContinue
            break
        }
    }

    $rawOutput = ''
    try { $rawOutput = (Receive-Job -Job $job -ErrorAction SilentlyContinue | Out-String) } catch { $rawOutput = '' }
    Remove-Job -Job $job -Force -ErrorAction SilentlyContinue

    if ($cancelled) {
        Write-Host "  Task $taskId cancelled - output discarded." -ForegroundColor Yellow
        Send-Heartbeat 'online'
        return
    }

    $status = 'completed'
    $errorMsg = ''
    if ($timedOut) {
        $rawOutput += "`n[agent] TIMEOUT: process killed after ${TaskTimeout}s - output may be partial."
        $status = 'failed'
        $errorMsg = "Tool execution exceeded ${TaskTimeout}s and was killed"
    } elseif ($rawOutput -match 'not installed') {
        $status = 'failed'
        $errorMsg = 'Required tool not available on agent'
    }

    $ver = Get-ToolVersion $tool
    Submit-Result -TaskId $taskId -Status $status -RawOutput $rawOutput -ErrorMsg $errorMsg -ToolVersion $ver

    Write-Host ""
    Write-Host "Task $taskId completed with status: $status"
    Write-Host "Output preview (first 10 lines):"
    $rawOutput -split "`n" | Select-Object -First 10 | ForEach-Object { Write-Host $_ }
    Write-Host "..."
    Write-Host ""
    Send-Heartbeat 'online'
}

# === Startup ==========================================================
Check-Tools
[void](Fetch-Registry)
$script:Tools = Get-ToolDiscovery
Show-Discovery $script:Tools

if (Ensure-Token) {
    Write-Host "Logged in as: $($env:ORION_USER_EMAIL)" -ForegroundColor Green
    [void](Register-Agent)
} elseif ($env:ORION_USER_EMAIL) {
    Write-Host "Continuing in legacy anon mode (registration/heartbeats unavailable)." -ForegroundColor Yellow
} else {
    Write-Host "NOTE: no ORION_USER_EMAIL/ORION_USER_PASSWORD set - legacy anon mode." -ForegroundColor Yellow
    Write-Host "      Set them in orion-config.ps1 to enable registration, heartbeats"
    Write-Host "      and capability-aware (per-agent) task dispatch."
}
Write-Host ""

# === Main loop ========================================================
Write-Host "Agent started. Polling for tasks every $PollInterval seconds..."
Write-Host "Press Ctrl+C to stop."
Write-Host ""

while ($true) {
    try {
        [void](Ensure-Token)
        Send-Heartbeat 'online'

        $response = Invoke-ApiGet 'poll' @{ agent_key = $AgentId }

        if ($response -and $response.task -and $response.task.id) {
            $kind = if ($response.task.kind) { [string]$response.task.kind } else { 'scan' }
            if ($kind -eq 'install') {
                $installTool = [string]$response.task.tool
                $installId = [string]$response.task.id
                Write-Host "==========================================" -ForegroundColor Magenta
                Write-Host "INSTALL TASK: $installTool"
                Write-Host "Task ID:      $installId"
                Write-Host "Time:         $(Get-Date)"
                Write-Host "==========================================" -ForegroundColor Magenta
                if ($installTool -and $installId) {
                    Invoke-InstallTask -Tool $installTool -TaskId $installId
                }
                Write-Host ""
            } else {
                Invoke-ScanTask -Task $response.task
            }
        }
    } catch {
        # Retry on the next poll; transient failures are expected.
    }

    Start-Sleep -Seconds $PollInterval
}
