# ====================================================================
# Orion Cyber AI - Agent environment loader (Windows PowerShell)
# ====================================================================
# Resolves the Supabase backend the agent should poll, in this order
# (highest priority first):
#
#   1. Environment variables: ORION_SUPABASE_URL, ORION_ANON_KEY
#   2. $HOME\..\orion-config.ps1
#   3. <agent dir>\orion-config.ps1  (from orion-config.ps1.example)
#
# There is deliberately NO hardcoded default project. If nothing is
# configured the agent refuses to start.
# ====================================================================

function Import-OrionEnv {
    param([string]$AgentDir)

    # Capture environment-provided values BEFORE any file is dot-sourced,
    # so an explicit setting always wins over a config file.
    $captured = @{
        Url   = $env:ORION_SUPABASE_URL
        Anon  = $env:ORION_ANON_KEY
        Agent = $env:ORION_AGENT_ID
        Poll  = $env:ORION_POLL_INTERVAL
    }

    $configFiles = @()
    if ($HOME) { $configFiles += (Join-Path $HOME '.orion-config.ps1') }
    if ($AgentDir) { $configFiles += (Join-Path $AgentDir 'orion-config.ps1') }

    foreach ($cfg in $configFiles) {
        if (Test-Path $cfg) { . $cfg }
    }

    $env:SUPABASE_URL       = if ($captured.Url)   { $captured.Url }   elseif ($env:ORION_SUPABASE_URL) { $env:ORION_SUPABASE_URL } else { $null }
    $env:SUPABASE_ANON_KEY  = if ($captured.Anon)  { $captured.Anon }  elseif ($env:ORION_ANON_KEY)     { $env:ORION_ANON_KEY }     else { $null }
    $env:ORION_AGENT_ID     = if ($captured.Agent) { $captured.Agent } elseif ($env:ORION_AGENT_ID)     { $env:ORION_AGENT_ID }     else { $null }
    $env:ORION_POLL_INTERVAL = if ($captured.Poll) { $captured.Poll } elseif ($env:ORION_POLL_INTERVAL) { $env:ORION_POLL_INTERVAL } else { $null }
}

function Assert-OrionConfig {
    $missing = @()
    if (-not $env:SUPABASE_URL)      { $missing += 'ORION_SUPABASE_URL' }
    if (-not $env:SUPABASE_ANON_KEY) { $missing += 'ORION_ANON_KEY' }

    if ($missing.Count -gt 0) {
        Write-Host ''
        Write-Host 'ERROR: Orion backend is not configured.' -ForegroundColor Red
        Write-Host "Missing: $($missing -join ', ')"
        Write-Host ''
        Write-Host 'Fix it with either:'
        Write-Host ''
        Write-Host '  1) Create your config file:'
        Write-Host '       copy orion-config.ps1.example orion-config.ps1'
        Write-Host '     then set:'
        Write-Host '       $env:ORION_SUPABASE_URL = "https://<your-project-ref>.supabase.co"'
        Write-Host '       $env:ORION_ANON_KEY     = "<your-anon-key>"'
        Write-Host ''
        Write-Host '  2) Or set the variables before running:'
        Write-Host '       set ORION_SUPABASE_URL=https://<your-project-ref>.supabase.co'
        Write-Host '       set ORION_ANON_KEY=<your-anon-key>'
        Write-Host ''
        Write-Host 'Find both values in: Supabase Dashboard -> Project Settings -> API'
        Write-Host ''
        exit 1
    }
}
