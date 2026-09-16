@echo off
REM ============================================================
REM Orion Cyber AI - Windows CMD Launcher
REM ============================================================
REM This launches the PowerShell agent script.
REM
REM Usage:
REM   Double-click this file, or run from CMD:
REM   orion-agent-windows.bat
REM
REM Requirements:
REM   - Windows 10 or later (includes curl and PowerShell)
REM   - Install security tools you want to use (see below)
REM
REM Tool installation links:
REM   Nmap:     https://nmap.org/download.html
REM   Git:      https://git-scm.com/download/win
REM   Python:   https://python.org
REM   YARA:     https://github.com/VirusTotal/yara/releases
REM   Nuclei:   https://github.com/projectdiscovery/nuclei/releases
REM   Gitleaks: https://github.com/gitleaks/gitleaks/releases
REM   Trivy:    https://github.com/aquasecurity/trivy/releases
REM   Semgrep:  pip install semgrep
REM   SSLyze:   pip install sslyze
REM   httpx:    pip install httpx
REM ============================================================

echo ============================================
echo   Orion Cyber AI - Windows Agent Launcher
echo ============================================
echo.

REM Check if PowerShell script exists
if not exist "%~dp0orion-agent-windows.ps1" (
    echo ERROR: orion-agent-windows.ps1 not found in the same folder.
    echo Please make sure both files are in the same directory.
    pause
    exit /b 1
)

REM Launch PowerShell with the agent script
powershell -ExecutionPolicy Bypass -File "%~dp0orion-agent-windows.ps1"

pause
