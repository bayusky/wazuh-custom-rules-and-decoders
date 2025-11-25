<#
.SYNOPSIS
    Downloads the Browser History Monitor from GitHub and sets up a Scheduled Task.
    Run this as Administrator.

.DESCRIPTION
    1. Creates installation directory C:\BrowserMonitor
    2. Downloads browser-history-monitor.py from the specific GitHub URL.
    3. Creates a Windows Scheduled Task that runs at logon.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\install_browser_monitor.ps1
#>

# --- CONFIGURATION ---
$SourceUrl = "https://raw.githubusercontent.com/bayusky/wazuh-custom-rules-and-decoders/refs/heads/main/browser-monitoring/browser-history-monitor.py"
$InstallDir = "C:\BrowserMonitor"
$ScriptFileName = "browser-history-monitor.py"
$TaskName = "BrowserHistoryMonitor"
$DestPath = Join-Path -Path $InstallDir -ChildPath $ScriptFileName

# --- CHECK FOR ADMIN ---
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "[-] This script must be run as Administrator to create the Scheduled Task."
    Write-Warning "[-] Please right-click and 'Run as Administrator'."
    exit 1
}

# --- INSTALLATION ---
Write-Host "[*] Starting Installation..." -ForegroundColor Cyan

# 1. Create Directory
if (-not (Test-Path -Path $InstallDir)) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Write-Host "[+] Created directory: $InstallDir" -ForegroundColor Green
}

# 2. Download Script
Write-Host "[*] Downloading script from GitHub..."
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $SourceUrl -OutFile $DestPath -UseBasicParsing
    Write-Host "[+] Download complete: $DestPath" -ForegroundColor Green
}
catch {
    Write-Error "[-] Failed to download file. Please check your internet connection."
    Write-Error "[-] Error details: $_"
    exit 1
}

# 3. Create Scheduled Task
Write-Host "[*] Creating Scheduled Task..."

# We verify Python exists
try {
    $pythonPath = (Get-Command python.exe -ErrorAction Stop).Source
} catch {
    Write-Warning "[-] Python not found in PATH. Please ensure Python is installed and added to PATH."
    Write-Warning "[-] Task creation will proceed, but execution may fail if python is not found later."
    $pythonPath = "python.exe"
}

# Action: Run Python with the script hidden
$Action = New-ScheduledTaskAction -Execute $pythonPath `
    -Argument """$DestPath""" `
    -WorkingDirectory $InstallDir

# Trigger: Run when the user logs on
$Trigger = New-ScheduledTaskTrigger -AtLogon

# Principal: Run as the current logged-in user
# This is crucial so the script finds the correct 'Home' directory for browser history
$Principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive

# Register the task
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Description "Runs the Browser History Monitor for Wazuh integration." | Out-Null

Write-Host "[+] Scheduled Task '$TaskName' created successfully." -ForegroundColor Green
Write-Host "[*] To test immediately, run: Start-ScheduledTask -TaskName '$TaskName'" -ForegroundColor Yellow
