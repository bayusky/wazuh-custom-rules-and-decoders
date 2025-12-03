<#
.SYNOPSIS
    Downloads the Browser History Monitor and sets up persistence for ALL USERS.
    Checks for Python and installs it automatically if missing.
    Run this as Administrator.
#>

# --- CONFIGURATION ---
$SourceUrl = "https://raw.githubusercontent.com/bayusky/wazuh-custom-rules-and-decoders/refs/heads/main/browser-monitoring/browser-history-monitor.py"
$InstallDir = "C:\BrowserMonitor"
$ScriptFileName = "browser-history-monitor.py"
$TaskName = "BrowserHistoryMonitor"
$DestPath = Join-Path -Path $InstallDir -ChildPath $ScriptFileName

# Python Installer Config
$PythonInstallerUrl = "https://www.python.org/ftp/python/3.12.0/python-3.12.0-amd64.exe"
$PythonInstallerPath = "$env:TEMP\python-installer.exe"

# --- CHECK FOR ADMIN ---
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "[-] This script must be run as Administrator."
    exit 1
}

# --- 1. PYTHON DETECTION (FIND ABSOLUTE PATH) ---
Write-Host "[*] Checking for Python installation..." -ForegroundColor Cyan
$PythonExePath = ""
$PythonWExePath = ""

# Check Common "All Users" Paths First
$CommonPaths = @(
    "C:\Program Files\Python312\python.exe",
    "C:\Program Files\Python311\python.exe",
    "C:\Program Files (x86)\Python312\python.exe"
)

foreach ($path in $CommonPaths) {
    if (Test-Path $path) {
        $PythonExePath = $path
        Write-Host "[+] Found System Python: $path" -ForegroundColor Green
        break
    }
}

# If not found, check PATH
if (-not $PythonExePath) {
    try {
        $py = Get-Command python.exe -ErrorAction SilentlyContinue
        if ($py) { $PythonExePath = $py.Source }
    } catch {}
}

# If STILL not found, Install it
if (-not $PythonExePath) {
    Write-Warning "[-] Python not found. Installing for ALL USERS..."
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $PythonInstallerUrl -OutFile $PythonInstallerPath -UseBasicParsing
    Start-Process -FilePath $PythonInstallerPath -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1 Include_test=0" -Wait
    
    # Assume default install path after silent install
    $PythonExePath = "C:\Program Files\Python312\python.exe"
}

# Find pythonw.exe (Windowless version) based on python.exe location
$Dir = Split-Path $PythonExePath -Parent
$PythonWExePath = Join-Path $Dir "pythonw.exe"

if (-not (Test-Path $PythonWExePath)) {
    Write-Warning "[-] Could not find pythonw.exe at $PythonWExePath. using python.exe (window might appear)"
    $PythonWExePath = $PythonExePath
}

Write-Host "[+] Python Executable to use: $PythonWExePath" -ForegroundColor Green

# --- 2. SETUP DIRECTORY ---
if (-not (Test-Path -Path $InstallDir)) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
}

# GRANT PERMISSIONS (Critical for non-admin logs)
$Acl = Get-Acl $InstallDir
$Ar = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Users", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
$Acl.SetAccessRule($Ar)
Set-Acl $InstallDir $Acl
Write-Host "[+] Granted 'Modify' permissions to Users on $InstallDir" -ForegroundColor Green

# --- 3. DOWNLOAD SCRIPT ---
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $SourceUrl -OutFile $DestPath -UseBasicParsing
Write-Host "[+] Script downloaded." -ForegroundColor Green

# --- 4. PERSISTENCE METHOD 1: SCHEDULED TASK ---
# We use a batch wrapper to ensure paths are correct
$BatchContent = @"
@echo off
cd /d "$InstallDir"
"$PythonWExePath" "$DestPath"
"@
$BatchPath = Join-Path $InstallDir "launcher.bat"
Set-Content -Path $BatchPath -Value $BatchContent

Write-Host "[*] Creating Scheduled Task..."
$Action = New-ScheduledTaskAction -Execute $BatchPath
$Trigger = New-ScheduledTaskTrigger -AtLogon
$Principal = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Users" -RunLevel Limited

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal | Out-Null
$TaskSettings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0
Set-ScheduledTask -TaskName $TaskName -Settings $TaskSettings | Out-Null
Write-Host "[+] Scheduled Task Created." -ForegroundColor Green

# --- 5. PERSISTENCE METHOD 2: STARTUP FOLDER (BACKUP) ---
# This is often more reliable for "All Users" than Task Scheduler
Write-Host "[*] Creating Global Startup Shortcut (Backup method)..."
$StartupDir = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
$ShortcutPath = Join-Path $StartupDir "WazuhBrowserMonitor.lnk"
$WScriptShell = New-Object -ComObject WScript.Shell
$Shortcut = $WScriptShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = $PythonWExePath
$Shortcut.Arguments = """$DestPath"""
$Shortcut.WorkingDirectory = $InstallDir
$Shortcut.Save()
Write-Host "[+] Shortcut created in All Users Startup folder." -ForegroundColor Green

Write-Host "`n[SUCCESS] Installation Complete." -ForegroundColor Green
Write-Host "The monitor will run automatically when ANY user logs in."
