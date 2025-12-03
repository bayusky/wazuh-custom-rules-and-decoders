<#
.SYNOPSIS
    Downloads the Browser History Monitor and sets up persistence for ALL USERS.
    Forces System-Wide Python Installation.
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

# --- 1. PYTHON DETECTION (MUST BE SYSTEM-WIDE) ---
Write-Host "[*] Checking for System-Wide Python (Accessible by User1)..." -ForegroundColor Cyan
$SystemPythonPath = ""

# Check Common "Program Files" Paths
$CommonPaths = @(
    "C:\Program Files\Python312\python.exe",
    "C:\Program Files\Python311\python.exe",
    "C:\Program Files (x86)\Python312\python.exe",
    "C:\Python312\python.exe"
)

foreach ($path in $CommonPaths) {
    if (Test-Path $path) {
        $SystemPythonPath = $path
        Write-Host "[+] Found System Python: $path" -ForegroundColor Green
        break
    }
}

# If not found in Program Files, check PATH but FILTER OUT User-specific installs
if (-not $SystemPythonPath) {
    try {
        $py = Get-Command python.exe -ErrorAction SilentlyContinue
        if ($py) {
            if ($py.Source -like "*\Users\*") {
                Write-Warning "[-] Found Python at $($py.Source)"
                Write-Warning "[-] BUT this is a User-Specific install (AppData). User1 cannot access this."
                Write-Warning "[-] We must install a System-Wide Python."
            } else {
                $SystemPythonPath = $py.Source
            }
        }
    } catch {}
}

# If STILL not found (or only found user-specific), Install it
if (-not $SystemPythonPath) {
    Write-Host "[*] Installing Python 3.12 System-Wide (This may take 2-3 minutes)..." -ForegroundColor Cyan
    
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $PythonInstallerUrl -OutFile $PythonInstallerPath -UseBasicParsing
    
    # Arguments explained:
    # /quiet = Silent
    # InstallAllUsers=1 = Installs to Program Files (Critical for User1 access)
    # PrependPath=1 = Adds to PATH
    # TargetDir = Force a clean path
    $InstallArgs = "/quiet InstallAllUsers=1 PrependPath=1 Include_test=0 TargetDir=`"C:\Program Files\Python312`""
    
    Start-Process -FilePath $PythonInstallerPath -ArgumentList $InstallArgs -Wait
    
    # Verify Install
    if (Test-Path "C:\Program Files\Python312\python.exe") {
        $SystemPythonPath = "C:\Program Files\Python312\python.exe"
        Write-Host "[+] Python installed successfully to $SystemPythonPath" -ForegroundColor Green
    } else {
        Write-Error "[-] Failed to install Python. Please install Python 3.12 manually and check 'Install for All Users'."
        exit 1
    }
}

# Find pythonw.exe (Windowless version) relative to the System Python
$Dir = Split-Path $SystemPythonPath -Parent
$PythonWExePath = Join-Path $Dir "pythonw.exe"

if (-not (Test-Path $PythonWExePath)) {
    Write-Warning "[-] Could not find pythonw.exe at $PythonWExePath. using python.exe"
    # Fallback to python.exe (will show window) only if absolutely necessary
    $PythonWExePath = $SystemPythonPath
} else {
    Write-Host "[+] Found Windowless Python: $PythonWExePath" -ForegroundColor Green
}

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

# --- 4. PERSISTENCE: SCHEDULED TASK ---
# FIX: Removed batch file wrapper. Execute pythonw directly to avoid CMD window.

Write-Host "[*] Creating Scheduled Task..."
# Note: Arguments must be quoted properly to handle spaces
$Action = New-ScheduledTaskAction -Execute $PythonWExePath -Argument """$DestPath""" -WorkingDirectory $InstallDir
$Trigger = New-ScheduledTaskTrigger -AtLogon
$Principal = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Users" -RunLevel Limited

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal | Out-Null
$TaskSettings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0
Set-ScheduledTask -TaskName $TaskName -Settings $TaskSettings | Out-Null
Write-Host "[+] Scheduled Task Created." -ForegroundColor Green

# --- 5. PERSISTENCE: STARTUP FOLDER (FAILSAFE) ---
Write-Host "[*] Creating Global Startup Shortcut..."
$StartupDir = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
$ShortcutPath = Join-Path $StartupDir "WazuhBrowserMonitor.lnk"
$WScriptShell = New-Object -ComObject WScript.Shell
$Shortcut = $WScriptShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = $PythonWExePath
$Shortcut.Arguments = """$DestPath"""
$Shortcut.WorkingDirectory = $InstallDir
$Shortcut.Save()
Write-Host "[+] Shortcut created in All Users Startup folder." -ForegroundColor Green

# Cleanup old batch file if it exists from previous attempts
if (Test-Path "$InstallDir\launcher.bat") { Remove-Item "$InstallDir\launcher.bat" -Force }

Write-Host "`n[SUCCESS] Installation Complete." -ForegroundColor Green
