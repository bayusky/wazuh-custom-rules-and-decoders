<#
.SYNOPSIS
    Downloads the Browser History Monitor and sets up a Scheduled Task for ALL USERS.
    Checks for Python and installs it automatically if missing.
    Run this as Administrator.

.DESCRIPTION
    1. Checks if Python is installed; if not, installs Python 3.12 for All Users.
    2. Creates C:\BrowserMonitor and grants write permissions to the 'Users' group.
    3. Downloads the python script.
    4. Creates a Scheduled Task that runs for ANY USER at logon.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\windows-installer.ps1
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
    Write-Warning "[-] Please right-click and 'Run as Administrator'."
    exit 1
}

# --- FUNCTIONS ---
function Test-PythonCommand {
    param($CmdPath)
    try {
        $processInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processInfo.FileName = $CmdPath
        $processInfo.Arguments = "--version"
        $processInfo.RedirectStandardOutput = $true
        $processInfo.RedirectStandardError = $true
        $processInfo.UseShellExecute = $false
        $processInfo.CreateNoWindow = $true
        
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $processInfo
        $process.Start() | Out-Null
        $process.WaitForExit(2000)
        
        if ($process.HasExited -and $process.ExitCode -eq 0) { return $true }
    } catch {}
    return $false
}

# --- INSTALLATION ---
Write-Host "[*] Starting Installation..." -ForegroundColor Cyan

# 1. Check and Install Python
Write-Host "[*] Checking for Python installation..."
$PythonExecutable = ""
$IsInstalled = $false

# Search Paths (Prioritize 'Program Files' as that is accessible to all users)
$CommonPaths = @(
    "C:\Program Files\Python312\python.exe",
    "C:\Program Files\Python311\python.exe",
    "C:\Program Files (x86)\Python312\python.exe",
    "C:\Program Files (x86)\Python311\python.exe"
)

foreach ($path in $CommonPaths) {
    if (Test-Path $path) {
        if (Test-PythonCommand $path) {
            $PythonExecutable = $path
            $IsInstalled = $true
            Write-Host "[+] Found valid Python (All Users): $path" -ForegroundColor Green
            $Dir = Split-Path $path -Parent
            $env:Path = "$Dir;$env:Path"
            break
        }
    }
}

# Fallback: Check PATH, but warn if it's a per-user install (AppData)
if (-not $IsInstalled) {
    try {
        $py = Get-Command python.exe -ErrorAction SilentlyContinue
        if ($py -and (Test-PythonCommand $py.Source)) {
            $PythonExecutable = $py.Source
            $IsInstalled = $true
            if ($py.Source -like "*AppData*") {
                 Write-Warning "[-] Warning: Found per-user Python in AppData. Non-admin users might not be able to execute this."
                 Write-Warning "[-] It is highly recommended to install Python for 'All Users'."
            } else {
                 Write-Host "[+] Found valid Python in PATH: $($py.Source)" -ForegroundColor Green
            }
        }
    } catch {}
}

# Install if missing
if (-not $IsInstalled) {
    Write-Warning "[-] Valid Python not found. Initiating automatic installation for ALL USERS..."
    try {
        Write-Host "[*] Downloading Python 3.12..."
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $PythonInstallerUrl -OutFile $PythonInstallerPath -UseBasicParsing
        
        Write-Host "[*] Installing Python (Silently)..."
        # InstallAllUsers=1 ensures it goes to Program Files, accessible by User1
        $Process = Start-Process -FilePath $PythonInstallerPath -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1 Include_test=0" -Wait -PassThru
        
        if ($Process.ExitCode -eq 0) {
            Write-Host "[+] Python installed successfully." -ForegroundColor Green
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
        } else {
            throw "Installation failed with exit code $($Process.ExitCode)"
        }
    } catch {
        Write-Error "[-] Failed to install Python. Please install manually."
        exit 1
    }
}

# 2. Create Directory & GRANT PERMISSIONS
if (-not (Test-Path -Path $InstallDir)) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
}

# CRITICAL STEP: Grant 'Modify' access to 'Users' group
# This allows non-admin users to write the log file in C:\BrowserMonitor
Write-Host "[*] Updating directory permissions for non-admin users..."
$Acl = Get-Acl $InstallDir
$Ar = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Users", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
$Acl.SetAccessRule($Ar)
Set-Acl $InstallDir $Acl
Write-Host "[+] Permissions updated: BUILTIN\Users have Modify access." -ForegroundColor Green

# 3. Download Script
Write-Host "[*] Downloading monitor script..."
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $SourceUrl -OutFile $DestPath -UseBasicParsing
    Write-Host "[+] Download complete: $DestPath" -ForegroundColor Green
} catch {
    Write-Error "[-] Download failed. Check internet."
    exit 1
}

# 4. Create Scheduled Task for ALL USERS
Write-Host "[*] Creating Scheduled Task..."

# Find pythonw.exe
if ($PythonExecutable) {
    $Dir = Split-Path $PythonExecutable -Parent
    $PotentialW = Join-Path $Dir "pythonw.exe"
    if (Test-Path $PotentialW) { $PythonWExecutable = $PotentialW }
    else { $PythonWExecutable = "pythonw.exe" }
} else { $PythonWExecutable = "pythonw.exe" }

Write-Host "[+] Using pythonw: $PythonWExecutable" -ForegroundColor Green

$Action = New-ScheduledTaskAction -Execute $PythonWExecutable -Argument """$DestPath""" -WorkingDirectory $InstallDir
$Trigger = New-ScheduledTaskTrigger -AtLogon

# FIXED: Changed 'LeastPrivilege' to 'Limited' to satisfy strict Enum typing
$Principal = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Users" -RunLevel Limited

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

# Register the task
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Description "Runs Browser History Monitor for any logged-on user." | Out-Null

# Set Hidden Settings
$TaskSettings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0
Set-ScheduledTask -TaskName $TaskName -Settings $TaskSettings | Out-Null

Write-Host "[+] Scheduled Task created for Group: BUILTIN\Users (Background Mode)." -ForegroundColor Green
Write-Host "[*] The monitoring script will now run automatically whenever ANY user logs in." -ForegroundColor Yellow
