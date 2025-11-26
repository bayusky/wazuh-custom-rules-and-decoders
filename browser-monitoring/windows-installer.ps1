<#
.SYNOPSIS
    Downloads the Browser History Monitor from GitHub and sets up a background Scheduled Task.
    Checks for Python and installs it automatically if missing.
    Run this as Administrator.

.DESCRIPTION
    1. Checks if Python is installed; if not, downloads and installs Python 3.12 silently.
    2. Creates installation directory C:\BrowserMonitor.
    3. Downloads browser-history-monitor.py from the specific GitHub URL.
    4. Creates a Windows Scheduled Task that runs at logon (HIDDEN).

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
    Write-Warning "[-] This script must be run as Administrator to create the Scheduled Task and Install Python."
    Write-Warning "[-] Please right-click and 'Run as Administrator'."
    exit 1
}

# --- INSTALLATION ---
Write-Host "[*] Starting Installation..." -ForegroundColor Cyan

# 1. Check and Install Python
Write-Host "[*] Checking for Python installation..."
try {
    # Check if python is already in PATH
    $py = Get-Command python.exe -ErrorAction Stop
    
    # CRITICAL: Check if pythonw is also in PATH (Required for background execution)
    $pyw = Get-Command pythonw.exe -ErrorAction Stop

    # Extra Check: Windows 10/11 includes "Execution Aliases" (stubs) in the WindowsApps folder.
    # These exist even if Python isn't actually installed (they open the MS Store).
    # We want to force a real installation if we see these stubs to ensure stability.
    if ($py.Source -like "*WindowsApps*" -or $pyw.Source -like "*WindowsApps*") {
        Write-Warning "[-] Detected Microsoft Store Python stub. Proceeding with full standalone installation."
        throw "Stub detected"
    }

    Write-Host "[+] Python (and pythonw.exe) is already installed." -ForegroundColor Green
}
catch {
    Write-Warning "[-] Python or pythonw.exe not found/usable. Initiating automatic installation..."
    
    try {
        # Download Python
        Write-Host "[*] Downloading Python 3.12 from $PythonInstallerUrl..."
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $PythonInstallerUrl -OutFile $PythonInstallerPath -UseBasicParsing
        
        # Install Python Silently
        # /quiet = No UI
        # InstallAllUsers=1 = Install to Program Files
        # PrependPath=1 = Add to Environment PATH (Critical)
        Write-Host "[*] Installing Python (this may take a minute)..."
        $Process = Start-Process -FilePath $PythonInstallerPath -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1 Include_test=0" -Wait -PassThru
        
        if ($Process.ExitCode -eq 0) {
            Write-Host "[+] Python installed successfully." -ForegroundColor Green
            
            # Refresh Environment Variables for the current session so we can use python immediately
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
        }
        else {
            Write-Error "[-] Python installation failed with exit code $($Process.ExitCode)."
            exit 1
        }
    }
    catch {
        Write-Error "[-] Failed to download or install Python. Please install manually."
        Write-Error "[-] Error: $_"
        exit 1
    }
    finally {
        # Cleanup Installer
        if (Test-Path $PythonInstallerPath) { Remove-Item $PythonInstallerPath -Force }
    }
}

# 2. Create Directory
if (-not (Test-Path -Path $InstallDir)) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Write-Host "[+] Created directory: $InstallDir" -ForegroundColor Green
}

# 3. Download Script
Write-Host "[*] Downloading monitor script from GitHub..."
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

# 4. Create Scheduled Task
Write-Host "[*] Creating Scheduled Task..."

# Find pythonw.exe (Windowless) now that Python is confirmed installed
try {
    $pythonPath = (Get-Command pythonw.exe -ErrorAction Stop).Source
    Write-Host "[+] Found pythonw.exe at: $pythonPath" -ForegroundColor Green
} catch {
    Write-Warning "[-] pythonw.exe not found in PATH immediately after install."
    Write-Warning "[-] Attempting to locate in standard install paths..."
    
    # Fallback search in standard locations if PATH refresh didn't catch it
    $StandardPaths = @(
        "C:\Program Files\Python312\pythonw.exe",
        "C:\Program Files\Python311\pythonw.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python312\pythonw.exe"
    )
    
    $Found = $false
    foreach ($Path in $StandardPaths) {
        if (Test-Path $Path) {
            $pythonPath = $Path
            $Found = $true
            Write-Host "[+] Found pythonw.exe manually at: $pythonPath" -ForegroundColor Green
            break
        }
    }
    
    if (-not $Found) {
        Write-Warning "[-] Could not locate pythonw.exe. Defaulting to 'pythonw.exe' (Task may fail if not in PATH)."
        $pythonPath = "pythonw.exe"
    }
}

# Action: Run Python Windowless with the script
$Action = New-ScheduledTaskAction -Execute $pythonPath `
    -Argument """$DestPath""" `
    -WorkingDirectory $InstallDir

# Trigger: Run when the user logs on
$Trigger = New-ScheduledTaskTrigger -AtLogon

# Principal: Run as the current logged-in user
$Principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive

# Register the task
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Description "Runs the Browser History Monitor for Wazuh integration." | Out-Null

# Configure the Task Settings to be Hidden
$TaskSettings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0
Set-ScheduledTask -TaskName $TaskName -Settings $TaskSettings | Out-Null

Write-Host "[+] Scheduled Task '$TaskName' created successfully (Background Mode)." -ForegroundColor Green
Write-Host "[*] To test immediately, run: Start-ScheduledTask -TaskName '$TaskName'" -ForegroundColor Yellow
