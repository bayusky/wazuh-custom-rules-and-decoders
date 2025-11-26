<#
.SYNOPSIS
    Downloads the Browser History Monitor from GitHub and sets up a background Scheduled Task.
    Checks for Python and installs it automatically if missing.
    Run this as Administrator.

.DESCRIPTION
    1. Checks if Python is installed (PATH or Common Dirs); if not, downloads and installs Python 3.12 silently.
    2. Creates installation directory C:\BrowserMonitor.
    3. Downloads browser-history-monitor.py from the specific GitHub URL.
    4. Creates a Windows Scheduled Task that runs at logon (HIDDEN).
    5. Starts the task immediately.

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
        # Try to get version. If it's a stub, this might fail or return nothing valid.
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
        $process.WaitForExit(2000) # Wait max 2 seconds to avoid hanging on GUI stubs
        
        if ($process.HasExited -and $process.ExitCode -eq 0) {
            return $true
        }
    } catch {}
    return $false
}

# --- INSTALLATION ---
Write-Host "[*] Starting Installation..." -ForegroundColor Cyan

# 1. Check and Install Python
Write-Host "[*] Checking for Python installation..."
$PythonExecutable = ""
$PythonWExecutable = ""
$IsInstalled = $false

# A. Check PATH
try {
    $py = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($py) {
        if (Test-PythonCommand $py.Source) {
            $PythonExecutable = $py.Source
            $IsInstalled = $true
            Write-Host "[+] Found valid Python in PATH: $($py.Source)" -ForegroundColor Green
        }
    }
} catch {}

# B. Check Common Directories (if PATH failed or was a bad stub)
if (-not $IsInstalled) {
    Write-Host "[*] Searching common install paths..."
    $CommonPaths = @(
        "C:\Python312\python.exe",
        "C:\Python311\python.exe",
        "C:\Program Files\Python312\python.exe",
        "C:\Program Files\Python311\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe"
    )
    
    foreach ($path in $CommonPaths) {
        if (Test-Path $path) {
            if (Test-PythonCommand $path) {
                $PythonExecutable = $path
                $IsInstalled = $true
                Write-Host "[+] Found valid Python manually: $path" -ForegroundColor Green
                
                # Add to PATH temporarily for this script session
                $Dir = Split-Path $path -Parent
                $env:Path = "$Dir;$env:Path"
                break
            }
        }
    }
}

# C. Install if absolutely missing
if (-not $IsInstalled) {
    Write-Warning "[-] Valid Python not found. Initiating automatic installation..."
    try {
        Write-Host "[*] Downloading Python 3.12..."
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $PythonInstallerUrl -OutFile $PythonInstallerPath -UseBasicParsing
        
        Write-Host "[*] Installing Python (Silently)..."
        $Process = Start-Process -FilePath $PythonInstallerPath -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1 Include_test=0" -Wait -PassThru
        
        if ($Process.ExitCode -eq 0) {
            Write-Host "[+] Python installed successfully." -ForegroundColor Green
            # Refresh Path
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
        } else {
            throw "Installation failed with exit code $($Process.ExitCode)"
        }
    } catch {
        Write-Error "[-] Failed to install Python. Please install manually."
        exit 1
    }
}

# 2. Create Directory
if (-not (Test-Path -Path $InstallDir)) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Write-Host "[+] Created directory: $InstallDir" -ForegroundColor Green
}

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

# 4. Create Scheduled Task
Write-Host "[*] Creating Scheduled Task..."

# Find pythonw.exe based on the found python.exe
if ($PythonExecutable) {
    $Dir = Split-Path $PythonExecutable -Parent
    $PotentialW = Join-Path $Dir "pythonw.exe"
    if (Test-Path $PotentialW) {
        $PythonWExecutable = $PotentialW
    } else {
        # Fallback to whatever is in path
        $PythonWExecutable = (Get-Command pythonw.exe -ErrorAction SilentlyContinue).Source
    }
}

if (-not $PythonWExecutable) {
    Write-Warning "[-] pythonw.exe not found. Defaulting to 'pythonw.exe'."
    $PythonWExecutable = "pythonw.exe"
} else {
    Write-Host "[+] Using pythonw: $PythonWExecutable" -ForegroundColor Green
}

$Action = New-ScheduledTaskAction -Execute $PythonWExecutable -Argument """$DestPath""" -WorkingDirectory $InstallDir
$Trigger = New-ScheduledTaskTrigger -AtLogon
$Principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Description "Runs the Browser History Monitor for Wazuh." | Out-Null

$TaskSettings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0
Set-ScheduledTask -TaskName $TaskName -Settings $TaskSettings | Out-Null

Write-Host "[+] Scheduled Task created (Background Mode)." -ForegroundColor Green

# 5. Start Immediately
Write-Host "[*] Starting task..."
try {
    Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop
    Write-Host "[+] Task started." -ForegroundColor Green
} catch {
    Write-Warning "[-] Task created but failed to start immediately. It will run at next logon."
}
