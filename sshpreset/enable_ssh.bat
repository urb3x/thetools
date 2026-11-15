@echo off
setlocal EnableExtensions
title OpenSSH Server Setup (No Admin)

echo ============================================================================
echo   Windows OpenSSH Server Setup (User-Space / No Admin Required)
echo ============================================================================
echo.

set "SSH_DIR=%LOCALAPPDATA%\OpenSSH"
set "SSHD_EXE=%SSH_DIR%\sshd.exe"
set "SSH_KEYGEN=%SSH_DIR%\ssh-keygen.exe"
set "HOST_KEY=%SSH_DIR%\ssh_host_ed25519_key"
set "SSHD_CFG=%SSH_DIR%\sshd_config"
set "SSH_PORT=2222"

:: ---------------------------------------------------------------------------
:: 1. Download Win32-OpenSSH into %LOCALAPPDATA%\OpenSSH if not present
:: ---------------------------------------------------------------------------
echo [1/4] Checking OpenSSH binaries...
if exist "%SSHD_EXE%" (
    echo       OpenSSH is already downloaded in "%SSH_DIR%".
    goto :setup_config
)

echo       Downloading latest official Win32-OpenSSH release...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$ProgressPreference = 'SilentlyContinue'; " ^
    "try { " ^
    "  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; " ^
    "  $rel = Invoke-RestMethod -Uri 'https://api.github.com/repos/PowerShell/Win32-OpenSSH/releases/latest' -TimeoutSec 15; " ^
    "  $asset = $rel.assets | Where-Object { $_.name -eq 'OpenSSH-Win64.zip' } | Select-Object -First 1; " ^
    "  if (-not $asset) { throw 'OpenSSH-Win64.zip asset not found.' }; " ^
    "  $zip = Join-Path $env:TEMP 'OpenSSH-Win64.zip'; " ^
    "  $dest = $env:SSH_DIR; " ^
    "  Write-Host ('      Downloading ' + $asset.name + ' (' + $rel.tag_name + ')...') -ForegroundColor Yellow; " ^
    "  Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zip -TimeoutSec 60; " ^
    "  $tmpExtract = Join-Path $env:TEMP 'OpenSSH-Extract'; " ^
    "  if (Test-Path $tmpExtract) { Remove-Item $tmpExtract -Recurse -Force }; " ^
    "  Expand-Archive -Path $zip -DestinationPath $tmpExtract -Force; " ^
    "  $inner = Get-ChildItem -Path $tmpExtract -Directory | Select-Object -First 1; " ^
    "  if (Test-Path $dest) { Remove-Item $dest -Recurse -Force }; " ^
    "  Move-Item -Path $inner.FullName -Destination $dest -Force; " ^
    "  Remove-Item $zip, $tmpExtract -Recurse -Force -ErrorAction SilentlyContinue; " ^
    "  Write-Host '      OpenSSH downloaded successfully.' -ForegroundColor Green; " ^
    "  exit 0 " ^
    "} catch { " ^
    "  Write-Host ('      Download failed: ' + $_.Exception.Message) -ForegroundColor Red; " ^
    "  exit 1 " ^
    "}"

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Failed to download OpenSSH. Check your internet connection.
    pause
    exit /b 1
)

:setup_config
:: ---------------------------------------------------------------------------
:: 2. Generate host key and sshd_config in %LOCALAPPDATA%\OpenSSH
:: ---------------------------------------------------------------------------
echo [2/4] Configuring SSH host key and sshd_config...
if not exist "%HOST_KEY%" (
    "%SSH_KEYGEN%" -t ed25519 -f "%HOST_KEY%" -N "" >nul 2>&1
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to generate SSH host key.
        pause
        exit /b 1
    )
    echo       Generated host key.
) else (
    echo       Host key already exists.
)

if not exist "%SSHD_CFG%" (
    powershell -NoProfile -ExecutionPolicy Bypass -Command ^
        "$dir = ($env:SSH_DIR -replace '\\', '/'); " ^
        "$cfg = @(" ^
        "  'Port ' + $env:SSH_PORT," ^
        "  'HostKey ' + $dir + '/ssh_host_ed25519_key'," ^
        "  'PidFile ' + $dir + '/sshd.pid'," ^
        "  'StrictModes no'," ^
        "  'PasswordAuthentication yes'," ^
        "  'PubkeyAuthentication yes'," ^
        "  'AuthorizedKeysFile .ssh/authorized_keys'," ^
        "  'Subsystem sftp ' + $dir + '/sftp-server.exe'" ^
        "); " ^
        "Set-Content -Path $env:SSHD_CFG -Value $cfg -Encoding Ascii"
    echo       Created "%SSHD_CFG%".
) else (
    echo       Config already exists at "%SSHD_CFG%".
)

:: ---------------------------------------------------------------------------
:: 3. Enable auto-start on login (HKCU, no admin) & launch sshd
:: ---------------------------------------------------------------------------
echo [3/4] Enabling auto-start and starting sshd...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "UserOpenSSH" /t REG_SZ /d "\"%SSHD_EXE%\" -f \"%SSHD_CFG%\"" /f >nul 2>&1

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$running = Get-Process -Name sshd -ErrorAction SilentlyContinue; " ^
    "if ($running) { " ^
    "  Write-Host ('      sshd is already running (PID: ' + ($running.Id -join ', ') + ').') -ForegroundColor Green " ^
    "} else { " ^
    "  Start-Process -FilePath $env:SSHD_EXE -ArgumentList @('-f', $env:SSHD_CFG) -WindowStyle Hidden; " ^
    "  Start-Sleep -Milliseconds 500; " ^
    "  $p = Get-Process -Name sshd -ErrorAction SilentlyContinue; " ^
    "  if ($p) { Write-Host ('      sshd started in background (PID: ' + $p.Id + ', Port: ' + $env:SSH_PORT + ').') -ForegroundColor Green } " ^
    "  else { Write-Host '      [WARNING] sshd did not stay running. Check sshd_config.' -ForegroundColor Yellow } " ^
    "}"

:: ---------------------------------------------------------------------------
:: 4. Show IP addresses and SSH connection info
:: ---------------------------------------------------------------------------
echo [4/4] Fetching IP addresses...
echo.
echo ============================================================================
echo   SSH Connection Details (Port %SSH_PORT%)
echo ============================================================================
echo   User     : %USERNAME%
echo   Hostname : %COMPUTERNAME%
echo   Port     : %SSH_PORT%
echo.
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$ips = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.IPAddress -notlike '169.254.*' -and $_.PrefixOrigin -ne 'WellKnown' }; " ^
    "if ($ips) { " ^
    "  Write-Host '  Local IPv4 Address(es):' -ForegroundColor Cyan; " ^
    "  foreach ($ip in $ips) { " ^
    "    Write-Host ('    - ' + $ip.IPAddress + '  (' + $ip.InterfaceAlias + ')') ; " ^
    "    Write-Host ('      Connect: ssh -p ' + $env:SSH_PORT + ' ' + $env:USERNAME + '@' + $ip.IPAddress) -ForegroundColor Gray " ^
    "  } " ^
    "} else { " ^
    "  Write-Host '  No active local IPv4 address found.' -ForegroundColor Yellow " ^
    "} " ^
    "try { " ^
    "  $pub = (Invoke-RestMethod -Uri 'https://api.ipify.org' -TimeoutSec 3).Trim(); " ^
    "  if ($pub) { Write-Host ('`n  Public IPv4 Address: ' + $pub) -ForegroundColor Cyan } " ^
    "} catch { }"

echo.
echo   Note: If Windows Firewall prompts you, click "Allow access".
echo ============================================================================
echo.
pause
