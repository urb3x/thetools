@echo off
setlocal EnableExtensions

cd /d "%~dp0"
set "REPO_URL=https://github.com/urb3x/thetools"
set "ZIP_URL=https://github.com/urb3x/thetools/archive/refs/heads/main.zip"

echo ============================================
echo   thetools Updater
echo ============================================
echo.

if exist ".git" (
    where git >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] This is a Git repository, but 'git' was not found in PATH.
        echo Install Git from https://git-scm.com/ or download the latest ZIP from:
        echo   %REPO_URL%
        goto :fail
    )

    echo Pulling latest changes from origin...
    git pull --ff-only
    if errorlevel 1 (
        echo.
        echo [ERROR] 'git pull --ff-only' failed.
        echo You may have local changes or no internet connection.
        goto :fail
    )
    goto :done
)

echo No .git folder found (downloaded as ZIP). Updating from GitHub main branch...
set "TMP_DIR=%TEMP%\thetools_update_%RANDOM%"
set "TMP_ZIP=%TMP_DIR%\main.zip"
mkdir "%TMP_DIR%" >nul 2>&1

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "try { Invoke-WebRequest -Uri '%ZIP_URL%' -OutFile '%TMP_ZIP%' -UseBasicParsing; Expand-Archive -Path '%TMP_ZIP%' -DestinationPath '%TMP_DIR%' -Force } catch { Write-Error $_; exit 1 }"
if errorlevel 1 (
    echo.
    echo [ERROR] Failed to download or extract %ZIP_URL%.
    if exist "%TMP_DIR%" rmdir /s /q "%TMP_DIR%" >nul 2>&1
    goto :fail
)

set "EXTRACTED="
for /d %%D in ("%TMP_DIR%\thetools-*") do set "EXTRACTED=%%~fD"
if not defined EXTRACTED (
    echo [ERROR] Could not locate extracted folder in %TMP_DIR%.
    rmdir /s /q "%TMP_DIR%" >nul 2>&1
    goto :fail
)

robocopy "%EXTRACTED%" "%~dp0." /E /NFL /NDL /NJH /NJS /NC /NS /NP >nul
set "RC=%ERRORLEVEL%"
rmdir /s /q "%TMP_DIR%" >nul 2>&1
if %RC% GEQ 8 (
    echo [ERROR] Failed to copy updated files (robocopy exit code %RC%).
    goto :fail
)

:done
echo.
echo [OK] thetools is up to date!
if exist "pass_folder\requirements.txt" (
    where python >nul 2>&1
    if not errorlevel 1 (
        echo Checking Python dependencies...
        python -m pip install -r "pass_folder\requirements.txt" --quiet
    )
)
echo.
pause
exit /b 0

:fail
echo.
pause
exit /b 1
