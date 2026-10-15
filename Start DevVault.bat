@echo off
setlocal
title DevVault Launcher
cd /d "%~dp0"

if not defined DEVVAULT_PORT set "DEVVAULT_PORT=5000"
set "PYTHON_EXE=%~dp0.venv\Scripts\python.exe"
set "DEVVAULT_URL=http://127.0.0.1:%DEVVAULT_PORT%/"

if not exist "%PYTHON_EXE%" (
    echo Setting up DevVault's Python environment...
    where py >nul 2>&1
    if errorlevel 1 (
        echo Python Launcher was not found. Install Python 3.11 or newer, then try again.
        pause
        exit /b 1
    )
    py -3 -m venv "%~dp0.venv"
    if errorlevel 1 (
        echo Could not create the Python environment.
        pause
        exit /b 1
    )
)

"%PYTHON_EXE%" -c "import flask" >nul 2>&1
if errorlevel 1 (
    echo Installing DevVault requirements...
    "%PYTHON_EXE%" -m pip install -r "%~dp0devvault\requirements.txt"
    if errorlevel 1 (
        echo Could not install the requirements. Check your internet connection and try again.
        pause
        exit /b 1
    )
)

"%PYTHON_EXE%" -c "import socket,sys; s=socket.socket(); s.settimeout(1); sys.exit(0 if s.connect_ex(('127.0.0.1',%DEVVAULT_PORT%))==0 else 1)" >nul 2>&1
if not errorlevel 1 (
    echo DevVault is already running. Opening it in your browser...
    start "" "%DEVVAULT_URL%"
    exit /b 0
)

start "" /b powershell.exe -NoProfile -WindowStyle Hidden -Command "$url='%DEVVAULT_URL%'; for ($i=0; $i -lt 180; $i++) { try { $r=Invoke-WebRequest -UseBasicParsing -Uri $url -TimeoutSec 1; if ($r.StatusCode -ge 200 -and $r.StatusCode -lt 400) { Start-Process $url; exit 0 } } catch { }; Start-Sleep -Seconds 1 }; exit 1"
pushd "%~dp0devvault"
echo Starting DevVault. Keep this window open while using the app.
echo Press Ctrl+C in this window to stop it.
"%PYTHON_EXE%" -m flask --app app run --host 127.0.0.1 --port %DEVVAULT_PORT%
set "SERVER_EXIT=%ERRORLEVEL%"
popd
if not "%SERVER_EXIT%"=="0" (
    echo DevVault stopped with an error. Check the message above.
    pause
)
endlocal
