@echo off
setlocal EnableExtensions
cd /d "%~dp0"

title GASHA LAN Setup
echo ============================================================
echo  GASHA LAN Development Stack
echo ============================================================
echo.

where node >nul 2>nul || (echo ERROR: Install Node.js 20 or newer, then run this file again.& goto :fail)
where py >nul 2>nul || (echo ERROR: Install Python 3.13, then run this file again.& goto :fail)
where npm >nul 2>nul || (echo ERROR: npm is missing. Reinstall Node.js 20 or newer.& goto :fail)

if not exist node_modules\ (
  echo Installing JavaScript dependencies. This may take a few minutes...
  call npm exec --yes --package=pnpm@9.0.0 -- pnpm install --frozen-lockfile
  if errorlevel 1 (echo ERROR: pnpm dependency installation failed.& goto :fail)
)

if not exist .venv\Scripts\python.exe (
  echo Creating Python environment...
  py -3.13 -m venv .venv
  if errorlevel 1 (echo ERROR: Python 3.13 is required to create the environment.& goto :fail)
)

if not exist .venv\.gasha-deps-installed (
  echo Installing Python service dependencies. This may take a few minutes...
  .venv\Scripts\python.exe -m pip install --upgrade pip
  if errorlevel 1 (echo ERROR: pip upgrade failed.& goto :fail)
  .venv\Scripts\python.exe -m pip install -r apps\api\requirements.txt
  if errorlevel 1 (echo ERROR: Python dependencies failed to install.& goto :fail)
  >.venv\.gasha-deps-installed echo installed
)

if not exist apps\data mkdir apps\data
for /f "delims=" %%I in ('powershell -NoProfile -Command "Get-NetIPAddress -AddressFamily IPv4 ^| Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' -and $_.PrefixOrigin -ne 'WellKnown' } ^| Select-Object -First 1 -ExpandProperty IPAddress"') do set "LAN_IP=%%I"
if not defined LAN_IP set "LAN_IP=127.0.0.1"

echo.
netsh advfirewall firewall show rule name="GASHA-LAN-Development" >nul 2>nul
if errorlevel 1 (
  echo Requesting a Private-network firewall rule for the four local services...
  powershell -NoProfile -Command "Start-Process -FilePath netsh.exe -ArgumentList 'advfirewall firewall add rule name=GASHA-LAN-Development dir=in action=allow protocol=TCP localport=3100,3101,3102,4000 profile=private' -Verb RunAs"
)
echo Starting GASHA API, client web, attacker console, and demo target...
start "GASHA API" /D "%~dp0apps\api" cmd /k "set GASHA_STORAGE_BACKEND=memory&& set GASHA_DB_DIALECT=sqlite&& set GASHA_DATABASE_PATH=%~dp0apps\data\gasha_storage.db&& ..\..\.venv\Scripts\python.exe -m uvicorn app.main:app --host 0.0.0.0 --port 4000"
start "Client Web" /D "%~dp0" cmd /k "call npm exec --yes --package=pnpm@9.0.0 -- pnpm --filter @gasha/web dev"
start "Demo Target" /D "%~dp0apps\demo-target" cmd /k "set GASHA_TELEMETRY_ENDPOINT=http://127.0.0.1:4000/api/v1/telemetry/ingest&& set GASHA_TELEMETRY_API_KEY=gasha-telemetry-demo-key-2026&& ..\..\.venv\Scripts\python.exe -m uvicorn main:app --host 0.0.0.0 --port 3101"
start "Attacker Console" /D "%~dp0apps\attacker-console" cmd /k "set TARGET_URL=http://127.0.0.1:3101&& ..\..\.venv\Scripts\python.exe -m uvicorn main:app --host 0.0.0.0 --port 3102"

echo Waiting for services to start...
timeout /t 8 /nobreak >nul
echo.
echo LAN addresses (use these from devices on the same network):
echo   Client web:       http://%LAN_IP%:3100
echo   Attacker console: http://%LAN_IP%:3102
echo   Demo target:      http://%LAN_IP%:3101
echo   GASHA API docs:   http://%LAN_IP%:4000/docs
echo.
echo If another device cannot connect, allow ports 3100, 3101, 3102, and 4000
echo through Windows Defender Firewall on a Private network.
echo Keep the service windows open. Close each window to stop that service.
echo.
start "" "http://%LAN_IP%:3100"
pause
exit /b 0

:fail
echo.
pause
exit /b 1



