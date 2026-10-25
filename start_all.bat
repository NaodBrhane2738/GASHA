@echo off
title GASHA Platform Runner
echo ====================================================
echo Starting GASHA Platform Services...
echo ====================================================

echo [1/4] Starting GASHA Core API on http://localhost:4000...
start "GASHA Core API (Port 4000)" cmd /k "python -m uvicorn app.main:app --app-dir apps/api --host 0.0.0.0 --port 4000"

echo [2/4] Starting Nexus Storefront Target on http://localhost:3101...
start "Nexus Store Target (Port 3101)" cmd /k "python -m uvicorn main:app --app-dir apps/demo-target --host 0.0.0.0 --port 3101"

echo [3/4] Starting Attacker Console on http://localhost:3102...
start "Attacker Console (Port 3102)" cmd /k "python -m uvicorn main:app --app-dir apps/attacker-console --host 0.0.0.0 --port 3102"

echo [4/4] Starting GASHA Web Console on http://localhost:3100...
start "GASHA Web Console (Port 3100)" cmd /k "pnpm --filter @gasha/web dev"

echo.
echo ====================================================
echo All services launched!
echo Web Console:      http://localhost:3100
echo Demo Storefront:  http://localhost:3101
echo Attacker Console: http://localhost:3102
echo Core API Docs:    http://localhost:4000/docs
echo.
echo Login Credentials:
echo   Username: analyst01
echo   Password: agis
echo ====================================================
