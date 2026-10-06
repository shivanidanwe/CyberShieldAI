# ============================================================
# CyberShield AI - Start Script
# Boots backend (FastAPI) + frontend (Vite dev server)
# ============================================================
param(
  [switch]$SkipFrontend,
  [switch]$SkipBackend,
  [switch]$Seed
)

$ErrorActionPreference = 'Continue'
$root = Split-Path $PSScriptRoot -Parent
$backend = Join-Path $PSScriptRoot 'backend'
$frontend = Join-Path $PSScriptRoot 'frontend'
$logDir = Join-Path $backend 'logs'

if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }

# ---- Resolve Python ----
$python = $null
$venvPython = Join-Path $PSScriptRoot 'venv\Scripts\python.exe'
if (Test-Path $venvPython) {
  $python = $venvPython
} else {
  $pyExe = Get-Command py -ErrorAction SilentlyContinue
  if ($pyExe) {
    $python = 'py'
  } else {
    $pyExe = Get-Command python -ErrorAction SilentlyContinue
    if ($pyExe) { $python = 'python' }
  }
}
if (-not $python) {
  Write-Host '[ERROR] Python not found. Install Python 3.11+ and add to PATH.' -ForegroundColor Red
  exit 1
}


Write-Host 'CyberShield AI - Starting up' -ForegroundColor Cyan
Write-Host "Python: $python"

# ---- Backend dependencies ----
if (-not $SkipBackend) {
  Write-Host '`n[1/4] Installing backend dependencies...' -ForegroundColor Yellow
  & $python -m pip install -r (Join-Path $backend 'requirements.txt') --quiet 2>$null

  if ($Seed) {
    Write-Host '[2/4] Seeding demo data...' -ForegroundColor Yellow
    Push-Location $backend
    & $python -m app.seed --force
    Pop-Location
  } else {
    Write-Host '[2/4] Checking seed status (skipping --Seed flag)...' -ForegroundColor Yellow
  }

  # ---- Start backend ----
  Write-Host '[3/4] Starting backend on http://127.0.0.1:8000 ...' -ForegroundColor Green
  $backendLog = Join-Path $logDir 'backend.log'
  $backendJob = Start-Process -FilePath $python `
    -ArgumentList '-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', '8000', '--reload' `
    -WorkingDirectory $backend `
    -NoNewWindow `
    -PassThru `
    -RedirectStandardOutput $backendLog `
    -RedirectStandardError (Join-Path $logDir 'backend_error.log')

  Write-Host "  Backend PID: $($backendJob.Id)  (log: $backendLog)"

  # ---- Health gate ----
  Write-Host '  Waiting for backend to become healthy...' -ForegroundColor Yellow
  $healthy = $false
  for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Milliseconds 1000
    try {
      $resp = Invoke-WebRequest -Uri 'http://127.0.0.1:8000/api/health' -TimeoutSec 2 -UseBasicParsing -ErrorAction Stop
      if ($resp.StatusCode -eq 200) { $healthy = $true; break }
    } catch { }
  }
  if ($healthy) {
    Write-Host '  Backend is healthy.' -ForegroundColor Green
  } else {
    Write-Host '  WARNING: Backend health check timed out. It may still be starting.' -ForegroundColor Yellow
  }
} else {
  Write-Host '`n[1-3/4] Backend skipped.' -ForegroundColor DarkGray
}

# ---- Frontend ----
if (-not $SkipFrontend) {
  Write-Host '`n[4/4] Starting frontend dev server on http://localhost:5173 ...' -ForegroundColor Green
  Push-Location $frontend
  if (-not (Test-Path 'node_modules')) {
    Write-Host '  Installing npm dependencies...' -ForegroundColor Yellow
    npm install --silent
  }
  $frontendLogDir = Join-Path $frontend 'logs'
  if (-not (Test-Path $frontendLogDir)) { New-Item -ItemType Directory -Path $frontendLogDir -Force | Out-Null }

  Start-Process -FilePath "cmd.exe" `
    -ArgumentList "/c", "node node_modules\vite\bin\vite.js --port 5173 > logs\frontend.log 2>&1" `
    -WorkingDirectory $frontend `
    -WindowStyle Hidden

  Write-Host '  Waiting for frontend to become ready...' -ForegroundColor Yellow
  $frontendReady = $false
  for ($i = 0; $i -lt 15; $i++) {
    Start-Sleep -Milliseconds 500
    try {
      $resp = Invoke-WebRequest -Uri 'http://localhost:5173' -TimeoutSec 2 -UseBasicParsing -ErrorAction Stop
      if ($resp.StatusCode -eq 200) { $frontendReady = $true; break }
    } catch { }
  }
  if ($frontendReady) {
    Write-Host '  Frontend is ready.' -ForegroundColor Green
  } else {
    Write-Host '  Frontend server launched.' -ForegroundColor Green
  }
  Pop-Location
} else {
  Write-Host '[4/4] Frontend skipped.' -ForegroundColor DarkGray
}
Write-Host 'CyberShield AI is running!' -ForegroundColor Cyan
Write-Host '  Frontend: http://localhost:5173'
Write-Host '  Backend:  http://127.0.0.1:8000'
Write-Host '  API docs: http://127.0.0.1:8000/docs'
Write-Host 'Press Ctrl+C to stop (or run stop_project.ps1).' -ForegroundColor DarkGray
