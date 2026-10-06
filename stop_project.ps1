# ============================================================
# CyberShield AI - Stop Script
# Kills backend (uvicorn) and frontend (vite) processes
# ============================================================
$ErrorActionPreference = 'SilentlyContinue'

Write-Host "CyberShield AI - Stopping services" -ForegroundColor Cyan

# Stop uvicorn processes (backend)
$stoppedBackend = $false
$uvicornProcs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
  Where-Object { $_.CommandLine -match 'uvicorn.*app\.main' -or $_.CommandLine -match 'app\.main:app' }
if ($uvicornProcs) {
  $uvicornProcs | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
  Write-Host "  Stopped backend (uvicorn) - $($uvicornProcs.Count) process(es)" -ForegroundColor Green
  $stoppedBackend = $true
}

# Also kill by listening port 8000 if still active
$port8000 = Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue
if ($port8000) {
  $port8000.OwningProcess | Select-Object -Unique | ForEach-Object {
    Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue
  }
  Write-Host "  Freed port 8000" -ForegroundColor Green
  $stoppedBackend = $true
}
if (-not $stoppedBackend) {
  Write-Host "  No backend (uvicorn) process found." -ForegroundColor DarkGray
}

# Stop Vite dev server processes (frontend)
$stoppedFrontend = $false
$viteProcs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
  Where-Object { $_.CommandLine -match 'vite' -and ($_.CommandLine -match '5173' -or $_.CommandLine -match 'cybershield') }
if ($viteProcs) {
  $viteProcs | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
  Write-Host "  Stopped frontend (vite) - $($viteProcs.Count) process(es)" -ForegroundColor Green
  $stoppedFrontend = $true
}

# Also kill by listening port 5173 if still active
$port5173 = Get-NetTCPConnection -LocalPort 5173 -ErrorAction SilentlyContinue
if ($port5173) {
  $port5173.OwningProcess | Select-Object -Unique | ForEach-Object {
    Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue
  }
  Write-Host "  Freed port 5173" -ForegroundColor Green
  $stoppedFrontend = $true
}
if (-not $stoppedFrontend) {
  Write-Host "  No frontend (vite) process found." -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "All services stopped." -ForegroundColor Cyan
