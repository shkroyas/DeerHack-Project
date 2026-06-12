# start.ps1
# Script to launch both BankSentinel Backend (FastAPI) and Frontend (Vite)

$ErrorActionPreference = "Stop"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Starting BankSentinel Multi-Agent IDS Pipeline" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Start FastAPI Backend in background
Write-Host "`n[1/2] Starting FastAPI Backend on port 8000..." -ForegroundColor Yellow
Start-Process -FilePath ".\venv\Scripts\python" -ArgumentList "-m uvicorn api.main:app --host 127.0.0.1 --port 8000" -WindowStyle Minimized

# Wait a few seconds for backend to initialize
Start-Sleep -Seconds 5

# 2. Start Vite Frontend
Write-Host "[2/2] Starting React Frontend on port 5173..." -ForegroundColor Yellow
Set-Location -Path ".\frontend"

# Check if node_modules exists, if not run npm install
if (-Not (Test-Path "node_modules")) {
    Write-Host "Installing frontend dependencies (this may take a minute)..." -ForegroundColor Yellow
    npm install --legacy-peer-deps
}

# Run frontend (this will block the terminal and show Vite logs)
npm run dev

# Note: when the user stops this script (Ctrl+C), they may need to manually close the minimized backend window.
