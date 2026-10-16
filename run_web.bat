@echo off
setlocal
echo ========================================================
echo   Starting DPI Web Dashboard on http://localhost:3000
echo ========================================================
cd /d "%~dp0web"
npm run dev
