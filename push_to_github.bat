@echo off
REM ── Sube SubDork a GitHub ──────────────────────────────────────────────
REM Repo destino: https://github.com/apololifter/SubDorking.git
REM Requiere git instalado y sesion iniciada en GitHub (token o credential manager).
cd /d "%~dp0"

where git >nul 2>nul || (echo [ERROR] git no esta en el PATH & pause & exit /b 1)

if not exist ".git" git init
git add -A
git commit -m "SubDork: recon recursivo de subdominios + Google dorks en vivo"
git branch -M main
git remote remove origin >nul 2>nul
git remote add origin https://github.com/apololifter/SubDorking.git

echo.
echo  Subiendo a GitHub... (te pedira usuario/token si no tienes credenciales guardadas)
echo.
git push -u origin main

echo.
echo  Listo. Revisa https://github.com/apololifter/SubDorking
pause
