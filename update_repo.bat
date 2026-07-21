@echo off
REM ── Sincroniza los archivos de esta carpeta con el repo y hace push ──────
REM Copia todo (menos .git) a C:\SubDorking, commitea y sube a GitHub.
setlocal
cd /d "%~dp0"

set "DST=C:\SubDorking"
where git >nul 2>nul || (echo [ERROR] git no esta en el PATH & pause & exit /b 1)

echo Copiando archivos nuevos a "%DST%" ...
if not exist "%DST%" mkdir "%DST%"
robocopy "%~dp0." "%DST%" /E /XD .git .venv __pycache__ /XF *.pyc >nul

cd /d "%DST%"
if not exist ".git" git init
git add -A
git commit -m "Actualizacion SubDork: crt.sh + fuentes en paralelo, UI con consola, dorks manuales"
git branch -M main
git remote get-url origin >nul 2>nul || git remote add origin https://github.com/apololifter/SubDorking.git

echo.
echo  Subiendo a GitHub... (te pedira usuario/token si no hay credenciales guardadas)
echo.
git push -u origin main

echo.
echo  Listo -^> https://github.com/apololifter/SubDorking
pause
