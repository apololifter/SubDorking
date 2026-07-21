@echo off
REM SubDork - arranque en Windows
cd /d "%~dp0"
where python >nul 2>nul || (echo Python no encontrado en PATH & pause & exit /b 1)

if not exist ".venv" (
  echo Creando entorno virtual...
  python -m venv .venv
)
call .venv\Scripts\activate.bat
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r requirements.txt

echo.
echo  SubDork corriendo en http://127.0.0.1:8000
echo  (Ctrl+C para detener)
echo.
python -m uvicorn app:app --app-dir backend --host 127.0.0.1 --port 8000
pause
