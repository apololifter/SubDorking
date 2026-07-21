#!/usr/bin/env bash
# SubDork - arranque en Linux / macOS
set -e
cd "$(dirname "$0")"

if [ ! -d ".venv" ]; then
  echo "Creando entorno virtual..."
  python3 -m venv .venv
fi
source .venv/bin/activate
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt

echo
echo " SubDork en http://127.0.0.1:8000  (Ctrl+C para detener)"
echo
exec python -m uvicorn app:app --app-dir backend --host 127.0.0.1 --port 8000
