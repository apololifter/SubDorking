#!/usr/bin/env bash
# ── Sube SubDork a GitHub ──────────────────────────────────────────────
# Repo destino: https://github.com/apololifter/SubDorking.git
set -e
cd "$(dirname "$0")"

command -v git >/dev/null || { echo "[ERROR] git no esta instalado"; exit 1; }

[ -d .git ] || git init
git add -A
git commit -m "SubDork: recon recursivo de subdominios + Google dorks en vivo" || true
git branch -M main
git remote remove origin 2>/dev/null || true
git remote add origin https://github.com/apololifter/SubDorking.git

echo
echo " Subiendo a GitHub... (te pedira usuario/token si no hay credenciales guardadas)"
echo
git push -u origin main
echo
echo " Listo -> https://github.com/apololifter/SubDorking"
