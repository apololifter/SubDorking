"""Sonda de diagnóstico para el 400 de Serper.

Prueba variantes de una misma query (de simple a compleja) y muestra el
status HTTP + el cuerpo del error de Serper. En una sola corrida deja claro
qué parte de un dork dispara el 400: comillas, paréntesis, operadores,
longitud, o los parámetros extra (num/gl/hl).

Uso (desde backend/):
    python probe_serper.py TU_API_KEY [host]

Gasta ~6 créditos. No hardcodees la key.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import httpx  # noqa: E402

from verify import _SERPER_URL  # noqa: E402


async def probe(key: str, host: str) -> None:
    variants = [
        ("baseline simple", f"site:{host}"),
        ("una comilla/frase", f'site:{host} intext:"login"'),
        ("parentesis en frase", f'site:{host} intext:"error_reporting(E_ALL)"'),
        ("intitle con ()", f'site:{host} intitle:"phpinfo()"'),
        ("operador OR", f'site:{host} inurl:"config.php" OR inurl:"config.inc.php"'),
        ("dork #1 completo",
         f'site:{host} intext:"error_reporting(E_ALL)" intitle:"phpinfo()" -github.com'),
    ]
    headers = {"X-API-KEY": key.strip(), "Content-Type": "application/json"}
    async with httpx.AsyncClient(timeout=25, headers=headers) as c:
        print(f"host={host}\n")
        for name, q in variants:
            r = await c.post(_SERPER_URL, json={"q": q, "num": 10, "gl": "us", "hl": "en"})
            if r.status_code == 200:
                n = len((r.json().get("organic") or []))
                print(f"[200] {name:22} organic={n}")
            else:
                body = r.text[:200].replace("\n", " ").strip()
                print(f"[{r.status_code}] {name:22} → {body}")
            await asyncio.sleep(0.5)

        # el mismo dork completo pero con body MÍNIMO (solo q, sin num/gl/hl)
        q = variants[-1][1]
        r = await c.post(_SERPER_URL, json={"q": q})
        tag = "OK" if r.status_code == 200 else r.text[:200].replace("\n", " ").strip()
        print(f"\n[{r.status_code}] dork #1 con body mínimo (solo q) → {tag}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("uso: python probe_serper.py TU_API_KEY [host]")
        raise SystemExit(2)
    host = sys.argv[2] if len(sys.argv) > 2 else "tgr.cl"
    asyncio.run(probe(sys.argv[1], host))
