"""SubDork — servidor FastAPI.

Expone:
  GET /                 -> interfaz web
  GET /api/dorks        -> base de dorks (categorías) para render en cliente
  GET /api/config       -> fuentes disponibles y totales
  GET /api/scan/stream  -> flujo SSE de la enumeración de subdominios en vivo

Las fuentes de enumeración (crt.sh / subfinder / amass) se lanzan EN PARALELO y
cada subdominio se transmite apenas se descubre. Los dorks se ejecutan a mano:
la interfaz arma para cada subdominio el catálogo completo de dorks como enlaces
clicables a Google.

Uso responsable: solo en objetivos que tengas autorización explícita a evaluar.
"""
from __future__ import annotations

import asyncio
import json
import random
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse

from dorks import DorkDB
from recon import enumerate_domain, tool_available

BASE = Path(__file__).resolve().parent.parent
FRONTEND = BASE / "frontend" / "index.html"

app = FastAPI(title="SubDork")
DORKS = DorkDB.load()


def _sse(event: dict) -> str:
    return f"data: {json.dumps(event, ensure_ascii=False)}\n\n"


@app.get("/")
async def index():
    return FileResponse(FRONTEND)


@app.get("/api/dorks")
async def api_dorks():
    return JSONResponse({"total": DORKS.total, "categories": DORKS.categories})


@app.get("/api/config")
async def api_config():
    return JSONResponse(
        {
            "tools": {
                "crtsh": True,
                "subfinder": tool_available("subfinder"),
                "amass": tool_available("amass"),
            },
            "total_dorks": DORKS.total,
            "total_categories": len(DORKS.categories),
        }
    )


async def _demo_enumerate(domain: str, depth: int, on_event):
    """Genera subdominios ficticios para probar la interfaz sin herramientas."""
    words = [
        "www", "api", "dev", "staging", "mail", "admin", "vpn", "cdn", "app",
        "test", "portal", "shop", "blog", "beta", "internal", "git", "jenkins",
    ]
    await on_event({"type": "level_start", "level": 1, "targets": 1})
    await on_event({"type": "tool_start", "tool": "demo", "target": domain, "level": 1})
    seen = []
    for w in random.sample(words, 8):
        await asyncio.sleep(0.35)  # simula el flujo en vivo
        host = f"{w}.{domain}"
        seen.append(host)
        await on_event({"type": "subdomain", "host": host, "parent": domain,
                        "level": 1, "source": "demo"})
    await on_event({"type": "tool_done", "tool": "demo", "target": domain,
                    "found": len(seen), "new": len(seen)})
    await on_event({"type": "level_done", "level": 1, "count": len(seen)})
    if depth >= 2:
        await on_event({"type": "level_start", "level": 2, "targets": min(3, len(seen))})
        for base in seen[:3]:
            for w in random.sample(["auth", "v2", "old", "docs"], 2):
                await asyncio.sleep(0.25)
                host = f"{w}.{base}"
                seen.append(host)
                await on_event({"type": "subdomain", "host": host, "parent": base,
                                "level": 2, "source": "demo"})
        await on_event({"type": "level_done", "level": 2, "count": len(seen)})
    return sorted(set(seen))


async def _run_scan(request: Request, params: dict):
    """Generador SSE principal."""
    queue: asyncio.Queue = asyncio.Queue()

    async def emit(ev: dict):
        await queue.put(ev)

    domain = params["domain"]
    depth = params["depth"]
    tools = params["tools"]
    demo = params["demo"]

    async def worker():
        try:
            await emit({
                "type": "start", "domain": domain, "depth": depth,
                "tools": tools, "demo": demo, "total_dorks": DORKS.total,
            })
            if demo:
                hosts = await _demo_enumerate(domain, depth, emit)
            else:
                hosts = await enumerate_domain(domain, depth, tools, emit)

            # El dominio raíz también sirve como objetivo de dorks.
            targets = [domain] + [h for h in hosts if h != domain]
            await emit({"type": "enum_done", "count": len(hosts), "targets": len(targets)})
            await emit({"type": "done", "subdomains": len(hosts), "targets": len(targets)})
        except Exception as exc:  # noqa: BLE001
            await emit({"type": "error", "message": str(exc)})
        finally:
            await queue.put(None)

    task = asyncio.create_task(worker())
    try:
        while True:
            ev = await queue.get()
            if ev is None:
                break
            yield _sse(ev)
    finally:
        task.cancel()


@app.get("/api/scan/stream")
async def scan_stream(request: Request):
    q = request.query_params
    domain = (q.get("domain") or "").strip().lower().lstrip("*.")
    if not domain or "." not in domain:
        return JSONResponse({"error": "dominio inválido"}, status_code=400)
    try:
        depth = max(1, min(4, int(q.get("depth", "1"))))
    except ValueError:
        depth = 1
    tools = [t for t in (q.get("tools", "crtsh,subfinder").split(",")) if t]
    demo = q.get("demo", "0") in ("1", "true", "yes")

    params = {"domain": domain, "depth": depth, "tools": tools, "demo": demo}
    return StreamingResponse(
        _run_scan(request, params),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
