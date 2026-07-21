"""SubDork — servidor FastAPI.

Expone:
  GET /                    -> interfaz web
  GET /api/dorks           -> base de dorks (categorías) para render en cliente
  GET /api/config          -> herramientas disponibles y valores por defecto
  GET /api/scan/stream     -> flujo SSE de la enumeración + dorks en vivo

Uso responsable: esta herramienta es para reconocimiento en objetivos que
tengas autorización explícita a evaluar (bug bounty, pentest con permiso,
tus propios dominios). Verifica siempre el alcance antes de escanear.
"""
from __future__ import annotations

import asyncio
import json
import random
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse

from dorks import DorkDB, build_google_url, build_query
from recon import enumerate_domain, tool_available
from verify import Verifier, VerifyConfig

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
    seen = []
    for i, w in enumerate(random.sample(words, 8)):
        await asyncio.sleep(0.4)  # simula el flujo en vivo
        host = f"{w}.{domain}"
        seen.append(host)
        await on_event({"type": "subdomain", "host": host, "parent": domain, "level": 1})
    await on_event({"type": "level_done", "level": 1, "count": len(seen)})
    if depth >= 2:
        await on_event({"type": "level_start", "level": 2, "targets": len(seen)})
        for base in seen[:3]:
            for w in random.sample(["auth", "v2", "old", "docs"], 2):
                await asyncio.sleep(0.3)
                host = f"{w}.{base}"
                seen.append(host)
                await on_event({"type": "subdomain", "host": host, "parent": base, "level": 2})
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
    vcfg: VerifyConfig = params["vcfg"]

    async def worker():
        try:
            await emit(
                {
                    "type": "start",
                    "domain": domain,
                    "depth": depth,
                    "tools": tools,
                    "demo": demo,
                    "verify": vcfg.provider if vcfg.enabled else "none",
                    "total_dorks": DORKS.total,
                }
            )
            # 1) Enumeración de subdominios (streaming a paneles colapsables)
            if demo:
                hosts = await _demo_enumerate(domain, depth, emit)
            else:
                hosts = await enumerate_domain(domain, depth, tools, emit)

            # Incluimos el dominio raíz como objetivo de dorks también.
            targets = [domain] + [h for h in hosts if h != domain]
            await emit({"type": "enum_done", "count": len(hosts), "targets": len(targets)})

            # 2) Verificación de dorks (sólo si hay API key). Sin key, el cliente
            #    ya construye los enlaces clicables por su cuenta.
            if vcfg.enabled:
                async with Verifier(vcfg) as verifier:
                    for host in targets:
                        await emit({"type": "dorks_start", "host": host})
                        hits = 0
                        for category, dork in DORKS.iter_dorks():
                            if await request.is_disconnected():
                                return
                            query = build_query(host, dork)
                            res = await verifier.check(query)
                            if res is None:
                                continue
                            if res.get("_exhausted"):
                                await emit({"type": "budget_exhausted", "host": host})
                                break
                            if res.get("_error"):
                                await emit({"type": "verify_error", "host": host,
                                            "message": res["_error"]})
                                continue
                            hits += 1
                            await emit(
                                {
                                    "type": "dork_hit",
                                    "host": host,
                                    "category": category,
                                    "dork": dork,
                                    "query": query,
                                    "url": build_google_url(host, dork),
                                    "count": res.get("count"),
                                    "top": res.get("top"),
                                }
                            )
                        await emit({"type": "dorks_done", "host": host, "hits": hits})
                        await emit({"type": "verify_budget", "left": verifier.budget_left})

            await emit({"type": "done", "subdomains": len(hosts), "targets": len(targets)})
        except Exception as exc:  # noqa: BLE001
            await emit({"type": "error", "message": str(exc)})
        finally:
            await queue.put(None)  # centinela de fin

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
        depth = max(1, min(4, int(q.get("depth", "2"))))
    except ValueError:
        depth = 2
    tools = [t for t in (q.get("tools", "subfinder,amass").split(",")) if t]
    demo = q.get("demo", "0") in ("1", "true", "yes")

    provider = q.get("provider", "none")
    vcfg = VerifyConfig(
        provider=provider,
        api_key=q.get("api_key", ""),
        cx=q.get("cx", ""),
        concurrency=int(q.get("concurrency", "3") or 3),
        delay=float(q.get("delay", "1.0") or 1.0),
        max_queries=int(q.get("max_queries", "300") or 300),
    )

    params = {"domain": domain, "depth": depth, "tools": tools, "demo": demo, "vcfg": vcfg}
    return StreamingResponse(
        _run_scan(request, params),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
