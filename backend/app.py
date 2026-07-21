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
import shutil
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse

from dorks import DorkDB
from recon import enumerate_domain, tool_available
from verify import ping as searxng_ping, verify_host

BASE = Path(__file__).resolve().parent.parent
FRONTEND = BASE / "frontend" / "index.html"
SEARXNG_SETTINGS = BASE / "searxng" / "settings.yml"
SEARXNG_URL = "http://localhost:8888"

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
                "anubis": True,
                "alienvault": True,
                "hackertarget": True,
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
    tools = [t for t in (q.get("tools", "crtsh,anubis,alienvault,hackertarget,subfinder").split(",")) if t]
    demo = q.get("demo", "0") in ("1", "true", "yes")

    params = {"domain": domain, "depth": depth, "tools": tools, "demo": demo}
    return StreamingResponse(
        _run_scan(request, params),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# --------------------------- gestión de SearXNG ---------------------------

async def _run_cmd(*args: str, timeout: int = 300):
    try:
        proc = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    except FileNotFoundError:
        return 127, "comando no encontrado"
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        return 124, "timeout"
    return proc.returncode, out.decode(errors="ignore")


async def _searxng_ready() -> bool:
    try:
        async with httpx.AsyncClient(timeout=6) as c:
            r = await c.get(f"{SEARXNG_URL}/search", params={"q": "test", "format": "json"})
        if r.status_code != 200:
            return False
        r.json()
        return True
    except Exception:  # noqa: BLE001
        return False


@app.get("/api/searxng/status")
async def searxng_status():
    return {
        "docker": shutil.which("docker") is not None,
        "ready": await _searxng_ready(),
        "url": SEARXNG_URL,
    }


@app.get("/api/searxng/up")
async def searxng_up():
    """Descarga/levanta y configura SearXNG con Docker (idempotente)."""
    if await _searxng_ready():
        return {"ok": True, "already": True, "url": SEARXNG_URL}
    if shutil.which("docker") is None:
        return {"ok": False, "error": "Docker no está instalado o no está en el PATH"}

    # Recrea el contenedor con nuestra config (JSON habilitado, limiter off).
    await _run_cmd("docker", "rm", "-f", "searxng", timeout=40)
    args = ["docker", "run", "-d", "--name", "searxng", "-p", "8888:8080"]
    if SEARXNG_SETTINGS.exists():
        args += ["-v", f"{SEARXNG_SETTINGS}:/etc/searxng/settings.yml:ro"]
    args += ["searxng/searxng"]
    code, out = await _run_cmd(*args, timeout=600)  # el primer pull puede tardar
    if code != 0:
        return {"ok": False, "error": (out or "no se pudo crear el contenedor").strip()[:300]}

    for _ in range(30):  # espera hasta ~60s a que responda JSON
        if await _searxng_ready():
            return {"ok": True, "url": SEARXNG_URL}
        await asyncio.sleep(2)
    return {"ok": False, "error": "SearXNG arrancó pero aún no responde JSON; reintenta el botón en unos segundos"}


@app.get("/api/verify/ping")
async def verify_ping(request: Request):
    q = request.query_params
    engine = q.get("engine", "bing")
    base = q.get("searxng", "")
    return JSONResponse(await searxng_ping(engine, base))


async def _run_verify(request: Request, host: str, engine: str, base: str,
                      mx: int, conc: int, delay: float):
    queue: asyncio.Queue = asyncio.Queue()

    async def emit(ev: dict):
        await queue.put(ev)

    dorks = list(DORKS.iter_dorks())

    async def worker():
        try:
            await verify_host(host, dorks, emit, engine=engine, base_url=base,
                              is_disconnected=request.is_disconnected,
                              max_queries=mx, concurrency=conc, delay=delay)
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


@app.get("/api/verify/stream")
async def verify_stream(request: Request):
    q = request.query_params
    host = (q.get("host") or "").strip().lower()
    engine = q.get("engine", "bing")
    base = (q.get("searxng") or "").strip()
    if not host or "." not in host:
        return JSONResponse({"error": "host inválido"}, status_code=400)
    if engine == "searxng" and not base:
        return JSONResponse({"error": "falta la URL de SearXNG"}, status_code=400)
    try:
        mx = max(1, min(2000, int(q.get("max", "150"))))
    except ValueError:
        mx = 150
    try:
        conc = max(1, min(8, int(q.get("concurrency", "3"))))
    except ValueError:
        conc = 3
    try:
        delay = max(0.0, float(q.get("delay", "1.0")))
    except ValueError:
        delay = 1.0
    return StreamingResponse(
        _run_verify(request, host, engine, base, mx, conc, delay),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
