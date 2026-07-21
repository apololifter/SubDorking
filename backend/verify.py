"""Verificación de dorks contra una instancia self-hosted de SearXNG.

SearXNG (https://github.com/searxng/searxng) es un metabuscador open-source que
corres tú mismo (Docker). Expone una API JSON sin clave ni facturación:

    GET {base}/search?q=<dork>&format=json  ->  {"results": [...], ...}

Aquí consultamos cada dork y consideramos que hay "hallazgo" si devuelve al
menos un resultado. Se respeta concurrencia, delay y un tope de consultas para
no martillar los motores de origen.

Nota: para que la API JSON funcione, en el settings.yml de SearXNG debes tener
    search:
      formats: [html, json]
y, si el limiter está activo, permitir el acceso desde localhost.
"""
from __future__ import annotations

import asyncio
from typing import Awaitable, Callable

import httpx

from dorks import build_google_url, build_query

EventCB = Callable[[dict], Awaitable[None]]
_UA = {"User-Agent": "Mozilla/5.0 (SubDork verify)"}


async def ping(base_url: str, timeout: int = 10) -> dict:
    """Comprueba que SearXNG responde y entrega JSON."""
    base = (base_url or "").strip().rstrip("/")
    if not base:
        return {"ok": False, "error": "sin URL"}
    try:
        async with httpx.AsyncClient(timeout=timeout, headers=_UA, follow_redirects=True) as c:
            r = await c.get(f"{base}/search", params={"q": "test", "format": "json"})
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    if r.status_code != 200:
        hint = " (¿limiter activo? permite localhost o desactívalo)" if r.status_code == 403 else ""
        return {"ok": False, "error": f"HTTP {r.status_code}{hint}"}
    try:
        r.json()
    except Exception:  # noqa: BLE001
        return {"ok": False, "error": "responde pero no en JSON (habilita 'formats: [html, json]' en settings.yml)"}
    return {"ok": True}


async def verify_host(
    host: str,
    dorks: list[tuple[str, str]],
    base_url: str,
    on_event: EventCB,
    is_disconnected: Callable[[], Awaitable[bool]] | None = None,
    max_queries: int = 200,
    concurrency: int = 3,
    delay: float = 1.0,
):
    """Verifica los dorks de un host, transmitiendo hallazgos en vivo."""
    base = base_url.strip().rstrip("/")
    subset = dorks[: max(1, max_queries)]
    total = len(subset)
    await on_event({"type": "verify_start", "host": host, "total": total})

    sem = asyncio.Semaphore(max(1, concurrency))
    checked = 0
    hits = 0
    stop = False

    async with httpx.AsyncClient(timeout=25, headers=_UA, follow_redirects=True) as client:

        async def one(category: str, dork: str):
            nonlocal checked, hits, stop
            if stop:
                return
            async with sem:
                if stop:
                    return
                if is_disconnected is not None and await is_disconnected():
                    stop = True
                    return
                query = build_query(host, dork)
                try:
                    r = await client.get(f"{base}/search", params={"q": query, "format": "json"})
                    r.raise_for_status()
                    data = r.json()
                except Exception as exc:  # noqa: BLE001
                    if not stop:
                        stop = True
                        await on_event({"type": "verify_error", "host": host,
                                        "message": f"{type(exc).__name__}: {exc}"})
                    return
                checked += 1
                results = data.get("results") or []
                if results:
                    hits += 1
                    await on_event({
                        "type": "dork_hit", "host": host, "category": category,
                        "dork": dork, "query": query,
                        "url": build_google_url(host, dork),
                        "count": len(results),
                        "top": (results[0] or {}).get("url"),
                    })
                if checked % 5 == 0:
                    await on_event({"type": "verify_progress", "host": host,
                                    "done": checked, "hits": hits})
                if delay > 0:
                    await asyncio.sleep(delay)

        await asyncio.gather(*(one(c, d) for c, d in subset))

    await on_event({"type": "verify_done", "host": host, "checked": checked, "hits": hits})
