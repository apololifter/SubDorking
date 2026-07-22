"""Verificación de dorks: comprueba qué dorks devuelven resultados reales.

Dos motores:
  * duckduckgo -> endpoint HTML de DuckDuckGo. NO requiere instalar nada ni claves.
                  Ideal para empezar. Puede limitarte si disparas mucho volumen
                  (usa delay). Es la opción por defecto.
  * searxng    -> tu instancia self-hosted de SearXNG (JSON API). Sin límites de
                  pago; requiere levantar el contenedor (ver README).

Un dork cuenta como "hallazgo" si el motor devuelve al menos un resultado.
Se respeta concurrencia, delay y un tope de consultas.
"""
from __future__ import annotations

import asyncio
import re
import urllib.parse
from typing import Awaitable, Callable

import httpx

from dorks import build_google_url, build_query

EventCB = Callable[[dict], Awaitable[None]]
_UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
       "Accept": "text/html,application/xhtml+xml"}

_DDG_RE = re.compile(r'class="result__a"[^>]*href="([^"]+)"')
_BING_RE = re.compile(r'<li class="b_algo".*?<h2>\s*<a[^>]*href="(https?://[^"]+)"', re.S)


def _decode_ddg(href: str) -> str:
    if "uddg=" in href:
        qs = urllib.parse.urlparse(href).query
        u = urllib.parse.parse_qs(qs).get("uddg", [None])[0]
        if u:
            return u
    return href


async def _search_duckduckgo(client: httpx.AsyncClient, base: str, query: str) -> list[str]:
    r = await client.get("https://html.duckduckgo.com/html/", params={"q": query})
    r.raise_for_status()
    html = r.text
    if "result__a" not in html and ("anomaly" in html.lower() or "blocked" in html.lower()):
        raise RuntimeError("DuckDuckGo bloqueó la consulta (rate limit); sube el delay")
    return [_decode_ddg(h) for h in _DDG_RE.findall(html)]


async def _search_bing(client: httpx.AsyncClient, base: str, query: str) -> list[str]:
    r = await client.get("https://www.bing.com/search",
                         params={"q": query, "count": 10, "setlang": "en"})
    r.raise_for_status()
    html = r.text
    links = _BING_RE.findall(html)
    if not links and "b_algo" not in html:
        low = html.lower()
        if "captcha" in low or "verify you are a human" in low or "unusual traffic" in low:
            raise RuntimeError("Bing pidió CAPTCHA (rate limit); sube el delay o usa SearXNG")
    return links


async def _search_searxng(client: httpx.AsyncClient, base: str, query: str) -> list[str]:
    r = await client.get(f"{base}/search", params={"q": query, "format": "json"})
    r.raise_for_status()
    data = r.json()
    return [(x or {}).get("url") for x in (data.get("results") or [])]


_SERPER_URL = "https://google.serper.dev/search"


async def _search_serper(client: httpx.AsyncClient, base: str, query: str) -> list[str]:
    """Serper.dev — API gestionada sobre Google (proxies+captcha resueltos por ellos).

    La API key va en la cabecera X-API-KEY (se fija en el cliente; ver verify_host/ping).
    Cada consulta consume 1 crédito. Resultados en organic[].link.
    """
    r = await client.post(_SERPER_URL, json={"q": query, "num": 10, "gl": "us", "hl": "en"})
    if r.status_code >= 400:
        try:
            body = r.text[:200].replace("\n", " ").strip()
        except Exception:  # noqa: BLE001
            body = ""
        if r.status_code in (401, 403):
            raise RuntimeError(f"Serper: API key inválida o sin permiso (HTTP {r.status_code}) {body}")
        if r.status_code == 402:
            raise RuntimeError(f"Serper: sin créditos (402); recarga en tu panel. {body}")
        if r.status_code == 429:
            raise RuntimeError("Serper: límite de tasa (429); baja la concurrencia o sube el delay")
        # 400 u otros: el cuerpo de Serper explica el motivo real
        raise RuntimeError(f"Serper HTTP {r.status_code}: {body}")
    data = r.json()
    return [(x or {}).get("link") for x in (data.get("organic") or []) if (x or {}).get("link")]


_ENGINES = {"bing": _search_bing, "duckduckgo": _search_duckduckgo,
            "searxng": _search_searxng, "serper": _search_serper}


def _client_headers(engine: str, api_key: str = "") -> dict:
    """Cabeceras del cliente HTTP; Serper añade su API key."""
    headers = dict(_UA)
    if engine == "serper" and api_key:
        headers["X-API-KEY"] = api_key.strip()
    return headers


async def ping(engine: str, base_url: str = "", api_key: str = "", timeout: int = 12) -> dict:
    """Comprueba que el motor de verificación responde."""
    engine = engine or "bing"
    if engine not in _ENGINES:
        return {"ok": False, "error": f"motor desconocido: {engine}"}
    if engine == "searxng" and not (base_url or "").strip():
        return {"ok": False, "error": "falta la URL de SearXNG"}
    if engine == "serper" and not (api_key or "").strip():
        return {"ok": False, "error": "falta la API key de Serper"}
    base = (base_url or "").strip().rstrip("/")
    headers = _client_headers(engine, api_key)
    try:
        async with httpx.AsyncClient(timeout=timeout, headers=headers, follow_redirects=True) as c:
            await _ENGINES[engine](c, base, "site:example.com")
    except httpx.ConnectError:
        where = base or "el motor"
        return {"ok": False, "error": f"no se pudo conectar a {where} (¿está corriendo/accesible?)"}
    except httpx.HTTPStatusError as exc:
        code = exc.response.status_code
        hint = " (¿limiter activo? permite localhost)" if code == 403 and engine == "searxng" else ""
        if engine == "searxng" and code == 404:
            hint = " (¿habilitaste 'formats: [html, json]' en settings.yml?)"
        return {"ok": False, "error": f"HTTP {code}{hint}"}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    return {"ok": True}


async def verify_host(
    host: str,
    dorks: list[tuple[str, str]],
    on_event: EventCB,
    engine: str = "bing",
    base_url: str = "",
    api_key: str = "",
    is_disconnected: Callable[[], Awaitable[bool]] | None = None,
    max_queries: int = 150,
    concurrency: int = 3,
    delay: float = 1.0,
):
    """Verifica los dorks de un host, transmitiendo hallazgos en vivo."""
    engine = engine or "bing"
    search = _ENGINES.get(engine)
    if search is None:
        await on_event({"type": "verify_error", "host": host, "message": f"motor desconocido: {engine}"})
        await on_event({"type": "verify_done", "host": host, "checked": 0, "hits": 0, "errored": True})
        return
    if engine == "serper" and not (api_key or "").strip():
        await on_event({"type": "verify_error", "host": host, "message": "falta la API key de Serper"})
        await on_event({"type": "verify_done", "host": host, "checked": 0, "hits": 0, "errored": True})
        return

    base = (base_url or "").strip().rstrip("/")
    subset = dorks[: max(1, max_queries)]
    total = len(subset)
    await on_event({"type": "verify_start", "host": host, "total": total, "engine": engine})

    sem = asyncio.Semaphore(max(1, concurrency))
    checked = 0
    hits = 0
    stop = False
    errored = False

    headers = _client_headers(engine, api_key)
    async with httpx.AsyncClient(timeout=25, headers=headers, follow_redirects=True) as client:

        # Prueba base: 'site:host' debería devolver resultados si el motor funciona
        # y el host está indexado. Si da 0, el problema es el motor, no los dorks.
        try:
            base_hits = await search(client, base, f"site:{host}")
            await on_event({"type": "verify_baseline", "host": host,
                            "query": f"site:{host}", "count": len(base_hits),
                            "top": base_hits[0] if base_hits else None})
        except Exception as exc:  # noqa: BLE001
            errored = True
            msg = f"{type(exc).__name__}: {exc}"
            if isinstance(exc, httpx.ConnectError):
                msg = f"no se pudo conectar a {base or 'el motor'} (¿está corriendo?)"
            await on_event({"type": "verify_error", "host": host, "message": msg})
            await on_event({"type": "verify_done", "host": host, "checked": 0,
                            "hits": 0, "errored": True})
            return

        async def one(category: str, dork: str):
            nonlocal checked, hits, stop, errored
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
                    results = await search(client, base, query)
                except Exception as exc:  # noqa: BLE001
                    if not stop:
                        stop = True
                        errored = True
                        msg = f"{type(exc).__name__}: {exc}"
                        if isinstance(exc, httpx.ConnectError):
                            msg = f"no se pudo conectar a {base or 'el motor'} (¿está corriendo?)"
                        await on_event({"type": "verify_error", "host": host, "message": msg})
                    return
                checked += 1
                if results:
                    hits += 1
                    await on_event({
                        "type": "dork_hit", "host": host, "category": category,
                        "dork": dork, "query": query,
                        "url": build_google_url(host, dork),
                        "count": len(results),
                        "top": results[0] if results else None,
                    })
                # progreso en cada consulta para que la barra avance suave
                await on_event({"type": "verify_progress", "host": host,
                                "done": checked, "total": total, "hits": hits})
                if delay > 0:
                    await asyncio.sleep(delay)

        await asyncio.gather(*(one(c, d) for c, d in subset))

    await on_event({"type": "verify_done", "host": host, "checked": checked, "hits": hits, "errored": errored})
