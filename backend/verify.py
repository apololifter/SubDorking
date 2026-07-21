"""Verificación opcional de dorks contra una API de búsqueda.

Modo híbrido:
  * Sin API key  -> no se verifica nada; el frontend muestra todos los dorks
    como enlaces clicables (rápido, gratis, sin límites).
  * Con API key  -> cada consulta se lanza contra el proveedor elegido y sólo
    se marcan como "hallazgo" los dorks que devuelven al menos un resultado.

Proveedores soportados:
  * google_cse -> Google Custom Search JSON API (necesita api_key + cx)
  * serpapi    -> SerpAPI (necesita api_key)

El scraping directo de google.com/search NO se implementa a propósito: viola
los términos de servicio de Google y se bloquea con CAPTCHA. Usa una API.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass

import httpx


@dataclass
class VerifyConfig:
    provider: str = "none"          # "none" | "google_cse" | "serpapi"
    api_key: str = ""
    cx: str = ""                    # sólo google_cse
    concurrency: int = 3            # consultas en paralelo
    delay: float = 1.0             # segundos entre consultas por worker
    max_queries: int = 300          # tope de seguridad para no gastar cuota

    @property
    def enabled(self) -> bool:
        return self.provider not in ("", "none") and bool(self.api_key)


class Verifier:
    """Ejecuta verificaciones respetando concurrencia, delay y cuota."""

    def __init__(self, cfg: VerifyConfig):
        self.cfg = cfg
        self._sem = asyncio.Semaphore(max(1, cfg.concurrency))
        self._budget = cfg.max_queries
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self):
        self._client = httpx.AsyncClient(timeout=20)
        return self

    async def __aexit__(self, *exc):
        if self._client:
            await self._client.aclose()

    @property
    def budget_left(self) -> int:
        return self._budget

    async def check(self, query: str) -> dict | None:
        """Devuelve {"count": n, "top": url|None} o None si no hay hallazgos.

        Lanza StopIteration-like (retorna {"_exhausted": True}) cuando se agota
        el presupuesto de consultas.
        """
        if not self.cfg.enabled:
            return None
        if self._budget <= 0:
            return {"_exhausted": True}
        async with self._sem:
            self._budget -= 1
            try:
                if self.cfg.provider == "google_cse":
                    res = await self._google_cse(query)
                elif self.cfg.provider == "serpapi":
                    res = await self._serpapi(query)
                else:
                    res = None
            except Exception as exc:  # noqa: BLE001 - reportamos, no rompemos el scan
                return {"_error": str(exc)}
            await asyncio.sleep(self.cfg.delay)
            return res

    async def _google_cse(self, query: str) -> dict | None:
        assert self._client is not None
        params = {"key": self.cfg.api_key, "cx": self.cfg.cx, "q": query, "num": 1}
        r = await self._client.get("https://www.googleapis.com/customsearch/v1", params=params)
        r.raise_for_status()
        data = r.json()
        total = int(data.get("searchInformation", {}).get("totalResults", "0"))
        if total <= 0:
            return None
        items = data.get("items") or []
        top = items[0].get("link") if items else None
        return {"count": total, "top": top}

    async def _serpapi(self, query: str) -> dict | None:
        assert self._client is not None
        params = {"engine": "google", "q": query, "api_key": self.cfg.api_key, "num": 1}
        r = await self._client.get("https://serpapi.com/search.json", params=params)
        r.raise_for_status()
        data = r.json()
        organic = data.get("organic_results") or []
        if not organic:
            return None
        total = data.get("search_information", {}).get("total_results", len(organic))
        return {"count": int(total or len(organic)), "top": organic[0].get("link")}
