"""Carga de la base de dorks y construcción de URLs de Google."""
from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import quote_plus

DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "dorks.json"

# Patrón para detectar si un dork ya trae un operador site: propio.
_SITE_RE = re.compile(r"\bsite:", re.IGNORECASE)


class DorkDB:
    """Contenedor en memoria de las categorías de dorks."""

    def __init__(self, categories: list[dict]):
        self.categories = categories
        self._total = sum(len(c["dorks"]) for c in categories)

    @classmethod
    def load(cls, path: Path | str = DATA_FILE) -> "DorkDB":
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return cls(data["categories"])

    @property
    def total(self) -> int:
        return self._total

    def category_names(self) -> list[str]:
        return [c["category"] for c in self.categories]

    def iter_dorks(self):
        """Genera (categoria, dork) para toda la base."""
        for cat in self.categories:
            for dork in cat["dorks"]:
                yield cat["category"], dork


def build_query(subdomain: str, dork: str) -> str:
    """Combina el subdominio con el dork.

    Si el dork ya contiene site:, se respeta tal cual (solo se ancla al
    subdominio si no menciona ningún dominio). En el resto de casos se
    antepone `site:<subdominio>`.
    """
    dork = dork.strip()
    if _SITE_RE.search(dork):
        return dork
    return f"site:{subdomain} {dork}"


def build_google_url(subdomain: str, dork: str) -> str:
    """Devuelve la URL de búsqueda de Google lista para abrir en el navegador."""
    return "https://www.google.com/search?q=" + quote_plus(build_query(subdomain, dork))
