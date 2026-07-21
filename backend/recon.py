"""Enumeración recursiva de subdominios con subfinder y amass.

El módulo lanza las herramientas como subprocesos, deduplica resultados y
entrega cada subdominio nuevo a través de un callback asíncrono para poder
transmitirlo en vivo a la interfaz. La profundidad es configurable:

    depth = 1  ->  dominio -> subdominios directos
    depth = 2  ->  además reinyecta cada subdominio para buscar sub-subdominios
    depth = N  ->  repite el proceso N niveles

Si una herramienta no está instalada, se omite silenciosamente (se reporta un
evento de aviso) para que el flujo siga funcionando con la que sí esté.
"""
from __future__ import annotations

import asyncio
import re
import shutil
from typing import Awaitable, Callable

# Callback: recibe un dict de evento y lo encola hacia el frontend.
EventCB = Callable[[dict], Awaitable[None]]

_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}$")


def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def _clean(line: str) -> str | None:
    line = line.strip().lower()
    # amass a veces imprine formato "sub --> tipo --> valor"; nos quedamos con hosts.
    line = line.split()[0] if line else ""
    line = line.strip().rstrip(".")
    if not line or not _DOMAIN_RE.match(line):
        return None
    return line


async def _run(cmd: list[str], timeout: int) -> set[str]:
    """Ejecuta un comando y devuelve el conjunto de hosts válidos de su stdout."""
    found: set[str] = set()
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
    except FileNotFoundError:
        return found
    try:
        assert proc.stdout is not None
        while True:
            try:
                raw = await asyncio.wait_for(proc.stdout.readline(), timeout=timeout)
            except asyncio.TimeoutError:
                break
            if not raw:
                break
            host = _clean(raw.decode(errors="ignore"))
            if host:
                found.add(host)
    finally:
        if proc.returncode is None:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
        await proc.wait()
    return found


async def _subfinder(domain: str, timeout: int) -> set[str]:
    return await _run(["subfinder", "-silent", "-d", domain], timeout)


async def _amass(domain: str, timeout: int) -> set[str]:
    # -passive evita escaneo activo/ruidoso; ideal para recon inicial autorizado.
    return await _run(["amass", "enum", "-passive", "-nocolor", "-d", domain], timeout)


async def enumerate_domain(
    domain: str,
    depth: int,
    tools: list[str],
    on_event: EventCB,
    per_tool_timeout: int = 180,
    max_hosts: int = 5000,
) -> list[str]:
    """Enumera subdominios de `domain` hasta `depth` niveles.

    Emite eventos:
      {"type": "subdomain", "host": ..., "parent": ..., "level": n}
      {"type": "level", "level": n, "count": k}
      {"type": "tool_missing", "tool": ...}
    Devuelve la lista final ordenada de subdominios únicos.
    """
    domain = domain.strip().lower().lstrip("*.")
    active_tools = []
    for t in tools:
        if tool_available(t):
            active_tools.append(t)
        else:
            await on_event({"type": "tool_missing", "tool": t})

    discovered: set[str] = set()
    # frontera del nivel actual: dominios a los que aún hay que consultar
    frontier: set[str] = {domain}
    queried: set[str] = set()

    for level in range(1, max(1, depth) + 1):
        if not frontier:
            break
        await on_event({"type": "level_start", "level": level, "targets": len(frontier)})
        next_frontier: set[str] = set()

        for target in sorted(frontier):
            if target in queried:
                continue
            queried.add(target)

            results: set[str] = set()
            jobs = []
            if "subfinder" in active_tools:
                jobs.append(_subfinder(target, per_tool_timeout))
            if "amass" in active_tools:
                jobs.append(_amass(target, per_tool_timeout))
            if not jobs:
                break

            for coro in asyncio.as_completed(jobs):
                partial = await coro
                for host in sorted(partial):
                    if host in results:
                        continue
                    results.add(host)
                    # Sólo nos interesan hosts que pertenecen al árbol del dominio raíz.
                    if not (host == domain or host.endswith("." + domain)):
                        continue
                    if host in discovered or host == domain:
                        continue
                    discovered.add(host)
                    next_frontier.add(host)
                    await on_event(
                        {
                            "type": "subdomain",
                            "host": host,
                            "parent": target,
                            "level": level,
                        }
                    )
                    if len(discovered) >= max_hosts:
                        await on_event({"type": "limit", "max_hosts": max_hosts})
                        return sorted(discovered)

        await on_event({"type": "level_done", "level": level, "count": len(discovered)})
        frontier = next_frontier

    return sorted(discovered)
