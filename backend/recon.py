"""Enumeración recursiva de subdominios.

Fuentes soportadas (se pueden combinar):
  * crtsh     -> Certificate Transparency vía crt.sh  (integrado, sin instalar,
                 sin claves API — la fuente más fiable para empezar)
  * subfinder -> https://github.com/projectdiscovery/subfinder  (binario)
  * amass     -> https://github.com/owasp-amass/amass          (binario, lento)

Cada fuente emite eventos de progreso para que la interfaz muestre en vivo qué
está pasando:
  {"type":"tool_start","tool","target","level"}
  {"type":"subdomain","host","parent","level","source"}
  {"type":"tool_done","tool","target","found","new"}
  {"type":"tool_error","tool","target","message"}
  {"type":"tool_missing","tool"}

La profundidad es configurable: cada subdominio nuevo se reinyecta como objetivo
en el siguiente nivel.
"""
from __future__ import annotations

import asyncio
import re
import shutil
from typing import Awaitable, Callable

import httpx

EventCB = Callable[[dict], Awaitable[None]]
HostCB = Callable[[str], Awaitable[None]]

_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?\.[a-z]{2,}$")

# Fuentes que no son binarios externos.
BUILTIN = {"crtsh"}


def tool_available(name: str) -> bool:
    if name in BUILTIN:
        return True
    return shutil.which(name) is not None


def _clean(line: str) -> str | None:
    line = (line or "").strip().lower()
    if not line:
        return None
    line = line.split()[0]
    line = line.lstrip("*.").rstrip(".")
    if line.startswith("http://") or line.startswith("https://"):
        line = line.split("/", 3)[2] if "/" in line[8:] else line.split("//", 1)[1]
    if "@" in line:
        line = line.split("@")[-1]
    if not _DOMAIN_RE.match(line):
        return None
    return line


# ----------------------------- fuentes ------------------------------------

async def _stream_cmd(cmd: list[str], on_host: HostCB, timeout: int) -> tuple[int, str | None]:
    """Ejecuta un binario y va entregando cada host de su stdout."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        return 0, "binario no encontrado"

    found = 0
    assert proc.stdout is not None
    try:
        while True:
            try:
                raw = await asyncio.wait_for(proc.stdout.readline(), timeout=timeout)
            except asyncio.TimeoutError:
                break
            if not raw:
                break
            host = _clean(raw.decode(errors="ignore"))
            if host:
                found += 1
                await on_host(host)
    finally:
        if proc.returncode is None:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
        err = b""
        try:
            err = await asyncio.wait_for(proc.stderr.read(), timeout=3) if proc.stderr else b""
        except asyncio.TimeoutError:
            pass
        await proc.wait()

    error = None
    if found == 0 and proc.returncode not in (0, None):
        msg = err.decode(errors="ignore").strip().splitlines()
        error = msg[-1] if msg else f"salida con código {proc.returncode}"
    return found, error


async def _run_subfinder(target: str, on_host: HostCB, timeout: int):
    return await _stream_cmd(["subfinder", "-silent", "-d", target], on_host, timeout)


async def _run_amass(target: str, on_host: HostCB, timeout: int):
    return await _stream_cmd(
        ["amass", "enum", "-passive", "-nocolor", "-d", target], on_host, timeout
    )


async def _run_crtsh(target: str, on_host: HostCB, timeout: int):
    """Consulta Certificate Transparency vía crt.sh (JSON)."""
    url = f"https://crt.sh/?q=%25.{target}&output=json"
    try:
        async with httpx.AsyncClient(
            timeout=timeout, headers={"User-Agent": "SubDork/1.0"}, follow_redirects=True
        ) as client:
            r = await client.get(url)
            r.raise_for_status()
            data = r.json()
    except Exception as exc:  # noqa: BLE001
        return 0, f"{type(exc).__name__}: {exc}"

    hosts: set[str] = set()
    for row in data if isinstance(data, list) else []:
        for field in ("name_value", "common_name"):
            val = row.get(field, "") or ""
            for piece in str(val).splitlines():
                h = _clean(piece)
                if h:
                    hosts.add(h)
    found = 0
    for h in sorted(hosts):
        found += 1
        await on_host(h)
    return found, None


RUNNERS = {"crtsh": _run_crtsh, "subfinder": _run_subfinder, "amass": _run_amass}
# timeout por fuente (segundos)
TIMEOUTS = {"crtsh": 40, "subfinder": 90, "amass": 150}


# --------------------------- enumeración ----------------------------------

async def enumerate_domain(
    domain: str,
    depth: int,
    tools: list[str],
    on_event: EventCB,
    max_hosts: int = 5000,
) -> list[str]:
    domain = domain.strip().lower().lstrip("*.")

    active = []
    for t in tools:
        if tool_available(t):
            active.append(t)
        else:
            await on_event({"type": "tool_missing", "tool": t})
    if not active:
        await on_event({"type": "tool_error", "tool": "-", "target": domain,
                        "message": "ninguna fuente disponible (instala subfinder/amass o usa crt.sh)"})
        return []

    discovered: set[str] = set()
    frontier: set[str] = {domain}
    queried: set[str] = set()
    next_frontier: set[str] = set()
    limit_hit = False

    async def emit_host(host: str, parent: str, level: int, source: str):
        """Registra un host (dedupe global) y lo transmite si es nuevo."""
        nonlocal limit_hit
        if not (host == domain or host.endswith("." + domain)):
            return
        if host in discovered or host == domain:
            return
        discovered.add(host)
        next_frontier.add(host)
        await on_event({"type": "subdomain", "host": host, "parent": parent,
                        "level": level, "source": source})
        if len(discovered) >= max_hosts and not limit_hit:
            limit_hit = True
            await on_event({"type": "limit", "max_hosts": max_hosts})

    async def run_one(tool: str, target: str, level: int):
        """Ejecuta UNA fuente sobre UN objetivo, transmitiendo en vivo."""
        await on_event({"type": "tool_start", "tool": tool, "target": target, "level": level})
        new_here = 0

        async def on_host(host: str):
            nonlocal new_here
            before = len(discovered)
            await emit_host(host, target, level, tool)
            if len(discovered) > before:
                new_here += 1

        try:
            found, err = await RUNNERS[tool](target, on_host, TIMEOUTS.get(tool, 90))
        except Exception as exc:  # noqa: BLE001
            found, err = 0, f"{type(exc).__name__}: {exc}"
        if err:
            await on_event({"type": "tool_error", "tool": tool, "target": target, "message": err})
        await on_event({"type": "tool_done", "tool": tool, "target": target,
                        "found": found, "new": new_here})

    for level in range(1, max(1, depth) + 1):
        if not frontier:
            break
        await on_event({"type": "level_start", "level": level, "targets": len(frontier)})
        next_frontier = set()

        # Todas las (fuente × objetivo) del nivel se lanzan EN PARALELO.
        tasks = []
        for target in sorted(frontier):
            if target in queried:
                continue
            queried.add(target)
            for tool in active:
                tasks.append(asyncio.create_task(run_one(tool, target, level)))
        if tasks:
            await asyncio.gather(*tasks)

        await on_event({"type": "level_done", "level": level, "count": len(discovered)})
        if limit_hit:
            break
        frontier = next_frontier

    return sorted(discovered)
