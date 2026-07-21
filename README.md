# SubDork

Herramienta local de reconocimiento: enumera subdominios de forma **recursiva**
con `subfinder` y `amass`, los va mostrando **uno a uno en una interfaz web
colapsable mientras cargan**, y dentro de cada subdominio genera **Google dorks**
(1882 dorks en 257 categorías) listos para lanzar con un clic. Opcionalmente
verifica cada dork contra una API de búsqueda y muestra **solo los que tienen
hallazgos**.

> ⚠ **Uso autorizado únicamente.** Ejecútalo solo sobre dominios que te
> pertenezcan o para los que tengas permiso explícito (bug bounty en alcance,
> pentest contratado). Tú eres responsable del uso que le des.

---

## Cómo funciona

```
dominio  ──subfinder+amass──►  subdominios (nivel 1)
                                  │  reinyecta cada uno
                                  ▼
                              sub-subdominios (nivel 2) ... hasta la profundidad elegida
                                  │
                                  ▼
   cada subdominio  ──►  panel colapsable  ──►  1290 dorks clicables por categoría
                                                (o solo los verificados con hallazgos)
```

- **Streaming en vivo (SSE):** cada subdominio aparece en la interfaz apenas se
  descubre, sin esperar a que termine todo.
- **Profundidad configurable (1–4):** cuántos niveles de recursión.
- **Dorks con un clic:** cada dork es un enlace `site:<subdominio> <dork>` que
  abre Google en una pestaña nueva. Si un dork ya trae su propio `site:`
  (p. ej. dorks de descubrimiento de programas bug bounty), se respeta tal cual.
- **Modo híbrido de verificación:** sin API key ves todos los dorks como enlaces;
  con API key solo aparecen los que devuelven resultados.

## Requisitos

1. **Python 3.9+**
2. **subfinder** y **amass** (opcionales pero recomendados; sin ellos usa el *modo demo*):
   - subfinder: https://github.com/projectdiscovery/subfinder → `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`
   - amass: https://github.com/owasp-amass/amass → `go install github.com/owasp-amass/amass/v4/...@master`
   - En Windows también hay binarios `.exe` en la sección *Releases* de cada repo.
     Deben quedar en el `PATH` para que SubDork los detecte.

## Arranque

**Windows:** doble clic en `run.bat` (crea el entorno virtual, instala
dependencias y levanta el servidor).

**Linux / macOS:**
```bash
chmod +x run.sh && ./run.sh
```

Luego abre **http://127.0.0.1:8000** en tu navegador.

Manual (cualquier SO):
```bash
pip install -r requirements.txt
python -m uvicorn app:app --app-dir backend --host 127.0.0.1 --port 8000
```

## Uso

1. Escribe el dominio (ej. `ejemplo.com`) y elige la profundidad.
2. Marca `subfinder` / `amass`. Si no los tienes instalados, activa **modo demo**
   para ver la interfaz funcionando con datos ficticios.
3. **Escanear.** Los subdominios van apareciendo como paneles colapsables.
4. Abre un panel para ver los dorks agrupados por categoría; usa el buscador
   interno para filtrar. Clic en un dork → se abre la búsqueda en Google.

### Verificación por API (opcional)

Despliega *"Verificación por API"* y elige proveedor:

- **Google CSE** (Custom Search JSON API): necesita `API key` + `cx`
  (ID del motor). 100 consultas/día gratis. Alta en
  https://developers.google.com/custom-search/v1/overview
- **SerpAPI**: necesita solo `API key`. https://serpapi.com

Con verificación activa, SubDork consulta cada dork y **solo lista los que
devuelven resultados**, con el conteo aproximado y el primer enlace. Como son
1290 dorks por subdominio, ajusta **Máx. consultas** para no agotar tu cuota
(el tope por defecto es 300 consultas por escaneo).

## Subir a GitHub

El repositorio destino es **https://github.com/apololifter/SubDorking**.

**Opción rápida:** ejecuta `push_to_github.bat` (Windows) o `./push_to_github.sh`
(Linux/macOS). Hace `init` + `commit` + `push` a `main`. Te pedirá tu usuario y
un **token de acceso personal** de GitHub (no la contraseña) si no tienes
credenciales guardadas — créalo en GitHub → Settings → Developer settings →
Personal access tokens, con permiso `repo`.

**Opción manual:**
```bash
cd subdork
git init
git add -A
git commit -m "SubDork: primera version"
git branch -M main
git remote add origin https://github.com/apololifter/SubDorking.git
git push -u origin main
```

Si el repo remoto ya tiene commits (por ejemplo un README creado en GitHub),
primero integra: `git pull origin main --allow-unrelated-histories` y vuelve a
hacer `push`.

## Estructura

```
subdork/
├─ backend/
│  ├─ app.py      API FastAPI + streaming SSE
│  ├─ recon.py    subfinder/amass recursivo
│  ├─ dorks.py    carga de dorks y armado de URLs
│  └─ verify.py   verificación opcional por API
├─ data/dorks.json   1882 dorks / 257 categorías (multi-fuente)
├─ _sources/         listas crudas + merge.py (regenera dorks.json)
├─ frontend/index.html   interfaz colapsable
├─ requirements.txt · run.bat · run.sh
├─ push_to_github.bat · push_to_github.sh   subida al repo
└─ LICENSE
```

## Notas

- No se hace scraping directo de google.com/search (lo bloquea con CAPTCHA y
  viola sus términos): la verificación usa APIs oficiales.
- `amass` corre en modo `-passive` para un reconocimiento silencioso.
- La base de dorks combina varias fuentes públicas (ver abajo). Al integrarlas
  se aplicó un **filtro de calidad**: solo se conservan líneas con operadores de
  búsqueda reales (`site:`, `inurl:`, `intitle:`, `intext:`, `filetype:`, `ext:`,
  `"index of"`, etc.). Por eso de listas enormes como BullsEye0 (13.750 entradas)
  se tomaron ~313 dorks con operadores y se descartaron los ~13.000 fragmentos de
  URL sueltos (`blank.php?page=`), que como fuzz-list por subdominio harían la
  interfaz y la cuota de API inservibles.
- Para **regenerar** `data/dorks.json` desde las fuentes: `python _sources/merge.py`.
  Puedes añadir nuevas listas en `_sources/` y volver a correrlo (deduplica solo).

## Fuentes de dorks integradas

Colección índice: https://github.com/cipher387/Dorks-collections-list — de ahí se
tomaron las listas de **Google dorks** aplicables por `site:` (se omitieron las de
Shodan/Censys/Netlas/GitHub-code y pastebins de carding/gaming, no relevantes para
reconocimiento web por subdominio).

- https://github.com/Ishanoshada/GDorks  *(base, 1290 dorks)*
- https://github.com/BullsEye0/google_dork_list  *(+313)*
- https://github.com/Proviesec/google-dorks  *(git / logs / aws-s3)*
- https://github.com/0xAbbarhSF/Info-Sec-Dork-List  *(sensitive / CCTV / LFI)*
- https://github.com/sushiwushi/bug-bounty-dorks  *(descubrimiento de programas)*
- https://github.com/Tobee1406/Awesome-Google-Dorks
- https://github.com/Just-Roma/DorkingDB
