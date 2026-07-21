# SubDork

Herramienta local de reconocimiento: enumera subdominios de forma **recursiva**
lanzando varias fuentes (`crt.sh`, `subfinder`, `amass`) **en paralelo**, los va
mostrando **uno a uno en una interfaz web colapsable mientras cargan** (streaming
SSE), y dentro de cada subdominio arma el **catálogo completo de Google dorks**
(1882 dorks en 257 categorías) como enlaces clicables para ejecutar **a mano**.

> ⚠ **Uso autorizado únicamente.** Ejecútalo solo sobre dominios que te
> pertenezcan o para los que tengas permiso explícito (bug bounty en alcance,
> pentest contratado). Tú eres responsable del uso que le des.

---

## Cómo funciona

```
dominio  ──[crt.sh ‖ subfinder ‖ amass]──►  subdominios (nivel 1)   (fuentes en PARALELO)
                                  │  reinyecta cada uno
                                  ▼
                              sub-subdominios (nivel 2) ... hasta la profundidad elegida
                                  │
                                  ▼
   cada subdominio  ──►  panel colapsable  ──►  1882 dorks clicables por categoría (manual)
```

- **Múltiples fuentes combinables, sin claves:** cuatro fuentes web integradas
  (`crt.sh`, `anubis`, `alienvault` OTX, `hackertarget`) que no requieren instalar
  nada, más los binarios `subfinder` y `amass` si los tienes. Como crt.sh se satura
  seguido (502), las otras fuentes cubren el hueco. crt.sh reintenta automáticamente.
- **Consola de actividad en vivo:** muestra qué fuente está consultando, cuántos
  resultados devuelve cada una y cualquier error, para que nunca te quedes sin saber
  qué está pasando.
- **Streaming en vivo (SSE):** cada subdominio aparece en la interfaz apenas se
  descubre, sin esperar a que termine todo.
- **Profundidad configurable (1–4):** cuántos niveles de recursión.
- **Fuentes en paralelo:** todas las fuentes activas se lanzan a la vez sobre cada
  objetivo; los resultados se entremezclan y aparecen en cuanto llegan.
- **Interfaz en 3 columnas:** sidebar de endpoints + catálogo completo de dorks +
  tabla de hallazgos validados.
- **Dorks manuales, con un clic:** cada dork es un enlace `site:<subdominio> <dork>`
  que abre Google. Si un dork ya trae su propio `site:`, se respeta tal cual.
- **Verificación opcional con SearXNG (gratis):** marca solo los dorks que devuelven
  resultados y los va colocando en la tabla en vivo. Sin claves ni pagos.

## Requisitos

1. **Python 3.9+**  *(única dependencia obligatoria — con `crt.sh` ya enumera sin nada más)*
2. **subfinder** y **amass** (opcionales, amplían la cobertura):
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
2. Elige las **fuentes**: `crt.sh` (recomendada, siempre disponible), `subfinder`
   y/o `amass` (marcada "lento"). Si no tienes ninguna instalada, `crt.sh` ya basta;
   o activa **modo demo** para ver la interfaz con datos ficticios.
3. **Escanear.** Las fuentes corren en paralelo y los subdominios aparecen como
   paneles colapsables en cuanto se descubren. La **consola de actividad** muestra
   qué está pasando (fuente, conteos, errores).
4. La interfaz se divide en tres: **sidebar** con los endpoints (subdominios)
   pulsables, panel central **"Todos los dorks"** (catálogo completo clicable del
   endpoint seleccionado) y panel derecho **"Hallazgos validados"** (tabla).
5. Clic en un dork → se abre la búsqueda en Google (ejecución manual).

## Agregar subdominios a mano / por .txt

En la columna **Endpoints** puedes:

- **＋ agregar**: escribe uno o varios hosts (separados por coma/espacio/Enter).
- **⬆ .txt**: sube un archivo de texto con un subdominio por línea.
- **filtrar…**: busca dentro de la lista cuando hay muchos endpoints.

Cada subdominio agregado obtiene su catálogo completo de dorks y puede verificarse.

## Verificación de hallazgos (gratis)

La tabla de **hallazgos** se llena solo con los dorks que devuelven resultados.
Hay tres motores (selector en la barra de verificación):

- **Bing** (por defecto): funciona **sin instalar nada ni claves** y **tolera el
  scraping mucho mejor** que DuckDuckGo. Es la mejor opción sin setup.
- **DuckDuckGo**: sin instalar nada, pero **bloquea muy rápido** el scraping
  automatizado (aunque subas el delay). Úsalo solo como alternativa puntual.
- **SearXNG**: tu instancia self-hosted ([searxng](https://github.com/searxng/searxng)),
  lo más robusto para verificar mucho volumen. Requiere levantar el contenedor:

> **Importante:** *todos* los buscadores limitan el scraping. Verificar cientos de
> dorks seguidos hará que cualquiera te bloquee temporalmente. Para uso sin setup,
> verifica **pocas consultas** (30–50) con **delay 2s+ y concurrencia 1** por
> endpoint. Para volumen alto, monta SearXNG (rota motores y aguanta más).

1. Levanta SearXNG con Docker:
   ```bash
   docker run -d --name searxng -p 8888:8080 searxng/searxng
   ```
2. Habilita la API JSON: en su `settings.yml`, bloque `search:`, pon
   `formats: [html, json]` y reinicia el contenedor. Si el *limiter* bloquea las
   consultas, permite localhost o desactívalo.
3. En SubDork, pega la URL (`http://localhost:8888`) y pulsa **probar conexión**.
4. Elige un endpoint en el sidebar y pulsa **verificar hallazgos**. SubDork
   consulta cada dork (con delay configurable) y va llenando la tabla en vivo solo
   con los que tienen resultados.

**Ojo:** la verificación consulta motores reales; usa `delay` y `máx. consultas`
para no abusar. Los operadores de dork los soporta bien Google, pero solo
parcialmente otros motores, así que el resultado es *aproximado*.

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
│  ├─ recon.py    crt.sh/anubis/alienvault/hackertarget/subfinder/amass en paralelo
│  ├─ verify.py   verificación de dorks vía SearXNG
│  └─ dorks.py    carga de dorks y armado de URLs
├─ data/dorks.json   1882 dorks / 257 categorías (multi-fuente)
├─ _sources/         listas crudas + merge.py (regenera dorks.json)
├─ frontend/index.html   interfaz colapsable
├─ requirements.txt · run.bat · run.sh
├─ push_to_github.bat · push_to_github.sh   subida al repo
└─ LICENSE
```

## Notas

- Los dorks se ejecutan manualmente (clic → Google). No hay scraping ni APIs de
  búsqueda: es más simple, gratis y sin límites de cuota.
- `crt.sh` es la fuente por defecto: no requiere instalación ni claves.
- `amass` corre en modo `-passive` para un reconocimiento silencioso (pero es lento;
  por eso viene desactivado por defecto).
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
