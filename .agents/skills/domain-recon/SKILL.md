---
name: domain-recon
description: Reconocimiento profundo de un dominio — subdominios, fingerprint tecnológico, y análisis de JS propio (no vendor) — usando bb_pipeline.py (reconv2.5.sh + recon_fingerprint + js_analyzer). Usar cuando el operador pide analizar, reconocer o mapear un dominio a fondo, no para tareas puntuales de un target ya mapeado.
---

## Metadata
- **Skill Name**: domain-recon
- **Folder**: domain-recon

## Descripción

Orquesta el pipeline de recon (`bb_pipeline.py`) para un dominio: descubre subdominios, los fingerprintea, filtra vendor JS conocido, y analiza el JS propio en busca de superficie de ataque. No reemplaza el trabajo manual de confirmación — entrega candidatos rankeados, no hallazgos. No se activa por default en ninguna sesión: solo cuando el pedido lo justifica explícitamente.

## Trigger Phrases

analizá este dominio, reconocé este dominio a fondo, corré el pipeline sobre, mapeá este target, recon profundo de, qué tecnología corre, escaneá subdominios de, hacé recon de, buscá subdominios de, fingerprintéa, corré bb_pipeline, corré el domain recon, qué corre atrás de, tirale recon a, metele reconocimiento a, chequeá qué tecnología usa, buscá superficie de ataque en

## Instructions for Claude

### Paso 0 — Gate de autorización (no negociable, va antes que cualquier otra cosa)

`bb_pipeline.py` ejecuta herramientas de descubrimiento activo contra infraestructura real (subfinder, assetfinder, crt.sh, resolución DNS masiva, httpx contra cada host vivo, y luego fetches HTTP completos vía `recon_fingerprint`). Esto no es pasivo ni de bajo impacto — antes de correrlo:

1. La presencia de `targets/<dominio>/` o de resultados previos no autoriza una corrida nueva. Usá la autorización explícita del operador para este dominio y este tipo de reconocimiento, o una política de programa vigente que incluya exactamente esos activos.
2. Confirmá si el alcance es solo el dominio exacto o también sus subdominios. `dominio.tld` cubre el host exacto; `*.dominio.tld` cubre subdominios, pero no el ápice. No asumir wildcard por el hecho de ejecutar discovery.
3. Si un subdominio descubierto **parece infraestructura posiblemente excluida** (vpn, citrix, rdp, ssh, remote, gateway, firewall, admin, staging con nombres sensibles, corp interno), no lo fingerprintees hasta contrastarlo con el scope del programa. Podés continuar con otros hosts autorizados.

Sin el paso 2 confirmado, no ejecutar nada de lo que sigue.

### Paso 1 — Elegir profundidad: solo subdominios, o pipeline completo

Si el pedido es explícitamente liviano ("solo traeme subdominios", "qué subdominios tiene", "descubrí subdominios de X" sin pedir más) → correr **solo** `reconv2.5.sh`, no `bb_pipeline.py` entero. Este script ya hace discovery + resolución DNS + `httpx` (título, tech-detect, status code — sin fingerprint profundo) + chequeo de takeovers, y para ahí:

```bash
export SUBDOMAIN_MONITOR_DIR="${BB_PIPELINE_DIR:-$HOME/.bb_pipeline}/<dominio>/subdomain_monitor"
bash scripts/reconv2.5.sh <dominio> --yes
```

Ejecutá desde la raíz del repositorio. `--yes` solo registra una autorización
que el operador ya dio explícitamente; no la sustituye. Este script descubre
subdominios y hace DNS/HTTP activos, así que usalo solo si el wildcard está
autorizado.

Resultado útil para el operador sin correr nada más pesado: `$RESULTS_DIR/<timestamp>_alive.jsonl` (título+tech+status por host vivo) y `$DOMAIN_DIR/interesting.txt` (categorizado). No hace falta invocar `bb_pipeline.py` ni el fingerprint completo para responder esto — sería gastar tiempo/tokens en algo que no se pidió.

Si el pedido es de recon a fondo ("analizá este dominio", "recon profundo", "mapeá este target", etc.) → seguir con el pipeline completo:

```bash
export BB_PIPELINE_DIR="${BB_PIPELINE_DIR:-$HOME/.bb_pipeline}"
python3 scripts/bb_pipeline.py -d <dominio> --scope '<dominio-o-*.dominio>' --yes --js-analyze
```

Ejecutá desde la raíz del repositorio y reemplazá `--scope` por el alcance
exacto que autorizó el operador. Para permitir subdominios, pasá el wildcard
entre comillas (por ejemplo `--scope '*.dominio.tld'`). `--yes` solo se usa
después de confirmar esa autorización.

`--js-analyze` es obligatorio si querés que corra la etapa 3/4 — sin esto el pipeline se detiene después del fingerprint.

**Flags disponibles para el pipeline completo, usar según corresponda (no todos siempre):**

- `--scope <dominio-o-wildcard>` — filtra hosts antes del fingerprint y análisis de JS. Acepta un ámbito por corrida: el dominio exacto incluye el ápice; `*.dominio.tld` incluye subdominios y excluye el ápice. Si el programa autoriza ambos, ejecutá una pasada por cada ámbito. No lo trates como ajuste de scoring ni amplíes el scope para mejorar cobertura.
- `--profile <generic|cms|saas|ecommerce>` — perfil de keywords para `js_analyzer` (no aplica todavía a `recon_fingerprint`, solo al análisis de JS). Elegir `ecommerce` para tiendas online, `cms` si el fingerprint detecta WordPress/Drupal y un perfil específico solo cuando esté configurado para el programa.
- `--only-new` — procesa solo subdominios nuevos desde la última corrida (requiere historial previo, es decir, no es la primera vez contra ese dominio). Usar para monitoreo recurrente de un programa ya mapeado, no para la primera pasada.
- `--max-js <N>` (default 15) — tope de archivos JS a analizar. Subir si el fingerprint devuelve muchos assets `app`/`unknown` (no vendor) y el default los recorta.
- `--js-max-matches <N>` (default 5) — cuántos matches por patrón guarda `js_analyzer` por archivo. Subir si un archivo grande parece tener más señal de la que el resumen muestra.
- `--app-only` — le pasa `--app-only` a `js_analyzer` para que filtre a nivel de finding individual código vendor-high (complementa, no reemplaza, el filtro de assets por `asset_role` que ya corre por default).
- `--timeout <segundos>` (default 120) — timeout por target en `recon_fingerprint`. Subir contra targets lentos o con muchos path-probes.
- `--no-path-probes` / `--extra-probes` — bajar o subir la profundidad de los path probes (`/api`, `/graphql`, `/.well-known/...`, etc.) que `recon_fingerprint` prueba por default. Usar `--no-path-probes` si el volumen de subdominios es alto y hay que ir rápido; `--extra-probes` si un target puntual amerita mirar más a fondo.
- `--notify` — manda el resumen final por Telegram, solo si `TELEGRAM_BOT_TOKEN`/`TELEGRAM_CHAT_ID` están configurados (opcional, no bloquea el pipeline si no lo están).
- `--include-vendor` — fuerza analizar JS marcado vendor con `js_analyzer` de todas formas. Usar solo para casos puntuales, ej. confirmar si una librería vieja con CVE conocido tiene algún patrón explotable, no como default.

Output: `$BB_PIPELINE_DIR/<dominio>/pipeline_<run_ts>.json` — esta carpeta vive fuera de `mulderx/targets/` a propósito (es almacenamiento crudo del pipeline, no el embudo curado de Notes→Leads→Findings). No promover nada de acá a `targets/` sin pasar por el paso 3.

### Paso 2 — Leer el status antes de interpretar nada

Antes de mirar `top_targets` o `js_high_findings`, revisar `meta.subdomain_discovery_status` en el JSON unificado:

- `"ok"` → cobertura normal, proceder.
- cualquier otro valor (`"failed"`, `"timeout"`, `"not_found"`) → la discovery no cubrió el dominio completo. Avisar al operador ANTES de reportar cualquier hallazgo: "el discovery de subdominios falló (`<detail>`), esto solo cubre `<lo que sí se procesó>`, no el dominio entero — ¿querés que reintente o seguimos con esta cobertura parcial?". Nunca presentar resultados parciales como si fueran cobertura completa.

### Paso 3 — Gate de evidencia (el mismo principio que SSRF/XSS, aplicado a recon)

Todo lo que sale de `recon_fingerprint` y `js_analyzer` es **candidato basado en regex/heurística**, no hallazgo confirmado. Antes de reportarle algo al operador como interesante:

- **Categorías de parámetros** (`ssrf_url`, `xss_content`, etc. en `parameter_intelligence`) pueden venir de código de librería, no de la app — revisar el campo `sources` de cada param. Si el único source es `asset:<archivo-vendor>`, es ruido (ejemplo real visto: `url` marcado `ssrf_url` cuyo único source era la firma interna de `jQuery.ajax()`, no un parámetro real de la app).
- **`is_vendor: false` en un finding de `js_analyzer` no es garantía de que sea código propio** — el analizador detecta el framework a nivel de archivo (`frameworks: ["jQuery"]`) pero no siempre propaga esa marca a cada finding individual. Si el archivo analizado es una librería conocida (jquery.js, bootstrap.js, cualquier CDN de terceros), tratar los findings como ruido de librería salvo que se verifique manualmente contra el código fuente real.
- **Endpoints/auth_endpoints con contenido que parece código fuente en vez de una URL** (fragmentos con `function`, `var`, llaves) son errores de extracción del analizador, no endpoints reales — descartar, no reportar.
- **Versión de librería vulnerable a un CVE conocido NO es un finding por sí sola.** Si `js_analyzer` detecta una librería vieja (ej. jQuery <3.4.0, vulnerable a CVE-2019-11358), eso es contexto — para que sea un lead real hace falta encontrar, en código PROPIO de la app (no en el archivo de la librería), un call site que use el patrón vulnerable con datos que rastreen hasta input del usuario. Sin ese call site, queda como nota de contexto, no como hallazgo.

### Paso 4 — Decidir el siguiente paso

### Stack-aware next steps and JavaScript

Before choosing tests, record per host the observed server/framework/CMS,
libraries and versions, frontend, API/protocols, CDN/WAF, and auth signals,
with evidence and confidence. Fingerprints are hypotheses. Check current
primary advisories and exposure/reachability for exact versions. Select
playbooks from components and flows actually observed; do not test a technology
just because its name appeared in a banner.

In this domain-recon path, JavaScript analysis runs through
`bb_pipeline.py --js-analyze`; it selects/downloads bundles and calls
`js_analyzer`, producing `js_high_findings` and `parameter_intelligence`.
During a hunt with downloaded JS, `docs/workflow.md` specifies
`js_analyzer_v4_8.py` and its `auth_map`, `taint_flows`,
`critical_mutations`, and `correlations` outputs. Verify candidates against
first-party code and the live in-scope endpoint.


Con `top_targets` (ya rankeado por score) y `js_high_findings` filtrados de ruido, mirar `parameter_intelligence.by_category` del fingerprint — `recon_fingerprint` clasifica parámetros en 10 categorías, no solo SSRF/XSS: `idor_id`, `ssrf_url`, `ssrf_file_fetch`, `open_redirect`, `path_traversal`, `cmd_injection`, `mass_assignment`, `auth_token`, `xss_content`, `sqli_hint`. Rutear según lo que aparezca, no asumir de antemano cuál va a estar presente:

- `ssrf_url` / `ssrf_file_fetch` reales (no vendor, ver Paso 3) → cargar el skill `ssrf` sobre ese endpoint.
- `xss_content` real, o sinks (`innerHTML`, `.html()`) en código propio con datos que rastrean a un parámetro → pipeline de XSS ya calibrado (filter-probing → vector-catalog → constructive-synthesis).
- `idor_id` con endpoints tipo `/api/x/{id}` sin scoping visible → candidato a IDOR/BFLA, requiere confirmación manual de si hay chequeo de rol server-side.
- `mass_assignment` (params como `role`, `is_admin`, `permissions` viajando al backend) → candidato a mass assignment / privilege escalation.
- `auth_token` expuesto en storage/params → candidato a session hijacking o token replay.
- `open_redirect` / `path_traversal` / `cmd_injection` / `sqli_hint` → mismo criterio: candidato, no hallazgo, hasta probarlo manualmente.
- Si ninguna categoría tiene señal real después de filtrar vendor — decirlo así, sin inflar. "Corrí el recon completo sobre `<dominio>`, la superficie propia es mínima, no hay vector obvio para seguir" es una respuesta válida y honesta, no un fracaso del skill.

**Cache poisoning — chequeo activo, no reactivo.** `recon_fingerprint`
ya detecta CDN por firma de headers (`x-served-by`, `x-cache:`,
`x-azure-ref`, etc.) y guarda `cache_control` por host. Esto NO
aparece como categoría en `parameter_intelligence` (esa lista es solo
de parámetros), así que revisarlo es un paso aparte, no algo que salga
solo al leer `top_targets`: para cada host del fingerprint con CDN
detectada o `cache_control` con `max-age`/`public`, hacer un `GET` con
cache buster manual y confirmar `Age`/`X-Cache`/`CF-Cache-Status` antes
de descartarlo. Si hay indicio de cache real, cargar el skill
`cache-poisoning` sobre ese host — no esperar a que el operador lo
pida ni a notarlo de casualidad revisando otra cosa.

Si no existe todavía un skill calibrado para la categoría que apareció (solo `ssrf` y el pipeline de XSS están armados hoy), no inventar una metodología sobre la marcha — avisar al operador que hay señal de esa clase pero que no hay skill calibrado aún, y preguntar si vale la pena armarlo (mismo proceso que se usó para `ssrf`: labs reales, catálogo confirmado, no copiar teoría sin probar).

## Notas de calibración

- `bb_pipeline.py` tuvo varios bugs reales corregidos (manejo de fallos de discovery, descarga de JS antes de analizar, parseo de `findings` como dict por severidad, filtro de vendor) — el hecho de que hoy corra limpio no lo vuelve infalible. Si algo en el output parece contradictorio o no cierra, tratarlo con la misma sospecha que cualquier otro dato no verificado, y preguntarle al operador en vez de asumir que el pipeline tiene razón.
