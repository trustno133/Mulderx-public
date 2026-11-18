---
name: recon-map
description: Genera un explorer HTML interactivo (estilo aquatone) para un target — inventario navegable de hosts con fingerprint real (status, edge/CDN, server, framework, CNAME/infra), facetas por tecnología/área/estado, búsqueda y panel de detalle. Además mantiene el índice fleet-wide tecnología→hosts para saber al instante dónde aplicar un CVE nuevo. Usar cuando el operador pide un "mapa", "explorer", "aquatone", "inventario visual", "mapa de tecnologías/dominios", o tras mapear la superficie de un target nuevo.
---

## Metadata
- **Skill Name**: recon-map
- **Folder**: recon-map
- **Assets**: `assets/fingerprint.sh`, `assets/enrich.py`, `assets/explorer_head.html`, `assets/explorer_tail.html`
- **Fleet script**: `scripts/tech_index.py`

## Descripción

Convierte una lista de hosts de un target en un **artefacto HTML interactivo** (publicable con la tool `Artifact`) que agrupa dominios por tecnología/área/estado, permite búsqueda y facetas combinables, y muestra el stack completo de cada host al clickearlo. No es decorativo: es la vista operable del recon — reemplaza tener los hosts sueltos en notas. Y alimenta un **índice fleet-wide** (`targets/_fleet/tech_index.md`) que responde "salió un CVE de tal tecnología, ¿en qué hosts de qué targets la tengo?".

No descubre superficie (eso lo hace `domain-recon`) — parte de una lista de hosts ya conocida (de certspotter/CT, del recon previo, o de tráfico capturado) y la enriquece + visualiza.

## Trigger Phrases

armá el mapa de, hacé un explorer de, algo tipo aquatone, mapa semántico de, inventario visual de, mapa de tecnologías de, mapá los dominios de, visualizá la superficie de, dashboard de recon de, actualizá el explorer, regenerá el mapa, dónde tengo esta tecnología, salió un CVE de, qué hosts corren, índice de tecnologías

## Reglas antes de correr (no negociables)

1. **Autorización de scope** — igual que `domain-recon`: los hosts deben caer bajo un wildcard/target ya autorizado (carpeta en `targets/<t>/` o confirmación explícita en la sesión). El fingerprint hace 1 GET por host.
2. **NO es un scanner ruidoso** — `fingerprint.sh` hace un `GET /` con timeout de 7s por host, en paralelo. Si el target prohíbe incluso esto (ej. `assets.spotify.com` prohíbe scans automáticos), **sacar ese host de la lista** antes de correr. Bajar `-P` si el programa es sensible al volumen.
3. **Datos reales, sin inventar** — todo campo sale del fingerprint o de DoH. Si un host no responde, queda `dead/internal`, no se adivina.

## Pipeline (4 pasos)

Todo se corre desde la raíz del repo. `<t>` = nombre del target (carpeta en `targets/`). Usar el scratchpad para los intermedios.

### Paso 1 — Lista de hosts

Reunir los hosts en un archivo plano, uno por línea. Fuentes típicas:
- certspotter/CT: `curl -s "https://api.certspotter.com/v1/issuances?domain=<dom>&include_subdomains=true&expand=dns_names"` → extraer `dns_names` (ver `targets/spotify/recon_notes.md` para el patrón).
- hosts vistos en tráfico capturado (jxscout) o en CSPs.
- el `interesting.txt` / `*_alive.jsonl` de `domain-recon` si ya se corrió.

Guardar en `$SB/subs.txt`. **Siempre pasa por `tr -d '\r'`** dentro de `fingerprint.sh` — no confiar en que la lista venga limpia (Windows-python mete `\r\n`, y un host con `\r` se marca muerto en falso: este bug ya nos pasó).

### Paso 2 — Fingerprint (2 fuentes; preferir httpx)

**Fuente PREFERIDA — `_alive.jsonl` de httpx** (lo produce `reconv2.5.sh` /
`domain-recon` / `bb_pipeline.py`, corriendo en el WSL del operador). Es
mucho más rico que curl: trae **tech-detect de Wappalyzer con versiones**
(`Apache/2.4.29`, `nginx/1.24.0`, `Bootstrap:4.4.1`), IP resuelta (`host_ip`/
`a[]`), webserver y status — sin re-probar nada. Si ya existe una corrida:
```bash
find .bb_pipeline -name '*_alive.jsonl'   # elegir el más reciente del target
```
`enrich.py` (Paso 3) lo consume directo — **saltear al Paso 3 pasándole el
`.jsonl`**. Idealmente el operador corre `reconv2.5.sh` con `-asn -location`
agregados al httpx para que traiga ASN y redirect también (hoy el ASN lo
completa `enrich.py` vía Cymru igual).

**Fallback — `fingerprint.sh` (curl)**, solo si NO hay httpx (ni output
previo ni herramienta):
```bash
bash .claude/skills/recon-map/assets/fingerprint.sh "$SB/subs.txt" "$SB/fp.psv"
```
Salida PSV: `host|code|server|edge|powered|location`. Fingerprint pobre
(regex de headers, sin Wappalyzer) — usar solo como último recurso. Si TODO
da 000, es problema de red o de `\r`, no que todo esté muerto.

### Paso 3 — Enriquecer a JSON

Opcional pero recomendado: crear `targets/<t>/area_rules.tsv` (regex⇥label, la primera que matchea gana) para agrupar por producto, y `targets/<t>/leads.tsv` (substring-host⇥LEAD-ID) para pinchar leads sobre hosts. Ver `targets/spotify/*.tsv` como ejemplo. Sin `area_rules.tsv`, el área default es el apex domain.

```bash
# fuente httpx (preferida):
python3 .claude/skills/recon-map/assets/enrich.py \
  ".bb_pipeline/<dom>/.../<ts>_alive.jsonl" "targets/<t>/hosts.json" \
  "targets/<t>/area_rules.tsv" "targets/<t>/leads.tsv"
# o fuente PSV (fallback): pasar "$SB/fp.psv" en vez del .jsonl
```
`enrich.py` **autodetecta el formato** (`.jsonl`/`{`=httpx, si no=PSV). Toma
las tech+versiones de Wappalyzer y la IP del jsonl cuando están; completa
CNAME/infra (DoH), ASN+org (Team Cymru vía DoH), versiones de headers,
bucket de estado, y **versiona el dataset en `targets/<t>/hosts.json`** (vive
en el repo, no solo en el artefacto).

### Paso 4 — Ensamblar y publicar el artefacto

El explorer se arma concatenando: `head` (shell+estilos+markup) + `hosts.json` (embebido en `<script id="data">`) + `tail` (la app JS). Reemplazar tokens del head.

```bash
sed -e 's/__TARGET__/<Nombre>/g' -e 's/__TARGETDIR__/<t>/g' \
    -e "s/__N__/$(python3 -c "import json;print(len(json.load(open('targets/<t>/hosts.json'))))")/g" \
    .claude/skills/recon-map/assets/explorer_head.html > "$SB/head.html"
cat "$SB/head.html" "targets/<t>/hosts.json" \
    .claude/skills/recon-map/assets/explorer_tail.html > "targets/<t>/<t>_explorer.html"
```
**El HTML final siempre va en `targets/<t>/`** (no en `.scratch/`) — es un artefacto persistente del target, no un intermedio. El scratchpad solo se usa para `head.html` (intermedio temporal).

Sanity: `grep -o '"host":' "targets/<t>/<t>_explorer.html" | wc -l` debe igualar el número de hosts (usar `-o`, no `-c`: el JSON va en una sola línea). Después publicar con la tool `Artifact` (`favicon: 🔎`, `title: "<Nombre> — Recon Explorer"`). Es documento vivo: para actualizarlo, regenerar `hosts.json` y re-publicar **el mismo file_path** (mantiene la URL).

## Fleet-wide — índice tecnología → hosts (el caso "salió un CVE")

Cada target con `hosts.json` alimenta el índice cruzado. Tras mapear un target nuevo (o actualizar uno):

```bash
python3 scripts/tech_index.py                    # regenera targets/_fleet/tech_index.md + fleet.json
python3 scripts/tech_index.py "Next.js"          # consulta puntual: dónde corre esa tech
```
La consulta puntual es la respuesta directa a "salió CVE-XXXX en <tech>, ¿dónde lo pruebo?" — lista host + target + estado. `targets/_fleet/fleet.json` es el dataset combinado (mismo schema + campo `target`) por si se quiere un explorer fleet-wide (mismo template, apuntando a ese JSON).

## Schema de `hosts.json` (un objeto por host)

```
host, area, code (HTTP status), server, edge (CDN/WAF normalizado), framework,
infra (de CNAME), cname, ip (primer A record), asn, asn_org (Team Cymru),
version (array producto/x.y de headers), status (bucket), loc (redirect target),
lead (LEAD-ID o ""), tags (array de tecnologías, incluye versiones)
```
Buckets de `status`: `live`, `live·404`, `gated` (401/403), `redirect`, `dead/internal`, `dangling` (CNAME sin A → candidato takeover), `error` (5xx).

**IP/ASN** salen de DoH (A record) + Team Cymru (`origin.asn.cymru.com` vía DoH, sin token) → permite clusterizar por hosting (facet "Hosting · ASN", agrupar por infra, encontrar orígenes fuera de la CDN). **Versiones** se extraen de los headers `Server`/`X-Powered-By` (nginx/1.24, awselb/2.0, Apache/2.4…); cobertura parcial — frameworks JS (Next.js, Express) no leakean versión en headers, para eso hace falta el modo deep (bundles), no implementado.

## Notas de calibración (bugs reales, no re-introducir)

- **`\r` en la lista de hosts** → curl resuelve `host\r`, marca muerto en falso. `fingerprint.sh` ya hace `tr -d '\r'`; si se arma la lista de otra forma, limpiarla igual.
- **Windows-python + consola cp1252** → `print()` con caracteres no-ASCII (`→`, `·`) crashea; los archivos se escriben bien (utf-8), solo falla el print final. Usar ASCII en stdout, unicode solo en archivos.
- **Embed del JSON** → `enrich.py` escribe el JSON en una sola línea (sin newlines) para que no rompa el `<script>`. No re-indentar. Ningún hostname contiene `</script>`, así que el embed es seguro.
- **CSP del Artifact** → el explorer es 100% self-contained (estilos + JS inline, sin libs externas, sin fuentes CDN). No agregar recursos externos: la CSP los bloquea.
- **`dangling`** en el status = CNAME que no resuelve a A → priorizar como candidato de subdomain takeover (cruzar con el skill correspondiente si existe).

## Mejoras futuras (roadmap, no implementado)

- **Modo deep de versiones**: para frameworks JS que no leakean versión en headers (Next.js, React, Express), extraer de bundles (`LICENSE.txt`, rutas `.pnpm/pkg@ver`, `buildId`). Hoy `version` solo cubre lo que el header `Server`/`X-Powered-By` expone.
- **Capa CVE automática**: cruzar `version` (producto/x.y) contra una base de CVEs (osv.dev/NVD) para auto-marcar hosts vulnerables, en vez de la consulta manual `tech_index.py "<tech>"`.
- **Screenshots** por host (aquatone real) — requiere browser headless; hoy no hay en el entorno.
- **Vista de grafo**: redirect chains (`loc`) + quién frontea a quién (edge) sobre el mismo dataset.
- **Diff temporal**: comparar `hosts.json` vs el de la corrida anterior → resaltar hosts nuevos / que cambiaron de stack/hosting (superficie nueva).

- **Integrar `recon_fingerprint_v3.6`**: ese script (WSL) ya captura por host superficie de ataque real — `.git`/`.env` expuestos, graphql/swagger/openapi, sourcemaps, WAF/CDN signals, CSP, TLS/JARM. Sumar esos campos al `hosts.json` (o un `hosts_deep.json`) y mostrarlos en el panel de detalle + como facets ("tiene .git", "expone graphql") convertiría el explorer de inventario a **priorizador de superficie**. `js_analyzer` alimenta el lado de leads (eso es trabajo de `domain-recon`, no de este skill).

Ya implementado (antes en roadmap): consumo del `_alive.jsonl` de httpx (tech-detect Wappalyzer + versiones + IP), IP + ASN/org (clustering por hosting), y versiones desde headers.
