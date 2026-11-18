---
name: wayback-js-recon
description: Encuentra endpoints, rutas y secrets presentes en versiones históricas de JS (vía Wayback Machine CDX) pero ausentes en la versión live actual — features legacy olvidados, APIs removidas que pueden seguir vivas server-side. Cargar cuando se quiere buscar superficie oculta en un target con historial en Wayback.
sources: internal (built from scratch)
---

## Qué hace y qué NO hace

Descarga versiones históricas de los bundles JS propios de un target y las
pasa por `js_analyzer_v4_8.py`. El resultado es un diff: qué endpoints/rutas/
secrets estaban en el JS viejo y **no están en el JS actual** — candidatos a
features legacy que pueden seguir funcionando server-side aunque el frontend
los haya borrado.

**No confirma que esos endpoints sigan vivos.** El diff es la lista de
candidatos — la confirmación requiere un request manual. Handoff obligatorio
a `hunt-web-fuzzing` o al skill correspondiente según el tipo de endpoint.

**No analiza JS de vendor** (jQuery, React, Bootstrap, webpack-runtime, etc.)
— filtrado por nombre de archivo antes de procesar.

## Gate de confirmación

| Nivel | Condición | Techo |
|---|---|---|
| **Candidato** | Endpoint/ruta aparece en snapshot histórico, ausente en live | Listar para confirmación manual |
| **Candidato prioritario** | El path matchea patrón de alto interés (`/api/`, `/admin/`, `/auth/`, `/v1/`, etc.) | Probar manualmente primero |
| **Confirmado vivo** | Request al endpoint devuelve respuesta no-404 con contenido distinto al catch-all | Handoff al skill del vector correspondiente |

Sin el tercer nivel, el hallazgo no puede reportarse como vulnerabilidad —
es solo superficie candidata.

## Cuándo cargarlo

- Al iniciar recon de un target con historia (más de 1 año en Wayback)
- Cuando `hunt-web-fuzzing` pasada 1 dio 0-1 resultados y se quiere buscar
  superficie alternativa sin wordlists genéricas
- Cuando el programa tiene muchas versiones de su frontend documentadas
- Cuando el target tiene un JS bundle grande que cambió mucho a lo largo del tiempo

**Prerequisito**: `domain-recon` ya corrió o el operador conoce la estructura
de JS del target. Este skill no hace fingerprint de tecnología ni descubrimiento
de subdominios — asume que sabés qué dominio/scope analizar.

## Cómo correr el script

```bash
# Básico — analiza example.com con defaults (10 archivos JS, 4 snapshots cada uno)
python3 scripts/wayback_js_recon.py example.com

# Con scope diferente al dominio principal
python3 scripts/wayback_js_recon.py example.com --scope api.example.com

# Solo snapshots recientes
python3 scripts/wayback_js_recon.py example.com --since 20220101

# Más cobertura histórica
python3 scripts/wayback_js_recon.py example.com --max-files 20 --max-snapshots 6

# Profile específico + output fijo
python3 scripts/wayback_js_recon.py example.com --profile saas --app-only -o /tmp/diff.json

# Rate más lento para targets con WAF agresivo
python3 scripts/wayback_js_recon.py example.com --rate 2.0
```

**Output**: el script imprime a stderr (progress) y a stdout solo el path al
JSON de resultado. Consumir el JSON para el análisis — no el stdout completo.

```bash
OUT=$(python3 scripts/wayback_js_recon.py example.com 2>/dev/null)
cat "$OUT" | python3 -m json.tool
```

## Flags relevantes

| Flag | Default | Cuándo cambiar |
|---|---|---|
| `--max-files N` | 10 | Subir si el target tiene muchos bundles propios (`js_analyzer` detectó muchos assets `app`/`unknown`) |
| `--max-snapshots N` | 4 | Subir si el target tiene historia larga y se quiere más granularidad temporal |
| `--since YYYYMMDD` | (todo el historial) | Usar si solo interesa un período específico (ej. desde que empezó el programa) |
| `--scope` | igual al dominio | Usar si el programa cubre un subdominio específico (ej. `api.example.com`) |
| `--profile` | generic | Cambiar a `saas`, `ecommerce`, etc. para keywords más afinados |
| `--app-only` | off | Activar para filtrar findings de código vendor que el analyzer no pudo filtrar por nombre |
| `--rate` | 1.0s | Subir a 2.0-3.0 en targets con rate limiting o WAF activo; nunca bajar de 0.5 en programas activos |
| `--no-live` | off | Usar si el target está caído o el JS live no es accesible — compara snapshots entre sí (sin baseline live) |

## Estructura del output JSON

```json
{
  "meta": {
    "domain": "example.com",
    "scope": "example.com",
    "run_ts": "20241215_143022",
    "js_files_analyzed": 8
  },
  "signal_summary": {
    "legacy_endpoints": 23,
    "legacy_routes": 7,
    "legacy_secrets": 0,
    "high_interest_legacy_endpoints": 5
  },
  "legacy_endpoints": [
    {
      "value": "/api/v1/admin/users",
      "found_in_snapshots": ["20200301120000", "20210615080000"],
      "last_seen_archived": "20210615080000",
      "high_interest": true,
      "source_js": ["https://example.com/static/app.bundle.js"]
    }
  ],
  "legacy_routes": [...],
  "legacy_secrets": [...],
  "per_file": [...]
}
```

## Cómo leer el resultado

1. **Empezar por `signal_summary.high_interest_legacy_endpoints`** — si es 0,
   el target no tiene superficie obvia de alto interés en su historial.

2. **`legacy_endpoints` con `high_interest: true`** — paths que matchean
   `/api/`, `/admin/`, `/auth/`, `/v1/`, etc. Estos van primero al checklist
   de confirmación manual.

3. **`legacy_secrets`** — si hay algo acá, es priority 1. Verificar
   manualmente si el secret sigue válido antes de cualquier otra cosa.
   Handoff inmediato a `exposed-secrets`.

4. **`legacy_routes`** — rutas del router frontend que no están en el live.
   Menos accionable que endpoints de API, pero útil para descubrir secciones
   del app que fueron deshabilitadas sin retirar el backend.

5. **`per_file`** — útil si querés ver qué snapshot específico contenía un
   endpoint determinado (para correlacionar con fechas de deploy/incidentes).

## Handoffs

- **`/api/` legacy endpoints que responden** → cargar `idor-bola` si hay IDs,
  `hunt-csrf` si son endpoints de mutación sin token, `ssrf` si aceptan URLs.
- **`/admin/` o `/internal/` endpoints** → confirmar auth, luego `auth_decision_tree.md`
- **Secrets en legacy JS** → `exposed-secrets` + verificar si el secret sigue activo
- **Rutas SPA legacy** → `hunt-web-fuzzing` para confirmar si el backend sigue sirviendo esas rutas

## Limitaciones conocidas

- **Wayback no tiene todo**: sitios que bloquean el Wayback crawler, o JS
  servido detrás de auth, no van a aparecer. Si el CDX devuelve 0 resultados,
  no es un fallo del script — el target simplemente no tiene historial público.
- **CDX con `collapse=urlkey`** da un snapshot por URL canónica. Si el bundle
  tiene hashing en el nombre (ej. `app.a3f8c2.js` vs `app.b91d44.js`), cada
  hash se trata como URL distinta — el script las filtra por contenido si son
  vendor, pero puede procesar más archivos de lo esperado.
- **js_analyzer sobre JS minificado antiguo** puede tener más ruido que sobre
  código actual — revisar con más escepticismo los findings de snapshots muy
  viejos (pre-2019).
- **`--no-live`**: sin baseline live, el diff compara el snapshot más nuevo
  contra todos los anteriores, no contra el estado actual real — menos útil.

## Work directory

Los snapshots descargados y sus análisis se guardan en:
```
$BB_PIPELINE_DIR/<domain>/wayback_js/<run_ts>/
  <canonical_js_name>/
    20200301120000.js
    20200301120000_analysis_v4_8.json
    live_current.js
    live_current_analysis_v4_8.json
  wayback_js_diff_<run_ts>.json   ← output principal
```

Las corridas son idempotentes para snapshots ya descargados (se cachean por
timestamp). Re-correr el script sobre el mismo target reutiliza lo descargado.
