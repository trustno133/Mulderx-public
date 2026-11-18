---
name: hunt-web-fuzzing
description: Descubrir endpoints, directorios y archivos no listados en el recon pasivo (backups .bak, .env, .git, paneles admin, rutas legacy) mediante fuzzing activo con ffuf. Construye wordlists específicas del target combinando output de js_analyzer_v4_8.py y fingerprint de tecnología (WordPress/Laravel/etc.), en vez de wordlists genéricas. Usar cuando katana/recon pasivo ya corrió y se quiere ampliar superficie con fuzzing activo dirigido, no como primer paso de recon.
sources: internal (built from scratch, evidence-gate-first)
---

## Qué es esto y qué NO es

Este skill **descubre que algo existe**. No clasifica qué tan grave es,
no decide si es explotable, no dispara remediación. Un `.env` con 200
que sale de acá es un lead — el handoff a `exposed-secrets` (si el
archivo tiene secretos reales) o a `idor-bola` (si es un panel sin
auth) lo hace quien reciba la lista, no este skill.

**Por qué el gate se corta acá:** mezclar "encontré la ruta" con "esto
es grave" es el mismo anti-patrón de gates contradictorios que ya
evitamos en otros skills — este solo confirma existencia, con el
código de respuesta como única señal.

## Gate de Confirmación

| Nivel | Qué probaste | Techo |
|---|---|---|
| **Respuesta 404/catch-all** | El path no existe o el server devuelve la misma página de error genérica | Descartar, no listar |
| **Existencia confirmada** | 200, 301/302 (que no sea el catch-all genérico), o 403 CON contenido distinto al 404 default | Se lista para revisión — sin clasificar severidad |
| **Confirmado por humano/Triage** | Alguien (vos o el agente de Triage) miró el hallazgo y decidió a qué skill hacer handoff | Recién ahí arranca cualquier proceso de severidad, en la skill que corresponda |

Nota importante para evitar falsos positivos: sitios con "soft 404"
(devuelven 200 en cualquier ruta con una página de error custom)
rompen este gate. **Paso obligatorio antes de fuzzear:** pedir un path
random garantizado inexistente (`/asdf-random-noexiste-12345`) y
guardar su respuesta (código + tamaño + hash del body) como baseline.
Cualquier resultado del fuzzing que coincida con ese baseline se
descarta, sin importar el código HTTP.

## Construcción de wordlist (esto es lo específico de este skill)

Dos pasadas, no una — la dirigida corre siempre primero; SecLists es
la escalada, no el default, para no comerte horas de `-rl 3 -c1`
contra un target real con una wordlist de miles de líneas de entrada.

### Pasada 1 — Dirigida al target (siempre)

1. **Desde `js_analyzer_v4_8.py`** — extraer todos los paths/rutas de
   API que aparecen en las llamadas `fetch`/`axios`/`XMLHttpRequest`
   del bundle. Esto ya lo tenés como output de recon — no requiere
   research nuevo, es tomar ese JSON y convertirlo en lista de paths
   candidatos para fuzzing (variantes: sin el parámetro final, con
   `/admin` o `/internal` antepuesto, versión `.bak`/`.old`/`.orig` de
   cada uno).
2. **Genérica de archivos sensibles** — SIEMPRE incluir, independiente
   del stack: `.git/config`, `.env`, `.env.local`, `.bak`, `.sql`,
   `.zip`, `backup/`, `.DS_Store`. Ver `references/common-sensitive-files.md`.
3. Combinar 1+2, deduplicar → wordlist chica para la primera corrida.

### Pasada 2 — SecLists local, por stack (escalada, no siempre)

Solo si la pasada 1 no encontró nada interesante (criterio: 0-1
hallazgos que sobrevivan el filtro de soft-404). Requiere que el
operador confirme antes de escalar — no es automático por default
(ver "Manual vs automático" abajo).

SecLists está cacheado localmente vía sparse-checkout, no clonado
completo (repo entero pesa varios GB; `Discovery/Web-Content/` sola
son ~200MB). Path configurado como variable de entorno, mismo patrón
que `.credentials/<target>.env`:

```bash
export SECLISTS_PATH="/path/to/SecLists"
```

Configurá esa variable con la ubicación local de SecLists antes de la pasada
2; no asumas una ruta fija del equipo. Si el checkout incluye
`seclist/SecLists`, podés usar esa ruta desde la raíz del repositorio.

El agente lee el stack de `recon.md` (ya identificado ahí, este skill
NO hace fingerprint de tecnología — eso es trabajo de Recon) y mapea a
un archivo puntual dentro de `$SECLISTS_PATH/Discovery/Web-Content/`
según `references/stack-to-seclist.md`. Si el archivo mapeado no está
en el checkout local todavía, bajarlo puntual con `curl` desde
`raw.githubusercontent.com` (ya en allowlist de red) en vez de ampliar
el sparse-checkout — mantiene el cacheo local liviano y creciendo solo
por uso real, no por las dudas.

**Nunca la lista completa de SecLists de un tirón** — un archivo
puntual (`raft-medium-directories.txt`, o el específico del stack) a
la vez, filtrado por baseline, igual que la pasada 1.

### Manual vs automático (arrancar en manual)

Por ahora la escalada a pasada 2 es **manual**: el agente corre pasada
1, reporta resultados, y el operador decide si pide la pasada 2 y con
qué archivo. Pasar a automático (el agente escala solo si pasada 1 da
0-1 hallazgos) recién cuando haya calibración real de cuánto ruido da
la dirigida en un target de los tres programas activos.

## Control de intensidad

El rate limit heredado del resto del pipeline (`-rl 3 -c 1` de katana)
es el default. El agente puede ajustar la intensidad si se le indica
explícitamente, con estos tres niveles — nunca asumir "agresivo" sin
instrucción directa, dado que estamos en programas con reglas de
scope activas (ver nota de Wien abajo):

| Nivel | ffuf flags | Cuándo usarlo |
|---|---|---|
| **Lento (default)** | `-rate 3 -t 1` | Default en cualquier target de programa activo, salvo indicación contraria |
| **Moderado** | `-rate 10 -t 5` | Solo si el programa confirma que no hay política de rate-limit-as-DoS, o en labs propios |
| **Agresivo** | `-rate 50+ -t 20+` | Solo en targets propios/labs locales (BBLabs Docker), NUNCA contra programa activo sin autorización explícita |

**Nota de scope:** si el programa (ej. Wien) excluye rate limiting y
tiene reglas de DoS por request único, fuzzing agresivo puede
constituir el mismo tipo de comportamiento excluido — confirmar reglas
del programa antes de subir de "lento" en cualquier target real.

## Testing Flow

1. Baseline de soft-404 (obligatorio, ver Gate arriba).
2. Construir wordlist combinada (paso "Construcción de wordlist").
3. Correr ffuf con el nivel de intensidad indicado, filtrando por el
   baseline (código/tamaño/hash que NO coincida con el soft-404).
4. Listar resultados crudos: path, código, tamaño — sin clasificar.
5. Entregar la lista a Triage (o directamente al operador) para
   decidir handoff a la skill correspondiente.

## Related Skills & Chains

- **`exposed-secrets`** — si el hallazgo es `.env`, `.git/config`, un
  archivo de backup con credenciales, el handoff va acá.
- **`idor-bola`** — si el hallazgo es un panel/endpoint sin auth que
  expone datos o acciones.
- **`domain-recon`** — este skill asume que domain-recon y katana ya
  corrieron; no reemplaza el crawling pasivo, lo complementa.
- **`hunt-fuzzing-params`** (parámetros — skill hermana, gate
  distinto) — si el hallazgo de acá es un endpoint conocido pero
  interesa qué PARÁMETROS acepta, no qué rutas existen, es la otra
  skill, no ésta.

## Referencias

- `references/tech-wordlists.md` — wordlists por stack detectado,
  carga condicional según fingerprint de recon.
- `references/common-sensitive-files.md` — lista base de archivos
  sensibles genéricos, se carga siempre (paso 3 de construcción).
