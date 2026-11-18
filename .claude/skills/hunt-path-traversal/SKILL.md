---
name: hunt-path-traversal
description: Identificar y explotar path traversal y arbitrary file read/write. Cubre lectura de archivos fuera del directorio base (../../../etc/passwd, /proc/self/environ, .env, configs), escritura arbitraria fuera del directorio esperado (upload con filename traversal), internal path traversal via API forwarding (user_id=../../admin/roles), y escalada a LFI/RCE. Usar cuando el target tiene endpoints que aceptan nombres de archivo, rutas, paths en params o body JSON, o cuando hay funcionalidad de download/export/preview/template.
sources: YesWeHack practical guide (2025-05), PayloadsAllTheThings, bug bounty reports HackerOne
---

## Qué es esto y qué NO es

Tres primitivos distintos — no son el mismo bug:

1. **Path Traversal / Arbitrary File Read** — input del usuario construye
   una ruta de archivo sin validar. El atacante lee archivos fuera del
   directorio esperado. "Read" es el impacto mínimo.
2. **Arbitrary File Write** — el servidor escribe en una ruta controlada
   por el atacante (upload con filename traversal, export con path
   controlado). Impacto mayor — puede llegar a RCE si el archivo escrito
   es ejecutable.
3. **Internal Path Traversal via API forwarding** — el servidor toma
   input del usuario para construir una ruta de API interna y la
   reenvía internamente. No es un file read — es un bypass de routing
   hacia endpoints internos privilegiados.

Estos tres tienen gates de evidencia distintos. Identificar cuál aplica
antes de empezar a probar payloads.

Esto NO cubre LFI directa (PHP `include($_GET['page'])`) ni RFI — esos
son skills de explotación de server-side injection, no de traversal.
La cadena traversal → LFI → RCE sí se documenta acá como escalada
posible, pero el skill arranca en el primitivo de traversal.

## Gate de Confirmación

### Read (Primitivo 1)

| Nivel | Qué probaste | Estado |
|---|---|---|
| **Payload enviado, respuesta distinta** | El server responde diferente a `../../../etc/passwd` vs un path inválido, pero sin contenido confirmado | Señal — no es confirmado todavía |
| **Confirmado (derivado)** | Error message revela que intentó abrir un archivo fuera del base dir, o timing diferente en archivos que existen vs no existen | Derivado — hay traversal pero no lectura confirmada |
| **Confirmado (verificado)** | El contenido del archivo aparece en la respuesta (`/etc/passwd`, contenido de `.env`, o archivo conocido con contenido predecible) | Confirmado — documentar qué archivo y qué contiene |
| **Impacto documentado** | Qué hay en el archivo leído (credenciales, tokens, source code, keys) | Recién acá arranca la severidad real |

### Write (Primitivo 2)

| Nivel | Estado |
|---|---|
| **Archivo escrito fuera del dir base** | Confirmado solo si podés verificar que el archivo existe en la ruta destino (ej: leerlo después con el primitivo 1, o una ruta predecible que el server sirve) |
| **RCE escalada** | El archivo escrito es interpretado como código por el server (requiere verificación separada — un webshell que responde, no solo "upload exitoso") |

"Upload aceptado" o "2xx response" sin verificar el archivo en destino = nada. Mismo criterio que IDOR: sin verificación desde fuera, no es confirmado.

### Internal API Traversal (Primitivo 3)

| Nivel | Estado |
|---|---|
| **Respuesta diferente con payload de traversal** | Señal — el server respondió distinto (código diferente, mensaje diferente, timing) |
| **Confirmado** | La respuesta del endpoint interno es visible en la respuesta del cliente, O el comportamiento demuestra que se ejecutó una acción en el endpoint interno (cambio de estado, error de permiso de ese endpoint específico) |

## Dónde buscar (señales que disparan este skill)

- `?file=`, `?path=`, `?filename=`, `?template=`, `?page=` en query string
- `{"filename": ...}`, `{"path": ...}`, `{"templatePath": ...}` en body JSON
- Endpoints de download, export, preview, backup, log viewer
- Upload de archivos con control del nombre final en el servidor
- `user_id`, `resource_id`, o cualquier ID que construya una ruta interna en microservicios
- GraphQL: `readFile(path: ...)`, `getDocument(name: ...)`

## Conocimiento previo

Use the `hexbrain` skill for relevant public prior art when it can change the test plan; verify any lead against primary sources and target evidence.

## Testing Flow

### Paso 1 — Baseline

Antes de tirar payloads, confirmar cómo responde el server a:
- Un path válido (la funcionalidad normal)
- Un path inválido/inexistente (`/asdf-noexiste-12345`)
- Un path fuera del base dir con traversal básico (`../../../etc/passwd`)

Diferencia en código HTTP, tamaño, timing, o mensaje de error entre estos
tres = señal de traversal. Sin diferencia = dead (o el filtro está muy
arriba en el stack).

### Paso 2 — Identificar el primitivo

¿El endpoint lee un archivo y devuelve su contenido? → Primitivo 1
¿El endpoint escribe/guarda un archivo con nombre controlable? → Primitivo 2
¿El endpoint hace un request interno usando el input? → Primitivo 3

### Paso 3 — Payloads por primitivo

Ver `references/payloads.md` para la lista completa con encodings y
bypasses. Orden de prueba:

1. `../../../etc/passwd` (bare, sin encode — confirmar si hay filtro)
2. `%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd` (URL encode)
3. `%252e%252e%252f` (double encode)
4. `..\\..\\.\\etc\\passwd` (Windows / mixed slashes)
5. Null byte: `../../../etc/passwd%00.jpg` (legacy, PHP < 5.3.4)

Si hay filtro de extensión pero no de contenido del path:
- `../../../etc/passwd%00.pdf` (null byte antes de la extensión esperada)
- `../../../etc/passwd.jpg` si el server no valida la extensión real del archivo

### Paso 4 — Archivos target (prioridad)

Ver `references/target-files.md` para la lista completa. Quick wins:
- `/etc/passwd` — PoC de read, sin impacto crítico por sí solo
- `/proc/self/environ` — variables de entorno en runtime (AWS keys, tokens, flags de debug)
- `.env`, `config.json`, `settings.py` — secretos, DB creds, API keys
- `/var/task/index.js` (AWS Lambda) — source code del servicio
- `.git/config` — metadata del repo

Para write: apuntar a rutas que el servidor sirva como estáticas o
ejecute (webroot, directorio de templates, cron.d).

### Paso 5 — Escalada

Si confirmás read:
- ¿El archivo leído contiene credenciales? → chain con `exposed-secrets`
- ¿Hay SSRF disponible además? → internal path traversal via forwarding
- ¿El servidor incluye/evalúa archivos? → LFI candidato (documentar, no explotar sin confirmar)

Si confirmás write:
- ¿Podés escribir en webroot o directorio de templates? → RCE candidato
- ¿Podés sobrescribir un archivo de config? → escalada a misconfig

## Root causes comunes

1. `path.join(base, userInput)` sin validar que el resultado empiece con `base`
2. Regex de filtro que bloquea `../` pero no encodings equivalentes
3. Frontend strips `../` pero el backend no valida
4. Extension validation sin validar el path completo (solo chequea `.csv`, no todo lo anterior)
5. Microservicio que construye rutas internas con input no sanitizado

## Related Skills & Chains

- **`exposed-secrets`** — si el file read expone credenciales, tokens, o keys
- **`ssrf`** — internal path traversal via API forwarding tiene superposición con SSRF; si el mecanismo de entrega es vía redirect de URL en vez de path construction, es SSRF, no traversal
- **`file-upload`** — el primitivo 2 (write) suele aparecer en contextos de upload; si el vector de entrada es un upload multipart, cruzar con ese skill
- **`idor-bola`** — si el traversal expone archivos de otros usuarios (no del sistema), el impacto se documenta como IDOR también

## Referencias

- `references/payloads.md` — payloads completos por tipo de bypass, carga cuando hay filtro activo
- `references/target-files.md` — archivos de alto valor por OS/entorno, carga cuando hay read confirmado
