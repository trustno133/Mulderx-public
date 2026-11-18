---
name: exposed-secrets
description: Identificar, confirmar y evaluar impacto de secretos hardcodeados (API keys, tokens, credenciales) expuestos en source JS/front, .git filtrado, .env expuesto, sourcemaps, respuestas de API, páginas de error/500. Usar para bug bounty y pentesting autorizado cuando se busca información sensible filtrada en el código o infraestructura de un target.
---

## Metadata
- **Skill Name**: exposed-secrets
- **Folder**: exposed-secrets

## Descripción

Metodología para encontrar secretos reales (no placeholders) expuestos en superficie pública de un target, confirmarlos con validación viva read-only, y determinar dónde se usan / qué impacto real tienen. No es una lista de keywords para grepear — el catálogo de patterns por proveedor y las calls de validación viven en `references/`, cargados condicionalmente.

## Trigger Phrases

exposed secrets, hardcoded API key, hardcoded token, .env expuesto, .git expuesto, sourcemap leak, secret en source code, credential leak, token filtrado

## Conocimiento previo

Use the `hexbrain` skill for relevant public prior art when it can change the test plan; verify any lead against primary sources and target evidence.

## Instructions for Claude

### Paso 1 — Superficie de búsqueda
Cubrir, en este orden de probabilidad de hit:
1. JS bundleado del front (mismo scraping que ya usa el pipeline de XSS/SSRF)
2. `.git` expuesto (`/.git/config`, packed-refs, objetos — si hay `.git/HEAD` accesible, dumpear con herramienta tipo git-dumper antes de asumir que no hay nada)
3. Sourcemaps (`.js.map`) — revelan código fuente pre-build, ahí aparecen secrets que el minificado esconde
4. `.env` / archivos de config expuestos directo por path
5. Respuestas de API verbosas (debug mode, stack traces)
6. Páginas de error / HTTP 500 (stack traces con paths, a veces con creds de conexión a DB en el traceback)

**Si la fuente es un dump de JXScout Pro**: la UI etiqueta un bucket como
"Secrets", pero eso corresponde en el CLI (`get-matches`) al
`match_kind=sensitive_property_name`. Ese kind detecta **nombres de
propiedad/identificador** (`apiKey`, `secret`, `clientId`...) — el campo
`match_value` que devuelve es el nombre, nunca el valor asignado. Sirve
como **mapa de dónde mirar** (una variable llamada `apiKey` puede tener el
valor hardcodeado un par de líneas más abajo — usar `position.start.line/
column` para ir a leer el código fuente ahí), pero **no es el bucket a
filtrar directo** contra `provider-patterns.md` — filtrando ahí vas a
sacar 100% nombres de identificador, no secretos, por diseño del matcher.

Los match kinds que sí traen contenido/valor real para filtrar directo son
los que capturan literales: `jwt`, `private_key`, `github_pat`,
`slack_token`, `stripe_secret_key`, y similares si el proyecto los tiene
habilitados (`list-match-kinds` lista los disponibles). Empezar por esos
para la Regla del Paso 2, y usar `sensitive_property_name` solo como guía
de ubicación cuando esos no alcanzan.

### Paso 2 — Filtro: formato real, no keyword suelta
**No** buscar por `=secret`, `=api_key`, `=token` como criterio único — eso matchea `apiKeyLabel`, `isSecret`, variables de UI, y ahoga todo en falsos positivos.

Filtrar por **regex de formato real por proveedor** (ver `references/provider-patterns.md`: AWS, Stripe, GitHub, Slack, Twilio, SendGrid, Google, JWT, etc.) como criterio primario. El match por keyword genérico (`=secret`, `+ token = `) queda como fallback de **baja confianza**, nunca como confirmación.

**Descartar automáticamente** antes de reportar nada si el valor matchea patterns de placeholder: `YOUR_API_KEY`, `xxx`, `example`, `test`, `dummy`, `<REDACTED>`, `sk_test_` (test key, no live), `00000...`, o si viene de un archivo claramente de documentación/ejemplo (`README`, `docs/`, `.env.example`, `.env.sample`).

### Paso 3 — Validación viva (read-only)
Un pattern matcheado es una **pista**, no un finding. Confirmar con la call de validación **menos invasiva posible** del servicio dueño de la key (ver `references/validation-calls.md` — ej. `aws sts get-caller-identity` para AWS, no `s3 ls`; `balance retrieve` para Stripe, no listar customers).

Si la call de validación devuelve auth exitosa → key viva confirmada.
Si devuelve 401/403 → key muerta/rotada, no hay finding (documentar igual, puede ser útil como contexto).

### Paso 4 — Impacto: dónde se usa
Una vez confirmada viva, mapear:
- ¿Dónde en el código/flujo se consume esa key? (grep de uso, no solo definición)
- ¿Qué scope/permisos tiene? (una AWS key con `get-caller-identity` OK puede tener IAM policy mínima o full admin — no asumir, chequear con call read-only de permisos si existe)
- ¿Expone data de otros usuarios, PII, infra interna?

### Gate de evidencia — no negociable

Un finding se considera **confirmado** si y solo si se cumplen **ambas**:
1. El valor matchea formato real de un proveedor conocido (no placeholder, no test key)
2. La validación read-only contra el servicio dueño confirma que la key está **viva y autentica**

Sin validación viva → el finding no pasa de **Informational/P4** ("posible secreto expuesto, sin confirmar"), aunque el patterns matcheado se vea "obviamente real". Formato correcto no es lo mismo que key activa — puede estar rotada, revocada, o ser de un entorno muerto.

Severidad post-confirmación depende de impacto real (Paso 4), no del tipo de key en abstracto — una key de analytics de solo-lectura no es lo mismo que una con permisos de escritura sobre data de usuarios.
