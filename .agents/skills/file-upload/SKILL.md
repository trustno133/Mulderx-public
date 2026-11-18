---
name: file-upload
description: Identificar y explotar validación insuficiente en funcionalidad de subida de archivos — bypass de extensión/blacklist/whitelist, content-type spoofing, magic-byte mismatch, path traversal en filename, hasta lograr RCE (web shell) o escritura arbitraria. Usar cuando el target expone cualquier endpoint de upload (avatar, adjunto, import, media) y el objetivo es subir contenido ejecutable o escribir fuera del directorio esperado.
sources: internal (built from scratch, evidence-gate-first)
---

## Qué es esto y qué NO es

El objetivo real casi nunca es "subir un archivo" — es lograr que el
servidor **ejecute** algo que subiste (web shell → RCE) o que lo
**guarde en una ruta que no debería** (path traversal → sobrescribir
config, escapar el directorio de uploads). Un upload que solo permite
guardar una imagen real, servida como estático, sin ejecución posible,
no es un finding por sí solo — es superficie, no impacto.

## Gate de Confirmación (no negociable)

Igual que el resto del catálogo: sin PoC real no hay severidad.

| Nivel | Qué probaste | Techo |
|---|---|---|
| **Upload aceptado** | El archivo con extensión/contenido manipulado pasó la validación (200, mensaje de éxito) | Nada todavía — no es un finding |
| **Ejecución confirmada** | Accediste a la URL del archivo subido y el servidor lo **ejecutó** (output del script, no el código fuente crudo) | Recién acá arranca severidad — P3+ según impacto |
| **Impacto demostrado** | RCE con comando real, lectura de archivo sensible, o escritura fuera del directorio esperado, con evidencia concreta | P1/P2 según qué se leyó/ejecutó/sobrescribió |

Un upload "raro" que el server aceptó pero que se sirve como estático
(mismo contenido crudo de vuelta, Content-Type de imagen) es evidencia de
un bypass del FILTRO, no de RCE. No reportar como web shell sin la
ejecución confirmada.

**Por qué "upload aceptado" vale cero (a diferencia de CSRF nivel 1, que
vale Informational):** en CSRF, un 2xx con Origin spoofeado ya prueba algo
real sobre el server (el check de Origin es naif). Acá, un upload
aceptado con extensión/contenido manipulado no prueba nada por sí
mismo — la gran mayoría de apps aceptan cualquier archivo y lo sirven
como estático sin problema, eso es comportamiento normal, no un hallazgo.
El filtro pasado es una precondición para investigar, no evidencia de
nada explotable todavía.

## Conocimiento previo

Use the `hexbrain` skill for relevant public prior art when it can change the test plan; verify any lead against primary sources and target evidence.

## Testing Flow

1. **Baseline** — subir un archivo legítimo (jpg/png real), confirmar
   dónde se sirve (`/uploads/<nombre>`, `/files/...`, etc.) y qué
   `Content-Type` devuelve.
2. **Probar el rechazo** — subir el payload real (ej. `<?php system($_GET['c']); ?>`)
   con la extensión ejecutable obvia (`.php`). Anotar el mensaje de error
   exacto — dice mucho sobre si el check es whitelist o blacklist.
3. **Caracterizar el filtro** — antes de tirar bypasses al azar, aislar
   QUÉ exactamente valida: ¿última extensión después del último punto?
   ¿contains en vez de endswith? ¿Content-Type del header multipart?
   ¿magic bytes del contenido? Cada uno se prueba por separado, no se
   asume — ver `references/bypass-techniques.md`.
4. **Confirmar ejecución** — GET directo a la URL del archivo subido.
   Si vuelve el código fuente crudo, el filtro bypasseó la subida pero
   NO hay ejecución (el servidor lo sirve estático). Si vuelve el
   output del script, hay RCE.
5. **Impacto** — leer archivo sensible, ejecutar comando, o encadenar
   con lo que dé el RCE.

## Root causes comunes

1. **Whitelist de extensión ancla mal** — valida la última extensión
   después del último punto (`.jpg`/`.png` pasan), pero el handler de
   ejecución del servidor (Apache `AddHandler`, no `FilesMatch $`)
   dispara por CUALQUIER extensión reconocida en el nombre, no solo la
   última. Confirmar empíricamente cuál de los dos modelos aplica antes
   de asumir que doble extensión (`shell.php.jpg`) alcanza — en configs
   modernas (`FilesMatch \.php$`) NO alcanza por sí sola.
2. **Validación y guardado leen el filename de fuentes distintas** —
   la validación mira un campo/regex, el guardado real usa otro
   (`filename` vs `filename*` RFC 5987, primera vs última ocurrencia de
   un campo duplicado, string crudo vs decodificado). El bypass real
   está en encontrar ESE diferencial, no en la obfuscación en sí. Ver
   `references/bypass-techniques.md` para la técnica de null byte
   como ejemplo concreto de este patrón — **con la advertencia de que
   el null byte está prácticamente muerto en stacks modernos** (PHP lo
   parchó en 5.3.4, 2011; la mayoría de runtimes actuales no lo tienen).
   Confirmar el lenguaje/versión del backend antes de gastar tiempo en
   esto — no es un bypass de rutina en 2026, es una nota histórica que
   solo aplica a legacy confirmado.
3. **Content-Type del multipart no se valida, o se valida en vez de la
   extensión** — probar content-type mentiroso primero, es gratis.
4. **Magic bytes no se validan** — el filtro confía en la extensión
   pero nunca abre el archivo, o el chequeo de magic bytes solo mira
   los primeros N bytes y el resto del archivo (con el payload real) no
   se toca — polyglot (imagen válida + payload al final o en metadata).
5. **Filename sin sanitizar habilita path traversal** — `../../` en el
   nombre del archivo puede escribir fuera del directorio de uploads
   si el backend concatena sin normalizar la ruta.

## Related Skills & Chains

Este skill cubre específicamente **ejecución server-side vía upload**. Si
el resultado no es RCE, no descartar el upload — capaz el finding real
está en otra skill:

- **`hunt-xss`** — si el server sirve el archivo subido con el
  Content-Type/extensión que VOS elegiste (ej. subís un `.svg` o `.html`
  y te lo devuelve como `image/svg+xml` o `text/html` en vez de forzar
  `Content-Disposition: attachment` o sanitizar), eso es stored XSS, no
  RCE. Confirmar el Content-Type de respuesta en el baseline (paso 1)
  y, si es "servido tal cual", saltar a `hunt-xss` en vez de seguir
  buscando ejecución acá.
- **Zip Slip** (sin skill propia todavía — evaluar si amerita una) — si
  el upload acepta `.zip`/`.tar`/`.tar.gz` y el server lo EXTRAE
  server-side, el vector de traversal no es el filename del upload
  (eso ya está en root cause 5) sino los nombres de entrada DENTRO del
  archivo comprimido. Es un mecanismo de testing distinto: armar un
  archivo con entradas tipo `../../../etc/cron.d/x` y confirmar dónde
  termina escribiendo la extracción. No asumir que las mismas técnicas
  de filename bypass de acá aplican.
- **`ssrf`** — si en vez de un upload directo hay un "importar desde
  URL" (avatar por link, importar imagen remota, etc.), esa
  funcionalidad es SSRF, no file-upload — el server hace el fetch, no
  vos. Redirigir a la skill de SSRF si aparece ese patrón.

## Referencias

- `references/bypass-techniques.md` — catálogo de bypass por tipo de
  defensa (extensión, content-type, magic bytes, traversal), con la
  técnica de null byte (`%00`) documentada en detalle porque tiene un
  gotcha real de testing (raw byte vs string literal) — marcada como
  probablemente inútil salvo legacy confirmado, ver root cause 2.
