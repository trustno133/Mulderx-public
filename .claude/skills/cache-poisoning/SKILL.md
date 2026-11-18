---
name: cache-poisoning
description: Explotar discrepancias entre lo que el cache usa como key y lo que el backend realmente procesa, para lograr que una respuesta dañina quede cacheada y se sirva a otros usuarios. Trigger cuando aparezcan headers de cache (X-Cache, Age, CF-Cache-Status, Cache-Control con max-age), cuando el target esté detrás de una CDN, o cuando el operador mencione "cache poisoning", "envenenar cache", "unkeyed header/param". NO usar para JS estático de un dump (JXScout/similar) — esto es comportamiento en vivo, no análisis de bundle.
---

# Cache Poisoning

## Qué es esto (una frase)
El cache y el backend no ven la misma request de la misma forma — hay partes que el backend procesa pero el cache ignora al armar la "cache key" ("unkeyed"). Si metés algo dañino en una parte unkeyed y el backend lo refleja, esa respuesta dañina puede quedar guardada y servirse a cualquiera que pida la misma URL después.

## Cuándo NO aplica esto
- Si no hay cache en el medio, no hay nada que envenenar. Confirmar primero buscando: `Age`, `X-Cache`, `CF-Cache-Status`, `Via`, `X-Served-By`, o `Cache-Control: public/max-age=...`.
- No confundir con **cache deception** (skill separado, `../cache-deception/`). Acá el ataque es "meter algo dañino en una respuesta que se cachea". Deception es "engañar al cache para que guarde algo que no debería cachearse".
- No sale de un dump de JS estático (JXScout y similares). Es comportamiento de cache en vivo: requests con headers/params raros y observar si la respuesta se cachea y se sirve a otros.

## Riesgo operacional — leer antes de tocar un target vivo
Cada request de prueba sin cache buster puede pisar la respuesta que reciben usuarios reales del target, no solo la tuya.
- SIEMPRE agregar un parámetro cache-buster único (`?cb=<random>`) en cada request de sondeo, hasta el momento exacto en que confirmás el hallazgo.
- Antes de cerrar la sesión de testing, si el cache quedó con tu payload activo (sin cache buster), intentar volver a pisarlo con una request limpia.

**Lab de entrenamiento vs. target real — no confundir el protocolo.** En
un lab de un solo tenant (ej. PortSwigger Academy) es intencional y
correcto envenenar la URL canónica SIN cache buster una vez confirmado
el gate — es la única forma de que el checker automático (que visita
la URL real, no una con `?cb=`) vea el payload, y no hay usuarios
reales de por medio. **En un target en producción esto NO aplica
igual**: envenenar la URL canónica expone el payload a usuarios reales
inmediatamente. Ahí:
- Nunca envenenar sin cache buster hasta tener autorización explícita
  y ventana coordinada con el operador/programa.
- Preferir una PoC de bajo impacto para la evidencia final (ej. un
  string inocuo detectable, no un `alert()` ni exfiltración real) y
  dejar que el operador decida el payload de la prueba de concepto
  final — regla no negociable de `CLAUDE.md`: la decisión de qué se
  ejecuta en producción no la toma el agente.
- Repoblar el cache con una request limpia inmediatamente después de
  cada ventana de prueba, y verificar que quedó limpio antes de cerrar
  la sesión.

## Conocimiento previo

Use the `hexbrain` skill for relevant public prior art when it can change the test plan; verify any lead against primary sources and target evidence.

## Loop de trabajo

### Paso 1 — Identificar inputs unkeyed
Un "unkeyed input" es cualquier parte de la request (header, cookie, param) que el backend procesa pero el cache ignora al decidir si sirve una respuesta cacheada.
- Manual: agregar headers/cookies/params al azar (siempre con cache buster) y ver si cambian la respuesta.
- Con Burp: extensión Param Miner → "Guess headers" / "Guess cookies" / "Guess params" (fuzzing automático contra wordlist).
- Ver `references/design-flaws-catalog.md` (headers/cookies clásicos) y `references/implementation-flaws-catalog.md` (manipular la cache key en sí — más avanzado).

### Paso 2 — Provocar una respuesta dañina
Con el input unkeyed confirmado, ver cómo lo procesa el backend:
- ¿Se refleja sin sanitizar en HTML/JS? → candidato a XSS vía poisoning (ver skill `../xss/` para la construcción del payload).
- ¿Se usa para armar una URL absoluta (import de JS, redirect)? → candidato a hijack de recurso u open redirect.
- ¿Cambia idioma/región/contenido servido? → impacto menor pero sigue siendo poisoning.
- **Un solo header puede no alcanzar.** Si un header candidato no tiene efecto solo, no descartarlo — probarlo combinado con un segundo header (típicamente uno que dispare una rama de código distinta, ej. un header de esquema/protocolo que solo importa cuando vale algo distinto de `https`). Un patrón clásico: header A controla el valor inyectado, header B es el que decide si esa rama de código se ejecuta. Ninguno de los dos muestra nada raro por separado.

### Paso 2.5 — Identificar el recurso correcto a envenenar (no asumir que es el documento HTML)
Antes de comprometerse a explotar el input confirmado, identificar QUÉ URL hay que envenenar — no siempre es la página donde se descubrió el bug:
- Si el HTML de la respuesta carga un `<script>`/`<link>`/`<img>` con **src/href ABSOLUTO** (`//host/recurso` o `https://host/recurso`) y el host viene del input unkeyed → el documento principal ES el target correcto (el string dañino queda embebido directo en el HTML servido).
- Si el src/href es **RELATIVO** (`/resources/algo.js`) → el navegador de la víctima pide ESE recurso como una request HTTP aparte, cacheada de forma independiente. Envenenar el documento que lo referencia no tiene ningún efecto sobre esa request. Hay que aplicar el mismo input unkeyed **directamente contra la URL del sub-recurso**.
- Señal de que se está atacando el activo equivocado: si el comportamiento del input (ej. un redirect) aplica igual en CUALQUIER path del sitio (probarlo en un segundo endpoint cualquiera para confirmar), es un middleware genérico — el impacto real está en encontrar el sub-recurso específico donde ese comportamiento genérico se vuelve peligroso, no en el primer lugar donde se lo observó.
- Señal operacional de que el target está mal elegido: después de confirmar el gate de poisoning (paso 3) y sostenerlo varios minutos, si no hay ningún indicio de que un tercero cargó la respuesta envenenada (ver "Diagnóstico" más abajo), reconsiderar el recurso atacado antes de asumir que "hay que tener más paciencia".

### Paso 3 — Confirmar que se cachea y se sirve (evidence gate)
No hay finding sin esto:
1. Enviar el request con el payload y un cache buster único.
2. Repetir el MISMO request (mismo cache buster) — confirmar `X-Cache: hit` (o equivalente, ver tabla abajo) y que el payload sigue en la respuesta.
3. **Crítico**: request SIN tus headers de ataque (o desde sesión distinta/incógnito) a la MISMA URL cacheada — confirmar que igual recibe tu payload. Si esto falla, no hay poisoning real: puede que solo estés viendo tu propio input reflejado, sin que se haya compartido vía cache.

### Trampa al verificar el gate — no uses una request "limpia" para revisar estado si eso puede repoblar el cache
Al reverificar (paso 3), cada request que hacés compite por poblar el cache si justo cae en una ventana de expiración (MISS). Si tu request de verificación NO lleva el payload/headers de ataque y cae justo en esa ventana, vas a re-envenenar el cache con contenido LIMPIO sin darte cuenta — pisando tu propio poisoning y generando falsos negativos intermitentes ("a veces funciona, a veces no"). Mientras estés sosteniendo un poisoning activo (loop de re-envenenado), que TODAS las requests del loop —incluidas las de chequeo/lectura de estado— lleven el mismo payload/headers de ataque. Recién hacé una request 100% limpia (sin headers) cuando quieras el veredicto final de "¿un tercero ve esto sin ayuda mía?".

### `Vary` — define el alcance del ataque, no lo bloquea
Si la respuesta trae `Vary: <header>` (comúnmente `User-Agent`, `Accept-Language`, `Accept-Encoding`), el cache SÍ está usando ese header como parte de la key — el poisoning sigue siendo posible, pero cada valor distinto de ese header tiene su propia entrada de cache independiente. Esto vuelve el ataque "targeted" en vez de masivo: tu payload solo llega a visitantes cuyo valor de ese header (ej. User-Agent exacto, byte a byte) coincida con el que usaste para envenenar.

**No adivines el valor — filtralo.** Probado en la práctica (lab de
entrenamiento, mismo comportamiento esperable contra cualquier cache
real con `Vary`): envenenar en paralelo varios User-Agent "plausibles"
(Chrome/Windows, HeadlessChrome/Linux, Safari/macOS, Firefox)
sostenido varios minutos **no funcionó** — la superficie de valores
posibles es demasiado grande para acertar a ciegas. Lo que sí
funciona: buscar CUALQUIER otro punto de la misma app donde puedas
lograr que el visitante objetivo haga una request observable por vos,
y leer su header real de ahí:
- **Content injection / stored HTML en cualquier parte de la app**
  (comentarios, perfil, ticket de soporte, nombre de producto) que
  permita `<img src=...>` u otro tag que dispare una request —
  inyectar una URL a infraestructura propia (exploit server, webhook,
  `requestbin`-like) y leer el access log. El propio `User-Agent`
  (y `Referer`, cookies si el vector lo permite) del visitante que
  cargue ese contenido queda registrado ahí, literal, sin adivinar.
- Si no hay un canal de content injection disponible, buscar cualquier
  otro log/telemetría accesible (analytics propio, error tracking) que
  exponga UA de visitantes reales a la página objetivo.
- Recién si NINGÚN canal de filtración está disponible, caer al
  fallback de envenenar varios UAs plausibles en paralelo — es la
  opción más débil, tratarla como último recurso, no como primer
  intento.
- No asumas que tu propio User-Agent por defecto (`curl/x.x`, el de tu
  herramienta) es el que va a usar la víctima real — casi seguro no lo
  es. Poblar el cache con el UA real filtrado, no con el default del
  cliente HTTP.

### Diagnóstico — cero tráfico de tercero después de sostener el poisoning es una señal, no solo falta de paciencia
Si tenés forma de ver quién más pidió el recurso envenenado (access log de un servidor propio hosteando el payload, logs del origin, analytics), y después de varios minutos sosteniendo el gate confirmado (paso 3 cumplido) seguís sin ver tráfico de otra IP/UA distinta a la tuya, no sigas asumiendo "debe tardar más" indefinidamente — es una señal fuerte de que el recurso atacado no es el que un visitante real/automatizado efectivamente carga. Volver al paso 2.5.

## Evidence gate — severidad
- **Sin el paso 3 confirmado (segunda request limpia recibe el payload) → no pasa de Informational/P4.**
- Paso 3 confirmado pero payload de bajo impacto (ej. solo cambia idioma) → Low/P4-P3.
- Paso 3 confirmado + XSS/redirect/resource hijack ejecutándose para el "usuario" simulado → recién ahí Medium/High según alcance (home page = alto tráfico = mayor impacto que una página profunda).

## Headers de cache por CDN/proxy (para leer resultado, no para asumir)
| Proveedor | Header |
|---|---|
| Varnish / genérico | `X-Cache: HIT\|MISS`, `Age` |
| Cloudflare | `CF-Cache-Status: HIT\|MISS\|DYNAMIC\|EXPIRED` |
| Fastly | `X-Served-By`, `X-Cache: HIT\|MISS` |
| Akamai | `X-Cache`, a veces sin headers visibles (silent caching) |

Si ninguno aparece, no asumir que no hay cache — puede que no exponga estado. Ahí el único gate válido es comportamental: mismo payload servido dos veces sin que vos lo reenvíes.

## Ver también
- `references/design-flaws-catalog.md` — inputs unkeyed clásicos (headers/cookies).
- `references/implementation-flaws-catalog.md` — manipulación de la cache key (query string, params, cloaking).
- `../cache-deception/SKILL.md` — técnica relacionada, no confundir.
- `../xss/` — la construcción del payload reflejado suele ser un problema de XSS, no de cache, una vez que el input unkeyed está confirmado.
