---
name: xss-reflected
description: Detecta y valida XSS reflejado — input de request (query, body,
  header, cookie) que la response devuelve sin persistir, en contexto
  peligroso de renderizado. Usar cuando un parámetro vuelve sin escapar en
  HTML body, atributo, bloque script, atributo de evento, URL, o cuando
  aparece en un mensaje de error (validación, stack trace) sin escapar.
---

# XSS Reflected

Trabajá sobre el caso concreto que dio el operador. No cargues
`references/common-xss.md` de `xss` entero de entrada — solo las
secciones puntuales que necesites, citadas abajo.

## Qué buscar

Source: cualquier param de request (query, body, header, cookie) que la
response devuelve sin persistir. Sink: se refleja en contexto peligroso —
HTML body, atributo, bloque `<script>`, atributo de evento, URL.

### Fuentes y salidas que suelen omitirse

Además de los valores de campos obvios, considera segmentos de ruta, nombres de
parámetros, headers/cookies, opciones de formato o render, y mensajes de error,
redirecciones y fallbacks si la aplicación los expone. Una entrada inválida que
aparece en una respuesta es solo una señal: confirma la ruta alcanzable, el tipo
de contenido, el contexto del navegador y la ejecución. Un valor reflejado en JSON
no demuestra XSS por sí solo; si el sink está en el cliente, enrútalo a `xss-dom`.

**Source subestimado: error handlers que citan el input.**
Mandar valores inválidos deliberadamente como parte del fuzzing normal —
no solo valores plausibles. Muchos frameworks citan el valor ofensivo en
el cuerpo del error sin escapar, creando reflected XSS en el path de
error en vez del path feliz.

Sistemas que hacen esto habitualmente:
- **GeoServer / WMS/WFS OGC**: un `format=` o `service=` inválido devuelve
  un `ServiceExceptionReport` XML con el valor reproducido dentro de
  `<ServiceException>`. Si el cliente lo renderiza como HTML (browser
  directo o app que inyecta la respuesta en el DOM), es XSS.
- **Frameworks web genéricos**: `ValidationException`, `IllegalArgumentException`,
  `ParameterBindingException` que incluyen el valor en `"message"` o en
  un stack trace HTML de desarrollo.
- **APIs REST con error bodies**: `{"error": "format 'VALOR' not recognized"}` —
  si ese JSON se renderiza sin escapar en el frontend, en realidad es
  `xss-dom`, no este skill — el server solo refleja JSON, el sink lo
  arma el cliente.

El sink varía según cómo el sistema devuelve el error:
- XML de error (`ServiceException`, `ExceptionReport`) → el valor queda en
  text content de un nodo XML; si el browser lo renderiza como HTML → sink HTML body
- HTML de error (stack trace, página 400/500) → sink HTML body o atributo

Payload para este path: el canary estándar (`'"><img src=x onerror=alert(1)>`)
funciona igual — lo que cambia es que hay que mandarlo como valor de parámetros
que el sistema valida, no solo los que parecen aceptar input libre. Ver también
"Sources adicionales — injection surface ampliada" (nombre de parámetro, path
segments, headers) en `../xss/references/common-xss.md`.

### XML Context (variante reflejada)

Source: input reflejado en respuestas XML (APIs REST/SOAP que devuelven
`Content-Type: text/xml` o `application/xml`), SVG servido como XML,
respuestas XHTML con parser XML estricto.

El riesgo ocurre cuando:
1. El browser renderiza el XML directamente (no via JS) → `<script>` en SVG
   ejecuta en el origen del SVG
2. El renderer del XML hace entity expansion que resulta en HTML ejecutable

```xml
<!-- SVG served as image/svg+xml — ejecuta en origen del SVG -->
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.domain)</script>
</svg>

<!-- CDATA bypass en XML: el parser XML ignora el contenido como markup -->
<element><![CDATA[</element><script>alert(1)</script><!--]]></element>

<!-- Atributo en XML sin escape correcto -->
<item id="x" title="PAYLOAD">
```

Canary para XML context: `]]><script>alert(1)</script><!--` — si el parser
XML procesa el CDATA de cierre y el output llega al browser, ejecuta.

Killer: XML bien formado con encoding de entidades (`&lt;`, `&gt;`, `&amp;`)
en todos los nodos de texto y atributos antes de serializar la respuesta.

## Qué mata el lead

- Hay encoding/escape antes del sink (HTML entity encode, escaping
  contexto-aware).
- El framework autoescapa por default (React/Angular/Vue con binding
  estándar, sin `dangerouslySetInnerHTML`/`v-html`/innerHTML explícito) y
  no hay bypass del binding — ver tabla de frameworks en
  `../xss/references/common-xss.md`.
- Sanitizer server-side activo **y la identidad confirma uno de los dos resistentes**
  (sanitize-html o loofah). Para cualquier otro sanitizer conocido (DOMPurify viejo,
  AntiSamy, JSoup, HtmlSanitizer, Typo3, rgrove/sanitize, google-caja...) no cerrar
  el lead — ver sección mXSS en `../xss/references/bypass-techniques.md`.
- El contexto de reflexión no es explotable aunque no escape (ej: dentro
  de un comentario HTML, o un atributo que no acepta eventos).

## Severidad

Sin ejecución confirmada (reflejo crudo en navegador real) = Informational
o P4 máximo. Nunca reportar por la sola presencia del patrón.

Depende de si requiere interacción (víctima clickea un link) vs
auto-ejecutable, y de qué habilita el JS (robo de sesión/token vs
defacement cosmético). Ver "Impact framing" en `../xss/references/common-xss.md`
para la escalada de PoC y las reglas de `HttpOnly`/`SameSite` antes de
elegir el vector de impacto.

## Referencias condicionales

- Contexto de reflexión (tabla de escape por contexto), polyglots, kxss
  cheatsheet, framework gotchas, impact framing, self-XSS encadenable:
  `../xss/references/common-xss.md`.
- Filtro observado con outcome BLOCKED o SANITIZED (canary strippeado): 
  `../xss/references/filter-probing.md`, luego `../xss/references/bypass-techniques.md`.
  Si el outcome es SANITIZED (sanitizer HTML, no WAF regex), ir directo a la sección
  mXSS / Parsing Differentials en bypass-techniques.md — el probing clásico es
  secundario en ese caso.
- Catálogo de vectores por contexto exacto: `../xss/references/vector-catalog.md`
  (buscar dirigido en `portswigger-vectors.json`, no volcar entero).
- JS ejecutado y catálogo insuficiente: `../xss/references/constructive-synthesis.md`.
- Formatos alternativos, impresores/exportadores o ramas de error/fallback:
  `../xss/references/output-mode-reflection.md`.
- WAF bloqueando una prueba autorizada: `../xss/references/wafbypass/SKILL.md`.
