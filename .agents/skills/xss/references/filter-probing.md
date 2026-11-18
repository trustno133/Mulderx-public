# Filter probing — caracterización del filtro antes del bypass

Cargar cuando hay canary reflejado confirmado y el objetivo es reversear
qué bloquea/sanitiza/encodea el filtro (WAF, sanitizer, blocklist, regex
custom) antes de tirar payloads. Este archivo NO genera bypass — produce
un mapa que alimenta `vector-catalog.md` para la selección de vectores.

## Principio

Antes de cualquier payload real: descubrir el corte del filtro. Sin este
paso, cualquier payload es tiro estadístico. Con este paso, la selección
de vectores del catálogo se vuelve quirúrgica — pasás de 144 candidatos a
~10 con probabilidad real de ejecutar.

*Nota lateral: esto es lo que separa "probar payloads de listas" de "hackear el filtro". La segunda cosa es la que rinde.*

## Output final

Un JSON estructurado — el "mapa del filtro" — con: contexto, source,
outcomes por carácter/keyword/evento, propiedades del filtro
(case-sensitive, byte-limit, multi-pass, encodings aceptadas), fingerprint
del WAF detectado, y un filtro de candidatos que se pasa a la selección
de vectores. Schema al final de este archivo.

## Los 4 outcomes

Toda respuesta a un probe se clasifica en uno de estos cuatro, no en
"pasa/no pasa". Confundir estos outcomes lleva a decisiones malas.

- **BLOCKED** — el request no alcanzó el sink. Evidencia: status 403/406/
  419, o 200 con block page en el body (Request Rejected, Sorry you have
  been blocked, incident ID, support ID, Ray ID), o timeout/tarpit
  anormal. El filtro cortó antes.
- **SANITIZED** — request pasó, reflection ocurre, pero los caracteres del
  probe fueron removidos. Ej: enviás `foo<bar>baz` y volvés `foobaz`. El
  filtro strippeó el tag entero. Distinto de encoding.
- **ENCODED** — request pasó, reflection ocurre, caracteres transformados a
  representación segura. Ej: `<` → `&lt;`, `"` → `&quot;`. El filtro
  escapó para el contexto.
- **RAW** — request pasó, reflection ocurre, caracteres devueltos idénticos
  al input. Este es el outcome que buscamos: significa que el filtro no
  tocó ese carácter en ese contexto.

*Nota lateral: RAW no garantiza ejecución — todavía tenés que salir del contexto y construir un payload válido. Pero RAW es la puerta abierta.*

## Qué observar por request

No mirar solo el body. Cada request produce señales en varios lugares y
todas importan para clasificar bien el outcome y detectar degradación de
la sesión.

- **Status code** — 403/406/419/451 → probable bloqueo. 429 → rate limit.
  5xx → puede ser tu culpa (mucho tráfico) o backend crasheando.
- **Body size** — cambios abruptos vs baseline del canary indican template
  distinto (block page). Si el body baja de 15KB a 500 bytes de golpe,
  cambió la respuesta.
- **Cookies observadas** — cambios en cookies WAF-relacionadas indican
  degradación de sesión. Lista de patrones a trackear:
  - `__cf_bm`, `cf_clearance`, `cf-ray` (Cloudflare)
  - `_abck`, `ak_bmsc`, `bm_sv`, `bm_sz` (Akamai Bot Manager)
  - `TS*` con hex, `TSPD101`, `F5_ST`, `BIGipServer*` (F5)
  - `incap_ses_*`, `visid_incap_*`, `reese84` (Imperva)
- **Headers de respuesta** — `X-Iinfo`, `cf-ray`, `akamai-grn`,
  `x-akamai-request-id`, presencia de support/incident/Ray ID en body.
  Estos identifican WAF y a veces la regla que disparó.
- **Timing** — delta vs baseline. Deep inspection tarda más. Un salto
  abrupto de 200ms a 2s sugiere que el filtro está inspeccionando ese
  payload más agresivamente.

## Rate y anti-ban

Sin esto, el probing se convierte en generador de bans. Reglas duras:

- **Baseline: 5 segundos entre probes.** No 3, no fijo. 5s con jitter
  (±1s aleatorio) para no parecer robot.
- **Backoff exponencial ante bloqueo.** Primer 403/406 → pausa 60s.
  Segundo bloqueo consecutivo → 120s. Tercero → 240s.
- **Mixin de tráfico legítimo.** Cada 3-4 probes de payload, mandar
  1-2 requests a rutas normales del target (root, `/robots.txt`, un CSS,
  una imagen). Rompe el patrón de "solo ataca".
- **Hard limit por sesión.** 3 pausas por backoff → sesión termina.
  No reintentar hasta próxima sesión (mínimo 24h para IP libre).
- **Kill signals — cortar sesión de inmediato:**
  - Cookie de WAF degradada: `_abck` con `~-1~` o `~0~` sostenido,
    `__cf_bm` regenerado sin motivo aparente entre requests
  - Challenge visible en body: Turnstile, hCaptcha, `cdn-cgi/challenge-
    platform/`, `_Incapsula_Resource`, Akamai sensor path
  - Redirect a URL de captcha
  - 3 códigos 5xx consecutivos (probable que hayas tirado el backend)

*Nota lateral: te comiste ban en geschichtewiki. Esta política es lo que evita repetirlo. Si el agente ignora estas reglas, cortalo vos manual.*

## Precondiciones (kill temprano)

Antes de arrancar el core loop, verificar:

1. **Auth configurada si el target lo requiere.** Cookie de sesión,
   token, header custom. Sin esto, todos los probes rebotan en login o
   401 y clasificás mal los outcomes.
2. **Baseline del target vivo.** Un GET al root retorna 200 (o el
   comportamiento normal esperado). Si el target está caído, probing es
   basura.
3. **No hay sesiones previas quemadas.** Chequear que no arrastramos
   cookies WAF degradadas de una sesión anterior interrumpida.

Si alguna falla: STOP. Documentar el motivo y no arrancar.

## Core loop

### Step 1 — Canary

Generar un token random alfanumérico de 8-12 caracteres. Evitar palabras
reales, evitar patrones que puedan matchear algo (no usar `test`, `xss`,
`admin`). Ejemplo: `kanjiu29a`, `xr7mq2pfv`.

Enviar el canary como valor del source objetivo. Buscar reflection en
el body de la response.

**Killers de este step:**
- Canary no aparece en el body → source no es reflected (o es stored,
  o es persistido pero rendereado en otra vista). STOP este flujo,
  pivotear a probing stored/blind.
- Canary aparece pero encodeado (`kanjiu29a` sale como `&kanjiu29a` o
  algo similar) → hay transformación por default. Documentar y ajustar
  expectativa para próximos probes.
- Canary aparece pero fragmentado (parcial) → filtro rompe strings
  largos, hay que probar canaries más cortos.

**Si el canary refleja limpio:** anotar coordenadas exactas — línea/
offset en el body, tag padre, atributo si aplica.

### Step 2 — Identificar contexto de reflection

Mirar el HTML alrededor del canary. Contextos posibles y cómo se ven:

- **HTML body node** — entre tags: `<div>CANARY</div>`, `<p>CANARY</p>`.
- **HTML attribute value** — dentro de comillas: `<input value="CANARY">`,
  `<a href="CANARY">`.
- **HTML attribute unquoted** — sin comillas: `<input value=CANARY>`.
  Contexto especialmente permisivo, cualquier espacio rompe el atributo.
- **JS string literal** — dentro de `<script>` o event handler:
  `<script>var x = "CANARY";</script>`, `onclick="doStuff('CANARY')"`.
  Ojo con qué comilla se usa.
- **URL context** — atributo href/src/action: `<a href="/search?q=CANARY">`.
  Probing tiene que respetar sintaxis URL.
- **CSS context** — dentro de `<style>` o atributo `style=""`.
  Probing especializado, distinto.
- **HTML comment** — `<!-- CANARY -->`. Salir del comentario primero
  (`-->`) antes de cualquier payload.
- **Script src / iframe src** — muy permisivo si controlás toda la URL.

**Regla dura:** cada contexto es un probing separado. El filtro puede
tratar el mismo carácter distinto según dónde caiga. Si el canary refleja
en dos contextos (raro pero pasa), correr el loop dos veces.

### Step 3 — Test caracteres individuales

Set base a probar, en este orden (los más restringidos primero):

```
<   >   "   '   =   (   )   `   \   ;   /   [   ]   {   }   :   #   %   &   +   *
```

Formato del probe: canary + char + canary. Ejemplo con canary `kanjiu29a`
y char `<`:

```
kanjiu29a<kanjiu29a
```

Esto permite localizar dónde quedó cada mitad y ver si el char sobrevivió
en medio. Enviar uno por request. Clasificar en los 4 outcomes.

**Trampas comunes:**
- `&` aislado puede llegar RAW pero pertenecer a otra estructura (ej:
  entity). No confundir "llegó raw" con "no hace nada".
- `%` aislado puede triggear url decoding en un middleware pero pasar
  el WAF. Anotarlo como RAW con nota.
- Backticks `` ` `` los ignora mucho filtro clásico. Alta probabilidad de RAW.

### Step 4 — Test keywords con bisección

Keywords base:

```
alert   prompt   confirm   eval   Function   setTimeout   setInterval
on   script   javascript   data   expression   import   require   src
href   srcdoc   innerHTML   document   window   location
```

**Estrategia bisección** — para no gastar 40 requests por keyword:

1. Probar keyword completa envuelta en canary: `kanjiu29a alert kanjiu29a`.
2. Si RAW → keyword pasa entera. Terminado para esa keyword.
3. Si BLOCKED → cortar la keyword al medio: probar `aler` sola.
   - Si `aler` BLOCKED → cortar a `al` → seguir bisectando.
   - Si `aler` RAW → el corte está entre `aler` y `alert`. Probar `alert`
     con un char extra: `alertx`. Si `alertx` BLOCKED también → el filtro
     matchea substring `alert`. Si `alertx` RAW → el filtro tiene word
     boundary (matchea solo `alert` exacto).
4. Si SANITIZED → mismo enfoque pero anotando cómo mutila.

**Por qué bisección importa:** con rate de 5s y 15 keywords, la
diferencia entre probing lineal (probar cada substring desde `a`) y
bisección es ~40 minutos vs ~2 minutos por keyword. En 15 keywords eso
es la diferencia entre terminar en la sesión o comerse ban a mitad.

### Step 5 — Test event handlers exóticos

Solo si algo del step 3 dejó pasar `<` y `=`. Sino no tiene sentido.

Lista corta priorizada (extraída del catálogo PortSwigger, eventos que
disparan sin interacción o con interacción mínima):

```
ontoggle              onbeforetoggle       onauxclick
onpointerenter        onbeforeinput        oncontentvisibilityautostatechange
onbeforematch         onanimationstart     onanimationend
onwebkitplaybacktargetavailabilitychanged
```

Formato del probe: envolver en un tag mínimo válido para hacer que el
filtro lo evalúe como atributo de evento real, no como texto suelto.
Ejemplo:

```
kanjiu29a<x ontoggle=y>kanjiu29a
```

Clasificar por evento. Los que llegan RAW son candidatos privilegiados
para el catálogo — significan que el filtro tiene blocklist estática de
los eventos "conocidos" (`onerror`, `onload`, `onclick`) pero no de estos.

*Nota lateral: `ontoggle` con `<details>` es probablemente el bypass más rentable de 2024-2026 contra F5 y Akamai antiguos. Vale probarlo siempre.*

### Step 6 — Test combos mínimos (opcional)

Solo si tenés caracteres RAW parciales — ej: `<` bloqueado pero `x` y `>` raw.

Combos a probar:

```
<x>       <x/>       <x y>       <x y=z>      <x y="z">
<x on=1>  <x/on=1>   <svg>       <svg/>
```

Descubre si el filtro bloquea solo tags de una blocklist (`<script`,
`<img`, `<iframe`) o cualquier tag-shape. Muchos filtros regex-based solo
matchean tags conocidos → cualquier tag custom pasa.

### Step 7 — Probes de propiedades del filtro

Con los outcomes de steps 3-6, hacer probes dirigidos para deducir
propiedades del filtro. Cada uno responde una pregunta específica.

#### 7a — Case sensitivity (flag `i` de la regex)

Si `alert` BLOCKED en step 4, probar variantes de caso:

```
AlErT    ALERT    alerT    ALert
```

Si alguna llega RAW → filtro sin flag `i` → **case mixing bypasseá todo
el resto de la blocklist**. Es un hallazgo mayor, anotarlo destacado.

#### 7b — Regex anchors y boundaries

Si `<script` BLOCKED, probar variantes con whitespace:

```
 <script      (espacio antes)
<script       (línea nueva antes con \n)
<	script      (tab entre < y script)
<script       (espacio dentro? probar <sc ript)
<Script       (mayúsculas — ya cubierto en 7a pero re-testear)
```

Detecta si la regex tiene anchors mal puestos o si el filtro no normaliza
whitespace. Un `<\tscript` que pasa significa que el parser HTML acepta
la tab como separador pero el filtro no la maneja.

#### 7c — Multi-pass replacement

Si `<script>` BLOCKED, probar:

```
<scr<script>ipt>
```

Lógica: si el filtro hace un solo pase de reemplazo (`filter.replace(/<script>/gi, '')`),
después del reemplazo queda `<script>` externo intacto. Payload clásico.

Si esto pasa RAW → el filtro es de un solo pase → hay un abanico entero
de bypass por nesting (`ononerrorerror`, `<<script>script>`).

#### 7d — Buffer / byte limit

**Hacer al final del loop, no antes.** Alto volumen de tráfico y riesgo
de rate limit.

Si probes cortos pasan y payloads reales bloquean, hay chance de
truncation attack. Enviar padding creciente antes del payload:

```
"A" * 1024   + <script>alert(1)</script>
"A" * 4096   + <script>alert(1)</script>
"A" * 8192   + <script>alert(1)</script>
"A" * 16384  + <script>alert(1)</script>
"A" * 32768  + <script>alert(1)</script>
```

Si en algún N el payload pasa → hay buffer limit → el WAF inspeccionó
solo los primeros N bytes. F5 ASM viejo se conoce con 8KB, Akamai con
32KB, algunos custom con 4KB.

**Cuidado:** cada request de esto pesa 30-60KB. Con rate de 5s son ~10
requests que van a llamar la atención. Considerarlo el último probe.

#### 7e — Null byte y control chars

**Saltear si WAF fingerprintea como F5 ASM** — F5 detecta null bytes y
bloquea inmediato. Contra F5 no vale la pena.

Contra otros WAFs, probar:

```
<script\x00>alert(1)</script>
<scr\x00ipt>alert(1)</script>
<script\x0dalert(1)</script>
<script\x0balert(1)</script>
```

Algunos filtros normalizan control chars, otros no. Algunos backends
tratan `\x00` como fin de string y truncan (útil o problemático según el
lado que trunque).

#### 7f — Encoding acceptance

Testear qué encodings el filtro acepta como equivalentes al carácter
crudo. Contra el carácter que llegó BLOCKED (típicamente `<`):

```
%3C           (URL encoded)
%253C         (double URL encoded)
&#60;         (HTML entity decimal)
&#x3C;        (HTML entity hex)
&lt;          (HTML entity named)
\x3C          (JS hex escape)
\u003C        (JS unicode escape)
\074          (JS octal)
```

**Ojo con el contexto:** HTML entities solo decodean en contexto HTML,
JS escapes solo en contexto JS. Testear cada encoding en el contexto
correcto — un HTML entity dentro de un `<script>` no se decodea, no
llegaría al parser HTML.

Clasificar cada encoding. Los que llegan RAW o SANITIZED-a-crudo abren
bypass por encoding.

#### 7g — Split/concat (contexto JS)

Solo aplica si estás en contexto JS. Si `alert` BLOCKED en input directo,
probar meter el string cortado:

```
canary + "ale" + canary + "rt" + canary
```

Si ambas mitades pasan RAW y el filtro no reconstruyó el string → el
filtro busca literales, no evalúa. Bypass: en el payload final,
reconstruís en runtime con `+`, template literals, o array joins.

*Nota lateral: esto también aplica a keywords como `eval`, `Function`, `document`. Todo el bypass de "destructuring dinámico" del bypass-techniques.md se apoya en que el filtro no reconstruye strings.*

### Step 8 — Build filter map

Consolidar todo en JSON estructurado (schema al final). Este es el output
del probing.

## Sources especiales

El core loop asume source visible con reflection en body. Para otros
sources, ajustes:

### Cookies

- **Reflection puede ser blind.** Muchas apps loguean cookies pero no las
  reflejan visualmente en la página. Sin reflection, no podés clasificar
  outcomes por observación de body.
- **Probing por cookie NO dispara los mismos checks WAF que query param.**
  Algunos WAFs solo inspeccionan query/body por defecto. Otros inspeccionan
  cookies pero con reglas distintas.
- **Approach recomendado:** primero mandar un canary crudo en cookie y ver
  si refleja en algún lado. Si no refleja, tratarlo como blind y usar OOB
  webhook para confirmar ejecución. Sin webhook, el probing por cookie
  queda como "hipótesis no confirmada" — Informational.

### Headers reflejados

User-Agent, Referer, X-Forwarded-For, X-Real-IP, custom headers
específicos del target. Casi siempre blind (van a logs de admin, sistemas
de analytics internos, dashboards).

Approach: OOB webhook obligatorio. El probing acá es distinto — no
clasificás outcomes por body, clasificás por callback recibido. Todos
los outcomes son:

- **CALLBACK** — el payload ejecutó en algún renderer downstream
- **NO CALLBACK** — no ejecutó, o ejecutó en contexto sin acceso a red,
  o todavía no lo vio nadie (dejar tiempo prudencial: 48-72h)

### Body JSON

Contexto adicional: JSON parsing en el server puede escapar/no escapar
distintos caracteres. Probar además del set base:

```
\"    \\    \/    \u003c    \n    \r    \t
```

Y ojo con Content-Type mismatch: si mandás JSON pero declarás
`application/x-www-form-urlencoded`, algunos backends parsean igual y
otros no. Cambia lo que inspecciona el WAF.

### Body multipart / file upload

**No es filter-probing clásico. Ver `file-upload-xss.md` para el flujo
completo.** Acá solo mencionar que los sources adicionales son:
Content-Type declarado, filename del part, y el contenido del archivo.

### URL fragment (`#...`)

Nunca viaja al server. Filter server-side no aplica. Solo relevante para
DOM XSS — probing en fragment es probing de sinks JS del cliente, no del
filtro del server. Fuera del scope de este archivo.

## Killers del probing

Cuándo declarar el target no-testeable (temporalmente o para la sesión):

- Canary no refleja después de retry en múltiples endpoints/params
- 3 pausas por backoff consumidas
- Cookie de WAF quemada de forma persistente
- Challenge JS interactivo aparece y no se puede resolver programáticamente
- Target retorna 5xx sostenido (posiblemente lo tiraste; ser buen ciudadano
  y no seguir martillando)

Documentar el killer en el target correspondiente. No dejar el probing
"a medias" — o completo, o cortado con razón anotada.

## Limitación crítica: sinks con decode implícito del lado cliente

Descubierto en calibración real (lab "JS URL some characters blocked",
sesión 2026-07-29) — no teórico, costó una sesión entera resolverlo.

**El problema:** el schema de 4 outcomes (BLOCKED/SANITIZED/ENCODED/RAW)
asume que `ENCODED` significa "neutralizado, el carácter no sirve para
bypass". Eso es correcto para la mayoría de sinks (HTML body, atributos
HTML) — pero es **falso** para sinks `javascript:` URI.

**Por qué:** el algoritmo de navegación de HTML hace percent-decode del
string completo de una URI `javascript:` ANTES de ejecutarla como código
— es parte del spec, ocurre en el navegador, en el momento del click.
`curl`/HTTP-only probing NUNCA ve este paso, porque no navega, solo lee
la respuesta del servidor. Entonces: un carácter que el servidor
percent-encodeó (ej. `=` → `%3d`) y que el probing HTTP-only clasifica
como `ENCODED` (⇒ "neutralizado") puede en realidad llegar **crudo y
funcional** al motor JS en el momento de la ejecución real — el
navegador deshace el encoding del servidor solo, gratis, sin que el
filtro pueda evitarlo.

**Regla dura:** para cualquier sink identificado como `javascript:` URI
(no `<script>`, no atributo de evento — específicamente el valor de un
atributo `href`/similar que arranca con `javascript:`), el outcome
`ENCODED` vía percent-encoding NO se puede tratar como bloqueo
confirmado. Reclasificar como `ENCODED-UNVERIFIED` para ese tipo de
sink puntual, y **no cerrar el lead como muerto sin confirmación de
ejecución real en browser** — HTTP-only probing es insuficiente para
descartar, no solo para confirmar, en este tipo de sink.

**Qué SÍ sigue siendo bloqueo real en este sink:** stripping literal
(el carácter desaparece por completo de la respuesta, no queda ni
encodeado) — eso el navegador no lo puede reconstruir de la nada,
sigue siendo un killer válido.

**Generalización:** cualquier sink con un paso de decode/parseo del
lado cliente entre "lo que sirve el servidor" y "lo que se ejecuta"
tiene este mismo punto ciego para HTTP-only probing — no es exclusivo
de `javascript:` URI. Otros candidatos a revisar con la misma
sospecha: contenido que pasa por `decodeURIComponent()` explícito en
JS del cliente antes de un sink, o `JSON.parse()` de un string que
contenga secuencias percent-encoded embebidas. Ante cualquiera de
estos, tratar `ENCODED` como no-concluyente hasta verificación real.

## Output — filter map (JSON schema)

```json
{
  "target": "https://example.tld/search",
  "source": {
    "kind": "query_param",
    "name": "q"
  },
  "context": "html_body",
  "reflection_evidence": "canary reflejado en <p class='result'>{{}}</p>",
  "waf_detected": {
    "vendor": "F5 ASM",
    "evidence": [
      "cookie TS<hex>",
      "body contiene 'Request Rejected' + support ID"
    ],
    "confidence": "high"
  },
  "outcomes": {
    "chars": {
      "<": "BLOCKED",
      ">": "BLOCKED",
      "\"": "ENCODED",
      "'": "RAW",
      "=": "RAW",
      "(": "RAW",
      ")": "RAW",
      "`": "RAW"
    },
    "keywords": {
      "alert": "BLOCKED",
      "prompt": "RAW",
      "eval": "BLOCKED",
      "onerror": "BLOCKED",
      "ontoggle": "RAW",
      "javascript": "BLOCKED",
      "data": "RAW"
    },
    "events_exotic": {
      "ontoggle": "RAW",
      "onauxclick": "RAW",
      "oncontentvisibilityautostatechange": "RAW"
    }
  },
  "properties": {
    "case_sensitive": false,
    "case_sensitive_evidence": "AlErT llegó RAW mientras alert BLOCKED",
    "multi_pass_replacement": false,
    "byte_limit": null,
    "byte_limit_note": "no testeado en esta sesión",
    "null_byte_normalized": false,
    "accepts_encoding": {
      "html_entity_decimal": "RAW → decoded a <",
      "html_entity_hex": "RAW → decoded a <",
      "url_double": "BLOCKED",
      "js_hex": "N/A (contexto no aplica)"
    }
  },
  "candidates_filter": {
    "exclude_chars_from_payload": ["<", ">"],
    "exclude_keywords_from_payload": ["alert", "eval", "onerror", "javascript"],
    "case_mixing_available": true,
    "encoding_available": ["html_entity_decimal", "html_entity_hex"],
    "preferred_events": ["ontoggle", "onauxclick", "oncontentvisibilityautostatechange"],
    "notes": [
      "backticks disponibles: alert`1` style bypass viable si reconstruimos keyword",
      "case mixing es la vía más rápida — probar AlErT primero"
    ]
  },
  "session_state": {
    "total_probes_sent": 47,
    "blocks_hit": 2,
    "pauses_taken": 1,
    "waf_cookies_state": "healthy",
    "elapsed_minutes": 8
  }
}
```

Este JSON se pasa a `vector-catalog.md` para la selección de vectores.
El vector-catalog aplica `candidates_filter` sobre el catálogo PortSwigger
y devuelve un ranking de payloads candidatos con probabilidad estimada
de bypass.

## Handoff al usuario

Cuando el probing termina, el agente entrega:

1. El JSON filter map
2. Un resumen en criollo de lo que encontró: "el filtro bloquea `<`, `>`,
   `alert`, `onerror` pero deja pasar case-mixing (`AlErT`), backticks,
   `ontoggle`, y HTML entities. F5 ASM detectado."
3. Top 5 vectores candidatos del catálogo, con el probe que los sostiene
4. Recomendación de próximo paso: cargar burp/browser y validar los top 5
   contra el target real. La confirmación de ejecución la hace el usuario,
   no el agente.

## No hacer

- Nunca reportar XSS por outcomes de probing. Probing dice "el filtro no
  bloquea esto"; no dice "ejecuta". Confirmación de ejecución es requisito
  para severidad > Informational.
- Nunca correr probing en producción sin haber testeado la política de
  rate/backoff en un target de laboratorio primero.
- Nunca ignorar los kill signals de sesión por "una probe más". Un ban
  cuesta la sesión entera y a veces más.
- Nunca asumir que un filtro se comporta igual en dos endpoints del mismo
  target. Cada endpoint requiere probing propio (mínimo un canary de
  verificación).
