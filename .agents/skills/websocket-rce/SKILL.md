# Skill: WebSocket RCE / CSWH (Message-Driven Exploitation)

Capa: Server-side/Behavior. Complementa al skill de SAML — acá el vector de entrada
no es un login flow, es el canal bidireccional post-handshake.

## Cuándo se dispara
- Cualquier `Upgrade: websocket` en el tráfico
- Endpoints de Socket.IO (`/socket.io/`), SignalR (`/signalr/`), STOMP/SockJS
- Features de chat, notificaciones en tiempo real, dashboards live, bots internos
- Cualquier app que use WS para algo más que un ticker de precios (mientras más
  "acción" dispara un mensaje — comandos, queries, uploads — más superficie)

## Prerequisitos
1. Sesión autenticada propia, con el handshake y al menos un mensaje legítimo
   capturado por proxy (Burp tiene soporte nativo de WS, o mitmproxy)
2. El bundle JS del cliente descargado — ahí están TODOS los event names que el
   front puede emitir, no solo los que ves clickeando la UI
3. Si hay DNS/HTTP OOB server propio (ya tenés uno montado en Oracle) para
   confirmar ejecución real, no solo timing

## Conocimiento previo

Use the `hexbrain` skill for relevant public prior art when it can change the test plan; verify any lead against primary sources and target evidence.

## Metodología (orden de ataque)

1. **Fingerprint de protocolo**: raw WS vs Socket.IO vs SignalR vs STOMP.
   Mirar el primer frame del handshake/los primeros mensajes — cada uno tiene
   su propio framing (ej Socket.IO prefija con `42[...]`, SignalR con JSON+`\x1e`).

2. **CSWH (Cross-Site WebSocket Hijacking)**: el handshake HTTP inicial
   lleva cookies pero el browser NO manda custom headers en el upgrade —
   si el server no valida `Origin` en ese handshake, un sitio de terceros
   puede abrir el WS usando la sesión de la víctima y leer/mandar todo.
   - Test: handshake con `Origin: https://evil.com` (o el que corresponda)
     desde fuera del dominio real, confirmar si acepta y si el stream trae
     datos de la sesión autenticada.
   - Esto es justo lo que ya reportaste en stadtservicebot — mismo chequeo,
     aplicable a cualquier target nuevo.

3. **Mapeo de eventos/mensajes**: inventariar TODOS los tipos de mensaje
   (del bundle JS, no de la UI). Prestar atención especial a:
   - Eventos con nombres tipo `admin.*`, `debug.*`, `internal.*`, `exec.*`
   - Eventos que en el código cliente están condicionados por un rol pero
     el server nunca re-valida ese rol al recibir el evento

4. **Fuzzing de campos — 3 clases de bug a buscar**:
   - **Command injection (timing-based)**: reemplazar valores de campos
     de texto en mensajes legítimos por `; sleep 5`, `` `sleep 5` ``,
     `$(sleep 5)`, `| sleep 5 #`. Medir RTT contra baseline, 3-5 muestras
     por payload (para descartar jitter de red, no alcanza con una sola).
   - **Deserialización insegura**: si el mensaje es binario y el stack es
     Java, buscar magic bytes `AC ED 00 05` (Java serialization) en
     responses/mensajes salientes del server — si el server ACEPTA binario
     entrante con ese header y lo deserializa, ahí hay gadget chain
     potencial. No reinventar el payload: confirmar el vector primero,
     después generar el gadget con `ysoserial` (herramienta externa,
     establecida) apuntando al OOB server para confirmar ejecución real
     antes de reportar nada como RCE.
   - **Prototype pollution** (si el backend es Node): mandar un mensaje
     JSON con `"__proto__": {"polluted": true}` o
     `"constructor": {"prototype": {"polluted": true}}` en algún campo
     que sepas que el server mergea a un objeto de config/estado. Si
     después otro mensaje/endpoint refleja la propiedad `polluted`,
     confirmás el merge inseguro — desde ahí se escala a RCE según qué
     libs usa el stack (ver si usan `child_process` en algún lado que lea
     de config contaminable).

5. **AuthZ check en eventos privilegiados**: emitir directamente (sin pasar
   por la UI) los eventos `admin.*`/`internal.*` detectados en el paso 3,
   con tu sesión de usuario normal. Si el server ejecuta igual, es BAC a
   nivel de mensaje, no solo de HTTP route.

6. **Confirmación de impacto real**: para cualquier hallazgo de injection/
   deserialización, la única evidencia válida es ejecución confirmada vía
   canal OOB (DNS/HTTP callback) o un efecto observable server-side
   (archivo creado, respuesta que cambia de forma determinística). Un
   delay de 5s solo no alcanza si hay rate limiting o colas async que
   puedan generar el mismo patrón.

## Evidencia a loggear (para no inflar severidad)
- Handshake completo (request/response) con los headers de Origin probados
- Las 3-5 muestras de timing, no un solo request — un outlier aislado es ruido
- Callback OOB recibido (timestamp, IP origen) si se confirmó deserialización
  o command injection real
- Para prototype pollution: el mensaje de ida + la respuesta/estado que
  demuestra que la propiedad contaminó algo fuera del mensaje mismo
- Sin ejecución confirmada: command injection "sospechado por timing" es
  Informational, no P1. CSWH con datos sensibles expuestos sí puede
  justificar P2/P1 — pero documentando QUÉ datos trae el stream, no asumiendo

## Falsos positivos comunes
- Colas de trabajo async que introducen delay fijo independiente del payload
  (todos los mensajes tardan ~5s, no es tu `sleep`)
- Rate limiting que throttlea después de N mensajes — confundible con timing
  injection si no controlás el orden de los tests
- Proxies/load balancers que buffer-ean y devuelven el ACK antes de que el
  backend real procese el mensaje — el timing en el cliente no refleja el
  timing real de ejecución

## Chaining
- CSWH confirmado + stream con datos de terceros → ya es IDOR a nivel de
  WebSocket, documentar como impacto propio
- RCE confirmado (deserialización o command injection real) → de ahí es
  directo a filesystem/backend access, como en el caso de Fran — separar
  en el reporte qué fue el RCE y qué fue el acceso resultante

## Referencias
- PortSwigger Web Security Academy — WebSocket vulnerabilities
- ysoserial (gadget chains para deserialización Java) — usar como herramienta
  externa, no reimplementar generador de gadgets acá
- OWASP Testing Guide — Testing WebSockets (OTG)
