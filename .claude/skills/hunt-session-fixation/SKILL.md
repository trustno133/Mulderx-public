---
name: hunt-session-fixation
description: Identificar y explotar falta de regeneración de identificador de sesión tras cambio de estado de privilegio (login, elevación de rol, cambio de cuenta). Cubre session ID en cookie no rotado post-auth, token de sesión pasado por URL, tokens de flujos SSO/OAuth aceptados sin invalidar el anterior, y cookies con scope de dominio demasiado amplio. Usar cuando el target tiene un flujo de login/auth y el objetivo es fijar una sesión conocida en la víctima para heredarla autenticada.
sources: internal (built from scratch, evidence-gate-first)
---

## Qué es esto y qué NO es

El bug real detrás de "session fixation" siempre es el mismo, más allá
de dónde aparezca el identificador: **el server no regenera el ID de
sesión cuando cambia el nivel de privilegio de esa sesión** (anónimo →
autenticado, usuario → admin, cuenta A → cuenta B en flujos de
impersonación). `nx_token_set` es una instancia puntual de esto — no
el único vector. Ver "Vectores" abajo antes de asumir que el caso que
tenés enfrente es igual al que ya vimos.

Esto NO es lo mismo que **session hijacking** (robar un token ya
autenticado, vía XSS/logs/referer) ni **CSWSH** (WebSocket sin
validación de Origin). Si el atacante necesita robar algo de la
víctima para que el ataque funcione, no es fixation — es otra skill.
Acá el atacante NUNCA toca una sesión de la víctima: **fija un ID
propio, se lo entrega a la víctima, y espera a que ella lo autentique
por él**.

## Gate de Confirmación (no negociable)

Igual que el resto del catálogo: "el token no cambió" o "recibí 2xx"
no prueba nada por sí solo.

| Nivel | Qué probaste | Techo |
|---|---|---|
| **ID persiste tras login (derivado)** | Capturaste el ID pre-auth, forzaste el login de una sesión propia con ese ID, y el mismo ID sigue siendo válido después | Nada todavía — puede ser coincidencia de implementación, no explotable sin el paso siguiente |
| **Entrega confirmada** | Demostraste un vector real de entrega del ID fijado a la víctima (link con param, cookie de dominio compartido, flujo que la víctima usa sin saber) | Sigue siendo derivado — falta la víctima real |
| **Confirmado (impersonación real)** | El atacante, en su navegador ORIGINAL (nunca participó del login), hace una request autenticada con el ID fijado y el server responde con datos/acciones de la cuenta de la víctima | Recién acá arranca severidad — P2/P3 según qué se puede leer o ejecutar como la víctima |

**Los 4 pasos del PoC de impersonación (el que define "confirmado"):**

1. Atacante obtiene/fija un ID de sesión propio, SIN loguearse (`nx_token_set=X` o cookie de sesión equivalente).
2. Atacante hace llegar ese ID a la víctima (URL compartida, cookie de dominio ancho, flujo de invitación, etc. — depende del vector, ver abajo).
3. Víctima se loguea normalmente, sin saber que ese ID ya lo tenía el atacante.
4. **Punto de confirmación:** atacante, en SU sesión original (la que nunca vio el login), hace una request autenticada usando ese mismo ID y el server le devuelve data o permite una acción de la cuenta de la víctima.

Sin el paso 4 con acción concreta del atacante post-login de la
víctima, es derivado nomás. "El servidor no regeneró el token" sin
probar impersonación real es observación, no finding.

## Vectores (no asumir que es solo el de session cookie clásico)

1. **Session ID en cookie que no rota post-login** — el clásico:
   capturás `JSESSIONID`/`nx_token_set`/similar pre-auth, la víctima
   loguea, la cookie sigue siendo la misma. Confirmar comparando el
   valor exacto antes/después del login, no solo si "sigue existiendo
   una cookie con ese nombre" (puede rotar el valor y vos no te diste cuenta).
2. **Session ID pasado por URL** — menos común en apps modernas, pero
   aparece en integraciones SSO/redirects viejos o mal armados
   (`?sessionid=X` o similar en un redirect de login). Si el ID viaja
   por URL, la entrega a la víctima es trivial (un link).
3. **Token de flujo OAuth/SSO aceptado sin invalidar el anterior** — el
   IdP externo autentica, pero el `state`/token de sesión local que
   ya tenía el atacante antes del handshake sigue siendo válido
   después. Requiere entender el flujo completo de redirect antes de
   asumir cuál token es el que persiste.
4. **Cookie con scope de dominio demasiado amplio** (`Domain=.dominio.com`)
   — permite fijar la cookie desde un subdominio con menos protección
   (uno con XSS, uno sin HTTPS forzado, uno que el atacante controla)
   y que aplique sobre el dominio principal. Este vector cruza con
   `cswsh`/`cors` — confirmar cuál es el mecanismo de entrega real
   antes de duplicar trabajo con esas skills.

## Conocimiento previo

Use the `hexbrain` skill for relevant public prior art when it can change the test plan; verify any lead against primary sources and target evidence.

## Testing Flow

1. **Baseline pre-auth** — identificar el/los identificador(es) de
   sesión que el server asigna ANTES de loguearse (cookie, param de
   URL, valor en respuesta de un endpoint de "iniciar sesión").
   Anotar el valor exacto.
2. **Forzar el login con ese ID fijo** — loguearse normalmente pero
   preservando ese identificador (no dejar que el cliente lo
   reemplace). Ver si el server lo acepta como sesión autenticada.
3. **Comparar valor exacto pre/post login** — si cambió, no hay
   fixation por esta vía (puede seguir habiendo por otro vector de la
   lista de arriba). Si es idéntico, pasás a derivado.
4. **Ejecutar los 4 pasos del PoC de impersonación** (arriba) con dos
   navegadores/perfiles reales — uno hace de "víctima" (nunca vio el
   ID fijado de antemano en su flujo normal, solo lo recibe por el
   vector de entrega), otro es el atacante que fijó el ID original y
   nunca tocó el login.
5. **Impacto** — con impersonación confirmada, documentar qué
   endpoints autenticados quedan expuestos con esa sesión (lectura de
   datos, acciones de escritura, cambio de configuración de cuenta).

## Root causes comunes

1. **Regeneración de sesión implementada solo en el login "principal"**
   — el flujo estándar de login regenera el ID, pero un flujo
   secundario (login social, magic link, recuperación de contraseña,
   impersonación de soporte) no pasa por el mismo código y no regenera
   nada.
2. **Regeneración condicionada a un chequeo que no siempre corre** —
   ej. solo regenera si detecta que el ID previo "no existía", pero si
   ya existía uno (el que fijó el atacante) asume que es válido y lo
   reusa tal cual.
3. **El framework regenera el session ID pero no invalida los tokens
   derivados** (ej. rota la cookie de sesión pero el JWT/refresh token
   sigue firmado con el claim viejo y el server no verifica que
   coincida con la sesión activa).

## Related Skills & Chains

- **`auth_decision_tree`** (mental model) — usar para decidir si un
  lead de auth es DEAD o BLOCKED antes de llegar acá. Este skill
  asume que ya identificaste que el flujo de login es candidato; no
  reemplaza ese análisis.
- **`cswsh`** — si el vector de entrega real es una cookie de scope
  amplio combinada con falta de validación de Origin en un WebSocket,
  el finding puede terminar reportándose bajo esa skill en vez de
  ésta. Confirmar el mecanismo de explotación final antes de elegir
  bajo cuál se documenta.
- **`cors`** — mismo caso si el vector de entrega depende de una
  respuesta CORS mal configurada.

## Referencias

- `references/payloads.md` — snippets de curl/pasos concretos por
  vector (cookie, URL param, OAuth, domain scope), carga condicional
  según cuál de los 4 vectores aplica al target.
