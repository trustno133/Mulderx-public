---
name: hunt-csrf
description: Hunting skill for CSRF (Cross-Site Request Forgery) — state-changing actions triggerable cross-origin. Three-tier confirmation gate (derivado / verificado-manual / verificado-completo) gates severity. Heavy catalogs (payloads, bypasses, disclosed reports) live in references/, loaded conditionally.
sources: internal (built from scratch, evidence-gate-first)
---

Use the `hexbrain` skill for relevant public prior art only when it changes a concrete test plan.

## Qué es esto y qué NO es

CSRF ≠ CORS. CSRF es forzar una acción state-changing en nombre de una víctima
autenticada, sin su consentimiento, aprovechando que el browser adjunta
cookies de sesión automáticamente en requests cross-site. Si el objetivo es
leer datos cross-origin por una política de CORS mal configurada, esa es otra
skill (`hunt-cors` — no existe todavía, no confundir con esta).

## Gate de Confirmación — 3 niveles (no negociable)

**No avanza de nivel sin evidencia del nivel anterior.** Esto determina el
techo de severidad de cualquier finding CSRF.

| Nivel | Qué probaste | Cómo | Techo de severidad |
|---|---|---|---|
| **1 — derivado** | El check server-side es naif (acepta `Origin`/`Referer` spoofeado, o acepta la acción sin token) | curl / Burp Repeater, headers seteados a mano | **Informational / P4** |
| **2 — verificado-manual** | El navegador realmente entrega la request cross-origin con la cookie sola (vos no la tocás) | Ejecutás el fetch/form/iframe desde una pestaña de OTRO origen real (devtools console, o página estática que abrís vos) | **P3** — mecanismo confirmado, falta probar cero-fricción |
| **3 — verificado-completo** | La víctima solo necesita visitar una URL/página — cero interacción adicional | PoC HTML hosteado, auto-submit (`onload`), reproducido de punta a punta | **P1/P2** según impacto — este es el estándar real para reportar |

**Regla de oro:** "el server devolvió 2xx con Origin spoofeado" es Nivel 1,
punto. No es "CSRF confirmado". Antes de escribir esa frase en un reporte,
preguntate: ¿esto lo probé con un browser real desde otro origen, o lo estoy
asumiendo porque el curl pasó?

## Conocimiento previo

Use the `hexbrain` skill for relevant public prior art when it can change the test plan; verify any lead against primary sources and target evidence.

## Testing Flow

1. **Mapear** — spider de la sesión autenticada, filtrar POST/PUT/PATCH/DELETE. Anotar cada form + llamada AJAX/fetch.
2. **Baseline** — GET del endpoint, ver si hay `csrf_token`/`authenticity_token`/`csrfmiddlewaretoken` oculto.
3. **Nivel 1** — repetir la acción sin el token (o con Origin/Referer spoofeado vía curl). Si pasa → nivel 1 confirmado, no más que eso todavía.
4. **Nivel 2** — mismo request pero disparado desde un origen real distinto (fetch en devtools de otra pestaña, o página estática servida localmente en otro puerto/dominio). Confirma que el browser realmente manda la cookie sola.
5. **Nivel 3** — armar el PoC autoejecutable, probarlo de punta a punta como lo haría la víctima.
6. **Impacto** — ver Gate 0 abajo antes de tocar severidad.

## Gate 0 — Impacto (aplica en cualquier nivel, pero solo importa desde nivel 2 en adelante)

1. **¿Qué puede hacer el atacante ahora mismo?** — acción state-changing concreta (cambio de email/password, transferencia, borrado, account-link).
2. **¿Qué pierde la víctima?** — "falta el token CSRF" no es impacto. "El atacante vincula su cuenta social a la de la víctima y gana acceso persistente" sí lo es.
3. **¿Se reproduce de punta a punta?** — crear atacante+víctima, hostear PoC, que la víctima lo visite, confirmar que la acción se ejecutó en su cuenta.

**Fuera de scope:** login (no hay sesión que explotar), logout (sin impacto real), GET de solo lectura.

## Objetivos de alto valor (orden de impacto)

1. Cambio de email/password → account takeover
2. Transferencia de dinero / pago → fraude financiero
3. Account-linking OAuth/social → ATO persistente
4. Acciones admin (roles, borrado de usuarios)

## Señales rápidas de superficie de ataque

- Cookie de sesión sin `SameSite` o con `SameSite=None`
- `Access-Control-Allow-Origin: *` + `Access-Control-Allow-Credentials: true` (combo peligroso, cruza con hunt-cors si existiera)
- Token CSRF estático entre page loads (mismo valor en dos cargas de la misma sesión) — probarlo es parte de nivel 1
- Endpoints JSON que también aceptan `text/plain` o `x-www-form-urlencoded` — ver `references/payload-catalog.md`
- Flujos OAuth/SAML con `RelayState`/`state` no validado — CSRF estructural sobre el callback

Para grep patterns, catálogo de payloads por técnica, y tabla de bypass por
tipo de defensa → `references/payload-catalog.md` y `references/bypass-techniques.md`.

## Related Skills & Chains

- **`hunt-xss`** — XSS en el origen confiable neutraliza cualquier defensa CSRF (token, SameSite, Origin check) al instante. Si hay XSS, CSRF pasa a ser trivial — chequear ese ángulo primero si ya hay XSS confirmado en el mismo origen.
- **`hunt-oauth`** *(si existe)* — `state`/`RelayState` sin validar es CSRF estructural sobre el flujo de login/linking.
- **`subdomain-takeover`** — si la cookie de sesión tiene `Domain=.ejemplo.com` (no host-only), un subdomain takeover permite fijar sesión (session fixation) sin ni siquiera necesitar CSRF clásico.

