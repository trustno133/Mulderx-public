---
name: idor-bola
description: Metodología de hunting para IDOR / BOLA (Broken Object Level Authorization) — mapeo de referencias a objetos, enumeración de IDs, cross-tenant testing, y chains hacia ATO/privesc/fraude financiero. Usar cuando el target expone endpoints con IDs de recurso (numéricos, UUID, o hasheados) en path, query o body, especialmente en apps multi-tenant (SaaS, B2B) o con GraphQL.
sources: adaptado de skill público "hunt-idor" (26 reportes públicos H1, IDs de reporte verificados por el operador el 04/08/2026) + catálogo propio de bypass tables
---

# IDOR / BOLA

## Por qué importa

IDOR es de los bug classes que más paga porque el impacto es directo y demostrable: acceso a datos/recursos de otro usuario sin necesidad de bypassear autenticación. Pega fuerte en:

- Apps multi-tenant (`org_id`, `account_id`, `business_id` en cualquier lado)
- Fintech / billing APIs
- Endpoints de admin/management de cuenta
- GraphQL con `node(id:)` global IDs

## Evidence Gates (no negociable)

Un finding de IDOR no pasa de **Informational/P4** sin:

1. **Dos cuentas separadas, mismo nivel de privilegio** — User A (owner) y User B (atacante). Si probaste con una sola cuenta contra vos mismo, no es IDOR, es self-testing.
2. **Request exacto documentado** con el ID de la víctima y el token/sesión del atacante. No alcanza con "creo que funcionaría".
3. **Respuesta 200 con data real de la víctima** (o cambio de estado confirmado) — no un 200 con array vacío o campos redactados. Este es el caso más común de N/A: 200-pero-sin-data.
4. **Reproducible en <10 min desde cero**, sin depender de estado previo o timing específico.

Si no podés marcar las 4, no escribas el reporte. Esto es tu Gate 0 aplicado a esta clase de bug — no el "CVSS típico por clase" que trae la fuente original (esa tabla la descarto a propósito, va contra tu criterio de severidad conservadora).

## ¿Esto es derivado o verificado en vivo?

Etiquetá cada finding con el sistema de dos niveles ya establecido:
- `confirmado (derivado)` — técnica generalizada de reportes/docs públicos (ver `references/chain-catalog.md`)
- `confirmado (verificado en vivo, técnica externa)` — vos lo corriste y confirmaste contra el target

## Metodología (10 pasos)

Use the `hexbrain` skill for relevant public prior art when it can change the test plan; verify any lead against primary sources and target evidence.

1. **Mapear todas las referencias a objetos** — navegá la app autenticado como User A, capturá todo en Burp, filtrá por `id=`, `_id=`, `uuid=`, `/v1/{noun}/{id}`.
2. **Clasificar el tipo de ID** — secuencial (enumerable ±N), UUID (buscar si leakea en otras respuestas/JS), hasheado (buscar el original leakeado en otro endpoint).
2b. **Gate de reachability — obligatorio antes de cualquier setup cross-account.**
Antes de crear cuentas adicionales, armar relaciones, o invertir tiempo
en el protocolo de dos cuentas, responder estas cuatro preguntas en orden.
Si ninguna aplica → documentar como MUERTO con killer "sin vector de
reachability del ID" y no avanzar al paso 3.

1. ¿El ID es secuencial o de rango acotado? ¿Un atacante podría
   enumerarlo con fuerza bruta razonable dentro de una sesión?
2. ¿El ID aparece en algún endpoint, listado, export, o response
   accesible para un usuario cualquiera sin privilegios especiales?
3. ¿El ID se comparte por diseño en algún flujo legítimo: link de
   invitación, URL en email, share link, QR code, notificación?
4. ¿Hay canal de leak identificable: bundle JS, source map, metadata
   pública, header de response, otro endpoint del mismo dominio?

Si al menos una vía aplica → documentar cuál, continuar al paso 3.
Si ninguna → **MUERTO**: "ID sin vector de reachability — [tipo de ID
y por qué no es alcanzable: ej. UUID generado en server sin leak
conocido en ningún endpoint accesible]".

3. **Dos cuentas, mismo nivel** — User A registra todos los IDs de sus propios recursos.
4. **Reemplazar sesión y repetir** — mismo request, token de User B, ID de User A. Probar TODOS los verbos (GET/POST/PUT/PATCH/DELETE), no solo GET.
5. **Cross-tenant** — cuentas en orgs distintas, ¿Org B puede referenciar IDs de Org A? Prioridad en endpoints de admin/management.
6. **GraphQL específicamente** — introspection primero, después sustituir IDs de víctima en cada query/mutation que tome `id:` como argumento. Ojo con `node(id:)` — el resolver top-level autentica pero las relaciones anidadas a veces no re-chequean ownership (ver Chain 3 en el catálogo).
7. **Write/destructive, no solo read** — ¿User B puede borrar o modificar recursos de User A? ¿Puede agregarse a la cuenta/team de User A?
8. **Encadenar** — un IDOR que leakea IDs (org_id, user_id) alimenta el siguiente. Ver `references/chain-catalog.md` para los 6 patrones de composición más pagos.
9. **Edge cases de estado** — tokens/invites expirados que siguen siendo aceptados, race conditions sobre el mismo ID.
10. **Documentar el diferencial exacto** — 200 OK vs el 403/404 esperado, con screenshot/log.

## Root causes comunes (para lectura de código)

- ORM sin scope: `Model.findById(params.id)` en vez de `Model.findOne({id: params.id, userId: req.user.id})`
- Auth chequeada a nivel de ruta ("¿está logueado?") pero no a nivel de objeto ("¿es dueño de esto?")
- Body acepta `org_id`/`account_id` del cliente sin verificar que el caller pertenezca a esa org
- Verbo protegido inconsistente: GET tiene ownership check, DELETE en el mismo path no
- Multi-tenant: chequean `user_id` pero se olvidan `org_id`/`tenant_id`

Catálogo de grep patterns por lenguaje → `references/attack-surface-catalog.md`

## Referencias

- `references/attack-surface-catalog.md` — URL patterns, JS source patterns, payloads (curl/ffuf/Burp Intruder/GraphQL), bypass techniques contra UUIDs/hashes/rate-limit. Cargalo cuando ya identificaste el target y necesitás las herramientas concretas.
- `references/chain-catalog.md` — 6 chains IDOR→algo-mayor (ATO, privesc, fraude financiero), con ejemplos reales `confirmado (derivado)` y sus H1 IDs. Cargalo cuando ya confirmaste un IDOR de read y estás evaluando si compone a algo más grande.

## Cross-links reales (no inventados)

- **`xss`** — Chain 2 del catálogo (IDOR + filename-controlled `Content-Disposition` → stored XSS vía header injection) cae en la categoría Stored del skill xss. El storage point "filename de upload" ya está listado explícitamente en xss/SKILL.md — cargar ese skill cuando llegues a la Cadena 2, no `client-side-prototype-pollution.md` (ese cubre sinks `innerHTML`/`document.write`, que es una clase distinta).
- **`file-upload`** — si el IDOR expone un endpoint de descarga, el vector de filename-controlled headers de Chain 2 es relevante para lo que ya tenés ahí.

No hay skill propio todavía para: auth-bypass genérico, GraphQL dedicado, business-logic, ni triage-validation formal. Los chains que dependían de esos (ATO vía password reset, GraphQL mass extraction, business-logic financiero) quedan documentados en el catálogo pero **sin skill destino real** — son notas para vos, no links funcionales. Si armás esos skills después, volvé a este archivo y actualizá la sección.
