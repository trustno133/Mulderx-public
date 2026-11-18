---
name: business-logic
description: Metodología de hunting para fallas de lógica de negocio — invariantes del dominio que el server no revalida, mass assignment / parámetros no documentados aceptados, parent/foreign-key cross-boundary, workflow state transitions bypassables, required-fields enforcement sólo en cliente, y "gates" client-side (HMAC/secret/CAPTCHA) que el server trata como auth real. Usar cuando el target expone APIs REST/GraphQL autenticadas con lógica de dominio no trivial (participación ciudadana, pagos, roles, cuotas, workflows, firma de requests), o cuando aparecen señales de validación que vive sólo en el frontend.
sources: patrones generales de fallas de lógica de negocio + VRT Bugcrowd Application-Level Bypass / Insufficient Input Validation / Broken Crypto; no incluye evidencia de programas concretos
---

# Business Logic

## Por qué importa

Los scanners genéricos no modelan invariantes de dominio: suelen comparar payloads conocidos contra sinks conocidos. Business logic requiere entender:

- Qué **asume** la UI que el server valide
- Qué contratos **implícitos** tienen las APIs (ej: "`parent_id` siempre pertenece a la misma `idea_id`")
- Qué estados pretende **el workflow** vs. qué estados **acepta** el server
- Qué "seguridad" vive sólo en el cliente (HMAC con key hardcoded, required-fields validados en el schema del form)

## Evidence Gates (no negociable)

Un finding de business logic no pasa de **Informational/P4** sin:

1. **Invariante del dominio escrito explícito** — "X siempre debe cumplir Y porque la UI/el schema/la ley/el flujo lo garantizan". Sin invariante nombrado, no hay bug, hay comportamiento raro.
2. **Request que viola la invariante** — curl concreto, no "se podría hacer".
3. **Response del server que acepta la violación** — HTTP 2xx + estado persistido (cuando aplica), no un 500 que accidentalmente dice algo. Idealmente verificado desde una SEGUNDA cuenta/perspectiva (GET post-mortem).
4. **Impacto operacional nombrable** — qué fluyó distinto en el mundo real. "Quota consumida sin satisfacer requisitos", "notificación cross-project al autor equivocado", "oracle de datos a escala". Si el impacto es "la base de datos tiene una fila rara", es cosmético.

Si no podés marcar las 4, el finding no se escribe — va a `discarded.md` con killer específico.

## Patrones (catálogo)

### P1 — Mass assignment / parámetro no documentado aceptado
El client-side nunca envía `role`, `is_admin`, `tenant_id`, `price`, `parent_id` fuera de su propia idea — pero el server los acepta.
- **Trigger**: Rails `permit(...)`, Django `fields = "__all__"`, Node `Object.assign(user, req.body)`, GraphQL mutations con input types laxos.
- **Comprobación**: validar que toda referencia padre pertenezca al recurso y tenant indicados en la operación.

### P2 — Required/validation sólo en cliente
El schema del form (JSON schema, custom_fields, Zod) marca `required: true`, pero el endpoint de submit acepta body vacío con 201.
- **Trigger**: forms con validación JS compleja, surveys/polls, onboarding multi-step.
- **Comprobación**: revalidar en el servidor todos los campos obligatorios antes de aceptar una transición.

### P3 — Workflow state transition bypass
Fase cerrada / proyecto archivado / período de participación terminado — pero una ruta API lateral evita el gate.
- **Trigger**: dos endpoints que modifican el mismo recurso, uno chequea estado y otro no; o un `parent_id` que arrastra el comentario a un árbol que el gate no revisa.
- **Comprobación**: aplicar el control de estado en cada ruta que pueda modificar el mismo recurso.

### P4 — Client-side gate presentado como server auth
HMAC/signature/token/CAPTCHA que el browser calcula con una key o algoritmo público, y el server lo trata como barrera real.
- **Trigger**: `X-Authorization: HMAC <hex>`, `X-Signature`, `X-Nonce` en requests desde JS; buscar `createHmac`, `sha256`, `sign(`, `secret` en el bundle.
- **Comprobación**: una firma calculada con una clave pública en el cliente no debe autorizar una acción por sí sola.

### P5 — Idempotencia / quota contables
Operaciones one-shot (voto, canje, aplicación, pago) que incrementan contador **antes** de validar, dejando el recurso en estado inválido pero contado.
- **Trigger**: `posting_limited_max_reached` tras submit vacío; retry después de 500/timeout; carrera entre `create` y `validate`.
- **Comprobación**: actualizar cuotas y contadores solo después de validar y persistir la operación válida.

### P6 — Ownership check en verb A, no en verb B
GET valida ownership, DELETE/PATCH no. O al revés — DELETE sí, pero `PATCH ?undelete=true` evade el check.
- **Trigger**: endpoints con mismo path y varios verbos; soft-delete vs hard-delete; archive/unarchive; share/revoke.

### P7 — Cross-tenant via referencia implícita
El request lleva sólo el `resource_id`; el server deriva `tenant_id` del recurso (no del caller). Si el recurso pertenece a otra org pero es visible, la op se ejecuta ahí.
- **Trigger**: multi-tenant SaaS con `org_id` opcional en el body, GraphQL `node(id:)` global IDs.

### P8 — Precio / rol / state en el body del cliente
El cliente manda `price`, `discount`, `role`, `status` como parte del payload y el server lo cree.
- **Trigger**: ecommerce, SaaS con planes, formularios de alta de usuario con dropdown de rol.

### P9 — Oracle de información a escala
Endpoint que devuelve respuestas distinguibles ("no existe" vs "existe sin acceso" vs "formato inválido") sin rate-limit real, permitiendo scraping de datos vía diferencial.
- **Trigger**: validación de username/plate/CUIT/email en registro, APIs tipo `check-availability`, forms de recuperación de password.
- **Comprobación**: medir si respuestas diferenciables permiten inferir datos a escala, respetando límites y autorización.

## Conocimiento previo

Antes de arrancar, leé `knowledge/business-logic.md` — los primeros 15 reportes tienen descripción técnica real de H1. Usalos para identificar qué patrones de falla lógica fueron confirmados en targets similares (mass assignment, workflow bypass, price manipulation, cross-tenant) y priorizá los que matchean la funcionalidad del target actual.

## Metodología (8 pasos)

1. **Enumerar invariantes del dominio** — leer la UI, docs del programa, EULA/ToS si están online. Anotar: "qué es imposible según el producto". Esta lista es tu plano de ataque.
2. **Mapear el shape del request desde el browser real** — DevTools Network, no inferencia. Capturar body entero + headers + cookies. Esto es lo que la UI manda.
3. **Comparar lo que la UI manda vs lo que el server acepta** — probar remover campos requeridos, agregar campos no documentados (`role`, `tenant_id`, `price`, `is_admin`, `parent_id`, `author_id`), cambiar tipos (string → array), mandar `null`/`""`/`0`/`[]`.
4. **Probar el workflow en todos los estados** — crear recurso, cambiar estado, probar la misma op en cada estado. Documentar diferenciales (201 en fase abierta vs. 201 en fase cerrada = bug).
5. **Verificación cross-perspective obligatoria** — toda mutation de lógica de negocio se verifica desde una segunda cuenta/perspectiva/estado. "El server devolvió 201" no es confirmación — "la cuenta B vio el cambio" sí.
6. **Buscar los client-side gates** — grep en el bundle por `createHmac|sign\(|secret|key[\s]*=|CAPTCHA`. Si una key aparece hardcoded, el gate es decorativo.
7. **Cross con oracle differentials** — mandar inputs borderline (vacío, longitud 1, UUID conocido, UUID random) y comparar respuestas. Diferenciales = oracle = impacto.
8. **Impacto operacional nombrado** — no cerrar el finding hasta responder: "qué fluyó distinto en el mundo real por esto". Si no hay respuesta operacional, no hay P3 — es nota.

## Root causes comunes (para lectura de código)

- Rails `permit(...)` con atributo que el UI nunca envía
- Django `ModelForm.Meta.fields = '__all__'` o DRF serializer sin `read_only`
- `acts_as_nested_set` / tree structures **sin `scope:`** → árboles globales en vez de scoped
- Validaciones en `before_action` que corren sólo para unos verbos
- `.find(id)` en lugar de `.find_by(id: id, user_id: current_user.id)`
- JSON schema / Zod / Yup en el frontend sin equivalente server-side
- HMAC con key en `process.env.NEXT_PUBLIC_*` (público por diseño del framework)
- Workflow transitions enum con `before_transition` que falta en una rama

## Cross-links a otros skills

- **`idor-bola`** — P7 (cross-tenant implícito) y P6 (ownership por verbo) solapan con IDOR. Si el bug es "mi cuenta puede operar sobre el recurso de otra cuenta" → `idor-bola` es el skill primario, `business-logic` complementa con el patrón de "por qué" (verb inconsistency vs mass assignment vs implicit tenant).
- **`exposed-secrets`** — P4 (client-side HMAC) usa secrets expuestos como entrada. `exposed-secrets` detecta la key; `business-logic` arma el modelo de amenaza y la PoC.
- **`hunt-csrf`** — una invariante de negocio bypasseada por CSRF sigue siendo CSRF primero y business logic después — reportar como CSRF con nota del impacto de dominio.
- **`cors`** — si el server lee una invariante del `Origin` o `Referer` como parte de la lógica de negocio (no sólo CORS), es business logic con vector CORS.

## Qué NO es business logic

- "La app no tiene rate-limit en login" → `hunt-session-fixation` o reporte de misconfig, no business logic.
- "El error leakea stack trace" → `exposed-secrets` / information disclosure.
- "XSS en un campo" → `xss`, aunque el campo sea "comentario" (business point).
- "La password policy acepta `12345678`" → security misconfig, no business logic.
- "El UUID es predecible" → `idor-bola` (reachability del ID).
