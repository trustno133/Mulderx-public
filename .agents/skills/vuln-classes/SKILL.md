---
name: vuln-classes
description: Índice de playbooks para elegir y encaminar pruebas de IDOR, auth bypass, SSRF, XSS, race conditions, GraphQL, OAuth/OIDC, lógica de negocio y file upload en Mulderx. Usar al clasificar una señal o seleccionar la siguiente clase; cargar una sola referencia relevante y delegar después en la skill especializada.
---

# Vulnerability classes

Este skill es un índice de decisión. No autoriza pruebas activas, no reemplaza
las skills canónicas y no convierte una respuesta 200, una introspección o un
filtro bypasseado en un finding. Empezá por la evidencia concreta del target y
cargá solo la referencia de la clase que matchee.

## Guardrails comunes

Antes de probar:

1. Confirmá scope, política, safe harbor, rate limits y actor/credenciales
   autorizados.
2. Establecé un baseline benigno y una expectativa observable.
3. Minimizá requests, evitá cambios irreversibles y usá datos sintéticos.
4. No copies tokens, cookies, contraseñas, claves ni datos personales a logs,
   prompts o `targets/`.
5. Ante CAPTCHA, ban, rate limit, WAF degradado o 5xx sostenidos, detené esa
   vía. Si el target es inalcanzable, reportá el error exacto y detenete.
6. Separá observación, inferencia y prueba. Antes de registrar un finding,
   aplicá Q1–Q3 de `.claude/mental_models/severity_gate.md`.

## Routing table

| Señal | Referencia | Skill/especialista de handoff |
|---|---|---|
| IDs de recursos, tenants o ownership | `references/idor.md` | `idor-bola` / `idor_specialist` |
| Login, reset, recovery o MFA con evidencia de salto de identidad | `references/auth-bypass.md` | `auth-bypass` / `auth_bypass_specialist`; OAuth, SAML, JWT y session fixation conservan sus especialistas |
| URL, webhook, import o renderer que hace fetch server-side | `references/ssrf.md` | `ssrf` / `ssrf_specialist` |
| Input llega a HTML, JS, atributo, URL o DOM sink | `references/xss.md` | `xss-hunt` / `xss_specialist` |
| Non-idempotent operation with observed concurrency divergence | `references/race-condition.md` | `race-condition` / `race_condition_specialist`; general workflow logic stays with `business-logic` |
| Endpoint GraphQL, field/resolver auth, schema o query behavior | `references/graphql.md` | `graphql-audit` / `graphql_specialist`; IDOR/workflow/injection findings keep their class owner |
| `redirect_uri`, state, code, PKCE, nonce o claims | `references/oauth-oidc.md` | `oauth`, `offensive-oauth` o especialista disponible |
| Precio, estado, cuota, rol o workflow manipulable | `references/business-logic.md` | `business-logic` / `business_logic_specialist` |
| Upload, import de archivo o contenido servido | `references/file-upload.md` | `file-upload`, `ssrf` o `xss-hunt` según el sink |
| URL controlada que provoca una redirección externa | `references/open-redirect.md` | `open-redirect` / `open_redirect_specialist`; OAuth callback va a `oauth` |
| Respuesta expone datos privados, diagnósticos o configuración | `references/info-disclosure.md` | `info-disclosure` / `info_disclosure_specialist`; credenciales o claves van a `exposed-secrets` |
| Input externo parece alcanzar ejecución de comandos/código en servidor | `references/rce.md` | `rce` / `rce_specialist`; SSTI/deserialization y upload siguen sus rutas más específicas |
| Código fuente disponible y autorizado para revisión estática | `references/sast.md` | `sast-methodology` con etapas `sast_mapper_specialist` → `sast_flow_specialist` → `sast_review_specialist` |
| Smart contract or DeFi with confirmed source/scope | `references/web3.md` | `web3-audit` / `web3_specialist`; static review unless a separate test is authorized |

## Kill signals versus cierre

Un kill signal debe describir qué se probó y por qué elimina esa hipótesis:

- mismo recurso ajeno rechazado de forma consistente por todos los hermanos
  relevantes;
- callback SSRF ausente después de un canary controlado y con el mecanismo
  realmente procesando la URL;
- input correctamente codificado o sanitizado antes del sink observado;
- operación idempotente y estado final único después de una prueba de
  concurrencia autorizada;
- upload servido como contenido estático con controles de tipo y sin sink
  ejecutable o interpretable.

No uses como killer único la tecnología, el nombre del campo, un UUID o un
status code aislado. Documentá también lo que quedó sin probar.

## Referencias bajo demanda

- [IDOR/BOLA](references/idor.md)
- [Auth bypass](references/auth-bypass.md)
- [SSRF](references/ssrf.md)
- [XSS](references/xss.md)
- [Race condition](references/race-condition.md)
- [GraphQL](references/graphql.md)
- [OAuth/OIDC](references/oauth-oidc.md)
- [Business logic](references/business-logic.md)
- [File upload](references/file-upload.md)
- [Open redirect](references/open-redirect.md)
- [Information disclosure](references/info-disclosure.md)
- [Remote code execution](references/rce.md)
- [Static source review](references/sast.md)

Después de leer una referencia, cargá la skill canónica indicada por el router
de Mulderx. Si no existe skill dedicada para la clase, devolvé un candidato
con evidencia y límites claros; no inventes una metodología destructiva.
- [Smart contracts / Web3](references/web3.md)
