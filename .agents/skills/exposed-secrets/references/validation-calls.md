# Calls de validación read-only por proveedor

Regla: siempre la call MENOS invasiva que confirme identidad/vida de la key, nunca la que enumera o lee data de terceros si hay alternativa. Fuente base: [streaak/keyhacks](https://github.com/streaak/keyhacks) + docs oficiales — pero **ojo**: varios ejemplos de keyhacks priorizan "demostrar que funciona" sobre "no dejar rastro". Marcados abajo los que NO son read-only puro, para no copiarlos ciegamente.

## Cloud / Infra

| Proveedor | Call read-only | Qué confirma |
|---|---|---|
| AWS Access/Secret Key | `aws sts get-caller-identity` | Identidad, sin tocar recursos. Para enumerar permisos después, usar `enumerate-iam` (solo-lectura) antes que ir probando servicio por servicio a mano. |
| Google Cloud Service Account (JSON) | `gcloud auth activate-service-account --key-file=X && gcloud auth print-access-token` | Confirma que las credenciales activan y generan token. No ejecuta ninguna operación sobre recursos todavía. |
| Azure (client_id + secret + tenant) | `POST https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/token` (client_credentials) | Devuelve token si las credenciales son válidas. Es una call de auth, no toca Graph API todavía. |
| Microsoft SAS token | Requiere SDK (`CloudBlobClient.GetServiceProperties()`) | No hay curl directo simple — anotar como "formato válido, validar con SDK" si no lo tenés a mano |
| Cloudflare API Token | `GET /client/v4/user/tokens/verify` | Endpoint hecho específicamente para esto — status `active`, sin tocar zonas/DNS |
| DigitalOcean | `GET /v2/account` | Identidad + límites de cuenta, sin listar droplets/DBs |
| Heroku | el ejemplo típico que circula es `POST /apps` (crea una app) — no usar. Usar `GET /account` en su lugar | Identidad sin crear nada |

## CI/CD y dev tooling

| Proveedor | Call read-only | Qué confirma |
|---|---|---|
| GitHub PAT | `GET /user` con `Authorization: token <key>`, mirar header `X-OAuth-Scopes` en la respuesta | Identidad + scopes reales del token, no solo si es válido |
| GitHub client_id + client_secret | `GET /users/<username>?client_id=X&client_secret=Y` | Válido si no tira error de rate-limit sin auth |
| GitLab personal access token | `GET /api/v4/projects?private_token=<token>` | Lista proyectos visibles — es lectura, pero devuelve data real del target, usar con criterio de scope |
| GitLab runner registration token | el único método conocido (`gitlab-runner register`) registra un runner real — tiene side-effect. No ejecutar sin autorización explícita, y documentar el riesgo antes de correrlo |
| CircleCI | `GET /api/v1.1/me?circle-token=<token>` | Identidad del usuario del token |
| Travis CI | `GET /repos` con `Authorization: token <token>` | Lista repos accesibles |
| npm token | `GET /-/whoami` con `Authorization: Bearer <token>` | Identidad. Si da 403 puede ser CIDR-whitelist, no necesariamente inválido — probar desde otra IP antes de descartar |
| Buildkite | `GET /v2/access-token` | Identidad + scopes del token |
| Sonarcloud | `GET /api/authentication/validate` con basic auth `<token>:` | Confirma validez explícitamente, hecho para esto |
| Docker Hub | No hay endpoint público de whoami simple documentado — tratar como "formato válido, no validado" salvo que confirmes uno |

## Pagos / Comunicaciones

| Proveedor | Call read-only | Qué confirma |
|---|---|---|
| Stripe live key | `GET /v1/balance` con basic auth `<key>:` | Auth válida sin listar customers/charges. `sk_test_` no vale, descartar antes de llegar acá |
| Twilio | `GET /2010-04-01/Accounts/<SID>.json` con basic auth SID:token | Confirma cuenta activa |
| SendGrid | `GET /v3/user/account` | Confirma auth sin enviar mail |
| Mailgun | `GET /v3/domains` con basic auth `api:<key>` | Lista dominios, sin enviar nada |
| PayPal (client_id + secret) | `POST /v1/oauth2/token` (sandbox) para obtener access token, luego `GET /v1/identity/oauth2/userinfo` | El userinfo confirma sin tocar transacciones. Usar `api.sandbox.paypal.com` primero si no estás seguro del entorno |
| Razorpay | `GET /v1/payments` con basic auth key:secret | Lista pagos — leve, pero es data real; si alcanza con que responda 200 vs 401, no hace falta mirar el body |
| Zendesk (API key) | `GET /api/v2/users.json` con basic auth `email/token:<key>` | Lista usuarios — leve, preferible sobre escribir un ticket |
| Zendesk (OAuth token) | `GET /api/v2/tickets.json` con `Authorization: Bearer <token>` | Confirma auth |

## Analytics / Monitoreo

| Proveedor | Call read-only | Qué confirma |
|---|---|---|
| DataDog | `GET /api/v2/validate` con header `DD-API-KEY` | Endpoint hecho específicamente para validar, devuelve org UUID y scopes — mejor que el viejo `/v1/dashboard` que además pide application_key |
| New Relic (Personal API / NerdGraph) | `POST /graphql` pidiendo solo `requestContext { userId apiKey }` | Confirma identidad sin tocar datos de apps |
| New Relic (REST v2) | `GET /v2/applications.json` con `X-Api-Key` | Si responde, validar después si es admin key antes de asumir alcance |
| Grafana | `GET /api/user` con Bearer o Basic | Identidad del usuario/token |
| Algolia | el ejemplo de "escribir un PUT en `highlightPreTag`" que circula en varias fuentes NO es read-only, deja un cambio persistente en el índice. Usar solo `GET /1/indexes/` (si el key tiene permiso `listIndexes`) | Confirma validez sin modificar nada |
| Amplitude | `GET /api/2/export?start=X&end=Y` con basic auth key:secret | Exporta data real si es válido — usar rango de tiempo mínimo (1hs) solo para confirmar, no para extraer todo |
| Mapbox | `GET /tokens/v2?access_token=<token>` | Endpoint de validación explícita, no gasta cuota de uso real como geocoding |
| Ipstack / Shodan / Google Maps APIs | Cada call individual tiene costo (Shodan consume créditos de query, Google Maps cobra por request) — documentar como "validación con costo menor conocido", no asumir gratis |

## Colaboración / Otros

| Proveedor | Call read-only | Qué confirma |
|---|---|---|
| Slack token (bot/user) | `POST /api/auth.test` | Team/user asociado, sin leer mensajes ni canales |
| Slack webhook | `POST` con `{"text":""}` — si responde `missing_text_or_fallback_or_attachments` el webhook es válido (falta texto, pero existe) | Confirma sin postear nada real al canal |
| Asana | `GET /api/1.0/users/me` con Bearer | Identidad |
| PagerDuty | `GET /schedules` con `Authorization: Token token=<token>` | Lista schedules, lectura |
| Zapier webhook | No hay validación sin disparar el webhook — cualquier POST ejecuta el Zap. Documentar como "formato válido, no validado sin side-effect" salvo autorización explícita |
| Firebase legacy server key (FCM) | El único método conocido (`POST /fcm/send`) manda una notificación real, aunque sea a un `registration_id` inválido — no es 100% side-effect-free. Tratar con la misma cautela que Zapier |
| JWT (cualquier proveedor) | Decodificar localmente (`exp`, `iat`, `scope`/`role` claims) — no requiere red | Si `exp` ya pasó, está muerto sin pegarle a nada. Es siempre el primer paso antes de cualquier call de red |

## Regla general para lo que no está en esta tabla

Si un proveedor no tiene call read-only conocida sin side-effects, documentarlo como "formato válido, no validado" y no forzar una call que pueda escribir/gastar/enviar/registrar algo. Esa incertidumbre también es información válida para el reporte — mejor un P4 honesto que un finding inflado con una validación que tuvo costo colateral.
