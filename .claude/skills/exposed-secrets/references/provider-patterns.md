# Patterns de formato real por proveedor

Usar como filtro primario. Si no matchea ninguno de estos, cae a fallback de baja confianza (keyword genérico), no se reporta como pista fuerte.

| Proveedor | Pattern | Nota |
|---|---|---|
| AWS Access Key | `AKIA[0-9A-Z]{16}` | Necesita Secret Key acompañante para ser útil — buscar par |
| AWS Secret Key | `[0-9a-zA-Z/+]{40}` | Muy genérico solo, usar cerca de un AKIA como contexto |
| Stripe live | `sk_live_[0-9a-zA-Z]{24,}` | `sk_test_` NO es live, descartar |
| GitHub PAT (classic) | `ghp_[0-9a-zA-Z]{36}` | |
| GitHub PAT (fine-grained) | `github_pat_[0-9a-zA-Z_]{82}` | |
| Slack token | `xox[baprs]-[0-9a-zA-Z-]{10,}` | |
| Slack webhook | `hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9a-zA-Z]+` | |
| Twilio | `SK[0-9a-fA-F]{32}` (API Key) / `AC[0-9a-fA-F]{32}` (Account SID) | |
| SendGrid | `SG\.[0-9a-zA-Z_-]{22}\.[0-9a-zA-Z_-]{43}` | |
| Google API key | `AIza[0-9A-Za-z_-]{35}` | |
| Google OAuth client | `[0-9]+-[0-9a-zA-Z_]{32}\.apps\.googleusercontent\.com` | |
| JWT | `eyJ[0-9a-zA-Z_-]+\.eyJ[0-9a-zA-Z_-]+\.[0-9a-zA-Z_-]+` | decodificar payload, ver exp/scope antes de asumir vivo |
| Firebase | `AAAA[0-9a-zA-Z_-]{7}:[0-9a-zA-Z_-]{140}` | server key legacy |
| Mailgun | `key-[0-9a-zA-Z]{32}` | |
| npm token | `npm_[0-9a-zA-Z]{36}` | |
| Heroku API key | UUID v4 en contexto `HEROKU_API_KEY` | formato UUID solo no alcanza, necesita contexto de variable |
| GitLab PAT | `glpat-[0-9a-zA-Z_-]{20}` | |
| Cloudflare API Token | `[0-9a-zA-Z_-]{40}` en contexto `CLOUDFLARE_API_TOKEN`/`CF_API_TOKEN` | muy genérico solo, necesita contexto de variable |
| Cloudflare Global API Key | 37 chars hex en contexto `X-Auth-Key` | |
| DigitalOcean token | `dop_v1_[0-9a-f]{64}` | |
| Azure client secret | `[0-9A-Za-z~_.\-]{34,40}` en contexto `AZURE_CLIENT_SECRET`/`client_secret` junto a un `client_id` GUID | genérico, necesita el trío client_id+client_secret+tenant_id (todos GUID los dos primeros) |
| npm token (nuevo formato) | `npm_[0-9a-zA-Z]{36}` | ya cubierto arriba |
| CircleCI token | `[0-9a-f]{40}` en contexto `circle-token`/`CIRCLE_TOKEN` | genérico, necesita contexto |
| Buildkite token | `bkua_[0-9a-f]{40}` | |
| PayPal client secret | `[0-9A-Za-z_-]{60,90}` en contexto `PAYPAL_CLIENT_SECRET`, junto a un `client_id` que arranca `A[0-9A-Za-z_-]{50,}` | |
| Datadog API key | `[0-9a-f]{32}` en contexto `DD_API_KEY`/`DATADOG_API_KEY` | genérico, necesita contexto |
| PagerDuty token | `[0-9a-zA-Z+_-]{20}` en contexto `PAGERDUTY`/`pd_token` | genérico, necesita contexto |
| Algolia Admin API key | `[0-9a-f]{32}` en contexto `ALGOLIA_ADMIN_KEY`/`x-algolia-api-key` junto a `ALGOLIA_APP_ID` (8-10 alfanumérico mayúsculas) | |
| Asana PAT | `[0-9]/[0-9]{16}:[0-9a-f]{32}` | formato viejo; el nuevo es opaco, necesita contexto `ASANA_ACCESS_TOKEN` |
| Zendesk API token | `[0-9a-zA-Z]{40}` en contexto `zendesk` + `/token:` | genérico, necesita contexto fuerte |
| Grafana service account token | `glsa_[0-9a-zA-Z]{32}_[0-9a-f]{8}` | |
| Sonarcloud token | `[0-9a-f]{40}` en contexto `SONAR_TOKEN`/`sonarcloud` | genérico, necesita contexto |
| Google Cloud Service Account JSON | archivo con `"type": "service_account"` y campo `"private_key": "-----BEGIN PRIVATE KEY-----"` | esto es estructural, no un regex de string — buscar el JSON completo, no un fragmento |

## Placeholders a descartar automático (regex NO importa si matchea esto)

`your[-_]?api[-_]?key`, `xxx+`, `example`, `test(?!_live)`, `dummy`, `changeme`, `<.*>`, `\$\{.*\}`, `000+`, `123456`, archivo es `.env.example` / `.env.sample` / dentro de `docs/` o `README`.
