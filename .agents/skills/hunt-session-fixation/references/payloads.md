# Payloads y snippets por vector — hunt-session-fixation

Carga condicional: leer solo la sección del vector que aplica al
target actual, no todo el archivo de una.

## Vector 1 — Cookie de sesión no rotada post-login

```bash
# 1. Baseline pre-auth: capturar cookie de sesión sin loguearse
curl -sI https://$TARGET/ -c cookies_pre.txt
grep -i session cookies_pre.txt   # anotar valor exacto

# 2. Forzar login preservando esa cookie (no dejar que curl la reemplace)
curl -s -b cookies_pre.txt -c cookies_post.txt \
  -X POST https://$TARGET/login \
  -d "user=$VICTIM_USER&pass=$VICTIM_PASS"

# 3. Comparar valor exacto
diff <(grep -i session cookies_pre.txt) <(grep -i session cookies_post.txt)
# Si no hay diff -> mismo ID pre/post, pasa a "derivado"
```

PoC de impersonación (paso 4 del gate): desde OTRA sesión curl/navegador
que nunca corrió el paso 2, reusar `cookies_pre.txt` (el valor que el
atacante fijó originalmente) contra un endpoint autenticado:

```bash
curl -s -b cookies_pre.txt https://$TARGET/api/me
# Si devuelve datos de la cuenta que hizo login en el paso 2 -> confirmado
```

## Vector 2 — Session ID en URL

Buscar redirects de login/SSO que incluyan el ID como query param:

```
https://$TARGET/sso/callback?sessionid=X&...
```

Si existe, la entrega a la víctima es directamente compartir esa URL
(phishing de link, no de credenciales). Confirmar armando la URL con
un ID propio y verificando que, tras un login de "víctima" siguiendo
ese link, el ID original responda autenticado (mismo paso 4 del gate
que el vector 1, pero la entrega es un link en vez de una cookie).

## Vector 3 — OAuth/SSO sin invalidar token local previo

Mapear el flujo completo antes de tocar nada:

1. ¿Qué cookie/token local existe ANTES de iniciar el handshake OAuth?
2. ¿Ese token cambia de valor en algún punto del callback, o solo se
   le agrega un claim de "autenticado=true" sin rotar el ID?

Si el ID no rota, el mismo PoC de 4 pasos aplica: el atacante inicia
el flujo (sin completar login), obtiene el token pre-auth, se lo
entrega a la víctima (ej. le pasa el link de callback antes de que el
IdP redirija), la víctima completa el login del lado del IdP, y el
atacante reusa el token pre-auth original para ver si quedó autenticado.

## Vector 4 — Domain scope amplio (`Domain=.dominio.com`)

```bash
# Confirmar el scope de la cookie
curl -sI https://$TARGET/ | grep -i "set-cookie"
# Buscar "Domain=.dominio.com" (con el punto inicial) en vez de
# ausencia de Domain (que la limitaría al host exacto)
```

Si el scope es amplio, el mecanismo de entrega depende de encontrar
un subdominio con menor protección (sin HTTPS forzado, con XSS, o que
el atacante ya controle) desde el cual setear esa cookie antes de que
la víctima visite el dominio principal. Este paso de "encontrar el
subdominio débil" es trabajo de recon, no de esta skill — si aparece,
cruzar con `domain-recon` / `hunt-external-takeover` antes de asumir
que hay un vector de entrega viable.
