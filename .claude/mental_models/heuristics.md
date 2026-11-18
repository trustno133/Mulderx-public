# Heuristics — Olfato del Agente

Esto no son vectores. No son checklists. Son patrones de anomalía que
un hunter entrenado reconoce antes de que haya una señal formal clara.

**Regla de uso**: cuando algo activa una heurística, no lanzar exploits.
Primero documentar la anomalía, después consultar `vector_interrogation.md`
para la señal correspondiente, después actuar. La heurística es el
"algo huele raro acá" — la confirmación viene después.

**Regla de priorización**: las heurísticas de mayor valor son las que
señalan superficie que nadie más está mirando. Un scanner ve lo obvio.
El olfato ve lo que el scanner pasa por alto.

---

## 1. ANOMALÍAS DE TIMING

El tiempo de respuesta es uno de los oráculos más honestos que existen.
Los servidores no mienten sobre cuánto tardan.

- **Un endpoint tarda 2-3x más que endpoints similares** → algo procesa
  en el backend. Candidato a: SSRF (hace fetch externo), deserialización
  (procesa un objeto), query sin índice (SQL injection posible), llamada
  a servicio externo.

- **El tiempo varía según el valor del parámetro** → oracle de blind
  injection. Si `id=1` tarda 100ms e `id=1 AND SLEEP(3)` tarda 3100ms
  → SQLi ciego confirmado por timing.

- **Login tarda más con usuarios que existen** → bcrypt comparison
  solo corre si el usuario existe → user enumeration por timing.

- **Reset de password tarda diferente según email** → mismo patrón,
  user enumeration.

- **Endpoint tarda exactamente lo mismo siempre, sin importar el input**
  → probablemente respuesta pre-generada o cacheada. Verificar si hay
  cache de por medio — si cachea respuestas autenticadas → cache deception.

- **Un request dispara múltiples requests salientes (detectable con OOB)**
  → el servidor procesa el input y hace fetches → SSRF, XXE, o
  deserialización activa.

- **Tiempo de respuesta aumenta linealmente con el tamaño del input**
  → el servidor procesa byte a byte → candidato a ReDoS o parsing lento
  que revela detalles del procesamiento interno.

---

## 2. ANOMALÍAS EN MENSAJES DE ERROR

Los errores son el debug mode involuntario del servidor. Cada error
mal manejado es información gratuita.

- **Stack trace completo en producción** → tecnología, versión, path
  absoluto, nombres de clases internas, a veces valores de variables.
  Guardar todo — es contexto para otros vectores.

- **Error con path absoluto** (`/var/www/html/app/models/User.php:142`) →
  estructura del filesystem. Útil para LFI dirigido.

- **Error que menciona el nombre de la base de datos, tabla, o columna**
  → (`column 'user_id' doesn't exist`) → schema leak. Útil para SQLi
  dirigido.

- **Error diferente para input que "casi funciona" vs input que no tiene
  sentido** → oracle de existencia. `"user not found"` vs `"invalid
  password"` → user enumeration. `"invalid token format"` vs `"token
  expired"` → el token existió alguna vez.

- **Error genérico en un endpoint, error específico en otro endpoint del
  mismo servidor** → el genérico está manejado, el específico no. El
  específico es el que vale explorar.

- **Error que cambia entre el primer request y el segundo request idéntico**
  → estado del servidor cambia entre requests → race condition posible,
  o la primera request inicializa algo.

- **Error 500 en un endpoint específico con un valor específico de
  parámetro** → el servidor no maneja ese caso → candidato a injection,
  deserialización rota, o lógica de negocio con edge case.

- **Error que incluye el valor del parámetro enviado** → reflexión en
  error → XSS en mensajes de error (menos obvio que XSS en respuesta
  normal, a veces sin filtrar).

- **Error 404 con cuerpo distinto al 404 estándar del servidor** →
  el endpoint existe pero algo dentro falla → no es un 404 real, es un
  error enmascarado. Probar con distintos métodos HTTP y payloads.

- **Error que dice "not implemented" o "coming soon"** → el endpoint
  existe en el código pero está deshabilitado → puede que solo esté
  deshabilitado en la UI, no en el servidor. Probar directamente.

---

## 3. ANOMALÍAS EN PARÁMETROS Y NOMBRES

Los nombres de los parámetros revelan la intención del desarrollador.
Un nombre honesto es la mejor documentación que existe.

- **Parámetro llamado `debug`, `test`, `dev`, `internal`, `admin`,
  `superuser`, `bypass`, `override`, `force`** → fue puesto ahí para
  algo. Cambiar el valor. Probar `true`, `1`, `yes`, `enabled`.

- **Parámetro llamado `role`, `group`, `permission`, `access`, `scope`,
  `tier`, `plan`, `level`** → privilege escalation candidato. Cambiar
  el valor al nivel más alto que se vea en la respuesta.

- **Parámetro llamado `redirect`, `next`, `url`, `goto`, `return`,
  `callback`, `target`, `dest`** → open redirect / SSRF. Ya cubierto en
  `vector_interrogation.md` sección 1 y 4, pero el nombre solo ya es
  la señal.

- **Parámetro con valor que parece un ID interno** (`userId=42`,
  `orderId=1337`, `accountId=99`) → IDOR. Ya cubierto en sección 2,
  pero el nombre + valor numérico bajo es la señal de que es secuencial.

- **Parámetro con valor que parece una ruta de archivo** (`template=
  invoice`, `page=home`, `include=header`, `file=config`) → LFI / path
  traversal candidato. Sección 16 de `vector_interrogation.md`.

- **Parámetro que aparece en el request pero NO aparece en la respuesta**
  → el servidor lo procesa internamente sin reflejarlo. Más interesante
  que los que sí se reflejan — puede afectar lógica sin ser visible.

- **Parámetro con valor booleano hardcodeado en el frontend** (`isAdmin=
  false`, `isPremium=false`, `canEdit=false`) → mass assignment candidato.
  Cambiar a `true` y ver qué pasa.

- **Dos parámetros con nombres similares** (`user_id` y `userId` en el
  mismo request) → uno puede ser el que el servidor usa realmente y el
  otro un vestigio. Probar enviando solo uno, solo el otro, valores
  distintos en cada uno.

- **Parámetro que el servidor ignora silenciosamente** → no devuelve
  error aunque el valor sea inválido → puede estar whitelisted o puede
  estar en un código path diferente. Probar con valores extremos.

- **Endpoint que acepta más campos de los que pide** → mass assignment.
  Enviar campos extras del schema (buscados en JS, en otros endpoints,
  en el swagger si existe) y ver cuáles son procesados.

---

## 4. ANOMALÍAS EN HEADERS DE RESPONSE

Los headers de respuesta son la firma involuntaria del servidor.

- **`Server:` o `X-Powered-By:` con versión exacta** → fingerprint
  directo. Buscar CVEs para esa versión. Sección 11 de
  `vector_interrogation.md`.

- **Header `X-Debug-Info`, `X-Request-Id`, `X-Trace-Id`** → el servidor
  tiene modo debug. Buscar otros endpoints con más debug info. A veces
  el trace ID permite correlacionar requests en logs internos (útil si
  hay SSRF o LFI que llega a logs).

- **Header de respuesta que refleja un header del request que no se
  envió** → el servidor añade headers basados en algo interno. Puede
  revelar proxies intermedios, tecnología de backend, o configuración
  interna.

- **`Access-Control-Allow-Origin` que refleja el `Origin` enviado** →
  CORS misconfiguration. Sección 19 de `vector_interrogation.md`.

- **`Set-Cookie` sin `HttpOnly` en cookie de sesión** → XSS roba sesión.
  Elevar severidad de cualquier XSS encontrado en ese dominio.

- **`Set-Cookie` sin `SameSite`** → CSRF posible. Sección 13 de
  `vector_interrogation.md`.

- **`Cache-Control: no-store` en un endpoint pero `Age: 30` en otro
  endpoint que devuelve datos similares** → inconsistencia de política
  de cache. El que tiene `Age` puede estar cacheando datos que no debería.

- **`Content-Type` de la respuesta no coincide con el contenido real** →
  el servidor sirve HTML con `Content-Type: text/plain` → XSS posible
  si se puede inyectar HTML (el browser puede sniffear el tipo).
  O sirve JSON con `Content-Type: text/html` → XSS si el JSON contiene
  input del usuario.

- **Response con header `Location:` que incluye parámetros del request**
  → open redirect / header injection. Sección 1 de
  `vector_interrogation.md`.

- **Dos requests idénticos devuelven headers distintos** → hay estado
  intermedio, load balancer con configuración inconsistente, o A/B
  testing. Si los headers revelan tecnologías distintas → hay más de
  un backend → buscar el más desactualizado.

- **`Vary: *`** → el servidor dice que la respuesta varía por cualquier
  header → cache probablemente no se aplica, pero también puede ser
  configuración defensiva mal entendida. Verificar si hay cache de
  todas formas.

- **Header `X-Frame-Options` ausente** → clickjacking posible. Por sí
  solo es P4, pero combinado con una acción sensible (cambio de email,
  transferencia de fondos) sube a P2/P3.

---

## 5. ANOMALÍAS EN COMPORTAMIENTO DE AUTH

El comportamiento de la autenticación revela mucho sobre cómo está
implementada.

- **Login exitoso devuelve el mismo token siempre** → token estático,
  no generado por sesión → cualquiera que lo haya capturado alguna vez
  puede usarlo indefinidamente.

- **Logout no invalida el token server-side** → probar reusando el token
  después del logout. Si funciona → sesión no invalidada → P2/P3.

- **Cambiar password no invalida las sesiones anteriores** → ATO parcial:
  si se capturó la sesión, sigue válida aunque la víctima cambie su
  contraseña.

- **El token de sesión no cambia después del login** → session fixation.
  Si un atacante puede fijar el token antes del login, después del login
  tiene la sesión de la víctima.

- **Endpoint de "verificar token" devuelve información sobre el token
  aunque sea inválido** → oracle. Puede revelar si el token existió,
  si expiró, o a qué usuario pertenecía.

- **El JWT tiene `"alg": "none"`** → firma no verificada. Forjar payload
  arbitrario. P1 inmediato.

- **El JWT tiene `"alg": "HS256"` en un sistema que usa RS256 para otros
  tokens** → alg confusion. Intentar firmar con la clave pública RSA
  como secret HMAC.

- **El claim `exp` del JWT está en el pasado pero el servidor lo acepta**
  → el servidor no verifica expiración → token válido indefinidamente.

- **Dos endpoints distintos aceptan el mismo token pero uno devuelve más
  información que otro** → el más restrictivo tiene validación adicional,
  el menos restrictivo puede tener gaps de autorización.

- **El endpoint de refresh de token acepta el mismo refresh token
  múltiples veces** → refresh token reutilizable → sesión perpetua
  aunque el usuario cierre sesión.

- **El flujo de 2FA se puede bypassear pasando directamente al endpoint
  post-2FA** → 2FA solo en el cliente, no en el servidor → bypass
  completo. Probar acceder a endpoints autenticados sin completar el
  flujo de 2FA.

- **El OTP de 2FA no expira o tiene un window de tiempo muy largo**
  → brute force con más tiempo disponible.

---

## 6. ANOMALÍAS EN LA SUPERFICIE DE JS

El código JavaScript es el mapa que el desarrollador dejó sin querer.

- **Source maps en producción** (`*.js.map` accesible) → código fuente
  original. Leer todo. Buscar endpoints hardcodeados, lógica de negocio
  no documentada, secrets, comentarios de desarrolladores.

- **`console.log` en producción con datos sensibles** → el developer
  olvidó limpiar el debug. Abrir DevTools y ver qué se loguea durante
  el uso normal de la app.

- **Variables globales con nombres sugestivos** (`window.userId`,
  `window.isAdmin`, `window.apiKey`, `window.config`) → leer su valor
  en la consola del browser. A veces contienen tokens, IDs internos,
  o configuración que no debería ser pública.

- **Endpoints hardcodeados en el JS que no aparecen en la UI** →
  funcionalidad no expuesta en la interfaz pero sí en el servidor.
  Probar directamente. Candidatos frecuentes: endpoints de admin,
  endpoints de debug, endpoints de export masivo.

- **URLs de entornos no-productivos hardcodeadas** (`api.dev.target.com`,
  `staging.target.com`, `qa-api.target.com`) → entornos con menos
  hardening. Verificar si son accesibles desde internet.

- **API keys, tokens, o secrets hardcodeados en el JS** → leer y guardar
  en `exposed-secrets`. Nunca usar credenciales de producción para
  testing destructivo — reportar inmediatamente.

- **Comentarios con TODOs, FIXMEs, o HACKs** → (`// TODO: add auth
  check here`, `// FIXME: this is insecure`, `// HACK: bypass for
  testing`) → el desarrollador sabía que era inseguro. Ir directo ahí.

- **Feature flags en el JS** (`if (config.featureFlags.newCheckout)`) →
  probar forzar la flag desde la consola o desde el request → puede
  habilitar funcionalidad sin terminar de implementar y sin los controles
  de la versión estable.

- **Versiones de librerías desactualizadas en `package.json` o en el
  bundle** → buscar CVEs para esas versiones exactas. Especialmente
  relevante para librerías de parsing (XML, YAML, archivos) y de
  autenticación.

- **El bundle JS carga otros scripts desde dominios externos** →
  si alguno de esos dominios está expirado o es tomable → script
  injection sobre todos los usuarios del sitio. Sección 17 de
  `vector_interrogation.md`.

- **Rutas de la SPA que la UI no linkea** → si la app es React/Vue/
  Angular, el router puede tener rutas definidas que no tienen link
  desde la navegación normal. Revisar el router en el JS y probar
  cada ruta directamente.

---

## 7. ANOMALÍAS DE COMPORTAMIENTO ENTRE ENDPOINTS

La inconsistencia entre endpoints del mismo servidor es siempre
interesante. Los servidores bien implementados son consistentes.

- **Un endpoint valida, otro no valida el mismo campo** → el que no
  valida se implementó después o por otro desarrollador. El que no
  valida es el candidato.

- **Un endpoint requiere auth, otro endpoint que hace algo similar no
  la requiere** → BFLA / acceso no autorizado. Probar el segundo
  endpoint directamente.

- **Un endpoint aplica rate limiting, otro endpoint equivalente no** →
  el segundo es el bypass del rate limit. Frecuente en APIs con
  versiones (`/api/v1/login` vs `/api/v2/login`).

- **Un endpoint devuelve un campo en la respuesta que otros endpoints
  no devuelven** → ese campo puede ser sensible y estar expuesto por
  error. Buscar campos como `password_hash`, `secret`, `internal_note`,
  `admin_comment`.

- **Distintas versiones de la API devuelven distinta cantidad de campos**
  → `/api/v1/user/me` devuelve 5 campos, `/api/v2/user/me` devuelve 3.
  La v1 puede estar exponiendo campos que la v2 filtró. Probar la v1
  aunque la UI use la v2.

- **El método GET y el método POST en el mismo endpoint tienen
  comportamientos distintos** → el POST puede tener validaciones que
  el GET no tiene (o viceversa). Probar ambos métodos en todos los
  endpoints de datos sensibles.

- **Endpoint que devuelve 200 con body vacío en vez de 403/404** →
  el servidor encontró el recurso pero decidió no mostrarlo. Puede
  haber metadata en los headers, o puede ser que otro parámetro
  desbloquee el contenido.

- **Endpoint que acepta el mismo request con distintos Content-Type** →
  si acepta tanto `application/json` como `application/x-www-form-
  urlencoded`, puede que el parser de uno tenga validaciones que el
  otro no tiene.

---

## 8. ANOMALÍAS EN LA INFRAESTRUCTURA

La infraestructura habla. Hay que saber escuchar.

- **Subdominio con certificado TLS válido pero que devuelve 404 en
  todas las rutas** → el cert se emitió para ese subdominio, el server
  responde, pero no hay contenido. Candidato a takeover o a superficie
  olvidada. Probar con diferentes métodos, paths, y hosts.

- **CNAME que apunta a un servicio externo que no tiene el nombre del
  target configurado** → subdomain takeover. Verificar si el servicio
  externo permite reclamar ese nombre. Sección 17 de
  `vector_interrogation.md`.

- **Dos subdominios que devuelven el mismo contenido pero con headers
  distintos** → están detrás de configuraciones distintas. El que tiene
  menos headers de seguridad es el más interesante.

- **Subdominio con nombre de entorno** (`dev`, `test`, `staging`, `qa`,
  `uat`, `demo`, `beta`, `sandbox`, `internal`, `corp`) → entornos de
  desarrollo con menos hardening. Priorizar.

- **IP que responde a múltiples nombres de host** → vhost scanning. El
  virtual host por defecto (sin `Host` header o con `Host: <IP>`) puede
  servir contenido distinto al esperado.

- **Puerto no estándar abierto en un host** (8080, 8443, 9000, 9090,
  4000, 3000, 5000, 8888) → aplicaciones de desarrollo o admin panels
  corriendo en puertos alternativos, a veces sin autenticación.

- **Certificado TLS con Subject Alternative Names (SANs) inesperados** →
  el cert revela otros hostnames del mismo servidor que no están en DNS
  público. Probar esos hostnames directamente con `Host` header override.

- **Headers de response que revelan tecnología de CDN/WAF/proxy distinta
  a la esperada** → hay una capa intermedia. Probar si se puede acceder
  al origen directamente (bypass de WAF). Buscar IP de origen en
  Shodan/Censys si el target lo permite.

- **Respuesta de un endpoint varía según el IP de origen** → el servidor
  trata distinto a distintos IPs. Puede haber allowlisting por IP que
  se puede bypassear con headers (`X-Forwarded-For`).

- **El mismo endpoint detrás de dos URLs distintas tiene comportamiento
  diferente** → una pasa por CDN/WAF y la otra no. La que no pasa por
  el WAF es más interesante.

---

## 9. ANOMALÍAS EN LÓGICA DE NEGOCIO

La lógica de negocio tiene invariantes que el desarrollador asume pero
no siempre verifica. Atacar las asunciones.

- **Precio que se puede hacer 0 o negativo** → `quantity: -1` convierte
  una compra en un crédito. `price: 0` permite comprar gratis.
  `discount: 110` aplica más del 100% de descuento.

- **Flujo que asume que los pasos se completan en orden** → saltear
  el paso de pago y ir directo a la confirmación. El servidor a veces
  solo verifica el último paso.

- **Límite de uso que no se verifica server-side** → cupón de "un solo
  uso", bono de bienvenida, crédito gratis — si el check es solo en
  el frontend, es bypasseable. Enviar el request directamente.

- **Operación que debe ser atómica pero no lo es** → race condition.
  Dos requests simultáneos para usar el mismo cupón, retirar el mismo
  saldo, reclamar el mismo recurso único.

- **Campo que el servidor actualiza en base a otro campo del request,
  pero ambos vienen del cliente** → `total = price * quantity` calculado
  en el cliente y enviado al servidor. Si el servidor no recalcula,
  manipular `total` directamente.

- **Estado de una entidad que el servidor asume que solo puede ir
  hacia adelante** → si una orden puede ir de "pendiente" a "enviada"
  a "entregada", ¿puede ir de "entregada" a "pendiente"? ¿Puede ir
  a "cancelada" después de "entregada" para obtener un reembolso?

- **Acción que requiere ser propietario de un recurso, pero la
  propiedad se verifica en el paso anterior, no en el paso de la
  acción** → completar el paso de verificación de propiedad con el
  recurso propio, luego cambiar el ID en el paso de la acción.

- **Funcionalidad "solo para usuarios premium" que verifica el plan
  en el frontend pero no en cada request de API** → si se puede
  llamar al endpoint de la API directamente sin pasar por el
  frontend → acceso a funcionalidad premium sin pagar.

- **Descuentos o beneficios que se calculan en el momento del checkout
  pero se aplican más tarde** → si el precio cambia entre el momento
  del cálculo y el momento de cobro, ¿qué precio usa el servidor?

---

## 10. ANOMALÍAS EN FLUJOS DE DATOS

Seguir el dato es más útil que atacar el endpoint. El dato pasa por
múltiples manos — alguna lo maneja mal.

- **Un dato que entra por un canal vuelve a salir por otro canal
  distinto** → si el nombre de usuario se muestra en emails, en PDFs,
  en notificaciones push — cada canal de salida tiene su propio parser
  y sus propias validaciones. Un canal puede sanitizar, otro no.

- **Dato que se almacena y se muestra más tarde a un usuario diferente**
  → XSS stored. El dato que entra como "nombre de empresa" en el
  perfil del atacante puede verse en el panel del admin que revisa
  empresas.

- **Dato que pasa por múltiples sistemas antes de mostrarse** → CRM →
  email marketing → template de email → inbox del usuario. Cada
  sistema aplica su propio encoding. Si hay doble encoding o encoding
  inconsistente, puede haber bypass de filtros.

- **Dato que se usa en una query sin ser el input directo** → si el
  nombre de usuario se usa en una query interna para buscar sus
  pedidos, y el nombre de usuario viene del token JWT (no del request),
  ¿se sanitiza antes de usarse en la query?

- **Dato sensible que aparece en la URL** → URLs van a logs de servidor,
  logs de CDN, header `Referer`, historial del browser, bookmarks.
  Tokens, IDs de sesión, o datos personales en la URL son un finding
  por sí mismos.

- **Dato que se envía a un tercero** → analytics, error tracking
  (Sentry, Datadog), CDN logs, webhooks. Si el dato sensible del
  usuario llega a un tercero sin su consentimiento → privacy finding.

- **Dato que existe en la response pero no se muestra en la UI** →
  campos en el JSON que el frontend no renderiza pero están ahí.
  Frecuente con campos de admin, campos internos, o campos de roles.
  Revisar el response completo, no solo lo que muestra la UI.

---

## 11. PATRONES DE DESARROLLADOR

Los desarrolladores dejan huellas. Reconocer las huellas dice mucho
sobre qué buscar.

- **Comentarios en inglés en código que el resto está en otro idioma** →
  ese código fue copiado de otro lugar (StackOverflow, un tutorial, un
  proyecto open source). Buscar de dónde viene — puede tener la misma
  vulnerabilidad que el original.

- **Nombres de variables internas en el error o en el response** →
  `userId`, `internalOrderId`, `adminFlag` — el developer usa los
  mismos nombres en la API que en el código interno. Esos nombres son
  candidatos a mass assignment.

- **Endpoint que existe pero no está documentado en el swagger/API docs**
  → fue agregado ad-hoc, probablemente sin el mismo proceso de review
  de seguridad que los endpoints documentados.

- **Funcionalidad que "no debería estar en producción" según comentarios**
  → (`// this is just for testing`, `// remove before deploy`) →
  el developer olvidó quitarlo. Estos son los endpoints más jugosos.

- **Dos implementaciones distintas de la misma funcionalidad** →
  una es la nueva, una es la vieja que "quedó". La vieja casi siempre
  tiene menos validaciones.

- **Endpoint que devuelve más información en el error que en el éxito**
  → en el éxito devuelve solo el resultado; en el error devuelve el
  stack trace, los parámetros del request, o el estado interno.
  Triggear errores deliberadamente para extraer información.

- **Comportamiento distinto entre el primer request y los siguientes**
  → lazy initialization, cache que se llena en el primer request,
  estado que se inicializa. El primer request puede tener un window
  de race condition o de estado inconsistente.

---

## 12. SEÑALES DE BAJO COSTO, ALTO VALOR

Cosas rápidas de verificar que tienen alto retorno si dan positivo.

- **`/.git/`** → si `/.git/HEAD` responde 200 → repositorio expuesto.
  Reconstruir el source con `git-dumper`. P1 inmediato.

- **`/.env`** → si responde 200 → credenciales, API keys, configuración
  de DB expuesta. P1 inmediato.

- **`/phpinfo.php`** → configuración completa de PHP, variables de
  entorno, rutas del filesystem.

- **`/server-status`** → Apache status page. Lista de IPs, URLs en
  proceso, carga del servidor.

- **`/actuator/env`** → Spring Boot con variables de entorno. Passwords,
  API keys, configuración interna.

- **`/api/swagger.json`** o **`/api/openapi.json`** → documentación
  completa de la API incluyendo endpoints no linkados desde la UI.

- **`/graphql`** con introspección → schema completo. Sección 8 de
  `vector_interrogation.md`.

- **`robots.txt`** → rutas que el dueño no quiere que indexen.
  Frecuentemente revelan admin panels, endpoints internos, o rutas
  de staging.

- **`/sitemap.xml`** → mapa completo de URLs del sitio. A veces incluye
  rutas que no son linkadas desde la navegación principal.

- **`/crossdomain.xml`** o **`/clientaccesspolicy.xml`** → política de
  acceso cross-domain de Flash/Silverlight (legacy pero a veces
  presente). Si es permisiva puede habilitar acceso cross-origin a
  datos.

- **Certificado TLS con SANs** → siempre revisar los SANs del cert.
  `openssl s_client -connect target.com:443 | openssl x509 -noout
  -text | grep DNS:` → revela otros hostnames del mismo servidor.

- **`/api/v1/` vs `/api/v2/`** → si la app usa v2, probar todos los
  endpoints en v1. Las versiones viejas frecuentemente tienen menos
  validaciones.

- **Método OPTIONS en endpoints de API** → a veces revela métodos
  aceptados que no están en la documentación (PUT, DELETE, PATCH
  en endpoints que la UI solo usa como GET).

- **Header `X-Powered-By: PHP/5.x` o versión muy vieja** → versión
  EOL con CVEs conocidos. P2/P1 si hay CVE explotable.

---

## 13. HEURÍSTICAS DE PRIORIZACIÓN

Cuando hay mucha superficie y poco tiempo, priorizar en este orden:

1. **Lo que nadie más está mirando** → subdominios nuevos, funcionalidad
   oscura, endpoints sin documentar. Los bugs en superficie obvia ya
   los encontraron otros hunters.

2. **Lo que tiene contexto de negocio sensible** → pagos, salud,
   identidad, mensajería privada, documentos legales. El mismo bug
   en un endpoint de "favoritos" vs en un endpoint de "transferencia
   bancaria" tiene severidades muy distintas.

3. **Lo que tiene múltiples caminos de explotación** → un XSS en una
   página pública con muchos usuarios vale más que un XSS en una
   página que nadie visita.

4. **Lo que el scanner no puede ver** → lógica de negocio, IDOR con
   contexto de roles, race conditions, flujos multi-paso. Si se puede
   encontrar con un scanner, ya lo encontraron.

5. **Lo que tiene mayor impacto con menos interacción de la víctima** →
   SSRF sin interacción > XSS sin interacción > XSS con click > CSRF
   con click. Menos fricción = mayor severidad real.

6. **Lo que está en infraestructura vieja o mantenida por equipos
   distintos** → el módulo de legacy, la integración de terceros, el
   subdominio que parece abandonado. Suelen tener menos security review.

7. **Lo que toca múltiples sistemas** → una vulnerabilidad en el SSO
   pega en todos los sistemas que dependen del SSO. Una en la API de
   pagos pega en todos los clientes. Mayor blast radius = mayor
   prioridad.

---

## 14. ANTI-HEURÍSTICAS — Qué NO señala un bug

Para no perder tiempo:

- **HTTPS con certificado válido** → no significa que la app sea segura.
  Solo significa que el canal es cifrado.

- **WAF presente** → no significa que todo esté bloqueado. Los WAFs
  tienen gaps, especialmente en lógica de negocio y en IDOR.

- **"Está en producción desde hace años sin reports"** → no significa
  que no haya bugs. Significa que no los encontraron todavía o que
  los encontraron y no los reportaron.

- **Response 403 en el primer intento** → no significa que el endpoint
  sea inaccesible. Puede haber bypass de path, de método, de header.

- **La empresa es grande y conocida** → no significa que el código sea
  seguro. Las empresas grandes tienen superficie enorme y equipos de
  seguridad que no pueden cubrir todo.

- **El endpoint no devuelve nada sensible "a primera vista"** → revisar
  el response completo. Hay campos en el JSON que el frontend no
  renderiza. Hay headers que revelan información. Hay timing que
  revela estado interno.

- **El parámetro tiene un nombre genérico** (`id`, `type`, `action`) →
  no significa que no sea interesante. El nombre genérico a veces
  esconde superficie más amplia que un nombre específico.

- **"Ya lo probamos antes"** → ¿cuándo? ¿Con qué profundidad? ¿Cambió
  el código desde entonces? Los targets cambian. Lo que no era
  vulnerable hace 6 meses puede serlo hoy.
