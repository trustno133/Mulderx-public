# Bypass catalog — SSRF

Cada técnica marcada `confirmado` (probada en vivo contra un target/lab
real, con evidencia) o `sin verificar` (documentada pero no probada acá,
o probada con un confound que no permite atribuir el resultado con
certeza). No tratar ambas con el mismo peso al elegir qué probar
primero — siempre arrancar por lo `confirmado`.

Nunca nombrar programas/targets activos de bug bounty acá — este
archivo es compartido entre sesiones y targets. Si una técnica se
confirmó en un lab de entrenamiento público (PortSwigger Academy y
similares) está bien referenciarlo por no ser información sensible;
si se confirmó contra un programa real, generalizar el patrón sin
nombrar el programa, la empresa, ni paths/IDs específicos de ese
target (igual criterio que credenciales: eso vive únicamente en
`targets/<target>/`).

## Blacklist de host/path case-sensitive vs. componente que resuelve la URL de forma case-insensitive — `confirmado`

**Contexto de confirmación**: PortSwigger Academy, lab "SSRF with
blacklist-based input filter" (PortSwigger Academy, 2026-07-31).

**Idea**: si el filtro compara el host o el path contra un blacklist de
strings exactos (`localhost`, `127.0.0.1`, `admin`, etc.) pero algún
componente aguas abajo (resolución DNS, y en algunos stacks el router
HTTP) no distingue mayúsculas de minúsculas, cambiar el case de la
parte filtrada puede bypasear el check sin cambiar el destino real.

**Evidencia concreta de esa sesión**:
- Filtro de host: bloqueaba `localhost` y `127.0.0.1` en minúsculas.
  `LOCALHOST` (mayúsculas) y `127.1` (IP corta, string distinto al
  literal `127.0.0.1`) pasaron el filtro y conectaron de verdad.
- Filtro de path: bloqueaba el substring `admin` en minúsculas.
  `/Admin` y `/ADMIN` pasaron el filtro.
- Combinados (`http://LOCALHOST/Admin/...`) llegaron al mismo panel
  admin interno que hubiera devuelto la URL en minúsculas sin filtro.

**Sobre por qué el backend igual rutea a la página correcta con case
distinto**: no se confirmó el stack/framework real detrás de este lab
(no se hizo fingerprinting — sin headers `Server`/`X-Powered-By` ni
error verboso que lo revele). No asumir que es un framework puntual
(ej. Express) sin haberlo verificado — lo único confirmado es el
comportamiento observado: el router de ESTE backend no distingue case
en el path, el filtro sí. Verificar caso a caso.

**Cómo probarlo**:
1. Aislar CADA componente de la URL por separado antes de asumir "todo
   bloqueado" — un blacklist de host y uno de path pueden coexistir, y
   probar `<host-sospechoso>/admin` mezcla ambos. Testear el host solo
   (`http://X`, sin path) y el path solo (sobre un host que se sabe
   limpio, ej. un dominio público arbitrario) para no confundir cuál
   defensa está bloqueando qué.
2. Si el string exacto en minúsculas está bloqueado, probar la MISMA
   URL con el componente sospechoso en mayúsculas.
3. Si eso pasa el filtro, confirmar que el backend real sigue
   resolviendo/ruteando igual (compara el contenido devuelto contra el
   que se esperaría del path/host original) — un bypass de filtro que
   termina en un 404 real del backend no es una confirmación.

## Doble-encoding de `#` en el userinfo para bypasear una whitelist de host bien implementada — `confirmado` (técnica de origen externo, ejecución verificada en vivo)

**Contexto de confirmación**: PortSwigger Academy, lab "SSRF with
whitelist-based input filter" (PortSwigger Academy, 2026-07-31).

**Origen — nota de honestidad**: la idea central de esta técnica NO
salió de fuzzing propio en esa sesión. Se agotó un barrido extenso de
bypasses clásicos (userinfo `@`, subdominios, `.localhost`, encodings
de IP, HPP, opaque URI) contra una whitelist que resultó tener un
parser de host robusto (`java.net.URI`, confirmado por el formato
exacto del mensaje de excepción) — nada de eso funcionó. Se consultó
la documentación pública del lab para obtener la técnica correcta en
vez de seguir adivinando. Lo que SÍ se verificó en vivo (y vale como
evidencia real): que el payload documentado efectivamente resuelve el
lab, y un detalle de encoding no documentado en la fuente original
(ver abajo).

**Cuándo aplica**: cuando la whitelist SÍ valida el host correctamente
(parser robusto, resistente a los trucos de ofuscación habituales) —
o sea, cuando el resto de este catálogo ya se agotó sin éxito. La
premisa a explotar no es "el parser de validación es débil", es "el
parser de validación y el mecanismo que hace la conexión real pueden
ser DOS componentes distintos que interpretan el mismo string de forma
diferente".

**Mecanismo**:
1. Insertar `%2523` (doble-encoding de `#`) en el userinfo, entre el
   host que se quiere alcanzar realmente y el `@<host-whitelisteado>`:
   `http://<host-real>%2523@<host-whitelisteado>/<path>`.
2. El framework decodifica el body UNA vez al parsear
   `application/x-www-form-urlencoded` → `%2523` se convierte en
   `%23` (todavía no es un `#` real). El parser de VALIDACIÓN ve ese
   `%23` como texto literal dentro del userinfo, no como delimitador
   de fragmento — extrae el host whitelisteado correctamente → pasa.
3. El mecanismo que hace la conexión real decodifica el string una vez
   más en algún punto de su propio procesamiento interno — `%23` pasa
   a ser un `#` real, ahora sí interpretado como inicio de fragmento
   URI. Todo lo que sigue (`@<host-whitelisteado>/...`) queda
   consumido como fragmento; el host efectivamente usado para conectar
   es solo la porción anterior (`<host-real>`).

**Cómo confirmarlo sin poder leer contenido interno (caso semi-blind)**:
la respuesta HTTP para el payload exitoso puede ser indistinguible en
texto de una falla real (mismo mensaje de error genérico en ambos
casos, porque la app intenta parsear la respuesta del destino interno
como si fuera el formato esperado del servicio legítimo y falla en
ambos casos). No tratar ese error genérico como gate de confirmación
por sí solo — buscar un efecto observable independiente (en un lab: el
estado "solved"; en un target real: releer el recurso por otra vía, o
un side-effect verificable).

**Detalle no documentado en la fuente, aislado empíricamente**: el
mismo payload falló cuando se envió con una herramienta que re-escapa
automáticamente TODOS los caracteres estructurales del valor
(`curl --data-urlencode`, que convierte `:`, `/`, `?`, `=` a `%XX`
antes de transmitir) — verificado byte a byte que el body,
decodificado una vez, reconstruía el string exacto esperado, y aun así
no funcionó. Funcionó recién al enviarlo como body crudo (solo el
`%2523` tipeado literalmente, el resto de caracteres sin escapar
adicionalmente — equivalente a como se escribiría a mano en Burp
Repeater). No se determinó la causa exacta de la diferencia
(matemáticamente ambas formas deberían decodificar al mismo string del
lado del servidor). **Lección práctica**: si un payload documentado
que depende de capas de encoding "no funciona" con una herramienta que
auto-encodea el valor completo, probar también con el body crudo antes
de descartarlo.

## Encodings alternativos de IP (octal, decimal, hexadecimal, IPv6 y trailing dot) — cobertura condicionada

Las representaciones alternativas solo son relevantes si la aplicación compara texto sin normalizar. Un resolver o cliente HTTP puede normalizar el host antes de conectar, y los controles de egreso de red pueden bloquear la conexión aunque el filtro de aplicación la permita.

**Cómo registrar la evidencia**:
- Probar un cambio por request y solo con autorización explícita para ese endpoint.
- Registrar status, latencia y cuerpo resumido, sin repetir solicitudes que ya activaron un challenge o bloqueo.
- Separar el rechazo de aplicación del timeout de red; un tiempo parecido no demuestra por sí solo dónde se aplicó el control.
- No inferir el comportamiento de otros entornos, direcciones o targets a partir de un resultado aislado.
- Detener la vía activa ante challenge, rate limit, degradación o errores sostenidos.

**Encodings alternativos de IP (octal, decimal, hex, IPv6, trailing dot) — `sin verificar` (confound sin aislar, contexto PortSwigger)**

**Contexto**: mismo lab de arriba. Se probaron `0177.0.0.1` (octal),
`2130706433` (decimal), `0x7f000001` (hex), `[::1]` (IPv6),
`127.0.0.1.` (punto final) y trucos de userinfo (`user@127.0.0.1`) —
todos devolvieron bloqueo.

**Por qué NO cuentan como "probado, no sirvió"**: todos se probaron
junto con el path `/admin`, que se sabía bloqueado por un segundo
filtro independiente (ver técnica de arriba). No se aisló cuál de los
dos filtros estaba cortando cada intento, así que no se puede afirmar
con certeza que estas representaciones de IP fallen contra el filtro
de HOST específicamente — pueden haber sido bloqueadas solo por el
path. Queda pendiente re-testear cada una sin path para saber si son
bypass reales de un filtro de host basado en substring.

**Única excepción aislada limpiamente**: `127.0.0.1.nip.io` (dominio
wildcard con el string exacto `127.0.0.1` como subdominio) se probó
SIN path y siguió bloqueado — confirma que ese filtro de host
específico hace substring match sobre el string completo, no solo
sobre el hostname exacto, así que insertar el string literal
blacklisteado dentro de un hostname más largo no alcanza como bypass
por sí solo.

## Open redirect propio de la app como salto del filtro "solo mismo host" — `confirmado`

**Contexto de confirmación**: PortSwigger Academy, lab "SSRF with
filter bypass via open redirection vulnerability"
(PortSwigger Academy, 2026-07-31).

**Idea**: cuando el filtro SSRF no es un blacklist de strings sino algo
más estricto — solo acepta paths relativos, rechaza cualquier valor
con esquema/host explícito (incluso apuntando al mismo dominio) — no
hay encoding que lo bypasee directamente, porque no está comparando el
destino, está rechazando la FORMA del input. El salto no está en el
parámetro SSRF: está en buscar un endpoint DISTINTO de la misma app
que reciba una URL y la use para redirigir (302, `Location` sin
validar) — un open redirect. Se manda un path relativo (pasa el
filtro) que apunta a ese endpoint con el destino real embebido en su
parámetro; el cliente HTTP que hace el fetch server-side sigue el 302
y termina en el destino que el filtro nunca vio.

**Evidencia concreta de esa sesión**:
- Filtro rechazaba `stockApi=<url-absoluta>` con `400 Invalid URL` —
  probado con IP objetivo, dominio externo, y hasta el propio dominio
  del lab con esquema explícito. Solo pasaban paths relativos puros.
- Endpoint de navegación de catálogo (`/product/nextProduct?path=X`)
  resultó ser un open redirect real: `path` se copia sin validar al
  header `Location`, confirmado primero con un destino externo
  benigno antes de apuntar a nada interno (paso 3 de la metodología
  de la skill).
- Payload final: `stockApi=/product/nextProduct?path=<url-interna>` —
  el valor completo sigue siendo un path relativo (pasa el filtro),
  pero resuelve a un 302 hacia la IP interna, y el fetcher del
  stock-checker sí sigue redirects (a diferencia de otros labs de la
  misma serie donde no los sigue — verificar esto puntualmente en cada
  target, no asumirlo).

**Cómo probarlo**:
1. Si el filtro SSRF rechaza cualquier URL con host explícito (no es
   un blacklist de destinos, es una restricción de forma), no buscar
   más encodings del mismo parámetro — buscar otro punto de la app que
   acepte una URL/path y la use para redirigir (parámetros típicos:
   `next`, `redirect`, `return`, `path`, `url`, `continue`, o cualquier
   link de "volver a"/"siguiente" visible en la UI).
2. Confirmar el open redirect de forma aislada primero (destino
   externo benigno, mirar el header `Location`) antes de asumir que
   sirve para el chaining.
3. Encadenar: el valor que se manda al parámetro SSRF original es el
   path relativo hacia el endpoint de redirect, con el destino real
   (interno) como parámetro de ESE endpoint — no directo.
4. Confirmar que el cliente que hace el fetch server-side realmente
   sigue el redirect (contenido del destino final en la respuesta, no
   solo que el redirect endpoint lo acepte) — algunos clientes HTTP
   server-side no siguen 3xx por diseño, en cuyo caso esta técnica no
   sirve y hay que buscar otro ángulo.

## Servicios de wildcard-DNS como vector de host controlado — depende de si el filtro resuelve DNS o solo compara strings

Un filtro que solo compara el string del host contra un blacklist
puede bypasearse insertando la IP objetivo en un dominio wildcard
(`nip.io`, `sslip.io`, etc.) **solo si el string resultante no sigue
conteniendo el literal blacklisteado** (ver caso de arriba: si el
filtro blacklistea `127.0.0.1` como substring, un subdominio que
todavía contenga ese string literal no sirve).

Un filtro que en cambio resuelve DNS y valida la IP resultante (en vez
de comparar strings) puede: (a) bloquear específicamente el dominio
wildcard conocido como firma de bypass, dejando pasar destinos
públicos legítimos vía otros medios; o (b) resolver y comparar la IP
real, en cuyo caso el wildcard-DNS no aporta nada como bypass — sirve
solo para ocultar cuál es el destino final antes de la resolución, no
para evadir una validación que ocurre después de resolver. Confirmado
en un target real (no reproducible acá por ser información específica
de programa — ver nota de manejo de datos al inicio de este archivo):
un filtro puede blocklistear un servicio de wildcard-DNS conocido por
nombre mientras deja pasar otro servicio equivalente que no está en su
lista, y por separado aplicar un chequeo real de rango de IP privada
DESPUÉS de la resolución — dos mecanismos independientes que hay que
diferenciar con controles (comparar timing/respuesta entre un destino
que se sabe que existe en la red interna vs. uno que se sabe que NO
existe, para confirmar si el corte pasa antes o después de intentar
conectar).

### Variante con guiones en nip.io — `sin verificar`

`127-0-0-1.nip.io` resuelve a `127.0.0.1` igual que
`127.0.0.1.nip.io`, pero el string del subdominio no contiene
el literal `127.0.0.1` con puntos. Esto bypasea blacklists que
hacen substring match sobre la representación canónica con puntos
pero no contemplan la variante con guiones como forma alternativa
del mismo host.

Análogamente para la IP de cloud metadata:
`169-254-169-254.nip.io` (variante con guiones de `169.254.169.254`).

No probado en lab ni target real — marcar como confirmado si se
verifica en algún entorno controlado antes de usarlo como evidencia
en un reporte.

### Concatenación con dominio whitelisteado — `sin verificar`

Si el filtro valida que la URL contiene un dominio autorizado pero
el regex no está anclado (no exige que el dominio sea el host exacto,
solo que aparezca en alguna parte del string), se puede construir
un payload donde el dominio whitelisteado quede embebido en la URL
pero el host efectivo que resuelve sea otro:

```
http://target.com.127.0.0.1.nip.io
```

El string `target.com` aparece al inicio y un filtro weak puede
validarlo ahí. El resolver DNS del servidor procesa el subdominio
completo (`target.com.127.0.0.1.nip.io`) y retorna `127.0.0.1`.

**Condición necesaria**: que el filtro sea regex sin anclar (no
equivale a validar que el host sea `*.target.com` de forma correcta).
Un filtro que parsea la URL y extrae el host antes de comparar no
es vulnerable a esta variante — hay que confirmar primero si la
validación opera sobre el string crudo o sobre el host parseado.

## DNS rebinding — TOCTOU entre validación y conexión — `sin verificar`

**Nota de calibración**: no concluyas que el control vive en la aplicación o en la red a partir de una sola respuesta. Separa observaciones de inferencias y no extrapoles resultados entre entornos.

Explota un filtro que **resuelve el hostname para validarlo** (ej:
"si la IP resuelta no es privada, dejar pasar") pero resuelve **de
nuevo** al hacer la conexión real, en vez de reusar la IP ya validada.
Entre esos dos resolves hay una ventana de tiempo — si el atacante
controla el DNS del hostname, puede servir una IP pública en la
primera resolución (pasa el filtro) y una IP interna en la segunda
(la conexión real pega ahí).

**Requisitos:**
- Dominio propio con TTL de DNS bajo (0–5s) y control total de las
  respuestas — servicios como `rbndr.us` o un resolver propio armado
  con TTL mínimo sirven para esto.
- El filtro tiene que resolver el hostname **antes** de la request
  real (no comparar contra una IP ya fija/hardcodeada) — si el filtro
  solo bloquea rangos de IP literal en el input (`127.0.0.1`,
  `169.254.169.254` tal cual) sin resolver nada, esto no aplica, el
  vector correcto ahí es un bypass de encoding, no rebinding.
- **Si el único bloqueo es TCP/red, rebinding no sirve** — la conexión
  TCP a la IP interna fallará igual. Rebinding solo es útil contra
  checks de app-level.

**Patrón de ataque:**
1. Confirmar que el target resuelve DNS en el momento de la request
   (no cachea agresivamente) — probar con un dominio propio que
   alterna IP pública/privada en respuestas DNS sucesivas y ver si el
   comportamiento del server cambia entre intentos.
2. Si hay ventana de carrera disponible (el filtro resuelve, valida,
   y *después* hace una request HTTP separada — no reusa el socket/IP
   ya resuelto), servir IP pública en la respuesta DNS que ve el
   validador y la IP interna en la que ve el cliente HTTP real. El
   timing exacto depende de la implementación — algunos frameworks
   resuelven DNS una sola vez y reusan la conexión (no vulnerable),
   otros resuelven en cada capa (validación + librería HTTP) por
   separado (vulnerable).
3. Si el servidor usa un connection pool/keep-alive, la ventana puede
   ser más angosta — probar también el caso donde el primer request
   "entrena" la conexión y un segundo request la reutiliza.

**Gate de evidencia**: igual que el resto del skill — callback OOB
recibido desde la IP interna, o data interna filtrada en la respuesta,
confirma el rebinding. Sin eso, "el filtro parece resolver DNS
dinámicamente" es observación, no confirmación.

No probado en lab ni target real — marcar como `confirmado` recién
cuando se verifique en un entorno controlado o contra el target real
con evidencia (gate de arriba), no asumir que funciona solo porque la
técnica es conocida.
