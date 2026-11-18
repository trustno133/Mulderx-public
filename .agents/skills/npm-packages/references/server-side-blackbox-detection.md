# Server-side prototype pollution — detección black-box sin identificar la dependencia

Cargar cuando el target expone un endpoint que acepta JSON (o cualquier
merge de input estructurado: form-urlencoded anidado, multipart con
campos anidados) y lo mergea de alguna forma en un objeto server-side
— **sin que haga falta tener package.json, bundle, ni saber qué
librería/versión está en juego**. Complementa `prototype-pollution-catalog.md`
(esa referencia asume que ya identificaste la dependencia vulnerable
por nombre+versión; esta asume que NO tenés esa visibilidad y vas a
ciegas contra el comportamiento HTTP). Para la variante **client-side**
(el mismo concepto pero corriendo en el navegador de la víctima, source
= URL, no request body), ver `xss/references/client-side-prototype-pollution.md`.

Caso real trabajado (lab PortSwigger "Privilege escalation via
server-side prototype pollution", Node.js + Express, sin código fuente
visible — resuelto 100% con `curl`, sin navegador. Ver
`targets/pswa-serverside-pp-privesc/leads.md` para el trazado completo).

## Señal de entrada — cuándo sospechar

- Cualquier endpoint que actualiza un perfil/config/preferencias y
  **devuelve el objeto actualizado en la respuesta** (patrón
  "echo-back" — común en REST APIs tipo `PATCH`/`POST` que responden
  con el recurso resultante). Es la superficie más fácil de confirmar
  porque no hace falta un side-channel: el propio response es la
  evidencia.
- El JS del cliente (si lo hay) **filtra explícitamente algún campo**
  antes de mostrarlo (`.filter(k => k !== 'algo')`,
  `delete obj.algo` antes de renderizar) — señal fuerte de que ese
  campo existe en la respuesta cruda y el frontend lo esconde a
  propósito. Revisar el JS de la página que consume el endpoint antes
  de asumir qué campos existen.
- Cualquier merge de config/opciones/settings de usuario sobre un
  objeto con valores por defecto (patrón `defaults + userInput`).

## Método — 3 pasos, un solo request cuando se puede

### 1. Probe de source — confirmar que el merge es vulnerable

Mandar el payload normal del endpoint MÁS una key `__proto__` (anidada,
JSON real — no hace falta bracket/dot notation como en las variantes
client-side, porque acá el body ya es un objeto JS deserializado, no
un string a parsear) con un valor canario:

```json
{"campo_normal_1": "...", "__proto__": {"canaryXYZ": "confirmado"}}
```

Si la respuesta refleja `canaryXYZ` (aunque no lo hayas pedido como
campo legítimo), el merge del lado del server itera propiedades
heredadas del prototype chain (`for...in`, o una función de deep-merge
sin guard de `__proto__`/`constructor`/`prototype`) — pollution
confirmada, sin necesidad de saber qué librería la causa.

Si el endpoint NO hace echo-back, alternativas para confirmar sin
side-channel visible: mandar el canario en un request, y en un
request SEPARADO golpear cualquier endpoint no relacionado que
debería fallar o comportarse distinto si `Object.prototype.canaryXYZ`
existe (timing, cambio de status code, aparición del campo en OTRA
respuesta que sí hace echo de algo).

### 2. Buscar el gadget — campos de autorización/config expuestos por el propio echo-back

El mismo request del paso 1 ya te muestra TODOS los campos del objeto
real que se está mergeando — no hace falta adivinar nombres.
Priorizar cualquier campo que suene a control de acceso o
comportamiento interno: `isAdmin`, `role`, `permissions`, `verified`,
`isPremium`, `debug`, `internal`, cualquier booleano que no
corresponda a lo que vos mandaste.

Si el campo existe y tiene un valor "no privilegiado" (`false`,
`"user"`, etc.), pollutearlo directo:
```json
{"campo_normal_1": "...", "__proto__": {"isAdmin": true}}
```
y confirmar en la MISMA respuesta que el valor cambió.

### 3. Confirmar persistencia global — no solo el objeto de esa respuesta

Paso que separa "pollution reflejada" de "pollution con impacto real":
`Object.prototype` en Node es **un singleton por proceso** — si el
merge realmente contaminó el prototype global (y no un objeto nuevo
aislado por request), el efecto tiene que verse en un request
COMPLETAMENTE SEPARADO, sin el payload de pollution:

```bash
# baseline ANTES de pollutear
curl --http1.1 -b cookies.txt "$BASE/admin"   # 401/403 esperado

# pollutear (paso 2)
curl --http1.1 -b cookies.txt -X POST "$BASE/endpoint-vulnerable" -d '{"__proto__":{"isAdmin":true}}'

# request SEPARADO, sin payload de pollution, misma sesión
curl --http1.1 -b cookies.txt "$BASE/admin"   # 200 si la pollution es global
```
Sin este paso, el finding es "pollution reflejada en un response" —
Informational. Con este paso, es escalada de privilegios confirmada
con impacto real (acceso a funcionalidad restringida, en vivo).

## Gotcha de infraestructura — no confundir con el bug

Algunos servers (visto en el lab de PortSwigger) mandan un header
`Keep-Alive: timeout=5` que rompe el parser HTTP/2 de curl:
```
curl: (92) Invalid HTTP header field was received
```
No es el target rechazando el payload — es curl fallando el parseo
del response por ese header. Fix: forzar `--http1.1` en todos los
requests contra el target. Si el body sale vacío o el comando corta
sin error claro, probar esto ANTES de asumir que el endpoint bloqueó
algo.

## Cuando NO hay reflejo — canario `json spaces` (detección no-destructiva)

Algunos endpoints mergean de forma vulnerable pero el código que arma
la respuesta enumera un set FIJO de campos (no itera todas las
propiedades del objeto contaminado) — el canario del paso 1 no
aparece en ningún lado, aunque el merge SÍ sea vulnerable. No asumir
"no vulnerable" solo por falta de reflejo — probar un side-channel que
no dependa de que la app te devuelva el campo.

**Técnica confirmada en vivo** (Node.js + Express): pollutear
`Object.prototype["json spaces"]` (nota: la key tiene un espacio
literal, va anidada bajo `__proto__` igual que cualquier otra):
```json
{"campo_normal": "...", "__proto__": {"json spaces": 10}}
```
Express lee `app.get('json spaces')` internamente para decidir la
indentación de `res.json()`. Si esa config nunca se seteó como
propiedad PROPIA de `app.settings` (default de la mayoría de apps),
la lectura sube al `Object.prototype` pollutado — CUALQUIER respuesta
JSON posterior de la app pasa de compacta a pretty-printed con el
espaciado que hayas inyectado. Cambio de comportamiento **medible,
reproducible y completamente no-destructivo** (no toca ningún campo
de negocio, no requiere restart del server) — ideal quando el
objetivo es solo confirmar la vulnerabilidad sin arriesgar romper el
target, o cuando el gadget de negocio (`isAdmin` y similares) no está
identificado todavía.

Confirmar persistencia igual que con cualquier gadget (paso 3): un
request separado, sin el payload, en la misma sesión, tiene que seguir
devolviendo JSON indentado.

Otras propiedades de config de framework con el mismo perfil (side
effect observable, no-destructivo, vale la pena probar si `json
spaces` no aplica porque el framework no es Express): cualquier
setting que controle FORMATO de output en vez de LÓGICA de negocio —
headers de respuesta, charset, paginación por default, orden de
campos.

## De detección a RCE — gadget de "task runner" / job registry

Patrón visto en apps con un panel admin que corre tareas de
mantenimiento por nombre (`{"tasks": ["db-cleanup", ...]}`, resuelto
contra un registry interno). Si el lookup de nombre de task no valida
con `hasOwnProperty` (usa acceso directo `registry[taskName]`), un
nombre de task **inventado** por vos, pollutado como key de
`Object.prototype`, se resuelve igual que uno real:

1. Pollutear `Object.prototype["<nombre-inventado>"] = {}` (objeto
   vacío) y correr ese task. Si el error pasa de "task no existe" a
   algo tipo `ERR_INVALID_ARG_TYPE` (Node) u otro error de tipo/
   argumento, confirma que el runner SÍ tomó tu objeto pollutado como
   definición real e intentó ejecutar algo con él — heurística barata
   para confirmar el gadget antes de saber el nombre exacto del campo.
2. Probar nombres de propiedad candidatos uno por uno (`command`,
   `cmd`, `path`, `script`, `exec`, `file`) hasta que el error
   desaparezca (`"success":true`) — ese es el campo que el runner pasa
   a una API de `child_process`.
3. Confirmado el campo, mandar comandos reales. Si corre vía
   `child_process.exec()` (no `execFile`), tenés shell completo:
   pipes, `;`, `$()`, redirects.

## Exfiltración sin OOB — el canal de error como side-channel

Cuando no hay Collaborator/webhook disponible (o el egress del target
está restringido a infra específica — visto en un lab real: `curl`
tirando `Could not resolve host` contra un webhook.site externo, la
red del contenedor solo permite salida hacia la infra de
Collaborator), no hace falta insistir con OOB si el endpoint devuelve
el error del comando fallido en la respuesta.

`child_process.exec()` en Node arma `error.message` como
`"Command failed: <cmd>\n" + stderr` cuando el comando sale con
código ≠ 0. Si la app devuelve ese `error.message` en el JSON de
respuesta (común — es el patrón de "error genérico" más fácil de
implementar), forzar que el comando querido mande su output a stderr
y falle:
```
<comando> >&2; exit 1
```
El resultado del comando vuelve directo en la respuesta HTTP de la
MISMA request — sin depender de que ningún servicio externo reciba
nada, sin polling, y funciona aunque el egress del target esté
totalmente bloqueado. Más simple y más confiable que armar un OOB
cuando la app ya te da un canal de vuelta.

## Qué mata el lead

- El merge usa `Object.create(null)` como base para el objeto
  destino, o pasa por una librería con guard explícito de
  `__proto__`/`constructor`/`prototype` (versión parcheada) — el
  canario no se refleja en el paso 1.
- El campo de gadget candidato (`isAdmin`, etc.) SÍ está como
  propiedad propia explícita en TODOS los objetos relevantes del
  código (no solo en el que hace echo-back) — shadow real, mismo
  criterio que las variantes client-side.
- Reflejo confirmado en el paso 1 pero sin persistencia en el paso 3 —
  indica que el objeto contaminado es local a esa request (ej. un
  `Object.create({})` fresco por request en vez de mutar
  `Object.prototype` real, o un framework que clona/congela el
  prototype global entre requests) — informational, no escalada.

## Severidad

Mismo criterio que el resto del catálogo: sin el paso 3 (persistencia
+ acceso real confirmado a algo restringido), Informational o P4
máximo. Con los 3 pasos: severidad según qué gadget se alcanzó — un
booleano de admin es Critical/P1 casi siempre: cualquier cuenta
autenticada sin privilegios escala a control total con un request
adicional, sin necesitar ninguna otra debilidad.
