# Patrones de búsqueda local para JavaScript

Usá estos patrones solo sobre archivos ya disponibles y autorizados. Son
semillas para localizar código, no reglas de confirmación. Si ya hay output del
analizador local, preferilo y abrí esta referencia solo para una búsqueda
puntual que agregue cobertura.

Ejemplo con ripgrep:

```sh
rg -n -g '*.js' -g '*.mjs' -g '*.cjs' -g '*.jsx' -g '*.ts' -g '*.tsx' 'PATTERN' path/to/artifacts
```

Adaptá el patrón al motor de regex disponible. Revisá el contexto de cada match,
el módulo al que pertenece y los callers; una coincidencia textual no prueba
autoría, reachability ni impacto.

| Superficie | Patrón inicial | Qué revisar después |
|---|---|---|
| Rutas API | `/(?:api|graphql|auth|admin|internal|v[0-9]+)(?:/|\b)` | Base URL, método, parámetros, caller y si la ruta es real o una cadena de documentación |
| Clientes HTTP | `\bfetch\s*\(|\baxios\.(?:get|post|put|patch|delete|request)\s*\(|XMLHttpRequest` | URL construida, headers, body, IDs y controles de auth |
| Operaciones GraphQL | `\b(?:query|mutation|subscription)\s+\w+|\bgql\b` | Variables, campos, mutaciones, endpoint observado y autorización del resolver |
| WebSocket | `\bnew\s+WebSocket\s*\(|\bwss?://|\bsocket\.io\b|\bsockjs\b|\.(?:send|emit)\s*\(` | Protocolo y esquema de mensajes; no inferir controles server-side |
| Fuentes del navegador | `location\.(?:search|hash|href|pathname)|document\.(?:referrer|URL|documentURI|baseURI)|window\.name|history\.state|event\.data` | Quién puede controlar el valor y transformaciones antes del uso |
| Sinks DOM/ejecución | `(?:innerHTML|outerHTML|srcdoc)\s*=|insertAdjacentHTML\s*\(|document\.write(?:ln)?\s*\(|\beval\s*\(|new\s+Function\s*\(` | Fuente alcanzable, sanitización, encoding, wrapper y contexto de ejecución |
| Handlers de mensajes | `addEventListener\s*\(|onmessage\s*=|\.postMessage\s*\(|event\.origin|event\.data` | Listener concreto, origen esperado, validación del mensaje y sink posterior |
| Storage/auth/UI | `(?:localStorage|sessionStorage)\.(?:getItem|setItem)|document\.cookie|Authorization|Bearer|(?:isAdmin|isStaff|hasPermission|canAccess|isAuthenticated)` | Tipo de dato, motivo de almacenamiento, transporte y validación server-side |
| Prototype pollution | `__proto__|constructor\.prototype|Object\.prototype|\b(?:deepmerge|merge|extend)\s*\(` | Origen de las claves, implementación concreta del merge y gadget alcanzable |
| PEM privado | `-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----` | Registrar solo ubicación y tipo; no copiar el material al output |
| Identificadores de proveedor | `AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}` | El identificador AWS no es una clave secreta por sí solo; una Google API key puede ser pública/restringida |
| Asignaciones sensibles | `(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)\s*[:=]\s*["']` | Revisar el valor localmente, placeholders, uso y restricciones; no incluir el valor en handoff |
| URI con credencial | `(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis)://[^'"\s]+:[^'"\s]+@` | Verificar si contiene credenciales reales y alcanzables sin imprimirlas |
| Callbacks JSONP | `callback|jsonp|document\.createElement\s*\(\s*["']script` | Seguir el valor hasta `script.src` y confirmar aparte cómo responde el endpoint |

## Manejo de coincidencias sensibles

- Para ubicar archivos con posibles secretos, empezá por `rg -l` para evitar
  volcar valores completos en la consola. Si necesitás inspeccionar una línea,
  mantené el valor redactado en notas, handoffs y reportes.
- Prefijos de tokens y longitudes cambian; esta lista no es exhaustiva. Un
  nombre de campo, formato parecido a JWT, clave pública, test key o valor de
  ejemplo no demuestra credencial utilizable.
- Derivá candidatos de secretos a `exposed-secrets`; validá alcance y uso sin
  registrar el secreto en `targets/`, prompts, logs ni reportes.
- No ejecutes pruebas activas a partir de un match. La validación de cada clase
  sigue requiriendo scope, autorización y su skill especializada.
