---
name: js-static-analysis
description: Review supplied or already acquired application JavaScript, bundles, and source maps for API surfaces including GraphQL and WebSocket, client-side security flows, authentication, storage, and concrete source-to-sink leads. Use for static code review, not new-domain recon or live validation.
---

# Análisis estático de JavaScript de aplicación

Usá esta skill cuando el operador pide revisar bundles, módulos, source maps o
resultados de un analizador JavaScript que ya están disponibles. El objetivo es
armar un mapa de flujos verificable y leads concretos para el especialista
correspondiente; una coincidencia de patrón no es un hallazgo.

## Alcance y límites

- Trabajá solo con archivos suministrados o adquiridos previamente dentro del
  scope autorizado. No descargues bundles, enumeres rutas ni consultes el target
  desde esta skill. Para adquisición o recon nuevo, usá `domain-recon` o
  `wayback-js-recon` según el pedido y la autorización.
- No ejecutes el JavaScript del target, dependencias, builds ni payloads. La
  validación dinámica requiere una tarea y autorización separadas contra el
  target real.
- No leas credenciales, cookies ni tokens del operador. Si un artefacto contiene
  un valor sensible, registrá solo su tipo, ubicación redactada y posible
  alcance; seguí `exposed-secrets` para evaluar el lead sin copiar el valor.
- Para una revisión estática amplia, conservá las etapas MAP → TRACE → REVIEW de
  `sast-methodology` y sus handoffs. Esta skill aporta criterios específicos
  para JavaScript; no reemplaza esa secuencia.

## Método

1. **Fijá procedencia y cobertura.** Registrá nombre y hash del archivo cuando
   estén disponibles, origen declarado, fecha y si parece código propio,
   vendor, generado o minificado. Separá archivos analizados de archivos
   ausentes; no presentes cobertura parcial como completa.
2. **Priorizá código de aplicación.** Confirmá las señales de vendor contra el
   archivo y su contexto. Bundles mixtos pueden combinar módulos propios y
   librerías; una marca `is_vendor: false`, el nombre del archivo o un score no
   prueban autoría ni reachability.
3. **Mapeá entradas y operaciones relevantes.** Buscá los flujos que existan
   en el material: URL (`search`, `hash`, rutas), formularios y eventos,
   `postMessage`, `window.name`, respuestas de API, almacenamiento del
   navegador y datos entre frames. Relacionalos con sinks, llamadas de red,
   navegación, cambios de estado y controles de autorización del cliente.
4. **Trazá solo leads concretos.** Para cada uno, seguí el mismo dato desde la
   fuente hasta el efecto: funciones y llamadas intermedias, encoding o
   sanitización, validaciones, guardas, wrappers, callers y condiciones de
   ejecución. Citá archivo y línea; en bundles de una línea, usá offset y un
   fragmento acotado que permita localizarlo.
5. **Buscá contraevidencia.** Revisá si el valor es constante, si el flujo está
   muerto o solo en tests, si una API segura transforma el dato, si una guarda
   central cubre al caller y si el comportamiento depende de configuración o
   código que no está disponible. Anotá qué parte no pudo verificarse.
6. **Enrutá por la clase observada.** Entregá cada lead accionable al
   especialista de vulnerabilidad correspondiente. No conviertas el inventario
   de endpoints en una campaña activa ni infieras impacto del nombre de una
   ruta o campo.

## Superficies para revisar

Priorizá las que estén respaldadas por el código observado; no marques una
clase como ausente solo porque un patrón no apareció:

- **DOM y ejecución:** `innerHTML`, `outerHTML`, `insertAdjacentHTML`,
  `document.write`, `eval`, `Function`, `srcdoc` y bindings explícitos del
  framework. Seguí al especialista `xss_specialist` solo si hay una fuente y un
  sink concretos; un sink aislado no prueba XSS.
- **Mensajes entre ventanas:** listeners `message`, validación de `origin`,
  estructura y validación de `event.data`, reenvíos y sinks alcanzables. Handoff
  a `postmessage_specialist`.
- **Navegación y URLs:** asignaciones a `location`, `location.replace`,
  `window.open`, callbacks y parámetros controlables. El código cliente puede
  señalar un lead de redirect, pero no demuestra impacto por sí solo; handoff a
  `open_redirect_specialist` o `oauth_specialist` si pertenece a OAuth/OIDC.
- **Identidad y API:** endpoints, métodos, IDs de objetos, campos de tenant/rol,
  headers y tokens, refresh/logout, decisiones de UI y controles locales.
  Ocultar un botón o enviar un ID no prueba un bypass server-side. Enrutá
  señales concretas a IDOR, lógica de negocio, auth bypass u OAuth según el
  flujo.
- **GraphQL:** operaciones y documentos embebidos, nombres de query/mutation,
  campos, variables, IDs y headers de autenticación. Un documento encontrado en
  el bundle no demuestra que el endpoint lo acepte ni que un resolver carezca de
  autorización. Si hay una API GraphQL observada, handoff a
  `graphql_specialist`; los leads de ownership pasan a IDOR y los de workflow a
  lógica de negocio.
- **JSONP y callbacks:** parámetros `callback`/`jsonp` y creación de `<script>`
  con `src` construido dinámicamente. Correlacioná callback, fuente controlable
  y contexto ejecutable; el nombre del parámetro no demuestra XSS ni lectura de
  datos. Handoff a XSS o disclosure según el efecto que se pueda demostrar.
- **WebSocket:** URLs, subprotocolos, transporte de credenciales, estructura de
  mensajes entrantes/salientes y validaciones del cliente. El código cliente no
  demuestra autorización server-side ni seguridad del handshake. Handoff a
  `websocket_specialist` para impacto de mensajes o a `cswsh_specialist` si hay
  una señal concreta de handshake cookie-authenticated y control de `Origin`.
- **Browser storage:** lectura/escritura de `localStorage`, `sessionStorage`,
  IndexedDB o cookies accesibles desde JS, con su propósito y exposición.
  Handoff de datos de auth o personales a `web_storage_specialist`. El código
  `document.cookie` no permite establecer atributos `HttpOnly` y no muestra por
  sí solo los headers `Set-Cookie` del servidor.
- **Objetos y configuración:** merges recursivos, claves controladas como
  `__proto__`/`constructor`, opciones de librería, carga dinámica de módulos y
  plantillas. Para un flujo de contaminación de prototipo, handoff a
  `prototype_pollution_specialist`.
- **Dependencias y valores sensibles:** identificá componente y versión con
  evidencia antes del handoff a `npm_packages_specialist`; una versión o patrón
  de scanner no prueba reachability. Secretos potenciales van a
  `exposed_secrets_specialist`, sin reproducirlos en el informe.

Las políticas CSP/CORS, autorización server-side y comportamiento de endpoints
no se confirman desde un bundle. CSP suele requerir la respuesta HTTP o el HTML;
registrá qué artefacto se revisó y qué evidencia falta.

## Analizadores y bundles grandes

### Ejecución inicial y control de cobertura

- Cuando ya haya un bundle de aplicación local y el repositorio incluya
  `scripts/js_analyzer_v4_8.py`, ejecutá el analyzer sobre ese archivo al
  comienzo de MAP. Reutilizá un JSON existente solo si su `sha256` coincide
  con el bundle actual. Hacelo offline: no inicies `bb_pipeline.py`, no
  descargues assets desde esta skill y no sobrescribas un reporte existente.
- Si el JSON de salida derivado del nombre del bundle ya existe con otro hash,
  ejecutá sin `--json` y conservá un resumen del stdout, o usá una copia local
  con nombre único dentro del scratch del mismo análisis para producir un JSON
  separado.
- Registrá versión, hash, modo (`full` o `--app-only`) y salida. Si el analyzer
  falla, falta o supera el timeout, anotá ese bloqueo y seguí con MAP estático;
  no presentes un output viejo como si correspondiera al archivo actual.
- El inventario del analyzer no acredita cobertura completa. Contrastá sus
  rutas con la configuración real del router y sus endpoints con los clientes
  HTTP de la aplicación. En bundles Angular, localizá la tabla de rutas
  (`path`, `component`, `children` o `loadChildren`) y conectá cada ruta con su
  componente; no aceptes `routes: ["/"]` como cobertura suficiente si el
  bundle contiene rutas de aplicación.
- Para cada llamada de red, reconstruí método, `baseUrl` + sufijo, query/body,
  headers y caller. Marcá cada operación como **definición solamente** o
  **alcanzable desde ruta/acción**. Un endpoint genérico como `./api` no
  sustituye la ruta resuelta ni permite inferir autorización.
- No cierres como `DESCARTADO` porque falte backend, respuesta o permiso de
  prueba. Conservá el lead como `CANDIDATO` si hay un flujo concreto pero falta
  confirmar el servidor; usá `BLOQUEADO` cuando la validación esté impedida y
  anotá el dato exacto que falta. Reservá el descarte para contraevidencia que
  refute esa hipótesis.

Si ya existe output de `js_analyzer` u otro analizador local, usalo para
priorizar endpoints, sinks, storage, auth y flujos candidatos. Tratá todos los
scores, labels de vendor, taint flows y secretos detectados como heurísticas.
Corroborá cada lead en el código de aplicación, sus callers y controles.

Si no hay output de analizador y una búsqueda puntual ayuda, consultá
[references/search-patterns.md](references/search-patterns.md). Cargá esa
referencia solo para la búsqueda local que necesites; sus patrones son pistas,
no detectores de vulnerabilidades.

Si el archivo `.map` o su contenido `sourcesContent` ya está disponible,
correlacionalo con el bundle para recuperar nombres, módulos y líneas fuente.
No descargues una URL `sourceMappingURL` desde esta skill. La presencia del mapa
por sí sola no demuestra exposición de información sensible: evaluá qué datos
concretos agrega frente al JavaScript ya servido y si contienen material
privado o secretos válidos; estos últimos van a `exposed-secrets` con el valor
redactado.

En archivos minificados, preferí coincidencias puntuales con contexto limitado,
offsets o source maps ya disponibles. No vuelques un bundle entero si un
fragmento localizado alcanza. No instales herramientas ni actualices
dependencias como parte de esta revisión.

## Handoff

Por lead, entregá:

```text
Archivo/origen y cobertura:
Entrada y actor que puede controlarla:
Flujo y transformaciones (archivo:línea u offset):
Sink, request o decisión afectada:
Validaciones y contraevidencia:
Reachability demostrada / inferida / desconocida:
Impacto posible y evidencia que falta:
Especialista siguiente:
Estado: CANDIDATO | DESCARTADO | BLOQUEADO
Motivo del descarte o bloqueo:
```

El análisis estático produce como máximo un candidato. No registres un finding
confirmado sin prueba de impacto, evidencia reproducible y el gate Q1–Q3 de
`AGENTS.md`.
