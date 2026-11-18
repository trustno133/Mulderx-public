# Constructive synthesis — construir payload cuando el catálogo no alcanza

Cargar cuando `vector-catalog.md` devuelve 0 candidatos viables **y** el
contexto es JS ejecutado directamente (URI `javascript:`, sink `eval`,
handler inline, template de framework) — no HTML markup simple. Para
markup simple sin candidatos, la respuesta correcta sigue siendo "cerrar
con evidencia", no forzar con esto.

## Principio

`vector-catalog.md` selecciona entre payloads conocidos. Este archivo NO
selecciona — construye, razonando sobre primitivas del lenguaje que
sobreviven al filter map, no sobre payloads pre-armados. Ningún catálogo
puede anticipar la combinación exacta de restricciones de un filtro
específico — pero el lenguaje JS tiene un set finito de primitivas
alternativas para cada restricción típica, y esas sí son enumerables.

**Costo:** esto gasta tokens de razonamiento, no requests HTTP. Es
más barato en tráfico que iterar a ciegas (evita el patrón "80k tokens
de curl por prueba y error"), pero exige construir la cadena analíticamente
antes de tirar la primera request de verificación — no antes de la
segunda o la décima.

## Protocolo — en orden, no saltear pasos

### 1 — Definir el objetivo mínimo de ejecución

No "conseguir el payload completo" — el objetivo atómico. Casi siempre:
lograr que ALGUNA función controlada por vos se invoque con ALGÚN
argumento controlado por vos. Todo lo demás (qué función, qué mensaje)
es secundario a lograr la invocación misma.

### 2 — Listar, del filter map, qué construcciones están cerradas

No caracteres sueltos — **construcciones sintácticas**:
- ¿Invocación directa de función bloqueada? (`(`/`)` bloqueados)
- ¿Espacio bloqueado?
- ¿Comillas bloqueadas? (afecta cómo armás strings)
- ¿Keywords específicas bloqueadas? (`eval`, `Function`, `alert` mismo)
- ¿Punto bloqueado? (afecta acceso a propiedades)

### 3 — Por cada construcción cerrada, elegir una primitiva alternativa

Tabla de alternativas conocidas — no son payloads, son **mecanismos**:

| Necesitás... | Si está bloqueado... | Alternativa |
|---|---|---|
| Invocar una función | `(` `)` | Tagged template: `` fn`arg` `` (llama a `fn` con el array de partes del template). Solo sirve si podés aceptar que el argumento venga como array de strings, no como valor arbitrario. |
| Invocar una función | `(` `)`, y necesitás un argumento arbitrario | Forzar invocación implícita via coerción: pisar `toString`/`valueOf` de un objeto y forzar conversión (`obj+''`, `` `${obj}` ``, comparación `==`). El motor invoca tu función sin que el payload tenga `(` `)` de invocación directa. |
| Invocar una función | `(` `)` | Getter: `Object.defineProperty` o un objeto literal con `get x(){...}` — leer la propiedad dispara el código, sin `()`. Puede requerir `Object.defineProperty(` que sí tiene parens — solo sirve si esa keyword puntual no está bloqueada. |
| Invocar una función | `(` `)` | Callback implícito: métodos que reciben función y la invocan solos — `[].map(fn)`, `''.replace(/x/,fn)`, `[].sort(fn)` — mismo problema, necesitás parens para pasar el callback salvo que armes el array/string por otro medio. |
| Espacio | bloqueado | `/**/` (comentario vacío) en cualquier punto donde JS acepte whitespace. Salto de línea literal si el input lo preserva. Tab (`\t`) si no se normaliza. |
| Statement que no es expresión (`throw`, `if`, `for`) | necesitás usarlo donde solo se acepta expresión | Envolver en arrow function: `` x=()=>{throw 1} `` convierte el bloque en algo asignable/invocable. |
| Comillas para strings | bloqueadas | Template literals sin interpolación (`` `texto` `` — ojo, sigue siendo un tipo de comilla, puede estar igual de bloqueado). Regex literal + `.source`: `/texto/.source`. `String.fromCharCode(...)` con códigos numéricos (sin comillas en absoluto). |
| Acceso a propiedad con punto | bloqueado | Bracket notation: `obj['prop']` — pero esto necesita comillas para el string `'prop'`, combinar con alternativa de comillas si también están bloqueadas. |
| Keyword bloqueada como string literal (`eval`, `alert`) | bloqueada | Reconstruir en runtime sin que el string aparezca completo en el payload: destructuring por índices, concatenación de fragmentos que individualmente no matchean la keyword. Ver bypass-techniques.md, "ofuscación de keywords vía destructuring dinámico". |
| Ejecutar código con excepción como vector | — | `onerror` como exception handler: forzar un `throw` (envuelto en arrow function si hace falta) asigna el control a `onerror`, que podés haber pisado con la función que querés ejecutar. |

Esta tabla no es exhaustiva — es el punto de partida. Si ninguna alcanza,
pensar en primitivas menos comunes: `Proxy` traps (`get`, `has`,
`deleteProperty` disparan código sin invocación explícita), generadores
(`function*`), `Symbol.toPrimitive` (control total sobre la coerción,
más flexible que solo `toString`).

### 4 — Componer la cadena

Encadenar las alternativas elegidas en el paso 3. Cada alternativa puede
introducir NUEVOS caracteres que hay que volver a chequear contra el
filter map — es iterativo: elegís una alternativa, verificás que no
reintroduce algo bloqueado, si lo hace, buscás otra alternativa para ESE
sub-problema.

### 5 — Verificar la composición contra el filter map completo, en la cabeza, antes de la primera request

Repasar carácter por carácter la cadena final contra la tabla de outcomes
del filter map (BLOCKED/SANITIZED/ENCODED/RAW). Si algún carácter de la
cadena está BLOCKED según el filter map, hay una inconsistencia — no
mandar la request todavía, resolver esa inconsistencia primero.

### 6 — Recién ahí, una request de verificación

Una, no veinte. Si falla, el fallo puntual (qué carácter rebotó, qué
error tiró el motor si hay consola) informa qué alternativa de la tabla
falló — no volver a probar variantes al azar, volver al paso 3 con la
información nueva.

## Cuándo esto NO aplica

- Contexto HTML markup simple sin ejecución de código JS de por medio —
  ahí el catálogo (`vector-catalog.md`) es la herramienta correcta, no
  esto. Construir código a mano para algo que un vector conocido ya
  resuelve es esfuerzo desperdiciado.
- Cuando el filter map todavía no está completo — sin saber qué está
  bloqueado, no hay nada que sintetizar. Completar `filter-probing.md`
  primero.
- CSTI (Angular/Vue sandbox escape) — comparte el espíritu de "construir
  en vez de seleccionar", pero las primitivas son del sandbox del
  framework, no del lenguaje JS puro. Fuera de alcance de este archivo,
  ver nota en `bypass-techniques.md` sobre CSTI necesitando metodología
  propia.

## Ejemplo de referencia (retrospectivo, no inventado en el momento)

Filtro bloqueaba: espacio, y evidentemente ciertos caracteres de
invocación directa en cierto contexto. La solución documentada de
PortSwigger para un lab con estas restricciones compuso:

1. Objetivo: invocar `alert` con un argumento.
2. `(` `)` de invocación directa bloqueados en el punto donde se
   necesitaba pasar el control a `alert` — resuelto asignando `alert` al
   handler `onerror` (la invocación la hace el motor al disparar la
   excepción, no el payload).
3. `throw` es statement, no expresión — resuelto envolviendo en arrow
   function (`x=()=>{throw ...}`).
4. Esa arrow function necesitaba invocarse sin agregar más invocación
   directa — resuelto pisando `toString` de `window` y forzando
   coerción (`window+''`).
5. Espacio bloqueado en el punto de unión — resuelto con `/**/`.

Ningún paso individual es exótico — la dificultad es la composición de
varios a la vez. Este es el nivel de razonamiento que el protocolo busca
reproducir analíticamente, no el catálogo de vectores.

## Trampa específica de sink `javascript:` URL — percent-decode antes de eval

El filter map que arma `filter-probing.md` mide qué sobrevive en la
**reflexión HTTP** (lo que devuelve el server, visto con curl/Burp Repeater
sin navegador). En un sink `javascript:` URL eso NO es el filter map final:
el HTML spec define que, al navegar a una URL `javascript:`, el navegador
hace **percent-decode del string completo** antes de tratarlo como código
JS (paso "javascript: URL" del algoritmo de navegación). Esto pasa en el
momento del click, después de cualquier request HTTP — curl nunca lo ve.

Consecuencia práctica: si el filtro del server responde a un carácter
peligroso (`=`, `'`, `<`, `>`, `;`, `+`, `&`, `:`, etc.) **encodeándolo a
`%XX`** en vez de eliminarlo, esa defensa es un no-op en este sink
específico — el navegador lo decodea de vuelta antes de ejecutar. Un
`%3d` que en la respuesta HTTP parece inerte se convierte en `=` real al
click. Lo único que sí frena de verdad es la eliminación literal del
carácter (regex que lo borra, no que lo encodea) — ahí no queda nada que
decodear.

Antes de concluir "`X` está bloqueado" en un sink `javascript:` a partir
de curl, distinguir explícitamente: ¿el carácter fue ELIMINADO (muerto de
verdad) o solo ENCODEADO a `%XX` (probablemente vivo, verificar con click
real o al menos con el algoritmo de navegación en mente antes de cerrar
el lead). Caso real: lab "Reflected XSS in a JavaScript URL with some
characters blocked" — el filtro encodeaba `=` `'` `<` `>` `+` `:` `;` `&`
`?` `@` `#` a `%XX` y solo eliminaba `( ) \` \ [ ] %`. La conclusión
correcta era que solo esos 6 caracteres estaban realmente bloqueados —
tratar los encodeados como bloqueados llevó a una síntesis fallida
(descartar `onerror=alert` como inviable) hasta verificar con click real.

## Nota de honestidad

Este protocolo no garantiza encontrar solución en todos los casos —
algunos filtros son restrictivos al punto de no tener bypass viable con
las primitivas conocidas (y ahí la respuesta correcta sigue siendo
cerrar con evidencia, no forzar). Lo que sí cambia es el modo de
trabajo: de prueba-y-error empírico caro en requests, a construcción
razonada con verificación puntual — más rápido, más barato, y más
transferible de un filtro a otro que memorizar payloads sueltos.
