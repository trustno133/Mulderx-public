---
name: xss-dom
description: Detecta y valida XSS DOM-based — todo el flujo pasa en
  JavaScript del cliente, nunca toca el server. Usar cuando hay un source
  tipo location.*, postMessage, respuesta de fetch/XHR, hash de URL o
  localStorage/sessionStorage que llega a un sink como innerHTML,
  document.write, eval, insertAdjacentHTML, o binding peligroso de un
  framework (dangerouslySetInnerHTML, v-html, [innerHTML]).
---

# XSS DOM-based

Trabajá sobre el caso concreto que dio el operador. Acá el análisis es
100% client-side: no hay request/response del server que importe, importa
el código JS real — source → sink dentro del bundle.

## Qué buscar

Source: `location.*`, datos de `postMessage`, respuesta de API vía
fetch/XHR, hash de URL, `localStorage`/`sessionStorage`. Sink:
`innerHTML`, `outerHTML`, `document.write`, `eval`, `insertAdjacentHTML`,
`.html()` de jQuery, `srcdoc`. Nunca toca el server — todo pasa en JS del
cliente.

| Sink | Source típico | Payload |
|---|---|---|
| `document.write(x)` | `location.hash` | `#<img src=x onerror=alert(1)>` |
| `eval(x)` | `location.search` | `?x=alert(1)` |
| `innerHTML = x` | `localStorage.getItem()` | inyectar vía localStorage write previo |
| `location.href = x` | `window.name` | `window.name = "javascript:alert(1)"` |
| `postMessage` listener | mensaje cross-origin | ejecutar desde página atacante |

Si el source es `postMessage`, cargar también `.claude/skills/postMessage/SKILL.md`
(validación de origin es parte del análisis, no solo el sink). Si el
sink recibe un objeto armado por un parser propio del bundle (no un
string plano), ver "prototype pollution" en Referencias abajo — puede
que el vector real sea contaminación de prototipo alimentando el sink, no
inyección directa de string.

## Análisis de JS — regla de fuente única

**Nunca leer archivos JS crudos directamente** (ni con `Read`, ni con
`cat`, ni descargando a `/tmp`). Si el js_analyzer ya corrió durante el
recon, usar su output en
`${BB_PIPELINE_DIR:-$HOME/.bb_pipeline}/<target>/js_analysis/<timestamp>/`.
Si necesitás contexto puntual de un offset o match específico, `grep`
con contexto limitado (±10 líneas). Si JXScout está activo, consultar
matches existentes antes de cualquier grep manual.

## Qué mata el lead

- `createTextNode`/`textContent` en el camino, o DOMPurify antes del sink.
- Gate de timing que no se cumple con el HTML/JS servido real.
- Trusted Types o CSP `strict-dynamic`+nonce bloqueando el sink
  específico — **verificar en vivo, no asumir por la sola cabecera.**
- Sink en código de vendor/SDK de terceros → probable known/dupe.
- Framework con binding estándar (sin `dangerouslySetInnerHTML`/`v-html`/
  innerHTML explícito) y sin bypass del binding — ver tabla de frameworks
  en `../xss/references/common-xss.md`.

## Severidad

Sin ejecución confirmada en el navegador real (no alcanza con leer el
código y decir "parece vulnerable") = Informational o P4 máximo. Ver
"Impact framing" en `../xss/references/common-xss.md` para la escalada
de PoC (cookie theft / token / CSRF token steal / acción state-changing)
y las reglas de `HttpOnly`/`SameSite` antes de elegir el vector de
impacto.

## Referencias condicionales

- Contexto de reflexión (tabla de escape), framework gotchas, impact
  framing, self-XSS encadenable: `../xss/references/common-xss.md`.
- Sink DOM-based alimentado por objeto armado por parser propio (no
  string plano): `../xss/references/client-side-prototype-pollution.md`.
- Source de `postMessage`: `.claude/skills/postMessage/SKILL.md`.
- Filtro/sanitizer observado bloqueando: `../xss/references/filter-probing.md`,
  luego `bypass-techniques.md` si hace falta una variante.
- JS ejecutado y catálogo insuficiente: `../xss/references/constructive-synthesis.md`.
- Catálogo de vectores por contexto exacto: `../xss/references/vector-catalog.md`.
