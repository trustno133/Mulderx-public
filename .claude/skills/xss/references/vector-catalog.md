# Vector catalog — selección de payloads a partir del filter map

Cargar después de `filter-probing.md`, cuando ya existe un filter map JSON
producido por probing. Este archivo NO caracteriza filtros — asume que ya
tenés el mapa y traduce ese mapa a un ranking de vectores candidatos del
catálogo PortSwigger.

Data: `references/portswigger-vectors.json` (157 vectores, extraídos del
PortSwigger XSS Cheat Sheet 2026 Edition de Gareth Heyes).

## Pipeline

```
filter-probing.md
    ↓ (produce filter map JSON)
vector-catalog.md      ←  este archivo
    ↓ (aplica matching + ranking)
top N candidates
    ↓ (usuario prueba con Burp/browser)
XSS confirmado o descartado
```

*Nota lateral: sin filter map, este archivo no sirve. No hardcodear "top 10 payloads que siempre funcionan" — eso es lo opuesto a la idea. Los payloads los elige el filter map, no la intuición.*

## Estructura del catálogo (JSON)

Cada vector tiene:

**Campos originales del cheat sheet:**
- `name` — nombre del evento o vector (ej `ontoggle`, `onbeforetoggle`)
- `description` — cuándo se dispara
- `tag_context` — tag sugerido por PortSwigger (`custom tags`, `body`, `a`, `img`, etc.)
- `payload` — el vector completo listo para inyectar
- `requires_user_interaction` — bool

**Campos derivados para matching:**
- `chars_used` — array de caracteres "interesantes" presentes en el payload (`<`, `>`, `"`, `'`, `=`, `(`, `)`, `` ` ``, `\`, `;`, `/`, `[`, `]`, `{`, `}`, `:`, `#`, `%`, `&`)
- `keywords_used` — array de keywords sensibles (`alert`, `prompt`, `eval`, `javascript:`, `data:`, `script`, `onerror`, etc.)
- `tag_base` — primer tag del payload en lowercase (`svg`, `iframe`, `xss`, `button`, etc.)
- `encoding_hints` — array de encodings presentes en el payload nativo (`html_entity_decimal`, `html_entity_hex`, `js_hex`, `js_unicode`, `url_encoded`)
- `features` — flags booleanos: `uses_backtick`, `uses_svg`, `uses_iframe`, `uses_script_tag`, `uses_data_uri`, `uses_javascript_uri`, `uses_srcdoc`, `uses_style`, `has_html_entities`, `payload_length`

Además hay dos secciones especiales fuera de event handlers:

- `content_type_injection_xss` — 12 payloads con content-types que bypasseán `X-Content-Type-Options: nosniff`. Usar solo si el sink es una response cuyo Content-Type controlás.
- `response_content_type_injection` — 5 vectores para content-type header injection. Muy nicho, casi nunca aplica.

## Reglas de matching — core

El input es el `candidates_filter` del filter map JSON. Ejemplo:

```json
"candidates_filter": {
  "exclude_chars_from_payload": ["<", ">"],
  "exclude_keywords_from_payload": ["alert", "eval", "onerror", "javascript"],
  "case_mixing_available": true,
  "encoding_available": ["html_entity_decimal", "html_entity_hex"],
  "preferred_events": ["ontoggle", "onauxclick"],
  "notes": [...]
}
```

**Algoritmo de matching (aplicar en orden):**

### Regla 1 — Descartar vectores con caracteres bloqueados sin bypass disponible

Para cada vector V del catálogo:

- Si `V.chars_used` contiene algún carácter en `exclude_chars_from_payload`
  Y ese carácter no puede resolverse con los `encoding_available` del
  filter map → **DESCARTAR**.

*Ejemplo:* filter map dice `<` está BLOCKED pero HTML entity hex llega
RAW y decodea a `<` (verificado en step 7f del probing). Entonces un
vector con `<svg onload=alert(1)>` NO se descarta — se marca para
transformar `<` → `&#x3C;` antes de sugerirlo.

*Ejemplo contrario:* filter map dice `<` está BLOCKED y ningún encoding
lo resuelve. Todos los vectores del catálogo salvo los raros
(`content_type_injection_xss`) están fuera — todos usan `<`. En ese
caso el output son cero candidatos y el mensaje al usuario es
"filtro cierra puerta HTML; posibles vías: content-type injection si
controlás Content-Type, DOM XSS del cliente, o filter tiene bug no
detectado por probing (rerun con más profundidad)".

### Regla 2 — Descartar por keywords bloqueadas

Para cada vector V que sobrevivió Regla 1:

- Si `V.keywords_used` contiene alguna keyword en
  `exclude_keywords_from_payload`:
  - Si `case_mixing_available` es `true` → **NO descartar, marcar para
    case-mix** (`alert` → `AlErT`).
  - Si no, y si el vector tiene una vía obvia de reemplazo (ej: el
    payload usa `alert(1)` y podemos sustituir por `print(1)` o
    `confirm(1)`) → **NO descartar, marcar para keyword swap**.
  - Si ninguna aplica → **DESCARTAR**.

*Nota lateral: `alert`, `prompt`, `confirm`, `print` son todas triviales de intercambiar. `eval`, `Function`, `setTimeout` no son intercambiables 1:1 — si el filter map bloquea `eval` sin case mixing disponible, los vectores que dependen de `eval` se caen.*

### Regla 3 — Descartar por contexto incompatible

El vector fue diseñado para HTML. Si el filter map dice
`context: "js_string_literal"` (canary reflejado dentro de `<script>`),
no tiene sentido sugerir vectores que empiezan con `<` — necesitás salir
del literal primero.

- Si `context` del filter map es `html_body` o `html_attribute` → todos los
  vectores del catálogo son compatibles en principio.
- Si es `js_string_literal` → filtrar SOLO vectores que puedan
  co-ejecutarse con salida de string (agregar prefix `';` o `";` en la
  sugerencia final). Vectores tipo `<svg>` requieren cierre de `</script>`
  antes, marcarlo en las notas.
- Si es `html_attribute_value` → filtrar vectores que puedan salir de
  atributo. Los que arrancan con `<` requieren cierre de comilla + `>`
  antes.
- Si es `url_context` (href/src) → solo vectores con `javascript:`,
  `data:`, o encodings equivalentes. La mayor parte del catálogo NO
  aplica.
- Si es `css_context` → catálogo casi no aplica; usar
  `references/bypass-techniques.md` sección "CSS injection" (fuera de
  este flujo).

### Regla 4 — Aplicar preferencias del probing

Si el filter map trae `preferred_events` (eventos que llegaron RAW en step
5 del probing) → los vectores cuyo `name` está en esa lista suben en el
ranking (ver "Ranking heurístico" más abajo).

## Ranking heurístico

Después de las 4 reglas de matching, los vectores sobrevivientes se
ordenan por score descendente. Score inicial = 0, aplicar cada modifier:

| Condición | Modifier |
|---|---|
| `V.name` en `preferred_events` del filter map | +50 |
| `V.requires_user_interaction == false` | +20 |
| `V.requires_user_interaction == true` y `context == html_body` | -10 |
| Vector no necesita ningún encoding para pasar el filter | +15 |
| Vector necesita 1 encoding disponible | +5 |
| Vector necesita 2+ transformaciones (encoding + keyword swap + case-mix) | -10 |
| `V.tag_base` es `xss` (tag custom, muy permisivo con blocklists de tag) | +10 |
| `V.tag_base` es `script`, `iframe`, `img` (tags clásicos, filtros los persiguen) | -15 |
| Payload length > 200 | -5 (más chances de que el WAF lo mire con más ganas) |
| Payload length < 60 | +5 |
| `V.features.uses_backtick == true` y backticks llegaron RAW en probing | +10 |
| `V.features.uses_data_uri == true` y `data:` está en `exclude_keywords` sin bypass | -20 |

*Nota lateral: estos números son arbitrarios pero relativos entre sí. Lo importante es el orden, no el valor absoluto. Si querés recalibrar después de usar el pipeline unas veces, cambiá los pesos.*

## Output — top N candidates

Devolver los top 5 (default) o top N (configurable) con este formato:

```json
{
  "candidates": [
    {
      "rank": 1,
      "score": 85,
      "vector_name": "ontoggle",
      "payload_original": "<details open ontoggle=alert(1)>",
      "payload_transformed": "<details open ontoggle=AlErT(1)>",
      "transformations_applied": [
        "case_mix: alert → AlErT"
      ],
      "sustaining_probes": [
        "step 5: ontoggle llegó RAW",
        "step 7a: AlErT llegó RAW (filter sin flag i)"
      ],
      "requires_user_interaction": false,
      "browsers_note": "Chrome, Firefox, Safari — <details> universal",
      "gotchas": [
        "verificar que <details> no esté en blocklist de tags"
      ]
    },
    {
      "rank": 2,
      "score": 68,
      "vector_name": "onauxclick",
      "payload_original": "<a onauxclick=alert(1)>click me</a>",
      "payload_transformed": "<a onauxclick=AlErT(1)>click me</a>",
      "transformations_applied": [
        "case_mix: alert → AlErT"
      ],
      "sustaining_probes": [
        "step 5: onauxclick llegó RAW",
        "step 7a: case mixing viable"
      ],
      "requires_user_interaction": true,
      "browsers_note": "requiere click con botón medio del mouse",
      "gotchas": [
        "auxclick es interacción específica, no vale para stored contra víctima pasiva"
      ]
    }
  ],
  "candidates_dropped_reason_summary": {
    "excluded_char_no_bypass": 87,
    "excluded_keyword_no_bypass": 34,
    "excluded_context_mismatch": 12,
    "total_evaluated": 140
  },
  "recommendation": "Probar rank 1 primero. Confirmar ejecución en Chrome vía Burp Repeater o browser real. Si rank 1 falla en confirmación pero el probe RAW se mantiene, revisar la variante ranked 2."
}
```

**Notas por candidato:**
- `sustaining_probes` es el link causal: qué del filter map hace que este
  vector sea viable. Sin este campo, el usuario no sabe por qué le
  sugerimos esto.
- `transformations_applied` es la lista concreta de qué se cambió del
  payload original. Auditable.
- `gotchas` son los caveats que el catálogo original no muestra
  (compatibilidad browser real, requerimientos de interacción).

## Casos especiales y descartes tempranos

### Content-type injection

Si el filter map indica que el sink es una response donde el Content-Type
es controlable (raro, aplica cuando hay un endpoint tipo `/proxy?url=` o
similar), el catálogo `content_type_injection_xss` se activa aparte.
Reglas de matching normales no aplican — el score se calcula solo por
compatibilidad browser + longitud.

### Response content-type injection

Solo aplica cuando podés inyectar en el header `Content-Type` de la
response del servidor. Casi nunca ocurre en programas reales. Si el
usuario reporta este contexto, sugerir los 5 vectores como están y
marcar como "hallazgo raro, revalidar contexto".

### Impossible labs

La sección "Impossible labs" del PDF (SVG use, animate + use, onbeforescript
execute, onafterscriptexecute) son vectores que quiebran assumptions
comunes. NO incluidos en el JSON principal por ahora — son de nicho y
requieren contexto muy específico. Si el pipeline no encuentra
candidatos con las reglas 1-4 y `context == html_body` con `<` RAW,
considerar cargar estos manualmente. Documentar el caso en
`wild-signals.md` si aplican.

## Actualización del catálogo

PortSwigger actualiza el cheat sheet cada X meses. Para regenerar el JSON:

1. Descargar el PDF actualizado desde
   `https://portswigger.net/web-security/cross-site-scripting/cheat-sheet`
2. Ejecutar el parser (`references/parse_vectors.py`, versionado en el
   repo del skill) sobre el nuevo PDF.
3. Comparar el JSON viejo vs nuevo (`diff` sobre nombres de vectores) —
   los agregados nuevos son los que hay que revisar manualmente porque
   pueden requerir nuevas keywords o encodings en el enrichment.
4. Actualizar `last_updated_source` en el meta del JSON.

*Nota lateral: no depender del parser 100%. El PDF cambia formato de vez en cuando y el parser puede fallar silenciosamente. Contar los vectores antes y después es la sanity check mínima.*

## No hacer

- Nunca sugerir un candidato sin `sustaining_probes` — si no hay probe
  del filter map que lo sostenga, es sugerencia ciega, no matching.
- Nunca inflar el ranking artificialmente ("este payload es cool, va al
  top"). El score se calcula por reglas, punto.
- Nunca devolver "top 10" fijo — devolver todos los que scorearon > 0, o
  los top N configurados, cortando cuando el score cae bajo umbral
  (default: si score < 10, no vale la pena mostrarlo).
- Nunca reportar XSS por sugerir un candidato. La confirmación es del
  usuario con Burp/browser. El pipeline solo prioriza qué probar.
- Nunca correr el pipeline sin filter map completo. Si el probing se
  cortó a mitad (por ban, kill signal), el filter map está incompleto y
  el ranking va a ser malo — mejor rerun del probing.

## Handoff al usuario

Cuando el catálogo devuelve candidates:

1. Mostrar el top 5 con payload transformado listo para copy-paste
2. Un resumen en criollo: "de 140 vectores, 87 no aplican por `<`
   bloqueado sin bypass, 34 por keywords bloqueadas, quedan 19
   viables. Top 5 rankeados por probes del filter map."
3. Recomendación concreta: "abrir Burp Repeater, tirar rank 1, si el
   response muestra reflection sin bloqueo → cargar en browser real y
   verificar ejecución. Si el rank 1 bloquea a pesar del score, el
   probing tiene un blind spot: rerun step X con más profundidad."
4. Guardar el JSON de candidates en `targets/<program>/xss_candidates_
   <timestamp>.json` para poder auditar después qué se sugirió y qué
   confirmó ejecución.
