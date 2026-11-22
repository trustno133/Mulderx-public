---
name: discoparameters
description: >
  Deep recon de parámetros no documentados sobre endpoints ya confirmados.
  Usar cuando ya existe superficie mapeada (URLs/endpoints válidos, con o sin
  JS parseado) y se busca ampliar el ataque descubriendo parámetros ocultos
  en GET/POST/JSON, headers y cookies. NO usar para descubrir endpoints
  nuevos (eso es trabajo de recon/subdomain enum) ni para explotar — este
  skill solo entrega evidencia cruda de comportamiento por parámetro.
---

# discoparameters

## Cuándo se dispara
- Hay una lista de endpoints confirmados (200/401/403 válidos, no 404).
- El objetivo es superficie de ataque adicional vía parámetros no
  documentados (query, body, JSON, headers, cookies).
- Opcional pero recomendado: hay JS ya parseado (jxscout) del mismo target,
  para cruzar params "vistos en código" vs "detectados por fuzzing".

No se dispara si:
- Todavía no hay endpoints confirmados (correr recon primero).
- El pedido es explotar un param ya conocido (eso es otro skill).

## Inputs esperados
- `targets`: lista de URLs/endpoints confirmados.
- `js_params` (opcional): lista de params extraídos del JS por jxscout, si existe.
- `scope_notes` (opcional): headers de auth necesarios, rate limit conocido, WAF presente.

## Pipeline

### Fase 0 — Preparación
- Verificar que cada target responde antes de fuzzear (evitar perder tiempo en dead endpoints).
- Confirmar autorización activa para cada endpoint y método, y que el host esté dentro del scope exacto.
- Detener la vía ante 429, CAPTCHA/challenge, bloqueo, degradación o 5xx sostenidos; no evadir rate limits ni controles del WAF.
- Si hay `js_params`, guardarlos aparte para el cruce en Fase 2.
- Usar `MULDERX_PARAM_WORDLIST` para x8; por defecto apunta al archivo `Discovery/Web-Content/burp-parameter-names.txt` bajo `SECLISTS_PATH`.

### Fase 1 — Discovery secuencial
- Primero `arjun -u <url> --stable -m GET,POST,JSON` (wordlist propia de Arjun, sin reemplazar).
- Ejecutar x8 después, solo si Arjun o el análisis de JS dejan una pregunta concreta: `x8 -u <url> -w "$MULDERX_PARAM_WORDLIST" -W 1 -d 100`.
- Para descubrir nombres de headers/cookies, usar el modo `--headers` de x8 con el mismo wordlist y un endpoint autorizado.
- Timeout por target: si excede el límite, marcar `skip - revisar manual` y seguir con el resto del batch (no bloquear todo por un endpoint lento).

### Fase 2 — Normalización y cruce
- Unificar output a: `{param, fuente(arjun|x8), metodo(GET|POST|JSON|header|cookie), endpoint}`.
- Cruzar contra `js_params`:
  - Confirmado por herramienta + visto en JS → confianza alta.
  - Visto en JS pero no confirmado por ninguna herramienta → `pendiente_manual` (puede necesitar valor específico que la wordlist no cubre).
  - Confirmado por ambas herramientas (Arjun y x8) → confianza alta también.

### Fase 3 — Clasificación por comportamiento
Por cada param confirmado, request baseline vs request con el param inyectado, comparando:
- Status code (delta).
- Content-length (delta).
- Response time (delta — descartar ruido de red, no marcar timing como señal fuerte sin repetir la medición).
- Reflejo literal del valor inyectado en el body.

Etiquetas de salida por param: `reflejado`, `cambia_longitud`, `cambia_status`, `error_revelado`, `silencioso`.

### Fase 4 — Output
Tabla o JSON rankeado, evidencia arriba de conclusión:

```
{
  "endpoint": "...",
  "param": "...",
  "fuente": ["arjun", "x8", "js"],
  "metodo": "GET",
  "comportamiento": ["reflejado", "cambia_longitud"],
  "delta_length": 128,
  "delta_status": null,
  "confianza": "alta|media|pendiente_manual"
}
```

## Reglas duras (no negociables)
- Este skill **nunca** concluye tipo de vulnerabilidad ni severidad. Entrega
  evidencia de comportamiento por parámetro, punto.
- Si un param muestra `reflejado` + `error_revelado`, se puede sugerir como
  candidato a revisar con otro skill (XSS, SSRF, etc.) — pero la sugerencia
  va como nota aparte, no como veredicto.
- Sin PoC/evidencia concreta en este output, cualquier hallazgo derivado es
  como mucho informativo hasta que se valide a mano.
- No repetir wordlists custom: usar siempre la wordlist propia de Arjun
  (se actualiza sola) y la wordlist de headers/cookies estándar de x8.

## Siguiente paso sugerido (encadenado, no automático)
- Params con `reflejado` + método GET/query → candidato a revisar con skill de XSS.
- Params tipo `url`, `redirect`, `callback`, `next` con delta de status/timing → candidato a SSRF/open redirect.
- Params `pendiente_manual` → revisar a mano antes de descartar.
