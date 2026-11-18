---
name: xss-stored
description: Detecta y valida XSS persistente — input que se guarda en algún
  almacenamiento (DB, log, config, perfil, comentario) y se renderiza
  después, potencialmente para otro usuario. Usar cuando hay funcionalidad
  de guardar/editar contenido (comentarios, perfil, tickets, uploads,
  nombres de archivo, config de panel admin) y el valor persistido se
  renderiza sin escapar en algún lugar.
---

# XSS Stored

Trabajá sobre el caso concreto que dio el operador. Mismo abanico de sinks
que `xss-reflected`, pero el disparo es diferido: importa DÓNDE y PARA
QUIÉN se renderiza, no solo si escapa.

## Qué buscar

Source: input que se guarda en algún almacenamiento (DB, log, config,
perfil, comentario) y se renderiza después — potencialmente para OTRO
usuario.

Storage points a chequear, no solo los obvios: comentarios/posts,
perfil/display name, tickets de soporte, filename de upload, headers
(Referer/User-Agent) que terminan en logs de admin, **y config/options
interno** — un valor de configuración persistido que se renderiza sin
escapar en un panel admin (caso real: Automattic/Pressable, ver
`../xss/references/wild-signals.md`).

Storage points con mayor payout histórico: SVG upload (`<svg onload=...>`),
markdown editors que no sanitizan HTML, campos "View as customer" /
"Impersonate" que un admin visualiza, webhook URLs renderizadas en panel,
rich text editor outputs.

## A quién afecta — esto es lo que define la severidad acá

Antes de documentar, identificar explícitamente:
- ¿Quién ve el contenido persistido? (cualquier usuario / solo el autor /
  solo un admin / solo soporte)
- ¿Hace falta alguna acción del viewer para disparar el render, o se
  renderiza automático al visitar una página normal del flujo?
- Si el viewer es un rol privilegiado (admin, soporte), documentarlo
  explícito — sube la severidad un escalón sobre un stored que solo afecta
  a usuarios pares.

## Qué mata el lead

- Hay encoding/escape antes de persistir o antes de reflejar (ambos
  puntos cuentan — algunos sistemas escapan al guardar, otros al
  renderizar, hay que confirmar cuál).
- El framework autoescapa por default y no hay bypass del binding — ver
  tabla de frameworks en `../xss/references/common-xss.md`.
- Sanitizer server-side activo **y la identidad confirma uno de los dos resistentes**
  (sanitize-html o loofah). Para cualquier otro sanitizer conocido (DOMPurify viejo,
  AntiSamy, JSoup, HtmlSanitizer, Typo3, rgrove/sanitize, google-caja...) la mayoría
  son bypasseables vía parsing differentials — no cerrar el lead, ver sección mXSS
  en `../xss/references/bypass-techniques.md`.
- El storage point existe pero nadie lo visualiza en un contexto que
  renderice HTML (ej: campo que solo se usa en exports CSV/JSON, nunca en
  una página).

## Severidad

Sin ejecución confirmada (reflejo crudo en navegador real al visitar el
storage point) = Informational o P4 máximo.

Sube un escalón vs reflected — no depende de convencer a la víctima de
clickear nada. Si afecta a admin o rol privilegiado, sube más. Ver "Impact
framing" en `../xss/references/common-xss.md` para la escalada de PoC
(cookie theft / token / CSRF token steal / acción state-changing /
persistencia auto-propagante) y las reglas de `HttpOnly`/`SameSite`.

## Cleanup — obligatorio acá

Si el storage point es un target vivo con usuarios reales (comentario,
perfil, ticket, review), borrar o editar el payload apenas se confirma
la ejecución. No dejarlo persistiendo — hay gente real viendo eso. Ver
`../xss/references/common-xss.md`.

## Referencias condicionales

- Contexto de reflexión (tabla de escape), framework gotchas, impact
  framing, cleanup, self-XSS encadenable: `../xss/references/common-xss.md`.
- Filtro observado con outcome BLOCKED o SANITIZED (canary strippeado, no reflejado
  verbatim) al guardar o al renderizar: `../xss/references/filter-probing.md`,
  luego `../xss/references/bypass-techniques.md`. Si el outcome es SANITIZED (vs
  BLOCKED), ir directo a la sección mXSS / Parsing Differentials en bypass-techniques.md
  — el filtro probing clásico es secundario cuando hay un sanitizer HTML.
- Catálogo de vectores por contexto exacto: `../xss/references/vector-catalog.md`.
- Caso real documentado de config persistido en panel admin:
  `../xss/references/wild-signals.md`.
- WAF bloqueando una prueba autorizada: `../xss/references/wafbypass/SKILL.md`.
