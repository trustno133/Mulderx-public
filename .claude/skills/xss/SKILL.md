---
name: xss
description: Librería compartida de referencias XSS (no se carga directo).
  Los 4 subtipos viven en skills separadas — xss-reflected, xss-stored,
  xss-dom, xss-blind — que son las que triggerean. Esta carpeta solo aloja
  references/ compartidas entre las cuatro.
---

# XSS — librería de referencias compartidas

**No cargues esta skill directo.** El punto de entrada es `xss-hunt`, que
clasifica el subtipo (reflected / stored / DOM / blind) y carga una de
las cuatro skills específicas:

- `.claude/skills/xss-reflected/SKILL.md`
- `.claude/skills/xss-stored/SKILL.md`
- `.claude/skills/xss-dom/SKILL.md`
- `.claude/skills/xss-blind/SKILL.md`

Esta carpeta existe para alojar `references/`, material técnico que las
cuatro skills citan en su sección "Referencias condicionales" y que no
tiene sentido duplicar cuatro veces:

- `references/common-xss.md` — contexto de reflexión/escape, polyglots,
  framework gotchas, impact framing (escalada de PoC), self-XSS
  encadenable, variants siempre rechazadas, cleanup.
- `references/filter-probing.md` — metodología para caracterizar un
  filtro observado antes de elegir payload.
- `references/bypass-techniques.md` — técnicas de evasión de filtros,
  aplican a los 4 subtipos por igual.
- `references/vector-catalog.md` + `references/portswigger-vectors.json`
  — catálogo de vectores PortSwigger, consultado dirigido a partir del
  filter map de `filter-probing.md`.
- `references/constructive-synthesis.md` — construcción de payload desde
  primitivas del lenguaje cuando el catálogo no alcanza.
- `references/client-side-prototype-pollution.md` — source/gadgets de
  prototype pollution conectado a un sink DOM-based.
- `references/wild-signals.md` — casos reales documentados.
- `Prueba/wafbypass/SKILL.md` — WAF bloqueando una prueba in-scope.

Si estás acá y no es porque una de las cuatro skills te mandó a leer algo
puntual, lo más probable es que quieras `xss-hunt` para clasificar primero.
