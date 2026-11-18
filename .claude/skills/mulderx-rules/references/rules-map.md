# Rules map for Mulderx

## Precedencia y lectura

La fuente clonada, si está presente, está en `pentest-agents/rules/` relativa
a la raíz del repositorio. Los paths de target y las credenciales no se
sustituyen por material de este directorio.

Leé solo los encabezados indicados. `mistakes.md` y `payloads.md` son grandes:
no se cargan completos.

## Fases

| Fase | Agente | Leer | No leer todavía |
|---|---|---|---|
| Setup / scope | Mulderx, Recon | `hunting.md` Rule 1; `mistakes.md` sección `SCOPE-POLICY` solo si hace falta una regla puntual | payloads, techniques, chain-table |
| Planning / priorización | Mulderx | `hunting.md` Rules 3, 5–7, 10–12, 16–18, 22, 30; `vendor-status.md` solo para una tecnología observada | payloads y bypasses |
| Recon / surface | Recon, Frohike | `hunting.md` Rules 4, 10, 16, 17, 30; `vendor-status.md` para fingerprint/cooldown concreto; `mistakes.md` `TOOLING` solo ante un problema | chain-table, never-submit completo |
| Triage | Triage | `hunting.md` Rules 0, 2, 13, 19, 20, 23; `mistakes.md` `METHODOLOGY` y `SCOPE-POLICY` en secciones puntuales; `never-submit.md` | payloads, pruebas activas, técnicas de explotación |
| Hunt / validation | Liquid, Solid, especialistas | `hunting.md` Rules 8, 9, 21, 24–28, 31; `mistakes.md` `METHODOLOGY`/`TOOLING` según el caso; skill específica | reglas de clases no relacionadas |
| Pass signal / chaining | Hunter dueño | `chain-table.md` y la sección de anchors de la clase correspondiente; `hunting.md` Rules 21 y 27 | cadenas sin capacidad demostrada |
| Judge | Ocelot | `hunting.md` Rules 0, 2, 13, 19, 20, 23; `never-submit.md`; `mistakes.md` `REPORTING` solo si aporta una refutación | payloads y requests nuevos |
| Reporting | Scully, operador | `never-submit.md`; `mistakes.md` `REPORTING` en secciones puntuales | payloads, técnicas y reglas de explotación |

## Carga por señal

- La cobertura es por host y deployment: `hunting.md` Rule 30 permite usar
  otra region solo para sembrar una hipotesis, nunca para marcar un host como
  probado o agotado. Si policy impide testearlo, registra el blocker exacto.
- Rule 26 (browser/API parity) ya esta cubierta por
  `business-logic/SKILL.md`: comparar restriccion UI con enforcement del API y
  verificar estado con una segunda perspectiva autorizada. No repitas esa
  prueba si la skill ya cubrio el mismo flujo.
- XSS o JS execution: skill `xss-hunt`; luego `payloads.md` solo para el
  contexto detectado; `waf-bypass-protocol.md` únicamente tras un bloqueo WAF
  reproducible.
- SSRF: skill `ssrf`; `payloads.md` o `techniques.md` solo para el mecanismo
  de fetch observado y con canary OOB controlado.
- IDOR/BOLA: skill `idor-bola`; `mistakes.md` sobre cross-account,
  differential testing y read-back; `chain-table.md` solo con acceso ajeno
  demostrado.
- GraphQL/OAuth/SAML: la skill específica; `techniques.md` solo para la
  sección del protocolo observada.
- Business logic/race: `business-logic`; `hunting.md` Rules 11, 22, 25, 26 y
  31, con pruebas sintéticas y límites explícitos.
- WAF: usar `waf-profiler` para documentar controles observables y límites;
  consultar `waf-bypass-protocol.md` solo tras un bloqueo reproducible,
  dentro de autorización explícita y sin evadir CAPTCHA, rate limits, bans,
  controles de identidad ni protección de origen.

## Traducciones de herramientas

| Regla externa | Equivalente Mulderx |
|---|---|
| `/validate` / 7-Question Gate | Q1–Q3 y evidence gate de la skill |
| `/chain` | `chain-table.md` + handoff del hunter |
| `brain.py record` | `leads.md`, `discarded.md`, `recon.md` o artefacto indicado por el workflow |
| `autopilot_gate.py` | gates de `mulderx_metrics.py`, AGENTS.md y el agente de la etapa |
| `submit` | reporte preparado por Scully; el operador decide el envío |
| 30 combinaciones fijas | matriz adaptativa, limitada por scope, señal y rate limit |
