---
name: mulderx-phases
description: Adapta el prompt pack público de bug bounty a las fases, handoffs y gates reales de Mulderx sin cargar prompts externos completos ni mezclar permisos entre agentes.
---

# Adapter de fases para Mulderx

Usá esta skill cuando el operador pida ejecutar, adaptar o auditar el ciclo
de fases del prompt pack público de bug bounty. El pack es una referencia de
orquestación y handoffs; no es una aplicación, no autoriza pruebas y no debe
cargarse completo en cada agente.

## Regla de carga

1. Leer `references/phase-map.md` para ubicar la fase solicitada.
2. Leer `references/handoff-contract.md` si la tarea crea o valida un
   handoff.
3. Leer solamente el `AGENT.md` y la skill específica de Mulderx que
   correspondan a la fase.
4. Nunca copiar `YOUR_*`, credenciales, cookies, tokens ni infraestructura
   privada del pack externo al workspace.

La precedencia es: `AGENTS.md` y scope/policy del programa, skill canónica y
evidence gate, contrato de fase, reglas puntuales de `mulderx-rules`, y recién
después hipótesis del agente.

## Mapeo operativo resumido

Planning es una capa de decisión previa al ciclo: Mulderx usa
`hunting-methodology` para elegir wide/deep, priorizar y fijar timebox. No es
una fase de explotación ni debe mezclarse con el hunting de Liquid/Solid.

| Fase externa | Mulderx | Salida principal | Restricción |
|---|---|---|---|
| 00 Recon | `recon` + `domain-recon` | `recon.md`, `recon_summary.md` | No hunting ni fuzzing |
| 01 Access | operador + preflight | cuentas/variables fuera del repo | No inventar cuentas ni copiar secretos |
| 02 Sweep | `triage` → Liquid/Solid + cobertura | `triage.md`, `leads.md`, `discarded.md` | Cobertura adaptativa; respetar gate de hunters |
| 03 Closeout | `closeout` | `coverage.md` | Auditoría de cobertura; no nuevos requests |
| 04 Browser walk | opcional Playwright/manual | evidencia de navegación | Solo con autorización y cuenta del operador |
| 05 Critical | `hunting-methodology` + especialistas | leads con PoC | Ruta deep, timebox y evidence gate |
| 06 Post-sweep triage | `posthunt-triage` | `posthunt-triage.md` | Dedupe/clasificación; no hunting ni severidad final |
| 07 Validate/escalate | Liquid/Solid + especialistas | `leads.md` actualizado | Baseline → ejecución → verify → cleanup |
| 08/08a Independent verify | etapa manual autorizada, no Ocelot | evidencia adicional | No activarla implícitamente |
| 09 Live triage gate | operador/programa | decisión de continuar | No auto-submit |
| 10 Self-duplicate check | `posthunt-triage` + revisión humana | dedupe documentado | No descartar sin motivo verificable |

## Invariantes

- Recon no se convierte en sweep por cargar una fase externa.
- El triage previo de Mulderx (`triage.md`) alimenta hunters; el triage
  posterior del pack (`posthunt-triage.md`) deduplica y audita resultados.
- Ocelot sigue siendo read-only y adversarial. No se lo usa como verificador
  activo ni se le pide enviar requests nuevos.
- Un bloqueo o fase no disponible se registra como `BLOQUEADO-EXTERNO` o
  `SETUP-PENDIENTE`, nunca como cobertura negativa.
- Cada fase termina con un artefacto auditable y un siguiente paso concreto.
