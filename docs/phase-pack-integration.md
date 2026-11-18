# Integración del prompt pack de hunting

Mulderx usa el repositorio público como doctrina de fases y handoffs, no como
runtime. La adaptación canónica está en la skill `mulderx-phases`.

## Secuencia Hermes

Después de crear y completar Liquid/Solid:

```bash
scripts/hermes_swarm.sh closeout <board> <workspace> <run-id>
scripts/hermes_swarm.sh posthunt-triage <board> <workspace> <run-id>
scripts/hermes_swarm.sh judge <board> <workspace> <run-id>
scripts/hermes_swarm.sh reporter <board> <workspace> <run-id>
```

Los comandos intermedios producen `coverage.md` y
`posthunt-triage.md`. Si el gate de closeout no encuentra `triage.md`, o el de
post-hunt no encuentra `coverage.md`, se detienen sin crear una tarea falsa.

## Perfiles de Hermes

Los perfiles viven fuera del repositorio, dentro de WSL, en
`~/.hermes/profiles/`. Hay que crear/sincronizar dos perfiles nuevos:

- `closeout/SOUL.md` con el contenido operativo de `agents/closeout/AGENT.md`.
- `posthunt-triage/SOUL.md` con el contenido operativo de
  `agents/posthunt-triage/AGENT.md`.

El wrapper acepta perfiles alternativos como quinto argumento de cada
subcomando. No se debe copiar credenciales ni el contenido privado del prompt
pack a esos perfiles.

## Qué queda manual

Access/preflight, browser walk, verificación independiente y el live triage
gate requieren decisión del operador. No se activan automáticamente porque
pueden cambiar el nivel de acceso, la carga sobre el target o el estado de
datos. El reporte final tampoco se envía automáticamente.

