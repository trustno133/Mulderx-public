# Integraciones de Mulderx

## Proveedores del orquestador

- `claude`: Claude Code CLI, proveedor por defecto y con ejecución de herramientas del CLI.
- `codex`: Codex CLI con autenticación de cuenta ChatGPT; usar `--model` si se quiere fijar el modelo.
- `opencode`: OpenCode CLI con herramientas del workspace; iniciar sesión/conectar un proveedor y especificar `--model proveedor/modelo` si hace falta.
- `openai`: OpenAI Responses API, limitado a lectura/listado de archivos y escritura bajo `targets/`. No ejecuta comandos, escáneres ni navegador; usarlo solo en agentes de análisis compatibles.

`codex` usa la sesión de Codex CLI y puede autenticarse con una cuenta ChatGPT elegible. `opencode` documenta autenticación para ChatGPT Plus. `openai` es la API directa: requiere `OPENAI_API_KEY` y facturación de API aparte; la suscripción Plus/Pro no la reemplaza. La clave no debe guardarse en `.credentials/<target>.env` ni en el repositorio.

Anthropic ofrece Claude Code con sus planes Pro/Max. OpenCode indica expresamente que usar la suscripción Claude Pro/Max dentro de OpenCode mediante plugins no está permitido; usar Claude Code CLI para esa suscripción.

## Agente XSS

Codex usa `AGENTS.md` y descubre playbooks completos en `.agents/skills/`; Claude Code usa `CLAUDE.md`, los playbooks completos en `.claude/skills/` y agentes en `.claude/agents/`. Las skills Codex incluyen el cuerpo completo de cada playbook y referencias de apoyo. `python scripts/sync_codex_skills.py --check` valida que no haya stubs ni contenido truncado y no sobrescribe archivos. La carpeta `xss` es una biblioteca de referencias compartida, no un playbook independiente.

Para una cacería XSS, Codex puede delegar en `.codex/agents/xss_specialist.toml`; Claude Code, en `.claude/agents/xss-specialist.md`, que precarga `xss-hunt` y omite `CLAUDE.md` para evitar contexto común duplicado. Ambos empiezan por la evidencia puntual y no abren `context.md`, triage, surface checklist ni leads por defecto. Las referencias se cargan bajo demanda.

Codex descubre el servidor Playwright desde `.codex/config.toml`; `.mcp.json` configura las mismas herramientas para Claude y no reemplaza la config MCP de Codex. El orquestador mantiene el shell en `workspace-write` sin red; la verificación web se hace mediante el navegador MCP, limitada por las instrucciones de scope del agente. Codex solo carga la config local del proyecto cuando este está marcado como confiable. Tras incorporar esta config, reiniciar la sesión de Codex y revisar que Playwright aparezca entre las herramientas MCP.

Invocación sugerida en Codex: `Usá xss_specialist y la skill xss-hunt. Analizá este request/response...`. En Claude Code: `Usá xss-specialist para analizar este request/response...`, o invocá `/xss-hunt`. La configuración del repo aplica cuando Claude Code/Codex opera desde el proyecto; ChatGPT web normal no carga estos archivos locales automáticamente.

## Skills y especialistas para Claude Code y Codex

El flujo previsto es Mulderx como coordinador y un subagente por lead accionable, elegido por vulnerabilidad. Cada subagente carga su skill canónica y devuelve evidencia y estado al coordinador; las skills de metodología, recon y reporting no necesitan agentes propios. Hay 57 playbooks Codex más el router (58 entradas) y 44 especialistas por proveedor; Claude mantiene además 3 asistentes auxiliares. Codex usa `.codex/agents/*.toml`; Claude usa `.claude/agents/*.md` (34 generados desde el registro compartido y 10 mantenidos a mano). Claude Code debe iniciarse desde el proyecto para descubrir sus archivos locales; la carga real requiere tener Claude Code instalado y autenticado.

Los especialistas Codex se actualizan y comprueban con `python scripts/sync_codex_agents.py [--check]`. Los equivalentes Claude se actualizan y comprueban con `python scripts/sync_claude_agents.py [--check]`; ese generador preserva los agentes escritos a mano. El registro y ruteo comunes están en `scripts/sync_codex_agents.py` y `AGENTS.md`. Los subagentes generados de Codex heredan el modelo principal y usan reasoning alto. Para preguntas conceptuales o leads sin evidencia accionable, no delegar una prueba.

## Hermes — orquestación multi-agente

Hermes (Nous Research, WSL) es una integración aparte. Su pipeline actual
corre `liquid`=Claude y `solid`=Codex/GPT vía Kanban, con un board por target;
ver `arquitectura_hermes_bugbounty.md`. Ese launcher no despacha los nuevos
subagentes Codex por tipo; no confundirlo con el flujo de
`arquitectura_codex.md`.

**Bug confirmado en `hermes kanban swarm` (v0.22.4, 2026-10-23):** ignora
el workdir default del board (`hermes kanban boards set-default-workdir`)
y le da a cada worker un workspace `scratch` que ni siquiera se crea en
disco (confirmado en el log del gateway: `agent.runtime_cwd: configured
working directory does not exist`). El agente arranca sin el contexto
pre-sembrado (`context.md`/`leads.md`/`discarded.md`) y sin poder escribir
resultados en el lugar correcto. **No usar `hermes kanban swarm`
directo** — usar `scripts/hermes_swarm.sh`, que usa `--workspace dir:<path>`
explícito y avanza por gates: inicia Liquid/Solid solo si Triage tiene
candidatos; después crea Ocelot solo si hay leads `CONFIRMADO` con recibos
estructurados válidos en `findings.json`; finalmente crea Scully solo si
Ocelot aprobó findings y el store valida como `APPROVED`. Re-testear si una actualización de
Hermes dice haber tocado `kanban swarm`.

El gate de hunters toma `triage.json` como fuente estructurada y mantiene
`triage.md` para lectura humana. Los workspaces anteriores pueden usar las
tablas Markdown como fallback; el resultado del gate incluye conteos de
candidatos, bloqueos y errores de formato.

## Política de datos

Al usar un proveedor remoto, el contenido de instrucciones, prompts y archivos leídos para la tarea se envía a ese proveedor. Revisar el material de `targets/` antes de usar OpenAI u OpenCode con datos sensibles. Las herramientas OpenAI del orquestador bloquean lectura directa de `.credentials/`, `.git/` y `.aws/`, y restringen escritura a `targets/`.
