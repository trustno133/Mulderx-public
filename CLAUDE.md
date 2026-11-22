# Mulderx — contexto para Claude Code

Leer `AGENTS.md` y seguir sus reglas comunes en toda tarea. Las instrucciones específicas de los agentes del pipeline Hermes (mulderx, liquid, solid, ocelot, scully, recon, triage, summarizer) se encuentran en `agents/<agente>/AGENT.md`, los sub-agentes especializados por tipo de vulnerabilidad en `.claude/agents/` y `.codex/agents/`, y las skills aplicables en `.claude/skills/`.

Todo especialista Claude que produzca o cambie un lead debe respetar el
registro estructurado `targets/<programa>/findings.json` y los gates descritos
en `AGENTS.md`/`docs/evidence-store.md`. Ocelot es read-only; el texto
`CONFIRMADO` o `APROBADO` en Markdown por sí solo no autoriza el siguiente
estadio.

Para SQLi (parámetros con queries, ORMs, NoSQL operator injection), cargar la skill `hunt-sqli`. Para XXE (SOAP, file upload XML, SAML, JSON→XML swap), cargar la skill `hunt-xxe`. Para HTTP Request Smuggling (CDN/proxy delante de origin), cargar la skill `hunt-http-smuggling`. Para Prototype Pollution (Node.js endpoints que mergean JSON, `__proto__` en params, librerías lodash/jquery desactualizadas), cargar la skill `prototype-pollution`.

Para hunts o validación XSS, delegar en el subagente `xss-specialist` de `.claude/agents/xss-specialist.md`; para postMessage, en `postmessage-specialist` de `.claude/agents/postmessage-specialist.md`; para CORS, en `cors-specialist` de `.claude/agents/cors-specialist.md`; para IDOR/BOLA, en `idor-specialist` de `.claude/agents/idor-specialist.md`; para SSRF, en `ssrf-specialist` de `.claude/agents/ssrf-specialist.md`; para lógica de negocio, en `business-logic-specialist` de `.claude/agents/business-logic-specialist.md`; para dependencias npm, en `npm-packages-specialist` de `.claude/agents/npm-packages-specialist.md`. Para perfilar un WAF/CDN observado, delegar en `waf-profiler-specialist` de `.claude/agents/waf-profiler-specialist.md`; para mapear servicios cloud explícitamente en scope, en `cloud-recon-specialist` de `.claude/agents/cloud-recon-specialist.md`. Para ampliar superficie ya mapeada (fuzzing de rutas/archivos, descubrimiento de parámetros), delegar en `surface-expansion-specialist` de `.claude/agents/surface-expansion-specialist.md` solo cuando exista autorización activa aplicable y dentro de sus límites. Para preguntas conceptuales breves, responder directamente. Cada subagente precarga solo su skill correspondiente y omite estos archivos generales de Claude para mantener su contexto enfocado.

El flujo detallado de bug bounty y las reglas operativas extensas están en `docs/workflow.md`. Consultar solo las secciones pertinentes para la tarea actual; no cargar el documento completo por defecto.

Para un dominio o una superficie amplia, cargar `multi-vuln-coverage` para mapear las funcionalidades observadas a clases de vulnerabilidad y planear cobertura equilibrada. Derivar las señales concretas a los especialistas correspondientes y cargar playbooks bajo demanda.

Para seleccionar una ruta wide/deep, priorizar superficie, aplicar sibling
rule, timeboxing y registrar cobertura, cargar `hunting-methodology`. Para
clasificar una señal entre clases de vulnerabilidad, cargar `vuln-classes` y
seguir el handoff hacia la skill especializada; no usar el índice como
autorización para pruebas activas.

Para los especialistas de hunting listados en `AGENTS.md`, Claude Code usa el
agente nativo equivalente de `.claude/agents/` con nombre en kebab-case
(por ejemplo, `graphql_specialist` -> `graphql-specialist`). Los equivalentes
generados se sincronizan desde el mismo registro que Codex; las skills de
metodología/recon/reporting se cargan directamente y no requieren agente.

Para consultar `pentest-agents/rules`, cargar `mulderx-rules` y únicamente la
sección correspondiente a la fase o señal. No cargar el directorio completo ni
dejar que sus reglas reemplacen scope, policy, evidence gate o Q1–Q3.

Para adaptar el prompt pack público de hunting, cargar `mulderx-phases` y sus
referencias `phase-map.md`/`handoff-contract.md` bajo demanda. El pack es una
referencia de orquestación: no reemplaza los agentes existentes, no contiene
autorización y no se carga entero. El cierre de cobertura va por `closeout`
antes de `judge`; el post-sweep dedupe va por `posthunt-triage`.

`knowledge/index.md` contiene un índice de reportes H1 públicos (Medium/High/Critical) organizados por tipo de vulnerabilidad. Los subagentes especialistas deben consultarlo al inicio de un hunt para tomar contexto de técnicas y patrones conocidos — cargar solo la sección del tag relevante, no el índice entero.
