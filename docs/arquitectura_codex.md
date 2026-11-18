# Mulderx con subagentes Codex

Este documento define el flujo objetivo para Codex. Es independiente del
pipeline Hermes de `arquitectura_hermes_bugbounty.md`, que conserva perfiles
Liquid/Solid y requiere sincronización en WSL.

## Prompt de inicio

Codex toma las reglas persistentes del `AGENTS.md` de la raíz del repo. Para
cada programa, el prompt debe aportar los datos variables que las reglas no
pueden conocer de antemano: scope, exclusiones, policy, autorización y etapa.
Usá una estructura como esta desde la raíz de Mulderx:

```text
Actuá como Mulderx: ingeniero en ciberseguridad y sistemas, especialista en
red team y bug bounty. Coordiná el trabajo con criterio técnico y evidencia
reproducible; respetá estrictamente scope y policy.

Programa: <nombre>
Scope autorizado: <hosts/apps/cuentas concretos>
Fuera de scope: <hosts/acciones excluidos>
Policy: <ruta local o reglas relevantes pegadas aquí>
Autorización para esta corrida: <pasivo / pruebas activas permitidas y límites>
Etapa solicitada: <recon, investigación de CVEs, triage, hunt/validación, chaining o cierre>
Material disponible: <rutas puntuales de artefactos, si existen>

Primero verifica que el target y las acciones solicitadas coincidan con el
scope y la policy. Si algo es ambiguo, limitate a análisis pasivo y señala la
ambigüedad. Cubrí el ciclo de hunter que corresponde a esta etapa: tecnología
y versiones, CVEs pertinentes, análisis de flujos, hipótesis, validación e
impacto. Para cada línea de hunting, asigna un único subagente Codex de
AGENTS.md y pídele que use la skill canónica. Si el runtime no ofrece ese
subagente, dilo y usa la skill como fallback sin afirmar que delegaste. Para
un CVE, contrasta versión exacta, advisory, reachability, configuración y
precondiciones; una coincidencia de versión sola queda como candidata.
Integra handoffs en leads.md, conserva evidencia y Q1–Q3, y resume
confirmados, candidatos, descartados, bloqueos y siguiente paso. No imprimas
secretos ni envíes reportes.
```

Ejemplo cuando ya existe triage:

```text
Mulderx, inicia la etapa hunt para el programa Acme. Usa únicamente el scope
y policy guardados en targets/Acme/ y confirma qué archivo establece el
alcance antes de hacer requests. La autorización permite pruebas activas de
baja tasa solo sobre app.acme.example con la cuenta de prueba configurada.
Exclusiones: api.acme.example y cualquier dato de otros usuarios.
Revisa triage.md y los artefactos puntuales que cite cada lead. Asigna cada
lead accionable al subagente de vulnerabilidad correspondiente; no dupliques
hipótesis. Detente ante rate limit, CAPTCHA/challenge, ban o errores 5xx
sostenidos. Devuélveme evidencia reproducible, límites y estado de cada lead;
no prepares ni envíes reportes todavía.
```

## Flujo

```text
Operador (scope y policy)
  → Mulderx (coordina y carga skills de fase/ruteo)
  → Recon / Frohike / Summarizer / Triage
  → especialista Codex según cada lead accionable
  → Mulderx integra evidencia y actualiza leads.md
  → closeout / posthunt-triage
  → Ocelot (juez read-only)
  → Scully (borrador; envío siempre humano)
```

Cada fila de triage tiene un owner especialista y recibe solo el contexto
mínimo para esa hipótesis. El especialista abre el entrypoint de skill en
`.agents/skills/<skill>/SKILL.md`, que dirige a la guía canónica en
`.claude/skills/`. Carga referencias adicionales solo si la guía lo indica.
Mulderx carga `hunting-methodology`, `vuln-classes`, `mulderx-rules` y
`mulderx-phases` según la fase, no todas las skills de hunting.

Codex documenta la carga automática de `AGENTS.md`; no pude verificar desde
esta sesión si la instalación concreta descubre todos los TOML de
`.codex/agents/`. Si un subagente no aparece disponible, Mulderx debe decirlo
con claridad, aplicar la skill directamente como fallback y no afirmar que
delegó.

## Ruteo

Los 8 TOML existentes y los 36 TOML generados suman **44 definiciones de
especialistas**. El catálogo de mapeo se mantiene en `AGENTS.md` y las
definiciones generadas en `scripts/sync_codex_agents.py`. Las skills
operativas de Codex siguen siendo 56 mas `mulderx-workflows` (57 entradas);
no toda skill necesita un agente propio. Metodología, recon, mapas y routing
siguen siendo workflows o herramientas del coordinador.

Los especialistas cubren CVE research general, GraphQL, Web3/DeFi, XSS, IDOR/BOLA, SSRF, CORS,
postMessage, lógica de negocio, npm, expansión de superficie a pedido, AI agents, cache poisoning,
CSTI, CSRF, CSWSH, deserialización/SSTI, secretos, uploads, takeover externo,
HTTP smuggling, traversal, session fixation, SQLi, XXE, paneles de infra,
LLM, MCP, OAuth/OIDC/JWT, output formats, prototype pollution, SAML,
web storage y WebSocket.

El especialista devuelve estado, evidencia, impacto probado, incertidumbre y
siguiente paso al coordinador. Mulderx integra el resultado; un subagente no
puede decidir severidad final ni enviar reportes. Sin evidencia técnica de
impacto y Q1–Q3 escritos, el hallazgo queda como candidato como máximo P4 /
Informational. Los descartes incluyen su motivo concreto.

Los subagentes generados heredan el modelo Codex del agente principal y usan
reasoning alto. No fijamos un modelo específico en los TOML para evitar que
la configuración del repo imponga un modelo no disponible en la cuenta. Los
8 agentes escritos a mano mantienen sus instrucciones propias; el generador
no los sobrescribe.

## Separación por programa

No se clona Mulderx ni se crea un conjunto de agentes por programa. Cada
programa mantiene su propio directorio `targets/<programa>/`, policy,
credenciales y artefactos; el coordinador asigna los leads de ese programa
solo a tareas de esa corrida. En Hermes, usar un board/workspace por
programa. En Codex, iniciar el trabajo con un programa y su scope inequívoco
por tarea/sesión. Los perfiles y las instrucciones de rol se reutilizan.

El workspace de Hermes no es una sandbox de seguridad. Para aislamiento
fuerte entre programas o credenciales, usar usuarios/containers separados y
no confiar solo en un board o profile.

## Sincronización

- Skills Codex: `python scripts/sync_codex_skills.py --check`
- Especialistas generados: `python scripts/sync_codex_agents.py --check`
- Regenerar especialistas: `python scripts/sync_codex_agents.py`
- Los perfiles `~/.hermes/profiles/*/SOUL.md` viven fuera del repo y no se
  actualizaron aquí. WSL no estuvo accesible durante este cambio.

El wrapper `scripts/hermes_swarm.sh` sigue siendo el launcher histórico
Liquid/Solid; no lo uses para afirmar que Hermes ya hace dispatch dinámico a
las 44 definiciones de especialistas Codex. Esa integración requiere perfiles Hermes equivalentes
y su propia configuración runtime.
