# Auditoría técnica de Mulderx

Auditoría técnica base: 2026-11-17. Revisión documental de `main`: 2026-11-18. No se hicieron requests a targets externos en esta revisión documental.

La auditoría técnica y las pruebas de la sección final corresponden al snapshot local del 2026-11-17; no verifican la fusión de skills ni los cambios posteriores. Consultar `MULDERX_FUSION.md` para el estado de permisos.

## Arquitectura observada

El repositorio reúne tres rutas que no comparten un único runtime:

- `scripts/bb_pipeline.py` coordina discovery, fingerprint y análisis JS. Sus
  resultados terminan en handoffs locales; no ejecuta por sí mismo un hunt de
  vulnerabilidades completo.
- `agents/*/AGENT.md` contiene contratos de roles del workflow Hermes. El
  wrapper versionado `scripts/hermes_swarm.sh` crea tareas Kanban, pero los
  perfiles `SOUL.md` activos viven fuera del repo, dentro de WSL.
- `CLAUDE.md`/`.claude/agents/` y `AGENTS.md`/`.codex/agents/` son las rutas
  de instrucciones y especialistas de Claude Code y Codex. Claude usa
  `.claude/skills/` y Codex usa playbooks completos en `.agents/skills/`;
  `sync_codex_skills.py` valida inventario, contenido mínimo y referencias,
  pero no genera ni reemplaza archivos.
- `orchestrator.py` es la ruta heredada. `USAGE.md` ya la marca como
  deprecada; se conserva para compatibilidad y no debe confundirse con el
  flujo Hermes actual.

Las rutas de ejecución no sincronizan automáticamente instrucciones nuevas
con los perfiles Hermes instalados. El diagnóstico de esta máquina encontró
WSL, pero no `hermes` en PATH; por eso no se pudo comprobar el contenido de los
perfiles externos ni ejecutar el wrapper de punta a punta.

## Hallazgos y cambios realizados

| Prioridad | Hallazgo verificable | Cambio | Estado |
|---|---|---|---|
| P0 | El matcher anterior de Katana aceptaba sufijos de host y subdominios implícitos en un scope exacto. | Política común exacta/wildcard, normalización IDNA y límites de host; wildcard ahora exige `*.`. | Corregido y probado. |
| P0 | Los recolectores de sourcemaps/JS histórico podían seguir URLs o redirecciones fuera del host declarado. | Filtro previo al request, redirect guard, autorización interactiva o `--yes`, límites de tamaño y filtro CDX por hostname real. | Corregido; pruebas locales con redirección controlada. |
| P0 | El token de Telegram podía quedar en el log del comando. | Registro de comando desactivado para esa llamada. | Corregido; no se probó envío externo. |
| P0 | Nombres de programa/run-id podían afectar rutas en disco. | Validación de slug y run-id; rutas contenidas al workspace; symlinks de métricas/store rechazados. | Corregido y probado. |
| P1 | `leads.md` con `CONFIRMADO` o `judged.md` con `APROBADO` bastaban para abrir etapas. | `findings.json`, schema y transiciones estructuradas; judge/report gates requieren store válido, evidencia y hashes coincidentes. | Corregido para gates locales. |
| P1 | Snapshots concurrentes podían perderse o sobrescribirse. | Run-id único, escritura atómica y locks advisory multiplataforma para métricas/evidencia. | Corregido; 24 snapshots concurrentes probados. |
| P1 | El wrapper Hermes tenía una ruta absoluta de otra instalación y `jq -r .id` aceptaba `null`. | Ruta relativa al propio script y extracción estricta del ID con `jq -er`. | Corregido estáticamente; runtime Hermes externo sin verificar. |
| P1 | `orchestrator.py` imprimía parte del prompt y añadía texto `[USAGE]` sin redactar valores de credenciales. Un CLI faltante podía terminar con `SystemExit` dentro de un worker. | Ya no imprime contenido de prompt, redacta valores conocidos y devuelve fallo normal si Claude falta. | Corregido y probado. |
| P2 | Skills, agentes y utilidades auxiliares incluían rutas absolutas de otra máquina; algunas instrucciones describían el scope como scoring. | Paths relativos/configurables, ejemplos actualizados y reglas de scope alineadas con el filtro estricto del pipeline. | Corregido en rutas activas; sincronizadores verificados. |
| P2 | No había memoria local indexada por programa ni un comando de diagnóstico. | SQLite/FTS5 aislado por workspace y `mulderx_doctor.py`. | Implementado; pruebas locales. |
| P2 | No había medición reproducible del taint tracker. | Benchmark sintético local con etiquetas conocidas y métricas de confusión. | Medido en 9 fixtures; ver `MULDERX_BENCHMARK.md`. |

## Riesgos que siguen abiertos

1. **Orquestador heredado:** las opciones de lanzamiento se endurecieron en
   la fusión: Codex usa `--sandbox workspace-write --ask-for-approval on-request`,
   Claude ya no omite confirmaciones y OpenCode no usa modo automático. El
   orquestador sigue siendo legado; sus rutas de proveedor no se validaron de
   punta a punta en el snapshot de esta auditoría.
2. **Recibos no autenticados:** SHA-256 detecta modificaciones posteriores,
   pero un agente con escritura en el workspace puede inventar una captura y
   su historial. El campo `source` es declarativo; no demuestra que un
   request/captura salió de una herramienta real. El gate reduce errores
   accidentales y claims solo en Markdown, no es una frontera criptográfica.
3. **Contratos de ejecución incompletos:** las tareas Hermes no devuelven un
   envelope común con task-id, presupuesto, error, evidencia y cancelación.
   El wrapper despacha tareas y no espera ni verifica su resultado. La
   integración Codex depende de las capacidades del runtime local.
4. **Hermes externo sin verificación:** los archivos `AGENT.md` versionados
   pueden diferir de `~/.hermes/profiles/*/SOUL.md`; WSL no fue consultado.
5. **Herramientas de recon opcionales faltantes:** doctor no encontró
   `subfinder`, `dnsx`, `httpx`, `katana`, `subzy` ni `ffuf` en PATH. La etapa
   de subdominios puede degradarse a la raíz; el doctor lo informa como
   herramienta opcional, pero no equivale a cobertura completa.
6. **Grafos AST JS no instalados:** no están `networkx`, `tree-sitter` ni
   `tree-sitter-javascript`; `module_graph.py` no puede correr en este entorno
   hasta instalar esas dependencias opcionales. No se instalaron porque no son
   necesarias para los tests o el pipeline base.
7. **Fuzzing sigue siendo una etapa explícita:** el pipeline principal no
   hace fuzzing amplio ni descubrimiento automático de parámetros. La
   expansión permanece bajo demanda, con el especialista correspondiente y
   autorización aplicable.
8. **Costos y calidad de agentes:** métricas actuales cuentan estados y
   artefactos, pero no tokens por proveedor, precio, tools, falsos positivos
   reales o costo por hallazgo confirmado.

## Verificación del snapshot local del 2026-11-17

Los resultados siguientes son históricos y no verifican la fusión posterior ni
los cambios de skills documentados el 2026-11-18. El estado de CI del commit
actual no pudo confirmarse desde la integración disponible.

- `python -m unittest discover -s tests -v`: 30 pruebas pasaron.
- `py_compile` de `orchestrator.py`, scripts y tests: pasó.
- `python scripts/sync_codex_agents.py --check`: 36 especialistas generados
  sincronizados.
- `python scripts/sync_codex_skills.py --check`: 57 entradas sincronizadas.
- `python scripts/mulderx_doctor.py --json`: 0 errores, 16 avisos opcionales
  (principalmente herramientas externas no instaladas y Hermes fuera de PATH).
- Las pruebas de scope usaron solo un servidor loopback local. No se probó un
  target, endpoint de bounty, Telegram ni Hermes.
- El workspace inspeccionado entonces no tenía `.git`; no había diff de Git
  ni commit que presentar desde esa copia.
