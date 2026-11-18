# Mapa detallado de fases

Este mapa adapta el orden conceptual del prompt pack público al pipeline de
Mulderx. No reemplaza las instrucciones de los agentes ni autoriza actividad
contra un target.

## Planning — capa previa

Antes de la fase 00, Mulderx carga `hunting-methodology` para decidir wide o
deep, priorizar superficie, fijar timebox y registrar qué línea se cierra. La
decisión de planning no ejecuta pruebas ni reemplaza el triage.

## 00 — Recon

Usar `agents/recon/AGENT.md`, `domain-recon` y, si corresponde, `mulderx-rules`
en modo recon. La salida es superficie observada, tecnologías, endpoints,
señales y blockers. No se prueban vulnerabilidades ni se hace fuzzing activo
por defecto.

## 01 — Access

Es un preflight del operador: scope confirmado, política, rate limits, cuentas
propias y variables de entorno disponibles. Las credenciales viven en
`.credentials/` o en el gestor externo; nunca se escriben en artefactos.
Si una capacidad no existe, se marca bloqueada y se continúa solo con fases
independientes.

## 02 — Sweep

El triage de Mulderx produce las líneas accionables y el wrapper crea Liquid y
Solid. La cobertura debe registrarse por lane, endpoint o clase aplicable, con
estado `CUBIERTO`, `PARCIAL`, `BLOQUEADO` o `NO APLICA`. No se impone una
cantidad fija de requests ni una matriz artificial si el scope, el rate limit o
la señal no la justifican.

## 03 — Closeout

`agents/closeout/AGENT.md` audita si el sweep dejó cada línea con veredicto,
evidencia negativa o blocker. Es un cierre de cobertura, no un hunter y no un
triage de findings. Produce `coverage.md` antes de judge.

## 04 — Browser walk

Es opcional y solo se activa con autorización, scope y una cuenta del
operador. Puede usar Playwright para observar flujos autenticados, pero sus
hallazgos vuelven a un lead concreto; no saltea evidence gates.

## 05 — Critical

Aplicar `hunting-methodology` en ruta deep y cargar `vuln-classes` más la skill
especializada cuando exista una señal concreta. Las cadenas se consideran solo
después de demostrar cada capacidad y documentar el pass signal.

## 06 — Post-sweep triage

`agents/posthunt-triage/AGENT.md` trabaja sobre artefactos ya escritos. Agrupa
duplicados, separa candidato de confirmado, registra huecos y prepara el
contexto para judge. No cambia severidad final ni hace nuevos requests.

## 07 — Validate/escalate

Liquid/Solid y los especialistas validan impacto real con baseline, ejecución,
verificación y cleanup cuando aplique. Un resultado meramente teórico no pasa
a `CONFIRMADO`.

## 08/08a — Independent verification

La verificación activa independiente es una etapa separada y opt-in. No se
simula con Ocelot: Ocelot solo refuta lo documentado sin generar requests.

## 09 — Live triage gate

Antes de cualquier acción de disclosure, el operador revisa scope, impacto,
dedupe y evidencia. Mulderx nunca envía reportes automáticamente.

## 10 — Self duplicate check

Se documenta en `posthunt-triage.md` contra findings previos del mismo
programa. Si no hay corpus suficiente, se marca `BLOQUEADO-EXTERNO`; no se
declara “no duplicado” por ausencia de búsqueda.

