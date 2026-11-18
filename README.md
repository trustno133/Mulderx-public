# Mulderx

Framework local de investigación de vulnerabilidades asistido por agentes.
Coordina recon, análisis de artefactos, especialistas, evidencia y revisión
humana. Las herramientas activas requieren autorización y scope explícitos.

## Instalación y diagnóstico

Requiere Python 3.10 o posterior. Desde la raíz del repositorio:

```powershell
python -m pip install -r requirements.txt
python scripts/mulderx_doctor.py
```

El doctor comprueba dependencias, archivos, MCP y sincronización de entradas
Codex sin acceder a targets ni leer valores de secretos. Claude Code y Codex
CLI se instalan/autentican por separado; Hermes se ejecuta desde WSL y su
configuración efectiva está fuera de este repositorio.

## Cómo se organiza

- `scripts/bb_pipeline.py`: recon activo por etapas, con confirmación humana,
  filtro de scope y límite de redirecciones.
- `scripts/recon_fingerprint_v3.6_handoff_slim.py`: fingerprint y handoff.
- `scripts/js_analyzer_v4_8.py`, `scripts/taint_tracker.py` y los
  reconstructores Webpack/Parcel: análisis local de JavaScript.
- `agents/`, `.claude/agents/` y `.codex/agents/`: contratos de rol y
  especialistas. Las skills canónicas viven en `.claude/skills/` y las
  `.agents/skills/` para Codex; no son entradas breves generadas.
- `scripts/evidence_store.py`: recibos JSON, hashes de evidencia y estados.
- `scripts/research_memory.py`: memoria SQLite aislada por workspace de
  programa.
- `scripts/hermes_swarm.sh`: wrapper de Kanban para Hermes. El wrapper está
  versionado aquí; los perfiles `SOUL.md` activos viven en WSL y deben
  verificarse allí.
- `orchestrator.py`: ruta heredada, conservada por compatibilidad; el flujo
  actual se documenta en `docs/MULDERX_ARCHITECTURE.md`.

## Recon autorizado

Primero define el alcance en las reglas del programa. El scope sin wildcard es
exacto. Para incluir subdominios, declara el wildcard autorizado explícitamente:

```powershell
python scripts/bb_pipeline.py -d example.com --scope "*.example.com" --yes
```

`--scope example.com` cubre solo la raíz; `--scope "*.example.com"` cubre
subdominios y excluye la raíz. `--yes` afirma que la autorización ya fue
revisada. Si se omite, el comando pregunta antes de enviar requests. El
fingerprint y los recolectores rechazan hosts fuera de scope y redirecciones
que salgan del alcance.

Para recolectores focales:

```powershell
python scripts/sourcemap_recon.py https://app.example.com --scope app.example.com --yes
python scripts/wayback_js_recon.py app.example.com --scope app.example.com --yes
```

Las herramientas de fuzzing y descubrimiento ampliado se ejecutan por separado
y solo con autorización expresa.

## Evidencia y memoria por programa

```powershell
python scripts/evidence_store.py init --workspace targets/example-program
python scripts/evidence_store.py validate --workspace targets/example-program
python scripts/research_memory.py init --workspace targets/example-program --program-id example-program
python scripts/research_memory.py search --workspace targets/example-program --program-id example-program --query React
```

Consulta [`docs/evidence-store.md`](docs/evidence-store.md) para crear leads,
registrar capturas y avanzar estados. El gate de Ocelot/reporter exige recibos
estructurados válidos; el Markdown permanece como vista para personas.

## Verificación local

```powershell
python -m unittest discover -s tests -v
python scripts/benchmark_taint_tracker.py
python scripts/sync_codex_agents.py --check
python scripts/sync_codex_skills.py --check
```

La auditoría, arquitectura, plan pendiente y resultados acotados del benchmark
están en `docs/MULDERX_AUDIT.md`, `docs/MULDERX_ARCHITECTURE.md`,
`docs/MULDERX_IMPROVEMENT_PLAN.md` y `docs/MULDERX_BENCHMARK.md`.
