# Registro estructurado de hallazgos

Cada workspace de programa puede tener un `findings.json`. Los Markdown
`leads.md`, `judged.md` y `reports/` siguen siendo vistas para personas; el
gate de Hermes usa el registro JSON validado como fuente de estado.

## Inicializar y crear un candidato

```bash
python scripts/evidence_store.py init --workspace targets/<programa>
python scripts/evidence_store.py create --workspace targets/<programa> --json targets/<programa>/staging/L01.json
```

La plantilla completa está en `docs/examples/finding.candidate.json`. El JSON
de entrada debe estar dentro del workspace. `create` fuerza el estado inicial
`CANDIDATE` y una historia vacía; no admite crear directamente un confirmado.
Use IDs `L01`, `L02`, etc. sin repetirlos.

Un lead no probado sigue como `CANDIDATE`; durante una validación autorizada,
usa `TESTING`. Reserva `DISCARDED` para una hipótesis refutada por evidencia
de una prueba ejecutada. Si faltan autorización, acceso, cuenta o datos, usa
`BLOCKED`; si la prueba quedó inconclusa, usa `INSUFFICIENT`. Para candidatos,
guarda en `leads.md` una PoC propuesta o pasos de reproducción y marca
`NO EJECUTADA` hasta observar el resultado en el target.

La transición a `DISCARDED` se rechaza si no hay `NOT_REPRODUCIBLE`, un intento
de refutación con `action` y `result`, y un recibo de evidencia `disproof`.
La validación general sigue aceptando recibos históricos; no los migra ni los
reescribe automáticamente.

## Añadir evidencia y completar la validación

Guarde evidencia local en el workspace, sin cookies, tokens ni claves. Registre
cada archivo para calcular su SHA-256:

```bash
python scripts/evidence_store.py record --workspace targets/<programa> \
  --lead-id L01 --kind baseline --path evidence/L01-baseline.txt \
  --description "Respuesta de baseline antes de la prueba"
```

Los tipos que habilitan `CONFIRMED` son `baseline`, `execution`,
`verification` e `impact`. El registro `update` permite modificar campos de
investigación y Q1–Q3, pero no permite cambiar ID, estado, historial ni lista
de evidencia. Las transiciones se hacen explícitamente:

```bash
python scripts/evidence_store.py update --workspace targets/<programa> \
  --lead-id L01 --json targets/<programa>/staging/L01-update.json
python scripts/evidence_store.py transition --workspace targets/<programa> \
  --lead-id L01 --to TESTING --actor liquid --reason "Comienza validación acotada"
python scripts/evidence_store.py transition --workspace targets/<programa> \
  --lead-id L01 --to CONFIRMED --actor liquid --reason "Reproducción e impacto verificados"
python scripts/evidence_store.py validate --workspace targets/<programa>
```

Para el juez, Ocelot continúa read-only. Después de que produzca `judged.md`,
Mulderx registra el archivo como evidencia `judge` y registra su veredicto:

```bash
python scripts/evidence_store.py record --workspace targets/<programa> \
  --lead-id L01 --kind judge --path judged.md --description "Revisión adversarial de Ocelot"
python scripts/evidence_store.py review --workspace targets/<programa> \
  --lead-id L01 --verdict APPROVED --summary "Veredicto y motivo desde judged.md"
python scripts/evidence_store.py transition --workspace targets/<programa> \
  --lead-id L01 --to REVIEWED --actor mulderx --reason "Veredicto de Ocelot registrado"
python scripts/evidence_store.py transition --workspace targets/<programa> \
  --lead-id L01 --to APPROVED --actor mulderx --reason "Aprobación validada"
```

Una revisión `REJECTED` debe terminar en `DISCARDED`; `INCOMPLETE` queda
pendiente y no abre el gate del reporter. No se debe registrar `APPROVED` para
un veredicto distinto.

## Garantías y límites

- El validador comprueba campos, estados, cadena de transiciones, rol del
  actor, rutas dentro del workspace y hashes actuales de evidencia.
- `mulderx_metrics.py gate --stage judge` solo cuenta `CONFIRMED` si el store
  entero es válido. El reporter exige un finding estructurado `APPROVED`.
- `source=tool_capture` y `source=operator_capture` describen el origen
  declarado por el operador. Actualmente no existe un colector firmado que
  certifique quién creó el archivo. Los hashes detectan cambios posteriores,
  no prueban que una captura haya venido del target o de una herramienta real.
- Un proceso con permiso de escritura sobre el workspace aún puede fabricar
  JSON e historial. Para una frontera de confianza fuerte hace falta separar
  permisos o firmar recibos desde un colector local; esto queda como mejora
  pendiente y se documenta en la auditoría.
- Workspaces históricos sin `findings.json` no abren judge ni reporter hasta
  migrar sus leads con evidencia. El Markdown anterior se conserva.
