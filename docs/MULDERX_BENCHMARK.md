# Benchmark local de Mulderx

## Alcance

La evaluación disponible es un microbenchmark determinista del
`scripts/taint_tracker.py`. Usa nueve fixtures JavaScript creados para este
repositorio: cuatro flujos vulnerables conocidos y cinco muestras seguras
(contenido constante, `textContent`, sanitización y texto literal). Se ejecuta
localmente, sin red ni target, con:

```powershell
python scripts/benchmark_taint_tracker.py
```

## Resultado medido

| Métrica | Resultado |
|---|---:|
| Muestras | 9 |
| True positives | 4 |
| False positives | 3 |
| False negatives | 0 |
| True negatives | 2 |
| Precisión | 57,14% |
| Recall | 100% |

Falsos positivos observados: `safe_sanitized_html.js`,
`safe_string_literal.js` y `safe_variable_literal.js`. El tracker ve una
fuente textual y un sink, pero no entiende sanitización ni separa correctamente
todos los literales de código. Por eso sus alertas son candidatos, no
confirmaciones.

## Interpretación y límites

El recall 100% solo significa que encontró las cuatro muestras vulnerables de
este fixture. Nueve ejemplos hechos a mano no representan frameworks,
bundlers, control flow, contexto de navegador, configuración de sanitizers,
minificación real ni distribución de targets. No se midió tiempo hasta un
finding, precisión de agentes, costo de modelos, falsos positivos de bounty ni
calidad aprobada por Ocelot.

La suite automatizada tiene 30 pruebas locales, incluyendo scope/redirecciones,
ciclo de vida de evidencia, locks, aislamiento de memoria y regresiones del
orquestador. Esas pruebas de ingeniería verifican comportamientos, no miden
eficacia de hunting.

## Próxima línea base

Antes de comparar una versión nueva, ampliar y etiquetar fixtures por fuente,
sink, sanitizer, contexto, framework y resultado esperado; ejecutar regex y
AST con el mismo set; publicar la matriz por categoría, falsos positivos y
falsos negativos. La mejora se declara solo contra esa línea base repetible.
