# Plan priorizado de mejoras

## P0 — Controles de ejecución

1. Sustituir `--dangerously-skip-permissions` de la ruta heredada por permisos
   explícitos por agente y aprobación interactiva para acciones activas.
2. Ejecutar subprocesses en grupos cancelables y verificar que timeout o
   cancelación detengan el árbol completo.
3. Añadir un colector de evidencia local que guarde request/response con
   redacción de secretos y emita recibos firmados o de solo escritura; evitar
   que un LLM pueda autodeclarar `tool_capture`.
4. Separar estrictamente la ejecución activa del contenido no confiable del
   target; confirmar que cada runtime aplica límites, no solo los prompts.

## P1 — Integración y recuperación

1. Definir JSON Schemas para task/result envelopes (task-id, agente, scope,
   entrada, acciones permitidas, presupuesto, estado, errores, evidencia y
   próximo paso) y validarlos en las rutas Claude, Codex y Hermes.
2. Hacer que el wrapper Hermes espere estado terminal, reintente solo acciones
   idempotentes y persista un checkpoint antes/después de cada etapa.
3. Sincronizar o validar perfiles Hermes externos con los contratos versionados
   y fallar si están desactualizados; hoy WSL queda fuera del ciclo de sync.
4. Añadir migrador de leads Markdown existentes a `findings.json` con estados
   `CANDIDATE` por defecto; exigir nueva evidencia antes de promover.
5. Probar aislamiento y locks entre procesos Windows y Linux, además de las
   pruebas concurrentes por threads ya existentes.

## P2 — Calidad de hunting y memoria

1. Ampliar el corpus JS con fixtures de sanitizers, contextos HTML/URL/JS,
   fuentes de postMessage/storage, control flow y casos minificados; comparar
   regex y AST. El benchmark actual muestra falsos positivos conocidos.
2. Añadir validación de reachability de sinks y evidencia de contexto DOM; no
   elevar severidad basándose solo en patrones o versiones.
3. Conectar automáticamente los eventos de recon/hunt con SQLite, con filtros
   por endpoint, tecnología, clase, relación y resultado de descarte.
4. Mantener perfiles por tecnología/WAF para elegir pruebas autorizadas de
   bajo impacto; no convertir el perfilado en evasión de bloqueos.

## P3 — Operación y eficiencia

1. Añadir tokens, modelo, coste estimado, duración, errores, retries y número
   de tools al envelope; medir costo por finding que Ocelot conserva.
2. Presupuestos por rol y selección de modelo después de construir una línea
   base de calidad, no antes.
3. Doctor ampliado con diagnóstico de Hermes dentro de WSL, versiones de CLI y
   disponibilidad de herramientas por etapa, sin ejecutar scans.
4. Publicar instalación reproducible para Python/Node/Go y entornos Windows,
   WSL y Linux; fijar versiones después de comprobar compatibilidad real.

## Criterio para cerrar cada ítem

Cada mejora debe tener un test local o contrato verificable, una descripción
de límites y evidencia de ejecución. No se reportará una mejora de precisión
sin un dataset más amplio con etiquetas independientes y comparación contra
una línea base.
