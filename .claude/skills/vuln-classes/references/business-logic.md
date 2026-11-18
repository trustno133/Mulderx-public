# Business logic

## Modelo

Escribí el flujo esperado, actor, recurso, precondiciones, estado inicial,
transición y efecto final. Después compará qué acepta el servidor, no solo qué
permite la UI.

## Candidatos

Precio o cantidad manipulable, pasos omitibles, cambios de estado fuera de
orden, confusión de privilegios o tenant, cuotas, límites de uso, referencias
parent/child y campos privilegiados enviados por mass assignment.

## Confirmación

Reproducí la violación con datos sintéticos y cleanup. Un campo aceptado sin
efecto, un estado no visible o una respuesta 200 no demuestran impacto. Si la
acción afecta dinero, votos, cuentas o datos de terceros, frená después de la
prueba mínima y documentá el alcance observado.

Delegá en `business-logic` cuando haya workflow autenticado, roles, precios,
cuotas o transiciones de estado.
