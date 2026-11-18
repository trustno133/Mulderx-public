# Race conditions

## Candidatos

Priorizá efectos no idempotentes: cupones, transferencias, votos, creación de
cuentas, bonos, límites de uso y cambios de estado. Confirmá primero la
operación normal y sus invariantes.

## Prueba controlada

Usá datos de prueba y el menor paralelismo que permita distinguir una carrera.
Un pequeño lote concurrente, con requests identificables y cleanup, suele ser
suficiente; no uses una ráfaga fija de 20 o más si el programa no la autoriza.
Compará el estado final con un control secuencial y repetí solo si la primera
prueba muestra una anomalía.

## Confirmación

La carrera requiere efecto duplicado o una violación reproducible de una
invariante, no solo respuestas distintas o errores intermitentes. Documentá
ventana, número de requests, estado inicial/final, idempotency keys y cleanup.
Detenete ante rate limit, degradación o cualquier impacto económico real.
