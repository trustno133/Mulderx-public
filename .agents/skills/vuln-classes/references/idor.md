# IDOR / BOLA

## Prerrequisitos

Usá dos cuentas autorizadas y datos sintéticos: actor A y actor B. Confirmá
qué recurso pertenece a cada una y guardá un baseline por actor.

## Secuencia

1. Ejecutá la operación como el dueño y anotá referencias a objetos en path,
   query, body, headers, cookies y variables GraphQL.
2. Repetí la misma operación como el otro actor usando solo IDs del recurso
   ajeno. No mezcles tokens reales en archivos.
3. Compará status, tamaño, cuerpo y efecto persistente. Un error genérico o un
   200 vacío no confirma acceso.
4. Si hay señal, revisá hermanos funcionales: GET, update, delete, export,
   share, archive, download e history; solo hasta el límite autorizado.
5. Si existen versiones API, compará versiones documentadas o ya observadas.
   No descubras rutas nuevas por fuzzing salvo pedido explícito.

## Variantes condicionadas

Probá ausencia de auth, IDs vecinos, IDs numéricos especiales, nested
resources, mass assignment, relationship spoofing y method override únicamente
si el endpoint o el framework observado lo hace plausible. En GraphQL,
considerá `node` y mutations, pero primero confirmá el formato real del ID.

## Evidencia y killer

Confirmación: el actor equivocado obtiene o modifica un recurso ajeno, o
produce un efecto observable sobre él. Killer: todos los hermanos relevantes
rechazan consistentemente el recurso ajeno y no queda un canal alternativo
observado. Un UUID no enumerables no es killer por sí mismo.
