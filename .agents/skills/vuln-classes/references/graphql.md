# GraphQL

## Recon

For protocol-level schema and resolver work, use `graphql-audit` / `graphql_specialist`. Route object ownership to `idor-bola`, workflow mutations to `business-logic`, and injection to its class specialist.

Usá solo endpoints GraphQL observados o documentados. Introspection puede
ayudar a mapear el schema, pero por sí sola es informativa y no demuestra un
bug.

## Vectores

- autorización de queries, mutations y nested resources;
- referencias globales como `node` y IDs codificados;
- batch queries que cambien límites o rate limits;
- diferencias entre REST y GraphQL para el mismo objeto;
- profundidad, aliasing o tamaño de query solo si hay evidencia de DoS y el
  programa autoriza pruebas de carga controladas.

## Confirmación

Un hallazgo requiere leer o modificar un recurso ajeno, ejecutar una mutation
sin permiso, o demostrar otro impacto concreto. Schema visible, campos
internos o introspection habilitada sin impacto no bastan. Delegá el análisis
de ownership en `idor-bola` y el de estados en `business-logic` cuando
corresponda.
