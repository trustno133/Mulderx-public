# Promotion policy

El contenido de `pentest-agents/rules/` se considera conocimiento externo al
workflow de Mulderx. Un aprendizaje de un target no se convierte
automáticamente en regla global.

## Puede promoverse cuando

- fue reproducido o refutado con evidencia concreta;
- no depende de un dominio, cuenta, token o dato secreto;
- cambia una decisión futura de forma útil;
- es compatible con scope, seguridad, Q1–Q3 y las skills canónicas;
- tiene una fuente y fecha de revisión.

## Destino

- regla de orquestación → `hunting-methodology` o `rules-map.md`;
- error recurrente de proceso → sección adecuada de `mistakes.md`;
- técnica de una clase → skill o referencia específica, no `AGENTS.md`;
- killer o never-submit → `never-submit.md` y el evidence gate afectado;
- señal dependiente del target → `targets/<programa>/discarded.md` o notas,
  nunca regla global.

## Formato mínimo

```text
Regla:
Motivo:
Evidencia de origen:
Alcance:
Excepciones:
Fecha de revisión:
```

No promover una observación porque un agente la repitió, porque el status fue
200 o porque una tecnología suele ser vulnerable.
