---
name: mulderx-rules
description: Adapta y enruta las reglas profundas de pentest-agents/rules al workflow de Mulderx por fase: planning, recon, triage, hunt, validation, judge y reporting. Usar cuando una etapa necesite doctrina operativa, anti-falsos-positivos, chaining, cobertura o técnicas específicas. No cargar todo el directorio ni usarlo para autorizar pruebas.
---

# Mulderx rules adapter

`pentest-agents/rules/` es una biblioteca de referencia, no una segunda
política de seguridad. Este adaptador decide qué parte consultar según la
etapa actual y conserva la precedencia de Mulderx:

```text
scope/policy + AGENTS.md
→ skill canónica y su evidence gate
→ reglas relevantes de pentest-agents/rules
→ hipótesis del agente
```

## Regla de carga

No leas todo `pentest-agents/rules/`. Abrí solo la fila correspondiente de
`references/rules-map.md` y, dentro de un archivo grande, solo la sección
indicada. Si una regla contradice scope, Q1–Q3, rate limits, stop conditions o
el rol del agente, gana Mulderx y la contradicción se documenta.

## Flujo de decisión

1. Identificá la fase real: setup, planning, recon, triage, hunt/validation,
   judge o reporting.
2. Cargá el paquete mínimo de reglas de esa fase.
3. Clasificá la señal con `vuln-classes` y cargá la skill especializada.
4. Cargá `payloads.md` o `techniques.md` solo después de identificar una
   clase y una superficie concreta.
5. Cargá `chain-table.md` solo después de un pass signal; no lo uses para
   inventar cadenas teóricas.
6. Devolvé qué reglas consultaste, qué cambió en la decisión y qué quedó sin
   probar.

## Ajustes obligatorios para Mulderx

- El gate de severidad es Q1–Q3 de Mulderx, no el gate de siete preguntas del
  repositorio externo.
- `/validate`, `/chain`, `brain.py` y `autopilot_gate.py` no se asumen
  disponibles. Usá los artefactos reales del target y las herramientas
  existentes.
- No se exfiltran cookies, tokens, credenciales cloud ni datos personales;
  usá canaries controlados y evidencia mínima.
- La matriz de cobertura es adaptativa: rate limit, autorización y riesgo
  prevalecen sobre una cantidad fija de combinaciones.
- `CONFIRMADO` requiere PoC funcional e impacto demostrado; un 200, una
  reflexión, una introspection o un filtro bypasseado son solo señales.
- Las reglas nunca habilitan fuzzing, descubrimiento de parámetros, acceso a
  regiones o acciones fuera del scope.

## Referencias

- `references/rules-map.md`: mapeo fase → archivo/sección → agente.
- `references/promotion-policy.md`: cómo promover aprendizajes de targets sin
  contaminar reglas globales.
