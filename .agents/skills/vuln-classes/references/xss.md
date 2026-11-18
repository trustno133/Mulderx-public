# XSS

## Regla principal

El contexto manda: HTML body, atributo, string JavaScript, URL, CSS, template
o DOM sink requieren canaries y payloads distintos. Identificá source,
transformaciones, sink y quién dispara el render antes de variar payloads.

## Secuencia

1. Confirmá reflexión o persistencia con un marcador inocuo.
2. Inspeccioná el contexto exacto y las codificaciones aplicadas.
3. Usá un payload mínimo y no destructivo para demostrar ejecución en el
   origen objetivo. No robes cookies, tokens ni datos de usuarios.
4. Solo si observás un filtro concreto, caracterizalo y cargá la referencia de
   bypass de XSS bajo demanda. No tires una lista de bypasses a ciegas.
5. Delegá en `xss-hunt`, que clasifica entre reflected, stored, DOM y blind.

## Confirmación y límites

Ejecución JavaScript en el contexto objetivo es evidencia de XSS; reflexión
sola, HTML inocuo o una alerta fuera del origen no prueba el impacto. Para
impacto, documentá qué privilegio o acción controlada queda demostrada sin
exfiltrar secretos.
