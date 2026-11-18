# Auth bypass

## Secuencia segura

1. Elegí un endpoint realmente protegido y establecé baseline con una cuenta
   autorizada y con una request anónima.
2. Quitá el header de autorización o usá una sesión expirada solo si el
   programa lo permite. Compará datos y efectos, no solo status.
3. Probá diferencias de método, content type, normalización de path y headers
   de method override únicamente cuando la request real los soporte.
4. Si aparece una señal, revisá hermanos del mismo controlador y versiones ya
   observadas, sin convertir esta guía en descubrimiento automático de rutas.

## Variantes

Case variation, slash/dot normalization, `X-HTTP-Method-Override`, método
alternativo y diferencias entre proxy y backend son hipótesis, no una lista
para disparar indiscriminadamente. No pruebes headers de confianza o rutas de
administración fuera del scope.

## Confirmación

Hay bypass cuando un actor sin el permiso requerido obtiene datos protegidos o
ejecuta una operación protegida con efecto observable. Un endpoint que solo
devuelve metadata pública, un mensaje diferente o un 200 vacío no basta.
