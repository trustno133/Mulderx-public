# SSRF

## Puntos de entrada

URL parameters, webhooks, imports remotos, previews, image/PDF fetchers y
procesadores asíncronos son candidatos. Primero confirmá que el servidor, y no
el navegador, hace el fetch.

## Secuencia

1. Usá un callback OOB controlado y único para confirmar DNS o HTTP callback.
2. Correlacioná timestamp, token y componente; una resolución local del
   navegador no es evidencia.
3. Solo con callback confirmado y autorización explícita, evaluá destinos
   internos de bajo impacto y respuestas limitadas. No recolectes secretos,
   credenciales cloud ni datos de producción.
4. Si hay filtro, caracterizá primero qué normaliza o decodifica. Las variantes
   IPv4, IPv6, decimal, hexadecimal, redirect y DNS rebinding son hipótesis
   condicionadas a la evidencia y al scope.

## Confirmación y cierre

SSRF confirmada requiere request server-side controlable y callback o respuesta
observable atribuible al target. Un campo que acepta una URL, un error de
parsing o un timeout aislado no alcanza. Registrá el destino, componente,
correlación y límites de impacto; no incluyas tokens OOB reales en el reporte.
