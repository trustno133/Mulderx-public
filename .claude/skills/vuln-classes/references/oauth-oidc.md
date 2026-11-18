# OAuth / OIDC

## Checks

Mapeá el flujo real antes de variar parámetros: `redirect_uri`, `state`, PKCE,
code reuse, nonce, issuer, audience y binding entre cliente y callback.
Usá una cuenta y un cliente de prueba autorizados.

## Variantes condicionadas

Probá redirect URIs alternativas solo contra callbacks del programa y con un
endpoint de recepción controlado. Las diferencias de subdominio, path,
fragment, encoding y normalización sirven para detectar validaciones débiles,
pero no deben redirigir tokens o códigos reales a terceros.

## Confirmación

El impacto debe demostrar login de una cuenta equivocada, mezcla de cliente,
reutilización de código o exposición de un token/código dentro del entorno
controlado. Falta de PKCE en un cliente que no lo requiere, redirect URI
rechazada o parámetros visibles sin impacto no son findings por sí solos.
