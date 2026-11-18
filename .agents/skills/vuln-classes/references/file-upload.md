# File upload

## Baseline

Subí un archivo sintético y benigno, confirmá dónde se guarda, cómo se sirve,
el `Content-Type`, `Content-Disposition` y si se transforma o procesa de forma
asíncrona.

## Hipótesis

Separá validación de extensión, content type, magic bytes, nombre, path
normalization, extracción de archivos y serving. Usá archivos inertes; no
subas web shells, payloads ejecutables ni polyglots con comandos contra un
target real.

Si el archivo se sirve como SVG/HTML interpretado, derivá a `xss-hunt`. Si el
servidor importa una URL, derivá a `ssrf`. Si extrae un archivo comprimido,
considerá traversal solo con un fixture inocuo y autorización explícita.

## Confirmación

Upload aceptado no es finding. Se necesita ejecución confirmada, escritura
fuera del directorio esperado, lectura no autorizada o un sink de contenido
interpretado con impacto demostrable. Si se sirve estático y descargable con
controles correctos, registrá el killer específico.
