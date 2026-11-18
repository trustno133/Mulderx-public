# Catálogo de implementation flaws — manipulación de la cache key en sí

**Estado: no validado en sesión todavía.** A diferencia de
`design-flaws-catalog.md` (headers/cookies, probado en 4 targets
reales de sesión), lo de acá es conocimiento general de la técnica,
sin un caso propio resuelto de punta a punta. Tratarlo como punto de
partida, no como receta confirmada — al validar alguno en un target
real, documentar acá el caso concreto (igual que se hizo con el
catálogo de headers) en vez de dejarlo como teoría.

## Qué es esto

Categoría distinta de `design-flaws-catalog.md`. Ahí el problema es
"el backend usa un input que el cache ignora". Acá el problema es "el
cache y el backend NORMALIZAN la misma URL de forma distinta" — dos
requests que un humano vería como "la misma página" pueden mapear a
cache keys distintas para el cache pero al MISMO recurso para el
backend (o viceversa), y esa discrepancia es lo que se explota.

## Técnicas conocidas (a validar)

- **Query string unkeyed / parameter cloaking**: el cache incluye la
  query string completa en la key, pero el backend solo lee UN
  parámetro específico e ignora el resto — o al revés, el cache
  normaliza/ignora ciertos parámetros que el backend sí procesa.
  Probar: mismo path, mismo parámetro relevante, agregar parámetros
  extra con nombres random — si el cache trata cada combinación como
  única (miss cada vez) pero el backend responde igual, no hay bug de
  este tipo. Si el cache colapsa variantes que el backend trata
  distinto (o viceversa), hay poisoning.
- **Fat GET request**: mover parámetros de la query string al BODY de
  un GET (técnicamente inválido pero muchos servers lo aceptan). Si el
  cache solo considera la query string para la key pero el backend
  también lee el body, se puede envenenar una URL "limpia" con
  contenido controlado desde el body sin que aparezca en la key.
- **Cache key injection vía delimitadores**: header o parámetro que
  usa un delimitador (`;`, `#`, espacio codificado) para el cual el
  cache y el backend interpretan el límite del valor de forma
  distinta — permite "esconder" contenido después del delimitador que
  el backend sigue procesando pero el cache ignora al calcular la key.
- **Discrepancias de normalización de path**: `//`, `/./`, trailing
  slash, encoding de caracteres en el path — mismo principio, el cache
  normaliza a una key pero el backend rutea distinto.
- **Puerto unkeyed**: si la URL efectiva incluye puerto no estándar y
  el cache lo ignora al armar la key pero el backend sí lo usa para
  algo (poco común, pero catalogado por PortSwigger como
  `web-cache-poisoning-via-an-unkeyed-port`).

## Metodología sugerida (sin validar todavía)

1. Fijar un baseline con cache buster en la query string (`?cb=...`).
2. Probar variantes de la MISMA URL lógica que un humano consideraría
   idénticas pero que técnicamente difieren (orden de parámetros,
   parámetros duplicados, mayúsculas en el path, trailing slash,
   parámetros con valores vacíos) — comparar si el cache las trata
   como la misma entrada (mismo `X-Cache` state) o como entradas
   distintas, y si el backend responde igual o distinto en cada caso.
3. Cualquier mismatch entre "lo que el cache considera la misma key" y
   "lo que el backend considera la misma request" es un candidato —
   aplicar el mismo gate de evidencia de `SKILL.md` (reflexión →
   cacheado → servido a request limpia).

## Ver también
- `SKILL.md` — loop de trabajo, gate de evidencia.
- `design-flaws-catalog.md` — la otra mitad del catálogo (headers/
  cookies), esa sí validada en sesión.
