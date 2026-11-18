# Catálogo de design flaws — inputs unkeyed clásicos

Headers y cookies que un cache suele ignorar al armar la key, pero que
el backend sí procesa. Batería probada en la práctica (4 labs
distintos, todos resueltos): probar cada uno con y sin un segundo
valor de control, comparando `Content-Length`/status/body contra un
baseline con el mismo cache buster.

## Headers de host/forwarding — candidato #1 siempre

El más común y el de mayor impacto cuando funciona (controla URLs
absolutas, redirects, canonical links).

| Header | Qué suele controlar | Notas |
|---|---|---|
| `X-Forwarded-Host` | Host usado para armar URLs absolutas | El más documentado — probarlo primero, pero NO asumir que es el único. |
| `X-Host` | Igual que arriba | No estándar, no está en ninguna lista de "headers de proxy conocidos" — solo aparece por fuzzing. Confirmado como el vector real en un lab donde `X-Forwarded-Host` no tenía ningún efecto. |
| `X-Forwarded-Server` | Similar | |
| `X-HTTP-Host-Override` | Similar | |
| `X-Original-Host` | Similar | |
| `X-Rewrite-URL` | Reescribe la URL interna | Puede combinarse con path-based bugs. |
| `X-Original-URL` | Similar | |
| `Forwarded` (RFC 7239, formato `host=...;proto=...`) | Formato estándar que agrupa host/proto/for | Probar el formato completo, no solo el nombre del header. |

## Headers de esquema/protocolo — casi nunca tienen efecto solos

Estos rara vez cambian algo por sí solos, pero habilitan una rama de
código (típicamente un redirect de "upgrade a HTTPS") que se vuelve
peligrosa SOLO cuando se combina con un header de host. Ver técnica de
"multiple headers" en `SKILL.md` paso 2.

| Header | Qué suele controlar |
|---|---|
| `X-Forwarded-Scheme` | Fuerza redirect si el valor no es `https` |
| `X-Forwarded-Proto` | Igual, nombre alternativo |
| `Front-End-Https` | Legacy (IIS/ASP.NET), igual función |

Metodología: probar cada uno de estos SOLO primero (esperar sin
efecto), después combinado con `X-Forwarded-Host`/`X-Host` con un
valor de host malicioso — recién ahí suele aparecer el `302` con
`Location` controlado.

## Headers de IP/cliente — impacto típicamente menor (bypass de rate-limit/geo), pero probar igual

| Header | Qué suele controlar |
|---|---|
| `True-Client-IP` | IP reportada al backend (bypass de rate-limit, geo-block, WAF por IP) |
| `X-Client-IP` | Similar |
| `X-Real-IP` | Similar |
| `X-Forwarded-For` | Similar, el más conocido |

## Otros headers de valor probado

| Header | Qué suele controlar |
|---|---|
| `Referer` | A veces reflejado en "volver a" / breadcrumbs / analytics |
| `Accept-Language` | Contenido localizado — impacto bajo salvo que se refleje sin sanitizar |
| `Origin` | Poco común como unkeyed, probar igual |
| `X-Wap-Profile` | Legacy mobile-detection, a veces reflejado |

## Cookies — mismo principio, nombres no estándar son la pista

No asumir que solo la cookie de sesión importa. Cookies con nombres
que sugieren infraestructura interna (`fehost`, `datacenter`,
`edge`, `pop`, `region`, cualquier nombre que no sea `session`/`auth`/
`token`) son candidatas fuertes — probablemente pensadas para uso
interno del balanceador/cache, filtradas sin querer al cliente vía
`Set-Cookie`, y con buena probabilidad de ser unkeyed + reflejadas sin
sanitizar (visto en producción: reflejo directo en un `<script>`
inline sin `JSON.stringify`, rompible con `"}</script><script>`).

## Metodología de barrido sistemático

1. Fijar un baseline: `curl -s -D - "$BASE/?cb=<random>"` — anotar
   `Content-Length` y status.
2. Para cada header candidato: request de control (mismo path, cb
   nuevo, sin el header) + request de ataque (mismo cb pattern,
   distinto valor, CON el header) — comparar `Content-Length`/status.
   Cualquier diferencia = candidato a investigar con `diff` real de
   los bodies.
3. No descartar un header por no tener efecto solo — ver "Paso 2" en
   `SKILL.md` sobre combinaciones de dos headers.
4. Automatizado: Burp Param Miner → "Guess headers" / "Guess cookies"
   corre esta misma lógica contra una wordlist mucho más grande —
   preferible cuando está disponible, esta tabla es la versión
   manual/curl para cuando no lo está.

## Ver también
- `SKILL.md` — loop de trabajo completo, gate de evidencia, manejo de
  `Vary` y técnica de filtración de User-Agent vía content injection.
