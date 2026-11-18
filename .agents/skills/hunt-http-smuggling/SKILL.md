---
name: hunt-http-smuggling
description: Hunting skill para HTTP Request Smuggling — CL.TE, TE.CL, H2.CL, H2.TE. El front-end y el back-end discrepan sobre dónde termina un request. Usar cuando el target corre CDN/proxy/load-balancer delante de un origin. H2.CL/H2.TE es el vector dominante en 2024-2026 (CDN + origin HTTP/1.1).
sources: elementalsouls/Claude-BugHunter (hunt-http-smuggling), hackerone_public, portswigger_research
---

## Qué es esto y qué NO es

HTTP Request Smuggling = el front-end (CDN/proxy/LB) y el back-end (origin) interpretan diferente dónde termina un request HTTP — CL vs TE. El atacante "envuelve" un request malicioso al final del body legítimo; el back-end lo procesa como el inicio del próximo request entrante.

**No es**: un bug de autenticación ni de validación de input. Es un bug de parsing de protocolo HTTP. El impacto viene de las chains (cache poisoning, credential theft, auth bypass).

---

## Conocimiento previo

Use the `hexbrain` skill for relevant public prior art when it can change the test plan; verify any lead against primary sources and target evidence.

---

## Gate de Confirmación — no negociable

El efecto smuggled **tiene que aterrizar en un request de un cliente diferente**, no en tu propio follow-up. Un timing delta en tu propio browser = parser disagreement, no smuggling explotable.

Para reportar necesitás demostrar:
- Cache poisoning que afecta a otra víctima, O
- Credential theft: las cookies/Authorization de otro usuario llegan en tu response, O
- Auth bypass: request interno procesado sin los controles del front-end

---

## Matrix de suitability — fingerprinting del front-end primero

```bash
curl -sI https://target/ | grep -i "Server:\|Via:\|X-Cache:"
```

| Front-end | CL.TE | TE.CL | H2.CL | H2.TE | Notas |
|---|---|---|---|---|---|
| Nginx ≥ 1.21 | NO | NO | parcial | parcial | RFC-strict, rechaza CL+TE con 400 |
| Caddy 2.x | NO | NO | — | — | Endurecido por default |
| Envoy ≥ 1.20 | NO | NO | parcial | parcial | |
| HAProxy ≤ 2.4 | **SÍ** | **SÍ** | — | — | CVE-2021-40346 |
| AWS ALB + upstream específico | parcial | parcial | **SÍ** | **SÍ** | Varios reportes pagados 2022-2024 |
| Cloudflare → S3/Lambda | — | — | **SÍ** | **SÍ** | H2-downgrade viable |
| F5 BIG-IP (TMM < 16) | **SÍ** | — | — | — | |
| Citrix ADC/NetScaler antiguo | **SÍ** | **SÍ** | — | — | |
| Apache Traffic Server antiguo | **SÍ** | **SÍ** | **SÍ** | **SÍ** | |
| Python/Go proxies custom | **SÍ** | **SÍ** | — | — | Frecuentemente sin RFC enforcement |

**Decisión rápida:**
- `nginx/1.21+`, `Caddy`, `envoy` → CL/TE clásico muerto → pivoteá a H2.CL/H2.TE si el front habla HTTP/2
- `HAProxy`, CDN/AWS → correr la matriz de payloads completa
- Sin Server header → asumir endurecido, pero correr un probe `space-before-colon`; si no da 400, investigar

---

## H2.CL / H2.TE — el vector dominante hoy

La mayoría de stacks CDN+origin en 2024-2026 hablan HTTP/2 al cliente y HTTP/1.1 al origin. El downgrade introduce confusión CL/TE porque los frame-length headers de HTTP/2 no sobreviven la conversión limpiamente.

**Tools:**
- Burp Pro + HTTP Request Smuggler extension (preferido)
- `h2csmuggler` para H2-specific
- `smuggler.py` para variantes clásicas

**Evitar curl/raw sockets contra targets H2** — mandás el protocolo equivocado.

---

## Payloads de referencia

### CL.TE (front usa Content-Length, back usa Transfer-Encoding)
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### TE.CL (front usa TE, back usa CL)
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0


```

### TE.TE obfuscation (front procesa TE, back ignora versión obfuscada)
```http
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding:[tab]chunked
 Transfer-Encoding: chunked
X: X\nTransfer-Encoding: chunked
Transfer-Encoding
 : chunked
```

---

## Metodología

### Paso 1 — Fingerprint del stack
```bash
curl -sI https://target/ | grep -i "Server:\|Via:\|CF-Ray:\|X-Amz:\|X-Cache:"
```

### Paso 2 — Probe con Burp HTTP Request Smuggler
Right-click → Extensions → HTTP Request Smuggler → Smuggle probe

### Paso 3 — Confirmación manual con timing
Enviá el probe CL.TE y medí si el siguiente request propio tarda ~30s más de lo normal (back-end esperando el resto del body smuggled).

### Paso 4 — Confirmar con cliente diferente
El timing en tu propio cliente no basta. Necesitás que el efecto aterrice en otro cliente/sesión.

### Paso 5 — Escalación a impact chain (elegir según el target)

**Cache poisoning:**
Smugglé un request cuya response contenga HTML/JS del atacante → front-end cache lo almacena bajo una URL popular (`/`, `/login`).

**Credential harvesting (el "collector gadget"):**
Smugglé un request hacia un back-end handler que refleja headers completos (search, redirect). El siguiente request de otra víctima llega con sus cookies/Authorization atribuidas a tu request smuggled → las headers de la víctima aparecen en tu response.

**Auth bypass:**
Smugglé `GET /admin/internal HTTP/1.1` que el WAF del front-end filtraría → el back-end lo procesa como si viniera de un source confiable.

---

## Root causes comunes

1. Proxy/LB usa Content-Length, origin usa Transfer-Encoding (o viceversa)
2. H2 downgrade: front habla HTTP/2, origin HTTP/1.1 → confusión en frame-length
3. Front-end ignora TE headers obfuscados que el back-end acepta
4. Apache mod_proxy_ajp → Tomcat: HTTP→AJP desync (CVE-2022-26377)

---

## Chains y skills relacionadas

- **`cache-poisoning`** — La chain canónica: smuggled request → response cacheada para todas las víctimas subsiguientes. Uno de los impactos más críticos
- **`hunt-auth-bypass`** — Smuggling alcanza rutas internas que el WAF/auth-proxy del front-end bloquea
- **`idor-bola`** — Smuggling adjunta cookies de sesión de la próxima víctima a un path del atacante → session theft → IDOR con sesión ajena
- **`xss-stored`** — Payload smuggled en response stream → XSS para el próximo visitante sin URL parameter visible
