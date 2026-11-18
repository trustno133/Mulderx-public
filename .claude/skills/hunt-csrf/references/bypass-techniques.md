# Bypass Techniques por tipo de defensa

Cada bypass acá te lleva como máximo a **nivel 1** por sí solo — confirmar
en nivel 2/3 antes de reportar severidad real.

| Defensa | Bypass | Nota |
|---|---|---|
| `SameSite=Lax` | Navegación top-level por GET sigue funcionando; si la acción sensible acepta GET (o un redirect POST→GET la convierte), Lax no protege. Subdominios igual pueden setear cookie para el dominio padre. | Confirmar que la acción realmente acepta GET, no asumir. |
| Token presente | Token estático por sesión (robable vía XSS/Referer/cache); token no validado server-side (sacarlo y probar); validado solo por formato, no por valor real; token atado a sesión predecible. | Cada una de estas es una hipótesis separada — probarlas una por una, no asumir cuál aplica. |
| `Content-Type: application/json` enforcement | `enctype="text/plain"` con nombres de campo armados para producir JSON válido — sin preflight, cookies viajan. | Ver payload-catalog.md nivel 3. |
| Check de Referer/Origin | Null origin vía iframe sandboxed; bypass de subdominio si `*.target.com` es confiable y hay XSS en cualquier subdominio; Referer se pierde en transición HTTPS→HTTP; matching débil tipo `target.com.evil.com` pasa un string-match naif; dominio target como substring en cualquier posición del Referer (path o query del atacante) si el check es un `.includes()` sin anclar. | El matching débil es exactamente el patrón de nivel 1 — no asumas que el check real (browser) lo replica sin probarlo en nivel 2. |
| Double-submit cookie | Si el atacante puede setear cookies (subdomain takeover, cookie injection HTTP) puede fijar cookie y campo del form con el mismo valor atacante-controlado. | Requiere una primitiva adicional (takeover/injection) — es un chain, no CSRF puro. |
| Header custom (`X-Requested-With`) | Simple requests (form POST, `text/plain`) no disparan preflight y no pueden setear headers custom — pero algunos servers solo chequean *presencia* del header, no valor. | Probar con y sin el header antes de descartar. |

## Nota metodológica — curl no es nivel 2, aunque parezca

Un bypass de Referer/Origin que depende de que el dominio target aparezca
en el **path o query** de la URL (no solo el origen) puede dar falso
positivo en curl y falso negativo en el browser real. curl manda
literalmente el header que le pidas. Chrome con la Referrer-Policy default
(`strict-origin-when-cross-origin`) recorta el Referer a **solo el origen**
(scheme+host+port) en cualquier request cross-origin — nunca manda path ni
query, sin importar qué URL tenga la página que dispara el request.

Si el bypass depende de contenido más allá del origen bare, confirmar
nivel 1 con curl no prueba nada sobre nivel 2/3. Para que el PoC real
funcione hay que forzar la política de referrer de la página atacante:

```html
<meta name="referrer" content="unsafe-url">
```

Sin ese meta tag, un PoC que "debería" andar porque el string pasó la
validación en curl puede fallar en silencio contra el victim real — el
form se envía, pero sin el path/query, y el chequeo del lado server
rechaza. Confirmar SIEMPRE nivel 2/3 end-to-end antes de dar por buena una
técnica de este tipo, no solo el curl inicial.

## Root causes comunes (para reconocer el patrón rápido)

1. **Token estático por sesión** — se genera uno solo al login y se reusa en toda la sesión → filtrable.
2. **Token no atado a identidad** — válido server-wide o rota por schedule, no por usuario/sesión.
3. **Falta en endpoints "secundarios"** — login/signup protegidos, pero import flows, webhooks, o API endpoints no.
4. **Asunción de que JSON-only es seguro** — cierto solo si el server rechaza `text/plain` y `x-www-form-urlencoded` también.
5. **`SameSite=None` por necesidad de embeds** — reintroduce CSRF a cambio de soportar iframes/integraciones third-party.
6. **`RelayState`/`state` de OAuth/SAML tratado como hint de redirect, no como CSRF token** — sin binding criptográfico.
7. **Middleware de framework deshabilitado** globalmente por error de deploy, o excluido a propósito en `/api/*` "porque los clientes API no lo necesitan" (pero un browser sí).
8. **Defaults de software third-party** (paneles de monitoreo, dashboards) con CSRF débil o ausente en versiones viejas — cruzar con `infra-panels-default-creds` para el fingerprint de versión.
