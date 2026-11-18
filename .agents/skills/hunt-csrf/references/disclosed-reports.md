# Disclosed Reports — CSRF

## Verificables (tienen link H1/GHSA — citables en un reporte)

1. **Argo CD — bypass SameSite=Lax vía subdominio hermano + abuso de Content-Type (CVE-2024-22424)**
   [GHSA-92mw-q256-5vwg](https://github.com/argoproj/argo-cd/security/advisories/GHSA-92mw-q256-5vwg) · [Writeup](https://blog.calif.io/p/argo-cd-csrf)
   Root cause: no forzaba `Content-Type: application/json`, y SameSite=Lax no importa si el atacante controla cualquier subdominio hermano del dominio padre compartido. Fix: 2.7.16/2.8.8/2.9.4 (ene 2024).

2. **GitLab — CSRF en `/api/graphql` vía mutations convertidas a GET**
   [H1 #1122408](https://hackerone.com/reports/1122408) — $3,370 (2021)
   Root cause: el backend saltaba la validación de `X-CSRF-Token` cuando el método HTTP era GET; GraphQL aceptaba mutations vía query string.

3. **Stripe Dashboard — middleware CSRF deshabilitado por error de deploy**
   [H1 #1483327](https://hackerone.com/reports/1483327) — $5,000 (2 investigadores, 2022)
   Root cause: deploy del 2022-02-14 apagó el middleware CSRF en todos los endpoints del Dashboard.

4. **GitHub Enterprise Server — bypass de token CSRF vía path traversal (CVE-2022-23732)**
   [H1 #1497169](https://hackerone.com/reports/1497169) — $10,000 (2022)
   Root cause: el router matcheaba el path post-traversal para ejecutar, pero el path pre-traversal para el scope de protección CSRF — el endpoint protegido se alcanzaba sin token válido.

5. **HackerOne (self) — CSRF en account linking → ATO**
   [H1 #1727221](https://hackerone.com/reports/1727221) — informational en programa propio, PoC público (2022)
   Root cause: token del callback de OAuth-link reusable o no atado al usuario — callbacks de link iniciados por el atacante se aceptaban en la sesión de la víctima.

## Duende BFF — superficie 2024-2026 (documentado, sin CVE directo hasta 2026-05)

Duende BFF (sucesor comercial de IdentityServer4) usa un primitivo de
antiforgery no estándar: header estático `X-CSRF: 1` en vez de token
atado a sesión/usuario. Fuentes: [docs.duendesoftware.com/bff](https://docs.duendesoftware.com/bff/),
[blog Duende mar-2025](https://duendesoftware.com/blog/20250325-understanding-antiforgery-in-aspnetcore).

- **`X-CSRF: 1` no está atado a rol** — un mismo BFF sirviendo `/admin/*` y `/user/*` no distingue: cualquier script same-origin con el header puesto llega a endpoints admin si la sesión de la víctima tiene ese rol. [docs.duendesoftware.com/bff/fundamentals/options](https://docs.duendesoftware.com/bff/fundamentals/options/)
- **SignalR/WebSocket como carve-out** — los WS del browser no pueden mandar headers custom, así que devs excluyen hubs SignalR de la antiforgery (`DisableAntiforgery()`). Eso abre CSRF-sobre-WebSocket. [DuendeArchive/Support#972](https://github.com/DuendeArchive/Support/issues/972)
- **Cookie de sesión con `Domain=.ejemplo.com`** — override común para compartir login entre subdominios, pierde la protección `__Host-`. Combinado con un subdomain takeover, se convierte en session fixation. [nestenius.se BFF cookie hardening](https://nestenius.se/net/bff-in-asp-net-core-3-the-bff-pattern-explained/)

Checklist si aparece un BFF de este tipo:
1. `curl https://target/bff/user -H 'X-CSRF: 1' -b '<session>'` → si dumpea claims/roles/tenant IDs, ya es info disclosure aparte.
2. Inspeccionar `Set-Cookie` en `/bff/login` callback — flag si `Domain=` está seteado (vs prefijo `__Host-`).
3. Desde sesión low-priv, replay de POSTs de partición admin con `X-CSRF: 1` (nivel 1 del gate — confirmar en nivel 2/3 antes de reportar).
4. Enumerar hubs SignalR/WS (`/hubs/*`, `/signalr/*`) sin `X-CSRF` — si upgrade a 101, viable CSWSH.

## Sin fuente verificada — NO citables en un reporte

Estos dos casos aparecieron en el md original sin link. Quedan acá como
ilustrativos de patrón (account-linking OAuth CSRF → ATO), pero **no los
uses como precedente en un reporte** hasta encontrar la fuente primaria:

- "Rockstar Games / SocialClub — Import Friends CSRF → account link no autorizado"
- "Oculus-Facebook — CSRF en callback de linking → ATO"

Si en algún momento encontrás el H1/writeup real de cualquiera de los dos,
promoverlos a la sección de arriba con link.
