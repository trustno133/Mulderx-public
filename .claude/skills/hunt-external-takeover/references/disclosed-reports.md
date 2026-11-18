# disclosed-reports.md — hunt-external-takeover

Casos de referencia para external resource takeover. Solo se incluyen casos
con fuente verificable o resumen público. Los marcados `[ilustrativo]` no
tienen link directo al reporte original — no citar como evidencia concreta.

---

## Caso 1 — Yahoo! / Bitly link takeover
**Fuente:** https://hackerone.com/reports/2086495 (disclosed, requiere login)  
**Resumen público:** Un link de Bitly referenciado en la descripción del handle
oficial de Yahoo en Twitter apuntaba a un destino expirado. El recurso era
reclamable y redirigía a un destino no controlado por Yahoo.  
**Vector:** Link corto externo (Bitly) referenciado desde perfil social oficial.  
**Impacto:** Brand impersonation — usuarios llegando al link desde el perfil
oficial de Yahoo podían ser redirigidos a contenido no controlado.  
**Estado:** Resuelto. Bounty pagado (monto no público).  
**Lección:** El finding no fue "link roto" — fue el contexto de confianza (perfil
oficial verificado de Yahoo) que convertía el link expirado en un vector real.

---

## Caso 2 — HackenProof / Twitter handle expirado → $250
**Fuente:** https://hackenproof.com/reports/HAC-858  
**Resumen:** El handle de Twitter oficial referenciado en el footer del sitio
de HackenProof apuntaba a una cuenta eliminada. El investigador registró el
handle y demostró control. El reporte menciona explícitamente el riesgo de
Telegram: usuarios buscando soporte podrían ser redirigidos a un canal falso
controlado por el atacante.  
**Vector:** Ícono de Twitter en footer → handle de Twitter expirado.  
**Impacto:** Brand impersonation, potencial phishing de usuarios de soporte.  
**Severidad pagada:** Medium → **$250**  
**Lección:** Incluso programas de seguridad (HackenProof es una plataforma de
bug bounty) tienen este problema. Severidad Medium confirma que "solo social
media" puede ser pagable con el contexto correcto.

---

## Caso 3 — Panther Labs / Twitter handle expirado
**Fuente:** https://hackerone.com/reports/1117079  
**Resumen:** El sitio de Panther Labs apuntaba a su handle de Twitter anterior
(desavowado) en lugar del nuevo. Un investigador registró ese handle y pudo
impersonar a la empresa.  
**Vector:** Link de Twitter en sitio oficial → handle viejo no reclamado.  
**Impacto:** Impersonación de marca. La empresa confirmó: "our website was not
updated to include our new twitter handle".  
**Estado:** Resuelto.  
**Lección:** El problema no siempre es cuenta eliminada — a veces es rebrand
sin cleanup. Buscar handles "viejos" en histórico de Wayback Machine.

---

## Caso 4 — Twitter (X) / GitHub account takeover en developer docs
**Fuente:** https://hackerone.com/reports/1031321  
**Resumen:** La página de developer docs de Twitter listaba una librería
JavaScript con un link a un GitHub user que ya no existía. El investigador
creó ese username en GitHub, tomando control del link desde documentación
oficial de Twitter.  
**Vector:** Link a GitHub username en documentación técnica oficial.  
**Impacto:** Un usuario siguiendo la doc oficial podría instalar código de un
repositorio controlado por el atacante.  
**Estado:** Resuelto.  
**Lección:** Documentación técnica (no solo footers) es superficie válida.
Links a GitHub users/orgs/repos son especialmente interesantes porque implican
confianza en código ejecutable.

---

## Caso 5 — Autodesk / Twitter broken link en thewild.com
**Fuente:** Telemetrio bug bounty channel feed (Autodesk, disclosed 2025-03-24)  
**Resumen:** Link de Twitter roto en thewild.com (subdominio Autodesk).  
**Severidad:** Low  
**Estado:** Resuelto.  
**Lección:** Autodesk lo triageó como Low, no Medium. El contexto de la página
(subdominio vs. página principal) afecta la severidad.

---

## Caso 6 — Broken Link Hijacking via short link (tiny.cc) [ilustrativo]
**Fuente:** https://mehedishakeel.medium.com/broken-link-hijacking-my-second-finding-on-hackerone-d715b0713fca  
**Resumen:** Short link (tiny.cc) referenciado desde un target en scope cuyo
destino ya no existía. Investigador reclamó el short link apuntándolo a su
perfil de HackerOne para demostrar control sin impacto real.  
**Vector:** Short link externo (tiny.cc) referenciado desde subdominio en scope.  
**Estado:** Resuelto en 30 minutos. Monto confidencial.  
**Nota técnica:** tiny.cc no acepta dominios arbitrarios como destino — el
investigador usó su perfil de H1 para pasar esa validación.  
**Lección:** Cada plataforma de short links tiene sus propias restricciones de
destino — verificar antes de asumir que cualquier URL es aceptada.

---

## Caso 7 — Instagram account takeover vía footer link [ilustrativo]
**Fuente:** https://medium.com/@josekuttykunnelthazhebinu/how-i-took-over-an-instagram-account-using-broken-link-hijacking-found-open-redirections-on-c03b0c62add6  
**Resumen:** Footer de subdominio corporativo apuntaba a
`instagram.com/abc.com` — cuenta inexistente. El investigador la creó. El
link pasaba además por un Google redirect (`google.com/url?q=...`) antes de
llegar a Instagram.  
**Vector:** Ícono de Instagram en footer de subdominio → cuenta inexistente.  
**Impacto:** Impersonación. Bounty no especificado (pentest / responsible
disclosure, no programa público).  
**Lección:** El redirect de Google no bloquea el finding — el destino final
sigue siendo reclamable. Vale la pena clickear los links, no solo extraerlos.

---

## Caso 8 — Bugcrowd / Dominio expirado con contenido inyectable → bounty pagado
**Fuente:** https://medium.com/@AlasdairGorniak/how-broken-link-hijacking-won-my-first-bug-bounty-a45a1d4b3438  
**Resumen:** Investigador identificó un dominio expirado referenciado desde un
target en Bugcrowd, lo registró en un dominio registrar, montó una landing
page de prueba y confirmó que el contenido se cargaba en el contexto del
target. Recibió payout. Luego encontró una segunda URL no parchada del mismo
issue y cobró de nuevo.  
**Vector:** Dominio externo expirado referenciado desde el target.  
**Impacto:** Inyección de contenido arbitrario en el contexto del sitio.  
**Estado:** Resuelto (en dos rondas). Bounty pagado (monto no especificado).  
**Nota técnica:** El scanner inicial fue bloqueado por Cloudflare — tuvo que
buildear su propio scraper para bypassear la protección.  
**Lección:** (1) Después de un fix, volver a revisar — el parche puede ser
incompleto. (2) Cloudflare bloquea scanners de broken links — herramientas
automatizadas estándar pueden no funcionar.

---

## Caso 9 — External JS file en dominio expirado → Stored XSS (patrón EdOverflow)
**Fuente:** https://edoverflow.com/2017/broken-link-hijacking/ (post original
que definió BLH como categoría)  
**Tipo:** Patrón documentado — no reporte único.  
**Resumen:** Si el target carga un archivo JS externo desde un dominio expirado,
quien tome ese dominio controla el JS ejecutado en el contexto del target.
Equivale a Stored XSS sin necesidad de injection — el browser lo carga solo.  
**Vector:** `<script src="//dominio-expirado.com/script.js">` en el HTML del target.  
**Impacto:** Stored XSS — ejecución de JS arbitrario en todos los visitantes.  
**Techo de severidad real:** P1/Critical con CSP permisiva o sin CSP.  
**Nota del autor original:** EdOverflow explícitamente advierte en el post que
desde su publicación muchos hunters reportan "broken social media links" como
si fueran este patrón — **no lo son**. El impacto de XSS por JS expirado es
órdenes de magnitud mayor que el de un handle de Instagram reclamable.  
**Lección:** Esta es la variante de mayor impacto de la skill. Buscar
`<script src>`, `<link href>`, y `<img src>` apuntando a dominios externos
antes de buscar links de redes sociales.

---

## Caso 10 — Dependency Confusion (Alex Birsan) → $130k+ en bounties
**Fuente:** https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610  
**Tipo:** Variante de supply chain — relacionado pero distinto a BLH clásico.  
**Resumen:** Publicó paquetes en npm/PyPI/RubyGems con el mismo nombre que
dependencias internas privadas de Apple, Microsoft, Shopify y otras 35
empresas. Los sistemas de build priorizaban el registro público sobre el
privado y ejecutaban el código del atacante automáticamente.  
**Bounties pagados:** $30k Apple, $30k Shopify, $130k+ total.  
**Vector:** Nombres de paquetes internos privados publicados en registro público.  
**Impacto:** RCE en infraestructura interna de build.  
**Relación con esta skill:** Si en un JS dump o `package.json` del target
aparecen dependencias a scopes npm inexistentes (especialmente scopes
corporativos privados), es superficie de dependency confusion — más grave que
un handle de Twitter.  
**Lección:** `@meli/`, `@united/`, `@wien/` en package.json valen más que
cualquier red social en el footer.

---

## Resumen de severidades observadas

| Contexto | Severidad típica | Bounty referencial |
|---|---|---|
| Handle social media (Twitter/Instagram) en footer | Low–Medium | $0–$500 |
| Handle social media de soporte oficial | Medium | $250–$1k |
| Short link expirado desde perfil oficial | Medium | confidencial |
| Dominio expirado con contenido inyectable | Medium–High | pagado |
| JS externo desde dominio expirado (Stored XSS) | High–Critical | variable |
| OAuth redirect_uri a dominio expirado | Critical | variable (P1) |
| Dependency confusion en packages internos | Critical | $30k+ |

---

## Señal de alerta del autor original (EdOverflow)

> "Since initial publication, many bug bounty hunters have referenced this
> blog post when reporting broken social media links to bug bounty programmes.
> The author advises against this behaviour and would encourage readers to
> focus on the more impactful attack vectors."

En criollo: reportar un Instagram roto sin más contexto probablemente sea N/A.
El valor real está en JS externo, OAuth callbacks, y dependency confusion.
