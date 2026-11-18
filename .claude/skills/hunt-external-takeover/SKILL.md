---
name: hunt-external-takeover
description: Hunting skill para external resource takeover — recursos externos (Telegram, Twitter/X, Discord, GitHub, dominios expirados, S3 buckets) referenciados desde targets en scope que ya no existen y pueden ser reclamados por un atacante. Gate de confirmación de 3 niveles. No confundir con subdomain takeover DNS-level (otro skill).
sources: internal (built from scratch, evidence-gate-first)
---

## Qué es esto y qué NO es

External takeover ≠ subdomain takeover. Acá el vector es un **recurso externo
referenciado desde el target** (link en footer, handle de soporte, redirect,
CSP allowlist, OAuth redirect_uri) cuyo titular ya no existe — y que un
atacante puede reclamar para impersonar a la marca o interceptar tráfico real.

El "broken link" es el síntoma. El finding es el **recurso reclamable con
contexto de confianza** (usuarios que clickean creyendo que es oficial, tokens
que llegan a una redirect_uri controlada, etc.).

**No aplica** a links rotos sin contexto de confianza (referencias internas
muertas, assets 404, imágenes rotas). Esos son bugs de mantenimiento, no
findings de seguridad.

## Gate de Confirmación — 3 niveles (no negociable)

**No avanza de nivel sin evidencia del nivel anterior.** Esto determina el
techo de severidad.

| Nivel | Qué probaste | Cómo | Techo de severidad |
|---|---|---|---|
| **1 — derivado** | El recurso externo referenciado no existe (404, handle libre, dominio expirado, bucket inexistente) | curl / browser / whois / plataforma correspondiente | **Informational / P4** |
| **2 — verificado** | El recurso es **reclamable por vos** en este momento (handle disponible, dominio registrable, bucket creatable) | Confirmación en la plataforma (pantalla de "username disponible", registro real del dominio/bucket en entorno de test) | **P3** — superficie confirmada, falta demostrar impacto |
| **3 — verificado-completo** | Reclamaste el recurso y podés controlar el contenido que reciben los usuarios / sistemas del target | Canal/cuenta creada, dominio registrado, bucket con contenido controlado — PoC que demuestra el impacto concreto | **P1/P2** según impacto |

**Regla de oro:** "el link da 404" es Nivel 1, punto. No es "takeover
confirmado". Antes de escalar, preguntate: ¿puedo yo reclamar esto ahora
mismo, o ya lo tiene alguien más?

## Conocimiento previo

Use the `hexbrain` skill for relevant public prior art when it can change the test plan; verify any lead against primary sources and target evidence.

## Testing Flow

1. **Recolectar referencias externas** — spider del target, extraer todos los
   links que salen del dominio en scope. Foco en: footers, páginas de
   contacto/soporte, botones de redes sociales, JS con handles hardcodeados,
   CSP `connect-src`/`frame-src`, OAuth `redirect_uri` registradas.

2. **Filtrar candidatos** — quedarse con recursos en plataformas reclamables:
   Telegram, Twitter/X, Discord, GitHub (orgs/repos), dominios expirados,
   S3/GCS/Azure Blob buckets, npm packages, PyPI packages.

3. **Nivel 1** — verificar que el recurso no existe:
   - Redes sociales: browser / API pública / `t.me/<handle>`, `twitter.com/<handle>`, etc.
   - Dominios: `whois` + intentar resolución DNS.
   - Buckets S3: `curl https://<bucket>.s3.amazonaws.com` → `NoSuchBucket`.
   - npm/PyPI: `npm info <package>` / `pip index versions <package>` → not found.

4. **Nivel 2** — confirmar que está disponible para registro **sin registrarlo
   todavía** si es posible. En algunas plataformas (Telegram, Twitter) podés
   ver "username not found" sin necesidad de reclamar. Para dominios, verificar
   en registrar pero no comprar todavía.

5. **Nivel 3** — reclamar el recurso (en entorno controlado o directamente si
   el costo es bajo y el programa lo permite). Generar PoC de impacto concreto
   antes de reportar.

6. **Impacto** — ver Gate 0 abajo antes de tocar severidad.

## Gate 0 — Impacto (aplica en cualquier nivel, pero solo importa desde nivel 2)

1. **¿Qué contexto de confianza tiene el recurso?** — ¿Los usuarios llegan ahí
   creyendo que es oficial? ¿Hay tokens/datos que llegan a ese endpoint?
2. **¿Qué puede hacer el atacante con el control?** — phishing de usuarios
   reales, intercepción de OAuth tokens, distribución de malware bajo marca
   confiable, manipulación de contenido (canal de soporte falso).
3. **¿Se reproduce de punta a punta?** — demostrar que un usuario real
   llegaría al recurso controlado por el atacante siguiendo un flujo legítimo
   del target.

**Fuera de scope:** links rotos sin contexto de confianza, assets estáticos
404, referencias internas muertas sin salida al exterior.

## Objetivos de alto valor (orden de impacto)

1. **OAuth redirect_uri** apuntando a dominio expirado → intercepción de tokens → ATO
2. **Canal de soporte oficial** (Telegram, Discord) → phishing directo de usuarios con confianza máxima
3. **CSP allowlist** con dominio expirado → potencial XSS bypass si se puede servir JS desde el dominio reclamado
4. **npm/PyPI package** abandonado referenciado en dependencias del target → supply chain
5. **Handle de redes sociales** (Twitter/X, Instagram) → impersonación de marca, phishing
6. **S3/GCS bucket** huérfano referenciado en frontend → subdomain-style takeover de assets

## Señales rápidas de superficie de ataque

- Links a `t.me/`, `discord.gg/`, `twitter.com/` en footer o página de contacto
- `redirect_uri` hardcodeada en JS apuntando a dominio externo
- CSP con dominios externos en `connect-src`, `script-src`, `frame-src`
- Referencias a buckets S3 en `src`/`href` del HTML o JS
- `package.json` del target con dependencias a scopes npm poco mantenidos
- Dominios en whois con expiración reciente (< 6 meses) referenciados desde el target

Para checklist por plataforma y comandos de verificación →
`references/platform-checklist.md` *(pendiente de crear)*.

Prior art: consult the `hexbrain` skill when relevant to the concrete signal; verify sources and current scope.

## Related Skills & Chains

- **`domain-recon`** — identifica subdominios y dominios relacionados; complementario para encontrar referencias externas en JS.
- **`exposed-secrets`** — handles y endpoints hardcodeados en JS son la misma superficie; correr ambas skills sobre el mismo dump de JXScout.
- **`hunt-csrf`** — si el canal reclamado puede recibir requests autenticadas (OAuth callback), CSRF puede ser el siguiente eslabón.
- **`subdomain-takeover`** *(skill separada, no confundir)* — ese skill cubre DNS dangling (CNAME a servicio externo dado de baja). Este skill cubre recursos externos referenciados explícitamente desde el target.

