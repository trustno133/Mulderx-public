# Skill: SAML Auth Bypass (XSW + Assertion Tampering)

Capa: Server-side/Behavior (según tu framework de 5 capas). Vive como skill propio,
separado de IDOR/BFLA — un solo root cause, un solo flujo de ataque: minteo/manipulación
de una SAML Assertion para suplantar identidad o escalar sesión.

## Cuándo se dispara
- Parámetro `SAMLResponse` (POST o GET) en cualquier endpoint
- Endpoint `/metadata`, `/saml/acs`, `/sso`, `/Shibboleth.sso/*`
- Cookies con patrón `_shibsession_*`, `JSESSIONID` + redirect a IdP externo
- Header `WWW-Authenticate` o redirect 302 hacia un dominio que resuelve a un IdP
  (Keycloak, ADFS, Okta, Shibboleth, or another federated identity provider)
- Cualquier login flow donde el POST final hacia el SP contenga XML base64

## Prerequisitos
1. Una sesión autenticada propia, válida, con el SAMLResponse completo capturado
   (vía proxy — Burp/mitmproxy/JXScout). Sin esto no hay baseline para diffear.
2. Si podés generar dos sesiones con dos cuentas de test distintas, mejor: te deja
   confirmar impersonation cruzada (cuenta A ve datos de cuenta B) en vez de solo
   bypass de firma.
3. Guardar el SAMLResponse legítimo decodificado (XML crudo) como baseline antes de tocar nada.

## Conocimiento previo

Use the `hexbrain` skill for relevant public prior art when it can change the test plan; verify any lead against primary sources and target evidence.

## Metodología (orden de ataque)
1. **Recon del SSO**: bajar `/metadata` si existe, identificar IdP, SP entityID,
   certs públicos, binding (POST vs Redirect), si usa Shibboleth/Keycloak/ADFS/PVP.
2. **Captura baseline**: un login normal, capturar el POST final al ACS
   (`AssertionConsumerService`) con el `SAMLResponse` válido. Guardar también la
   cookie de sesión resultante y la respuesta de un endpoint autenticado
   (ej `/api/me`) para comparar identidad después.
3. **Batería de variantes** (ver abajo) generadas desde ese baseline.
4. **Replay de cada variante** contra el ACS, un request por variante.
5. **Diffing**: comparar status code, longitud de respuesta, y sobre todo el
   `Set-Cookie` resultante — si el SP te setea sesión con una variante corrupta/alterada,
   ahí está el bypass.
6. **Confirmación de impacto**: con la cookie nueva, pegarle a un endpoint que
   devuelva identidad (`/api/me`, `/profile`) y confirmar que corresponde al
   usuario suplantado en el NameID alterado, no al tuyo.

## Variantes a probar (orden de prioridad por yield histórico)

| # | Técnica | Qué prueba |
|---|---------|------------|
| 1 | **Signature stripping** | Sacar `<ds:Signature>` entero. Si el SP igual setea sesión, no valida nada. |
| 2 | **XSW genérico (sibling duplication)** | Clonar la Assertion firmada, modificar el clon (NameID/atributos), insertarlo como primer hijo de `<Response>` dejando el original firmado como segundo hijo. Parsers ingenuos validan la firma del 2do pero procesan el 1ro. |
| 3 | **XSW wrapping en Extensions** | Mover la Assertion original firmada dentro de un `<Extensions>` de una Assertion forjada nueva. Variante más agresiva, cubre SPs que sí chequean "cuál assertion tiene firma" pero mal. |
| 4 | **NameID comment/CDATA injection** | `<NameID>admin<!---->@evil.com</NameID>` o con CDATA. El parser XML y la lógica de negocio pueden leer el nodo distinto. |
| 5 | **Duplicate Assertion ID** | Dos Assertions con mismo `ID`, una firmada legítima y otra forjada con el mismo ID — confunde el matching firma↔contenido en libs que indexan por ID. |
| 6 | **Algorithm/cert confusion** | Firmar con un cert propio (self-signed) si el SP no valida la cadena de confianza contra el cert del IdP real, solo que "haya firma". |
| 7 | **Replay** | Reenviar el SAMLResponse legítimo tal cual, minutos/horas después — confirma si falta validación de `NotOnOrAfter`/`Audience`. No es técnica de minteo pero suma para el reporte de "validación insuficiente" en general. |
| 8 | **Parser differential** | Si identificás que el SP usa una lib para extraer el NameID y otra (o el mismo motor en distinto modo) para validar la firma — típico en stacks Liferay/Shibboleth — las variantes de arriba tienen más chance de pegar. Documentar qué libs están en juego si se puede fingerprintear (headers, stack traces, error pages).

Las variantes 2 y 3 son una aproximación genérica al taxonomy clásico de XSW1–8
(Somorovsky et al.). Para la implementación byte-exacta de las 8 variantes
oficiales, usar SAMLRaider como referencia — ahí está el detalle estructural
de cada una validado contra implementaciones reales.

## Evidencia a loggear (clave para no inflar severidad)
- Request/response completo de la variante que funcionó (no solo "funcionó", el raw)
- Diff explícito: NameID/atributo alterado vs. el que vino en el baseline
- Prueba de que la sesión resultante corresponde al usuario suplantado — un
  endpoint `/me` o similar devolviendo otro email/ID/rol, no solo "me logueó"
- Si hay impacto más allá de auth (CRUD, lectura de datos de terceros), capturar
  ESO por separado como evidencia de impacto, no asumirlo del bypass solo
- Sin esto: Informational/P4 como mucho, por más que el auth bypass en sí sea real

## Falsos positivos comunes
- SP que acepta la variante pero no te da sesión nueva (solo no rechaza el POST,
  te vuelve a la pantalla de login) — no es bypass, es tolerancia de parseo nomás
- Session fixation: la cookie que ves después es la misma que tenías antes de
  mandar la variante (no se regeneró) — confirmá que cambió
- WAF/proxy devolviendo 200 genérico sin que la app procese nada — mirar el body,
  no solo el status code

## Chaining
Si el bypass funciona, encadenar inmediatamente con:
- IDOR/BFLA sobre el usuario suplantado (¿se puede elegir cualquier NameID arbitrario,
  o solo replicar uno que ya viste?)
- Si el NameID es predecible/enumerable (emails, IDs secuenciales), el bypass se
  vuelve impersonation masivo — subir severidad en base a ESO, documentado
- Revisar si el acceso resultante da lectura/escritura sobre backend (como el caso
  de Fran) — ahí el reporte tiene dos impactos: el bypass en sí + lo que destapa

## Referencias
- Somorovsky et al., "On Breaking SAML: Be Whoever You Want to Be" (paper original del taxonomy XSW1-8)
- SAMLRaider (Burp extension) — implementación de referencia
- PortSwigger Web Security Academy — SAML attacks
