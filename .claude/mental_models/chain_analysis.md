# Chain Analysis — Razonamiento de Encadenamiento

Dos modos de uso:
- **Oportunista**: tengo N leads documentados → ¿alguno se combina con otro?
- **Dirigido**: tengo un hallazgo puntual → ¿con qué lo escalo a P1/P2?

**Regla de uso**: el encadenamiento es la jugada de mayor valor cuando
aparece, pero un hallazgo aislado con PoC real en P3 ya es reportable.
No demorar el reporte esperando una cadena que puede no aparecer nunca.

**Regla de evidencia**: cada eslabón de la cadena necesita su propia
evidencia. No asumir que porque A es posible y B es posible, A→B es
posible. Cada link se confirma por separado.

---

## PARTE 1 — Chain Oportunista

### Cómo usarlo

Cuando hay 2+ leads documentados en el target, cruzarlos contra esta
matriz antes de cerrar la sesión. No hacer el cruce "a ojo" — recorrer
la matriz sistemáticamente.

El cruce se hace en dos pasos:
1. Clasificar cada lead existente por tipo (columna izquierda)
2. Para cada lead, buscar en la fila correspondiente qué otros tipos lo escalan

---

### Matriz de combinaciones de alto valor (P1/P2)

#### XSS (reflejado, stored, DOM) +

| Combinado con | Resultado | Severidad |
|---|---|---|
| Cookie sin HttpOnly | Robo de sesión directo desde el XSS | P1 ATO |
| CSRF ausente | Acción forzada en nombre de víctima sin interacción extra | P2 |
| Open redirect | Exfiltración de tokens OAuth via redirect post-XSS | P1 ATO |
| Subdominio con CORS permisivo | XSS en sub → leer datos del dominio principal | P1 |
| postMessage sin origin check | XSS en página embedida → escala al padre | P1/P2 |
| Panel de admin accesible | XSS stored que pega al admin = ATO de admin | P1 |
| Token en localStorage | XSS roba token de larga duración | P1 ATO |

#### IDOR/BOLA (lectura) +

| Combinado con | Resultado | Severidad |
|---|---|---|
| Campo de email/password en el recurso | Leer email → ATO via reset | P1 ATO |
| PII sensible (DNI, tarjeta, dirección) | Data breach de usuario individual | P2/P1 |
| Token de sesión o API key del recurso | Tomar la sesión directamente | P1 ATO |
| IDOR de escritura en mismo recurso | Leer + modificar = ATO completo | P1 |
| Enumeración de IDs (secuencial) | IDOR masivo → data breach de todos los usuarios | P1 |

#### IDOR/BOLA (escritura) +

| Combinado con | Resultado | Severidad |
|---|---|---|
| Campo de email | Cambiar email de víctima → ATO via reset | P1 ATO |
| Campo de password | Cambiar password directamente | P1 ATO |
| Campo de rol | Escalar a admin | P1 |
| Campo de webhook/notification URL | SSRF via configuración de víctima | P2 |
| Sin verificación de impacto real | No es chain — verificar primero que el cambio afecta a la víctima | — |

#### SSRF (ciego) +

| Combinado con | Resultado | Severidad |
|---|---|---|
| Cloud metadata accesible (169.254.169.254) | Credenciales IAM → acceso a AWS/GCP/Azure | P1 |
| Servicio interno sin auth | Pivot a red interna | P1/P2 |
| Redis/Memcached interno | RCE via SSRF→Redis | P1 |
| SSRF full-read | Leer archivos internos, configs, secrets | P1/P2 |
| Otro SSRF en distinto endpoint | Confirmar patrón de red interna, aumenta confianza | P2 |

#### SSRF (full-read) +

| Combinado con | Resultado | Severidad |
|---|---|---|
| Kubernetes metadata | Token de service account → cluster takeover | P1 |
| AWS IMDS v1 | IAM role credentials → AWS takeover | P1 |
| Servicio interno con auth bypass por IP | Acceso completo al servicio interno | P1 |
| Lectura de `.env` / configs | Credenciales de DB, API keys, secrets | P1 |

#### Open Redirect +

| Combinado con | Resultado | Severidad |
|---|---|---|
| OAuth flow (redirect_uri laxa) | Robo de authorization code | P1 ATO |
| XSS reflejado en el destino | XSS fuera del dominio original | P2 |
| Phishing de alta credibilidad | URL del target redirige a phishing | P3 (por sí solo) |
| Token en URL que se filtra por Referer | Robo de token via redirect | P1/P2 |

#### Information Disclosure (versión, stack, path) +

| Combinado con | Resultado | Severidad |
|---|---|---|
| CVE conocido para esa versión exacta | Explotación directa | P1/P2 |
| Path absoluto + LFI | Path traversal dirigido | P2 |
| Credenciales en respuesta | Acceso directo | P1 |
| Estructura interna + SSRF | SSRF dirigido a servicios internos conocidos | P2 |

#### Auth Misconfiguration (JWT alg:none, ROPC, implicit flow) +

| Combinado con | Resultado | Severidad |
|---|---|---|
| JWT alg:none + endpoints sensibles | Forjar token de cualquier usuario → ATO masivo | P1 |
| ROPC habilitado + user enumeration | Password spray sin MFA | P2 |
| Implicit flow + open redirect | Token leak en URL | P1 |
| SSO misconfiguration + account linking | ATO via IdP confusion | P1 |

#### GraphQL introspección abierta +

| Combinado con | Resultado | Severidad |
|---|---|---|
| Mutations de admin sin auth check | BFLA directo | P1/P2 |
| IDOR en argumentos de query | Data de otros usuarios | P2 |
| Sin depth limit + datos sensibles | DoS + data exposure | P2/P3 |
| Batch queries + login endpoint | Rate limit bypass → brute force | P2 |

#### Subdomain takeover +

| Combinado con | Resultado | Severidad |
|---|---|---|
| Cookie de sesión con scope `*.dominio.com` | Cookie theft desde subdominio controlado | P1 ATO |
| CORS que acepta subdominios | Leer datos del dominio principal | P1 |
| CSP que confía en el subdominio | XSS bypass de CSP | P1/P2 |
| SPF/DMARC débil | Email spoofing desde subdominio legítimo | P2 |

#### Cache Poisoning/Deception +

| Combinado con | Resultado | Severidad |
|---|---|---|
| XSS en header cacheado | XSS stored via cache para todos los usuarios | P1 |
| Datos sensibles en cache sin key de sesión | Data exposure masiva | P1/P2 |
| Open redirect en respuesta cacheada | Redirect masivo para todos los usuarios | P2 |

#### CSRF +

| Combinado con | Resultado | Severidad |
|---|---|---|
| Cambio de email/password | ATO sin interacción extra | P1 |
| Cambio de webhook URL | SSRF via CSRF | P2 |
| Acción destructiva (delete account, transfer funds) | Impacto directo | P1/P2 |
| XSS stored | CSRF ejecutado sin click del usuario | P1 |

#### Panel expuesto (admin, actuator, debug) +

| Combinado con | Resultado | Severidad |
|---|---|---|
| Sin auth o auth débil | Acceso directo a funciones de admin | P1 |
| Default credentials | Idem | P1 |
| Info de usuarios en panel | Data breach | P2 |
| Funciones de ejecución (actuator/restart, shell) | RCE | P1 |
| SSRF desde panel | Pivot interno | P1/P2 |

---

### Procedimiento de cruce oportunista

Cuando hay 2+ leads en el target:

```
Para cada lead A en el target:
  Clasificar A por tipo (XSS / IDOR / SSRF / etc.)
  Para cada lead B != A en el target:
    Clasificar B por tipo
    Buscar en la matriz si (tipo_A + tipo_B) tiene combinación de alto valor
    Si existe combinación:
      → Documentar chain candidato: "LEAD-X + LEAD-Y → [resultado] → [severidad]"
      → Identificar qué evidencia falta para confirmar el link entre ellos
      → Consultar al operador si vale la pena intentar confirmar
```

**No intentar confirmar chains automáticamente** — documentar el candidato
y consultar. La decisión de intentar explotar un chain la toma el operador.

---

## PARTE 2 — Chain Dirigido

### Cómo usarlo

Cuando se encuentra un hallazgo puntual, buscar en la sección
correspondiente qué necesitaría para escalar. El razonamiento es:
"tengo X, ¿qué me falta para llegar a P1/P2?"

---

### Desde XSS reflejado

**Estado actual**: XSS reflejado confirmado. Requiere que la víctima haga
click en un link.

**Preguntas para escalar**:
1. ¿La cookie de sesión tiene `HttpOnly`?
   - No → robo de sesión directo. Ya es P1, no necesita más.
   - Sí → no se puede robar la cookie. Seguir.

2. ¿Hay CSRF token ausente o débil en endpoints sensibles?
   - Sí → XSS ejecuta acciones en nombre de la víctima. P1/P2 según la acción.

3. ¿Hay open redirect en el mismo dominio o subdominio?
   - Sí + OAuth flow → chain para robo de authorization code. P1.

4. ¿El XSS se puede volver stored?
   - ¿El payload se guarda en algún lado que otros usuarios ven?
   - Si llega al panel de admin → ATO del admin. P1.

5. ¿Hay postMessage handlers en el dominio que toman acción con el mensaje?
   - XSS → postMessage al handler → acción privilegiada. P1/P2.

**Si ninguno aplica**: XSS reflejado sin HttpOnly + sin CSRF = P2 standalone.
Con HttpOnly y CSRF robusto = P3. Reportar en el nivel que corresponde,
no esperar el chain perfecto.

---

### Desde IDOR de lectura

**Estado actual**: puedo leer recursos de otro usuario.

**Preguntas para escalar**:
1. ¿Qué datos contiene el recurso?
   - Email + token de reset → ATO via reset de password. P1.
   - PII sensible (DNI, tarjeta, datos médicos) → data breach. P1/P2.
   - API key o token de sesión → tomar la sesión. P1.
   - Solo datos no sensibles → P3/P4 standalone.

2. ¿Hay endpoint de escritura sobre el mismo recurso?
   - Sí → probar IDOR de escritura. Si funciona → P1/P2 según campo.

3. ¿El ID es enumerable?
   - Numérico secuencial → IDOR masivo. P1 (data breach de todos).
   - GUID v4 → no enumerable por sí solo. ¿Se expone en algún otro endpoint?

4. ¿El recurso afecta a otros usuarios si se modifica?
   - Mensajes, comentarios, archivos compartidos → impacto en otros usuarios.

---

### Desde IDOR de escritura

**Estado actual**: puedo modificar recursos de otro usuario.

**Preguntas para escalar**:
1. ¿Qué campos puedo modificar?
   - Email → ATO via password reset al email del atacante. P1.
   - Password → ATO directo. P1.
   - Rol → privilege escalation. P1.
   - Webhook/notification URL → SSRF. P2.
   - Datos no sensibles → verificar impacto real desde cuenta víctima.

2. ¿El cambio tiene impacto real en la cuenta víctima?
   - Verificar SIEMPRE desde la cuenta víctima. Archive/mute → per-user, sin impacto.
   - Sin verificación → no es chain, es un candidato sin confirmar.

3. ¿Se puede combinar con CSRF?
   - IDOR de escritura + CSRF ausente = explotable sin que la víctima haga nada.

---

### Desde SSRF ciego

**Estado actual**: OOB callback recibido, pero no veo la respuesta del servidor.

**Preguntas para escalar**:
1. ¿El servidor está en cloud?
   - AWS → probar `169.254.169.254/latest/meta-data/iam/security-credentials/`
   - GCP → probar `metadata.google.internal/computeMetadata/v1/`
   - Azure → probar `169.254.169.254/metadata/instance?api-version=2021-02-01`
   - ECS → probar `169.254.170.2/v2/credentials/`

2. ¿Puedo hacer el SSRF full-read?
   - ¿Hay forma de ver la respuesta? (reflection en la response, error message, timing)
   - Si la respuesta se refleja aunque sea parcialmente → intentar leer metadata.

3. ¿Qué servicios internos pueden estar en la red del servidor?
   - Usar info de otros leads: versiones detectadas, tecnologías, nombres de hosts internos
   - Puertos comunes: 6379 (Redis), 5432 (Postgres), 3306 (MySQL), 8080/8443 (apps internas)
   - Kubernetes: 10.0.0.1:443, 10.96.0.1:443

4. ¿Hay otro SSRF en el mismo target?
   - Dos SSRFs distintos → confirman patrón de red, aumentan confianza en internos.

---

### Desde open redirect

**Estado actual**: puedo redirigir a cualquier dominio externo.

**Preguntas para escalar**:
1. ¿Está en un flujo OAuth?
   - ¿El `redirect_uri` usa este mismo endpoint? → robo de authorization code. P1.
   - ¿Hay tokens en la URL que se filtren por Referer al destino externo? → P1/P2.

2. ¿Hay XSS reflejado en el mismo dominio?
   - Open redirect → XSS en página de destino controlada → chain. P2.

3. ¿El redirect lo hace el servidor (302) o el cliente (JS)?
   - Servidor → puede filtrar tokens en Referer header.
   - Cliente → útil para phishing, menos para token theft.

4. ¿Qué tan creíble es el phishing?
   - URL del target redirige a phishing → alta credibilidad → P3 standalone si no hay más.

---

### Desde information disclosure (versión exacta)

**Estado actual**: sé exactamente qué versión de software corre.

**Preguntas para escalar**:
1. ¿Hay CVEs conocidos para esa versión?
   - Buscar en NVD, Exploit-DB, GitHub Security Advisories.
   - ¿El CVE requiere auth? ¿Red interna? ¿Configuración específica?

2. ¿El CVE es explotable desde internet en este deployment?
   - Verificar las condiciones del CVE contra lo que se sabe del target.
   - No asumir que porque el CVE existe es explotable — verificar condiciones.

3. ¿La info expuesta revela estructura interna?
   - Path absoluto + otro vector (LFI, SSRF) → dirigir el ataque con info real.
   - Nombres de servicios internos + SSRF → SSRF dirigido.

---

### Desde JWT débil (alg:none o alg confusion)

**Estado actual**: puedo forjar tokens JWT.

**Preguntas para escalar**:
1. ¿Qué claims controlo en el token forjado?
   - `sub` o `userId` → suplantar cualquier usuario → ATO masivo. P1.
   - `role` o `scope` → escalar a admin. P1.
   - `email` → cambiar identidad. P1.

2. ¿Hay un ID de admin conocido?
   - User enumeration en otro endpoint → obtener ID del admin → forjar token de admin. P1.

3. ¿El token forjado funciona en todos los endpoints o solo en algunos?
   - Mapear alcance del token forjado para dimensionar el impacto real.

---

### Desde GraphQL introspección abierta

**Estado actual**: tengo el schema completo.

**Preguntas para escalar**:
1. ¿Hay mutations que no aparecen en la UI?
   - Mutations de admin, de cambio de rol, de creación de usuarios privilegiados.
   - Probar cada mutation con el rol actual → ¿alguna funciona sin auth de admin?

2. ¿Hay queries que devuelven datos de otros usuarios?
   - `user(id: OTRO_ID)` → IDOR en GraphQL.
   - `users { email, phone }` → data breach masivo si no hay paginación/auth.

3. ¿Hay campos de PII o sensibles en el schema?
   - `password`, `token`, `apiKey`, `secret`, `creditCard` → priorizar esos queries.

4. ¿El schema revela servicios internos o arquitectura?
   - Nombres de tipos, resolvers, servicios → contexto para otros vectores (SSRF, IDOR).

---

### Desde subdomain takeover

**Estado actual**: controlo el contenido de un subdominio del target.

**Preguntas para escalar**:
1. ¿Las cookies del dominio principal tienen scope `*.dominio.com`?
   - Sí → desde el subdominio controlado puedo leer las cookies de sesión. P1 ATO.

2. ¿El CORS del dominio principal acepta el subdominio?
   - Sí → fetch desde el subdominio controlado lee datos del API principal. P1.

3. ¿La CSP del dominio principal confía en el subdominio?
   - Sí → XSS bypass de CSP via subdominio controlado. P1/P2.

4. ¿El SPF/DMARC permite enviar emails desde el subdominio?
   - Sí → phishing desde dirección legítima del target. P2.

5. ¿Hay postMessage que acepta mensajes de subdominios?
   - Sí → postMessage desde subdominio controlado → acción en el dominio principal. P1/P2.

---

### Desde panel expuesto (admin, actuator, debug)

**Estado actual**: hay un panel accesible que no debería estarlo.

**Preguntas para escalar**:
1. ¿Requiere autenticación?
   - No → acceso directo. Documentar qué funciones expone.
   - Sí → probar default credentials, auth bypass (ver auth_decision_tree.md Camino 1F).

2. ¿Qué funciones expone el panel?
   - Listado de usuarios → data breach.
   - Ejecución de comandos (actuator/restart, shell, eval) → RCE. P1.
   - Configuración de la app → secrets, credenciales de DB.
   - Logs con datos de usuarios → PII exposure.

3. ¿El panel expone endpoints de la app interna?
   - Endpoints internos visibles en el panel → SSRF dirigido desde otro vector.

4. ¿Hay funciones de impersonación?
   - "Login as user", "switch account" → ATO de cualquier usuario. P1.

---

## Regla de priorización de chains

Cuando hay múltiples chain candidatos, priorizar en este orden:

1. **ATO (Account Takeover)** → P1. Siempre primero.
2. **RCE (Remote Code Execution)** → P1. Siempre primero.
3. **Data breach masivo** (todos los usuarios) → P1.
4. **Privilege escalation a admin** → P1/P2.
5. **Data breach individual** (un usuario específico) → P2.
6. **SSRF a internos** → P1/P2 según qué se alcanza.
7. **Acciones forzadas sin ATO** → P2/P3 según impacto.

---

## Regla de cierre para análisis de chains

Antes de cerrar la sesión con leads documentados, responder:

1. ¿Crucé todos los leads entre sí usando la matriz oportunista?
2. ¿Para cada hallazgo puntual, recorrí la sección de chain dirigido correspondiente?
3. ¿Documenté todos los chain candidatos aunque no los haya confirmado?
4. ¿Consulté al operador sobre los chain candidatos antes de intentar confirmarlos?

Si alguno está sin responder → el análisis de chains está incompleto.
