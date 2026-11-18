# Auth Decision Tree — Mapa de Caminos

Cuando un endpoint o funcionalidad requiere autenticación, este archivo
define todos los caminos posibles. No es un árbol lineal — varios caminos
pueden ser verdad simultáneamente. Recorrelos todos en paralelo, no en
secuencia.

**Regla de uso**: "requiere auth" no es un killer. Es el inicio de un
análisis, no el final. Un lead no se marca MUERTO por auth hasta haber
recorrido todos los caminos de este archivo y documentado por qué cada
uno no aplica.

---

## CAMINO 0 — Antes de buscar credenciales: ¿hay superficie pre-auth?

Este camino se recorre SIEMPRE, independientemente de si se consigue
acceso o no. La superficie pre-auth existe aunque nunca se logre entrar.

### Preguntas obligatorias sobre el flujo de login

1. **¿La URL de login tiene parámetros?**
   - `?next=`, `?redirect=`, `?return_to=` → open redirect pre-auth
   - `?client_id=`, `?response_type=` → OAuth misconfiguration
   - Cualquier parámetro que se refleje en la response → XSS pre-auth

2. **¿Hay endpoint de reset de password?**
   - ¿Respuesta diferente entre email registrado y no registrado? → user enumeration
   - ¿El token de reset va en la URL? → leak en Referer
   - ¿El token expira? ¿Se invalida después de usarse?
   - ¿Sin rate limit en el endpoint de reset? → enumeración masiva posible

3. **¿Hay endpoint de registro?**
   - ¿Respuesta diferente entre email existente y nuevo? → user enumeration
   - ¿Sin captcha? → registro masivo posible
   - ¿Valida formato de email o acepta cualquier string?

4. **¿El flujo es OAuth/OIDC/SAML?**
   - Ver sección 20 de `vector_interrogation.md` para análisis completo
   - Puntos críticos pre-auth: `state` ausente, `redirect_uri` laxa, implicit flow

5. **¿Hay endpoints públicos que filtran info de usuarios autenticados?**
   - APIs de búsqueda que devuelven emails/usernames
   - Perfiles públicos con más info de la necesaria
   - Endpoints de "check if user exists" (verificación de email/phone)

6. **¿El mecanismo de login tiene superficie de timing/oracle?**
   - ¿Tarda más cuando el usuario existe (bcrypt comparison)?
   - ¿El mensaje de error distingue "usuario no existe" de "contraseña incorrecta"?

---

## CAMINO 1 — Conseguir acceso: todos los caminos posibles

### 1A. Credenciales ya disponibles

**Primero**: revisar `.credentials/<target>.env` antes de cualquier otra cosa.

Si hay credenciales guardadas:
- ¿Siguen válidas? (verificar con un request autenticado)
- ¿Cuántos roles/tiers cubren las cuentas disponibles?
- Si las cookies están vencidas → no marcar el lead como bloqueado, seguir con 1B/1C

---

### 1B. Registro self-service

**Señales de que existe**: formulario en `/register`, `/signup`, `/crear-cuenta`,
botón "Crear cuenta" en la UI, endpoint `POST /api/users` o similar.

**Cuentas del programa disponibles**:

| Plataforma | Email base | Patrón multi-cuenta |
|---|---|---|
| Bugcrowd | `researcher@example.invalid` | `researcher+1@example.invalid`, `+2`, `+3`... |
| HackerOne | `d33pthroat@wearehackerone.com` | `d33pthroat+1@wearehackerone.com`, `+2`, `+3`... |

**Cuándo usar `+N`**: para crear cuentas víctima en pruebas de IDOR/BOLA,
para probar escalada de rol (cuenta A ataca cuenta B), para verificar
impacto real desde la perspectiva de otra cuenta.

**Preguntas antes de registrar**:
- ¿El registro requiere verificación de email? → usar las cuentas del programa (reciben email)
- ¿Requiere número de teléfono real? → bloqueador, documentar
- ¿Requiere identidad real (ID Austria, eIDAS, Handy-Signatur)? → bloqueador, documentar
- ¿Hay captcha? → si es solo client-side, bypasseable; si es server-side, documentar

**Si el registro funciona**: crear mínimo 2 cuentas (atacante + víctima)
para poder probar IDOR/BOLA correctamente.

---

### 1C. SSO del target — ¿es registrable?

Muchos targets corporativos usan SSO propio (enterprise identity providers, Azure AD,
Okta, Ping Identity). No asumir que es solo para empleados — verificar primero.

**Preguntas**:
- ¿Hay un flujo de registro ciudadano/público en el IdP? → intentar
- ¿El IdP acepta las cuentas del programa (`@bugcrowdninja.com`)?
- ¿Hay un portal de self-service del IdP separado del target principal?
- ¿El brief del programa menciona cómo conseguir acceso SSO?

**Señal de que el SSO es solo interno**: nombre de dominio `.intern`, requiere
VPN, redirige a login de Azure AD con tenant corporativo sin opción de cuenta
externa.

**Si el SSO no es registrable**: documentar como bloqueador y consultar al
operador — no marcar el target completo como MUERTO.

---

### 1D. SSO externo (Google, GitHub, Apple, Facebook)

Si el target tiene "Login con Google/GitHub/etc.":
- Registrar con la cuenta del programa que corresponda
- Verificar si el OAuth linking permite account takeover (ver sección 20
  de `vector_interrogation.md`)
- ¿Se puede linkear una cuenta OAuth a una cuenta existente sin verificación?

---

### 1E. Cuenta de prueba en el brief del programa

Algunos programas proveen credenciales de prueba en el brief de Bugcrowd/HackerOne.

**Siempre revisar el brief antes de asumir que no hay cuentas disponibles.**

Si hay credenciales en el brief:
- Guardarlas en `.credentials/<target>.env` antes de usarlas
- Verificar si las credenciales siguen válidas
- Documentar el rol/tier de esas cuentas

---

### 1F. Auth bypass directo (el camino más valioso)

Antes de rendirse con la auth, verificar si es bypasseable:

1. **¿Hay endpoints que no requieren auth aunque deberían?**
   - Variar el método HTTP: endpoint POST autenticado → ¿GET sin auth devuelve algo?
   - Remover el header `Authorization` o la cookie → ¿sigue respondiendo?
   - Cambiar `Authorization: Bearer TOKEN` por `Authorization: Bearer invalid` → ¿mismo response?

2. **¿Hay path bypass?**
   - `/api/admin/users` → 403, pero `/api/admin/users/` → 200?
   - `/api/v1/secure` → 403, pero `/api/v1/secure;.js` → 200? (Spring)
   - `/api/v1/secure` → 403, pero `/api/V1/secure` → 200? (case sensitivity)
   - `/api/v1/secure` → 403, pero `/%2e/api/v1/secure` → 200?

3. **¿Hay IP bypass?**
   - `X-Forwarded-For: 127.0.0.1` → ¿el server cree que es localhost?
   - `X-Custom-IP-Authorization: 127.0.0.1`
   - `X-Real-IP: 127.0.0.1`

4. **¿El token se valida realmente?**
   - JWT con algoritmo `none` → firma vacía
   - JWT con `alg: HS256` y clave pública como secret
   - Token expirado → ¿sigue funcionando?
   - Token de otro usuario → ¿funciona en este endpoint?

5. **¿Hay mass assignment?**
   - Agregar `"role": "admin"` o `"isAdmin": true` al body del request de registro/update
   - Agregar campos no esperados en el body → ¿alguno cambia el rol?

---

## CAMINO 2 — Una vez dentro: qué explorar

### 2A. Mapear roles y tiers disponibles

**Documentar siempre**:
- ¿Qué roles existen? (user, admin, moderator, staff, superuser...)
- ¿Qué tiers existen? (free, premium, enterprise, trial...)
- ¿Cómo se asignan? ¿En el registro? ¿Por invitación? ¿Por pago?

**Señales de que hay roles distintos**:
- Menú o sección "Admin" visible aunque no accesible
- Endpoints `/admin/`, `/staff/`, `/moderator/` en el JS
- Claims en el JWT (`role`, `scope`, `permissions`, `tier`)
- Respuestas distintas según el usuario (algunos ven más campos que otros)
- Parámetro `role` o `plan` en la response del perfil

**Acción**: documentar los roles detectados y **consultar al operador**
qué camino tomar — no escalar automáticamente sin confirmación.

Preguntas para el operador:
- ¿Intentamos conseguir un rol más alto? (¿hay registro de admin/staff disponible?)
- ¿Probamos acceder a endpoints de admin con el rol actual?
- ¿Intentamos mass assignment para elevar el rol?

---

### 2B. Explorar la superficie autenticada

Con acceso, recorrer en orden de prioridad:

1. **IDs propios expuestos** → son el punto de entrada para IDOR/BOLA
   - ¿El ID del usuario propio aparece en la URL, body, o JWT?
   - ¿Es numérico secuencial, GUID, o slug?
   - Aplicar razonamiento de sección 2 de `vector_interrogation.md`

2. **Endpoints que operan sobre recursos de otros usuarios**
   - Cualquier endpoint que tome un ID como parámetro
   - Cualquier endpoint de mensajería, compartir, asignar, transferir
   - Probar con ID de la cuenta víctima (+1, +2) y verificar impacto real

3. **Tokens y sesión**
   - Analizar JWT si existe: ¿qué claims tiene? ¿son manipulables?
   - ¿La sesión expira? ¿Se invalida en logout?
   - Aplicar razonamiento de sección 7 de `vector_interrogation.md`

4. **Funcionalidades de import/export/upload**
   - Aplicar razonamiento de secciones 5 y 22 de `vector_interrogation.md`

5. **Webhooks e integraciones configurables**
   - Aplicar razonamiento de sección 23 de `vector_interrogation.md`

---

### 2C. Probar acceso a endpoints de nivel superior

Con rol bajo, intentar acceder a endpoints de nivel superior **sin escalar el rol**:

- Endpoints `/admin/*`, `/staff/*`, `/internal/*` encontrados en el JS
- Mutations de GraphQL que no aparecen en la UI pero sí en el schema
- Endpoints de API documentados para otro rol

**Regla**: si el endpoint devuelve algo distinto a 401/403 con el rol actual
→ candidato a BFLA/BOLA, documentar y consultar al operador antes de continuar.

**No asumir que 403 = seguro**: algunos implementan auth check pero no
authz check. El endpoint puede devolver 403 para la lista pero 200 para
el detalle individual.

---

## CAMINO 3 — Cuando no hay forma de entrar

Si todos los caminos de acceso fallan o están bloqueados:

### 3A. Documentar el bloqueador específico

No "requiere auth" genérico. El killer tiene que ser específico:
- "Requiere ID Austria real — no registrable con `@bugcrowdninja.com`"
- "Requiere invitación de admin — no hay forma de auto-registrarse"
- "SSO solo para empleados — Azure AD tenant corporativo sin acceso externo"
- "Requiere número de teléfono austriaco real para verificación"

### 3B. Volver a Camino 0

Con el bloqueador documentado, asegurarse de haber recorrido toda la
superficie pre-auth (Camino 0) antes de cerrar el lead.

### 3C. Anotar qué desbloquearía este lead

El lead no muere — queda en estado "bloqueado por [killer específico]"
con una nota de qué lo desbloquearía:
- "Se desbloquea si el programa provee cuenta de prueba SSO"
- "Se desbloquea si se encuentra auth bypass en el login"
- "Se desbloquea si otro lead provee credenciales de staff"

---

## Regla de cierre para leads con auth

Un lead con "requiere auth" se marca MUERTO solo si:

1. ✓ Camino 0 recorrido completo (superficie pre-auth)
2. ✓ `.credentials/<target>.env` revisado
3. ✓ Registro self-service intentado o descartado con razón específica
4. ✓ SSO del target evaluado (¿registrable o solo interno?)
5. ✓ SSO externo evaluado si existe
6. ✓ Brief del programa revisado por cuentas de prueba
7. ✓ Auth bypass básico probado (método HTTP, path variations, headers)
8. ✓ Bloqueador documentado con killer específico

Si alguno de estos está sin marcar → el lead no está muerto, está incompleto.
