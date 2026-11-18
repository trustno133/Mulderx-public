# Severity Gate — Filtro de Contexto Antes de Escribir un Finding

Este archivo se ejecuta **antes de escribir cualquier hallazgo** en
`leads.md` o cualquier archivo de findings. No se ejecuta durante el
análisis de señales — se ejecuta en el momento de documentar.

Las tres preguntas se responden **por escrito** en el finding, en el bloque
"Severity Gate" del template. No quedarlas en la cabeza del agente.

---

## Las tres preguntas

### Q1 — ¿Qué delta le da esto a un atacante?

¿Qué puede hacer un atacante con esto que **no podría hacer antes** de encontrarlo?

Responder de forma operacional y específica:

- ✓ "Puede leer el token de sesión de otro usuario sin tener sus credenciales"
- ✓ "Puede ejecutar código en el contexto del browser de la víctima"
- ✗ "Puede ver el email que el usuario publicó en su perfil público" — ya era visible
- ✗ "Ahora sabe que el servidor usa nginx 1.18" — sin CVE o vector concreto, no cambia nada

**Regla de corte**: Si la respuesta honesta es "nada diferente a lo que ya podía hacer",
el hallazgo no es finding. Es nota de contexto. Va a `discarded.md` con killer:
"sin delta para el atacante — [especificar por qué]".

---

### Q2 — ¿Ya era visible por diseño?

¿Este dato o acceso es público o visible por diseño en el flujo normal de la app?

Patrones que califican como "público por diseño":

- El propio dueño del dato lo publicó con esa intención (email en perfil público,
  nombre en listado de autores, teléfono en directorio de contacto, foto de perfil)
- El endpoint no tiene auth por decisión de negocio documentada (API pública,
  feed RSS, sitemap, documentación abierta)
- La información aparece en el frontend sin auth o en documentación oficial del producto
- El dato es visible para cualquier usuario registrado y ese es el modelo de negocio
  (nombre de otros miembros en un foro, avatares, rankings públicos)

**Regla de corte**: Si aplica cualquiera de estos patrones → Informational o
descarte directo. **El nombre del campo o del archivo no cambia esto**:
un email en un perfil público sigue siendo público aunque la categoría del hallazgo
diga "PII expuesta". Un source map con solo código de UI sigue siendo bajo impacto
aunque el nombre diga "código fuente expuesto".

**Excepción**: Si el dato es público por diseño PERO se expone en exceso más allá
de lo que el diseño justifica (el endpoint de búsqueda devuelve el email de contacto
aunque solo debería devolver el nombre, la foto, y el rol), eso sí es señal.
Documentar la discrepancia: qué justifica el diseño vs. qué se expone realmente.

---

### Q3 — ¿Evidencia concreta o inferencia por categoría?

¿Tengo evidencia técnica concreta del impacto, o estoy infiriendo severidad por el
nombre o la categoría del hallazgo?

**Evidencia concreta** (habilita subir de P4/Informational):

- Source map leído → contenido revisado → contiene: `API key hardcodeada "sk-..."`,
  endpoint interno `/api/admin/...`, lógica de negocio con validaciones bypasseables
- PoC ejecutada → request forjado → cambió estado del servidor (confirmado con cuenta
  víctima, no solo con "devolvió 200")
- Callback recibido en servidor externo controlado
- Dato de otro usuario leído desde cuenta sin permisos, verificado desde cuenta víctima

**Inferencia por categoría** (techo P4/Informational hasta que haya evidencia):

- "Source map accesible" sin leer el contenido real
- "Email encontrado en response" sin confirmar si era privado o público por diseño
- "Endpoint sin autenticación" sin confirmar qué devuelve ni si fue intencional
- "Versión de librería antigua" sin CVE explotable en el contexto del target
- "Header de seguridad faltante" sin demostrar el vector de explotación concreto
- "Formulario sin CSRF token" sin ejecutar el request forjado y confirmar efecto

**Regla de corte**: Sin evidencia concreta, el hallazgo no puede superar P4/Informational.
No importa la categoría del hallazgo. "Se ve que funciona" es inferencia, no evidencia.

---

## Tabla de decisión

| Q1 (delta) | Q2 (público por diseño) | Q3 (evidencia) | Resultado |
|---|---|---|---|
| Ninguno | — | — | `discarded.md`. Killer: "sin delta para el atacante" |
| Hay delta | Sí, por diseño | — | Informational o descarte. No escalar por nombre del campo |
| Hay delta | Sí, pero exceso de exposición | — | Señalar la discrepancia, P4 máximo |
| Hay delta | No / parcial | No (solo categoría) | P4 máximo. Documentar qué falta para confirmar |
| Hay delta | No | Sí (evidencia real) | Continuar con el skill para determinar P1–P3 |

---

## Bloque obligatorio en el finding

Todo hallazgo que pase a `leads.md` incluye este bloque
**antes del análisis técnico**. Sin este bloque, el finding está incompleto.

```
#### Severity Gate
- **Q1 — Delta para el atacante**: [respuesta específica, o "ninguno → descartado"]
- **Q2 — Público por diseño**: [sí / no / parcial — justificación de una línea]
- **Q3 — Evidencia concreta**: [qué evidencia existe, o "inferencia por categoría — techo P4"]
- **Resultado del gate**: [continuar con skill / P4 máximo / Informational / descartado]
```

Si el resultado es "descartado", el finding **no** va a `leads.md`.
Va a `discarded.md` con el killer del severity gate.

---

## Casos concretos

**Source map expuesto sin leer el contenido**
- Q1: Sin leer el contenido, el delta es desconocido. No asumir que "expone lógica sensible" porque es un `.map`. Leer el contenido antes de asignar severidad.
- Q2: El source map es un artefacto de build expuesto accidentalmente — no es público por diseño. Este punto no aplica como descarte.
- Q3: "Source map accesible" sin leer el contenido = inferencia por categoría → P4/nota hasta leer. Si el contenido es solo mapeo de líneas de UI sin secrets ni lógica no documentada → techo Informational.

**Email en listado o perfil público**
- Q1: ¿El atacante puede hacer algo con ese email que no podía antes? Si el email es de contacto publicado por el propio usuario, ya lo podía ver cualquiera → delta cero.
- Q2: Publicado a propósito por el dueño del dato → público por diseño → descarte directo.
- Q3: No aplica si Q1 y Q2 ya cierran.

**CORS permisivo en endpoint sin datos sensibles**
- Q1: ¿El endpoint retorna datos que no deberían ser accesibles cross-origin? Si solo devuelve contenido público, el cross-origin read no da ventaja.
- Q2: Endpoint público por diseño → CORS permisivo puede ser intencional.
- Q3: "ACAO: *" sin verificar qué devuelve el endpoint = inferencia → P4 hasta confirmar el contenido.

**Versión de librería con CVE conocido**
- Q1: ¿Hay call site en código propio de la app que use el patrón vulnerable con input del usuario? Sin ese call site, el delta es cero — la vulnerabilidad existe en la librería pero no hay vector de activación en este target.
- Q2: No aplica (librería vendorizada, no dato público por diseño).
- Q3: "Versión X detectada, CVE-XXXX-XXXX existe" sin call site = inferencia por categoría → nota de contexto, no finding. Call site confirmado = evidencia → continuar.
