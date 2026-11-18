# The Complete Guide to Building Skills for Claude

> Fuente: Anthropic, "The Complete Guide to Building Skills for Claude" (resources.anthropic.com).
> Bajada y convertida a Markdown el 2026-10-23 para uso como referencia del subagente `skill-architect`.
> Precarga esto en vez de en `CLAUDE.md`/`AGENTS.md` general — es contenido pesado que solo necesita
> quien está creando o editando una skill, no los hunters.

## Qué es una skill

Un folder con:
- `SKILL.md` (requerido): instrucciones en Markdown con YAML frontmatter.
- `scripts/` (opcional): código ejecutable (Python, Bash, etc).
- `references/` (opcional): documentación que se carga solo cuando hace falta.
- `assets/` (opcional): templates, fuentes, íconos usados en el output.

## Progressive disclosure — el sistema de tres niveles

1. **Frontmatter YAML**: siempre está en el system prompt de Claude. Da lo justo para que Claude
   sepa cuándo usar la skill, sin cargar el resto en contexto.
2. **Cuerpo de `SKILL.md`**: se carga cuando Claude considera que la skill es relevante para la
   tarea actual. Instrucciones completas.
3. **Archivos linkeados** (`references/`, etc.): Claude los navega y descubre solo si hace falta.

Esto minimiza tokens mientras mantiene expertise especializado — es la justificación técnica de
por qué "más skills" no cuesta tokens por sí solo (el índice es liviano), pero si el `SKILL.md`
mismo es gigante o nunca usa `references/`, ahí sí pesa.

Composability: una skill debe funcionar bien junto a otras, no asumir que es la única capacidad
disponible. Portability: las skills funcionan igual en Claude.ai, Claude Code y la API.

## Antes de escribir nada: definir casos de uso

Identificar 2-3 casos de uso concretos. Para cada uno: trigger (qué dice el usuario), pasos, y
resultado esperado. Preguntas guía: ¿qué quiere lograr el usuario?, ¿qué workflow multi-paso
requiere?, ¿qué herramientas hacen falta?, ¿qué conocimiento de dominio hay que embeber?

Tres categorías comunes (observadas por Anthropic):
1. **Document & Asset Creation** — output consistente y de calidad (docs, código, diseños).
2. **Workflow Automation** — procesos multi-paso con metodología consistente, coordinando
   múltiples herramientas/MCP.
3. **MCP Enhancement** — guía de workflow sobre un MCP server ya existente (la skill es la capa
   de conocimiento sobre la conectividad que da MCP).

### Criterios de éxito (antes de dar la skill por terminada)

Cuantitativos: triggerea en ~90% de queries relevantes (correr 10-20 queries de prueba), completa
el workflow en X tool calls, 0 llamadas fallidas por workflow.

Cualitativos: el usuario no necesita indicarle a Claude los próximos pasos, el workflow se
completa sin corrección del usuario, resultados consistentes entre sesiones.

## Requisitos técnicos

### Estructura de carpetas

```
your-skill-name/
├── SKILL.md                  # Requerido
├── scripts/                  # Opcional — código ejecutable
├── references/               # Opcional — documentación cargada bajo demanda
└── assets/                   # Opcional — templates, etc.
```

### Reglas críticas

- El archivo debe llamarse exactamente `SKILL.md` (case-sensitive). No `SKILL.MD`, no `skill.md`.
- El nombre de la carpeta va en kebab-case: `notion-project-setup` ✅. Nada de espacios,
  guiones bajos o mayúsculas.
- **No incluir `README.md` dentro de la skill.** Toda la documentación va en `SKILL.md` o
  `references/`. (Si se distribuye la skill vía GitHub, el README va a nivel de repo, no de skill.)

### Frontmatter YAML — la parte más importante

Es lo que decide si Claude carga la skill. Formato mínimo:

```yaml
---
name: your-skill-name
description: What it does. Use when user asks to [specific phrases].
---
```

**`name` (requerido):** kebab-case, sin espacios ni mayúsculas, debe matchear el nombre de la
carpeta.

**`description` (requerido):** DEBE incluir ambas cosas — qué hace la skill, y cuándo usarla
(condiciones de trigger). Menos de 1024 caracteres. Sin tags XML (`<` `>`). Incluir frases
específicas que el usuario podría decir. Mencionar tipos de archivo si aplica.

Ejemplos buenos:
```yaml
description: Analyzes Figma design files and generates developer handoff
  documentation. Use when user uploads .fig files, asks for "design specs",
  "component documentation", or "design-to-code handoff".
```

Ejemplos malos:
```yaml
description: Helps with projects.                      # muy vago
description: Creates sophisticated multi-page documentation systems.   # sin triggers
description: Implements the Project entity model with hierarchical relationships.  # muy técnico, sin triggers de usuario
```

**`license` (opcional):** si es open source (MIT, Apache-2.0).

**`compatibility` (opcional):** 1-500 caracteres, requisitos de entorno (producto, paquetes de
sistema, acceso a red).

**`metadata` (opcional):** pares clave-valor libres. Sugeridos: `author`, `version`, `mcp-server`.

**Prohibido en el frontmatter:**
- Ángulos XML (`<` `>`) — el frontmatter aparece en el system prompt; contenido malicioso podría
  inyectar instrucciones.
- Skills con "claude" o "anthropic" en el nombre (reservado).

## Escribir las instrucciones

Estructura recomendada después del frontmatter:

```markdown
# Your Skill Name

## Instructions

### Step 1: [First Major Step]
Clear explanation of what happens.

### Examples
Example 1: [common scenario]
User says: "..."
Actions: 1. ... 2. ...
Result: ...

### Troubleshooting
Error: [Common error message]
Cause: [Why it happens]
Solution: [How to fix]
```

### Buenas prácticas

- **Ser específico y accionable.** Mal: "Validate the data before proceeding." Bien: comando
  exacto + qué hacer si falla, con los casos comunes listados.
- **Incluir manejo de errores** — una sección de errores comunes con causa y solución.
- **Referenciar recursos empaquetados con claridad**: "Before writing queries, consult
  `references/api-patterns.md` for: rate limiting guidance, pagination patterns, error codes."
- **Usar progressive disclosure**: mantener `SKILL.md` enfocado en las instrucciones core, mover
  documentación detallada a `references/` y linkearla ahí.

## Testing e iteración

Tres niveles de rigor: manual en Claude.ai, scripted en Claude Code, programático vía Skills API.

### 1. Triggering tests
Verificar que la skill carga cuando corresponde: triggerea en tareas obvias, triggerea en
pedidos parafraseados, NO triggerea en temas no relacionados.

### 2. Functional tests
Outputs válidos generados, llamadas a API exitosas, manejo de errores funciona, edge cases
cubiertos.

### 3. Performance comparison
Comparar con y sin la skill: mensajes de ida y vuelta, llamadas fallidas, tokens consumidos.

**Tip de los early adopters:** iterar sobre una sola tarea difícil hasta que Claude la resuelva
bien, y recién ahí extraer el approach ganador a una skill — da señal más rápida que testear
amplio desde el principio.

### Señales de iteración

**Undertriggering** (no carga cuando debería): agregar más detalle y matices a la `description`,
incluir keywords técnicos específicos.

**Overtriggering** (carga para queries irrelevantes): agregar triggers negativos, ser más
específico.

```yaml
# Ejemplo de trigger negativo
description: Advanced data analysis for CSV files. Use for statistical
  modeling, regression, clustering. Do NOT use for simple data exploration
  (use data-viz skill instead).
```

## Troubleshooting

### La skill no sube / no carga
- `"Could not find SKILL.md in uploaded folder"` → el archivo no se llama exactamente `SKILL.md`.
- `"Invalid frontmatter"` → problema de formato YAML (falta `---`, comillas sin cerrar).
- `"Invalid skill name"` → el `name` tiene espacios o mayúsculas.

### La skill no triggerea
Revisar la `description`: ¿es muy genérica? ¿incluye frases que el usuario realmente diría?
¿menciona tipos de archivo relevantes? Debug: preguntarle a Claude "¿cuándo usarías la skill
[nombre]?" — va a citar la `description` textual, y eso muestra qué falta.

### La skill triggerea demasiado
Agregar triggers negativos, ser más específico, aclarar el scope explícitamente (ver ejemplos
arriba).

### Las instrucciones no se siguen
Causas comunes:
1. Instrucciones muy verbosas → usar bullets/listas numeradas, mover detalle a `references/`.
2. Instrucciones enterradas → poner lo crítico arriba de todo, usar headers `## Important` o
   `## Critical`, repetir puntos clave si hace falta.
3. Lenguaje ambiguo:
   ```
   # Malo
   Make sure to validate things properly

   # Bueno
   CRITICAL: Before calling create_project, verify:
   - Project name is non-empty
   - At least one team member assigned
   - Start date is not in the past
   ```
   Técnica avanzada: para validaciones críticas, empaquetar un script que las corra
   programáticamente en vez de confiar en interpretación de lenguaje natural — código es
   determinístico, el lenguaje no.
4. "Laziness" del modelo → agregar encouragement explícito tipo "Take your time to do this
   thoroughly, quality is more important than speed, do not skip validation steps" (más efectivo
   en el prompt del usuario que en el `SKILL.md`).

### Problemas de contexto grande
Síntoma: la skill se siente lenta o las respuestas degradan.

Causas: contenido de la skill muy grande, demasiadas skills habilitadas simultáneamente, todo el
contenido cargado en vez de progressive disclosure.

Soluciones: mover documentación detallada a `references/` y linkear en vez de inlinear, mantener
`SKILL.md` bajo 5000 palabras, evaluar si hay más de 20-50 skills habilitadas simultáneamente y
considerar "packs" de skills relacionadas.

## Checklist rápido (Reference A del documento original)

**Antes de empezar:**
- [ ] Identificaste 2-3 casos de uso concretos
- [ ] Identificaste las herramientas (built-in o MCP)
- [ ] Revisaste esta guía y ejemplos
- [ ] Planeaste la estructura de carpetas

**Durante el desarrollo:**
- [ ] Carpeta nombrada en kebab-case
- [ ] Existe `SKILL.md` (ortografía exacta)
- [ ] El frontmatter YAML tiene delimitadores `---`
- [ ] `name`: kebab-case, sin espacios, sin mayúsculas
- [ ] `description` incluye QUÉ y CUÁNDO
- [ ] Sin tags XML (`<` `>`) en ningún lado
- [ ] Instrucciones claras y accionables
- [ ] Manejo de errores incluido
- [ ] Ejemplos provistos
- [ ] Referencias linkeadas con claridad

**Antes de publicar / después de publicar:** testear triggering en tareas obvias y parafraseadas,
verificar que no triggerea en temas no relacionados, tests funcionales pasan, testear en
conversaciones reales, monitorear under/overtriggering, iterar sobre `description` e
instrucciones.

## Referencia YAML completa

```yaml
---
name: skill-name-in-kebab-case
description: What it does and when to use it. Include specific trigger phrases.
license: MIT                          # opcional
allowed-tools: "Bash(python:*) Bash(npm:*) WebFetch"   # opcional — restringe acceso a tools
metadata:                             # opcional
  author: Company Name
  version: 1.0.0
  mcp-server: server-name
  category: productivity
  tags: [project-management, automation]
---
```

**Permitido:** tipos YAML estándar (strings, números, booleanos, listas, objetos), campos
metadata custom, descriptions largas (hasta 1024 caracteres).

**Prohibido:** ángulos XML (`<` `>`), ejecución de código en el YAML (parsing YAML seguro),
nombres de skill con prefijo "claude" o "anthropic" (reservado).

## Nota sobre estándar abierto

Anthropic publicó Agent Skills como un estándar abierto — la misma skill debería funcionar en
Claude u otras plataformas de IA, con la salvedad de que algunas skills aprovechan capacidades
específicas de una plataforma (eso se anota en `compatibility`). Esto es relevante para Mulderx
porque las skills en `.claude/skills/` ya siguen este formato, y los mismos `SKILL.md` son
reutilizables tal cual para el import a Hermes (`hermes import-agent claude-code`).
