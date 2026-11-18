---
name: deserialization-ssti
description: Detectar y confirmar Server-Side Template Injection (SSTI) y deserialización insegura — motores de templates (Jinja2, Twig, Freemarker, Velocity, Smarty, Thymeleaf, Handlebars/ERB server-side) y formatos de serialización (Java ObjectInputStream, PHP unserialize, Python pickle/YAML, .NET BinaryFormatter/ViewState, Ruby Marshal/YAML). Usar cuando el target expone un motor de templates identificable con input de usuario en posición de render, o endpoints/cookies/parámetros que aceptan blobs serializados (base64 con magic bytes reconocibles, headers de tipo application/x-java-serialized-object, ViewState __VIEWSTATE).
---

# Deserialización insegura y SSTI

Van juntas porque comparten la misma causa raíz: **input del atacante
evaluado como código/objeto en vez de tratado como dato**. SSTI pasa
cuando el motor de templates interpola input sin escapar dentro de la
sintaxis del template (no solo del HTML resultante); deserialización
insegura pasa cuando el server reconstruye un objeto desde bytes que
el atacante controla, sin validar qué tipo de objeto está construyendo.

No son el mismo bug — se separan abajo en dos metodologías — pero
comparten el mismo gate de evidencia duro: **sin ejecución de código
confirmada (RCE) o callback OOB, no hay finding**, por más que el
motor/formato esté identificado con certeza.

---

## Gate de evidencia general — no negociable

Identificar el motor de templates o el formato de serialización **no
es un finding**. Evaluar una expresión aritmética en el template
(`{{7*7}}` → `49`) o observar un error de deserialización en el log
**no son findings** — son confirmación de que el vector existe, el
paso siguiente obligatorio es demostrar impacto real:

- **SSTI confirmado** = ejecución de comando del sistema operativo
  demostrada (output del comando reflejado, o callback OOB si no hay
  reflejo) — no alcanza con evaluación aritmética o acceso a objetos
  internos del motor sin llegar a ejecución.
- **Deserialización confirmada** = callback OOB recibido (DNS/HTTP vía
  gadget chain que dispara una request saliente), o efecto observable
  demostrado (archivo escrito, comando ejecutado, error que cambia de
  forma predecible y controlable según el payload — no solo "tiró
  excepción distinta").

Sin uno de los dos, el techo es Informational/P4, documentado como
candidato con el motor/formato identificado y qué falta para confirmar.

---

## Conocimiento previo

Use the `hexbrain` skill for relevant public prior art when it can change the test plan; verify any lead against primary sources and target evidence.

## SSTI — metodología

### 1. Identificar el motor

Fingerprint primero por stack (ver `references/ssti-payloads-by-engine.md`
para la tabla completa framework→motor por default):

| Stack | Motor típico por default |
|---|---|
| Flask/Django (Python) | Jinja2 (Flask), Django Templates |
| Spring Boot (Java) | Thymeleaf, FreeMarker, Velocity |
| Symfony/Laravel-adjacent (PHP) | Twig |
| Node/Express | EJS, Handlebars, Pug, Nunjucks |
| ColdFusion | CFML |

No asumas el motor por el lenguaje del backend — frameworks modernos
mezclan (Spring puede correr Thymeleaf o FreeMarker según config).
Confirmar con el polyglot antes de elegir payloads específicos de un
motor.

### 2. Polyglot de detección

Mandar un polyglot que produzca salida distinguible en varios motores
a la vez, antes de apostar a uno:

```
${{<%[%'"}}%\.
```

Si parte del polyglot se evalúa (desaparece un fragmento específico,
o aparece un error de sintaxis del motor en vez de un 500 genérico),
usar qué fragmento disparó para acotar el motor candidato — ver
`references/ssti-payloads-by-engine.md` para el mapeo polyglot→motor.

### 3. Confirmar con aritmética (paso intermedio, no el finding)

Una vez acotado el motor candidato, confirmar evaluación real:

```
{{7*7}}        # Jinja2/Twig → 49
${7*7}         # FreeMarker/Velocity/JSP EL → 49
#{7*7}         # Thymeleaf (si SpEL habilitado) → 49
<%= 7*7 %>     # ERB/EJS → 49
```

`49` en la respuesta = el motor evalúa el input como expresión, no
como texto plano. **Esto es un checkpoint intermedio, no el finding
— seguir al paso 4 siempre.**

### 4. Escalar a RCE

Por motor (catálogo completo con más variantes en
`references/ssti-payloads-by-engine.md`):

```
# Jinja2 (Python) — via __class__ walk hasta subprocess
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}

# Twig (PHP)
{{ ['id'] | map('system') }}

# FreeMarker (Java)
<#assign ex = "freemarker.template.utility.Execute"?new()>${ex("id")}

# Velocity (Java)
#set($e="exp")$e.getClass().forName("java.lang.Runtime").getMethod("exec",$e.getClass().forName("java.lang.String")).invoke($e.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")
```

Si el sandbox/filtro del motor bloquea el payload directo, no hay
catálogo de bypass en este skill todavía — documentar el motor
confirmado, el bloqueo exacto observado, y dejarlo como candidato de
alta confianza con el killer específico del bloqueo (ej: "FreeMarker
con `TemplateClassResolver` restringido a allowlist, `Execute` no
resuelve").

---

## Deserialización insegura — metodología

### 1. Identificar el formato por magic bytes / encoding

No asumas el lenguaje por el framework — confirmá el formato real del
blob antes de elegir gadget chain:

| Prefijo / patrón | Formato |
|---|---|
| `rO0AB` (base64) o bytes `AC ED 00 05` | Java `ObjectInputStream` nativo |
| `O:` seguido de un número (ej `O:8:"ClassName"`) | PHP `unserialize()` (formato nativo) |
| `a:`, `s:`, `i:` al inicio (sin `O:`) | PHP serialize, probablemente sin objeto — menos interesante |
| Header `Content-Type: application/x-java-serialized-object` | Java, explícito |
| Cookie/param llamado `__VIEWSTATE` | .NET ViewState (puede o no tener MAC validation) |
| `gASV` o `KGRw` (base64) | Python `pickle` |
| Bloque YAML con `!!python/object:` o `!!java.lang` | YAML inseguro (`yaml.load` sin `SafeLoader`, SnakeYAML sin tipo restringido) |
| `BAh` (base64) | Ruby `Marshal.load` |

### 2. Confirmar que el server realmente deserializa el blob sin validar tipo

Antes de armar un gadget chain, confirmar la superficie: mandar un
blob malformado del formato correcto (header correcto, contenido
basura) y ver si el error es de parseo de formato (confirma que el
endpoint intenta deserializar) vs. un error que sugiere que el input
nunca llega a un deserializer real (ej: rechazado por longitud/charset
antes de tocar el parser).

### 3. Gadget chain por lenguaje

No reinventar gadgets — usar las herramientas estándar del ecosistema
para generar el payload, documentar exactamente qué chain se usó:

- **Java**: `ysoserial` (`java -jar ysoserial.jar <Gadget> '<comando>' > payload.bin`). Gadgets comunes a probar primero según librerías detectadas en el classpath/JS del fingerprint: `CommonsCollections1-7`, `Spring1-2`, `ROME`, `Groovy1`, `Jdk7u21`. Si no se puede fingerprint el classpath, probar los gadgets más universales primero (CommonsCollections, dado lo común que es Commons Collections como dependencia transitiva).
- **PHP**: requiere una clase con método mágico explotable (`__wakeup`, `__destruct`, `__toString`) presente en el código de la app o sus dependencias — sin eso, `unserialize()` inseguro no es explotable por sí solo. Buscar POP chain candidata en el código fuente si está accesible (composer.lock, vendor/), o en frameworks conocidos (Laravel, Monolog tienen chains públicas documentadas).
- **Python**: `pickle.loads()` inseguro — gadget clásico vía `__reduce__` en una clase custom que ejecuta `os.system`/`subprocess`. `yaml.load()` sin `Loader=yaml.SafeLoader` permite construir objetos arbitrarios vía `!!python/object/apply:os.system`.
- **.NET**: `BinaryFormatter`/`ObjectDataProvider` vía `ysoserial.net` (equivalente a ysoserial para .NET, gadgets `TypeConfuseDelegate`, `ActivitySurrogateSelector`). Para `__VIEWSTATE`: si `EnableViewStateMac` está deshabilitado o la `validationKey`/`decryptionKey` se puede derivar (clave default conocida, o leakeada), el ViewState es forjable — revisar `references/deserialization-by-language.md` para el procedimiento con `ysoserial.net --generator=ViewState`.
- **Ruby**: `Marshal.load` inseguro con gadget vía `Gem::Requirement` u otras clases con `_load`/`marshal_load` explotables (Rails ha tenido CVEs documentados en este patrón — ver si la versión de Rails/gems coincide con algún CVE conocido antes de intentar construir un gadget desde cero).

### 4. Confirmar con OOB o efecto observable

Mismo criterio que SSRF — preferir un payload que dispare un callback
DNS/HTTP a un listener propio (`Interactsh`/`Burp Collaborator`) como
primera confirmación, menos invasivo que apuntar directo a RCE
completo. Si el gadget solo soporta ejecución directa (no hay gadget
de "solo hacer un request saliente" disponible para ese chain), usar
un comando de bajo impacto (`id`, `whoami`, `sleep 5` para confirmar
por timing) antes de escalar a algo con efecto persistente.

---

## Qué mata el lead

- El endpoint rechaza el blob antes de llegar a cualquier deserializer
  real (ej: validación de longitud/charset/whitelist de tipo previa).
- El motor de templates usa sandbox real (no solo un filtro de
  palabras) y el payload de escalación falla específicamente contra
  ese sandbox — documentar el mecanismo exacto del sandbox, no
  "está protegido" genérico.
- El formato de serialización detectado no tiene ninguna clase
  explotable conocida en el classpath/dependencias visibles, y no se
  puede confirmar acceso al código fuente para buscar una POP chain
  custom — queda como candidato sin vía de explotación confirmada, no
  como MUERTO (puede haber una clase explotable no identificada
  todavía).
- Blind total sin ningún gadget capaz de generar tráfico saliente ni
  efecto observable por timing — documentar como Informational hasta
  tener una vía de confirmación.

## Severidad

Sin RCE o callback OOB confirmado = Informational o P4 máximo, sin
importar cuán identificable sea el motor/formato. SSTI con RCE
confirmado parte de P2 como piso (ejecución arbitraria en el server).
Deserialización con RCE confirmado, igual piso — si además el proceso
corre con privilegios elevados o en un contexto con acceso a datos de
otros tenants, sube a P1.

## Referencias

- `references/ssti-payloads-by-engine.md` — tabla completa
  framework→motor por default, polyglots de detección, payloads de
  escalación por motor (Jinja2, Twig, FreeMarker, Velocity, Thymeleaf,
  Smarty, Handlebars/ERB/EJS, Pug). Cargar cuando ya se identificó o
  se sospecha fuerte el motor.
- `references/deserialization-by-language.md` — detalle de magic
  bytes/fingerprint por formato, uso de `ysoserial`/`ysoserial.net`,
  gadget chains conocidas por librería, y el procedimiento de ViewState
  forgery para .NET. Cargar cuando ya se confirmó el formato del blob.

## Cross-links

- **`ssrf`** — un gadget de deserialización que solo logra disparar una
  request saliente (sin RCE directo) es, en los hechos, un SSRF vía
  deserialización — aplica el mismo gate de evidencia de `ssrf` (OOB
  callback) para esa confirmación específica.
- **`exposed-secrets`** — si la explotación de .NET ViewState depende
  de una `validationKey`/`decryptionKey` leakeada en vez de ausente,
  la fuente de esa key es un finding de `exposed-secrets` aparte,
  encadenado.
