---
name: output_format_enumerator
description: Dado un software open-source conocido corriendo en el target (nombre
  + versión), enumera su superficie completa de formatos de salida alternativos
  leyendo el código fuente real o la documentación oficial. No fuzzing ciego.
  Sub-step de XSS cuando el fingerprint detecta software con arquitectura de
  plugins/renderers y un parámetro format=/f=/type= observable.
---

# Output Format Enumerator

## Cuándo se invoca

Señales de trigger (cualquiera de estas):
- Fingerprint identifica software conocido con arquitectura de renderers/printers
  (MediaWiki, SRF, Drupal Views, WordPress REST, ArcGIS Server, GeoServer,
  Liferay, TYPO3, Moodle, Roundcube, etc.)
- Response contiene parámetro `format=`, `f=`, `type=`, `outputFormat=`,
  `rendererType=`, `output=` con un valor identificador de formato
- Endpoint devuelve distinto Content-Type según el valor del parámetro
- JS del target menciona un array/objeto de formatos disponibles

**No se invoca** si el software no es identificable con versión o si no hay
evidencia de arquitectura de formatos alternativos.

---

## Arquitectura: tres modos de enumeración

La generalización clave de este módulo es que **el método de enumeración
depende de cómo el software expone sus formatos**, no del software en sí.
Clasificar antes de ejecutar:

### Modo A — Repo-based (open source con releases etiquetadas)

Aplica cuando: el software tiene repo público con tags de versión exacta
y los renderers/printers viven como clases/archivos en el código fuente.

**Flujo:**
1. Resolver software → repo oficial (ver tabla de mapeos abajo)
2. Clonar el tag exacto de la versión detectada:
   ```bash
   git clone --branch <tag> --depth 1 <repo_url> /tmp/sw_source
   # Si el tag no existe exacto, buscar el más cercano:
   git tag -l | grep <version_prefix> | sort -V | tail -5
   ```
3. Encontrar el directorio de formatos (ver heurísticas abajo)
4. Por cada clase encontrada: extraer nombre, parámetros, tipo de sink
5. Filtrar y clasificar (ver criterios abajo)
6. Verificar disclosures existentes

### Modo B — Doc-based (software propietario/comercial con catálogo documentado)

Aplica cuando: el software no tiene repo público pero mantiene documentación
oficial de sus parámetros de API. Típico en GIS comercial, enterprise CMS
propietario, plataformas cloud.

**Flujo:**
1. Localizar la página de docs correspondiente a la versión exacta detectada
   (las APIs cambian entre versiones — versión exacta importa)
2. En la docs, buscar la sección de "output formats", "response formats",
   "f= parameter", "format parameter" o equivalente
3. Extraer: lista de valores válidos del parámetro, parámetros adicionales
   por formato, tipo de contenido devuelto (HTML/JSON/XML/binary)
4. Priorizar los que devuelven HTML o texto sin Content-Type restrictivo
5. No hay análisis de código fuente — la docs es la fuente de verdad

### Modo C — Grep-based fallback

Aplica cuando: no hay repo, no hay docs claras de formatos, o el software
tiene un framework base conocido pero las extensiones/portlets son custom
y propietarios.

**Flujo:**
1. Descargar el HTML/JS de las páginas principales del target:
   ```bash
   curl -s "https://target.com/page" | grep -oE 'format=[a-zA-Z0-9_-]+' | sort -u
   curl -s "https://target.com/page" | grep -oE '"format"\s*:\s*"[^"]+"' | sort -u
   ```
2. Buscar en JS servido por el target (no vendor):
   ```bash
   # Valores del parámetro hardcodeados en JS propio
   grep -oE '(format|outputFormat|rendererType|f)\s*[=:]\s*["\x27][a-zA-Z0-9_-]+["\x27]' target_js.js | sort -u
   # Arrays de formatos disponibles
   grep -oE 'formats\s*[=:]\s*\[[^\]]+\]' target_js.js
   ```
3. Buscar en el HTML de respuestas con el parámetro ya visible:
   ```bash
   # Selects o options que exponen los valores
   grep -oE '<option[^>]*value=["\x27][^"'\'']+["\x27]' response.html
   ```
4. Si el framework base es conocido (ej: Liferay), usar los valores por
   default de ese framework como seed list y verificar cuáles responden
5. Output: lista de valores candidatos sin garantía de exhaustividad —
   marcarlos como `source: grep_inferred` para el paso siguiente

---

## Tabla de mapeos conocidos

Esta tabla es la fuente de verdad del módulo. Actualizar cuando aparezca
un software nuevo. Formato: `software_id | modo | repo_o_doc_url | patrón_de_formats_dir`.

| Software | Versión ref | Modo | Fuente | Directorio de formatos |
|---|---|---|---|---|
| MediaWiki core | cualquiera | A | github.com/wikimedia/mediawiki | `includes/api/` — clases `ApiFormat*.php` que extienden `ApiFormatBase` |
| SemanticResultFormats | cualquiera | A | github.com/SemanticMediaWiki/SemanticResultFormats | `src/` o `formats/` — clases que extienden `SMWResultPrinter` / `ResultPrinter` |
| Semantic MediaWiki | cualquiera | A | github.com/SemanticMediaWiki/SemanticMediaWiki | `src/Query/ResultPrinters/` |
| Drupal Views | 8/9/10 | A | git.drupalcode.org/project/drupal | `core/modules/views/src/Plugin/views/style/` |
| WordPress REST API | cualquiera | A | github.com/WordPress/WordPress | `src/wp-includes/rest-api/` |
| GeoServer | cualquiera | A | github.com/geoserver/geoserver | `src/wms/src/main/java/org/geoserver/wms/responses/` y `src/wcs/` |
| ArcGIS Server | cualquiera | B | developers.arcgis.com/rest/services-reference/ | Doc: sección "Output" de cada endpoint, parámetro `f=` |
| Esri Portal/AGO | cualquiera | B | developers.arcgis.com/rest/users-groups-and-items/ | Doc: sección "Response" de cada endpoint |
| TYPO3 | 10/11/12 | A | github.com/TYPO3/typo3 | `typo3/sysext/core/Classes/DataHandling/` + extensiones custom |
| Moodle | cualquiera | A | github.com/moodle/moodle | `lib/outputrenderers.php` + `mod/*/renderer.php` |
| Roundcube | cualquiera | A | github.com/roundcube/roundcubemail | `plugins/*/` — plugins con output hooks |
| Liferay portlets custom | cualquiera | C | — (propietario) | Grep JS/HTML: `_outputFormat`, portlet namespace + `format` |
| OpenLayers (cliente) | cualquiera | C | — (JS bundle) | Grep JS: `format:`, `outputFormat:` en config de capas WMS |

**Agregar nuevas filas cuando aparezca un software no listado.** No inventar
el modo ni la fuente — si no está claro, empezar por Modo C como fallback.

---

## Heurísticas para encontrar el directorio de formatos (Modo A)

Si el directorio no es obvio desde la tabla de mapeos, aplicar en orden:

**1. Buscar por nombre de directorio:**
```bash
find /tmp/sw_source -type d \( \
  -name "format*" -o -name "render*" -o -name "printer*" \
  -o -name "output*" -o -name "style" -o -name "handler*" \
\) | grep -v -E "test|vendor|node_modules|\.git"
```

**2. Buscar por herencia de clase base:**
```bash
# PHP
grep -r "extends.*Printer\|extends.*Format\|extends.*Renderer\|implements.*OutputInterface" \
  /tmp/sw_source --include="*.php" -l | grep -v test | grep -v vendor

# Python
grep -r "class.*Printer\|class.*Format\|class.*Renderer" \
  /tmp/sw_source --include="*.py" -l | grep -v test

# Java
grep -r "implements.*OutputHandler\|extends.*AbstractFormat\|@Format" \
  /tmp/sw_source --include="*.java" -l | grep -v test
```

**3. Validar que es el directorio correcto:** el directorio de formatos tiene
al menos 3+ archivos/clases que implementan la misma interfaz. Si hay solo 1-2,
es probablemente un helper, no el registro de formatos.

---

## Extracción por clase/archivo (Modo A)

Por cada archivo encontrado en el directorio de formatos:

### Nombre identificador del formato
El string que va como valor del parámetro `format=`. Buscar en este orden:
```bash
# PHP: constante de nombre, nombre de archivo, o valor de método getName()
grep -E "getName|'name'\s*=>\s*['\"]|format_name\s*=" archivo.php | head -5
# Si no hay: el nombre del archivo sin extensión, en lowercase, es el candidato

# Python: atributo de clase
grep -E "format_name\s*=|name\s*=\s*['\"]" archivo.py | head -5

# Java: anotación o constante
grep -E "@Format\(|FORMAT_NAME\s*=\|formatName\s*=" Archivo.java | head -5
```

### Parámetros propios del formato
```bash
# PHP: método getParamDefinitions, getParameters, getDefaultParameters
grep -A 30 "function getParamDef\|function getParam\b\|function getDefaultParam" archivo.php

# Python: método get_params, params dict
grep -A 20 "def get_params\|params\s*=\s*{" archivo.py

# Java: método getParameterDescriptions, @Parameter annotations
grep -B2 -A5 "@Parameter\|getParameterDesc" Archivo.java
```

### Tipo de sink de renderizado

Clasificar como uno de cuatro tipos analizando el cuerpo del método principal
de output (`getResult`, `getHTML`, `render`, `execute`, o equivalente):

- **`html_direct_raw`** — la clase construye HTML a mano Y los parámetros del
  usuario entran sin función de escape en el punto de concatenación. Candidato
  real para XSS.
- **`html_direct_escaped`** — la clase construye HTML a mano PERO los parámetros
  están envueltos en escape antes de concatenar. Killer aplicado — no pasa al
  fuzzer salvo que se busque bypass del escape específico.
- **`structured_data`** — output es JSON, XML, CSV, KML, GML, RDF: buscar
  `json_encode`, `simplexml`, `csvWriter`, extensiones `.json`/`.xml`/`.csv`
  en el nombre de clase.
- **`wraps_default_template`** — delega a un sistema de templates compartido:
  buscar `$this->template->render`, `Twig::render`, `Smarty::display`,
  `return parent::getHTML()`.

**Sub-check obligatorio para clasificar `html_direct_raw` vs `html_direct_escaped`:**

Por cada parámetro propio extraído, verificar si aparece envuelto en una
función de escape en el punto donde se concatena al HTML de salida:

```bash
# PHP — funciones de escape comunes:
grep -n "\$paramVar" archivo.php | grep -E \
  "htmlspecialchars|htmlentities|Html::encode|Html::escapeAttribute|\
wfEscapeWikiText|esc_html|esc_attr|e\(\\\$|strip_tags"

# Si el param aparece en una línea CON alguna de esas funciones → escaped
# Si el param aparece en concatenación directa sin esas funciones → raw

# Python
grep -n "param_var" archivo.py | grep -E "escape\(|markupsafe|html\.escape|bleach"

# Java
grep -n "paramVar" Archivo.java | grep -E \
  "StringEscapeUtils|HtmlUtils\.htmlEscape|escapeHtml|Encode\.forHtml"
```

Nota: el check tiene que hacerse **en el punto de uso en el método de output**,
no en el método de validación de parámetros. Un parámetro puede ser validado
contra una whitelist (que no es escape) y seguir siendo raw en el sink.

### Error path dentro de la clase (exception reflection)

Cada clase puede tener su propio path de error cuando recibe un parámetro
inválido — y ese path a menudo cita el valor sin escapar en el mensaje de
excepción. Es un segundo sink por formato, independiente del happy path.

```bash
# Buscar throws que interpolán el valor del parámetro directamente:
grep -n "throw new\|throw \$" archivo.php | head -20
# Luego para cada throw encontrado, ver si el mensaje incluye la variable:
grep -A3 "throw new.*Exception" archivo.php | grep -E "\\\$param|\\\$value|\\\$input"

# Python
grep -n "raise " archivo.py | grep -E "f['\"]|\.format\(|% "

# Java
grep -n "throw new" Archivo.java | grep -E "paramValue|inputValue|userInput"
```

Si el mensaje de excepción interpola el parámetro crudo → agregar una entrada
separada en el output con `sink_type: "exception_reflection"` y
`path: "error_handler"`. Este sink se conecta con el patrón documentado en
`xss/SKILL.md` (sección "Source subestimado: error handlers que citan el input").

Para sistemas OGC/GeoServer específicamente: el error no lo lanza la clase
del formato sino el dispatcher central (`Dispatcher.java`, `OWS` framework)
cuando el valor del parámetro `format=` o `service=` no matchea ningún
renderer registrado. Buscar en el directorio raíz del proyecto, no en la
clase del formato:
```bash
grep -rn "not.*recognized\|unknown.*format\|invalid.*format\|no.*renderer" \
  /tmp/sw_source/src --include="*.java" --include="*.xml" | grep -i "exception\|error\|message"
```
Si el dispatcher cita el valor en el `ServiceExceptionReport` XML sin escape →
marcar como `sink_type: "ogc_service_exception"`, aplica a todos los formatos
del sistema, no solo a uno.

---

## Filtrado y priorización

De todos los formatos encontrados, filtrar para el siguiente paso:

1. **Descartar** `structured_data` puro — EXCEPTO si el `Content-Type` de la
   respuesta es `text/xml` o `application/xml` y el browser lo renderiza
   directamente (ver sección XML Context XSS abajo).
2. **Descartar** el formato default del sistema (normalmente `html`, `default`,
   `table`, o `wikitable`) — ya está cubierto por el path normal.
3. **Descartar** `html_direct_escaped` — killer aplicado. Retener solo como
   contexto si se va a investigar bypass del escape específico.
4. **Candidatos reales al fuzzer**: `html_direct_raw` y `exception_reflection`
   y `ogc_service_exception`. Cuantos más parámetros propios tenga un
   `html_direct_raw`, mayor superficie.
5. **Notar** `wraps_default_template` — pueden ser interesantes si el template
   acepta parámetros que el formato no sanitiza antes de pasarlos.

---

## XML Context XSS — cuando el formato devuelve XML

Cuando un formato enumerable devuelve `Content-Type: text/xml` o
`application/xml` (o `image/svg+xml`), el riesgo de XSS es diferente al
HTML context: el parser XML tiene sus propias reglas de escape y los sinks
son distintos.

**Cuándo aplica:**
- El formato devuelve XML que el browser renderiza directamente (sin pasar
  por JS del frontend)
- El frontend inyecta la respuesta XML en el DOM via `innerHTML` o similar
- El XML contiene SVG embebido que el browser procesa como HTML

**Señal de verificación:** abrir la URL del formato XML directamente en el
browser. Si el browser muestra el árbol XML raw (con indentación coloreada),
el parser XML está activo — `<script>` dentro del XML puede ejecutar si el
XML es un SVG o XHTML servido con el Content-Type correcto.

**Payloads específicos para XML context:**

```xml
<!-- SVG served as image/svg+xml — ejecuta en el origen -->
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.domain)</script>
</svg>

<!-- CDATA breakout — el XML parser trata el contenido de CDATA como texto,
     pero si el output va a un innerHTML de HTML, el browser HTML-parsea
     el texto resultante y ejecuta el script -->
<description><![CDATA[</description><script>alert(1)</script><!--]]></description>

<!-- Atributo XML sin escaping correcto -->
<item title="PAYLOAD"><![CDATA[ ]]></item>
```

**Clasificación del sink para el output del módulo:**
Agregar tipo `xml_context` al enum de `sink_type` cuando aplique:
- `xml_context_svg` — SVG con script ejecutable
- `xml_context_cdata_breakout` — CDATA que llega a innerHTML
- `xml_context_attribute` — atributo XML sin escape en output renderizado

**Killer válidos para XML XSS:**
- El XML está bien formado y usa `xmlspecialchars`/`htmlspecialchars` en
  todos los nodos de texto y atributos antes de serializar
- El browser no renderiza el XML directamente (lo consume JS y lo descarta)
- Content-Type `application/xml` con `X-Content-Type-Options: nosniff` —
  el browser no ejecuta scripts en ese contexto

---

## Verificación de disclosures existentes

Antes de pasar los candidatos al fuzzer, verificar si el printer/clase
específica ya tiene hallazgo público. Buscar en orden:

```bash
# GitHub Security Advisories del repo
# URL: github.com/<org>/<repo>/security/advisories

# CVE databases
# Query: "<software_name> <format_name> XSS" en NVD y OSV

# Bugcrowd/HackerOne Hacktivity
# Query: "<software_name> <format_name>"
```

Si hay disclosure público del mismo printer y versión → marcar
`ya_reportado: true` y no reportar como finding propio. Si es una versión
más nueva que el disclosure o un parámetro distinto del mismo printer →
`ya_reportado: parcial` y documentar la diferencia.

---

## Output del módulo

Lista estructurada para alimentar el fuzzer dirigido:

```
[
  {
    "formato": "broadtable",
    "parametro_invocacion": "format=broadtable",
    "parametros_propios": ["headers", "class", "style"],
    "sink_type": "html_direct_raw",        // raw | escaped | structured_data | wraps_default_template
    "path": "happy_path",                  // happy_path | error_handler | ogc_service_exception
    "ya_reportado": false,
    "fuente": "github.com/SemanticMediaWiki/SemanticResultFormats/src/formats/BroadTablePrinter.php",
    "version_analizada": "4.2.0",
    "notas": "parámetro 'class' concatenado sin escape en atributo class del <table>"
  },
  {
    "formato": "broadtable",
    "parametro_invocacion": "format=broadtable&charttype=INVALID",
    "parametros_propios": ["charttype"],
    "sink_type": "exception_reflection",
    "path": "error_handler",
    "ya_reportado": false,
    "fuente": "BroadTablePrinter.php línea 87 — throw new InvalidArgumentException con $charttype crudo",
    "version_analizada": "4.2.0",
    "notas": "mensaje de excepción interpola el valor sin htmlspecialchars"
  },
  {
    "formato": "*",
    "parametro_invocacion": "format=INVALID",
    "parametros_propios": [],
    "sink_type": "ogc_service_exception",
    "path": "ogc_service_exception",
    "ya_reportado": false,
    "fuente": "Dispatcher.java — ServiceExceptionReport XML cita el valor del parámetro format=",
    "version_analizada": "2.24.0",
    "notas": "aplica a todos los formatos del sistema; sink es XML sin escape del valor"
  }
]
```

Escribir este output en `targets/<programa>/surface_checklist.md` bajo la
sección del software correspondiente, con estado `PENDIENTE-FUZZ`.

---

## Regla dura

Este módulo genera **candidatos**, no findings. Ninguna severidad se asigna,
ningún lead se abre en `leads.md`, hasta que el operador confirme ejecución
real en navegador (Playwright screenshot, callback OOB recibido, o reflejo
crudo verificado). El módulo reduce el espacio de búsqueda — no reemplaza
la confirmación.

---

## Mantenimiento de la tabla de mapeos

Cuando el módulo procesa un software que no está en la tabla:
1. Intentar Modo A primero (buscar repo oficial en GitHub/GitLab/Bitbucket)
2. Si no hay repo, intentar Modo B (buscar docs de API de la versión)
3. Si no hay docs claras, usar Modo C y marcar `source: grep_inferred`
4. **Agregar la fila a la tabla** con el modo y la fuente encontrada — no
   procesar el mismo software dos veces a ciegas
