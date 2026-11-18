# Bypass Techniques por tipo de defensa

Cada bypass acá te lleva como máximo a "upload aceptado" — confirmar
ejecución real (GET al archivo, ver si corre o vuelve crudo) antes de
hablar de RCE. Ver gate de confirmación en `SKILL.md`.

| Defensa | Bypass | Nota |
|---|---|---|
| Blacklist de extensión (`.php`, `.asp`, ...) | Variantes ejecutables no listadas: `.php3/4/5/7`, `.phtml`, `.pht`, `.phar`, `.asa`, `.cer`, `.jsp`/`.jspx`. | Probar cada una — el blacklist casi nunca cubre todas las variantes del stack. |
| Blacklist case-sensitive | `.pHp`, `.PHP`, `.PhP` — si el check compara string exacto sin lowercase. | Probar SIEMPRE, es gratis. Si el check es case-insensitive (rechaza todas las variantes) no perder más tiempo en esta rama. |
| Whitelist de extensión (última tras el último punto) | Doble extensión `shell.php.jpg` — sube, pero **solo ejecuta si el servidor tiene `AddHandler` sin anclar** (no `<FilesMatch \.php$>`). Confirmar con un GET directo: si vuelve el código fuente crudo con `Content-Type` de imagen, no hay handler match — la ejecución falló, aunque la subida haya pasado. | No asumir ejecución solo porque la subida fue aceptada — son dos checks independientes. |
| Whitelist con regex sin anclar | Si el check es `.includes('.jpg')` en vez de `.endsWith()`, un archivo `shell.jpg.php` (jpg en el medio, php al final) pasaría el check Y ejecutaría. | Probar ambos órdenes de extensión — no asumir cuál aplica sin probar el orden invertido explícitamente. |
| **Null byte en filename** | `Content-Disposition: ...; filename="exploit.php%00.jpg"` — el validador de extensión ve el string completo (termina en `.jpg`, pasa), pero el backend decodifica el `%00` internamente y trunca el nombre real guardado a `exploit.php`. | **Gotcha de testing**: mandar el string **literal** `%00` (los 3 caracteres `%`, `0`, `0`) en el campo `filename` del multipart — NO un byte `0x00` crudo inyectado en el body. Un byte crudo suele ser rechazado de entrada por el parser (mismo error genérico que `.php` puro) y da falso negativo de "no vulnerable". El bypass real depende de que el backend haga su propio decode del string `%00` después de la validación — probar ambas variantes (raw byte y string literal) antes de descartar la técnica. |
| Content-Type del multipart | Header `Content-Type: image/jpeg` mentiroso sobre un archivo `.php` — rara vez alcanza solo (la extensión suele validarse aparte), pero confirma qué chequea el filtro exactamente si el server SÍ lo acepta. | Probar junto con la extensión real primero — barato, y aísla si el check es de extensión, content-type, o ambos. |
| Magic bytes / sniffing de contenido | Prefijo con bytes mágicos reales de imagen (`\xFF\xD8\xFF` JPEG, `\x89PNG` PNG) seguido del payload real (polyglot), si el filtro abre el archivo para "confirmar" que es imagen pero solo mira los primeros bytes. | Requiere que el runtime que ejecuta el archivo ignore basura antes/después del código válido (PHP sí lo hace fuera de las tags `<?php ?>`; GIF89a + PHP es el polyglot clásico). |
| Duplicar campos/parámetros en el multipart | Dos partes con `name="avatar"`, o `filename=` y `filename*=` (RFC 5987) con valores distintos — si validación y guardado leen índices/campos distintos del mismo multipart. | Barato de probar, rara vez funciona en parsers modernos (busboy/multer/Commons FileUpload son consistentes) pero vale la pena descartar. |
| Path traversal en filename | `../../../var/www/html/shell.php` como nombre — si el backend concatena el filename a una ruta base sin normalizar/sanitizar. | Objetivo distinto: no es bypass de extensión, es escribir fuera del directorio de uploads. Puede combinarse con lo anterior si además hace falta bypass de extensión para que el nombre pase validación. |
| **`.htaccess` / `web.config` como vector propio (Apache/IIS)** | Subir un `.htaccess` con `AddType application/x-httpd-php .jpg` (Apache) o un `web.config` con handler mapping equivalente (IIS). Una vez que el server lo lee, TODOS los `.jpg` que subas después ejecutan como PHP/ASP — sin volver a pelear la whitelist de extensión nunca más. | **Categoría aparte, no una variante más** — el ataque es al archivo de configuración, no al payload. Requiere: (a) que el filtro no trate `.htaccess`/`web.config` como "extensión peligrosa" (muchas whitelists solo miran extensiones de código, no nombres de config), y (b) que `AllowOverride` esté habilitado en Apache (si está en `None`, el `.htaccess` subido se ignora — confirmar esto con un `.htaccess` de prueba inocuo antes de asumir que funciona). Alto impacto: controla la ejecución de todo el directorio, no un archivo — priorizar esta prueba temprano, antes de perder tiempo en variantes de extensión. |
| Terminación NTFS (`shell.php.`, `shell.php `) | Punto o espacio final en el nombre — Windows lo descarta al guardar en disco, pero el string que ve el validador (antes de guardar) todavía lo tiene, así que puede fallar el match de `.php` limpio en la blacklist mientras el archivo termina guardado como `shell.php` de verdad. | Solo aplica a backends corriendo sobre Windows/NTFS — confirmar el OS del server antes de probarlo. Variante legacy adicional en IIS viejo: `shell.php::$DATA` (alternate data stream). |
| Strip no recursivo de string peligroso | Si el filtro hace `nombre.replace("php", "")` una sola pasada (no recursivo/regex global), `shell.pphphp` → después del strip queda `shell.php`. | Patrón común en filtros escritos rápido con `.replace()` simple. Probar con la extensión target duplicada alrededor de sí misma (`pphphp`, `jjspsp`, etc.) antes de descartar. |

## Root causes comunes (para reconocer el patrón rápido)

1. **Dos code paths para el mismo dato** — el que valida y el que
   guarda/sirve el archivo no leen el filename de la misma forma
   (decodificado vs crudo, primera vs última ocurrencia de un campo,
   `filename` vs `filename*`). El bypass siempre vive en ESE
   diferencial — pensar en términos de "¿qué ve cada lado?" antes de
   probar payloads al azar.
2. **Whitelist ancla al último punto, pero el handler de ejecución del
   servidor no** — ver fila de doble extensión arriba. Confirmar
   empíricamente cuál modelo aplica (siempre con un GET real al
   archivo) antes de dar el bypass por bueno.
3. **Validación de extensión sin validación de contenido, o viceversa**
   — nunca asumir que ambas están activas; probar cada una por
   separado para saber contra qué se está jugando.
4. **El filtro piensa en extensiones de código, no en archivos de
   configuración** — `.htaccess`/`web.config` no "parecen" peligrosos
   para una whitelist pensada en `.php`/`.jsp`/`.asp`, pero redefinen
   qué ejecuta el servidor. Es la variante de mayor impacto de la
   tabla — probarla temprano, no como último recurso.
