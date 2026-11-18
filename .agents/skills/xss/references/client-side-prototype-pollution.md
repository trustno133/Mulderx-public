# Client-side prototype pollution → DOM XSS

Cargar cuando el sink candidato es DOM-based y el source no es el típico
`location.hash`/`postMessage` reflejado directo, sino un objeto armado a
partir del query string o el hash por un parser propio del bundle
(`deparam`, `parseParams`, `qs`-like, cualquier función que convierta
`key[sub]=val` o `key.sub=val` en un objeto anidado). Ver también
`npm-packages/references/prototype-pollution-catalog.md` para la variante
**server-side** (misma raíz conceptual, source/gadget/detección
completamente distintos — esa cubre librerías npm tipo `lodash.merge` con
`req.body` como source; esta cubre JS que corre en el navegador).

Catálogo armado sobre 4 labs de PortSwigger Academy resueltos en sesión
(pswa-prototype-pollution-browser-apis, pswa-prototype-pollution-dom-xss,
pswa-prototype-pollution-alt-vector, pswa-prototype-pollution-bypass-defense
— ver `targets/` para el detalle completo de cada trazado).

## Paso 1 — encontrar el source

Buscar en Sources (o bajar el JS con curl y grep) cualquier función que
parsee `location.search`/`location.hash`/`new URL(location)` en un objeto
anidado. Dos formas típicas de notación, mismo bug de fondo:

- **Corchetes**: `key[sub][sub2]=val` (`deparam.js` estilo jQuery BBQ).
- **Puntos**: `key.sub.sub2=val` (`$.parseParams` u otros).

El bug de fondo en ambas: cuando el parser arma el objeto nivel por nivel
con algo como `cur = cur[key] = cur[key] || {}`, y `key` resulta ser el
string literal `"__proto__"`, la LECTURA `cur["__proto__"]` no crea nada
nuevo — invoca el getter nativo de `__proto__`, que devuelve el
`Object.prototype` real (truthy), así que el `||` corta ahí. El `cur =`
que sigue deja la variable apuntando literalmente al `Object.prototype`
global. El próximo nivel de la key hace un set normal sobre esa
referencia → pollution directa del prototype global, sin necesidad de
ningún gadget adicional para ESTE paso.

**Confirmar el source (rápido, sin gadget)**:
```
/?__proto__[foo]=bar          (notación corchetes)
/?__proto__.foo=bar           (notación puntos)
```
DevTools → Console → `Object.prototype.foo` debería devolver `"bar"`.

## Paso 2 — encontrar el gadget

Buscar en el JS del bundle cualquier lectura de una propiedad de un
objeto plano que NO haya sido asignada explícitamente en ese mismo
scope, y que alimente un sink de ejecución. Patterns vistos, de más a
menos directo:

### 2a — `script.src` sin shadow (el caso simple)
```js
let config = {params: ...};   // transport_url NUNCA se asigna acá
if (config.transport_url) {
    let s = document.createElement('script');
    s.src = config.transport_url;
    document.body.appendChild(s);
}
```
Si `transport_url` no es propiedad propia de `config`, la lectura sube
al `Object.prototype` pollutado. PoC inmediato, sin exploit server:
```
/?__proto__[transport_url]=data:,alert(1);
```
(`<script src="data:,...">` ejecuta el contenido decodificado como JS —
no hace falta hostear nada externo.)

### 2b — propiedad "parcheada" con `Object.defineProperty` incompleto
Cuando el dev nota el gadget de 2a y lo "arregla":
```js
let config = {params: ..., transport_url: false};
Object.defineProperty(config, 'transport_url', {configurable: false, writable: false});
```
Pollutear `Object.prototype.transport_url` directo NO alcanza acá —
propiedad propia (`false`) shadowea al prototype sin importar el lock
posterior. **Pero el propio `defineProperty` es el gadget**: el segundo
argumento es un objeto descriptor plano, y `ToPropertyDescriptor` (el
algoritmo interno que lee `value`/`get`/`set`/`writable`/`enumerable`/
`configurable` de ese objeto) usa `HasProperty`/`Get`, que recorren el
prototype chain — no solo propiedades propias. Si el descriptor no trae
`value` explícito y pollutéas `Object.prototype.value`, `defineProperty`
termina usando tu valor pollutado como el nuevo valor de la propiedad,
en la misma llamada que se suponía la iba a asegurar (todavía era
configurable en ese momento, recién creada).
```
/?__proto__[value]=data:,alert(1);
```
Regla general: cualquier `Object.defineProperty(obj, key, {algunosCampos})`
en el bundle donde el descriptor omite `value` (o `get`/`set`/`writable`/
`enumerable`) es candidato — pollutear el campo omitido.

### 2c — `eval()` alimentado por concatenación de string
```js
let a = manager.sequence || 1;      // sequence no es propiedad propia → lee del prototype
manager.sequence = a + 1;           // si a es string, esto CONCATENA, no suma
eval('...' + manager.sequence + '...');
```
Control total del fragmento inyectado en el `eval`, con dos advertencias
de diseño de payload:

- El `+1` de JS al final de tu valor controlado se concatena como
  string `"1"` — dejalo caer dentro de lo que sea inofensivo (código
  muerto, comentario, o argumento extra de una función que ya se llamó).
- **No uses `//` para comentar el resto de la línea a menos que hayas
  verificado que no hay nada IMPRESCINDIBLE después de tu punto de
  inyección** (una llave de cierre `}`, un paréntesis de cierre que
  balancea el bloque). Si el `//` se come una llave que el propio código
  de la app necesita para cerrar un `if`/función, `eval` tira
  `SyntaxError` sobre el string completo y no ejecuta nada — ni siquiera
  la parte anterior al error. Preferí un payload que sea una
  **expresión completa y balanceada** en el punto de inyección (ej.
  `alert(1)-` en vez de `);alert(1);//`) — no depende de qué código
  agregue la app después, porque no lo comenta, lo vuelve parte de una
  expresión válida.

### 2d — callback de config de una librería third-party, invocado vía `setTimeout`/`setInterval`

Pattern real (no un lab artificial — código genuino de Google
Analytics legacy, `ga.js`): la librería expone una opción de config
tipo callback (`hitCallback` en GA — se ejecuta como fallback de
seguridad si el beacon de tracking tarda demasiado) y la invoca así:
```js
setTimeout(opt_hitCallback, timeout)
```
Si `opt_hitCallback` no viene seteado explícitamente en la config de
la app, la lectura sube al prototype chain. Pollutéalo con un STRING
(no hace falta una función real — `setTimeout` acepta un string como
primer argumento y lo evalúa como código, igual que `eval`):
```
/#__proto__[hitCallback]=alert%28document.cookie%29
```

**Dónde buscar este patrón**: cualquier snippet de analytics/tracking/
monitoring de terceros cargado con un `<script>` de `src` fijo (GA,
Segment, Mixpanel, Sentry, etc.) — el hecho de que la URL del script
no sea controlable NO significa que el contenido no importe. **Abrir
el archivo igual**, aunque el `src` esté hardcodeado — el gadget vive
en la lógica interna de la librería, no en su URL de carga. Confundir
"URL fija" con "nada que mirar acá" es el error más caro de este
catálogo: descarta de entrada exactamente el tipo de archivo que el
lab busca que mires (código third-party real, genuinamente minificado,
no los archivos propios/chicos de la app que sí se leen fácil con
`js-beautify`).

Búsqueda rápida en el bundle de la librería: grep por `hitCallback`,
`callback`, `setTimeout(`, `setInterval(` y cualquier opción de config
con nombre terminado en `Callback`/`Handler`/`Fn` que la librería lea
de un objeto de opciones sin verificar `typeof === "function"` antes
de pasarla a `setTimeout`/`setInterval`/`new Function`.

## Paso 3 — sanitizers no-recursivos (bypass)

Pattern visto: blacklist de substrings peligrosos (`constructor`,
`__proto__`, `prototype`) aplicada con `String.replaceAll` en un loop,
una pasada por término:
```js
function sanitizeKey(key) {
    for (let bad of ['constructor','__proto__','prototype']) {
        key = key.replaceAll(bad, '');
    }
    return key;
}
```
`replaceAll` escanea la cadena UNA vez por término — no vuelve a
examinar el resultado tras borrar un match. Bypass: anidar el término
prohibido dentro de sí mismo de forma que, al borrar la ocurrencia
interna, los pedazos que quedan a los costados se concatenen y
reconstruyan el mismo término prohibido — que ya no se vuelve a escanear
en esa pasada.

Ejemplo confirmado: `__pro__proto__to__` → la pasada de `'__proto__'`
borra el match interno (posiciones 5-13) y deja `"__pro"+"to__"` =
`"__proto__"` de nuevo, intacto porque esa pasada ya terminó. La pasada
siguiente (`'prototype'`) no lo toca porque `"__proto__"` no contiene
`"prototype"` como substring.

**No lo asumas a mano — verificalo con Node antes de proponer el
payload**, pegando la función `sanitizeKey` (o el sanitizer que sea)
tal cual del bundle:
```bash
node -e '
function sanitizeKey(key){
  let bad=["constructor","__proto__","prototype"];
  for (let b of bad) key = key.replaceAll(b, "");
  return key;
}
console.log(sanitizeKey("__pro__proto__to__"));
'
```
Esto es determinístico y gratis (no gasta requests contra el target, no
depende del navegador) — mismo motivo por el que el paso 2c también se
beneficia de simular la concatenación en Node antes de tirar el payload
real.

## Qué mata el lead

- El source parsea con `Object.create(null)` como base (sin prototype
  chain) en vez de `{}` — la lectura de `__proto__` no devuelve nada
  útil.
- El sanitizer SÍ es recursivo (aplica el reemplazo en loop hasta que no
  cambia más) o usa un allowlist de caracteres en vez de blacklist de
  substrings — el bypass de reconstrucción de este documento no aplica,
  hace falta otro vector.
- Ningún gadget alcanzable: todas las propiedades leídas desde objetos
  planos están explícitamente asignadas como propias antes de leerse
  (shadow real, sin `defineProperty` con descriptor incompleto de por
  medio).
- CSP/Trusted Types bloqueando el sink final (mismo criterio que XSS DOM
  normal, ver `SKILL.md`).

## Severidad

Mismo criterio que XSS DOM-based en `SKILL.md`: sin `alert()` (o
callback) confirmado en navegador real (o DOM Invader), es Informational
o P4 máximo. El análisis estático (curl + trazado manual + verificación
en Node de la lógica de string) da candidatos de alta confianza, pero no
reemplaza la ejecución real — dejarlo así de explícito en el reporte.
