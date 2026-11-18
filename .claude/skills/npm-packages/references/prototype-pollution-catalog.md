# Paquetes con historial de prototype pollution + patterns de sink

Referencia para Sección C (prototype pollution en dependencia específica). No reemplaza la búsqueda en vivo de CVEs (eso es Sección A) — esto es para reconocer rápido si un paquete detectado en el target tiene historial conocido, y saber qué función mirar primero.

Esto es la variante **server-side, con la dependencia ya identificada** (librería npm vulnerable + `req.body`/`req.query` como source, corriendo en el backend Node). Dos variantes hermanas:

- Si el bug está en JS que corre en el navegador de la víctima (source = `location.search`/`location.hash` parseado por un parser propio del bundle, sink = DOM XSS), ver `xss/references/client-side-prototype-pollution.md`.
- Si es server-side pero **no tenés visibilidad de la dependencia/versión** (sin package.json, sin bundle) y hay que detectarlo puramente por comportamiento HTTP, ver `references/server-side-blackbox-detection.md`.

Mismo concepto de fondo en las tres, source/gadget/detección completamente distintos.

## Paquetes con historial confirmado (chequear versión exacta contra el advisory antes de asumir vigente)

| Paquete | Función(es) vulnerable(s) | CVE(s) representativos |
|---|---|---|
| lodash / lodash-es | `merge`, `mergeWith`, `defaultsDeep`, `zipObjectDeep`, `set`, `unset`, `omit` (variantes más nuevas) | CVE-2018-3721, CVE-2019-10744, CVE-2020-8203, CVE-2025-13465, CVE-2026-2950 |
| lodash.defaultsdeep (paquete standalone) | `defaultsDeep` | advisory 2019/2020, mismo patrón que lodash core |
| minimist | parsing de flags tipo `--__proto__.x` o `--constructor.prototype.x` | CVE-2020-7598, CVE-2021-44906 |
| yargs-parser | mismo patrón que minimist (parsing de argv) | reportado junto con minimist por Snyk, 2020 |
| deep-extend | `deepExtend` (merge recursivo) | CVE-2018-3750 |
| jquery-deep-extend | `deepExtend` | mismo patrón que deep-extend |
| hoek | `applyToDefaults`, `merge` | CVE-2018-3728 |
| dset | función `dset` (set dinámico de path) | CVE-2024-21529 |
| web3-utils | utilidades de parsing/merge internas | CVE-2024-21505 |
| uplot | opciones de configuración con merge inseguro | CVE-2024-21489 |
| ajv (versiones viejas, <6.12.3) | validación de schema con `$data` mal filtrado | advisory histórico, confirmar versión antes de asumir vigente |

## Supply chain — caso aparte (no es prototype pollution, pero mismo punto de entrada)

**Shai-Hulud (sep 2025)**: ataque de supply chain donde se comprometieron paquetes de alto uso (`chalk`, `debug`, y otros) vía cuenta de maintainer phisheada, con un worm que se auto-replicó a 500+ paquetes adicionales usando tokens de npm robados. Si el target tiene en su lockfile una versión de un paquete popular publicada durante esa ventana de tiempo, vale la pena cruzarla contra la lista de paquetes comprometidos antes de descartarlo como ruido — esto es más cercano a Sección B (supply chain) que a C, pero como el vector de detección es el mismo (parsear lockfile/bundle), se anota acá para no perderlo de vista.

## Patterns de sink a buscar en el código del target (no en la librería)

La librería tiene el bug — el finding depende de que el **target** use el resultado contaminado de forma peligrosa. Buscar en el código propio del target (no en node_modules):

- Merge/extend de un objeto que sale de `req.body`, `req.query`, o cualquier input de usuario, sin sanitizar `__proto__`/`constructor`/`prototype` antes
- Acceso dinámico a propiedad tipo `obj[userControlledKey]` donde `userControlledKey` puede llegar a ser `__proto__` o `constructor.prototype`
- Configuración de la app armada por merge de defaults + input de usuario (patrón clásico: `config = merge(defaultConfig, userInput)`)
- Cualquier uso de `JSON.parse` seguido de merge/set dinámico sin `Object.create(null)` como base

## Detección rápida (sanity check, no reemplaza el PoC real)

Payload mínimo para confirmar si un endpoint específico es vulnerable a pollution vía JSON body (ajustar según el sink identificado):

```json
{"__proto__": {"polluted": "yes"}}
```

Si después de mandar esto un objeto nuevo sin relación aparente (`{}`) también tiene `polluted: "yes"` en algún lado observable de la respuesta o comportamiento, hay pollution. Esto confirma la vulnerabilidad de la librería en runtime — todavía falta demostrar el sink real con impacto (Paso 3 del SKILL.md) para que sea más que Informational.
