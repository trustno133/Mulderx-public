---
name: npm-packages
description: Auditar dependencias npm de un target en varios frentes — CVEs conocidos en versiones vulnerables (SCA con gate de reachability), dependency confusion en paquetes de scope privado, prototype pollution en dependencias específicas explotable hacia un sink real, y prototype pollution server-side detectada black-box (sin identificar la dependencia, solo probing HTTP). Usar para bug bounty y pentesting autorizado cuando el target expone package.json/package-lock.json o JS bundleado con dependencias identificables (vía JXScout u otro extractor), o cuando aparece cualquier endpoint que mergea input estructurado (JSON/form anidado) en un objeto server-side.
---

## Metadata
- **Skill Name**: npm-packages
- **Folder**: npm-packages

## Descripción

Tres metodologías bajo un mismo punto de entrada (dependencias npm del target), cada una con su propio gate de evidencia — no se mezclan entre sí. Insumo principal: output de JXScout (paquetes + versiones extraídos del bundle), o `package.json`/`package-lock.json` si están expuestos directamente.

## Trigger Phrases

npm dependency, dependency confusion, prototype pollution npm, vulnerable package, CVE en dependencia, package.json expuesto, supply chain npm, typosquatting, prototype pollution server-side, privilege escalation via prototype pollution, merge inseguro de JSON body, isAdmin en response

## Conocimiento previo

Use the `hexbrain` skill for relevant public prior art when it can change the test plan; verify any lead against primary sources and target evidence.

## Instructions for Claude

### Paso 0 — Extracción de dependencias (todas las secciones)

Si hay output de JXScout disponible, usarlo directo — ya viene con paquete+versión resuelto. Si no:
- `package.json` / `package-lock.json` expuestos directo por path → parsear ahí, es la fuente más confiable (versión exacta, no inferida)
- Sin eso, grep manual sobre el JS bundleado buscando patterns de paquete conocido (nombres en imports/requires, comentarios de webpack con path de `node_modules/<paquete>/...`, banners de licencia que algunos bundlers dejan) — la versión exacta rara vez sale de acá, queda como "paquete identificado, versión no confirmada" hasta cruzarla con otra fuente
- Sourcemaps, si los hay, suelen tener el path completo de `node_modules` con versión en el nombre de carpeta cuando el lockfile usa flat structure

### Sección A — SCA (CVEs conocidos)

1. Extraer lista de paquete+versión exacta (ver Paso 0).
2. Cruzar contra base de CVEs (`npm audit` si hay `package.json` real, o consulta manual a OSV/GitHub Advisory Database por paquete+versión).
3. **Gate de reachability — no negociable**: una versión vulnerable presente no es un finding. Hay que confirmar que el **código que dispara la vulnerabilidad específica está efectivamente en uso** en el flujo del target — no solo instalado como transitive dependency sin llamar nunca a la función afectada. Sin esto, es ruido de `npm audit` copiado y pegado, y así te lo van a triagear.
4. Confirmado = versión vulnerable + función/endpoint afectado localizable en el código real del target (llamada real, no solo import) + (si es posible) PoC disparando el comportamiento vulnerable.

### Sección B — Dependency Confusion

1. Identificar candidatos: paquetes con **scope privado** (`@empresa-interna/algo`) o nombres que no siguen convención de paquete público conocido, extraídos según Paso 0.
2. Por cada candidato: `GET https://registry.npmjs.org/<nombre>`. Si devuelve **404**, el nombre está libre en el registry público — ahí está la ventana.
3. **Gate de evidencia**: confirmado es nombre interno usado en el bundle + 404 en el registry público. El agente **no publica el paquete** — eso queda a criterio manual tuyo, fuera del scope de lo que el agente ejecuta solo. El agente solo corrobora el estado del nombre en el registry.
4. Sin publicación real y sin confirmar que el build process del target prioriza el registry público sobre uno privado (rara vez verificable desde afuera), el finding queda como "nombre interno expuesto + libre en registry público, no explotado activamente" — válido pero con esa aclaración explícita en el reporte, la severidad final depende del programa.

### Sección C — Prototype Pollution en dependencia específica

1. Identificar la dependencia y versión sospechada (extracción según Paso 0). Chequear primero contra `references/prototype-pollution-catalog.md` — si el paquete está ahí, confirmar la versión exacta contra el CVE listado antes de asumir vigente. Si no está en el catálogo, buscar en changelogs/advisories del paquete, o analizar código si es chico.
2. Confirmar el **sink real**: dónde en el código del target el objeto potencialmente contaminado se usa de forma peligrosa (merge inseguro, acceso dinámico a propiedad, etc.) — mismo espíritu que SSRF/XSS, no alcanza con "la librería tiene el bug", tiene que llegar a algo explotable en el target.
3. **Gate de evidencia**: confirmado = PoC real de pollution llegando al sink con efecto observable (cambio de comportamiento, bypass, DoS, o escalada — documentar cuál).

### Sección D — Prototype Pollution server-side, detección black-box (sin identificar la dependencia)

Distinta de la Sección C: acá NO hace falta package.json, bundle, ni
saber qué librería está en juego — se prueba directo contra el
comportamiento HTTP de cualquier endpoint que mergea input
estructurado (JSON, form anidado) en un objeto server-side. Ver
`references/server-side-blackbox-detection.md` para el método completo
(probe de source con canario, búsqueda de gadget vía campos expuestos
por echo-back, y el paso que separa reflejo de impacto real:
confirmar persistencia global en un request separado, sin el payload).

1. Buscar endpoints que hagan "echo-back" del objeto actualizado
   (perfil, config, preferencias) — la superficie más fácil de
   confirmar sin side-channel.
2. Probe con `{"__proto__":{"canary":"valor"}}` — si se refleja en la
   respuesta, el merge es vulnerable.
3. **Gate de evidencia**: reflejo en un solo response = pollution
   confirmada pero sin impacto todavía (Informational). Confirmado con
   severidad real = el mismo efecto se ve en un request SEPARADO, sin
   el payload de pollution (prueba que contaminó el `Object.prototype`
   global del proceso, no solo un objeto local a esa request).

## Gate de evidencia general — no negociable

Sin PoC/reachability confirmado en la sección correspondiente, el finding no pasa de **Informational/P4**. Las cuatro secciones comparten esta regla pero NO comparten definición de "confirmado" — no usar el gate de una sección para justificar severidad en otra.
