---
name: multi-vuln-coverage
description: Plan balanced bug bounty coverage across relevant vulnerability classes for a new or broadly scoped target, then route evidence-backed leads to the existing Mulderx specialists.
---

# Cobertura multiclase de Mulderx

Usá esta guía cuando el operador pida evaluar un dominio, aplicación o
programa de forma amplia, al iniciar un target nuevo, o cuando la cobertura
registrada se haya concentrado en una sola clase pese a que existan otras
superficies observadas. No la uses para ampliar una tarea que el operador
limitó explícitamente a una vulnerabilidad concreta.

El objetivo es que Mulderx considere sus capacidades relevantes y registre
qué cubrió. No es ejecutar todas las skills ni probar todas las clases a
ciegas. Cargá cada playbook especializado solo cuando la superficie y la
autorización lo justifiquen.

## Procedimiento

1. **Scope y modalidad.** Confirmá activos, exclusiones, política, credenciales
   y si están autorizadas pruebas activas. Si faltan datos, podés hacer
   análisis pasivo y dejar las pruebas activas como pendientes; no infieras
   autorización por el pedido de “revisar un dominio”.
2. **Superficie antes que payloads.** Usá `domain-recon` y los artefactos
   existentes para identificar hosts, tecnología, código propio, endpoints,
   formularios, estados de autenticación, roles, IDs, APIs, uploads,
   importaciones, webhooks, renderizadores, exportaciones, WebSockets,
   operaciones con estado y dependencias. No repitas una fase ya cubierta.
3. **Generá hipótesis por función observada.** No dependas solo de firmas
   automáticas, parámetros reflejados o etiquetas `*_hint`. Por ejemplo:
   - login, recovery, SSO y sesiones → auth bypass, OAuth/OIDC/JWT, SAML,
     session fixation y CSRF, según el flujo observado;
   - IDs, tenant, roles y objetos → IDOR/BOLA, GraphQL y lógica de negocio;
   - compras, cambios de estado, cuotas y operaciones repetibles → lógica de
     negocio y race conditions;
   - URL, preview, import, webhook y fetch → SSRF; rutas y descargas → path
     traversal o divulgación;
   - archivos, XML, plantillas y procesamiento asíncrono → file upload, XXE,
     SSTI/deserialización o ejecución, solo si hay un parser/sink alcanzable;
   - UI y JavaScript propio → XSS (reflected, stored, DOM o blind), CSTI,
     `postMessage`, prototype pollution y browser storage, cuando existan
     fuentes, sinks o datos sensibles;
   - formularios que cambian estado, cookies y fetches cross-origin → CSRF,
     CORS o CSWSH según el flujo; callbacks y destinos controlables → open
     redirect u OAuth, sin asumir impacto por el nombre del parámetro;
   - CDN/proxy/cache → cache poisoning/deception o HTTP smuggling solo si hay
     señal de discrepancia; datos privados, diagnósticos o claves →
     info-disclosure o exposed-secrets;
   - versiones, paneles, servicios cloud o recursos externos → CVE/npm,
     infraestructura, cloud o takeover según la evidencia y el scope;
   - código fuente entregado y autorizado → `sast-methodology` con sus
     handoffs secuenciales; versiones identificadas → consultar advisories
     primarios y verificar reachability antes de derivar un CVE;
   - funciones de IA, MCP o Web3 → sus playbooks dedicados, solo si existen y
     están explícitamente dentro del alcance.
4. **Llevá una matriz de cobertura.** Usá `coverage.md` si el cierre del
   pipeline lo produce; en una corrida manual, actualizá el artefacto de
   cobertura que ya exista. Una fila representa una hipótesis/familia y debe
   incluir señal o superficie, evidencia, skill/especialista, prioridad,
   estado y próximo paso. Estados válidos: `NO EVALUADA`, `PRIORIZADA`,
   `EN CURSO`, `CANDIDATA`, `DESCARTADA` (con killer), `NO APLICA` (con
   motivo) o `BLOQUEADA` (con causa). No marques una familia como cubierta
   solo porque no apareció en un escaneo automático.
5. **Priorizá y rotá entre clases.** Ordená por evidencia de reachability,
   impacto potencial, relevancia de la función, coste y riesgo de la prueba.
   Ninguna clase va primero por ser client-side; XSS es una ruta entre varias.
   Si XSS consume su timebox sin evidencia nueva y quedan otras filas
   aplicables prioritarias sin evaluar, rotá a la siguiente. Un bloqueo en una
   vía no autoriza a evadirlo; continuá solo con trabajo independiente.
6. **Delegá cada lead a su dueño.** Para cada hipótesis accionable, usá la
   skill y el especialista de la tabla de ruteo de `AGENTS.md`, usando
   `vuln-classes` como índice cuando la señal no tenga una ruta clara; si el
   runtime no descubre al subagente, aplicá la skill como fallback y decilo. Una
   hipótesis distinta puede tener otra tarea solo si tiene señal y objetivo
   propios. No dupliques el mismo lead entre especialistas.
7. **Cerrá sin ocultar huecos.** Separá observación, inferencia y prueba.
   Guardá descartes con su killer, límites de cobertura, bloqueos y pasos
   manuales pendientes. No llames `COMPLETA` a la cobertura mientras haya
   filas aplicables sin evaluar; reportá la cobertura parcial con claridad.

## Salida mínima

```text
Modo: wide | deep
Superficie revisada:
Familias priorizadas y por qué:
Matriz/artefacto de cobertura:
Leads y skill/especialista asignado:
Clases descartadas con killer:
No evaluadas, bloqueadas o no aplicables y motivo:
Próximo paso autorizado:
```

## Límites

- Respetá scope, rate limits, señales de parada y consentimiento para pruebas
  activas. La guía no amplía autorización.
- Una tecnología, CVE potencial, nombre de parámetro, respuesta `200` o
  ausencia de detección no confirma ni descarta por sí sola una vulnerabilidad.
- No cargues todas las skills para cada objetivo. Usá el inventario para
  seleccionar las rutas relevantes y abrí solo sus playbooks.
- Antes de un finding, aplicá los gates de evidencia y severidad de Mulderx.
