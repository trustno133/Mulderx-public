---
name: ssrf
description: Identificar, confirmar y escalar Server-Side Request Forgery (SSRF) en aplicaciones web — parámetros que aceptan URL/hostname, funcionalidad de proxy/fetch, webhooks, preview generators, procesamiento de archivos con imports remotos (PDF/SVG/DOCX/XLSX), blind SSRF vía OOB callback, y bypass de filtros incluyendo DNS rebinding. Usar para bug bounty y pentesting autorizado cuando aparece cualquier vector que dispare una request server-side controlable por el atacante.
---

## Metadata
- **Skill Name**: ssrf
- **Folder**: ssrf

## Descripción

Metodología para SSRF: identificación de vectores, confirmación con evidencia real (no asumida), bypass de filtros solo cuando hace falta, y escalación solo después de confirmar. No es un catálogo de payloads para memorizar — el catálogo vive en `references/`, cargado condicionalmente.

## Trigger Phrases

SSRF, server-side request forgery, blind SSRF, cloud metadata, AWS metadata, GCP metadata, internal port scan, webhook URL, fetch URL parameter, redirect chain SSRF

## Instructions for Claude

Use the `hexbrain` skill for relevant public prior art when it can change the test plan; verify any lead against primary sources and target evidence.

1. Identificar el vector: un parámetro (URL, hostname, webhook) o un **archivo subido que el server procesa e intenta resolver referencias remotas dentro de él** que dispara una request hecha por el servidor, no por el browser del atacante. Vectores de file upload a chequear explícitamente:
   - PDF con `/URI` externo o JavaScript embebido que el motor de renderizado/preview resuelve server-side
   - SVG con `<image href="http://...">` o `<use>` externo — procesadores de imagen (ImageMagick, librerías de thumbnail) que resuelven la referencia
   - DOCX/XLSX/ODT con referencias OLE/template remoto (`w:attachedTemplate`, external relationship en `_rels/`) que Office/LibreOffice headless resuelve al abrir
   - XML/XLSX con entidades externas que además de XXE pueden disparar una request SSRF pura (sin necesidad de leer el archivo de vuelta, solo con que el parser intente resolver la URL)
   - Imágenes con metadata EXIF/XMP que contenga una URL que algún pipeline de procesamiento resuelva (menos común, confirmar antes de asumir)

   Para estos casos, el callback OOB (paso 2) es el gate principal — raramente hay data interna reflejada en la respuesta cuando el trigger es un archivo procesado async o server-side sin devolver el resultado.
2. Setup de listener OOB antes de probar nada interno — Interactsh, Burp Collaborator, o canary propio. Sin esto no hay forma de confirmar el caso blind.
3. Probar primero con una URL externa benigna (confirmar que el flujo realmente hace la request saliente) antes de apuntar a direcciones internas. Si ni siquiera la externa dispara nada, no hay vector — cortar acá, no seguir probando internals a ciegas.
4. Probar direcciones internas / metadata endpoints.

### Gate de evidencia — no negociable

SSRF se considera **confirmado** si y solo si se cumple **al menos una** de estas dos condiciones:

- **Callback recibido** en el listener OOB (para el caso blind), o
- **Data interna filtrada** en la respuesta HTTP (para el caso no-blind: contenido, headers, o error que revela info del recurso interno real)

Nada más cuenta como confirmado. Timing diferente, error genérico, "el comportamiento cambió" — eso es una **pista**, no una confirmación. Sin uno de los dos gates de arriba, el finding no pasa de Informational/P4, sin importar cuán prometedor parezca el vector.

Antes de avanzar a bypass o escalation, decir explícitamente cuál de los dos gates se cumplió y con qué evidencia (log del listener, o el fragmento de respuesta que lo prueba).

5. Si hay filtro/sanitización bloqueando el payload directo → cargar `references/bypass-catalog.md`. No cargar antes — si no hay filtro de por medio, no hay nada que bypassear.
6. Si el gate de confirmación ya se cumplió → cargar `references/escalation.md` para decidir el siguiente paso. No cargar antes — escalar algo no confirmado es specular, no hackear.
7. Reportar: endpoint, parámetro, payload exacto que funcionó, y cuál gate de evidencia se cumplió.

## Referencias

- `references/bypass-catalog.md` — técnicas de bypass de allowlist/denylist/weak-parser. Cargar solo cuando el vector está identificado y el filtro bloquea el payload directo (paso 5). Cada técnica debe quedar marcada `confirmado` (probada en un target/lab real) o `sin verificar` (documentada pero no probada) — nunca tratar ambas categorías con el mismo peso al elegir qué probar primero.
- `references/escalation.md` — qué hacer después de confirmar SSRF: metadata endpoints por cloud provider (AWS/GCP/Azure/otros), Kubernetes/service mesh (Kubelet API, Envoy, Linkerd, Consul), sockets de container runtime (Docker/containerd/CRI-O). Cargar solo después del gate de confirmación (paso 6).
- `references/component-divergence.md` — heurístico de razonamiento (no catálogo de payloads) para cuando ya se agotó una ronda razonable de `bypass-catalog.md` contra un filtro específico y todo sigue bloqueado. Cargar en ese momento, no antes — no reemplaza probar el catálogo primero, es para cuando el catálogo se queda corto y hace falta preguntarse si hay dos componentes leyendo el mismo input de forma distinta (sintáctica o temporal).

## Notas de calibración

- No asumir que IMDSv2 bloquea el acceso por default — es una opción a nivel de cuenta/AMI que hay que habilitar explícitamente en AWS, no un default universal. Si un `GET` plano a `169.254.169.254/latest/meta-data/` devuelve 401/403, no descartar el vector todavía: revisar si la app permite pasar método HTTP y headers custom (para el flujo `PUT` + token de IMDSv2) antes de concluir "está protegido, no hay nada".
- Antes de sumar una técnica de bypass a `bypass-catalog.md`, preguntarse: ¿esto lo probamos contra algo real, o lo estamos copiando de un blog? Si es lo segundo, va marcado `sin verificar` y no cuenta como evidencia de nada hasta calibrarlo.
