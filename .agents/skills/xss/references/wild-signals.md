# Wild Signals — XSS

Evidencia con fecha de reportes disclosed reales. A diferencia de
`bypass-techniques.md` (mecanismo, estable), esto caduca — podar
entradas viejas cuando el patrón deje de ser relevante o se confirme
parcheado en general.

## 2024-05 (actividad hasta jun 2026) — Shopify, HackerOne disclosed
**Técnica: NUEVA — Markdown-to-XSS vía `javascript:` URI**
El asistente de chat de Help Center renderizaba markdown en el saludo.
Un link/imagen markdown con URL `javascript:` (`![texto](javascript:...)`)
ejecuta JS al activarse. Encadenado con CSRF: un POST cross-site seteaba
el valor del greeting en la sesión de la víctima antes del render —
mismo patrón que nuestra sección de Encadenamiento (self-XSS que se
vuelve explotable de tercero vía CSRF).
**Vigencia:** el bug puntual está parchado (Shopify sacó el input path).
El PATRÓN sigue vivo — chequear en cualquier target con chat/asistente
que renderice markdown de usuario. Cada vez más común con AI chat
interfaces.

## 2026 (advisory REVIVE-SA-2026-001) — Revive Adserver
**Técnica: reflected XSS clásica**, parámetro `acls[0][executionorder]`
sin sanitizar en `banner-acl.php`/`channel-acl.php`, reflejado en
contexto HTML/JS/CSS. Requiere que un admin logueado visite la URL.
**Vigencia:** reciente, confirmar si ya parchearon.

## 2025-12 — Automattic/Pressable, HackerOne #3447021
**Técnica: stored XSS vía config interna (options table)**, no un campo
de usuario obvio. Falta `esc_html()` al renderizar un admin notice desde
un valor previamente persistido en options table de WordPress.
**Suma a la tabla storage→render de nuestro SKILL.md**: agregar
"config/options interno" como storage point, no solo comentarios/perfiles.
**Vigencia:** reciente.

## 2025-05 — US Dept of Defense, HackerOne #3166579
**Técnica: confirma bypass "sin paréntesis"** — usaron `` print`` `` en
vez de `alert()` para evadir el WAF (ya estaba en bypass-techniques.md
como técnica genérica, esto la confirma con caso real reciente).
**Sink nuevo:** `Control.ResolveUrl` de ASP.NET — sumar a la lista de
sinks conocidos para stacks .NET.
**Vigencia:** reciente, bypass confirmado contra WAF real.

## Revive Adserver — patrón repetido (2 reportes más, misma familia)
`zone-include.php` (parámetro `refresh` en iframe de zona) y las
maintenance tools (`maintenance-acl-check.php`/
`maintenance-banners-check.php`, entity names sin escapar). Nota de
proceso: cuando un vendor tiene 3 reportes seguidos del mismo patrón de
falta de sanitización en scripts admin, vale la pena revisar TODOS los
scripts admin similares del mismo vendor si aparece como target, no solo
el que ya reportaron otros.

## Recursos de payloads (no son casos fechados)
- github.com/payload-box/xss-payload-list — dump de payloads por
  categoría, útil como banco de pruebas rápidas, no como referencia de
  técnica.
