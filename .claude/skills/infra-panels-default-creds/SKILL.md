---
name: infra-panels-default-creds
description: Identificar y explotar paneles de infraestructura expuestos con credenciales default, sin autenticación directa, o con bypass de login. Cubre Grafana, Kibana, Jenkins, Prometheus, Tomcat Manager, phpMyAdmin, Portainer, Consul, Jupyter, y cualquier panel de gestión/monitoreo expuesto en el scope. Usar cuando recon o fuzzing detecta un panel con login visible, una interfaz admin accesible, o un servicio de infraestructura respondiendo en un puerto/path no estándar.
sources: internal (built from scratch, evidence-gate-first)
---

## Qué es esto y qué NO es

Este skill cubre tres casos distintos — no asumir que el target es
solo "admin/admin":

1. **Panel con credenciales default** — el servicio responde con login
   y acepta credenciales que el vendor configuró por defecto y que
   nadie cambió.
2. **Panel sin autenticación** — no hay login en absoluto, cualquiera
   accede directo a la interfaz (el caso más grave).
3. **Bypass de login** — hay login pero se puede eludir (path que
   saltea auth, endpoint de API sin verificación, header especial,
   versión con CVE de bypass conocido).

Estos tres tienen el mismo gate de confirmación final pero distinto
vector de explotación — identificar cuál de los tres aplica antes de
empezar a probar credenciales.

Este skill NO cubre brute force de credenciales personalizadas (no
default) ni fuerza bruta en general — eso está fuera de scope en
programas con reglas de rate limiting y excedería el criterio de
"default credential testing".

## Gate de Confirmación

| Nivel | Qué probaste | Estado |
|---|---|---|
| **Panel detectado** | Recon/fuzzing devolvió un path que responde con interfaz de login o panel visible | Lead — empezar testing |
| **Sin auth (caso 2)** | Panel accesible directamente sin credenciales, con contenido real visible | Confirmado — documentar qué expone exactamente |
| **Credenciales default aceptadas (caso 1)** | Login exitoso con credenciales de `creds search <producto>` | Confirmado — documentar nivel de acceso obtenido |
| **Bypass confirmado (caso 3)** | Acceso a funcionalidad autenticada sin pasar por el login | Confirmado — documentar el vector exacto del bypass |
| **Impacto documentado** | Qué se puede leer o ejecutar desde el acceso obtenido (datos, comandos, configs, secretos) | Recién acá arranca la severidad real |

"Panel encontrado" sin acceso obtenido = Lead, no finding.
"Login exitoso" sin documentar qué expone = derivado, no finding completo.

## Severidad orientativa

No inflar — el impacto real depende de qué expone el panel:

- **Panel sin auth con ejecución de comandos** (Jenkins, Jupyter con
  terminal) → P1/P2 candidato
- **Panel sin auth con datos sensibles** (Grafana con métricas
  internas, Kibana con logs de producción) → P2/P3 según sensibilidad
- **Panel sin auth solo con métricas genéricas** (Prometheus /metrics
  endpoint) → P3/P4 — information disclosure, no RCE
- **Credenciales default sin acceso a nada crítico** → P4, considerar
  si el programa lo acepta antes de reportar

## Testing Flow

### Paso 1 — Identificar el producto

Antes de buscar credenciales, confirmar QUÉ producto es el que está
expuesto. Señales:

```bash
# Headers del panel
curl -sI https://$TARGET_PANEL/ | grep -i "server\|x-powered-by\|grafana\|jenkins"

# Título de la página
curl -s https://$TARGET_PANEL/ | grep -i "<title>"

# Path característico
# /api/health → Grafana
# /actuator → Spring Boot
# /manager/html → Tomcat
# /__admin/ → WireMock
```

### Paso 2 — Verificar si hay auth en absoluto

```bash
# Intentar acceso directo sin credenciales
curl -s -o /dev/null -w "%{http_code}" https://$TARGET_PANEL/
curl -s -o /dev/null -w "%{http_code}" https://$TARGET_PANEL/api/
# 200 directo sin redirect a login → caso 2 (sin auth), confirmar inmediato
```

### Paso 3 — Buscar credenciales default con DefaultCreds

```bash
# Instalación (una sola vez)
pipx install defaultcreds-cheat-sheet

# Consulta por producto detectado
creds search grafana
creds search jenkins
creds search kibana
creds search tomcat
creds search prometheus
creds search portainer
creds search jupyter
# etc — siempre buscar el nombre exacto del producto, no genérico

# Si el nombre no da resultados, probar variantes del vendor
creds search elastic
```

### Paso 4 — Probar las credenciales devueltas

Probar cada par usuario/contraseña devuelto por `creds search` — no
solo el primero. El orden importa: empezar por las más comunes del
producto específico antes de las genéricas.

Siempre incluir en la prueba:
- `admin` / `admin`
- `admin` / (en blanco)
- `admin` / `password`
- `root` / `root`
- El nombre del producto como usuario y contraseña

```bash
# Ejemplo para panel con login básico HTTP
curl -s -u admin:admin https://$TARGET_PANEL/api/health

# Para panel con form POST (ajustar según el producto)
curl -s -X POST https://$TARGET_PANEL/login \
  -d "username=admin&password=admin" \
  -c cookies.txt -L
```

### Paso 5 — Documentar impacto

Con acceso obtenido, documentar exactamente qué expone:
- ¿Datos de usuarios/clientes visibles?
- ¿Credenciales o tokens en la interfaz?
- ¿Ejecución de comandos posible?
- ¿Configuración interna expuesta?
- ¿Endpoints internos que no deberían ser públicos?

Esto define la severidad real — no el hecho de entrar, sino qué se
puede hacer desde adentro.

## Paneles comunes y sus paths típicos

Ver `references/panel-paths.md` — carga condicional, solo si el
path detectado en recon no es obvio y necesitás buscar variantes.

## Related Skills & Chains

- **`hunt-web-fuzzing`** — si el panel no apareció directamente en
  recon pasivo, fuzzing activo (especialmente `references/common-sensitive-files.md`
  y paths de infraestructura) es el paso anterior a este skill.
- **`exposed-secrets`** — si el panel expone credenciales, tokens, o
  API keys en su interfaz, el hallazgo puede encadenarse acá.
- **`ssrf`** — paneles de infraestructura internos accesibles desde
  afuera son candidatos a SSRF si tienen funcionalidad de fetch
  externo o webhook.
- **`idor-bola`** — si el panel expone IDs de recursos de otros
  usuarios/tenants sin verificación de ownership.
