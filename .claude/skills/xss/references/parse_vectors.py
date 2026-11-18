#!/usr/bin/env python3
"""
Parser del PortSwigger XSS Cheat Sheet 2026 → JSON estructurado.
Extrae vectores por sección + metadata (chars usados, keywords, tag base).
"""
import json
import re
from pathlib import Path

TXT = Path("/home/claude/portswigger-xss.txt").read_text()
lines = TXT.split("\n")

# Boundaries de secciones (por línea 1-indexed)
SECTIONS = {
    "no_interaction": (41, 765),
    "with_interaction": (766, 8681),
    "content_types": (8682, 8714),
    "response_content_types": (8715, 8735),
    "impossible_labs": (8736, 9551),
    "extras": (9552, 9599),
}

def clean(s):
    return s.strip().replace("\x0c", "").strip()

def is_name_line(s):
    """Nombre de evento: empieza con 'on' y sin espacios ni tags."""
    s = s.strip()
    if not s or "<" in s or " " in s or "=" in s or "/" in s or "\"" in s:
        return False
    # Descartar líneas de descripción o 'Compatibility:'
    if s.endswith(":") or s.endswith("."):
        return False
    # Eventos empiezan con 'on', descarta también otros nombres de vectores raros
    return s.startswith("on") and s.replace("on", "", 1).isalpha() and len(s) < 60

def parse_event_section(start, end, requires_interaction):
    """Parsear secciones de event handlers. Estado FSM."""
    vectors = []
    i = start - 1
    end_idx = min(end, len(lines))

    while i < end_idx:
        raw = lines[i]
        stripped = clean(raw)

        if is_name_line(stripped):
            name = stripped
            desc = ""
            tag = ""
            payload_lines = []

            # Descripción: primera línea no-vacía siguiente
            j = i + 1
            while j < end_idx and not clean(lines[j]):
                j += 1
            if j < end_idx:
                desc = clean(lines[j])
                j += 1

            # Tag context: siguiente línea no-vacía
            while j < end_idx and not clean(lines[j]):
                j += 1
            if j < end_idx:
                tag = clean(lines[j])
                j += 1

            # Payload: hasta encontrar "Compatibility" o siguiente evento
            while j < end_idx and not clean(lines[j]):
                j += 1
            payload_start = j
            while j < end_idx:
                l = clean(lines[j])
                if not l:
                    # ver si termina en 'Compatibility:' que puede venir suelto
                    j += 1
                    continue
                if "Compatibility" in l or l == "Copy" or l == "Link":
                    break
                if is_name_line(l):
                    break
                payload_lines.append(lines[j].rstrip())
                j += 1

            payload = " ".join(clean(p) for p in payload_lines if clean(p))
            payload = re.sub(r"\s+", " ", payload).strip()

            if payload and name.startswith("on"):
                vectors.append({
                    "name": name,
                    "description": desc,
                    "tag_context": tag,
                    "payload": payload,
                    "requires_user_interaction": requires_interaction,
                })

            i = j
        else:
            i += 1

    return vectors

def enrich(v):
    """Añadir metadata derivada del payload para el matching engine."""
    p = v["payload"]
    p_lower = p.lower()

    # Caracteres crudos utilizados (los que un filtro podría bloquear)
    interesting_chars = ["<", ">", "\"", "'", "=", "(", ")", "`", "\\",
                         ";", "/", "[", "]", "{", "}", ":", "#", "%", "&"]
    chars_used = [c for c in interesting_chars if c in p]

    # Keywords sensibles al filtro
    interesting_kw = ["alert", "prompt", "confirm", "print", "eval",
                       "function", "settimeout", "setinterval",
                       "javascript:", "data:", "script", "onerror",
                       "onload", "onclick", "document", "window",
                       "location", "innerhtml", "srcdoc", "expression",
                       "import", "svg", "iframe", "object", "embed"]
    keywords_used = [k for k in interesting_kw if k in p_lower]

    # Tag base — el primer tag que aparece
    tag_match = re.search(r"<\s*([a-zA-Z][a-zA-Z0-9]*)", p)
    tag_base = tag_match.group(1).lower() if tag_match else None

    # Encodings usados en el payload como parte del vector
    encoding_hints = []
    if re.search(r"&#\d+;", p):
        encoding_hints.append("html_entity_decimal")
    if re.search(r"&#x[0-9a-fA-F]+;", p):
        encoding_hints.append("html_entity_hex")
    if re.search(r"&[a-z]+;", p):
        encoding_hints.append("html_entity_named")
    if re.search(r"\\x[0-9a-fA-F]{2}", p):
        encoding_hints.append("js_hex")
    if re.search(r"\\u[0-9a-fA-F]{4}", p):
        encoding_hints.append("js_unicode")
    if "%" in p and re.search(r"%[0-9a-fA-F]{2}", p):
        encoding_hints.append("url_encoded")

    # Feature flags — para heurísticas de ranking
    features = {
        "uses_backtick": "`" in p,
        "uses_svg": "<svg" in p_lower,
        "uses_iframe": "<iframe" in p_lower,
        "uses_script_tag": "<script" in p_lower,
        "uses_data_uri": "data:" in p_lower,
        "uses_javascript_uri": "javascript:" in p_lower,
        "uses_srcdoc": "srcdoc" in p_lower,
        "uses_style": "<style" in p_lower or "style=" in p_lower,
        "has_html_entities": bool(encoding_hints and any(
            h.startswith("html_entity") for h in encoding_hints)),
        "payload_length": len(p),
    }

    v["chars_used"] = chars_used
    v["keywords_used"] = keywords_used
    v["tag_base"] = tag_base
    v["encoding_hints"] = encoding_hints
    v["features"] = features
    return v

# Parseo
no_interaction = parse_event_section(*SECTIONS["no_interaction"],
                                      requires_interaction=False)
with_interaction = parse_event_section(*SECTIONS["with_interaction"],
                                        requires_interaction=True)

# Enrich
no_interaction = [enrich(v) for v in no_interaction]
with_interaction = [enrich(v) for v in with_interaction]

# Content types y response content types: tabla, otro formato
def parse_content_types_table(start, end):
    """Content-Type: xxxx  <payload>"""
    out = []
    for l in lines[start-1:end]:
        m = re.match(r"^\s*([a-z]+/[a-zA-Z0-9\-\+\.]+(?:[;,\s]+.*?)?)\s+(<.*)$", l.rstrip())
        if m:
            ct = m.group(1).strip()
            payload = m.group(2).strip()
            out.append({"content_type": ct, "payload": payload})
    return out

content_types = parse_content_types_table(*SECTIONS["content_types"])
response_content_types = parse_content_types_table(*SECTIONS["response_content_types"])

# Ensamblar catálogo final
catalog = {
    "meta": {
        "source": "PortSwigger XSS Cheat Sheet 2026",
        "author": "PortSwigger Research (Gareth Heyes)",
        "last_updated_source": "2026-05-22",
        "extracted_date": "2026-07-29",
        "total_event_vectors": len(no_interaction) + len(with_interaction),
    },
    "event_handlers_no_user_interaction": no_interaction,
    "event_handlers_with_user_interaction": with_interaction,
    "content_type_injection_xss": content_types,
    "response_content_type_injection": response_content_types,
}

out = Path("/home/claude/portswigger-vectors.json")
out.write_text(json.dumps(catalog, indent=2, ensure_ascii=False))

print(f"No-interaction vectors: {len(no_interaction)}")
print(f"With-interaction vectors: {len(with_interaction)}")
print(f"Content-type vectors: {len(content_types)}")
print(f"Response content-type vectors: {len(response_content_types)}")
print(f"JSON: {out} ({out.stat().st_size} bytes)")

# Sample de calidad
print("\n=== SAMPLE no-interaction ===")
for v in no_interaction[:3]:
    print(f"  {v['name']} | tag_base={v['tag_base']} | chars={v['chars_used'][:6]} | kw={v['keywords_used'][:4]}")

print("\n=== SAMPLE with-interaction ===")
for v in with_interaction[:3]:
    print(f"  {v['name']} | tag_base={v['tag_base']} | chars={v['chars_used'][:6]} | kw={v['keywords_used'][:4]}")
