"""
build.py — genera knowledge/index.md desde filtered_meta.json o data.csv

Uso:
    python knowledge/build.py <archivo.json>   # desde h1_filter.py
    python knowledge/build.py <archivo.csv>    # desde reddelexc/hackerone-reports

Ejemplos:
    python knowledge/build.py "<downloads>/filtered_meta.json"
    python knowledge/build.py "<downloads>/h1_reports.csv"

El índice resultante vive en knowledge/index.md.
"""
import sys
import json
import csv
import re
from pathlib import Path
from collections import defaultdict
from datetime import datetime

# Mapeo directo de vuln_type H1 → tag (para CSV de reddelexc/hackerone-reports)
VULNTYPE_MAP: dict[str, str] = {
    "cross-site scripting (xss)": "xss",
    "cross-site scripting": "xss",
    "ui redressing / clickjacking": "clickjacking",
    "sql injection": "sqli",
    "server-side request forgery (ssrf)": "ssrf",
    "server-side request forgery": "ssrf",
    "path traversal": "path-traversal",
    "directory traversal": "path-traversal",
    "improper access control - generic": "idor",
    "broken access control": "idor",
    "insecure direct object reference (idor)": "idor",
    "privilege escalation": "idor",
    "cross-site request forgery (csrf)": "csrf",
    "cross-site request forgery": "csrf",
    "information disclosure": "info-disclosure",
    "information exposure through an error message": "info-disclosure",
    "cleartext transmission of sensitive information": "info-disclosure",
    "insufficiently protected credentials": "secrets",
    "use of hard-coded credentials": "secrets",
    "improper authentication - generic": "auth-bypass",
    "authentication bypass": "auth-bypass",
    "open redirect": "open-redirect",
    "url redirection to untrusted site ('open redirect')": "open-redirect",
    "remote code execution": "rce",
    "code injection": "rce",
    "os command injection": "rce",
    "command injection": "rce",
    "denial of service": "dos",
    "uncontrolled resource consumption": "dos",
    "race condition": "business-logic",
    "business logic errors": "business-logic",
    "improper authorization": "idor",
    "server-side template injection": "ssti",
    "template injection": "ssti",
    "xml external entity (xxe) injection": "xxe",
    "xml external entity injection": "xxe",
    "deserialization of untrusted data": "deserialization",
    "unrestricted file upload": "file-upload",
    "file upload": "file-upload",
    "prototype pollution": "prototype-pollution",
    "subdomain takeover": "takeover",
    "cors misconfiguration": "cors",
    "http request smuggling": "http-smuggling",
    "postmessage": "postmessage",
    "cache poisoning": "cache-poisoning",
    "integer underflow": "dos",
    "integer overflow": "dos",
    "use after free": "rce",
    "heap buffer overflow": "rce",
    "stack-based buffer overflow": "rce",
    "memory corruption": "rce",
}

# ---------------------------------------------------------------------------
# Mapeo CWE → tags
# ---------------------------------------------------------------------------
CWE_TAGS = {
    "cwe-79": ["xss"],
    "cwe-80": ["xss"],
    "cwe-116": ["xss"],
    "cwe-22": ["path-traversal"],
    "cwe-23": ["path-traversal"],
    "cwe-73": ["path-traversal"],
    "cwe-918": ["ssrf"],
    "cwe-352": ["csrf"],
    "cwe-601": ["open-redirect"],
    "cwe-89": ["sqli"],
    "cwe-434": ["file-upload"],
    "cwe-502": ["deserialization"],
    "cwe-611": ["xxe"],
    "cwe-776": ["xxe"],
    "cwe-400": ["dos"],
    "cwe-770": ["dos"],
    "cwe-835": ["dos"],
    "cwe-1333": ["dos"],
    "cwe-284": ["idor"],
    "cwe-285": ["idor"],
    "cwe-639": ["idor"],
    "cwe-862": ["idor"],
    "cwe-863": ["idor"],
    "cwe-94": ["rce"],
    "cwe-78": ["rce"],
    "cwe-77": ["rce"],
    "cwe-1004": ["csrf"],
    "cwe-614": ["csrf"],
    "cwe-1021": ["clickjacking"],
    "cwe-295": ["tls"],
    "cwe-287": ["auth-bypass"],
    "cwe-306": ["auth-bypass"],
    "cwe-307": ["auth-bypass"],
    "cwe-640": ["auth-bypass"],
    "cwe-384": ["session"],
    "cwe-313": ["secrets"],
    "cwe-798": ["secrets"],
    "cwe-259": ["secrets"],
    "cwe-200": ["info-disclosure"],
    "cwe-209": ["info-disclosure"],
    "cwe-532": ["info-disclosure"],
    "cwe-1098": ["prototype-pollution"],
    "cwe-915": ["prototype-pollution"],
}

# ---------------------------------------------------------------------------
# Mapeo por keywords en el título/weakness name → tags
# ---------------------------------------------------------------------------
KEYWORD_RULES: list[tuple[list[str], str]] = [
    (["xss", "cross-site scripting", "script injection", "html injection"], "xss"),
    (["stored xss", "stored cross"], "xss"),
    (["reflected xss", "reflected cross"], "xss"),
    (["dom xss", "dom-based"], "xss"),
    (["idor", "broken access control", "insecure direct object", "bac", "bola",
      "unauthorized access", "access control", "privilege escalation", "horizontal",
      "vertical escalation", "trip hijacking"], "idor"),
    (["ssrf", "server-side request forgery", "server side request"], "ssrf"),
    (["path traversal", "directory traversal", "lfi", "local file inclusion",
      "file read", "arbitrary file read"], "path-traversal"),
    (["sql injection", "sqli", "sql query"], "sqli"),
    (["csrf", "cross-site request forgery", "request forgery"], "csrf"),
    (["cors", "cross-origin resource sharing", "access-control-allow-origin"], "cors"),
    (["business logic", "logic flaw", "workflow bypass", "race condition",
      "toctou", "time of check", "fare", "bid", "booking", "wallet",
      "coins transfer", "payment bypass", "price manipulation"], "business-logic"),
    (["deserialization", "deserializing", "pickle", "yaml.load",
      "unserialize", "object injection"], "deserialization"),
    (["ssti", "template injection", "server-side template",
      "server side template"], "ssti"),
    (["file upload", "arbitrary file", "malicious upload",
      "unrestricted upload"], "file-upload"),
    (["open redirect", "url redirect", "unvalidated redirect",
      "redirect to"], "open-redirect"),
    (["denial of service", " dos ", "infinite loop", "resource exhaustion",
      "cpu consumption", "memory exhaustion", "billion laughs",
      "zip bomb", "redos", "algorithmic complexity"], "dos"),
    (["prototype pollution", "proto pollution", "__proto__"], "prototype-pollution"),
    (["npm", "dependency confusion", "supply chain", "package hijack",
      "malicious package"], "npm"),
    (["subdomain takeover", "takeover", "dangling dns", "dangling cname"], "takeover"),
    (["postmessage", "post message", "event.data", "window.postmessage"], "postmessage"),
    (["cache poisoning", "cache deception", "web cache poisoning",
      "unkeyed", "cache key"], "cache-poisoning"),
    (["websocket", "web socket", " ws "], "websocket"),
    (["xxe", "xml external entity", "xml injection"], "xxe"),
    (["rce", "remote code execution", "command injection", "os command",
      "code execution", "arbitrary code", "shell injection"], "rce"),
    (["smart contract", "blockchain", "ethereum", "solidity",
      "evm", "gas exhaustion", "rskj"], "blockchain"),
    (["session fixation", "session hijack", "session token"], "session"),
    (["information disclosure", "info disclosure", "sensitive data",
      "credentials exposed", "api key", "token leak", "secret leak"], "info-disclosure"),
    (["auth bypass", "authentication bypass", "login bypass",
      "2fa bypass", "mfa bypass", "otp bypass"], "auth-bypass"),
    (["account takeover", "ato", "account hijack"], "ato"),
    (["cors", "origin header"], "cors"),
    (["llhttp", "http request smuggling", "request smuggling",
      "http smuggling"], "http-smuggling"),
    (["clickjack", "ui redressing", "x-frame-options"], "clickjacking"),
]

# ---------------------------------------------------------------------------
# Etiquetas que corresponden a skills del pipeline
# ---------------------------------------------------------------------------
SKILL_TAGS = {
    "xss", "idor", "ssrf", "cors", "postmessage", "csrf", "business-logic",
    "cache-poisoning", "websocket", "deserialization", "file-upload",
    "path-traversal", "npm", "takeover", "sqli", "ssti", "rce",
}

# Etiqueta humana para el índice
TAG_LABEL = {
    "xss": "XSS",
    "idor": "IDOR / BAC / BOLA",
    "ssrf": "SSRF",
    "cors": "CORS",
    "postmessage": "postMessage",
    "csrf": "CSRF",
    "business-logic": "Business Logic",
    "cache-poisoning": "Cache Poisoning",
    "websocket": "WebSocket",
    "deserialization": "Deserialization",
    "file-upload": "File Upload",
    "path-traversal": "Path Traversal",
    "npm": "npm / Supply Chain",
    "takeover": "Subdomain Takeover",
    "sqli": "SQLi",
    "ssti": "SSTI",
    "rce": "RCE / Command Injection",
    "open-redirect": "Open Redirect",
    "dos": "DoS",
    "prototype-pollution": "Prototype Pollution",
    "auth-bypass": "Auth Bypass",
    "ato": "Account Takeover",
    "info-disclosure": "Info Disclosure",
    "session": "Session",
    "http-smuggling": "HTTP Smuggling",
    "xxe": "XXE",
    "blockchain": "Blockchain / Smart Contracts",
    "clickjacking": "Clickjacking",
    "other": "Other",
}


def load_csv(path: Path) -> list[dict]:
    """Lee el CSV de reddelexc/hackerone-reports y normaliza al formato interno."""
    reports = []
    with open(path, newline="", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            link = row.get("link", "").strip()
            if not link:
                continue
            if not link.startswith("http"):
                link = "https://" + link
            m = re.search(r"/reports/(\d+)", link)
            report_id = int(m.group(1)) if m else 0
            bounty_raw = row.get("bounty", "0") or "0"
            try:
                bounty = float(bounty_raw)
            except ValueError:
                bounty = 0.0
            vuln_type = (row.get("vuln_type") or "").strip()
            reports.append({
                "id": report_id,
                "url": link,
                "title": (row.get("title") or "").strip(),
                "program": (row.get("program") or "").strip(),
                "bounty": bounty,
                "upvotes": int(row.get("upvotes") or 0),
                "weakness": vuln_type,
                "cwe": "",
                "severity": "",  # CSV no tiene severity
                "_vuln_type": vuln_type.lower(),
            })
    return reports


def classify(report: dict) -> list[str]:
    tags: set[str] = set()

    # Mapeo directo por vuln_type (fuente CSV)
    vt = report.get("_vuln_type", "")
    if vt and vt in VULNTYPE_MAP:
        tags.add(VULNTYPE_MAP[vt])

    cwe = (report.get("cwe") or "").lower()
    if cwe and cwe in CWE_TAGS:
        tags.update(CWE_TAGS[cwe])

    haystack = " ".join([
        (report.get("title") or ""),
        (report.get("weakness") or ""),
    ]).lower()

    for keywords, tag in KEYWORD_RULES:
        if any(kw in haystack for kw in keywords):
            tags.add(tag)

    return sorted(tags) if tags else ["other"]


def fmt_bounty(amount) -> str:
    if not amount:
        return ""
    try:
        v = float(amount)
        return f" · **${v:,.0f}**" if v > 0 else ""
    except Exception:
        return ""


TOP_N = 100  # reportes por archivo de tag


def build_index(reports: list[dict], out_dir: Path):
    by_tag: dict[str, list[dict]] = defaultdict(list)
    for r in reports:
        tags = classify(r)
        r["_tags"] = tags
        for t in tags:
            by_tag[t].append(r)

    skill_first = sorted(t for t in by_tag if t in SKILL_TAGS)
    rest = sorted(t for t in by_tag if t not in SKILL_TAGS and t != "other")
    order = skill_first + rest

    today = datetime.now().strftime("%Y-%m-%d")

    # index.md liviano — solo tabla de tags
    index_lines = [
        "# Knowledge Base -- H1 Disclosed Reports",
        "",
        f"_Auto-generado el {today}. Fuente: {len(reports)} reportes._",
        "_Actualizar: `python knowledge/build.py <archivo.csv|json>`_",
        "",
        "Cada archivo tiene los top 100 del tag, ordenados por bounty/upvotes.",
        "",
        "| Tag | Archivo | Total |",
        "|-----|---------|-------|",
    ]
    for t in order:
        label = TAG_LABEL.get(t, t)
        total = len(by_tag[t])
        index_lines.append(f"| {label} | [{t}.md]({t}.md) | {total} |")

    (out_dir / "index.md").write_text("\n".join(index_lines), encoding="utf-8")
    print(f"Escrito: {out_dir / 'index.md'}")

    # un archivo por tag con top N
    for t in order:
        label = TAG_LABEL.get(t, t)
        entries = sorted(
            by_tag[t],
            key=lambda r: (
                {"critical": 0, "high": 1, "medium": 2}.get(r.get("severity", ""), 3),
                -(r.get("bounty") or 0),
                -(r.get("upvotes") or 0),
            )
        )[:TOP_N]

        tag_lines = [
            f"# {label} -- Top {len(entries)} reportes H1",
            "",
            f"_Generado el {today} | Ordenado por bounty/upvotes_",
            "",
        ]
        for r in entries:
            sev = r.get("severity") or ""
            sev_str = f"{sev.upper()} · " if sev else ""
            program = r.get("program") or "?"
            url = r.get("url") or f"https://hackerone.com/reports/{r['id']}"
            title = (r.get("title") or "No title").replace("|", "-")
            cwe = r.get("cwe") or ""
            weakness = r.get("weakness") or ""
            bounty_val = r.get("bounty") or 0
            upvotes = r.get("upvotes") or 0
            parts = [x for x in [
                program,
                f"${bounty_val:,.0f}" if bounty_val else None,
                weakness if weakness else None,
                cwe.upper() if cwe else None,
                f"{upvotes}up" if upvotes else None,
            ] if x]
            tag_lines.append(f"- [{title}]({url}) -- {sev_str}{' | '.join(parts)}")

        (out_dir / f"{t}.md").write_text("\n".join(tag_lines), encoding="utf-8")

    print(f"Archivos generados: {len(order)} tags")
    print(", ".join(f"{t}({len(by_tag[t])})" for t in order))


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    meta_path = Path(sys.argv[1]).expanduser()
    if not meta_path.exists():
        print(f"Archivo no encontrado: {meta_path}")
        sys.exit(1)

    suffix = meta_path.suffix.lower()
    if suffix == ".csv":
        reports = load_csv(meta_path)
        print(f"CSV cargado: {len(reports)} reportes")
    elif suffix == ".json":
        payload = json.loads(meta_path.read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            payload = next(
                (payload.get(key) for key in ("reports", "data", "results")
                 if isinstance(payload.get(key), list)),
                None,
            )
        if not isinstance(payload, list) or any(not isinstance(row, dict) for row in payload):
            raise ValueError("El JSON debe ser una lista de reportes o contener reports/data/results.")
        reports = payload
        print(f"JSON cargado: {len(reports)} reportes")
    else:
        raise ValueError("El archivo de entrada debe ser .csv o .json")

    out_dir = Path(__file__).parent
    build_index(reports, out_dir)


if __name__ == "__main__":
    main()
