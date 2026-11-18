#!/usr/bin/env python3
"""
sourcemap_recon.py — detecta, descarga y extrae sourcemaps expuestos en producción.

Exit codes:
  0 — al menos un sourcemap encontrado
  1 — ningún sourcemap encontrado
  2 — error de red/IO
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
from html.parser import HTMLParser
from pathlib import Path

from scope_policy import HostScope, ScopeError, normalize_domain_input, open_scoped_url

# ──────────────────────────────────────────────────────────────────────────────
# Constantes
# ──────────────────────────────────────────────────────────────────────────────

MAX_BYTES = 50 * 1024 * 1024  # 50 MB
INTERESTING_KEYWORDS = [
    "auth", "token", "api", "admin", "password", "secret",
    "key", "login", "oauth", "session",
]

# ANSI colors
RESET   = "\033[0m"
BOLD    = "\033[1m"
RED     = "\033[91m"
YELLOW  = "\033[93m"
GREEN   = "\033[92m"
CYAN    = "\033[96m"
DIM     = "\033[2m"

USE_COLOR = True


def c(color: str, text: str) -> str:
    if not USE_COLOR:
        return text
    return f"{color}{text}{RESET}"


# ──────────────────────────────────────────────────────────────────────────────
# HTTP helpers
# ──────────────────────────────────────────────────────────────────────────────

def make_request(url: str, scope: str, method: str = "GET", head_only: bool = False):
    """Devuelve (response, body_bytes) o lanza urllib.error.*"""
    resp = open_scoped_url(
        url,
        scope,
        timeout=15,
        method="HEAD" if head_only else method,
        headers={
            "User-Agent": "Mozilla/5.0 (compatible; sourcemap-recon/1.0)",
            "Accept": "*/*",
        },
    )
    if head_only:
        return resp, b""
    body = b""
    while True:
        chunk = resp.read(65536)
        if not chunk:
            break
        body += chunk
        if len(body) > MAX_BYTES:
            raise ValueError(f"Archivo supera {MAX_BYTES // 1024 // 1024} MB — omitido")
    return resp, body


def fetch_text(url: str, scope: str, rate: float = 1.0) -> tuple[dict, str]:
    """Devuelve (headers_dict, text). headers_dict tiene claves en minúsculas."""
    time.sleep(rate)
    resp, body = make_request(url, scope)
    headers = {k.lower(): v for k, v in resp.headers.items()}
    return headers, body.decode("utf-8", errors="replace")


def check_accessible(url: str, scope: str, rate: float = 1.0) -> bool:
    """True si la URL devuelve 200."""
    time.sleep(rate)
    try:
        resp, _ = make_request(url, scope, head_only=True)
        return resp.status == 200
    except Exception:
        return False


# ──────────────────────────────────────────────────────────────────────────────
# Extracción de <script src> desde HTML
# ──────────────────────────────────────────────────────────────────────────────

class ScriptSrcParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.js_urls: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "script":
            return
        attrs_d = dict(attrs)
        src = attrs_d.get("src", "")
        if src and urllib.parse.urlsplit(src).path.lower().endswith(".js"):
            self.js_urls.append(src)


def extract_js_from_html(html: str, base_url: str) -> list[str]:
    parser = ScriptSrcParser()
    parser.feed(html)
    result = []
    for src in parser.js_urls:
        if src.startswith("http://") or src.startswith("https://"):
            result.append(src)
        else:
            result.append(urllib.parse.urljoin(base_url, src))
    return result


# ──────────────────────────────────────────────────────────────────────────────
# Detección de sourcemap URL en un bundle JS
# ──────────────────────────────────────────────────────────────────────────────

_SOURCEMAP_COMMENT_RE = re.compile(
    r"//[#@]\s*sourceMappingURL\s*=\s*(\S+)", re.MULTILINE
)


def detect_sourcemap_url(js_url: str, headers: dict, js_body: str) -> str | None:
    """Devuelve la URL absoluta del sourcemap, o None si no se detecta."""
    # 1. Cabeceras HTTP
    for header in ("sourcemap", "x-sourcemap"):
        val = headers.get(header, "").strip()
        if val:
            return urllib.parse.urljoin(js_url, val)

    # 2. Comentario al final del JS
    match = None
    for match in _SOURCEMAP_COMMENT_RE.finditer(js_body):
        pass  # quedarse con el último match
    if match:
        url_val = match.group(1).strip()
        # Descartar data URIs
        if url_val.startswith("data:"):
            return None
        return urllib.parse.urljoin(js_url, url_val)

    return None


# ──────────────────────────────────────────────────────────────────────────────
# Parsing y extracción del sourcemap
# ──────────────────────────────────────────────────────────────────────────────

def sanitize_path(raw: str) -> str:
    """Aplana cualquier ../ y strips iniciales de /."""
    # Quitar prefijos de protocolo webpack://, parcel://, etc.
    raw = re.sub(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", "", raw)
    # Normalizar separadores
    raw = raw.replace("\\", "/")
    # Resolver componentes peligrosos
    parts = []
    for part in raw.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts:
                parts.pop()
        else:
            parts.append(part)
    return "/".join(parts) if parts else "unnamed"


def parse_sourcemap(map_json: str, map_url: str) -> dict:
    """
    Devuelve:
      {
        "source_root": str,
        "sources": [str, ...],          # paths originales (con sourceRoot aplicado)
        "sources_content": [str|None],  # alineado con sources
        "bundler_hints": [str],         # webpack://, parcel://, etc.
      }
    """
    data = json.loads(map_json)
    source_root = data.get("sourceRoot", "")
    raw_sources = data.get("sources", [])
    raw_content = data.get("sourcesContent", [])

    # Normalizar longitud de sourcesContent
    contents: list[str | None] = list(raw_content)
    while len(contents) < len(raw_sources):
        contents.append(None)

    # Aplicar sourceRoot
    sources = []
    for s in raw_sources:
        if source_root and not s.startswith(("http://", "https://")):
            combined = source_root.rstrip("/") + "/" + s.lstrip("/")
        else:
            combined = s
        sources.append(combined)

    # Detectar bundler
    hints = set()
    for s in raw_sources:
        m = re.match(r"^([a-zA-Z][a-zA-Z0-9+\-.]*://)", s)
        if m:
            hints.add(m.group(1).rstrip(":/"))

    return {
        "source_root": source_root,
        "sources": sources,
        "sources_content": contents,
        "bundler_hints": sorted(hints),
    }


# ──────────────────────────────────────────────────────────────────────────────
# Escritura de archivos extraídos
# ──────────────────────────────────────────────────────────────────────────────

def write_sources(parsed: dict, map_url: str, output_dir: Path, rate: float, scope: str) -> list[dict]:
    """
    Escribe cada fuente en output_dir respetando la jerarquía de paths.
    Devuelve lista de dicts con info de cada archivo escrito.
    """
    written = []
    for raw_path, content in zip(parsed["sources"], parsed["sources_content"]):
        safe_rel = sanitize_path(raw_path)
        dest = output_dir / safe_rel

        if content is not None:
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content, encoding="utf-8")
            written.append({
                "path": raw_path,
                "safe_rel": safe_rel,
                "size": len(content.encode("utf-8")),
                "source": "sourcesContent",
            })
        else:
            # Intentar descargar el archivo fuente directamente
            candidate = urllib.parse.urljoin(map_url, raw_path.lstrip("/"))
            time.sleep(rate)
            try:
                resp_h, body = make_request(candidate, scope)
                if resp_h.status == 200 and body:
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(body)
                    written.append({
                        "path": raw_path,
                        "safe_rel": safe_rel,
                        "size": len(body),
                        "source": "direct_fetch",
                    })
                else:
                    written.append({
                        "path": raw_path,
                        "safe_rel": safe_rel,
                        "size": 0,
                        "source": "not_accessible",
                    })
            except Exception:
                written.append({
                    "path": raw_path,
                    "safe_rel": safe_rel,
                    "size": 0,
                    "source": "not_accessible",
                })

    return written


# ──────────────────────────────────────────────────────────────────────────────
# Clasificación de interés
# ──────────────────────────────────────────────────────────────────────────────

def is_interesting(path: str) -> bool:
    lp = path.lower()
    return any(kw in lp for kw in INTERESTING_KEYWORDS)


# ──────────────────────────────────────────────────────────────────────────────
# Procesamiento de un bundle JS individual
# ──────────────────────────────────────────────────────────────────────────────

def process_js_url(js_url: str, output_dir: Path, rate: float, scope: str) -> dict:
    """
    Devuelve un dict con el resultado del procesamiento de un bundle:
      found: bool
      map_url: str | None
      map_accessible: bool
      sources_count: int
      written: list[dict]
      bundler_hints: list[str]
      error: str | None
    """
    result = {
        "js_url": js_url,
        "found": False,
        "map_url": None,
        "map_accessible": False,
        "sources_count": 0,
        "written": [],
        "bundler_hints": [],
        "error": None,
    }

    print(c(DIM, f"  → {js_url}"))

    if not HostScope.parse(scope).matches_url(js_url):
        result["error"] = "URL de JavaScript fuera de scope"
        return result

    try:
        headers, js_body = fetch_text(js_url, scope, rate)
    except urllib.error.HTTPError as e:
        result["error"] = f"HTTP {e.code}"
        return result
    except Exception as e:
        result["error"] = str(e)
        return result

    map_url = detect_sourcemap_url(js_url, headers, js_body)
    if not map_url:
        return result
    if not HostScope.parse(scope).matches_url(map_url):
        result["error"] = "URL de sourcemap fuera de scope; no se consultó"
        return result

    result["found"] = True
    result["map_url"] = map_url
    print(c(YELLOW, f"    ✓ sourcemap detectado: {map_url}"))

    # Verificar accesibilidad
    try:
        accessible = check_accessible(map_url, scope, rate)
    except Exception:
        accessible = False

    result["map_accessible"] = accessible

    if not accessible:
        print(c(DIM, "      (sourcemap expuesto en código pero no accesible — hallazgo igualmente)"))
        return result

    # Descargar el .map
    try:
        _, map_body = fetch_text(map_url, scope, rate)
    except Exception as e:
        result["error"] = f"No se pudo descargar el map: {e}"
        return result

    try:
        parsed = parse_sourcemap(map_body, map_url)
    except (json.JSONDecodeError, KeyError) as e:
        result["error"] = f"JSON inválido en el sourcemap: {e}"
        return result

    result["sources_count"] = len(parsed["sources"])
    result["bundler_hints"] = parsed["bundler_hints"]

    # Crear subdirectorio por bundle (nombre limpio del JS)
    js_name = re.sub(r"[^\w\-.]", "_", os.path.basename(urllib.parse.urlparse(js_url).path))
    bundle_dir = output_dir / js_name
    bundle_dir.mkdir(parents=True, exist_ok=True)

    written = write_sources(parsed, map_url, bundle_dir, rate, scope)
    result["written"] = written

    accessible_count = sum(1 for w in written if w["source"] != "not_accessible")
    print(c(GREEN, f"      {accessible_count}/{len(written)} fuentes recuperadas"))

    return result


# ──────────────────────────────────────────────────────────────────────────────
# Resumen final
# ──────────────────────────────────────────────────────────────────────────────

def print_summary(all_results: list[dict]) -> None:
    print()
    print(c(BOLD, "=" * 70))
    print(c(BOLD, "  RESUMEN"))
    print(c(BOLD, "=" * 70))

    found = [r for r in all_results if r["found"]]
    not_found = [r for r in all_results if not r["found"]]

    print(f"\n  Bundles procesados : {len(all_results)}")
    print(f"  Con sourcemap      : {c(GREEN if found else DIM, str(len(found)))}")
    print(f"  Sin sourcemap      : {len(not_found)}")

    if not found:
        print(c(DIM, "\n  No se encontraron sourcemaps expuestos."))
        return

    all_written: list[dict] = []
    for r in found:
        for w in r["written"]:
            w["_bundle"] = r["js_url"]
            all_written.append(w)

    total_bytes = sum(w["size"] for w in all_written)
    accessible = [w for w in all_written if w["source"] != "not_accessible"]

    print(f"\n  Archivos fuente recuperados : {len(accessible)}")
    print(f"  Tamaño total               : {total_bytes / 1024:.1f} KB")

    # Bundlers detectados
    hints: set[str] = set()
    for r in found:
        hints.update(r.get("bundler_hints", []))
    if hints:
        print(f"  Bundlers detectados        : {', '.join(sorted(hints))}")

    # Archivos interesantes
    interesting = [w for w in all_written if is_interesting(w["path"])]
    if interesting:
        print(c(BOLD + RED, f"\n  ── Archivos de interés ({len(interesting)}) ──"))
        for w in sorted(interesting, key=lambda x: x["path"].lower()):
            tag = ""
            if w["source"] == "not_accessible":
                tag = c(DIM, " [no accesible]")
            elif w["source"] == "direct_fetch":
                tag = c(CYAN, " [descargado]")
            kws = [kw for kw in INTERESTING_KEYWORDS if kw in w["path"].lower()]
            label = c(YELLOW, f"[{', '.join(kws)}]")
            print(f"    {label} {w['path']}{tag}")

    # Resto de archivos
    other = [w for w in all_written if not is_interesting(w["path"])]
    if other:
        print(c(DIM, f"\n  ── Otros archivos ({len(other)}) ──"))
        for w in sorted(other, key=lambda x: x["path"].lower())[:50]:
            tag = c(DIM, " [no acc.]") if w["source"] == "not_accessible" else ""
            print(c(DIM, f"    {w['path']}{tag}"))
        if len(other) > 50:
            print(c(DIM, f"    ... y {len(other) - 50} más"))

    # Sourcemaps detectados pero no accesibles
    exposed_no_access = [r for r in found if not r["map_accessible"]]
    if exposed_no_access:
        print(c(BOLD + YELLOW, f"\n  ── Sourcemaps expuestos pero no descargables ({len(exposed_no_access)}) ──"))
        for r in exposed_no_access:
            print(f"    {r['js_url']}")
            print(c(DIM, f"      map: {r['map_url']}"))
        print(c(DIM, "    (La referencia al .map en el bundle JS es un hallazgo de information disclosure)"))

    # Errores
    errors = [r for r in all_results if r.get("error")]
    if errors:
        print(c(DIM, f"\n  ── Errores ({len(errors)}) ──"))
        for r in errors:
            print(c(DIM, f"    {r['js_url']}: {r['error']}"))

    print()


# ──────────────────────────────────────────────────────────────────────────────
# Resolución del input inicial → lista de JS URLs
# ──────────────────────────────────────────────────────────────────────────────

def resolve_js_urls(target: str, scope: str, rate: float) -> list[str]:
    """
    target puede ser:
      - URL directa a un .js
      - URL a una página HTML (extrae <script src>)
      - Dominio desnudo (se añade https:// y se trata como página)
    """
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "https://" + target

    parsed = urllib.parse.urlparse(target)
    if parsed.path.endswith(".js"):
        return [target]

    print(c(DIM, f"  Obteniendo JS desde {target} ..."))
    try:
        _, html = fetch_text(target, scope, rate)
    except Exception as e:
        print(c(RED, f"  Error al obtener {target}: {e}"), file=sys.stderr)
        sys.exit(2)

    js_urls = extract_js_from_html(html, target)
    if not js_urls:
        print(c(DIM, "  No se encontraron <script src=...> con .js en la página."))
    return js_urls


def derive_output_dir(target: str) -> Path:
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "https://" + target
    parsed = urllib.parse.urlparse(target)
    domain = re.sub(r"[^\w\-.]", "_", parsed.netloc or parsed.path)
    return Path(f"{domain}/sourcemap_sources")


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def main() -> int:
    global USE_COLOR

    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    ap = argparse.ArgumentParser(
        description="Detecta y extrae sourcemaps expuestos en producción.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("target", nargs="?", help="URL a un .js, una página, o un dominio")
    ap.add_argument("--output-dir", "-o", help="Directorio de salida (default: ./<dominio>/sourcemap_sources/)")
    ap.add_argument("--js-urls", help="Archivo con una URL de JS por línea")
    ap.add_argument("--no-color", action="store_true", help="Deshabilitar colores ANSI")
    ap.add_argument("--rate", type=float, default=1.0, metavar="SECS",
                    help="Delay entre requests en segundos (default: 1.0)")
    ap.add_argument("--scope", help="Host exacto o wildcard autorizado (ej: example.com o *.example.com)")
    ap.add_argument("--yes", action="store_true", help="Confirma que las solicitudes activas están autorizadas dentro del scope indicado")
    args = ap.parse_args()

    if args.no_color:
        USE_COLOR = False

    if not args.target and not args.js_urls:
        ap.print_help()
        return 2

    # Establish a strict scope before building any output or making requests.
    try:
        if args.target:
            target_for_host = args.target if "://" in args.target else f"https://{args.target}"
            parsed_target = urllib.parse.urlsplit(target_for_host)
            if parsed_target.scheme.lower() not in {"http", "https"} or not parsed_target.hostname:
                raise ScopeError("El target debe ser un host o URL HTTP(S).")
            if parsed_target.username or parsed_target.password:
                raise ScopeError("No se admiten credenciales en el target.")
            target_host = parsed_target.hostname
        elif args.scope:
            target_host = normalize_domain_input(args.scope.removeprefix("*.") )
        else:
            ap.error("--scope es obligatorio cuando se usa --js-urls sin --target.")
        scope = args.scope or target_host
        scope_policy = HostScope.parse(scope)
        if args.target and not scope_policy.matches_host(target_host) and not (
            scope.startswith("*.") and scope_policy.root == target_host
        ):
            raise ScopeError("El target no pertenece al scope indicado.")
        if args.rate < 0:
            raise ScopeError("--rate no puede ser negativo.")
    except ScopeError as exc:
        ap.error(str(exc))

    if not args.yes:
        try:
            answer = input(f"Confirmás autorización para requests activos a {scope}? Escribí 'yes': ").strip()
        except EOFError:
            answer = ""
        if answer.lower() != "yes":
            print("Sin confirmación de autorización; no se hicieron requests.", file=sys.stderr)
            return 2

    # Build the list of JS URLs only after authorization is confirmed.
    js_urls: list[str] = []

    if args.js_urls:
        try:
            with open(args.js_urls, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        js_urls.append(line)
        except OSError as e:
            print(c(RED, f"Error leyendo {args.js_urls}: {e}"), file=sys.stderr)
            return 2

    if args.target:
        js_urls += resolve_js_urls(args.target, scope, args.rate)

    if not js_urls:
        print(c(DIM, "No hay URLs de JS para procesar."))
        return 1

    js_urls = [url for url in js_urls if scope_policy.matches_url(url)]
    if not js_urls:
        print(c(YELLOW, "Todas las URLs de JavaScript quedaron fuera del scope; no se hicieron requests adicionales."))
        return 1

    # Directorio de output
    if args.output_dir:
        output_dir = Path(args.output_dir)
    elif args.target:
        output_dir = derive_output_dir(args.target)
    else:
        output_dir = Path("sourcemap_sources")

    output_dir.mkdir(parents=True, exist_ok=True)
    print(c(BOLD, f"\n[sourcemap_recon] {len(js_urls)} bundle(s) — output: {output_dir}\n"))

    all_results: list[dict] = []
    try:
        for url in js_urls:
            result = process_js_url(url, output_dir, args.rate, scope)
            all_results.append(result)
    except KeyboardInterrupt:
        print(c(YELLOW, "\n  Interrumpido por el usuario."))

    print_summary(all_results)

    found_any = any(r["found"] for r in all_results)
    return 0 if found_any else 1


if __name__ == "__main__":
    sys.exit(main())
