#!/usr/bin/env python3
"""
wayback_js_recon.py v1.0 — Historical JS analysis via Wayback Machine CDX API.

Finds endpoints, secrets, and routes present in old JS snapshots but absent
from the current live version — legacy features, removed APIs, forgotten auth
flows that may still be alive server-side.

Usage:
    python3 wayback_js_recon.py example.com [options]
    python3 wayback_js_recon.py example.com --since 20200101 --max-files 15
    python3 wayback_js_recon.py example.com --scope '*.example.com' --profile saas
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

from scope_policy import HostScope, ScopeError, normalize_domain_input

try:
    import requests
except ImportError:
    sys.exit("[ERROR] requests not installed: pip install requests")

# ─── Paths ───────────────────────────────────────────────────────────────────

SCRIPTS_DIR = Path(__file__).parent
JS_ANALYZER = SCRIPTS_DIR / "js_analyzer_v4_8.py"
BB_PIPELINE_DIR = Path(os.environ.get("BB_PIPELINE_DIR", str(Path.home() / ".bb_pipeline")))

CDX_API = "https://web.archive.org/cdx/search/cdx"
WAYBACK_RAW = "https://web.archive.org/web/{ts}if_/{url}"

VERSION = "1.0"

# ─── Filters ─────────────────────────────────────────────────────────────────

# Filenames that indicate vendor/third-party code — skip analysis
_VENDOR_RE = re.compile(
    r"(?:jquery|bootstrap|react(?:-dom|-router)?|vue(?:-router)?|angular|"
    r"lodash|underscore|moment|dayjs|axios|node_modules|"
    r"webpack[-.]runtime|chunk[-.]vendors?|polyfill|core[-.]js|"
    r"runtime[-.]chunk|vendor[-.]chunk|modernizr|foundation|materialize|"
    r"swiper|slick|owl|fancybox|select2|tinymce|quill|codemirror|"
    r"highlight\.js|prism|marked|three(?:\.min)?|d3(?:\.min)?|"
    r"chart\.js|leaflet|mapbox|gsap|anime|aos|wow|typed|particles)",
    re.IGNORECASE,
)

# Filename patterns that suggest app-owned code
_INTERESTING_NAME_RE = re.compile(
    r"(?:app|main|index|bundle|chunk|pages|components|store|router|"
    r"api|client|frontend|spa|src|dist|assets)",
    re.IGNORECASE,
)

# Endpoint patterns worth flagging as high-interest
_INTERESTING_EP_RE = re.compile(
    r"/(?:api|v\d+|graphql|admin|internal|auth|login|oauth|sso|"
    r"upload|webhook|callback|token|user[s]?|account|profile|"
    r"payment|checkout|order|invoice|dashboard|config|settings|"
    r"debug|health|metrics|status|export|import|batch|bulk)/",
    re.IGNORECASE,
)

JS_MIMES = {"text/javascript", "application/javascript", "application/x-javascript"}
MAX_JS_BYTES = 25 * 1024 * 1024


def _scoped_session(scope: str) -> requests.Session:
    policy = HostScope.parse(scope)

    class ScopedSession(requests.Session):
        def get_redirect_target(self, response):
            location = super().get_redirect_target(response)
            if location:
                destination = urljoin(response.url, location)
                if not policy.matches_url(destination):
                    raise requests.RequestException("Redirection bloqueada fuera del scope autorizado.")
            return location

    return ScopedSession()


# ─── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class JSFile:
    url: str
    canonical: str          # URL without query string
    first_seen: str         # CDX timestamp YYYYMMDDHHMMSS
    last_seen: str
    snapshot_count: int
    interest_score: int = 0


@dataclass
class Snapshot:
    original_url: str
    timestamp: str
    wayback_url: str
    local_path: Path
    analysis_path: Path
    report: Dict = field(default_factory=dict)
    error: str = ""


# ─── CDX helpers ─────────────────────────────────────────────────────────────

def _cdx_get(params: Dict, rate: float) -> List[List[str]]:
    """Single CDX API call with one retry. Returns list-of-rows (no header row)."""
    time.sleep(rate)
    for attempt in range(2):
        try:
            r = requests.get(
                CDX_API, params=params, timeout=60,
                headers={"User-Agent": f"wayback_js_recon/{VERSION}"},
                allow_redirects=False,
            )
            if r.status_code == 200:
                data = r.json()
                return data[1:] if len(data) > 1 else []
            else:
                _warn(f"CDX returned HTTP {r.status_code} (attempt {attempt + 1}/2)")
                if attempt == 0:
                    time.sleep(max(rate, 3))
                    continue
        except Exception as exc:
            if attempt == 0:
                time.sleep(max(rate, 2))
                continue
            _err(f"CDX request failed: {exc}")
    return []


def fetch_js_urls(domain: str, scope: str, since: Optional[str], limit: int, rate: float) -> List[JSFile]:
    """
    Query CDX for all distinct JS URLs seen on the domain.
    Uses collapse=urlkey to get one row per unique URL (first-seen timestamp).
    A second reversed query captures the last-seen timestamp per URL.
    """
    scope_policy = HostScope.parse(scope)
    query_root = scope_policy.root
    _log(f"CDX: discovering JS files in {scope} (query root {query_root})")
    base_params: Dict = {
        "url": query_root,
        "matchType": "domain",
        "output": "json",
        "fl": "timestamp,original,statuscode,mimetype",
        "collapse": "urlkey",
        "limit": str(limit * 20),   # over-fetch because we'll filter vendor
        "filter": [
            "statuscode:200",
            r"mimetype:(application/javascript|text/javascript|application/x-javascript)",
        ],
    }
    if since:
        base_params["from"] = since

    # First pass: oldest snapshot per URL (collapse=urlkey default)
    rows_first = _cdx_get(base_params, rate)
    _log(f"CDX: {len(rows_first)} raw JS URLs found (first-seen pass)")

    # Second pass: newest snapshot per URL (sort=reverse + collapse=urlkey)
    params_last = {**base_params, "fl": "timestamp,original"}
    # CDX doesn't support sort=reverse + collapse together cleanly, so we
    # fetch without collapse in reverse order and build a last-seen map.
    params_last.pop("collapse", None)
    params_last["sort"] = "reverse"
    rows_last = _cdx_get(params_last, rate)

    # Build last-seen map: canonical → latest timestamp
    last_seen_map: Dict[str, str] = {}
    for row in rows_last:
        if len(row) < 2:
            continue
        ts, original = row[0], row[1]
        parsed = urlparse(original)
        canonical = parsed.scheme + "://" + parsed.netloc + parsed.path
        if canonical not in last_seen_map:
            last_seen_map[canonical] = ts

    files: List[JSFile] = []
    seen_canonicals: Set[str] = set()

    for row in rows_first:
        if len(row) < 4:
            continue
        ts, original, status, mime = row[0], row[1], row[2], row[3]
        parsed = urlparse(original)

        # Scope check
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            continue
        if parsed.username or parsed.password or not scope_policy.matches_url(original):
            continue

        # Mime filter — CDX mime can be empty for some snapshots
        if mime and mime.lower().split(";")[0].strip() not in JS_MIMES and not original.lower().endswith(".js"):
            continue

        canonical = parsed.scheme + "://" + parsed.netloc + parsed.path
        if canonical in seen_canonicals:
            continue
        seen_canonicals.add(canonical)

        filename = parsed.path.split("/")[-1].lower()
        if _VENDOR_RE.search(filename):
            continue

        score = _interest_score(original)
        files.append(JSFile(
            url=original,
            canonical=canonical,
            first_seen=ts,
            last_seen=last_seen_map.get(canonical, ts),
            snapshot_count=0,
            interest_score=score,
        ))

    files.sort(key=lambda f: -f.interest_score)
    selected = files[:limit]
    _log(f"Selected {len(selected)} JS files after vendor filter (top {limit} by interest)")
    return selected


def fetch_snapshots_for_url(js_url: str, max_snapshots: int, since: Optional[str], rate: float) -> List[str]:
    """
    Return a representative list of timestamps for a single JS URL.
    Samples: oldest, evenly distributed middle, most recent archived.
    Minimum gap between selected snapshots: 30 days.
    """
    params = {
        "url": js_url,
        "output": "json",
        "fl": "timestamp",
        "filter": "statuscode:200",
        "limit": "1000",
    }
    if since:
        params["from"] = since

    rows = _cdx_get(params, rate)
    all_ts = [r[0] for r in rows if r]
    if not all_ts:
        return []

    all_ts = sorted(set(all_ts))

    if len(all_ts) <= max_snapshots:
        return all_ts

    # Select representative snapshots with minimum 30-day gap
    selected: List[str] = [all_ts[0]]
    min_gap_days = 30

    if max_snapshots >= 2:
        step = (len(all_ts) - 1) / (max_snapshots - 1)
        indices = sorted(set(round(i * step) for i in range(max_snapshots)))
        for idx in indices:
            ts = all_ts[min(idx, len(all_ts) - 1)]
            last = selected[-1]
            last_dt = datetime.strptime(last[:8], "%Y%m%d")
            ts_dt = datetime.strptime(ts[:8], "%Y%m%d")
            if (ts_dt - last_dt).days >= min_gap_days and ts not in selected:
                selected.append(ts)

    if all_ts[-1] not in selected:
        selected.append(all_ts[-1])

    return sorted(selected)[:max_snapshots]


# ─── Download ─────────────────────────────────────────────────────────────────

def download_snapshot(original_url: str, timestamp: str, dest: Path, rate: float, scope: str) -> bool:
    """Download raw JS content from Wayback using the if_ flag (no toolbar injection)."""
    if not HostScope.parse(scope).matches_url(original_url):
        _warn(f"Skipping archived URL outside scope: {original_url}")
        return False
    wb_url = WAYBACK_RAW.format(ts=timestamp, url=original_url)
    time.sleep(rate)
    try:
        with _scoped_session("web.archive.org").get(
            wb_url, timeout=30, headers={"User-Agent": f"wayback_js_recon/{VERSION}"},
            stream=True,
        ) as response:
            if response.status_code != 200:
                return False
            body = bytearray()
            for chunk in response.iter_content(chunk_size=65536):
                if chunk:
                    body.extend(chunk)
                    if len(body) > MAX_JS_BYTES:
                        _warn(f"Archived JS exceeds {MAX_JS_BYTES} bytes; skipped")
                        return False
            if len(body) < 50 or b"<html" in body[:200].lower():
                return False
            dest.write_bytes(body)
            return True
    except Exception as exc:
        parsed = urlparse(wb_url)
        _err(f"Archived JS download failed at {parsed.netloc}{parsed.path}: {exc}")
        return False


def download_live(url: str, dest: Path, rate: float, scope: str) -> bool:
    """Download current live version of the JS file."""
    if not HostScope.parse(scope).matches_url(url):
        _warn(f"Skipping live URL outside scope: {url}")
        return False
    time.sleep(rate)
    try:
        with _scoped_session(scope).get(
            url, timeout=30, headers={"User-Agent": f"wayback_js_recon/{VERSION}"},
            stream=True,
        ) as response:
            if response.status_code != 200:
                return False
            body = bytearray()
            for chunk in response.iter_content(chunk_size=65536):
                if chunk:
                    body.extend(chunk)
                    if len(body) > MAX_JS_BYTES:
                        _warn(f"Live JS exceeds {MAX_JS_BYTES} bytes; skipped")
                        return False
            if len(body) < 50 or b"<html" in body[:200].lower():
                return False
            dest.write_bytes(body)
            return True
    except Exception as exc:
        parsed = urlparse(url)
        _err(f"Live JS download failed at {parsed.netloc}{parsed.path}: {exc}")
        return False


# ─── JS Analyzer ─────────────────────────────────────────────────────────────

def run_js_analyzer(js_path: Path, scope: Optional[str], profile: str, app_only: bool) -> Optional[Dict]:
    """
    Run js_analyzer_v4_8.py on a local JS file.
    Returns the parsed JSON report or None on failure.
    """
    if not JS_ANALYZER.exists():
        _err(f"js_analyzer not found: {JS_ANALYZER}")
        return None

    expected_out = js_path.with_name(js_path.stem + "_analysis_v4_8.json")

    cmd = [
        sys.executable, str(JS_ANALYZER), str(js_path),
        "--json", "--no-color",
        "--profile", profile,
        "--max", "10",
    ]
    if scope:
        cmd += ["--scope", scope]
    if app_only:
        cmd.append("--app-only")

    try:
        subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        _err(f"js_analyzer timeout on {js_path.name}")
        return None
    except Exception as exc:
        _err(f"js_analyzer error on {js_path.name}: {exc}")
        return None

    if not expected_out.exists():
        return None

    try:
        return json.loads(expected_out.read_text(encoding="utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return None


# ─── Diff logic ──────────────────────────────────────────────────────────────

def _extract_endpoint_set(report: Dict) -> Set[str]:
    """Extract normalized endpoint paths from a js_analyzer report."""
    eps: Set[str] = set()
    for ep in report.get("endpoints", []):
        url = ep.get("url", "")
        if url:
            # Normalize: strip domain, keep path+query skeleton
            parsed = urlparse(url)
            path = parsed.path.strip()
            if path and path != "/":
                path = re.sub(r"/\d+", "/{id}", path)
                eps.add(path)
    for client in report.get("api_clients", []):
        for p in client.get("paths", []):
            if p and p.startswith("/"):
                p = re.sub(r"/\d+", "/{id}", p)
                eps.add(p)
    return eps


def _extract_route_set(report: Dict) -> Set[str]:
    routes: Set[str] = set()
    for r in report.get("routes", []):
        if isinstance(r, str):
            path = r
        else:
            path = r.get("path") or r.get("url") or ""
        if path and path.startswith("/"):
            path = re.sub(r"/\d+", "/{id}", path)
            routes.add(path)
    return routes


def _extract_secret_types(report: Dict) -> Set[str]:
    secrets: Set[str] = set()
    for s in report.get("secrets", []):
        name = s.get("name") or s.get("type") or ""
        match = s.get("match") or s.get("value") or ""
        if name:
            # Use type + first 20 chars of match as key (not the full secret)
            key = f"{name}::{match[:20]}"
            secrets.add(key)
    return secrets


def _extract_param_set(report: Dict) -> Set[str]:
    params: Set[str] = set()
    for p in report.get("params", []):
        if isinstance(p, str):
            name = p
        elif isinstance(p, dict):
            name = p.get("name") or p.get("param") or ""
        else:
            continue
        if name:
            params.add(name.lower())
    return params


def _interest_score(url: str) -> int:
    """Score a JS URL by how interesting it is for security research."""
    score = 0
    filename = url.split("/")[-1].lower().split("?")[0]
    path = urlparse(url).path.lower()

    # High-value names
    if re.search(r"(?:app|main|index|bundle)(?:\.|[-_])", filename):
        score += 5
    if _INTERESTING_NAME_RE.search(filename):
        score += 2
    # Path depth (deeper = more specific = more interesting)
    score += min(path.count("/"), 4)
    # Avoid chunks that are numbered (low signal per file)
    if re.search(r"chunk[-_\.]\d+", filename):
        score -= 2

    return score


def build_file_diff(
    js_file: JSFile,
    snapshots: List[Snapshot],
    current: Optional[Snapshot],
) -> Dict:
    """
    Compare historical snapshots against the current live version.
    Returns legacy items (in old, not in current) and disappeared items.
    """
    if not snapshots:
        return {}

    # Collect what exists across ALL historical snapshots
    hist_endpoints: Dict[str, List[str]] = {}  # path -> [timestamps]
    hist_routes: Dict[str, List[str]] = {}
    hist_secrets: Dict[str, List[str]] = {}
    hist_params: Dict[str, List[str]] = {}

    for snap in snapshots:
        if not snap.report:
            continue
        ts = snap.timestamp
        for ep in _extract_endpoint_set(snap.report):
            hist_endpoints.setdefault(ep, []).append(ts)
        for r in _extract_route_set(snap.report):
            hist_routes.setdefault(r, []).append(ts)
        for s in _extract_secret_types(snap.report):
            hist_secrets.setdefault(s, []).append(ts)
        for p in _extract_param_set(snap.report):
            hist_params.setdefault(p, []).append(ts)

    # Current live sets
    cur_eps = _extract_endpoint_set(current.report) if current and current.report else set()
    cur_routes = _extract_route_set(current.report) if current and current.report else set()
    cur_secrets = _extract_secret_types(current.report) if current and current.report else set()
    cur_params = _extract_param_set(current.report) if current and current.report else set()

    def _legacy(hist: Dict[str, List[str]], current_set: Set[str]) -> List[Dict]:
        items = []
        for key, timestamps in hist.items():
            if key not in current_set:
                items.append({
                    "value": key,
                    "found_in_snapshots": sorted(timestamps),
                    "last_seen_archived": max(timestamps),
                    "high_interest": bool(_INTERESTING_EP_RE.search(key)),
                })
        items.sort(key=lambda x: (-x["high_interest"], x["value"]))
        return items

    legacy_endpoints = _legacy(hist_endpoints, cur_eps)
    legacy_routes = _legacy(hist_routes, cur_routes)
    legacy_secrets = _legacy(hist_secrets, cur_secrets)
    legacy_params = _legacy(hist_params, cur_params)

    return {
        "canonical_url": js_file.canonical,
        "snapshots_analyzed": len([s for s in snapshots if s.report]),
        "snapshot_timestamps": [s.timestamp for s in snapshots],
        "has_current_live": bool(current and current.report),
        "legacy_endpoints": legacy_endpoints,
        "legacy_routes": legacy_routes,
        "legacy_secrets": legacy_secrets,
        "legacy_params": legacy_params,
        "counts": {
            "legacy_endpoints": len(legacy_endpoints),
            "legacy_routes": len(legacy_routes),
            "legacy_secrets": len(legacy_secrets),
            "legacy_params": len(legacy_params),
            "high_interest_endpoints": sum(1 for e in legacy_endpoints if e["high_interest"]),
        },
    }


def build_global_diff(domain: str, scope: str, file_diffs: List[Dict], run_ts: str) -> Dict:
    """Merge per-file diffs into a single global output."""
    all_legacy_eps: Dict[str, Dict] = {}
    all_legacy_routes: Dict[str, Dict] = {}
    all_legacy_secrets: Dict[str, Dict] = {}

    for fd in file_diffs:
        src = fd.get("canonical_url", "")
        for ep in fd.get("legacy_endpoints", []):
            v = ep["value"]
            if v not in all_legacy_eps:
                all_legacy_eps[v] = {**ep, "source_js": [src]}
            else:
                if src not in all_legacy_eps[v]["source_js"]:
                    all_legacy_eps[v]["source_js"].append(src)

        for r in fd.get("legacy_routes", []):
            v = r["value"]
            if v not in all_legacy_routes:
                all_legacy_routes[v] = {**r, "source_js": [src]}
            else:
                if src not in all_legacy_routes[v]["source_js"]:
                    all_legacy_routes[v]["source_js"].append(src)

        for s in fd.get("legacy_secrets", []):
            v = s["value"]
            if v not in all_legacy_secrets:
                all_legacy_secrets[v] = {**s, "source_js": [src]}

    # Sort merged lists
    sorted_eps = sorted(all_legacy_eps.values(), key=lambda x: (-x["high_interest"], x["value"]))
    sorted_routes = sorted(all_legacy_routes.values(), key=lambda x: x["value"])

    total_hi = sum(1 for e in sorted_eps if e["high_interest"])

    return {
        "meta": {
            "version": VERSION,
            "domain": domain,
            "scope": scope,
            "run_ts": run_ts,
            "js_files_analyzed": len(file_diffs),
            "total_files_with_results": sum(1 for fd in file_diffs if fd.get("counts", {}).get("legacy_endpoints", 0) > 0),
        },
        "signal_summary": {
            "legacy_endpoints": len(all_legacy_eps),
            "legacy_routes": len(all_legacy_routes),
            "legacy_secrets": len(all_legacy_secrets),
            "high_interest_legacy_endpoints": total_hi,
        },
        "legacy_endpoints": sorted_eps,
        "legacy_routes": sorted_routes,
        "legacy_secrets": list(all_legacy_secrets.values()),
        "per_file": file_diffs,
    }


# ─── Output helpers ───────────────────────────────────────────────────────────

GREEN  = "\033[32m"
YELLOW = "\033[33m"
RED    = "\033[31m"
CYAN   = "\033[36m"
DIM    = "\033[2m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

_NO_COLOR = False


def _c(color: str, text: str) -> str:
    return text if _NO_COLOR else f"{color}{text}{RESET}"


def _log(msg: str) -> None:
    print(_c(CYAN, f"[*] {msg}"), file=sys.stderr)


def _ok(msg: str) -> None:
    print(_c(GREEN, f"[+] {msg}"), file=sys.stderr)


def _warn(msg: str) -> None:
    print(_c(YELLOW, f"[!] {msg}"), file=sys.stderr)


def _err(msg: str) -> None:
    print(_c(RED, f"[-] {msg}"), file=sys.stderr)


def print_summary(result: Dict) -> None:
    sig = result.get("signal_summary", {})
    meta = result.get("meta", {})
    print(file=sys.stderr)
    print(_c(BOLD + CYAN, "=" * 60), file=sys.stderr)
    print(_c(BOLD + CYAN, f"  Wayback JS Recon — {meta.get('domain')}"), file=sys.stderr)
    print(_c(BOLD + CYAN, "=" * 60), file=sys.stderr)
    print(_c(CYAN, f"  JS files analyzed:          {meta.get('js_files_analyzed', 0)}"), file=sys.stderr)
    print(_c(GREEN, f"  Legacy endpoints:           {sig.get('legacy_endpoints', 0)}"), file=sys.stderr)
    print(_c(RED if sig.get('high_interest_legacy_endpoints', 0) > 0 else DIM,
             f"  High-interest legacy eps:   {sig.get('high_interest_legacy_endpoints', 0)}"), file=sys.stderr)
    print(_c(YELLOW, f"  Legacy routes:              {sig.get('legacy_routes', 0)}"), file=sys.stderr)
    print(_c(RED if sig.get('legacy_secrets', 0) > 0 else DIM,
             f"  Legacy secrets:             {sig.get('legacy_secrets', 0)}"), file=sys.stderr)

    hi_eps = [e for e in result.get("legacy_endpoints", []) if e.get("high_interest")]
    if hi_eps:
        print(_c(BOLD + RED, "\n  HIGH-INTEREST legacy endpoints:"), file=sys.stderr)
        for ep in hi_eps[:15]:
            last = ep.get("last_seen_archived", "")
            print(_c(RED, f"    {ep['value']:<60} last: {last}"), file=sys.stderr)

    print(_c(BOLD + CYAN, "=" * 60), file=sys.stderr)
    print(file=sys.stderr)


# ─── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    global _NO_COLOR

    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description=f"wayback_js_recon v{VERSION} — Historical JS diff for legacy endpoint discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 wayback_js_recon.py example.com
  python3 wayback_js_recon.py example.com --since 20200101 --max-files 15 --profile saas
  python3 wayback_js_recon.py example.com --scope '*.example.com' --app-only -o out.json
        """,
    )
    parser.add_argument("domain", help="Target domain (e.g. example.com)")
    parser.add_argument("--scope", default=None, help="Host exacto o wildcard autorizado (default: dominio exacto)")
    parser.add_argument("--yes", action="store_true", help="Confirma que autorizás el análisis histórico y las solicitudes live del scope indicado")
    parser.add_argument("--since", default=None, metavar="YYYYMMDD", help="Only look at snapshots from this date onwards (overrides --max-age-years)")
    parser.add_argument("--max-age-years", type=int, default=3, metavar="N", help="Ignore snapshots older than N years (default: 3). Set 0 to disable.")
    parser.add_argument("--max-files", type=int, default=10, metavar="N", help="Max distinct JS files to analyze (default: 10)")
    parser.add_argument("--max-snapshots", type=int, default=4, metavar="N", help="Max historical snapshots per JS file (default: 4)")
    parser.add_argument("--profile", default="generic", choices=["generic", "cms", "saas", "ecommerce"], help="js_analyzer keyword profile")
    parser.add_argument("--app-only", action="store_true", help="Pass --app-only to js_analyzer (filter vendor-high findings)")
    parser.add_argument("--rate", type=float, default=1.0, metavar="SECS", help="Delay between HTTP requests in seconds (default: 1.0)")
    parser.add_argument("--no-live", action="store_true", help="Skip downloading current live version (diff will compare snapshots only)")
    parser.add_argument("-o", "--output", default=None, metavar="PATH", help="Output JSON path (default: auto under BB_PIPELINE_DIR)")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    args = parser.parse_args()

    _NO_COLOR = args.no_color
    try:
        domain = normalize_domain_input(args.domain)
        scope = args.scope or domain
        scope_policy = HostScope.parse(scope)
        if not scope_policy.matches_host(domain) and not (scope.startswith("*.") and scope_policy.root == domain):
            raise ScopeError("El dominio base no coincide con el scope indicado.")
        if args.rate < 0 or args.max_files < 1 or args.max_snapshots < 1:
            raise ScopeError("rate no puede ser negativo; max-files y max-snapshots deben ser positivos.")
        if args.since and not re.fullmatch(r"\d{8}", args.since):
            raise ScopeError("--since debe tener formato YYYYMMDD.")
    except ScopeError as exc:
        parser.error(str(exc))

    if not args.yes:
        try:
            answer = input(f"Confirmás autorización para revisar Wayback y requests live dentro de {scope}? Escribí 'yes': ").strip()
        except EOFError:
            answer = ""
        if answer.lower() != "yes":
            _err("Sin confirmación de autorización; no se hicieron requests.")
            sys.exit(2)

    # Resolve effective since date: explicit --since wins, then --max-age-years
    since = args.since
    if not since and args.max_age_years > 0:
        from datetime import timezone
        cutoff = datetime.now(timezone.utc).replace(year=datetime.now(timezone.utc).year - args.max_age_years)
        since = cutoff.strftime("%Y%m%d")
        _log(f"Age filter: snapshots before {since} will be ignored (--max-age-years {args.max_age_years})")

    from datetime import timezone as _tz
    run_ts = datetime.now(_tz.utc).strftime("%Y%m%d_%H%M%S")

    # Work directory
    work_dir = BB_PIPELINE_DIR / domain / "wayback_js" / run_ts
    work_dir.mkdir(parents=True, exist_ok=True)
    _log(f"Work dir: {work_dir}")

    if not JS_ANALYZER.exists():
        _err(f"js_analyzer_v4_8.py not found at {JS_ANALYZER} — cannot proceed")
        sys.exit(1)

    # ── Step 1: Discover JS files ────────────────────────────────────────────
    js_files = fetch_js_urls(domain, scope, since, args.max_files, args.rate)
    if not js_files:
        _warn("No JS files found in Wayback CDX for this domain/scope")
        if since:
            _warn(f"  (within the age window since {since} — try --max-age-years 0 to include all history)")
        sys.exit(0)

    # ── Step 2: Per-file: discover snapshots, download, analyze ─────────────
    file_diffs: List[Dict] = []

    for js_file in js_files:
        _log(f"Processing: {js_file.canonical}")
        file_dir = work_dir / _safe_name(js_file.canonical)
        file_dir.mkdir(parents=True, exist_ok=True)

        # 2a. Get representative snapshot timestamps
        timestamps = fetch_snapshots_for_url(js_file.url, args.max_snapshots, since, args.rate)
        if not timestamps:
            _warn(f"No snapshots found for {js_file.canonical}")
            continue
        _log(f"  {len(timestamps)} snapshots selected: {timestamps}")

        # 2b. Download + analyze each historical snapshot
        snapshots: List[Snapshot] = []
        for ts in timestamps:
            snap_path = file_dir / f"{ts}.js"
            analysis_path = file_dir / f"{ts}_analysis_v4_8.json"

            snap = Snapshot(
                original_url=js_file.url,
                timestamp=ts,
                wayback_url=WAYBACK_RAW.format(ts=ts, url=js_file.url),
                local_path=snap_path,
                analysis_path=analysis_path,
            )

            if snap_path.exists() and snap_path.stat().st_size > 50:
                _log(f"  Snapshot {ts}: cached")
            else:
                ok = download_snapshot(js_file.url, ts, snap_path, args.rate, scope)
                if not ok:
                    _warn(f"  Snapshot {ts}: download failed — skipping")
                    continue

            report = run_js_analyzer(snap_path, scope, args.profile, args.app_only)
            if report:
                snap.report = report
                _ok(f"  Snapshot {ts}: analyzed ({len(report.get('endpoints', []))} endpoints)")
            else:
                _warn(f"  Snapshot {ts}: analysis failed")

            snapshots.append(snap)

        # 2c. Download + analyze current live version
        current: Optional[Snapshot] = None
        if not args.no_live:
            live_url = js_file.canonical
            live_path = file_dir / "live_current.js"

            if live_path.exists() and live_path.stat().st_size > 50:
                _log(f"  Live: cached")
            else:
                ok = download_live(live_url, live_path, args.rate, scope)
                if not ok:
                    _warn(f"  Live: download failed — diff will use latest archived as baseline")

            if live_path.exists() and live_path.stat().st_size > 50:
                report = run_js_analyzer(live_path, scope, args.profile, args.app_only)
                if report:
                    current = Snapshot(
                        original_url=live_url,
                        timestamp="live",
                        wayback_url=live_url,
                        local_path=live_path,
                        analysis_path=live_path.with_name("live_current_analysis_v4_8.json"),
                        report=report,
                    )
                    _ok(f"  Live: analyzed ({len(report.get('endpoints', []))} endpoints)")

        # 2d. Build diff for this file
        diff = build_file_diff(js_file, snapshots, current)
        if diff:
            file_diffs.append(diff)
            _ok(f"  Diff: {diff['counts']['legacy_endpoints']} legacy endpoints, "
                f"{diff['counts']['high_interest_endpoints']} high-interest")

    # ── Step 3: Build global output ──────────────────────────────────────────
    result = build_global_diff(domain, scope, file_diffs, run_ts)

    # ── Step 4: Write output ─────────────────────────────────────────────────
    if args.output:
        out_path = Path(args.output)
    else:
        out_path = work_dir / f"wayback_js_diff_{run_ts}.json"

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    _ok(f"Output: {out_path}")

    # ── Step 5: Print summary ────────────────────────────────────────────────
    print_summary(result)

    # Emit clean JSON path to stdout for piping/agent consumption
    print(str(out_path))


def _safe_name(url: str) -> str:
    """Convert a URL to a safe directory name."""
    name = re.sub(r"https?://", "", url)
    name = re.sub(r"[^\w\-.]", "_", name)
    return name[:80]


if __name__ == "__main__":
    main()
