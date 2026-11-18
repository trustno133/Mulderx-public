#!/usr/bin/env python3
"""
parcel_analyze.py — Pipeline: module_graph_parcel → js_analyzer por módulo.

Extrae módulos de un bundle Parcel 1, corre js_analyzer_v4_8 sobre cada uno,
y consolida los findings con atribución por módulo.

Usage:
  parcel_analyze.py bundle.js [--scope DOMAIN] [--profile PROFILE]
                              [--modules-dir DIR] [--output JSON] [--no-color]
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPTS = Path(__file__).parent
MODULE_GRAPH = SCRIPTS / "module_graph_parcel.py"
JS_ANALYZER  = SCRIPTS / "js_analyzer_v4_8.py"

SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

# ── helpers ──────────────────────────────────────────────────────────────────

def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def label_or_id(mod: dict) -> str:
    return mod.get("label") or mod["module_id"]


def sev_counts(findings: list[dict]) -> dict[str, int]:
    c: dict[str, int] = {}
    for f in findings:
        s = (f.get("severity") or f.get("level") or "?").lower()
        c[s] = c.get(s, 0) + 1
    return c


def parse_analyzer_json(path: Path) -> dict:
    """Load js_analyzer JSON; tolerate different root shapes."""
    try:
        raw = json.loads(path.read_text("utf-8"))
    except Exception:
        return {}
    # js_analyzer v4.8 wraps everything under the filename key sometimes
    if isinstance(raw, dict) and "findings" not in raw:
        for v in raw.values():
            if isinstance(v, dict) and "findings" in v:
                return v
    return raw if isinstance(raw, dict) else {}


def parse_resumen(text: str) -> dict[str, int]:
    """Extract HIGH/MEDIUM/LOW counts from plain-text analyzer output."""
    counts: dict[str, int] = {}
    for line in text.splitlines():
        line = line.strip()
        for sev in ("HIGH", "MEDIUM", "LOW"):
            if line.startswith(f"{sev}:"):
                try:
                    counts[sev.lower()] = int(line.split(":")[1].strip())
                except ValueError:
                    pass
    return counts


# ── colors ───────────────────────────────────────────────────────────────────

class C:
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

    @classmethod
    def disable(cls) -> None:
        for attr in ("RED", "YELLOW", "CYAN", "BOLD", "DIM", "RESET"):
            setattr(cls, attr, "")


def sev_color(sev: str) -> str:
    return {
        "high":   C.RED,
        "medium": C.YELLOW,
        "low":    C.CYAN,
    }.get(sev.lower(), "")


# ── main pipeline ─────────────────────────────────────────────────────────────

def run_pipeline(
    bundle: Path,
    scope: str | None,
    profile: str,
    modules_dir: Path,
    output_json: Path | None,
    no_color: bool,
) -> int:
    if no_color:
        C.disable()

    modules_dir.mkdir(parents=True, exist_ok=True)

    # ── Step 1: module graph + extraction ────────────────────────────────────
    print(f"\n{C.BOLD}[1/3] Extrayendo módulos con module_graph_parcel…{C.RESET}")
    graph_json_path = modules_dir / "_graph.json"

    # Dos llamadas separadas: [extracted] va a stdout y contaminaría el JSON
    r_extract = run([
        sys.executable, str(MODULE_GRAPH),
        str(bundle),
        "--extract-dir", str(modules_dir),
    ])
    if r_extract.returncode == 2:
        print("[!] bundle no es formato Parcel 1 — abortando.", file=sys.stderr)
        return 2
    if r_extract.returncode not in (0, 1):
        print(r_extract.stderr, file=sys.stderr)
        return 1
    # print extraction lines so the user sees them
    for line in r_extract.stdout.splitlines():
        if line.startswith("[extracted]"):
            print(f"    {line}")

    r_json = run([sys.executable, str(MODULE_GRAPH), str(bundle), "--json"])
    try:
        graph = json.loads(r_json.stdout)
    except json.JSONDecodeError:
        print("[!] module_graph_parcel no devolvió JSON válido.", file=sys.stderr)
        return 1

    graph_json_path.write_text(json.dumps(graph, indent=2))

    mod_meta: dict[str, dict] = graph.get("modules", {})
    stats = graph.get("stats", {})
    print(f"    {stats.get('module_count', '?')} módulos  "
          f"{stats.get('edge_count', '?')} edges  "
          f"orphans={stats.get('orphan_count', '?')}")

    # ── Step 2: js_analyzer por módulo ───────────────────────────────────────
    print(f"\n{C.BOLD}[2/3] Analizando módulos con js_analyzer_v4_8…{C.RESET}")

    extracted = sorted(modules_dir.glob("*.js"))
    if not extracted:
        print("[!] No se encontraron módulos extraídos.", file=sys.stderr)
        return 1

    results: list[dict] = []

    for js_path in extracted:
        mod_id = js_path.stem
        meta   = mod_meta.get(mod_id, {})
        display = meta.get("label") or mod_id

        cmd = [sys.executable, str(JS_ANALYZER), str(js_path),
               "--json", "--no-color"]
        if scope:
            cmd += ["--scope", scope]
        cmd += ["--profile", profile, "--app-only"]

        r2 = run(cmd)
        counts = parse_resumen(r2.stdout)
        total  = sum(counts.values())

        # locate the JSON the analyzer wrote next to the .js file
        analyzer_json_path = js_path.with_name(f"{mod_id}_analysis_v4_8.json")
        analyzer_data = parse_analyzer_json(analyzer_json_path) if analyzer_json_path.exists() else {}

        sev_str = ""
        if counts.get("high"):
            sev_str += f"{C.RED}H:{counts['high']}{C.RESET} "
        if counts.get("medium"):
            sev_str += f"{C.YELLOW}M:{counts['medium']}{C.RESET} "
        if counts.get("low"):
            sev_str += f"{C.CYAN}L:{counts['low']}{C.RESET}"

        status = sev_str.strip() if total else f"{C.DIM}sin findings{C.RESET}"
        print(f"  {mod_id:>10}  {display:<45}  {js_path.stat().st_size:>8,}b  {status}")

        results.append({
            "module_id":       mod_id,
            "label":           display,
            "is_entry":        meta.get("is_entry", False),
            "is_orphan":       meta.get("is_orphan", False),
            "out_degree":      len(meta.get("out", [])),
            "in_degree":       len(meta.get("in", [])),
            "file_bytes":      js_path.stat().st_size,
            "counts":          counts,
            "total_findings":  total,
            "analyzer_json":   str(analyzer_json_path) if analyzer_json_path.exists() else None,
            "analyzer_data":   analyzer_data,
        })

    # ── Step 3: consolidar y reportar ────────────────────────────────────────
    print(f"\n{C.BOLD}[3/3] Consolidando{C.RESET}")

    results.sort(key=lambda r: (
        -r["counts"].get("high", 0),
        -r["counts"].get("medium", 0),
        -r["counts"].get("low", 0),
    ))

    total_h = sum(r["counts"].get("high", 0)   for r in results)
    total_m = sum(r["counts"].get("medium", 0) for r in results)
    total_l = sum(r["counts"].get("low", 0)    for r in results)

    W = 70
    print(f"\n{'═'*W}")
    print(f"  {C.BOLD}PARCEL ANALYZE — {bundle.name}{C.RESET}")
    print(f"  módulos analizados: {len(results)}  "
          f"{C.RED}HIGH={total_h}{C.RESET}  "
          f"{C.YELLOW}MEDIUM={total_m}{C.RESET}  "
          f"{C.CYAN}LOW={total_l}{C.RESET}")
    print(f"{'═'*W}")

    for r in results:
        if not r["total_findings"]:
            continue
        counts = r["counts"]
        h = counts.get("high", 0)
        m = counts.get("medium", 0)
        l = counts.get("low", 0)
        tag = "(entry)" if r["is_entry"] else "(orphan)" if r["is_orphan"] else ""
        print(f"\n  {C.BOLD}{r['module_id']}{C.RESET}  {r['label']}  {tag}")
        print(f"    out={r['out_degree']}  in={r['in_degree']}  "
              f"{r['file_bytes']:,}b  │  "
              f"{C.RED}H:{h}{C.RESET}  {C.YELLOW}M:{m}{C.RESET}  {C.CYAN}L:{l}{C.RESET}")

        # top findings from analyzer data
        findings = []
        adata = r["analyzer_data"]
        for key in ("findings", "matches", "results"):
            v = adata.get(key, [])
            if isinstance(v, list):
                findings = v
                break

        shown = 0
        for f in findings:
            if shown >= 5:
                remaining = len(findings) - shown
                print(f"    {C.DIM}  … +{remaining} más{C.RESET}")
                break
            kind  = f.get("kind") or f.get("type", "?")
            sev   = (f.get("severity") or f.get("level") or "?").lower()
            snip  = (f.get("snippet") or f.get("match") or "")[:80].replace("\n", " ")
            col   = sev_color(sev)
            print(f"    {col}[{sev.upper()}]{C.RESET} {kind}  {C.DIM}{snip}{C.RESET}")
            shown += 1

    # modules sin findings
    clean = [r for r in results if not r["total_findings"]]
    if clean:
        print(f"\n  {C.DIM}Sin findings: "
              + ", ".join(f"{r['module_id']}({r['label']})" for r in clean)
              + C.RESET)

    print(f"\n{'═'*W}")
    print(f"  JSONs por módulo en: {modules_dir}/")
    if output_json:
        payload = {
            "bundle":  str(bundle),
            "scope":   scope,
            "profile": profile,
            "graph":   graph,
            "modules": results,
            "totals":  {"high": total_h, "medium": total_m, "low": total_l},
        }
        output_json.write_text(json.dumps(payload, indent=2))
        print(f"  JSON consolidado:   {output_json}")
    print(f"{'═'*W}\n")

    return 0


# ── CLI ──────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(
        description="parcel_analyze.py — pipeline module_graph_parcel → js_analyzer por módulo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python3 parcel_analyze.py bundle.js --scope app.example.com
  python3 parcel_analyze.py bundle.js --modules-dir /tmp/mods --output report.json
""",
    )
    ap.add_argument("bundle", help="Parcel 1 bundle JS")
    ap.add_argument("--scope",       default=None, help="Dominio en scope para js_analyzer")
    ap.add_argument("--profile",     default="generic",
                    choices=["generic", "cms", "saas", "ecommerce"],
                    help="Perfil de js_analyzer (default: generic)")
    ap.add_argument("--modules-dir", default=None, metavar="DIR",
                    help="Directorio para módulos extraídos (default: <bundle_dir>/modules/)")
    ap.add_argument("--output",      default=None, metavar="JSON",
                    help="Path para JSON consolidado")
    ap.add_argument("--no-color",    action="store_true")
    args = ap.parse_args()

    bundle = Path(args.bundle).resolve()
    if not bundle.exists():
        print(f"[error] No existe: {bundle}", file=sys.stderr)
        sys.exit(1)

    modules_dir = Path(args.modules_dir).resolve() if args.modules_dir \
                  else bundle.parent / "modules"

    output_json = Path(args.output).resolve() if args.output else None

    sys.exit(run_pipeline(bundle, args.scope, args.profile,
                          modules_dir, output_json, args.no_color))


if __name__ == "__main__":
    main()
