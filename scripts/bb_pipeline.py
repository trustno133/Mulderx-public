#!/usr/bin/env python3
"""
bb_pipeline.py — Bug Bounty Pipeline Orchestrator
Integra: subdomain.sh → recon_fingerprint → js_analyzer → Claude Code handoff

Usage:
    python3 bb_pipeline.py -d target.com [opciones]
    python3 bb_pipeline.py -d target.com --scope target.com --profile generic --js-analyze
    python3 bb_pipeline.py -d target.com --only-new --notify
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path
try:
    from scope_policy import HostScope, ScopeError, normalize_domain_input, open_scoped_url
except ModuleNotFoundError:
    from scripts.scope_policy import HostScope, ScopeError, normalize_domain_input, open_scoped_url

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
PIPELINE_DIR     = Path(os.environ.get("BB_PIPELINE_DIR", Path.home() / ".bb_pipeline"))
SCRIPTS_DIR      = Path(os.environ.get("BB_SCRIPTS_DIR", Path(__file__).parent))
RECON_FP_SCRIPT  = SCRIPTS_DIR / "recon_fingerprint_v3.6_handoff_slim.py"
JS_ANALYZER      = SCRIPTS_DIR / "js_analyzer_v4_8.py"
SUBDOMAIN_SCRIPT = SCRIPTS_DIR / "reconv2.5.sh"


def _resolve_bash() -> str:
    """En Windows, subprocess.run(['bash', ...]) puede resolver al stub de
    WSL en WindowsApps (App Execution Alias) en vez de Git Bash, aunque
    'where bash' liste Git Bash primero — ese stub usa rutas /mnt/c/... y
    rompe con paths tipo C:/... o /c/.... Preferir Git Bash explícito si
    existe."""
    if os.environ.get("BB_BASH_PATH"):
        return os.environ["BB_BASH_PATH"]
    if sys.platform == "win32":
        for candidate in (
            r"C:\Program Files\Git\bin\bash.exe",
            r"C:\Program Files\Git\usr\bin\bash.exe",
        ):
            if Path(candidate).exists():
                return candidate
    return "bash"


BASH_BIN = _resolve_bash()

TELEGRAM_TOKEN   = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT    = os.environ.get("TELEGRAM_CHAT_ID", "")


# ─────────────────────────────────────────────
# UTILS
# ─────────────────────────────────────────────
def log(msg: str, level: str = "INFO") -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    colors = {"INFO": "\033[36m", "OK": "\033[32m", "WARN": "\033[33m",
              "ERR": "\033[31m", "STEP": "\033[35m"}
    reset = "\033[0m"
    c = colors.get(level, "")
    print(f"{c}[{ts}][{level}]{reset} {msg}", flush=True)


def run(
    cmd: list[str],
    timeout: int = 300,
    capture: bool = False,
    *,
    log_command: bool = True,
) -> subprocess.CompletedProcess:
    if log_command:
        log(f"$ {' '.join(str(c) for c in cmd)}", "STEP")
    kwargs = dict(timeout=timeout, text=True)
    if capture:
        kwargs["capture_output"] = True
    return subprocess.run(cmd, **kwargs)


def telegram_notify(msg: str) -> None:
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT:
        return
    try:
        run(["curl", "-s", "--max-time", "10", "-X", "POST",
             f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
             "-d", f"chat_id={TELEGRAM_CHAT}",
             "-d", f"text={msg}",
             "-d", "parse_mode=Markdown"], capture=True, log_command=False)
    except Exception as e:
        log(f"Telegram error: {e}", "WARN")


def save_state(state_file: Path, data: dict) -> None:
    state_file.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=state_file.parent,
        prefix=f".{state_file.name}.", suffix=".tmp", delete=False,
    ) as handle:
        temp_path = Path(handle.name)
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp_path, state_file)


def load_state(state_file: Path) -> dict:
    if state_file.exists():
        try:
            state = json.loads(state_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"No se pudo leer el estado del pipeline {state_file}: {exc}") from exc
        if not isinstance(state, dict):
            raise ValueError(f"El estado del pipeline debe ser un objeto JSON: {state_file}")
        return state
    return {}


# ─────────────────────────────────────────────
# STAGE 1: SUBDOMAIN DISCOVERY
# ─────────────────────────────────────────────
def stage_subdomains(domain: str, work_dir: Path, args) -> dict:
    """Devuelve {"subdomains": [...], "status": "ok"|"failed"|"timeout"|"not_found", "detail": str}.

    Antes esto devolvía solo la lista y decidía el fallback mirando qué
    archivos existían en disco — eso trataba "primera corrida, sin
    historial" y "el script crasheó" exactamente igual, porque nunca se
    chequeaba el returncode real del subprocess. Ahora sí.
    """
    log(f"[1/4] Subdomain discovery → {domain}", "STEP")

    known_file = work_dir / "known_subdomains.txt"
    today = datetime.now().strftime("%Y%m%d")
    new_file = work_dir / f"new_{today}.txt"

    if not SUBDOMAIN_SCRIPT.exists():
        log(f"subdomain.sh no encontrado en {SUBDOMAIN_SCRIPT}, saltando discovery", "WARN")
        return {
            "subdomains": [domain],
            "status": "not_found",
            "detail": f"{SUBDOMAIN_SCRIPT} no existe",
        }

    env = os.environ.copy()
    env["SUBDOMAIN_MONITOR_DIR"] = str(work_dir / "subdomain_monitor")

    script_status = "ok"
    script_detail = ""
    try:
        result = subprocess.run(
            [BASH_BIN, str(SUBDOMAIN_SCRIPT).replace("\\", "/"), domain, "--yes"],
            timeout=600, text=True, capture_output=True, env=env,
        )
        if result.returncode != 0:
            script_status = "failed"
            script_detail = (result.stderr or result.stdout or "").strip()[-500:]
            log(f"subdomain.sh terminó con exit code {result.returncode}: {script_detail}", "ERR")
    except subprocess.TimeoutExpired:
        script_status = "timeout"
        script_detail = "subdomain.sh timeout (600s)"
        log(script_detail, "WARN")
    except OSError as exc:
        script_status = "failed"
        script_detail = f"No se pudo iniciar subdomain.sh: {exc}"
        log(script_detail, "WARN")

    # Fallback de subdominios — depende de si el script realmente falló
    # o si simplemente es la primera corrida (eso NO es una falla).
    new_subs: list[str] = []
    if script_status == "ok" and new_file.exists():
        new_subs = [s.strip() for s in new_file.read_text().splitlines() if s.strip()]
        log(f"Nuevos subdominios: {len(new_subs)}", "OK")
    elif script_status == "ok" and not known_file.exists():
        # Corrida legítima, sin historial previo — primera vez con este dominio.
        new_subs = [domain]
        log("Sin historial (primera corrida), usando dominio raíz", "INFO")
    elif known_file.exists():
        # Falló, o corrió ok pero sin diff nuevo — en ambos casos, el
        # último conocido es mejor base que nada. Si falló, esto es
        # DEGRADADO (subdominios viejos, no una discovery real de hoy).
        new_subs = [s.strip() for s in known_file.read_text().splitlines() if s.strip()]
        if script_status != "ok":
            log(f"Discovery falló — usando {len(new_subs)} subdominios conocidos de una corrida anterior (degradado)", "WARN")
        else:
            log(f"Sin diff, usando {len(new_subs)} subdominios conocidos", "INFO")
    else:
        # Falló Y no hay ningún historial previo — no hay nada mejor que el dominio raíz.
        new_subs = [domain]
        log(f"Discovery falló y no hay historial — usando solo dominio raíz (cobertura mínima)", "ERR")

    if args.only_new and not new_file.exists():
        log("--only-new activo pero sin nuevos subdominios. Abortando.", "WARN")
        return {"subdomains": [], "status": script_status, "detail": script_detail}

    return {"subdomains": new_subs, "status": script_status, "detail": script_detail}


# ─────────────────────────────────────────────
# STAGE 2: RECON FINGERPRINT
# ─────────────────────────────────────────────
def stage_recon_fingerprint(
    subdomains: list[str],
    work_dir: Path,
    args,
    run_ts: str,
) -> list[dict]:
    log(f"[2/4] recon_fingerprint → {len(subdomains)} targets", "STEP")

    fp_dir = work_dir / "fingerprints" / run_ts
    fp_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict] = []
    scope_policy = HostScope.parse(args.scope)

    for sub in subdomains:
        try:
            sub_host = normalize_domain_input(sub)
        except ScopeError as exc:
            log(f"Subdominio inválido descartado: {sub!r} ({exc})", "WARN")
            continue
        if not scope_policy.matches_host(sub_host):
            log(f"Target fuera de scope, omitido: {sub_host}", "WARN")
            continue
        url = sub if sub.startswith("http") else f"https://{sub}"
        safe_name = sub.replace("://", "_").replace("/", "_").replace(".", "_")
        out_json   = fp_dir / f"{safe_name}.json"
        handoff_out = fp_dir / f"{safe_name}_handoff.json"

        cmd = [
            sys.executable, str(RECON_FP_SCRIPT), url,
            "-o", str(out_json),
            "--handoff-output", str(handoff_out),
            "--json-pretty",
            "--timeout", str(args.timeout),
        ]
        cmd += ["--scope", args.scope, "--yes"]
        if args.profile and args.profile != "generic":
            # recon_fingerprint no tiene --profile pero lo dejamos para futuro
            pass
        if args.no_path_probes:
            cmd.append("--no-path-probes")
        if args.extra_probes:
            cmd.append("--extra-probes")

        try:
            result = run(cmd, timeout=args.timeout + 60)
            if result.returncode != 0:
                log(f"recon_fingerprint terminó con exit code {result.returncode} para {sub}", "WARN")
                continue
        except subprocess.TimeoutExpired:
            log(f"Timeout en {sub}", "WARN")
            continue
        except Exception as e:
            log(f"Error en {sub}: {e}", "ERR")
            continue

        if out_json.exists():
            try:
                data = json.loads(out_json.read_text())
                data["_pipeline_target"] = sub
                results.append(data)
                log(f"✓ {sub}", "OK")
            except json.JSONDecodeError:
                log(f"JSON inválido para {sub}", "WARN")

    log(f"Fingerprint completo: {len(results)}/{len(subdomains)}", "OK")
    return results


# ─────────────────────────────────────────────
# STAGE 3: JS ANALYSIS
# ─────────────────────────────────────────────
def stage_js_analysis(
    fp_results: list[dict],
    work_dir: Path,
    args,
    run_ts: str,
) -> list[dict]:
    log(f"[3/4] js_analyzer sobre bundles detectados", "STEP")

    js_dir = work_dir / "js_analysis" / run_ts
    js_dir.mkdir(parents=True, exist_ok=True)

    # Extraer JS assets del handoff de recon_fingerprint
    js_files: list[dict] = []
    for fp in fp_results:
        handoff = fp.get("analyzer_handoff", {})
        assets = handoff.get("js_assets", []) or fp.get("assets", {}).get("js", [])
        target = fp.get("_pipeline_target", "unknown")
        for asset in assets:
            url = asset if isinstance(asset, str) else asset.get("url", "")
            if url:
                js_files.append({"url": url, "target": target})

    if not js_files:
        log("No se encontraron JS assets para analizar", "WARN")
        return []

    # Deduplicar por URL
    seen = set()
    unique_js = []
    for j in js_files:
        if j["url"] not in seen:
            seen.add(j["url"])
            unique_js.append(j)

    log(f"JS assets únicos: {len(unique_js)}", "INFO")

    # Cargar baseline para diff incremental
    baseline_file = work_dir / "js_baseline.json"
    baseline_arg = str(baseline_file) if baseline_file.exists() else None

    js_results: list[dict] = []
    scope_policy = HostScope.parse(args.scope)
    dl_dir = js_dir / "_downloaded"
    dl_dir.mkdir(parents=True, exist_ok=True)

    for js in unique_js[:args.max_js]:  # límite configurable
        url = js["url"]
        if not scope_policy.matches_url(url):
            log(f"JS fuera de scope, omitido: {url[:100]}", "WARN")
            continue
        safe_base = url.split("?", 1)[0].replace("://", "_").replace("/", "_").replace(".", "_")[:68]
        safe = f"{safe_base}_{hashlib.sha256(url.encode('utf-8')).hexdigest()[:10]}"

        # js_analyzer solo lee archivos LOCALES — nunca fetchea URLs.
        # Pasarle la URL cruda como "file" siempre falla ("Archivo no
        # encontrado"). Hay que bajar el contenido primero.
        local_path = dl_dir / f"{safe}.js"
        try:
            with open_scoped_url(
                url,
                args.scope,
                timeout=20,
                headers={"User-Agent": "Mozilla/5.0"},
            ) as resp:
                body = resp.read(5 * 1024 * 1024 + 1)
                if len(body) > 5 * 1024 * 1024:
                    log(f"JS supera el límite local de 5 MiB, omitido: {url[:60]}", "WARN")
                    continue
                local_path.write_bytes(body)
        except Exception as e:
            log(f"No se pudo descargar {url[:60]}: {e}", "WARN")
            continue

        cmd = [
            sys.executable, str(JS_ANALYZER), str(local_path),
            "--json",
            "--max", str(args.js_max_matches),
        ]
        if args.scope:
            cmd += ["--scope", args.scope]
        if args.profile:
            cmd += ["--profile", args.profile]
        if baseline_arg:
            cmd += ["--baseline-json", baseline_arg]
        if args.app_only:
            cmd.append("--app-only")
        if args.no_color:
            cmd.append("--no-color")

        try:
            result = run(cmd, timeout=120, capture=True)
            if result.returncode == 0:
                # Nombre real que genera js_analyzer_v4_8: {stem}_analysis_v4_8.json
                # junto al archivo analizado — no ".report.json" en cwd.
                possible = local_path.with_name(local_path.stem + "_analysis_v4_8.json")
                out_json = js_dir / f"{safe}.json"
                if possible.exists():
                    data = json.loads(possible.read_text())
                    data["_js_url"] = url
                    data["_target"] = js["target"]
                    js_results.append(data)
                    possible.rename(out_json)
                    log(f"✓ JS: {url[:60]}", "OK")
                else:
                    log(f"js_analyzer retornó OK pero no se encontró {possible.name} para {url[:60]}", "WARN")
            else:
                detail = (result.stderr or result.stdout or "").strip()[:150]
                log(f"js_analyzer falló para {url[:60]}: {detail or '(sin detalle)'}", "WARN")
        except subprocess.TimeoutExpired:
            log(f"Timeout JS: {url[:60]}", "WARN")
        except Exception as e:
            log(f"Error JS {url[:60]}: {e}", "ERR")

    return js_results


# ─────────────────────────────────────────────
# STAGE 4: UNIFIED JSON + CLAUDE HANDOFF
# ─────────────────────────────────────────────
def stage_handoff(
    domain: str,
    subdomains: list[str],
    fp_results: list[dict],
    js_results: list[dict],
    work_dir: Path,
    run_ts: str,
    disco: dict,
) -> Path:
    log("[4/4] Generando unified JSON para Claude Code", "STEP")

    # Extraer top targets con score
    top_targets = []
    for fp in fp_results:
        handoff = fp.get("analyzer_handoff", {})
        score   = handoff.get("priority_score", 0) or fp.get("score", 0)
        top_targets.append({
            "target": fp.get("_pipeline_target"),
            "score": score,
            "tech_stack": fp.get("tech_stack", {}),
            "endpoints_count": len(handoff.get("endpoints", [])),
            "auth_signals": handoff.get("auth_signals", {}),
            "interesting_headers": handoff.get("interesting_headers", []),
            "notes": handoff.get("notes", []),
        })
    top_targets.sort(key=lambda x: x["score"], reverse=True)

    # Extraer JS findings de alto interés
    # js_analyzer_v4_8 agrupa findings por severidad en mayúsculas:
    # {"CRITICAL": [...], "HIGH": [...], "MEDIUM": [...], "LOW": [...], "INFO": [...]}
    # — no es una lista plana, y las claves de severidad van en mayúsculas.
    high_js = []
    for js in js_results:
        findings = js.get("findings", {})
        if isinstance(findings, dict):
            high = findings.get("CRITICAL", []) + findings.get("HIGH", [])
        else:
            # Fallback por si alguna versión futura vuelve a lista plana.
            high = [f for f in findings if isinstance(f, dict) and f.get("severity", "").upper() in ("HIGH", "CRITICAL")]
        if high:
            high_js.append({
                "url": js.get("_js_url"),
                "target": js.get("_target"),
                "high_findings": high,
            })

    unified = {
        "meta": {
            "domain": domain,
            "run_ts": run_ts,
            "pipeline_version": "1.0",
            "subdomains_total": len(subdomains),
            "fingerprinted": len(fp_results),
            "js_analyzed": len(js_results),
            "subdomain_discovery_status": disco["status"],
            "subdomain_discovery_detail": disco["detail"],
        },
        "top_targets": top_targets[:10],
        "js_high_findings": high_js,
        "claude_prompt": _build_claude_prompt(domain, top_targets, high_js, disco),
    }

    out_file = work_dir / f"pipeline_{run_ts}.json"
    out_file.write_text(json.dumps(unified, indent=2, ensure_ascii=False), encoding="utf-8")
    log(f"Unified JSON → {out_file}", "OK")
    return out_file


def _build_claude_prompt(domain: str, top_targets: list, high_js: list, disco: dict) -> str:
    """Genera el prompt listo para pasarle a Claude Code."""
    targets_summary = "\n".join(
        f"  - {t['target']} (score={t['score']}, endpoints={t['endpoints_count']})"
        for t in top_targets[:5]
    )
    js_summary = "\n".join(
        f"  - {j['url']} → {len(j['high_findings'])} high findings"
        for j in high_js[:5]
    ) or "  (ninguno)"

    warning = ""
    if disco["status"] != "ok":
        warning = (
            f"\n⚠️ ADVERTENCIA: subdomain discovery status = '{disco['status']}' "
            f"({disco['detail'] or 'sin detalle'}). Los targets de abajo pueden NO "
            f"cubrir el dominio completo — no asumas cobertura total del scope antes "
            f"de confirmar esto con el operador.\n"
        )

    return f"""Sos un experto en bug bounty analizando resultados de recon para {domain}.
{warning}
TOP TARGETS POR SCORE:
{targets_summary}

JS HIGH FINDINGS:
{js_summary}

Tareas:
1. Identificá los 3 targets más prometedores y explicá por qué.
2. Para cada JS high finding, describí el riesgo real y el impacto potencial.
3. Sugerí cadenas de ataque (chains) basadas en los auth_signals y endpoints detectados.
4. Indicá el siguiente paso concreto de testing para el target #1.
5. Identificá si hay patrones comunes entre los targets (misma tecnología, mismo tipo de falla).

Sé directo, técnico y orientado a impacto de bounty. No generalices."""


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="bb_pipeline.py — Bug Bounty Pipeline Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python3 bb_pipeline.py -d target.com --scope target.com
  python3 bb_pipeline.py -d target.com --profile generic --js-analyze --notify
  python3 bb_pipeline.py -d target.com --only-new --max-js 20
        """
    )
    p.add_argument("-d", "--domain", required=True, help="Dominio objetivo")
    p.add_argument(
        "--scope",
        default=None,
        help="Ámbito autorizado: host exacto (incluye ápice) o wildcard *.dominio (solo subdominios; default: host exacto del target)",
    )
    p.add_argument("--yes", "-y", action="store_true",
                   help="Confirmar autorización del dominio para este pipeline activo")
    p.add_argument("--profile", default="generic",
                   choices=["generic", "cms", "saas", "ecommerce"],
                   help="Perfil para js_analyzer")
    p.add_argument("--only-new", action="store_true",
                   help="Solo procesar subdominios nuevos (requiere historial previo)")
    p.add_argument("--js-analyze", action="store_true",
                   help="Correr js_analyzer sobre bundles detectados")
    p.add_argument("--max-js", type=int, default=15,
                   help="Máximo de JS files a analizar (default: 15)")
    p.add_argument("--js-max-matches", type=int, default=5,
                   help="--max para js_analyzer (default: 5)")
    p.add_argument("--app-only", action="store_true",
                   help="Pasar --app-only a js_analyzer")
    p.add_argument("--timeout", type=int, default=120,
                   help="Timeout por target en recon_fingerprint (default: 120s)")
    p.add_argument("--no-path-probes", action="store_true")
    p.add_argument("--extra-probes", action="store_true")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--notify", action="store_true",
                   help="Enviar resumen por Telegram al final")
    p.add_argument("--work-dir", default=None,
                   help=f"Directorio de trabajo (default: {PIPELINE_DIR}/<domain>)")
    return p.parse_args()


def main() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    args = parse_args()
    if args.timeout <= 0 or args.max_js < 1 or args.js_max_matches < 1:
        raise SystemExit("timeout, max-js y js-max-matches deben ser positivos.")
    try:
        domain = normalize_domain_input(args.domain)
        scope_value = args.scope or domain
        scope_policy = HostScope.parse(scope_value)
    except ScopeError as exc:
        raise SystemExit(f"Scope/domain inválido: {exc}") from exc
    if not scope_policy.matches_host(domain) and not (
        scope_policy.include_subdomains and domain == scope_policy.root
    ):
        raise SystemExit(f"El dominio {domain} no pertenece al scope declarado {scope_value}.")
    args.domain = domain
    args.scope = scope_value

    if args.yes:
        log(f"Autorización afirmada con --yes para {domain} dentro de {scope_value}.", "WARN")
    else:
        try:
            answer = input(
                f"Este pipeline hará requests activos sobre {domain} (scope: {scope_value}). "
                "¿Tienes autorización explícita para este alcance? (s/n): "
            ).strip().lower()
        except EOFError:
            raise SystemExit("No hay terminal para confirmar. Usa --yes solo si la autorización está confirmada.")
        if answer != "s":
            log("Pipeline cancelado por el operador.", "WARN")
            return

    work_dir = Path(args.work_dir) if args.work_dir else PIPELINE_DIR / domain
    work_dir = work_dir.resolve()
    work_dir.mkdir(parents=True, exist_ok=True)

    run_ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    state_file = work_dir / "pipeline_state.json"
    try:
        state = load_state(state_file)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    log(f"╔══ BB Pipeline v1.0 ══ {domain} ══ {run_ts} ╗", "STEP")
    log(f"Work dir: {work_dir}", "INFO")

    start = time.time()

    # Stage 1: Subdomains
    disco = stage_subdomains(domain, work_dir, args)
    subdomains = disco["subdomains"]
    if not subdomains:
        log("Sin subdominios para procesar. Saliendo.", "WARN")
        sys.exit(0)
    if disco["status"] != "ok":
        log(f"⚠ Subdomain discovery status: {disco['status']} — el análisis siguiente puede tener cobertura reducida", "WARN")

    # Stage 2: Recon fingerprint
    fp_results = stage_recon_fingerprint(subdomains, work_dir, args, run_ts)

    # Stage 3: JS analysis (opcional)
    js_results: list[dict] = []
    if args.js_analyze and fp_results:
        js_results = stage_js_analysis(fp_results, work_dir, args, run_ts)

    # Stage 4: Unified handoff
    unified_file = stage_handoff(domain, subdomains, fp_results, js_results, work_dir, run_ts, disco)

    elapsed = time.time() - start

    # Actualizar estado
    state["last_run"] = run_ts
    state["last_unified"] = str(unified_file)
    save_state(state_file, state)

    # Resumen final
    summary = (
        f"🏁 *BB Pipeline completo* — `{domain}`\n"
        f"⏱ {elapsed:.0f}s\n"
        f"🌐 Subdominios: {len(subdomains)}\n"
        f"🔍 Fingerprinted: {len(fp_results)}\n"
        f"📦 JS analizados: {len(js_results)}\n"
        f"📄 Output: `{unified_file.name}`\n\n"
        f"Siguiente paso:\n"
        f"  claude --print < {unified_file} | jq .claude_prompt -r | claude"
    )

    log("─" * 60, "INFO")
    log(f"Pipeline completo en {elapsed:.0f}s", "OK")
    log(f"Output: {unified_file}", "OK")
    log(f"\nPara analizar con Claude Code:", "INFO")
    log(f"  cat {unified_file} | jq -r .claude_prompt | claude", "INFO")
    log(f"  # o directamente:", "INFO")
    log(f"  claude --print 'Analizá este recon:' --file {unified_file}", "INFO")

    if args.notify:
        telegram_notify(summary)


if __name__ == "__main__":
    main()
