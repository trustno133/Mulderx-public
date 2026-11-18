#!/usr/bin/env python3
"""
Mulderx Orchestrator
Lanza agentes de Claude Code en secuencia para bug bounty hunting.
"""

import json
import os
import subprocess
import sys
import argparse
import re
import time
import threading
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from functools import partial
from scripts.scope_policy import ScopeError, build_katana_regex as _build_katana_regex
from scripts.scope_policy import parse_orchestrator_target, validate_program_name

# Flush inmediato en background (sin terminal no hay flush automático)
print = partial(print, flush=True)

_PRINT_LOCK = threading.Lock()


def _make_prefixed_printer(prefix: str):
    """Printer thread-safe que antepone un prefijo a cada línea."""
    def _p(*args, **kwargs):
        with _PRINT_LOCK:
            if args:
                print(f"{prefix}{args[0]}", *args[1:], **kwargs)
            else:
                print(**kwargs)
    return _p

def build_katana_regex(target: str, scope_type: str = "domain") -> str:
    """Build a host-boundary regex for the explicit exact/wildcard scope."""
    return _build_katana_regex(target, scope_type)


MULDERX_ROOT  = Path(__file__).resolve().parent
AGENTS_DIR    = MULDERX_ROOT / "agents"
TARGETS_DIR   = MULDERX_ROOT / "targets"
CREDS_DIR     = MULDERX_ROOT / ".credentials"

AGENT_TIMEOUTS = {
    "recon":          3600,
    "summarizer":      600,
    "triage":         1200,
    "cve-scanner":    1200,
    "cve-exploit":    1800,
    "business-logic": 1200,
    "exploit-client": 1800,
    "exploit-server": 1800,
    "documentador":    900,
    "xss":            2400,
}

AGENT_MAX_TURNS = {
    "recon":          40,
    "summarizer":      8,
    "triage":         20,
    "cve-scanner":    15,
    "cve-exploit":    20,
    "business-logic": 20,
    "exploit-client": 30,
    "exploit-server": 30,
    "documentador":   15,
    "xss":            40,
}

# Acumulador de tokens por agente para el resumen final de sesión
SESSION_TOKENS: dict[str, dict] = {}
MAX_PARALLEL_AGENTS = 8


def read_agent_claude(agent_name: str) -> str:
    path = AGENTS_DIR / agent_name / "CLAUDE.md"
    if not path.exists():
        raise FileNotFoundError(f"No existe CLAUDE.md para agente '{agent_name}' en {path}")
    return path.read_text()


def read_agent_context(agent_name: str) -> str:
    """Instrucciones comunes más el prompt específico, sin adjuntar el manual entero."""
    common_path = MULDERX_ROOT / "AGENTS.md"
    if not common_path.exists():
        raise FileNotFoundError(f"Falta el archivo de reglas comunes: {common_path}")
    return common_path.read_text(encoding="utf-8") + "\n\n--- Instrucciones específicas del agente ---\n\n" + read_agent_claude(agent_name)


def _safe_workspace_path(raw_path: str, *, write: bool = False) -> Path:
    candidate = (MULDERX_ROOT / raw_path).resolve()
    try:
        candidate.relative_to(MULDERX_ROOT.resolve())
    except ValueError as exc:
        raise ValueError("La ruta debe permanecer dentro del workspace de Mulderx.") from exc
    relative = candidate.relative_to(MULDERX_ROOT.resolve())
    blocked = {".credentials", ".git", ".aws"}
    if any(part.lower() in blocked for part in relative.parts):
        raise ValueError("Acceso denegado a una carpeta privada o de control.")
    if write and (not relative.parts or relative.parts[0].lower() != "targets"):
        raise ValueError("El proveedor OpenAI solo puede escribir dentro de targets/.")
    return candidate


def _openai_tool_call(name: str, arguments: dict) -> str:
    if name == "read_file":
        path = _safe_workspace_path(arguments["path"])
        if not path.is_file():
            raise FileNotFoundError(f"No existe un archivo en esa ruta: {arguments['path']}")
        return path.read_text(encoding="utf-8", errors="replace")[:120_000]
    if name == "list_files":
        path = _safe_workspace_path(arguments.get("path", "."))
        if not path.is_dir():
            raise NotADirectoryError(arguments.get("path", "."))
        items = []
        for child in sorted(path.iterdir(), key=lambda p: p.name.lower()):
            if child.name.lower() in {".credentials", ".git", ".aws"}:
                continue
            items.append(("dir  " if child.is_dir() else "file ") + child.relative_to(MULDERX_ROOT).as_posix())
        return "\n".join(items[:500])
    if name == "write_file":
        path = _safe_workspace_path(arguments["path"], write=True)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(arguments["content"], encoding="utf-8")
        return f"Escrito: {path.relative_to(MULDERX_ROOT).as_posix()}"
    raise ValueError(f"Herramienta desconocida: {name}")


def run_openai_agent(agent_name: str, prompt: str, env: dict, timeout: int, out_fn=None) -> bool:
    """Agente Responses API para análisis de archivos; sin shell ni acceso a credenciales."""
    if out_fn is None:
        out_fn = print
    api_key = env.get("OPENAI_API_KEY") or os.environ.get("OPENAI_API_KEY")
    if not api_key:
        out_fn("[!] Falta OPENAI_API_KEY en el entorno.")
        return False
    model = env.get("MULDERX_OPENAI_MODEL", "gpt-6-astra")
    instructions = read_agent_context(agent_name)
    tools = [
        {"type": "function", "name": "list_files", "description": "Listar archivos del workspace (sin credenciales ni .git).", "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": [], "additionalProperties": False}},
        {"type": "function", "name": "read_file", "description": "Leer un archivo del workspace, excepto credenciales y carpetas privadas.", "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"], "additionalProperties": False}},
        {"type": "function", "name": "write_file", "description": "Escribir un resultado únicamente dentro de targets/.", "parameters": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}}, "required": ["path", "content"], "additionalProperties": False}},
    ]
    payload = {"model": model, "instructions": instructions, "input": prompt, "tools": tools}
    start = time.time()
    for _ in range(40):
        if time.time() - start > timeout:
            out_fn(f"[!] {agent_name} superó el timeout de {timeout}s")
            return False
        request = urllib.request.Request(
            "https://api.openai.com/v1/responses",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=max(1, timeout - int(time.time() - start))) as response:
                result = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            out_fn(f"[!] OpenAI API falló: {exc}")
            return False
        calls = [item for item in result.get("output", []) if item.get("type") == "function_call"]
        for item in result.get("output", []):
            if item.get("type") == "message":
                for content in item.get("content", []):
                    if content.get("type") == "output_text" and content.get("text"):
                        out_fn(content["text"])
        if not calls:
            return result.get("status") == "completed"
        outputs = []
        for call in calls:
            try:
                output = _openai_tool_call(call["name"], json.loads(call.get("arguments", "{}")))
            except Exception as exc:
                output = f"Error de herramienta: {exc}"
            outputs.append({"type": "function_call_output", "call_id": call["call_id"], "output": output})
        payload = {"model": model, "instructions": instructions, "previous_response_id": result["id"], "input": outputs, "tools": tools}
    out_fn("[!] OpenAI alcanzó el límite de 40 turnos de herramientas.")
    return False


def load_credentials(programa: str) -> tuple[dict, str | None, str]:
    """
    Busca .credentials/<programa>.env (case-insensitive).
    Devuelve (dict_de_vars, nombre_de_archivo, usage_block).
    usage_block es el contenido entre # [USAGE] y # [/USAGE], o "" si no existe.
    """
    if not CREDS_DIR.exists():
        return {}, None, ""
    for path in sorted(CREDS_DIR.glob("*.env")):
        if path.stem.lower() == programa.lower():
            env_vars = {}
            usage_lines = []
            in_usage = False
            for line in path.read_text().splitlines():
                stripped = line.strip()
                if stripped == "# [USAGE]":
                    in_usage = True
                    continue
                if stripped == "# [/USAGE]":
                    in_usage = False
                    continue
                if in_usage:
                    usage_lines.append(line.removeprefix("# ").removeprefix("#"))
                    continue
                if not stripped or stripped.startswith("#") or "=" not in stripped:
                    continue
                k, _, v = stripped.partition("=")
                env_vars[k.strip()] = v.strip()
            return env_vars, path.name, "\n".join(usage_lines).strip()
    return {}, None, ""


def format_creds_for_prompt(creds: dict, creds_file: str, usage_block: str) -> str:
    if not creds:
        return ""
    if usage_block:
        safe_usage = usage_block
        for value in creds.values():
            if value:
                safe_usage = safe_usage.replace(value, "[REDACTED]")
        return (
            f"\n\nCredenciales cargadas desde .credentials/{creds_file} "
            f"como variables de entorno (usar como $VAR en bash):\n\n"
            + safe_usage
        )
    keys = ", ".join(creds.keys())
    return (
        f"\n\nCredenciales cargadas desde .credentials/{creds_file} "
        f"como variables de entorno (usar como $VAR en bash): {keys}."
    )


def _print_token_line(agent_name: str, usage: dict, out_fn=None) -> None:
    if out_fn is None:
        out_fn = print
    inp   = usage.get("input_tokens", 0)
    out   = usage.get("output_tokens", 0)
    cr    = usage.get("cache_read_input_tokens", 0)
    cw    = usage.get("cache_creation_input_tokens", 0)
    out_fn(
        f"\n[tokens] {agent_name}: "
        f"input={inp:,}  output={out:,}  "
        f"cache_read={cr:,}  cache_write={cw:,}  "
        f"total={inp + out:,}"
    )


def print_session_token_summary() -> None:
    if not SESSION_TOKENS:
        return
    print(f"\n{'═'*62}")
    print("  TOKENS DE SESIÓN")
    print(f"{'═'*62}")
    grand = {"input_tokens": 0, "output_tokens": 0,
             "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0}
    for agent, usage in SESSION_TOKENS.items():
        inp = usage.get("input_tokens", 0)
        out = usage.get("output_tokens", 0)
        cr  = usage.get("cache_read_input_tokens", 0)
        cw  = usage.get("cache_creation_input_tokens", 0)
        for k in grand:
            grand[k] += usage.get(k, 0)
        print(f"  {agent:<20} in={inp:>9,}  out={out:>7,}  "
              f"cache_r={cr:>9,}  cache_w={cw:>9,}")
    print(f"{'─'*62}")
    print(f"  {'TOTAL':<20} in={grand['input_tokens']:>9,}  "
          f"out={grand['output_tokens']:>7,}  "
          f"cache_r={grand['cache_read_input_tokens']:>9,}  "
          f"cache_w={grand['cache_creation_input_tokens']:>9,}")
    print(f"{'═'*62}\n")


def run_agent(
    agent_name: str,
    prompt: str,
    timeout: int | None = None,
    verbose: bool = False,
    extra_env: dict | None = None,
    out_fn=None,
    provider: str = "claude",
    model: str | None = None,
) -> bool:
    if out_fn is None:
        out_fn = print
    system_prompt = read_agent_context(agent_name)
    effective_timeout = AGENT_TIMEOUTS.get(agent_name, 1800) if timeout is None else timeout
    if effective_timeout <= 0:
        out_fn("[!] El timeout debe ser un entero positivo.")
        return False

    out_fn(f"\n{'─'*60}")
    out_fn(f"[*] Agente: {agent_name}  (timeout: {effective_timeout}s)")
    out_fn(f"    Prompt preparado ({len(prompt)} caracteres; contenido omitido para no filtrar datos).")
    out_fn(f"{'─'*60}")

    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)

    if model:
        env["MULDERX_OPENAI_MODEL"] = model

    if provider == "openai":
        if agent_name not in {"summarizer", "triage", "business-logic", "documentador"}:
            out_fn(f"[!] OpenAI API solo está habilitado para análisis de archivos; '{agent_name}' necesita CLI/herramientas externas.")
            return False
        openai_prompt = re.sub(
            r"\n\nCredenciales cargadas desde \.credentials/.*?(?=\n\n|$)",
            "",
            prompt,
            flags=re.DOTALL,
        )
        openai_prompt += "\n\nNota: este proveedor no tiene acceso a credenciales ni ejecuta comandos externos. Analizá solo los artefactos existentes; no afirmes haber hecho pruebas activas ni confirmes impacto que no esté demostrado en esos artefactos."
        return run_openai_agent(agent_name, openai_prompt, env, effective_timeout, out_fn=out_fn)

    if provider == "codex":
        # Keep the legacy CLI gated by the operator's approval at tool boundaries.
        cmd = ["codex", "exec", "--sandbox", "workspace-write", "--ask-for-approval", "on-request"]
        if model:
            cmd.extend(["--model", model])
        cmd.extend(["-C", str(MULDERX_ROOT), system_prompt + "\n\n--- Tarea ---\n" + prompt])
        try:
            return _run_plain_command(agent_name, cmd, env, effective_timeout, verbose, out_fn=out_fn)
        except FileNotFoundError:
            out_fn("[!] 'codex' no encontrado en PATH. Instalá Codex CLI e iniciá sesión con ChatGPT.")
            return False

    if provider == "opencode":
        # Do not auto-approve tools in the legacy orchestration path.
        cmd = ["opencode", "run", "--format", "json"]
        if model:
            cmd.extend(["--model", model])
        cmd.append(system_prompt + "\n\n--- Tarea ---\n" + prompt)
        try:
            return _run_plain_command(agent_name, cmd, env, effective_timeout, verbose, out_fn=out_fn)
        except FileNotFoundError:
            out_fn("[!] 'opencode' no encontrado en PATH.")
            return False

    # Claude Code CLI: stream-json permite capturar el texto y consumo.
    # La flag verbose del orquestador controla solo qué se imprime.
    max_turns = AGENT_MAX_TURNS.get(agent_name, 30)
    cmd = [
        "claude", "-p", prompt,
        "--append-system-prompt", system_prompt,
        "--output-format", "stream-json",
        "--verbose",
        "--max-turns", str(max_turns),
    ]

    try:
        return _run_streaming(agent_name, cmd, env, effective_timeout, verbose, out_fn=out_fn)
    except FileNotFoundError:
        out_fn("[!] 'claude' no encontrado en PATH. ¿Está instalado Claude Code?")
        return False


def _run_plain_command(agent_name: str, cmd: list, env: dict, timeout: int, verbose: bool, out_fn=None) -> bool:
    if out_fn is None:
        out_fn = print
    try:
        proc = subprocess.Popen(cmd, cwd=str(MULDERX_ROOT), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=env, text=True, bufsize=1)
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        out_fn(f"[!] {agent_name} superó el timeout de {timeout}s")
        return False
    if stdout.strip():
        out_fn(stdout.strip() if verbose else stdout.strip()[-2000:])
    if proc.returncode:
        out_fn(f"[!] {agent_name} terminó con error (código {proc.returncode})")
        if stderr:
            out_fn(stderr[:1000])
        return False
    return True


def _run_streaming(
    agent_name: str,
    cmd: list,
    env: dict,
    timeout: int,
    verbose: bool = False,
    out_fn=None,
) -> bool:
    """
    Corre el agente con stream-json.
    - Siempre captura y loguea tokens del evento 'result'.
    - verbose=True imprime tool calls y texto del agente en tiempo real.
    - out_fn permite redirigir output (ej: printer prefijado para runs paralelos).
    """
    if out_fn is None:
        out_fn = print

    start = time.time()
    proc = subprocess.Popen(
        cmd,
        cwd=str(MULDERX_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=True,
        bufsize=1,
    )

    success = True
    try:
        for line in proc.stdout:
            if time.time() - start > timeout:
                proc.kill()
                out_fn(f"\n[!] {agent_name} superó el timeout de {timeout}s")
                return False

            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                if verbose:
                    out_fn(line)
                continue

            etype = event.get("type", "")

            if etype == "assistant" and verbose:
                for block in event.get("message", {}).get("content", []):
                    btype = block.get("type", "")
                    if btype == "text":
                        text = block.get("text", "").strip()
                        if text:
                            out_fn(f"\n[agent] {text}")
                    elif btype == "tool_use":
                        tool_name = block.get("name", "?")
                        inp = block.get("input", {})
                        if tool_name == "Bash":
                            out_fn(f"\n[tool] Bash: {inp.get('command', '')[:120]}")
                        elif tool_name in ("Read", "Write"):
                            fp = inp.get("file_path", inp.get("path", "?"))
                            out_fn(f"\n[tool] {tool_name}: {fp}")
                        else:
                            out_fn(f"\n[tool] {tool_name}: {str(inp)[:120]}")

            elif etype == "tool_result" and verbose:
                content = event.get("content", "")
                if isinstance(content, list):
                    for c in content:
                        if c.get("type") == "text":
                            snippet = c.get("text", "")[:200].replace("\n", " ")
                            out_fn(f"       → {snippet}")
                elif isinstance(content, str):
                    snippet = content[:200].replace("\n", " ")
                    out_fn(f"       → {snippet}")

            elif etype == "result":
                if event.get("subtype") == "error":
                    out_fn(f"\n[!] Error del agente: {event.get('error', '')}")
                    success = False
                usage = event.get("usage", {})
                if usage:
                    SESSION_TOKENS[agent_name] = usage
                    _print_token_line(agent_name, usage, out_fn=out_fn)

        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
        out_fn(f"\n[!] {agent_name} superó el timeout de {timeout}s")
        return False

    if proc.returncode != 0:
        stderr_out = proc.stderr.read()[:500] if proc.stderr else ""
        out_fn(f"\n[!] {agent_name} terminó con error (código {proc.returncode})")
        if stderr_out:
            out_fn(f"    stderr: {stderr_out}")
        return False

    if success:
        out_fn(f"[+] {agent_name} completado.")
    return success


def run_parallel_agents(
    agents: list[tuple[str, str]],
    timeout: int | None = None,
    verbose: bool = False,
    extra_env: dict | None = None,
    provider: str = "claude",
    model: str | None = None,
) -> dict[str, bool]:
    """
    Corre múltiples agentes en paralelo con output prefijado y thread-safe.
    Devuelve {agent_name: bool} con el resultado de cada uno.
    """
    names = [name for name, _ in agents]
    if not agents:
        return {}
    if len(set(names)) != len(names):
        raise ValueError("La lista de agentes no puede contener nombres duplicados.")
    if len(agents) > MAX_PARALLEL_AGENTS:
        raise ValueError(f"Máximo de agentes paralelos: {MAX_PARALLEL_AGENTS}.")
    if timeout is not None and timeout <= 0:
        raise ValueError("El timeout debe ser un entero positivo.")
    print(f"\n{'─'*60}")
    print(f"[*] Paralelo: {' + '.join(names)}")
    print(f"{'─'*60}")

    results: dict[str, bool] = {}

    with ThreadPoolExecutor(max_workers=min(len(agents), MAX_PARALLEL_AGENTS)) as executor:
        futures = {
            executor.submit(
                run_agent,
                name,
                prompt,
                timeout,
                verbose,
                extra_env,
                _make_prefixed_printer(f"[{name}] "),
                provider,
                model,
            ): name
            for name, prompt in agents
        }
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                results[name] = fut.result()
            except Exception as exc:
                print(f"[!] {name} lanzó excepción inesperada: {exc}")
                results[name] = False

    for name, ok in results.items():
        status = "completado" if ok else "FALLÓ"
        print(f"[{'+'  if ok else '!'}] {name}: {status}")

    return results


def wait_for_operator(file_path: str) -> bool:
    print(f"\n{'='*60}")
    print(f"[PAUSA OBLIGATORIA]")
    print(f"Revisá el archivo antes de continuar: {file_path}")
    print(f"{'='*60}")
    resp = input("¿Continuar? (s/n): ").strip().lower()
    return resp == "s"


def file_has_content(path: Path, min_bytes: int = 200) -> bool:
    return path.exists() and path.stat().st_size > min_bytes


def main():
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description="Mulderx Orchestrator")
    parser.add_argument("target",   help="Target (ej: target.com  o  *.target.com)")
    parser.add_argument("programa", help="Nombre del programa (ej: mercadolibre)")
    parser.add_argument(
        "--scope",
        choices=["wildcard", "domain"],
        default="domain",
        help="Tipo de scope: wildcard (*.target.com) o domain (app.target.com)"
    )
    parser.add_argument(
        "--provider",
        choices=["claude", "codex", "openai", "opencode"],
        default="claude",
        help="Runtime del agente (OpenAI API solo soporta análisis de archivos).",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Modelo (OpenAI: default gpt-6-astra; OpenCode: provider/model).",
    )
    parser.add_argument(
        "--yes", "-y",
        action="store_true",
        help="Saltear confirmación interactiva de autorización"
    )
    parser.add_argument(
        "--agent",
        choices=["recon", "summarizer", "triage", "cve-scanner", "cve-exploit", "exploit-client", "business-logic", "xss"],
        default=None,
        help="Correr solo este agente en vez de la secuencia completa"
    )
    parser.add_argument(
        "--timeout", "-t",
        type=int,
        default=None,
        help="Override de timeout en segundos (default: por agente, recon=3600)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Mostrar tool calls y texto del agente en tiempo real"
    )
    parser.add_argument(
        "--creds-file",
        default=None,
        metavar="NOMBRE",
        help="Nombre del .env en .credentials/ (sin extensión). Default: igual al programa."
    )
    parser.add_argument(
        "--no-creds",
        action="store_true",
        help="No cargar credenciales desde .credentials/"
    )
    args = parser.parse_args()

    if args.timeout is not None and args.timeout <= 0:
        parser.error("--timeout debe ser un entero positivo.")

    if args.provider == "openai" and not args.agent:
        parser.error("--provider openai requiere --agent summarizer, triage o business-logic; la API no ejecuta comandos externos.")
    if args.provider == "openai" and args.agent not in {"summarizer", "triage", "business-logic"}:
        parser.error("OpenAI API solo admite por ahora --agent summarizer, triage o business-logic.")

    try:
        domain, is_wildcard = parse_orchestrator_target(args.target, args.scope)
        programa = validate_program_name(args.programa)
    except ScopeError as exc:
        parser.error(str(exc))
    args.target = f"*.{domain}" if is_wildcard else domain
    args.programa = programa

    # ── Credenciales ─────────────────────────────────────────────
    creds, creds_file, usage_block = {}, None, ""
    if not args.no_creds:
        creds_lookup = args.creds_file or args.programa
        creds, creds_file, usage_block = load_credentials(creds_lookup)
        if creds_file:
            has_usage = "con bloque [USAGE]" if usage_block else "sin bloque [USAGE]"
            print(f"[+] Credenciales cargadas: .credentials/{creds_file} ({len(creds)} vars, {has_usage})")
        else:
            print(f"[~] Sin credenciales para '{args.programa}' en .credentials/")

    creds_note = format_creds_for_prompt(creds, creds_file, usage_block) if creds else ""

    p = args.programa

    print(f"\n{'='*60}")
    print(f"  MULDERX ORCHESTRATOR")
    print(f"  Target:   {args.target}")
    print(f"  Programa: {args.programa}")
    print(f"  Scope:    {args.scope}")
    print(f"  Provider: {args.provider}{' / ' + args.model if args.model else ''}")
    print(f"  Verbose:  {'sí' if args.verbose else 'no'}")
    if args.agent:
        print(f"  Agente:   {args.agent} (modo single)")
    if args.timeout:
        print(f"  Timeout:  {args.timeout}s (override)")
    print(f"{'='*60}\n")

    print(f"[!] Vas a correr testing activo contra: {args.target}")
    if args.yes:
        print("[*] Autorización confirmada con --yes.")
    else:
        confirm = input("¿El target está autorizado en el programa? (s/n): ").strip().lower()
        if confirm != "s":
            print("[*] Abortado por el operador.")
            sys.exit(0)

    target_dir = TARGETS_DIR / programa
    target_dir.mkdir(parents=True, exist_ok=True)

    # ── Construcción de prompts ──────────────────────────────────
    katana_regex = build_katana_regex(args.target, args.scope)

    prompts = {
        "recon": (
            f"Target: {args.target}. Dominio raíz: {domain}. Scope: {args.scope}. "
            f"Katana regex para -mr: '{katana_regex}'. "
            f"Realizá recon completo y escribí el output en targets/{p}/recon.md"
            + creds_note
        ),
        "summarizer": (
            f"Leé targets/{p}/recon.md en su totalidad. "
            f"Extraé solo las señales de seguridad relevantes, descartando ruido "
            f"de outputs de herramientas. Escribí el output compacto en "
            f"targets/{p}/recon_summary.md siguiendo las instrucciones de tu CLAUDE.md."
        ),
        "triage": (
            f"Leé targets/{p}/recon_summary.md (si no existe, usá targets/{p}/recon.md). "
            f"Clasificá las señales observables, "
            f"identificá vectores a trabajar y escribí el output en targets/{p}/triage.md"
            + creds_note
        ),
        "cve-scanner": (
            f"Leé targets/{p}/recon_summary.md (si no existe, usá targets/{p}/recon.md). "
            f"Identificá el stack tecnológico y "
            f"buscá CVEs relevantes para cada componente. "
            f"Escribí el output en targets/{p}/cves.md"
        ),
        "cve-exploit": (
            f"Leé targets/{p}/recon_summary.md (si no existe, usá targets/{p}/recon.md) "
            f"para contexto del target. "
            f"Después leé targets/{p}/cves.md. Para cada CVE en estado LISTO, "
            f"PENDIENTE-SIN-DATOS o PENDIENTE-SIN-VERSIÓN, buscá PoC pública o armá una. "
            f"Documentá todo en targets/{p}/cve_pocs.md. "
            f"NO ejecutes ningún exploit — documentá y para."
        ),
        "business-logic": (
            f"Leé targets/{p}/recon_summary.md (si no existe, usá targets/{p}/recon.md) "
            f"y targets/{p}/triage.md. "
            f"Identificá flujos de lógica de negocio: precios, roles, estados, "
            f"flujos multi-step. Escribí candidatos en targets/{p}/business_logic.md"
            + creds_note
        ),
        "exploit-client": (
            f"Leé targets/{p}/triage.md y targets/{p}/recon_summary.md "
            f"(si recon_summary.md no existe, usá targets/{p}/recon.md). "
            f"Trabajá los vectores client-side según la metodología de tu CLAUDE.md. "
            f"Escribí findings en targets/{p}/exploit_client.md"
            + creds_note
        ),
        "xss": (
            f"Target autorizado: {args.target}. Programa: {p}. Scope declarado: {args.scope}. "
            f"Trabajá el caso y los endpoints concretos entregados por el operador. "
            f"No leas context.md, triage.md, surface_checklist.md ni leads por defecto. "
            f"Usá Playwright MCP para abrir la página in-scope y verificar la ejecución "
            f"del candidato en navegador cuando la herramienta esté disponible; no declares "
            f"confirmación si no observaste ejecución real. Si no se entregó una ruta o "
            f"parámetro concreto, empezá por la página indicada y limitá la exploración. "
            f"Escribí resultados en "
            f"targets/{p}/exploit_xss.md. No inventes evidencia ni ejecutes fuera del scope."
            + creds_note
        ),
        "exploit-server": (
            f"Leé targets/{p}/triage.md y targets/{p}/recon_summary.md "
            f"(si recon_summary.md no existe, usá targets/{p}/recon.md). "
            f"Trabajá vectores server-side: SSRF, XXE, injection, deserialización. "
            f"Escribí findings en targets/{p}/exploit_server.md"
            + creds_note
        ),
        "documentador": (
            f"Leé todos los archivos en targets/{p}/. "
            f"Consolidá los findings en targets/{p}/leads.md "
            f"y escribí el estado de sesión en targets/{p}/handoff.md"
        ),
    }

    run_kwargs = dict(
        timeout=args.timeout,
        verbose=args.verbose,
        extra_env=creds if creds else None,
        provider=args.provider,
        model=args.model,
    )

    # ── Modo single-agent ────────────────────────────────────────
    if args.agent:
        run_agent(args.agent, prompts[args.agent], **run_kwargs)
        print_session_token_summary()
        sys.exit(0)

    # ── FASE 1: RECON ────────────────────────────────────────────
    run_agent("recon", prompts["recon"], **run_kwargs)

    # ── FASE 1.5: SUMMARIZER ─────────────────────────────────────
    summarizer_ok = run_agent("summarizer", prompts["summarizer"], **run_kwargs)
    if not summarizer_ok:
        print("[!] Summarizer falló — triage y cve-scanner usarán recon.md como fallback.")

    # ── FASE 2+3: TRIAGE y CVE-SCANNER en paralelo ───────────────
    run_parallel_agents(
        [("triage", prompts["triage"]), ("cve-scanner", prompts["cve-scanner"])],
        **run_kwargs,
    )

    # ── FASE 4: CVE EXPLOIT (con pausa) ─────────────────────────
    if file_has_content(target_dir / "cves.md"):
        run_agent("cve-exploit", prompts["cve-exploit"], **run_kwargs)
        wait_for_operator(f"targets/{p}/cve_pocs.md")
    else:
        print("[*] cves.md vacío o inexistente — saltando CVE Exploit.")

    # ── FASE 5: LÓGICA DE NEGOCIO ────────────────────────────────
    run_agent("business-logic", prompts["business-logic"], **run_kwargs)

    # ── FASE 6: EXPLOIT (según orden) ───────────────────────────
    # exploit-server está pendiente — no tiene CLAUDE.md todavía.
    # Por ahora solo corre exploit-client en ambos órdenes.
    run_agent("exploit-client", prompts["exploit-client"], **run_kwargs)
    # run_agent("exploit-server", prompts["exploit-server"], **run_kwargs)

    # ── FASE 7: DOCUMENTADOR ─────────────────────────────────────
    # run_agent("documentador", prompts["documentador"], **run_kwargs)

    print(f"\n{'='*60}")
    print(f"[+] Sesión completada.")
    print(f"    Client-side:   targets/{p}/exploit_client.md")
    print(f"    CVE PoCs:      targets/{p}/cve_pocs.md")
    print(f"    Leads activos: targets/{p}/leads.md  (si existía de sesión previa)")
    print(f"{'='*60}\n")

    print_session_token_summary()


if __name__ == "__main__":
    main()
