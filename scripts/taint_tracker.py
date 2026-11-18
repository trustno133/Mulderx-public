#!/usr/bin/env python3
"""
taint_tracker.py v1 — Regex-based taint tracker for minified JS.

Traces data flow from user-controlled sources to dangerous sinks.
Works on single-file minified JS without a full AST parser.

Limitations:
  - Single-letter variables in minified code produce false positives.
  - Does not understand control flow (if/else, loops).
  - Does not cross module boundaries.
  - Use results as a ranked candidate list, not confirmed findings.

Usage:
  taint_tracker.py <file.js> [options]

Exit codes:
  0  tainted paths found
  1  no tainted paths found
  2  error
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ── Sources — user-controlled input ──────────────────────────────────────────

SOURCES: list[tuple[str, str]] = [
    ("url_search",   r"location\.search|location\.hash|URLSearchParams\b"),
    ("url_href",     r"location\.href(?!\s*=)"),
    ("storage",      r"localStorage\.getItem\s*\(|sessionStorage\.getItem\s*\("),
    ("postmessage",  r"\be\.data\b|\bevent\.data\b|\bmsg\.data\b|\bdata\.data\b"),
    ("cookie_read",  r"document\.cookie(?!\s*=)"),
    ("xhr_response", r"\.responseText\b|\.responseJSON\b|\.response(?!T|J|\w)"),
    ("fetch_result", r"\bfetch\s*\(|\baxios\s*[\.(]"),
    ("json_parse",   r"JSON\.parse\s*\("),
    ("decode",       r"decodeURIComponent\s*\(|decodeURI\s*\(|\batob\s*\("),
    ("window_name",  r"\bwindow\.name\b|document\.referrer\b"),
    ("dom_value",    r"\.value(?!\w)|\.textContent\b|\.innerText\b"),
]

SOURCE_RE = re.compile(
    "|".join(f"(?P<src_{i}_{name.replace('-','_')}>{pat})"
             for i, (name, pat) in enumerate(SOURCES)),
    re.DOTALL,
)

# ── Sinks — dangerous operations ─────────────────────────────────────────────

@dataclass
class SinkDef:
    name:       str
    pattern:    str
    arg_index:  int   # which argument (0-based) is the dangerous one; -1 = RHS of =
    rhs:        bool  # True → sink is an assignment (=), False → function call

SINK_DEFS: list[SinkDef] = [
    SinkDef("innerHTML",          r"\.innerHTML\s*=",                          0,  True),
    SinkDef("outerHTML",          r"\.outerHTML\s*=",                          0,  True),
    SinkDef("insertAdjacentHTML", r"\.insertAdjacentHTML\s*\(",                1,  False),
    SinkDef("document.write",     r"\bdocument\.write\s*\(",                   0,  False),
    SinkDef("eval",               r"\beval\s*\(",                              0,  False),
    SinkDef("Function",           r"\bnew\s+Function\s*\(",                    0,  False),
    SinkDef("location.href",      r"\blocation\.href\s*=",                     0,  True),
    SinkDef("location.replace",   r"\blocation\.(?:replace|assign)\s*\(",      0,  False),
    SinkDef("cookie_write",       r"\bdocument\.cookie\s*=",                   0,  True),
    SinkDef("object_assign",      r"\bObject\.assign\s*\(",                    1,  False),
    SinkDef("jquery_html",        r"\.html\s*\(",                              0,  False),
    SinkDef("script_src",         r"\.src\s*=",                                0,  True),
    SinkDef("setTimeout_str",     r"\bsetTimeout\s*\(",                        0,  False),
    SinkDef("setInterval_str",    r"\bsetInterval\s*\(",                       0,  False),
]

# ── Extraction helpers ────────────────────────────────────────────────────────

_IDENT = r"[A-Za-z_$][A-Za-z0-9_$]*"
_ASSIGN_RE = re.compile(
    rf"(?:var|let|const)\s+({_IDENT})\s*=\s*|({_IDENT})\s*="
)
_STRING_RE = re.compile(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'|`(?:[^`\\]|\\.)*`')


def _strip_strings(s: str) -> str:
    """Replace string literals with placeholders to avoid false matches."""
    return _STRING_RE.sub('""', s)


def extract_rhs(code: str, sink_end: int, window: int = 800) -> str:
    """
    Extract the RHS expression after a sink `=` or the first arg of a call.
    Returns a short snippet (up to 120 chars).
    """
    chunk = code[sink_end: sink_end + window]
    # strip to first semicolon or balanced paren close at depth 0
    result: list[str] = []
    depth = 0
    for ch in chunk:
        if ch in "({[":
            depth += 1
        elif ch in ")}]":
            if depth == 0:
                break
            depth -= 1
        elif ch == ";" and depth == 0:
            break
        result.append(ch)
    return "".join(result).strip()[:200]


def extract_call_arg(code: str, call_start: int, arg_index: int) -> str:
    """
    Extract the N-th argument (0-based) from a function call.
    call_start is the position of the opening '(' of the call.
    """
    pos = call_start
    if pos >= len(code) or code[pos] != "(":
        return ""
    pos += 1
    current_arg: list[str] = []
    arg_num = 0
    depth = 0
    in_str = False
    str_char = ""

    while pos < len(code):
        ch = code[pos]
        if in_str:
            if ch == "\\" :
                pos += 1
            elif ch == str_char:
                in_str = False
            current_arg.append(ch)
        else:
            if ch in ('"', "'", "`"):
                in_str = True
                str_char = ch
                current_arg.append(ch)
            elif ch in "({[":
                depth += 1
                current_arg.append(ch)
            elif ch in ")}]":
                if depth == 0:
                    break
                depth -= 1
                current_arg.append(ch)
            elif ch == "," and depth == 0:
                if arg_num == arg_index:
                    return "".join(current_arg).strip()[:200]
                arg_num += 1
                current_arg = []
                pos += 1
                continue
            else:
                current_arg.append(ch)
        pos += 1

    if arg_num == arg_index:
        return "".join(current_arg).strip()[:200]
    return ""


def extract_identifiers(expr: str) -> list[str]:
    """
    Pull out all identifiers from an expression, excluding JS keywords and
    very short single-letter ones (too ambiguous in minified code).
    """
    keywords = {
        "var","let","const","function","return","if","else","for","while",
        "do","switch","case","break","continue","new","typeof","instanceof",
        "void","delete","in","of","true","false","null","undefined",
        "this","class","extends","super","import","export","default",
        "try","catch","finally","throw","async","await","yield",
    }
    clean = _strip_strings(expr)
    idents = re.findall(rf"\b({_IDENT})\b", clean)
    # keep identifiers > 1 char unless they look like meaningful names
    return [i for i in idents
            if i not in keywords and (len(i) > 1 or i in ("$",))]


def find_last_assignment(code: str, var_name: str, before: int,
                          window: int = 3000) -> Optional[str]:
    """
    Find the last assignment to `var_name` before position `before`
    within `window` bytes. Returns the RHS snippet or None.
    """
    start = max(0, before - window)
    chunk = code[start:before]
    # match: var/let/const x = ... OR x = ... (not ==, !=, <=, >=, ===, !==)
    pat = re.compile(
        rf"(?:var|let|const)\s+{re.escape(var_name)}\s*=\s*([^;{{]*)|"
        rf"(?<![=!<>]){re.escape(var_name)}\s*=(?!=)\s*([^;{{]*)"
    )
    matches = list(pat.finditer(chunk))
    if not matches:
        return None
    last = matches[-1]
    rhs = (last.group(1) or last.group(2) or "").strip()
    return rhs[:200] if rhs else None


# ── Taint analysis ────────────────────────────────────────────────────────────

@dataclass
class TaintChain:
    sink_name:   str
    sink_offset: int
    sink_snippet: str
    initial_expr: str
    hops:        list[tuple[str, str]] = field(default_factory=list)  # (var, rhs)
    source_name: Optional[str] = None
    source_snippet: Optional[str] = None
    confidence:  str = "low"  # low / medium / high


def source_match(expr: str) -> Optional[tuple[str, str]]:
    """Return (source_name, matched_snippet) if expr contains a tainted source."""
    m = SOURCE_RE.search(expr)
    if not m:
        return None
    # find which group matched
    for key, val in m.groupdict().items():
        if val is not None:
            # key is like "src_0_url_search"
            parts = key.split("_", 2)
            name = parts[2] if len(parts) >= 3 else key
            return name, val
    return None


def trace(code: str, sink: SinkDef, sink_match: re.Match,
          max_hops: int = 5) -> Optional[TaintChain]:
    """
    Attempt to trace taint from a sink occurrence back to a source.
    Returns a TaintChain if a tainted source is reachable, else None.
    """
    offset = sink_match.start()
    end    = sink_match.end()

    # Extract the dangerous expression
    if sink.rhs:
        expr = extract_rhs(code, end)
    else:
        # find opening paren of call
        paren_pos = code.find("(", end - 1)
        if paren_pos < 0:
            return None
        expr = extract_call_arg(code, paren_pos, sink.arg_index)

    if not expr:
        return None

    sink_ctx = code[max(0, offset - 60): end + 80].replace("\n", " ").strip()
    chain = TaintChain(
        sink_name    = sink.name,
        sink_offset  = offset,
        sink_snippet = sink_ctx[:200],
        initial_expr = expr,
    )

    # Immediate source check
    hit = source_match(expr)
    if hit:
        chain.source_name    = hit[0]
        chain.source_snippet = hit[1]
        chain.confidence     = "high"
        return chain

    # Hop-based backward trace
    frontier = extract_identifiers(expr)
    visited:  set[str] = set()

    for hop in range(max_hops):
        if not frontier:
            break
        next_frontier: list[str] = []
        for var in frontier:
            if var in visited:
                continue
            visited.add(var)
            rhs = find_last_assignment(code, var, offset)
            if rhs is None:
                continue
            chain.hops.append((var, rhs))
            hit = source_match(rhs)
            if hit:
                chain.source_name    = hit[0]
                chain.source_snippet = hit[1]
                chain.confidence     = "high" if hop == 0 else "medium" if hop < 3 else "low"
                return chain
            next_frontier.extend(extract_identifiers(rhs))
        frontier = [v for v in next_frontier if v not in visited]

    return None


# ── Sink scanning ─────────────────────────────────────────────────────────────

def scan(code: str, sink_defs: list[SinkDef], max_hops: int,
         min_confidence: str) -> list[TaintChain]:
    conf_order = {"low": 0, "medium": 1, "high": 2}
    min_conf_val = conf_order.get(min_confidence, 0)
    results: list[TaintChain] = []

    for sink in sink_defs:
        pat = re.compile(sink.pattern)
        for m in pat.finditer(code):
            chain = trace(code, sink, m, max_hops)
            if chain and conf_order.get(chain.confidence, 0) >= min_conf_val:
                results.append(chain)

    results.sort(key=lambda c: -{"high": 2, "medium": 1, "low": 0}.get(c.confidence, 0))
    return results


# ── Output ────────────────────────────────────────────────────────────────────

class C:
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    GREEN  = "\033[92m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

    @classmethod
    def off(cls) -> None:
        for a in ("RED","YELLOW","CYAN","GREEN","BOLD","DIM","RESET"):
            setattr(cls, a, "")


CONF_COLOR = {"high": "RED", "medium": "YELLOW", "low": "CYAN"}


def print_text(results: list[TaintChain], filepath: str) -> None:
    W = 72
    h = sum(1 for r in results if r.confidence == "high")
    m = sum(1 for r in results if r.confidence == "medium")
    l = sum(1 for r in results if r.confidence == "low")

    print(f"\n{'═'*W}")
    print(f"  {C.BOLD}TAINT TRACKER — {Path(filepath).name}{C.RESET}")
    print(f"  {C.RED}HIGH={h}{C.RESET}  {C.YELLOW}MEDIUM={m}{C.RESET}  {C.CYAN}LOW={l}{C.RESET}  "
          f"total={len(results)}")
    print(f"{'═'*W}\n")

    if not results:
        print(f"  {C.DIM}No tainted paths found.{C.RESET}\n")
        return

    for i, r in enumerate(results, 1):
        col = getattr(C, CONF_COLOR.get(r.confidence, "CYAN"))
        print(f"  [{i}] {col}{r.confidence.upper()}{C.RESET}  "
              f"{C.BOLD}{r.sink_name}{C.RESET}  @byte {r.sink_offset:,}")
        print(f"       source: {C.GREEN}{r.source_name}{C.RESET}  "
              f"({r.source_snippet})")
        print(f"       sink:   {C.DIM}{r.sink_snippet[:100]}{C.RESET}")
        if r.initial_expr:
            print(f"       expr:   {r.initial_expr[:100]}")
        if r.hops:
            print(f"       chain ({len(r.hops)} hops):")
            for var, rhs in r.hops:
                print(f"         {var} = {rhs[:80]}")
        print()

    print(f"{'═'*W}\n")


def print_json_out(results: list[TaintChain], filepath: str) -> None:
    out = {
        "file": filepath,
        "total": len(results),
        "counts": {
            "high":   sum(1 for r in results if r.confidence == "high"),
            "medium": sum(1 for r in results if r.confidence == "medium"),
            "low":    sum(1 for r in results if r.confidence == "low"),
        },
        "paths": [
            {
                "sink":           r.sink_name,
                "offset":         r.sink_offset,
                "sink_snippet":   r.sink_snippet,
                "initial_expr":   r.initial_expr,
                "hops":           [{"var": v, "rhs": rhs} for v, rhs in r.hops],
                "source":         r.source_name,
                "source_snippet": r.source_snippet,
                "confidence":     r.confidence,
            }
            for r in results
        ],
    }
    print(json.dumps(out, indent=2))


# ── CLI ──────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(
        description="taint_tracker.py v1 — regex-based JS taint analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python3 taint_tracker.py modules/6Qj8q.js --scope object_assign,innerHTML
  python3 taint_tracker.py bundle.js --hops 6 --confidence medium --json
  python3 taint_tracker.py bundle.js --list-sinks
""",
    )
    ap.add_argument("file",          help="JS file to analyze")
    ap.add_argument("--scope", "-s", default=None, metavar="SINKS",
                    help="Comma-separated list of sink names to check (default: all). "
                         "Use --list-sinks to see available names.")
    ap.add_argument("--hops",        type=int, default=5,
                    help="Max backward hops per chain (default: 5)")
    ap.add_argument("--confidence",  default="low",
                    choices=["low", "medium", "high"],
                    help="Minimum confidence to report (default: low)")
    ap.add_argument("--json",        action="store_true", dest="output_json")
    ap.add_argument("--no-color",    action="store_true")
    ap.add_argument("--list-sinks",  action="store_true",
                    help="Print available sink names and exit")
    args = ap.parse_args()

    if args.list_sinks:
        print("Available sinks:")
        for s in SINK_DEFS:
            print(f"  {s.name:<25}  {s.pattern}")
        print("\nAvailable sources:")
        for name, pat in SOURCES:
            print(f"  {name:<20}  {pat}")
        sys.exit(0)

    if args.no_color:
        C.off()

    path = Path(args.file)
    if not path.exists():
        print(f"[error] File not found: {path}", file=sys.stderr)
        sys.exit(2)

    code = path.read_text("utf-8", errors="replace")
    print(f"[*] {path.name}  {len(code):,} chars", file=sys.stderr)

    # Filter sinks
    active_sinks = SINK_DEFS
    if args.scope:
        names = {s.strip() for s in args.scope.split(",")}
        active_sinks = [s for s in SINK_DEFS if s.name in names]
        if not active_sinks:
            print(f"[!] No matching sinks for: {args.scope}", file=sys.stderr)
            sys.exit(2)
    print(f"[*] Checking {len(active_sinks)} sink(s), max {args.hops} hops, "
          f"min confidence={args.confidence}", file=sys.stderr)

    results = scan(code, active_sinks, args.hops, args.confidence)
    print(f"[*] {len(results)} tainted path(s) found", file=sys.stderr)

    if args.output_json:
        print_json_out(results, str(path))
    else:
        print_text(results, str(path))

    sys.exit(0 if results else 1)


if __name__ == "__main__":
    main()
