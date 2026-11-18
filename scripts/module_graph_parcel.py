#!/usr/bin/env python3
"""
module_graph_parcel.py v1 — Parcel 1 bundle dependency graph reconstructor.

Parcel 1 IIFE format:
  !function(modules, cache, entry, globalName, publicURL) { runtime }
  ({moduleMap}, {}, [entryIds], "parcelRequire<hash>", "")

No external dependencies — stdlib Python 3.10+ only.

Usage:
  module_graph_parcel.py bundle.js [--json] [--dot] [--analyzer-json FILE]

Exit codes:
  0  success
  1  file not found / I/O error
  2  format not supported (not Parcel 1)
"""

from __future__ import annotations

import argparse
import json
import mmap
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

_10MB = 10 * 1_048_576

_MAP_OPEN_RE = re.compile(rb"\}\s*\(\s*\{")
_PARCEL_REQUIRE_BYTES = b"parcelRequire"


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass
class ParcelModule:
    module_id: str
    label: Optional[str]            # readable path when ID contains '/' or '.js'
    start_byte: int                  # offset of opening '"' of key in bundle
    end_byte: int                    # offset after closing ']' of entry
    deps: list[str] = field(default_factory=list)
    dep_names: dict[str, str] = field(default_factory=dict)  # {require_name: dep_id}
    factory_body_start: int = -1     # first byte inside factory function '{'
    factory_body_end: int = -1       # byte of factory function closing '}'


# ---------------------------------------------------------------------------
# Scanner — works with both bytes and mmap.mmap (both return int on [i])
# ---------------------------------------------------------------------------


class Scanner:
    __slots__ = ("src", "pos", "end")

    def __init__(self, src, start: int = 0) -> None:
        self.src = src
        self.pos = start
        self.end = len(src)

    # --- whitespace / comments -------------------------------------------

    def skip_ws(self) -> None:
        s = self.src
        while self.pos < self.end and s[self.pos] in (9, 10, 13, 32):
            self.pos += 1

    def skip_ws_comments(self) -> None:
        s = self.src
        while self.pos < self.end:
            while self.pos < self.end and s[self.pos] in (9, 10, 13, 32):
                self.pos += 1
            if self.pos + 1 >= self.end:
                break
            a, b = s[self.pos], s[self.pos + 1]
            if a == 47 and b == 47:        # //
                self.pos += 2
                while self.pos < self.end and s[self.pos] != 10:
                    self.pos += 1
            elif a == 47 and b == 42:      # /*
                self.pos += 2
                while self.pos + 1 < self.end:
                    if s[self.pos] == 42 and s[self.pos + 1] == 47:
                        self.pos += 2
                        break
                    self.pos += 1
            else:
                break

    # --- identifier reading -----------------------------------------------

    def read_identifier(self) -> Optional[str]:
        """Read a bare JS identifier (unquoted key). pos must be at first char."""
        self.skip_ws_comments()
        s = self.src
        if self.pos >= self.end:
            return None
        c = s[self.pos]
        # identifiers start with letter, _ or $
        if not (65 <= c <= 90 or 97 <= c <= 122 or c == 95 or c == 36):
            return None
        buf: list[int] = []
        while self.pos < self.end:
            c = s[self.pos]
            if (65 <= c <= 90 or 97 <= c <= 122 or 48 <= c <= 57 or c == 95 or c == 36):
                buf.append(c)
                self.pos += 1
            else:
                break
        return bytes(buf).decode("utf-8") if buf else None

    def read_key(self) -> Optional[str]:
        """Read a JS object key — quoted string OR bare identifier."""
        self.skip_ws_comments()
        if self.pos >= self.end:
            return None
        c = self.src[self.pos]
        if c in (34, 39):
            return self.read_string()
        return self.read_identifier()

    # --- string reading ---------------------------------------------------

    def read_string(self) -> Optional[str]:
        """Read a JS quoted string. pos must be at the opening quote."""
        self.skip_ws_comments()
        s = self.src
        if self.pos >= self.end or s[self.pos] not in (34, 39):  # '"' | "'"
            return None
        q = s[self.pos]
        self.pos += 1
        buf: list[int] = []
        while self.pos < self.end:
            c = s[self.pos]
            if c == 92:   # backslash
                self.pos += 1
                if self.pos < self.end:
                    e = s[self.pos]
                    buf.append(10 if e == 110 else 9 if e == 116 else 13 if e == 114 else e)
                    self.pos += 1
            elif c == q:
                self.pos += 1
                return bytes(buf).decode("utf-8", errors="replace")
            else:
                buf.append(c)
                self.pos += 1
        return None

    # --- balanced skip ---------------------------------------------------

    def skip_balanced(self, open_ch: int, close_ch: int) -> bool:
        """Skip balanced brackets handling strings and comments."""
        s = self.src
        if self.pos >= self.end or s[self.pos] != open_ch:
            return False
        depth = 0
        while self.pos < self.end:
            c = s[self.pos]
            if c in (34, 39, 96):          # string / template literal
                q = c
                self.pos += 1
                while self.pos < self.end:
                    c2 = s[self.pos]
                    if c2 == 92:
                        self.pos += 2
                        continue
                    self.pos += 1
                    if c2 == q:
                        break
                continue
            if c == 47 and self.pos + 1 < self.end:
                nxt = s[self.pos + 1]
                if nxt == 47:
                    while self.pos < self.end and s[self.pos] != 10:
                        self.pos += 1
                    continue
                if nxt == 42:
                    self.pos += 2
                    while self.pos + 1 < self.end:
                        if s[self.pos] == 42 and s[self.pos + 1] == 47:
                            self.pos += 2
                            break
                        self.pos += 1
                    continue
            if c == open_ch:
                depth += 1
            elif c == close_ch:
                depth -= 1
                if depth == 0:
                    self.pos += 1
                    return True
            self.pos += 1
        return False

    # --- factory skip ---------------------------------------------------

    def skip_to_comma_depth0(self) -> None:
        """
        Scan forward tracking (), {}, [] and string depth.
        Stop when a ',' is found at all depths == 0.
        pos lands on the ',' (not past it).
        """
        s = self.src
        dp = db = dsq = 0
        in_s = False
        sq = 0
        while self.pos < self.end:
            c = s[self.pos]
            if in_s:
                if c == 92:
                    self.pos += 2
                    continue
                if c == sq:
                    in_s = False
            else:
                if c in (34, 39, 96):
                    in_s = True
                    sq = c
                elif c == 47 and self.pos + 1 < self.end:
                    nxt = s[self.pos + 1]
                    if nxt == 47:
                        while self.pos < self.end and s[self.pos] != 10:
                            self.pos += 1
                        continue
                    if nxt == 42:
                        self.pos += 2
                        while self.pos + 1 < self.end:
                            if s[self.pos] == 42 and s[self.pos + 1] == 47:
                                self.pos += 2
                                break
                            self.pos += 1
                        continue
                elif c == 40:   dp += 1
                elif c == 41:   dp -= 1
                elif c == 123:  db += 1
                elif c == 125:  db -= 1
                elif c == 91:   dsq += 1
                elif c == 93:   dsq -= 1
                elif c == 44 and dp == 0 and db == 0 and dsq == 0:
                    return      # pos is at ','
            self.pos += 1

    # --- dep map ---------------------------------------------------------

    def read_dep_map(self) -> dict[str, str]:
        """Parse {"require_name": "module_id", ...}. pos must be at '{'."""
        self.skip_ws_comments()
        s = self.src
        if self.pos >= self.end or s[self.pos] != 123:  # '{'
            return {}
        self.pos += 1
        result: dict[str, str] = {}
        while self.pos < self.end:
            self.skip_ws_comments()
            if self.pos >= self.end:
                break
            c = s[self.pos]
            if c == 125:                    # '}'
                self.pos += 1
                break
            if c == 44:                     # ','
                self.pos += 1
                continue
            if c in (34, 39) or (65 <= c <= 90 or 97 <= c <= 122 or c == 95 or c == 36):
                k = self.read_key()
                self.skip_ws_comments()
                if self.pos < self.end and s[self.pos] == 58:  # ':'
                    self.pos += 1
                v = self.read_key()
                if k is not None and v is not None:
                    result[k] = v
            else:
                # Unexpected — bail out by depth-scanning to matching '}'
                depth = 1
                self.pos += 1
                while self.pos < self.end and depth:
                    c2 = s[self.pos]
                    if c2 == 123:   depth += 1
                    elif c2 == 125: depth -= 1
                    self.pos += 1
                break
        return result


# ---------------------------------------------------------------------------
# Factory body extraction helper
# ---------------------------------------------------------------------------


def _extract_factory_body(sc: Scanner) -> tuple[int, int]:
    """
    sc.pos must be right after the '[' of a module entry, at the start of the
    factory expression.  Tries to locate the body of function(...){ ... }.
    Returns (body_start, body_end) as absolute byte offsets where body_start
    is the byte AFTER '{' and body_end is the byte OF the closing '}'.
    Returns (-1, -1) if not a recognizable function literal.
    Restores sc.pos on exit — caller must still call skip_to_comma_depth0().
    """
    saved = sc.pos
    sc.skip_ws_comments()
    s = sc.src

    # Must start with 'function'
    if sc.pos + 8 > sc.end:
        sc.pos = saved
        return -1, -1
    chunk = s[sc.pos : sc.pos + 8]
    if isinstance(chunk, memoryview):
        chunk = bytes(chunk)
    if chunk != b"function":
        sc.pos = saved
        return -1, -1

    sc.pos += 8
    sc.skip_ws_comments()

    # Skip optional function name (Parcel 1 factories are anonymous, but be safe)
    if sc.pos < sc.end:
        c = s[sc.pos]
        if 65 <= c <= 90 or 97 <= c <= 122 or c == 95 or c == 36:
            while sc.pos < sc.end:
                c2 = s[sc.pos]
                if not (65 <= c2 <= 90 or 97 <= c2 <= 122 or 48 <= c2 <= 57 or c2 == 95 or c2 == 36):
                    break
                sc.pos += 1

    sc.skip_ws_comments()
    # Skip parameter list
    if sc.pos < sc.end and s[sc.pos] == 40:   # '('
        sc.skip_balanced(40, 41)

    sc.skip_ws_comments()
    if sc.pos >= sc.end or s[sc.pos] != 123:  # '{'
        sc.pos = saved
        return -1, -1

    body_start = sc.pos + 1             # first byte inside '{'
    sc.skip_balanced(123, 125)
    body_end = sc.pos - 1               # byte of closing '}'

    sc.pos = saved                      # restore for caller
    return body_start, body_end


def enrich_labels_from_dep_names(modules: dict[str, "ParcelModule"]) -> None:
    """
    Modules with hash-style IDs (no label) may be referenced in other modules'
    dep_names with their real path as the require-name (e.g. '@parcel/...').
    Populate label from the first such path-like require-name found.
    """
    for mod in modules.values():
        if mod.label is not None:
            continue
        for importer in modules.values():
            for req_name, dep_id in importer.dep_names.items():
                if dep_id == mod.module_id and ("/" in req_name or "\\" in req_name):
                    mod.label = req_name
                    break
            if mod.label is not None:
                break


def _is_vendor(mod: ParcelModule) -> bool:
    """True if module is a Parcel/SWC internal that should not be extracted."""
    for s in (mod.label or "", mod.module_id):
        if "parcel/" in s or "@parcel/" in s or "@swc/" in s:
            return True
    return False


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------


def _window(src, size: int) -> bytes:
    chunk = src[:size]
    return chunk if isinstance(chunk, bytes) else bytes(chunk)


def is_parcel1(src) -> bool:
    if src.find(_PARCEL_REQUIRE_BYTES) < 0:
        return False
    header = _window(src, 8192)
    return bool(_MAP_OPEN_RE.search(header))


def find_map_start(src) -> int:
    """Return byte offset of the opening '{' of the module map, or -1."""
    for size in (8192, 65536):
        w = _window(src, min(size, len(src)))
        m = _MAP_OPEN_RE.search(w)
        if m:
            return m.end() - 1      # '{'  is always the last char of the match
    return -1


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def parse_module_map(src, map_start: int) -> tuple[dict[str, ParcelModule], int]:
    """
    Parse the Parcel 1 module map at map_start.
    Returns (modules, pos_after_closing_brace).
    Module byte offsets are absolute (relative to start of src).
    """
    sc = Scanner(src, map_start)
    modules: dict[str, ParcelModule] = {}

    if sc.pos >= sc.end or sc.src[sc.pos] != 123:  # '{'
        return modules, sc.pos
    sc.pos += 1

    while sc.pos < sc.end:
        sc.skip_ws_comments()
        if sc.pos >= sc.end:
            break
        c = sc.src[sc.pos]
        if c == 125:                                # '}' — end of map
            sc.pos += 1
            break
        if c == 44:                                 # ','
            sc.pos += 1
            continue
        if c not in (34, 39) and not (65 <= c <= 90 or 97 <= c <= 122 or c == 95 or c == 36):
            sc.pos += 1
            continue

        key_start = sc.pos
        mod_id = sc.read_key()
        if mod_id is None:
            sc.pos += 1
            continue

        sc.skip_ws_comments()
        if sc.pos < sc.end and sc.src[sc.pos] == 58:   # ':'
            sc.pos += 1
        sc.skip_ws_comments()

        if sc.pos >= sc.end or sc.src[sc.pos] != 91:   # '[' expected
            continue
        sc.pos += 1                                 # skip '['

        sc.skip_ws_comments()
        fb_start, fb_end = _extract_factory_body(sc)
        sc.skip_to_comma_depth0()                   # skip factory, land on ','
        if sc.pos < sc.end and sc.src[sc.pos] == 44:
            sc.pos += 1                             # skip ','

        deps_map = sc.read_dep_map()

        sc.skip_ws_comments()
        if sc.pos < sc.end and sc.src[sc.pos] == 93:   # ']'
            sc.pos += 1
        entry_end = sc.pos

        label: Optional[str] = (
            mod_id if ("/" in mod_id or "\\" in mod_id or mod_id.endswith(".js")) else None
        )

        modules[mod_id] = ParcelModule(
            module_id=mod_id,
            label=label,
            start_byte=key_start,
            end_byte=entry_end,
            deps=list(deps_map.values()),
            dep_names=deps_map,
            factory_body_start=fb_start,
            factory_body_end=fb_end,
        )

    return modules, sc.pos


def parse_call_tail(src, pos: int) -> tuple[list[str], str]:
    """
    Parse call args after the module map:
      , {cache}, [entryIds], "parcelRequireName", ...
    Returns (entry_ids, parcel_require_name).
    """
    sc = Scanner(src, pos)
    entry_ids: list[str] = []
    pr_name = ""

    sc.skip_ws_comments()
    if sc.pos < sc.end and sc.src[sc.pos] == 44:       # ','
        sc.pos += 1

    sc.skip_ws_comments()
    if sc.pos < sc.end and sc.src[sc.pos] == 123:      # skip cache {}
        sc.skip_balanced(123, 125)

    sc.skip_ws_comments()
    if sc.pos < sc.end and sc.src[sc.pos] == 44:       # ','
        sc.pos += 1

    sc.skip_ws_comments()
    if sc.pos < sc.end and sc.src[sc.pos] == 91:       # entry array '['
        sc.pos += 1
        while sc.pos < sc.end:
            sc.skip_ws_comments()
            c2 = sc.src[sc.pos] if sc.pos < sc.end else -1
            if c2 == 93: sc.pos += 1; break           # ']'
            if c2 == 44: sc.pos += 1; continue        # ','
            s = sc.read_string()
            if s is not None:
                entry_ids.append(s)
            else:
                sc.pos += 1

    sc.skip_ws_comments()
    if sc.pos < sc.end and sc.src[sc.pos] == 44:       # ','
        sc.pos += 1

    sc.skip_ws_comments()
    pn = sc.read_string()
    if pn:
        pr_name = pn

    return entry_ids, pr_name


# ---------------------------------------------------------------------------
# Graph (no networkx — stdlib only)
# ---------------------------------------------------------------------------


def build_graph(
    modules: dict[str, ParcelModule],
) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    out: dict[str, list[str]] = {m: [] for m in modules}
    ins: dict[str, list[str]] = {m: [] for m in modules}
    for mid, mod in modules.items():
        for dep in mod.deps:
            if dep not in out: out[dep] = []
            if dep not in ins: ins[dep] = []
            if dep not in out[mid]:    out[mid].append(dep)
            if mid not in ins[dep]:    ins[dep].append(mid)
    return out, ins


def find_orphans(
    modules: dict[str, ParcelModule],
    ins: dict[str, list[str]],
    entry_ids: list[str],
) -> list[str]:
    es = set(entry_ids)
    return sorted(m for m in modules if not ins.get(m) and m not in es)


# ---------------------------------------------------------------------------
# Analyzer JSON integration
# ---------------------------------------------------------------------------


def _normalize_findings(adata, bundle_name: str) -> list[dict]:
    """Extract a flat list of findings from various js_analyzer output shapes."""
    if isinstance(adata, list):
        return adata
    for key in ("findings", "matches", "results", "secrets"):
        v = adata.get(key)
        if isinstance(v, list):
            return v
    for key in (bundle_name,):
        v = adata.get(key)
        if isinstance(v, list):
            return v
    for v in adata.values():
        if isinstance(v, list) and v and isinstance(v[0], dict) and "offset" in v[0]:
            return v
    return []


def cross_analyzer_data(
    modules: dict[str, ParcelModule],
    adata: dict,
    bundle_name: str,
) -> tuple[dict[str, str], dict[str, list[dict]]]:
    """
    Returns:
      chunk_labels:  {module_id: label_str}
      sec_findings:  {module_id: [finding_dict, ...]}
    """
    sorted_mods = sorted(
        [(m.start_byte, m.end_byte, mid) for mid, m in modules.items()],
        key=lambda t: t[0],
    )

    def find_mod(offset: int) -> Optional[str]:
        lo, hi = 0, len(sorted_mods) - 1
        while lo <= hi:
            mi = (lo + hi) // 2
            s, e, fmid = sorted_mods[mi]
            if s <= offset < e:  return fmid
            elif offset < s:     hi = mi - 1
            else:                lo = mi + 1
        return None

    # Chunk labels from 'chunks' key (same format as module_graph.py)
    chunk_labels: dict[str, str] = {}
    for chunk in adata.get("chunks", []):
        label = chunk.get("label") or chunk.get("name", "")
        if not label:
            continue
        c_start, c_end = chunk.get("start", 0), chunk.get("end", 0)
        for mid, mod in modules.items():
            overlap = min(mod.end_byte, c_end) - max(mod.start_byte, c_start)
            if overlap > 0 and mid not in chunk_labels:
                chunk_labels[mid] = label

    # Security findings
    findings = _normalize_findings(adata, bundle_name)
    sec_findings: dict[str, list[dict]] = {m: [] for m in modules}
    for f in findings:
        offset = f.get("offset")
        if offset is None:
            continue
        mid = find_mod(offset)
        if mid:
            sec_findings[mid].append(f)

    return chunk_labels, sec_findings


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


def _display(mod: ParcelModule) -> str:
    return mod.label or mod.module_id


def print_text(
    modules: dict[str, ParcelModule],
    out: dict[str, list[str]],
    ins: dict[str, list[str]],
    entry_ids: list[str],
    orph: list[str],
    pr_name: str,
    chunk_labels: Optional[dict[str, str]],
    sec_findings: Optional[dict[str, list[dict]]],
) -> None:
    edge_count = sum(len(v) for v in out.values())
    print(f"\n[module_graph_parcel] {len(modules)} modules, {edge_count} edges  (parcel1)")
    print(f"[bundle] parcelRequire={pr_name!r}")

    if entry_ids:
        labels = [_display(modules[e]) if e in modules else e for e in entry_ids]
        print(f"[entry]  {', '.join(labels)}")
    else:
        print("[entry]  unknown (empty entry array)")

    if orph:
        shown = [_display(modules[o]) if o in modules else o for o in orph[:20]]
        suffix = " ..." if len(orph) > 20 else ""
        print(f"[orphans] {len(orph)} total: {', '.join(shown)}{suffix}")
    else:
        print("[orphans] none")

    print("\n[top 20 by out-degree — modules that import most]")
    for mid in sorted(modules, key=lambda m: -len(out.get(m, [])))[:20]:
        oc = len(out.get(mid, []))
        ic = len(ins.get(mid, []))
        cl = f"  [{chunk_labels[mid]}]" if chunk_labels and mid in chunk_labels else ""
        lb = f"  {modules[mid].label}" if modules[mid].label else ""
        print(f"  {mid:>10}  out={oc:3d}  in={ic:3d}{lb}{cl}")

    print("\n[top 20 by in-degree — most imported modules]")
    for mid in sorted(modules, key=lambda m: -len(ins.get(m, [])))[:20]:
        ic = len(ins.get(mid, []))
        oc = len(out.get(mid, []))
        cl = f"  [{chunk_labels[mid]}]" if chunk_labels and mid in chunk_labels else ""
        lb = f"  {modules[mid].label}" if modules[mid].label else ""
        print(f"  {mid:>10}  in={ic:3d}  out={oc:3d}{lb}{cl}")

    if sec_findings:
        hits = [(m, f) for m, f in sec_findings.items() if f]
        if hits:
            print("\n[security findings by module]")
            for mid, flist in sorted(hits, key=lambda x: -len(x[1]))[:10]:
                kinds: dict[str, int] = {}
                for f in flist:
                    k = f.get("kind") or f.get("type", "?")
                    kinds[k] = kinds.get(k, 0) + 1
                print(f"  {mid:>10}  {_display(modules[mid])}  {len(flist)} findings  {kinds}")


def print_json(
    modules: dict[str, ParcelModule],
    out: dict[str, list[str]],
    ins: dict[str, list[str]],
    entry_ids: list[str],
    orph: list[str],
    pr_name: str,
    chunk_labels: Optional[dict[str, str]],
    sec_findings: Optional[dict[str, list[dict]]],
) -> None:
    orphan_set = set(orph)
    entry_set = set(entry_ids)
    mods_out = {
        mid: {
            "module_id": mid,
            "label": mod.label,
            "chunk_label": (chunk_labels or {}).get(mid),
            "out": out.get(mid, []),
            "in": ins.get(mid, []),
            "dep_names": mod.dep_names,
            "is_entry": mid in entry_set,
            "is_orphan": mid in orphan_set,
            "security_findings": (sec_findings or {}).get(mid, []),
        }
        for mid, mod in modules.items()
    }
    result = {
        "format": "module_graph_parcel_v1",
        "bundle_format": "parcel1",
        "parcel_require_name": pr_name,
        "stats": {
            "module_count": len(modules),
            "edge_count": sum(len(v) for v in out.values()),
            "entry_count": len(entry_ids),
            "orphan_count": len(orph),
        },
        "entry_ids": entry_ids,
        "modules": mods_out,
    }
    print(json.dumps(result, indent=2))


def print_dot(
    modules: dict[str, ParcelModule],
    out: dict[str, list[str]],
    entry_ids: list[str],
    orph: list[str],
) -> None:
    entry_set = set(entry_ids)
    orphan_set = set(orph)

    def esc(s: str) -> str:
        return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")

    lines = [
        "digraph parcel_bundle {",
        "  rankdir=LR;",
        '  node [shape=box fontname="monospace" fontsize=9];',
    ]
    for mid, mod in modules.items():
        attrs = [f'label="{esc(_display(mod))}"']
        if mid in entry_set:
            attrs.append("style=filled fillcolor=lightblue")
        elif mid in orphan_set:
            attrs.append("style=filled fillcolor=lightyellow")
        lines.append(f'  "{esc(mid)}" [{", ".join(attrs)}];')
    for mid, deps in out.items():
        for dep in deps:
            lines.append(f'  "{esc(mid)}" -> "{esc(dep)}";')
    lines.append("}")
    print("\n".join(lines))


# ---------------------------------------------------------------------------
# Module extraction
# ---------------------------------------------------------------------------


def extract_modules(
    src,
    modules: dict[str, ParcelModule],
    extract_dir: Path,
    include_vendor: bool,
) -> list[tuple[str, int]]:
    """Write each module's factory body to extract_dir/<module_id>.js."""
    extract_dir.mkdir(parents=True, exist_ok=True)
    extracted: list[tuple[str, int]] = []
    for mid in sorted(modules):
        mod = modules[mid]
        if not include_vendor and _is_vendor(mod):
            continue
        if mod.factory_body_start < 0 or mod.factory_body_end < 0:
            continue
        raw = src[mod.factory_body_start : mod.factory_body_end]
        content: bytes = bytes(raw) if not isinstance(raw, (bytes, bytearray)) else raw
        if not content.strip():
            continue
        filename = f"{mid}.js"
        (extract_dir / filename).write_bytes(content)
        extracted.append((filename, len(content)))
    return extracted


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main() -> None:
    ap = argparse.ArgumentParser(
        description="module_graph_parcel.py v1 — Parcel 1 bundle dependency graph",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("bundle", help="Path to Parcel 1 bundle JS file")
    ap.add_argument("--json", action="store_true", dest="output_json",
                    help="Output JSON instead of text report")
    ap.add_argument("--dot", action="store_true",
                    help="Output GraphViz DOT to stdout")
    ap.add_argument("--analyzer-json", metavar="FILE",
                    help="js_analyzer_v4_8.py JSON for security findings / chunk labels")
    ap.add_argument("--extract-dir", metavar="DIR",
                    help="Extract each module's factory body as <module_id>.js into DIR/")
    ap.add_argument("--include-vendor", action="store_true",
                    help="Also extract vendor/Parcel/SWC modules (skipped by default)")
    args = ap.parse_args()

    path = Path(args.bundle)
    if not path.exists():
        print(f"[error] File not found: {path}", file=sys.stderr)
        sys.exit(1)

    size = path.stat().st_size
    print(f"[*] {path.name}  {size:,} bytes", file=sys.stderr)

    fh = None
    src = None
    try:
        if size > _10MB:
            print("[*] File > 10 MB — using mmap (no full load into RAM)", file=sys.stderr)
            fh = open(path, "rb")
            src = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        else:
            src = path.read_bytes()

        if not is_parcel1(src):
            print(
                "[!] Format not supported — not a Parcel 1 bundle.\n"
                "    Use module_graph.py for Webpack / Vite bundles.",
                file=sys.stderr,
            )
            sys.exit(2)

        map_start = find_map_start(src)
        if map_start < 0:
            print(
                "[!] Cannot locate module map. Non-standard Parcel 1 variant?",
                file=sys.stderr,
            )
            sys.exit(2)
        print(f"[*] Module map at byte {map_start:,}", file=sys.stderr)

        modules, pos_after = parse_module_map(src, map_start)
        if not modules:
            print(
                "[!] No modules extracted. Bundle may not be standard Parcel 1.",
                file=sys.stderr,
            )
            sys.exit(2)

        entry_ids, pr_name = parse_call_tail(src, pos_after)
        enrich_labels_from_dep_names(modules)
        print(
            f"[*] {len(modules)} modules  parcelRequire={pr_name!r}  entries={entry_ids}",
            file=sys.stderr,
        )

        out, ins = build_graph(modules)
        orph = find_orphans(modules, ins, entry_ids)
        print(f"[*] Orphans: {len(orph)}", file=sys.stderr)

        chunk_labels: Optional[dict[str, str]] = None
        sec_findings: Optional[dict[str, list[dict]]] = None
        if args.analyzer_json:
            try:
                adata = json.loads(Path(args.analyzer_json).read_text("utf-8"))
                chunk_labels, sec_findings = cross_analyzer_data(modules, adata, path.name)
                total = sum(len(v) for v in sec_findings.values())
                print(f"[*] analyzer-json: {total} findings crossed", file=sys.stderr)
            except Exception as exc:
                print(f"[!] --analyzer-json failed: {exc}", file=sys.stderr)

        if args.dot:
            print_dot(modules, out, entry_ids, orph)
        elif args.output_json:
            print_json(modules, out, ins, entry_ids, orph, pr_name, chunk_labels, sec_findings)
        else:
            print_text(modules, out, ins, entry_ids, orph, pr_name, chunk_labels, sec_findings)

        if args.extract_dir:
            extracted = extract_modules(
                src, modules, Path(args.extract_dir), args.include_vendor
            )
            for filename, nbytes in extracted:
                print(f"[extracted] {filename}  ({nbytes:,} bytes)")
            print(f"[extract-dir] {len(extracted)} modules written to {args.extract_dir}",
                  file=sys.stderr)

    finally:
        if isinstance(src, mmap.mmap):
            src.close()
        if fh:
            fh.close()


if __name__ == "__main__":
    main()
