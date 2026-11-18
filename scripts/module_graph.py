#!/usr/bin/env python3
"""
module_graph.py v1 — Webpack bundle dependency graph reconstructor.

Reconstructs the internal require graph of a webpack bundle using tree-sitter
for AST parsing (error-tolerant, no Node.js dependency). Supports webpack5_object
and webpackJsonp (WP3/WP4 with object map) formats.

WP4 array format produces exit 2. Vite bundles produce exit 2 with a clear message.

Usage:
  module_graph.py bundle.js [--jxscout-json FILE] [--analyzer-json FILE]
                            [--bundles-dir DIR] [--json] [--dot]
                            [--assume-orphans]
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import networkx as nx
import tree_sitter_javascript as tsjs
from tree_sitter import Language, Parser, Query, QueryCursor

# ---------------------------------------------------------------------------
# Tree-sitter setup
# ---------------------------------------------------------------------------
_JS_LANG = Language(tsjs.language())
_PARSER = Parser(_JS_LANG)


def _parse(src: bytes) -> object:
    return _PARSER.parse(src)


def _query(pattern: str, node) -> dict:
    """captures() — flat dict per capture name. Only safe when alignment is 1:1 guaranteed."""
    cur = QueryCursor(Query(_JS_LANG, pattern))
    return cur.captures(node)


def _matches(pattern: str, node) -> list[tuple[int, dict]]:
    """
    matches() — one entry per pattern match, captures grouped together.
    Use for all paired captures (key+body, fn+arg) to avoid flat-list alignment bugs.
    """
    cur = QueryCursor(Query(_JS_LANG, pattern))
    raw = cur.matches(node)
    result = []
    for pattern_idx, cap_dict in raw:
        normalized = {k: (v if isinstance(v, list) else [v]) for k, v in cap_dict.items()}
        result.append((pattern_idx, normalized))
    return result


def _has_parse_errors(tree) -> bool:
    return tree.root_node.has_error


def _node_text(node) -> str:
    return node.text.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------
@dataclass
class ModuleNode:
    module_id: str
    start_byte: int
    end_byte: int
    body_node: object  # tree-sitter Node of the factory function body
    deps: list[str] = field(default_factory=list)
    external_chunks: list[str] = field(default_factory=list)  # __webpack_require__.e(N)


@dataclass
class BundleStructure:
    """Result of format detection — format + entry ID information."""
    fmt: str               # "webpack5_object" | "webpackJsonp" | "unsupported"
    entry_ids: set[str]    # known entry module IDs (may be empty)
    entry_known: bool      # False → orphan detection must be opt-in


@dataclass
class FilenameTemplate:
    """
    Parsed representation of the __webpack_require__.u filename construction.

    Segments are evaluated left-to-right:
      ("lit", "libs/")         — literal string fragment
      ("chunk_id",)            — the chunk_id parameter
      ("hash_map", {dict})     — per-chunk hash object lookup {chunk_id: hash}
      ("global_hash", "abc")   — resolved static hash from __webpack_require__.h()
      ("global_hash_call",)    — __webpack_require__.h() whose hash is not yet resolved
    """
    segments: list
    degraded: bool = False  # True if the template was built from regex, not AST

    def resolve(self, chunk_id: str) -> Optional[str]:
        parts = []
        for seg in self.segments:
            if seg[0] == "lit":
                parts.append(seg[1])
            elif seg[0] == "chunk_id":
                parts.append(chunk_id)
            elif seg[0] == "hash_map":
                h = seg[1].get(chunk_id)
                if h is None:
                    return None
                parts.append(h)
            elif seg[0] in ("global_hash", "global_hash_call"):
                h = seg[1] if seg[0] == "global_hash" else None
                if h is None:
                    return None
                parts.append(h)
        return "".join(parts) if parts else None


@dataclass
class ExternalDep:
    chunk_id: str
    chunk_name: Optional[str]
    resolved_filename: Optional[str]
    resolution_method: str  # "manifest" | "directory_glob" | "regex_fallback_degraded" | "unresolved"
    found_in_bundles_dir: bool

    def to_dict(self) -> dict:
        return {
            "chunk_id": self.chunk_id,
            "chunk_name": self.chunk_name,
            "resolved_filename": self.resolved_filename,
            "resolution_method": self.resolution_method,
            "found_in_bundles_dir": self.found_in_bundles_dir,
        }


@dataclass
class ChunkManifest:
    """Result of __webpack_require__.u + .h + .k/n/cn parsing."""
    template: Optional[FilenameTemplate]     # filename template (may be None if .u absent)
    hash_map: dict[str, str]                 # chunk_id → hash (from per-chunk object in .u)
    global_hash: Optional[str]               # single hash for all chunks (from .h)
    names: dict[str, str]                    # chunk_id → friendly name (from .k/.n/.cn)
    degraded: bool = False                   # True if any part used regex fallback

    def resolve_filename(self, chunk_id: str) -> tuple[Optional[str], str]:
        """
        Returns (filename_or_None, resolution_method).
        resolution_method: "manifest" | "regex_fallback_degraded" | "unresolved"
        """
        if self.template is None:
            return None, "unresolved"
        # Resolve global_hash_call segments
        resolved_segs = []
        for seg in self.template.segments:
            if seg[0] == "global_hash_call":
                if self.global_hash:
                    resolved_segs.append(("global_hash", self.global_hash))
                else:
                    return None, "unresolved"
            elif seg[0] == "hash_map" and not seg[1] and self.hash_map:
                # template has empty hash_map placeholder — fill with actual hash_map
                resolved_segs.append(("hash_map", self.hash_map))
            else:
                resolved_segs.append(seg)
        filled = FilenameTemplate(segments=resolved_segs, degraded=self.template.degraded)
        result = filled.resolve(chunk_id)
        if result is None:
            return None, "unresolved"
        method = "regex_fallback_degraded" if self.degraded else "manifest"
        return result, method


# ---------------------------------------------------------------------------
# WebpackFormatDetector
# ---------------------------------------------------------------------------

_PUSH_CALL_QUERY = """\
(call_expression
  function: (member_expression
    property: (property_identifier) @push_prop)
  arguments: (arguments (array) @outer_arr)
)
"""

_JSONP_CALL_QUERY = """\
(call_expression
  function: (identifier) @fn_name
  arguments: (arguments) @args
)
"""

_WP5_S_QUERY = """\
(assignment_expression
  left: (member_expression
    object: (identifier) @obj
    property: (property_identifier) @prop)
  right: [
    (number) @entry_id
    (string) @entry_id
  ]
)
"""


class WebpackFormatDetector:
    """
    Determines bundle format via AST structural inspection of the module map argument.

    "webpack5_object" — (.push([[chunkIds], {moduleId: fn, ...}]))
    "webpackJsonp"    — webpackJsonp([chunkIds], {key: fn, ...}, [entryIds?])
    "unsupported"     — WP4 array format, Vite, or unknown
    """

    @staticmethod
    def detect(tree) -> BundleStructure:
        src = tree.root_node.text or b""

        if b"webpackJsonp" in src:
            return WebpackFormatDetector._detect_jsonp(tree)

        if b"__webpack_require__" in src:
            return WebpackFormatDetector._detect_wp5(tree, src)

        return BundleStructure(fmt="unsupported", entry_ids=set(), entry_known=False)

    @staticmethod
    def _detect_jsonp(tree) -> BundleStructure:
        """
        webpackJsonp([chunkIds], {mods}, [entryIds?])
        Second arg: object → supported, array → WP4 array format (unsupported).
        Third arg (optional): entry module ids.
        """
        for _, caps in _matches(_JSONP_CALL_QUERY, tree.root_node):
            fn_nodes = caps.get("fn_name", [])
            args_nodes = caps.get("args", [])
            if not fn_nodes or not args_nodes:
                continue
            if fn_nodes[0].text != b"webpackJsonp":
                continue
            args_node = args_nodes[0]
            named = [c for c in args_node.named_children]
            if len(named) < 2:
                continue
            mod_map_node = named[1]
            if mod_map_node.type == "object":
                entry_ids: set[str] = set()
                entry_known = False
                if len(named) >= 3 and named[2].type == "array":
                    for item in named[2].named_children:
                        entry_ids.add(_node_text(item).strip("'\""))
                    entry_known = True
                return BundleStructure(fmt="webpackJsonp", entry_ids=entry_ids,
                                       entry_known=entry_known)
            elif mod_map_node.type == "array":
                return BundleStructure(fmt="unsupported", entry_ids=set(), entry_known=False)

        # webpackJsonp in source but couldn't parse call — default to supported with unknown entry
        return BundleStructure(fmt="webpackJsonp", entry_ids=set(), entry_known=False)

    @staticmethod
    def _detect_wp5(tree, src: bytes) -> BundleStructure:
        """
        WP5: (self["webpackChunk..."] || []).push([[chunkIds], {mods}])

        webpackChunk in source is a WP5-exclusive marker — the object module map is always
        used in WP5. We only declare "unsupported" if we positively find an array module map
        (WP4 artifact). If the structural check can't determine either way (e.g., ERROR nodes
        break the inner parse of large bundles), we trust webpackChunk and proceed.
        """
        has_chunk_marker = b"webpackChunk" in src

        found_array_map = False
        found_object_map = False

        for _, caps in _matches(_PUSH_CALL_QUERY, tree.root_node):
            prop_nodes = caps.get("push_prop", [])
            arr_nodes = caps.get("outer_arr", [])
            if not prop_nodes or not arr_nodes:
                continue
            if prop_nodes[0].text != b"push":
                continue
            outer_arr = arr_nodes[0]
            named = [c for c in outer_arr.named_children]
            if len(named) < 2:
                continue
            mod_map_node = named[1]
            if mod_map_node.type == "object":
                found_object_map = True
                break
            elif mod_map_node.type == "array":
                found_array_map = True
                # Keep scanning — a later push might have an object map

        # Only reject as unsupported when:
        #   - array map found AND no object map found (genuine WP4-like array format)
        #   - AND no webpackChunk marker (which would indicate WP5 regardless)
        # Without the chunk marker check, normal app code that calls .push([[a],[b]])
        # anywhere in the bundle would incorrectly trigger this path on a WP5 bundle.
        if found_array_map and not found_object_map and not has_chunk_marker:
            return BundleStructure(fmt="unsupported", entry_ids=set(), entry_known=False)

        # webpackChunk is WP5-exclusive. Absence of object map can be due to ERROR nodes.
        if not found_object_map and not has_chunk_marker:
            return BundleStructure(fmt="unsupported", entry_ids=set(), entry_known=False)

        # WP5 confirmed. Find entry module ID via __webpack_require__.s assignment.
        entry_ids: set[str] = set()
        for _, caps in _matches(_WP5_S_QUERY, tree.root_node):
            obj_nodes = caps.get("obj", [])
            prop_nodes = caps.get("prop", [])
            eid_nodes = caps.get("entry_id", [])
            if not obj_nodes or not prop_nodes or not eid_nodes:
                continue
            if (obj_nodes[0].text == b"__webpack_require__"
                    and prop_nodes[0].text == b"s"):
                entry_ids.add(_node_text(eid_nodes[0]).strip("'\""))

        return BundleStructure(
            fmt="webpack5_object",
            entry_ids=entry_ids,
            entry_known=bool(entry_ids),
        )


# ---------------------------------------------------------------------------
# ModuleExtractor
# ---------------------------------------------------------------------------

_MODULE_PAIR_QUERY = """\
(pair
  key: [
    (number) @mod_id
    (string) @mod_id
  ]
  value: [
    (function_expression body: (statement_block) @body)
    (arrow_function      body: (statement_block) @body)
  ]
) @pair
"""


class ModuleExtractor:
    """Extracts module id → ModuleNode from a parsed bundle tree."""

    @staticmethod
    def extract(tree, structure: BundleStructure) -> dict[str, ModuleNode]:
        if structure.fmt in ("webpack5_object", "webpackJsonp"):
            return ModuleExtractor._extract_pairs(tree)
        return {}

    @staticmethod
    def _extract_pairs(tree) -> dict[str, ModuleNode]:
        """
        Works for both WP5 and JSONP: (key: fn) pairs where key is number or string
        and value is a function with a block body.
        Uses _matches() so each mod_id is guaranteed paired with its body.
        """
        modules: dict[str, ModuleNode] = {}
        for _, caps in _matches(_MODULE_PAIR_QUERY, tree.root_node):
            id_nodes = caps.get("mod_id", [])
            body_nodes = caps.get("body", [])
            if not id_nodes or not body_nodes:
                continue
            id_node, body_node = id_nodes[0], body_nodes[0]
            raw = _node_text(id_node).strip("'\"")
            modules[raw] = ModuleNode(
                module_id=raw,
                start_byte=id_node.start_byte,
                end_byte=body_node.end_byte,
                body_node=body_node,
            )
        return modules


# ---------------------------------------------------------------------------
# DependencyResolver
# ---------------------------------------------------------------------------

_REQ_CALL_QUERY = """\
(call_expression
  function: (identifier) @fn
  arguments: (arguments [
    (number) @dep_id
    (string) @dep_id
  ])
)
"""

_REQ_ALIAS_QUERY = """\
(call_expression
  function: (identifier) @fn
  arguments: (arguments (number) @dep_id)
)
"""

_REQ_LAZY_QUERY = """\
(call_expression
  function: (member_expression
    object: (identifier) @obj
    property: (property_identifier) @prop)
  arguments: (arguments [
    (number) @chunk_id
    (string) @chunk_id
  ])
)
"""

_ALIAS_DECL_QUERY = """\
(variable_declarator
  name: (identifier) @alias
  value: (identifier) @rhs
)
"""


class DependencyResolver:
    """
    Extracts direct deps and lazy chunk refs from a module body.
    All paired captures use _matches() to avoid ordering bugs.
    """

    @staticmethod
    def resolve(module_node: ModuleNode, all_module_ids: set[str]) -> None:
        body = module_node.body_node
        aliases = DependencyResolver._find_aliases(body)

        for _, caps in _matches(_REQ_CALL_QUERY, body):
            fn_nodes = caps.get("fn", [])
            dep_nodes = caps.get("dep_id", [])
            if not fn_nodes or not dep_nodes:
                continue
            fn_name = _node_text(fn_nodes[0])
            if fn_name == "__webpack_require__" or fn_name in aliases:
                dep_id = _node_text(dep_nodes[0]).strip("'\"")
                if dep_id not in module_node.deps:
                    module_node.deps.append(dep_id)

        if aliases:
            for _, caps in _matches(_REQ_ALIAS_QUERY, body):
                fn_nodes = caps.get("fn", [])
                dep_nodes = caps.get("dep_id", [])
                if not fn_nodes or not dep_nodes:
                    continue
                fn_name = _node_text(fn_nodes[0])
                if fn_name in aliases and fn_name != "__webpack_require__":
                    dep_id = _node_text(dep_nodes[0]).strip("'\"")
                    if dep_id not in module_node.deps and dep_id in all_module_ids:
                        module_node.deps.append(dep_id)

        for _, caps in _matches(_REQ_LAZY_QUERY, body):
            obj_nodes = caps.get("obj", [])
            prop_nodes = caps.get("prop", [])
            chunk_nodes = caps.get("chunk_id", [])
            if not obj_nodes or not prop_nodes or not chunk_nodes:
                continue
            obj_name = _node_text(obj_nodes[0])
            prop_name = _node_text(prop_nodes[0])
            if (obj_name == "__webpack_require__" or obj_name in aliases) and prop_name == "e":
                cid = _node_text(chunk_nodes[0]).strip("'\"")
                if cid not in module_node.external_chunks:
                    module_node.external_chunks.append(cid)

        chunk_set = set(module_node.external_chunks)
        module_node.deps = [d for d in module_node.deps if d not in chunk_set]

    @staticmethod
    def _find_aliases(body_node) -> set[str]:
        aliases: set[str] = set()
        for _, caps in _matches(_ALIAS_DECL_QUERY, body_node):
            alias_nodes = caps.get("alias", [])
            rhs_nodes = caps.get("rhs", [])
            if alias_nodes and rhs_nodes:
                if rhs_nodes[0].text == b"__webpack_require__":
                    aliases.add(_node_text(alias_nodes[0]))
        return aliases


# ---------------------------------------------------------------------------
# GraphBuilder
# ---------------------------------------------------------------------------
class GraphBuilder:

    @staticmethod
    def build(modules: dict[str, ModuleNode]) -> nx.DiGraph:
        g = nx.DiGraph()
        for mid in modules:
            g.add_node(mid)
        for mid, mod in modules.items():
            for dep in mod.deps:
                if not g.has_node(dep):
                    g.add_node(dep, external_stub=True)
                g.add_edge(mid, dep)
        return g


# ---------------------------------------------------------------------------
# OrphanDetector
# ---------------------------------------------------------------------------
class OrphanDetector:
    """
    Finds in-degree==0 modules that are not known entry points.

    When entry_known is False and assume_orphans is False (default), returns []
    and sets entry_unknown=True in the output — better no data than systematic
    false positives.

    With --assume-orphans: reports in-degree==0 nodes regardless, with a warning.
    """

    @staticmethod
    def find(
        graph: nx.DiGraph,
        structure: BundleStructure,
        assume_orphans: bool = False,
    ) -> list[str]:
        if not structure.entry_known and not assume_orphans:
            return []

        entry_set = structure.entry_ids
        orphans = []
        for node in graph.nodes:
            if graph.nodes[node].get("external_stub"):
                continue
            if graph.in_degree(node) == 0 and node not in entry_set:
                orphans.append(node)
        return sorted(orphans)


# ---------------------------------------------------------------------------
# ChunkManifestResolver  (Camino A — AST-only, regex only as explicit fallback)
# ---------------------------------------------------------------------------

_WR_ASSIGN_QUERY = """\
(assignment_expression
  left: (member_expression
    object: (identifier) @obj
    property: (property_identifier) @prop)
  right: [
    (function_expression body: (statement_block) @fn_body)
    (arrow_function body: (statement_block) @fn_body)
    (arrow_function body: _ @fn_body)
    (object) @obj_body
  ]
)
"""


class ChunkManifestResolver:
    """
    Extracts chunk filename information from __webpack_require__ runtime assignments.

    Handles two distinct WP5 patterns observed in regional deployments:

    Pattern A — global hash:
      __webpack_require__.u = function(e) { return "libs/" + e + "." + r.h() + ".js"; }
      __webpack_require__.h = function() { return "c441d9750eb16ae66fa5"; }
      Filename template: "libs/{chunk_id}.{global_hash}.js"

    Pattern B — per-chunk hash map:
      __webpack_require__.u = function(e) { return "" + {123:"abc", 456:"def"}[e] + ".js"; }
      Filename template: "{hash_for_chunk_id}.js"

    Regex fallback: used only if AST walk finds no object nodes in the .u body.
    Marked as "regex_fallback_degraded" in resolution_method so the caller knows.
    """

    _NAME_PROPS = {"k", "n", "cn"}

    @staticmethod
    def resolve(tree) -> ChunkManifest:
        hash_map: dict[str, str] = {}
        global_hash: Optional[str] = None
        names: dict[str, str] = {}
        template: Optional[FilenameTemplate] = None
        degraded = False

        for _, caps in _matches(_WR_ASSIGN_QUERY, tree.root_node):
            obj_nodes = caps.get("obj", [])
            prop_nodes = caps.get("prop", [])
            if not obj_nodes or not prop_nodes:
                continue
            if obj_nodes[0].text != b"__webpack_require__":
                continue
            prop = _node_text(prop_nodes[0])

            fn_body_nodes = caps.get("fn_body", [])
            obj_body_nodes = caps.get("obj_body", [])

            if prop == "u" and fn_body_nodes:
                template = TemplateExtractor.extract(fn_body_nodes[0])

            elif prop == "h" and fn_body_nodes:
                h = ChunkManifestResolver._extract_return_string(fn_body_nodes[0])
                if h:
                    global_hash = h

            elif prop in ChunkManifestResolver._NAME_PROPS:
                if fn_body_nodes:
                    pairs = ChunkManifestResolver._extract_obj_from_body(fn_body_nodes[0])
                    names.update(pairs)
                elif obj_body_nodes:
                    names.update(_parse_object_node(obj_body_nodes[0]))

        # If .u was found but template extraction got nothing (partial parse), try regex fallback
        src = tree.root_node.text or b""
        if template is None and b"__webpack_require__.u" in src:
            fb_map, fb_tmpl = ChunkManifestResolver._regex_fallback(src)
            if fb_map or fb_tmpl:
                degraded = True
                hash_map = fb_map
                template = fb_tmpl

        return ChunkManifest(
            template=template,
            hash_map=hash_map,
            global_hash=global_hash,
            names=names,
            degraded=degraded,
        )

    @staticmethod
    def _extract_return_string(body_node) -> Optional[str]:
        """
        Walk a function body (statement_block or expression) to find the first
        return statement that returns a plain string literal.
        """
        if body_node.type == "statement_block":
            for child in body_node.named_children:
                if child.type == "return_statement":
                    for c in child.named_children:
                        if c.type == "string":
                            # Strip quotes
                            txt = _node_text(c)
                            return txt.strip("'\"")
        elif body_node.type == "string":
            return _node_text(body_node).strip("'\"")
        return None

    @staticmethod
    def _extract_obj_from_body(body_node) -> dict[str, str]:
        """Walk a function body to find the first object literal, return its pairs."""
        for child in body_node.children:
            if child.type == "return_statement":
                for c in child.children:
                    if c.type == "object":
                        return _parse_object_node(c)
                    if c.type == "subscript_expression":
                        obj_child = c.child_by_field_name("object")
                        if obj_child and obj_child.type == "object":
                            return _parse_object_node(obj_child)
        return {}

    @staticmethod
    def _regex_fallback(src: bytes) -> tuple[dict[str, str], Optional[FilenameTemplate]]:
        """
        Last-resort regex scan. Only reached when AST completely fails to find object nodes
        inside __webpack_require__.u (e.g., severe parse errors). Caller marks as degraded.
        """
        import re
        m = re.search(
            rb"__webpack_require__\.u\s*=\s*(?:function[^{]*\{[^}]*return[^{]*|[a-z]\s*=>\s*)"
            rb'[^{]*\{([^}]{0,8192})\}\s*\[',
            src,
        )
        if not m:
            return {}, None
        body_text = m.group(1).decode("utf-8", errors="replace")
        pairs = {k: v for k, v in re.findall(
            r'(\d+)\s*:\s*["\']?([a-f0-9]{6,32})["\']?', body_text
        )}
        if not pairs:
            return {}, None
        # Build a minimal template: hash_map + ".js" suffix
        tmpl = FilenameTemplate(
            segments=[("hash_map", pairs), ("lit", ".js")],
            degraded=True,
        )
        return pairs, tmpl


# ---------------------------------------------------------------------------
# TemplateExtractor — AST walker for __webpack_require__.u function body
# ---------------------------------------------------------------------------

def _parse_object_node(obj_node) -> dict[str, str]:
    """Walk a tree-sitter object node, return numeric_key → value pairs."""
    result: dict[str, str] = {}
    for child in obj_node.named_children:
        if child.type != "pair":
            continue
        key_node = child.child_by_field_name("key")
        val_node = child.child_by_field_name("value")
        if key_node and val_node:
            k = _node_text(key_node).strip("'\"")
            v = _node_text(val_node).strip("'\"")
            if k.isdigit():
                result[k] = v
    return result


class TemplateExtractor:
    """
    Parses the body of __webpack_require__.u = function(e) { return EXPR; }
    into a FilenameTemplate by recursively evaluating the return expression.

    Handles:
      "prefix/" + e + "." + __webpack_require__.h() + ".js"   (Pattern A — global hash)
      "" + {123:"abc"}[e] + ".js"                             (Pattern B — per-chunk hash map)
      and combinations thereof.
    """

    @staticmethod
    def extract(body_node) -> Optional[FilenameTemplate]:
        """body_node is the statement_block or expression body of the .u function."""
        param_name = TemplateExtractor._find_param(body_node)
        return_expr = TemplateExtractor._find_return_expr(body_node)
        if return_expr is None:
            return None
        segments = TemplateExtractor._eval_expr(return_expr, param_name)
        if not segments:
            return None
        return FilenameTemplate(segments=segments)

    @staticmethod
    def _find_param(body_node) -> str:
        """
        Walk up from the body node to find the enclosing function's first parameter name.
        Falls back to "e" which is the minification convention.
        """
        parent = body_node.parent
        if parent is None:
            return "e"
        # parent is function_expression or arrow_function
        params = parent.child_by_field_name("parameters") or parent.child_by_field_name("parameter")
        if params:
            for child in params.named_children:
                if child.type == "identifier":
                    return _node_text(child)
        return "e"

    @staticmethod
    def _find_return_expr(body_node):
        """Find the first return statement's expression in a statement_block."""
        if body_node.type == "statement_block":
            for child in body_node.named_children:
                if child.type == "return_statement":
                    for c in child.named_children:
                        if c.type not in ("return",):
                            return c
        else:
            # arrow function with expression body
            return body_node
        return None

    @staticmethod
    def _eval_expr(node, param: str) -> list:
        """
        Recursively evaluate a binary_expression tree into a list of segments.
        Returns [] if the expression cannot be mapped to the segment vocabulary.
        """
        if node.type == "binary_expression":
            op = None
            for child in node.children:
                if child.type == "+":
                    op = "+"
                    break
            if op != "+":
                return []
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is None or right is None:
                return []
            left_segs = TemplateExtractor._eval_expr(left, param)
            right_segs = TemplateExtractor._eval_expr(right, param)
            if left_segs is None or right_segs is None:
                return []
            return left_segs + right_segs

        elif node.type == "string":
            txt = _node_text(node).strip("'\"")
            # Unescape common JS escapes
            txt = txt.replace('\\"', '"').replace("\\'", "'").replace("\\\\", "\\")
            return [("lit", txt)] if txt else []

        elif node.type == "template_string":
            # Template literal — extract raw text as literal (approximate)
            txt = _node_text(node).strip("`")
            return [("lit", txt)]

        elif node.type == "identifier":
            name = _node_text(node)
            if name == param:
                return [("chunk_id",)]
            return []  # Unknown identifier — skip rather than error

        elif node.type == "subscript_expression":
            # {hash_map}[param] pattern
            obj_child = node.child_by_field_name("object")
            idx_child = node.child_by_field_name("index")
            if obj_child and idx_child:
                if obj_child.type == "object" and _node_text(idx_child) == param:
                    hmap = _parse_object_node(obj_child)
                    return [("hash_map", hmap)]
                elif obj_child.type == "object":
                    # Index is not the param — we can't evaluate this generically
                    return []
            return []

        elif node.type == "call_expression":
            # __webpack_require__.h() pattern — resolved later via .h assignment
            fn = node.child_by_field_name("function")
            args = node.child_by_field_name("arguments")
            if fn and fn.type == "member_expression":
                prop = fn.child_by_field_name("property")
                if prop and prop.type == "property_identifier" and _node_text(prop) == "h":
                    if args and not args.named_children:
                        return [("global_hash_call",)]
            return []

        elif node.type == "parenthesized_expression":
            inner = node.named_children[0] if node.named_children else None
            if inner:
                return TemplateExtractor._eval_expr(inner, param)
            return []

        # Anything else (ternary, logical, etc.) — skip silently
        return []


# ---------------------------------------------------------------------------
# ChunkDirectoryFallback  (Camino B)
# ---------------------------------------------------------------------------
class ChunkDirectoryFallback:
    """
    Glob-based fallback. Patterns tried in order:
      {chunk_id}.*.js, {chunk_id}-*.js, {chunk_id}.js
    """

    @staticmethod
    def resolve(chunk_id: str, bundles_dir: str) -> list[str]:
        base = Path(bundles_dir)
        if not base.is_dir():
            return []
        candidates: list[str] = []
        for pat in (f"{chunk_id}.*.js", f"{chunk_id}-*.js", f"{chunk_id}.js"):
            candidates.extend(str(p) for p in base.glob(pat))
        return sorted(set(candidates))


# ---------------------------------------------------------------------------
# Chunk resolution — ExternalDep per chunk_id
# ---------------------------------------------------------------------------

def _resolve_chunk(
    chunk_id: str,
    manifest: ChunkManifest,
    bundles_dir: Optional[str],
) -> ExternalDep:
    """
    Combines Camino A (manifest template) and Camino B (directory glob).
    Manifest is always preferred. directory_glob is fallback.
    """
    chunk_name = manifest.names.get(chunk_id)

    # Camino A: try template-based filename reconstruction
    template_filename, template_method = manifest.resolve_filename(chunk_id)

    found_in_dir = False
    dir_filename: Optional[str] = None

    if bundles_dir:
        candidates = ChunkDirectoryFallback.resolve(chunk_id, bundles_dir)
        if template_filename:
            # Confirm template result exists on disk
            basename = Path(template_filename).name
            matched = [c for c in candidates if Path(c).name == basename]
            if not matched and candidates:
                # Hash substring match
                hash_part = manifest.hash_map.get(chunk_id) or manifest.global_hash or ""
                matched = [c for c in candidates if hash_part and hash_part in Path(c).name]
            if matched:
                dir_filename = matched[0]
                found_in_dir = True
            elif candidates:
                found_in_dir = True  # file exists but name doesn't match template (unusual)
        elif len(candidates) == 1:
            dir_filename = candidates[0]
            found_in_dir = True
        elif candidates:
            found_in_dir = True  # ambiguous — don't guess

    if template_filename:
        return ExternalDep(
            chunk_id=chunk_id,
            chunk_name=chunk_name,
            resolved_filename=dir_filename or template_filename,
            resolution_method=template_method,
            found_in_bundles_dir=found_in_dir,
        )

    if dir_filename:
        return ExternalDep(
            chunk_id=chunk_id,
            chunk_name=chunk_name,
            resolved_filename=dir_filename,
            resolution_method="directory_glob",
            found_in_bundles_dir=True,
        )

    if found_in_dir:
        return ExternalDep(
            chunk_id=chunk_id,
            chunk_name=chunk_name,
            resolved_filename=None,
            resolution_method="directory_glob",
            found_in_bundles_dir=True,
        )

    return ExternalDep(
        chunk_id=chunk_id,
        chunk_name=chunk_name,
        resolved_filename=None,
        resolution_method="unresolved",
        found_in_bundles_dir=False,
    )


# ---------------------------------------------------------------------------
# JxscoutMatcher  (optional)
# ---------------------------------------------------------------------------
@dataclass
class JxscoutMatch:
    match_id: str
    kind: str
    value: str
    offset: int

    def to_dict(self) -> dict:
        return {"id": self.match_id, "kind": self.kind, "value": self.value, "offset": self.offset}


class JxscoutMatcher:

    @staticmethod
    def match(
        modules: dict[str, ModuleNode], jxscout_data: list[dict]
    ) -> dict[str, list[JxscoutMatch]]:
        result: dict[str, list[JxscoutMatch]] = {mid: [] for mid in modules}
        ranges = sorted(
            [(mod.start_byte, mod.end_byte, mid) for mid, mod in modules.items()],
            key=lambda t: t[0],
        )
        for entry in jxscout_data:
            offset = entry.get("offset")
            if offset is None:
                continue
            mod_id = JxscoutMatcher._find_module(ranges, offset)
            if mod_id and mod_id in result:
                result[mod_id].append(JxscoutMatch(
                    match_id=entry.get("id", ""),
                    kind=entry.get("kind", ""),
                    value=entry.get("value", ""),
                    offset=offset,
                ))
        return result

    @staticmethod
    def _find_module(ranges: list, offset: int) -> Optional[str]:
        lo, hi = 0, len(ranges) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            start, end, mod_id = ranges[mid]
            if start <= offset < end:
                return mod_id
            elif offset < start:
                hi = mid - 1
            else:
                lo = mid + 1
        return None


# ---------------------------------------------------------------------------
# ChunkLabelMatcher  (optional — crosses js_analyzer _detect_chunks() output)
# ---------------------------------------------------------------------------
@dataclass
class ChunkLabel:
    name: str
    start: int
    end: int
    is_vendor: bool
    label: str

    def display(self) -> str:
        return self.label or self.name


class ChunkLabelMatcher:

    @staticmethod
    def match(modules: dict[str, ModuleNode], analyzer_data: dict) -> dict[str, ChunkLabel]:
        result: dict[str, ChunkLabel] = {}
        chunks = [
            ChunkLabel(
                name=c.get("name", ""),
                start=c.get("start", 0),
                end=c.get("end", 0),
                is_vendor=c.get("is_vendor", False),
                label=c.get("label", ""),
            )
            for c in analyzer_data.get("chunks", [])
        ]
        chunks.sort(key=lambda c: c.start)
        for mid, mod in modules.items():
            best: Optional[ChunkLabel] = None
            best_overlap = 0
            for chunk in chunks:
                overlap = min(mod.end_byte, chunk.end) - max(mod.start_byte, chunk.start)
                if overlap > best_overlap:
                    best_overlap = overlap
                    best = chunk
            if best:
                result[mid] = best
        return result


# ---------------------------------------------------------------------------
# Output serialisation
# ---------------------------------------------------------------------------

def _build_output(
    graph: nx.DiGraph,
    modules: dict[str, ModuleNode],
    structure: BundleStructure,
    orphans: list[str],
    manifest: ChunkManifest,
    partial_parse: bool,
    assume_orphans: bool,
    jxscout_map: Optional[dict],
    label_map: Optional[dict],
    bundles_dir: Optional[str],
) -> dict:
    orphan_set = set(orphans)
    modules_out = []

    for mid in graph.nodes:
        if graph.nodes[mid].get("external_stub"):
            continue
        mod = modules[mid]

        external_deps = [
            _resolve_chunk(cid, manifest, bundles_dir).to_dict()
            for cid in mod.external_chunks
        ]

        chunk_label: Optional[str] = None
        if label_map and mid in label_map:
            chunk_label = label_map[mid].display()

        matches_dentro: list[dict] = []
        if jxscout_map and mid in jxscout_map:
            matches_dentro = [m.to_dict() for m in jxscout_map[mid]]

        modules_out.append({
            "module_id": mid,
            "chunk_label": chunk_label,
            "deps": list(graph.successors(mid)),
            "dependents": list(graph.predecessors(mid)),
            "external_deps": external_deps,
            "is_orphan": mid in orphan_set,
            "matches_dentro": matches_dentro,
        })

    return {
        "format": "module_graph_v1",
        "bundle_format": structure.fmt,
        "partial_parse": partial_parse,
        "entry_known": structure.entry_known,
        "entry_ids": sorted(structure.entry_ids),
        "orphan_detection": (
            "active" if (structure.entry_known or assume_orphans) else "disabled_entry_unknown"
        ),
        "module_count": len(modules),
        "edge_count": graph.number_of_edges(),
        "orphan_count": len(orphans),
        "chunk_manifest_has_template": manifest.template is not None,
        "chunk_manifest_degraded": manifest.degraded,
        "modules": modules_out,
    }


def _print_text_report(out: dict) -> None:
    pp = " [PARTIAL PARSE — ERROR nodes]" if out["partial_parse"] else ""
    print(f"\n[module_graph] {out['module_count']} modules, "
          f"{out['edge_count']} edges  ({out['bundle_format']}){pp}")

    if out["orphan_detection"] == "disabled_entry_unknown":
        print("[!] entry point unknown — orphan detection disabled. "
              "Use --assume-orphans to force (may include false positives).")
    else:
        orphans = [m["module_id"] for m in out["modules"] if m["is_orphan"]]
        if orphans:
            print(f"[orphans] {', '.join(orphans[:20])}"
                  + (" ..." if len(orphans) > 20 else ""))

    if out["entry_ids"]:
        print(f"[entry] {', '.join(out['entry_ids'])}")

    tpl_status = "yes" if out["chunk_manifest_has_template"] else "no"
    if out["chunk_manifest_degraded"]:
        tpl_status += " (degraded — regex fallback)"
    print(f"[manifest] filename template: {tpl_status}")

    print("\n[modules by out-degree]")
    mods = sorted(out["modules"], key=lambda m: -len(m["deps"]))
    for m in mods[:20]:
        label = f"  [{m['chunk_label']}]" if m["chunk_label"] else ""
        n_ext = len(m["external_deps"])
        unresolved = sum(1 for e in m["external_deps"]
                         if e["resolution_method"] == "unresolved")
        ext_info = f"  lazy={n_ext}"
        if unresolved:
            ext_info += f" ({unresolved} unresolved)"
        print(f"  {m['module_id']:>10}  deps={len(m['deps']):3d}{ext_info}{label}")

    hits = [(m["module_id"], m["matches_dentro"]) for m in out["modules"]
            if m["matches_dentro"]]
    if hits:
        print("\n[jxscout matches by module]")
        for mid, matches in sorted(hits, key=lambda x: -len(x[1]))[:10]:
            kinds: dict[str, int] = {}
            for match in matches:
                kinds[match["kind"]] = kinds.get(match["kind"], 0) + 1
            print(f"  {mid:>10}  {len(matches)} matches  {kinds}")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="module_graph.py v1 — webpack bundle dependency graph",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("bundle", help="Path to webpack bundle JS file")
    ap.add_argument("--jxscout-json", metavar="FILE",
                    help="JXScout match JSON for this file")
    ap.add_argument("--analyzer-json", metavar="FILE",
                    help="js_analyzer JSON with 'chunks' key (_detect_chunks output)")
    ap.add_argument("--bundles-dir", metavar="DIR",
                    help="Directory of sibling chunk files (Camino B fallback)")
    ap.add_argument("--json", action="store_true", dest="output_json",
                    help="Output JSON instead of text report")
    ap.add_argument("--dot", action="store_true",
                    help="Output GraphViz DOT to stdout")
    ap.add_argument("--assume-orphans", action="store_true",
                    help="Report in-degree==0 modules as orphans even when entry "
                         "is unknown (may produce false positives)")
    args = ap.parse_args()

    try:
        bundle_path = Path(args.bundle)
        if not bundle_path.exists():
            print(f"[error] File not found: {bundle_path}", file=sys.stderr)
            sys.exit(1)

        src = bundle_path.read_bytes()
        print(f"[*] Parsing {bundle_path.name} ({len(src):,} bytes) ...", file=sys.stderr)

        try:
            tree = _parse(src)
        except Exception as exc:
            print(f"[error] AST parse failed completely: {exc}", file=sys.stderr)
            sys.exit(2)

        partial_parse = _has_parse_errors(tree)
        if partial_parse:
            print("[!] WARNING: AST contains ERROR nodes — parse is partial. "
                  "Results may be incomplete.", file=sys.stderr)

        structure = WebpackFormatDetector.detect(tree)
        print(f"[*] Format: {structure.fmt}  entry_known={structure.entry_known}  "
              f"entry_ids={structure.entry_ids}", file=sys.stderr)

        if structure.fmt == "unsupported":
            print("[!] Format unsupported in v1 (WP4 array, Vite, or unknown). Exiting.",
                  file=sys.stderr)
            sys.exit(2)

        print("[*] Extracting modules ...", file=sys.stderr)
        modules = ModuleExtractor.extract(tree, structure)
        print(f"[*] {len(modules)} module factories found.", file=sys.stderr)

        if not modules:
            print("[!] No modules extracted — check bundle format.", file=sys.stderr)
            sys.exit(2)

        all_ids = set(modules.keys())

        print("[*] Resolving dependencies ...", file=sys.stderr)
        for mod in modules.values():
            DependencyResolver.resolve(mod, all_ids)

        print("[*] Building graph ...", file=sys.stderr)
        graph = GraphBuilder.build(modules)

        if args.assume_orphans and not structure.entry_known:
            print("[!] --assume-orphans active: entry unknown, orphan list may include "
                  "the real entry module.", file=sys.stderr)
        orphans = OrphanDetector.find(graph, structure, args.assume_orphans)

        print("[*] Resolving chunk manifest ...", file=sys.stderr)
        manifest = ChunkManifestResolver.resolve(tree)
        if manifest.template:
            print(f"[*] Filename template extracted "
                  f"({'degraded/regex' if manifest.degraded else 'AST'}). "
                  f"global_hash={manifest.global_hash!r}", file=sys.stderr)

        jxscout_map: Optional[dict] = None
        if args.jxscout_json:
            jdata = json.loads(Path(args.jxscout_json).read_text(encoding="utf-8"))
            if isinstance(jdata, dict):
                key = bundle_path.name
                entries = (jdata.get(key)
                           or jdata.get(str(bundle_path))
                           or next(iter(jdata.values()), []))
            else:
                entries = jdata
            jxscout_map = JxscoutMatcher.match(modules, entries)

        label_map: Optional[dict] = None
        if args.analyzer_json:
            adata = json.loads(Path(args.analyzer_json).read_text(encoding="utf-8"))
            label_map = ChunkLabelMatcher.match(modules, adata)

        out = _build_output(
            graph, modules, structure, orphans, manifest, partial_parse,
            args.assume_orphans, jxscout_map, label_map, args.bundles_dir,
        )

        if args.dot:
            print(nx.nx_pydot.to_pydot(graph).to_string())
        elif args.output_json:
            print(json.dumps(out, indent=2))
        else:
            _print_text_report(out)

    except SystemExit:
        raise
    except Exception as exc:
        print(f"[error] Unexpected failure: {exc}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
