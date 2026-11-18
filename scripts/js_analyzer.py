#!/usr/bin/env python3
"""
JS Bundle Analyzer v4.8 — Recon / Bug Bounty Edition (flattened single-class)
"""

from __future__ import annotations

import re
import sys
import json
import math
import base64
import hashlib
import argparse
from dataclasses import dataclass, asdict
from pathlib import Path
from bisect import bisect_right
from collections import defaultdict, Counter
from typing import Any, Dict, List, Tuple, Optional, Set

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
MAGENTA= "\033[95m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"
NO_COLOR = False

def c(color: str, text: str) -> str:
    return text if NO_COLOR else f"{color}{text}{RESET}"

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLOR = {"CRITICAL": RED, "HIGH": RED, "MEDIUM": YELLOW, "LOW": GREEN, "INFO": CYAN}

VENDOR_SIGNATURES = [
    r"react(?:\.production|\.development|DOM|\.createElement)",
    r"__REACT_DEVTOOLS",
    r"reconcileChildFibers",
    r"updateFunctionComponent",
    r"sentry[_.]",
    r"@sentry/",
    r"captureException",
    r"BrowserTracing",
    r"_sentrySpan",
    r"breadcrumb",
    r"momentjs\.com",
    r"moment\.locale",
    r"lodash",
    r"_\.merge|_\.extend|_\.assign",
    r"qs\.stringify|qs\.parse",
    r"querystring",
    r"core-js",
    r"regeneratorRuntime",
    r"Object\.setPrototypeOf\s*\|\|\s*\{__proto__",
    r"Symbol\.toStringTag",
    r"formatjs\.github\.io",
    r"IntlMessageFormat",
    r"useForm\b.*shouldUnregister",
    r"isSubmitSuccessful",
    r"tippy",
    r"popperOffsets|computeStyles|preventOverflow|createPopper",
    r"focus-lock|focus-guard",
    r"styled-components|emotion|@emotion",
    r"posthog\b",
    r"intercom",
    r"satismeter",
    r"weglot",
    r"Observable.*subscribe|BehaviorSubject|ReplaySubject",
    r"Symbol\.toStringTag.*propertyIsEnumerable",
    r"SECRET_DO_NOT_PASS_THIS",
    r"googletagmanager",
]
VENDOR_STRONG_SIGNATURES = [
    r"react\.production",
    r"__REACT_DEVTOOLS",
    r"reconcileChildFibers",
    r"@sentry/",
    r"core-js",
    r"regeneratorRuntime",
    r"SECRET_DO_NOT_PASS_THIS",
    r"googletagmanager",
]
SANITIZER_PATTERNS = [r"DOMPurify", r"sanitize-html", r"\bxss\s*\(", r"escapeHtml", r"sanitiz[a-zA-Z_]*"]
_VENDOR_RE = re.compile("|".join(f"(?:{p})" for p in VENDOR_SIGNATURES), re.I)
_VENDOR_STRONG_RE = re.compile("|".join(f"(?:{p})" for p in VENDOR_STRONG_SIGNATURES), re.I)
_SANITIZER_RE = re.compile("|".join(f"(?:{p})" for p in SANITIZER_PATTERNS), re.I)

@dataclass(frozen=True)
class PatternSpec:
    name: str
    regex: str
    severity: str
    module: str = "patterns"
    flags: int = re.IGNORECASE
    note: str = ""

@dataclass
class Finding:
    name: str
    severity: str
    line: int
    offset: int
    match: str
    context_before: str
    context_match: str
    context_after: str
    total_hits_for_pattern: int
    module: str
    note: str = ""
    is_vendor: bool = False
    vendor_confidence: str = "none"
    chunk_name: str = ""
    chunk_label: str = ""
    function_context: str = ""
    confidence: str = "medium"
    confidence_score: int = 0
    scope_nearby: bool = False
    near_sanitizer: bool = False
    source_signals: List[str] = None
    literal_assignment: bool = False

    def dedupe_key(self) -> Tuple[str, str, int, str, int]:
        return (self.name, self.severity, self.line, self.context_match[:120], self.offset)

@dataclass(frozen=True)
class SecretSpec:
    name: str
    regex: str
    severity: str
    flags: int = 0

@dataclass
class ChunkInfo:
    name: str
    start: int
    end: int
    is_vendor: bool = False
    label: str = ""


def normalize_space(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()

def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    return -sum((cnt / length) * math.log2(cnt / length) for cnt in freq.values())

def looks_like_placeholder(value: str) -> bool:
    return bool(re.match(r"^(x+|your[_-]?|change[_-]?me|placeholder|example|test|demo|todo|null|undefined|%filtered%)$", value, re.I))



class JSAnalyzer:
    def __init__(self, filepath: str, max_per: int = 5, scope: Optional[str] = None, app_only: bool = False, profile: str = "generic", baseline_json: Optional[str] = None):
        # base attrs
        self.path = Path(filepath)
        self.max_per = max_per
        self.scope = scope
        self.app_only = app_only

        self.content = ""
        self.lines: List[str] = []
        self.line_offsets: List[int] = []
        self.chunks: List[ChunkInfo] = []
        self.chunk_starts: List[int] = []

        self.frameworks: List[str] = []
        self.findings: Dict[str, List[Finding]] = defaultdict(list)
        self.endpoints: List[Dict] = []
        self.routes: List[str] = []
        self.params: List[str] = []
        self.storage_keys: List[str] = []
        self.secrets: List[Dict] = []
        self.api_clients: List[Dict] = []
        self.validation_playbooks: List[Dict] = []
        self.action_clusters: List[Dict] = []
        self.stats: Dict = {}

        self._finding_keys: Set[Tuple] = set()
        self._endpoint_seen: Set[Tuple[str, str]] = set()

        # V4 attrs
        self.profile = profile
        self.profile_keywords = self._get_profile_keywords(profile)
        self.critical_mutations: List[Dict] = []
        self.stored_xss_hints: List[Dict] = []
        self.document_export_flows: List[Dict] = []
        self.realtime_surfaces: List[Dict] = []
        self.create_render_correlations: List[Dict] = []
        self.resource_groups: List[Dict] = []
        self.entities_map: List[Dict] = []
        self.authz_surfaces: List[Dict] = []
        self.workflow_surfaces: List[Dict] = []
        self.write_effect_chains: List[Dict] = []

        # V46 attrs
        self.baseline_json = baseline_json
        self.final_risk_ranking: List[Dict] = []
        self.manual_test_queue: Dict[str, List[Dict]] = {
            "idor": [],
            "workflow_bypass": [],
            "stored_xss": [],
            "document_export_abuse": [],
            "realtime_session_binding": [],
        }
        self.entity_journeys: List[Dict] = []
        self.investigation_bundle: Dict[str, Any] = {}
        self.diff_report: Dict[str, Any] = {}

        # V47 attrs
        self.prototype_pollution_hints: List[Dict] = []
        self.postmessage_analysis: List[Dict] = []
        self.file_media_surfaces: List[Dict] = []
        self.redirect_callback_abuse: List[Dict] = []
        self.attack_paths: List[Dict] = []

        # V48 attrs
        self.read_surfaces: List[Dict] = []
        self.mutation_read_links: List[Dict] = []
        self.prioritized_targets: List[Dict] = []

    # ── run (V48 version — complete, no super) ──────────────────────────────
    def run(self) -> Dict:
        self._load_file()
        self._banner()
        self._detect_chunks()
        self._detect_frameworks()
        self._detect_build_info()
        self._scan_patterns()
        self._extract_endpoints()
        self._reconstruct_api_clients()
        self._extract_routes()
        self._extract_params()
        self._extract_storage_keys()
        self._extract_websockets()
        self._extract_graphql()
        self._extract_secrets()
        self._extract_internal_infra()
        self._extract_custom_headers()
        self._decode_strings()
        self._analyze_auth_flows()
        self._correlate_source_to_sink()
        self._extract_taint_flows()
        self._build_auth_map()
        self._detect_critical_mutations()
        self._detect_stored_xss_hints()
        self._build_resource_groups()
        self._build_entities_map()
        self._detect_authz_surfaces()
        self._detect_workflow_surfaces()
        self._detect_write_effect_chains()
        self._detect_document_export_flows()
        self._detect_realtime_surfaces()
        self._detect_create_render_correlations()
        self._detect_prototype_pollution_hints()
        self._analyze_postmessage_deep()
        self._detect_file_media_surfaces()
        self._detect_redirect_callback_abuse()
        self._detect_read_surfaces()
        self._build_mutation_read_links()
        self._generate_validation_playbooks()
        self._build_action_clusters()
        self._build_final_risk_ranking()
        self._boost_final_risk_ranking_v47()
        self._build_prioritized_targets_v48()
        self._build_manual_test_queue()
        self._build_entity_journeys()
        self._build_attack_paths()
        self._build_investigation_bundle()
        self._build_diff_report()
        self._analyze_data_flow()
        self._analyze_access_control()
        self._detect_hidden_debug()
        self._detect_source_maps()
        self._detect_error_patterns()
        self._extract_comments()
        self._analyze_file_uploads()
        self._extract_cors_hints()
        self._analyze_redirect_params()
        self._print_results()
        return self._build_report()

    # ── base utility methods ─────────────────────────────────────────────────
    def _load_file(self) -> None:
        if not self.path.exists():
            print(c(RED, f"[!] Archivo no encontrado: {self.path}"))
            sys.exit(1)
        self.content = self.path.read_text(encoding="utf-8", errors="ignore")
        self.lines = self.content.splitlines()
        self.line_offsets = [0]
        running = 0
        for line in self.lines:
            running += len(line) + 1
            self.line_offsets.append(running)

    def _line_of(self, offset: int) -> int:
        return bisect_right(self.line_offsets, offset)

    def _get_context(self, start: int, end: int, chars: int = 140) -> Tuple[str, str, str]:
        s = max(0, start - chars)
        e = min(len(self.content), end + chars)
        return (normalize_space(self.content[s:start]), normalize_space(self.content[start:end]), normalize_space(self.content[end:e]))

    def _get_func_context(self, offset: int, window: int = 500) -> str:
        start = max(0, offset - window)
        chunk = self.content[start:offset]
        funcs = list(re.finditer(r'(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:function|async\s+function|\([^)]*\)\s*=>|\w+\s*=>))', chunk))
        if funcs:
            last = funcs[-1]
            return last.group(1) or last.group(2) or "anonymous"
        methods = list(re.finditer(r'(\w+)\s*(?:\([^)]*\))?\s*{', chunk))
        if methods:
            return methods[-1].group(1)
        return ""

    def _vendor_signal_counts(self, offset: int, window: int = 800) -> Tuple[int, int]:
        start = max(0, offset - window)
        end = min(len(self.content), offset + window)
        ctx = self.content[start:end]
        strong_count = len(set(m.group(0).lower() for m in _VENDOR_STRONG_RE.finditer(ctx)))
        weak_count = len(set(m.group(0).lower() for m in _VENDOR_RE.finditer(ctx)))
        return strong_count, weak_count

    def _vendor_confidence(self, offset: int) -> str:
        strong_count, weak_count = self._vendor_signal_counts(offset, 800)
        if strong_count >= 3 or weak_count >= 4:
            return "high"
        if strong_count >= 1 or weak_count >= 2:
            return "medium"
        far_start = max(0, offset - 1500)
        far_end = min(len(self.content), offset + 1500)
        return "low" if _VENDOR_RE.search(self.content[far_start:far_end]) else "none"

    def _is_vendor_context(self, offset: int, strict: bool = False) -> bool:
        level = self._vendor_confidence(offset)
        return level == "high" if not strict else level in {"high", "medium"}

    def _chunk_at(self, offset: int) -> Optional[ChunkInfo]:
        if not self.chunk_starts:
            return None
        idx = bisect_right(self.chunk_starts, offset) - 1
        if idx >= 0:
            chunk = self.chunks[idx]
            if chunk.start <= offset < chunk.end:
                return chunk
        return None

    def _scope_nearby(self, offset: int, window: int = 250) -> bool:
        if not self.scope:
            return False
        start = max(0, offset - window)
        end = min(len(self.content), offset + window)
        return self.scope.lower() in self.content[start:end].lower()

    def _near_sanitizer(self, offset: int, window: int = 300) -> bool:
        start = max(0, offset - window)
        end = min(len(self.content), offset + window)
        return bool(_SANITIZER_RE.search(self.content[start:end]))

    def _detect_sources_nearby(self, offset: int, window: int = 300) -> List[str]:
        start = max(0, offset - window)
        end = min(len(self.content), offset + window)
        ctx = self.content[start:end]
        patterns = {
            "query_param": r"(?:searchParams|getParam|urlParam|URLSearchParams|location\.search)",
            "hash": r"location\.hash",
            "postMessage": r"event\.data|message\.data",
            "storage": r"(?:localStorage|sessionStorage)\.(?:getItem|setItem)",
            "api_data": r"(?:response\.data|res\.data|json\(\)|await\s+[^;]+\.json\()",
        }
        found = []
        for name, pat in patterns.items():
            if re.search(pat, ctx, re.I):
                found.append(name)
        return found

    def _is_literal_assignment(self, spec_name: str, offset: int) -> bool:
        sink_map = {
            "XSS - innerHTML": r"\.innerHTML\s*=\s*([\"'`])",
            "XSS - outerHTML": r"\.outerHTML\s*=\s*([\"'`])",
            "XSS - srcdoc": r"\.srcdoc\s*=\s*([\"'`])",
            "Redirect - location assign": r"(?:window\.)?location(?:\.href)?\s*=\s*([\"'`])",
        }
        pat = sink_map.get(spec_name)
        if not pat:
            return False
        ctx = self.content[offset:min(len(self.content), offset + 180)]
        return bool(re.search(pat, ctx))

    def _compute_confidence(self, spec_name: str, vendor_confidence: str, source_signals: List[str], literal_assignment: bool, near_sanitizer: bool, scope_nearby: bool, offset: int = 0) -> Tuple[str, int]:
        score = 40
        if spec_name in {"XSS - innerHTML", "XSS - outerHTML", "XSS - srcdoc", "XSS - dangerouslySetInnerHTML", "XSS - eval()", "postMessage - wildcard"}:
            score += 20
        if source_signals:
            score += 20 + min(10, len(source_signals) * 4)
        if literal_assignment:
            score -= 25
        if near_sanitizer:
            score -= 20
        if scope_nearby:
            score += 10
        if spec_name.startswith("XSS -") and offset:
            cosmetic_ctx = self.content[max(0, offset - 220):min(len(self.content), offset + 220)].lower()
            if re.search(r'tooltip|spinner|icon|styleelement|responsivestyle|createhtmldocument|pdf|blob|download|table|grid|chart|canvas', cosmetic_ctx, re.I):
                score -= 18
            if re.search(r'createtextnode|appendchild\s*\(', cosmetic_ctx, re.I):
                score -= 8
        if vendor_confidence == "high":
            score -= 30
        elif vendor_confidence == "medium":
            score -= 15
        elif vendor_confidence == "low":
            score -= 5
        score = max(0, min(100, score))
        if score >= 75:
            return "high", score
        if score >= 50:
            return "medium", score
        return "low", score

    def _detect_chunks(self) -> None:
        chunks = []
        has_webpack = bool(re.search(r"webpackChunk|__webpack_require__", self.content))
        has_vite = bool(re.search(r"import\.meta\.hot|/@vite/", self.content))
        has_banner_modules = bool(re.search(r"/\*[!*]+\s+[\w./@-]+\s+\*+/", self.content))
        if not (has_webpack or has_vite or has_banner_modules):
            self.chunks, self.chunk_starts = [], []
            return
        boundaries = []
        if has_banner_modules:
            boundaries.extend(re.finditer(r"/\*[!*]+\s+([\w./@-]+)\s+\*+/", self.content))
        if has_webpack:
            boundaries.extend(re.finditer(r'"([^"]{3,80})"\s*:\s*function\s*\(', self.content))
        if has_vite:
            boundaries.extend(re.finditer(r'"([^"]{3,120})"\s*:\s*\(', self.content))
        boundaries = sorted(boundaries, key=lambda m: m.start())
        for i, m in enumerate(boundaries):
            raw_name = next((g for g in m.groups() if g), None) or f"chunk_{i}"
            start = m.start()
            end = boundaries[i + 1].start() if i + 1 < len(boundaries) else len(self.content)
            segment = self.content[start:min(start + 2000, end)]
            is_vendor = bool(_VENDOR_RE.search(segment))
            label = raw_name if not re.fullmatch(r"[a-f0-9]{3,32}", raw_name, re.I) else ""
            chunks.append(ChunkInfo(name=raw_name, start=start, end=end, is_vendor=is_vendor, label=label))
        self.chunks = chunks
        self.chunk_starts = [ch.start for ch in chunks]
        if chunks:
            vendor_count = sum(1 for ch in chunks if ch.is_vendor)
            app_count = len(chunks) - vendor_count
            print(c(CYAN, f"  [*] Módulos detectados: {len(chunks)} ({app_count} app, {vendor_count} vendor)"))

    def _add_finding(self, finding: Finding) -> None:
        key = finding.dedupe_key()
        if key in self._finding_keys:
            return
        self._finding_keys.add(key)
        if self.app_only and finding.vendor_confidence == "high":
            return
        self.findings[finding.severity].append(finding)

    def _add_endpoint(self, url: str, ep_type: str) -> None:
        url = url.strip().rstrip(".,;)")
        if not url or len(url) > 300:
            return
        key = (ep_type, url)
        if key in self._endpoint_seen:
            return
        self._endpoint_seen.add(key)
        self.endpoints.append({"url": url, "type": ep_type, "in_scope": bool(self.scope and self.scope in url), "score": self._score_endpoint(url)})

    def _score_endpoint(self, url: str) -> int:
        score = 0
        low = url.lower()
        hot_words = ["admin", "internal", "debug", "graphql", "auth", "login", "token", "callback", "upload", "import", "export", "webhook", "staff", "backoffice", "config", "metrics", "health", "test", "staging", "private", "secret", "api_key", "password", "session"]
        for h in hot_words:
            if h in low:
                score += 2
        if re.search(r"/v\d+/", low):
            score += 1
        if "{" in url or "${" in url:
            score += 1
        if low.startswith("http"):
            score += 1
        if self.scope and self.scope in low:
            score += 3
        return score

    # ── banner (V48) ─────────────────────────────────────────────────────────
    def _banner(self) -> None:
        size_kb = self.path.stat().st_size / 1024
        print(c(CYAN + BOLD, f"\n{'=' * 78}"))
        print(c(CYAN + BOLD, f"  JS Bundle Analyzer v4.8 — {self.path.name} ({size_kb:.1f} KB)"))
        if self.scope:
            print(c(CYAN + BOLD, f"  Scope: {self.scope}"))
        print(c(CYAN + BOLD, f"  Profile: {self.profile}"))
        if self.app_only:
            print(c(YELLOW + BOLD, "  Mode: APP-ONLY (vendor-high findings filtered)"))
        if self.baseline_json:
            print(c(CYAN + BOLD, f"  Baseline: {self.baseline_json}"))
        print(c(CYAN + BOLD, f"{'=' * 78}\n"))

    def _detect_frameworks(self) -> None:
        checks = [("React", [r"React\.createElement", r"ReactDOM", r"jsx\("]), ("Angular", [r"@angular/core", r"ɵɵdefineComponent"]), ("Vue", [r"createApp\s*\(", r"__vue__"]), ("Svelte", [r"\bsvelte\b", r"SvelteComponent"]), ("jQuery", [r"\bjQuery\s*\(", r"\$\s*\(\s*['\"]"]), ("Next.js", [r"__NEXT_DATA__", r"_next/"]), ("Webpack", [r"webpackChunk", r"__webpack_require__"]), ("Vite", [r"import\.meta\.hot", r"/@vite/"]), ("MediaWiki", [r"mw\.config", r"mw\.loader"]), ("Liferay", [r"\bLiferay\.", r"\bAUI\("])]
        self.frameworks = [name for name, pats in checks if any(re.search(p, self.content, re.I) for p in pats)]
        if self.frameworks:
            print(c(MAGENTA, f"  [*] Frameworks: {', '.join(self.frameworks)}"))

    def _detect_build_info(self) -> None:
        info = {}
        v = set(re.findall(r'(?:version|VERSION)\s*[:=]\s*["\'](\d+\.\d+(?:\.\d+)*)["\']', self.content))
        if v: info["versions"] = sorted(v)
        h = set(re.findall(r'(?:buildHash|BUILD_HASH|commit|COMMIT_SHA)\s*[:=]\s*["\']([a-f0-9]{7,40})["\']', self.content, re.I))
        if h: info["build_hashes"] = sorted(h)
        e = set(re.findall(r'(?:NODE_ENV|APP_ENV|ENVIRONMENT)\s*[:=]\s*["\'](\w+)["\']', self.content))
        if e: info["envs"] = sorted(e)
        self.stats["build_info"] = info
        if info:
            print(c(CYAN, f"  [*] Build info: {info}\n"))

    def _build_patterns(self) -> List[PatternSpec]:
        return [
            PatternSpec("XSS - innerHTML", r"\.innerHTML\s*=", "HIGH"),
            PatternSpec("XSS - outerHTML", r"\.outerHTML\s*=", "HIGH"),
            PatternSpec("XSS - insertAdjacentHTML", r"insertAdjacentHTML\s*\(", "HIGH"),
            PatternSpec("XSS - document.write", r"document\.write(?:ln)?\s*\(", "HIGH"),
            PatternSpec("XSS - dangerouslySetInnerHTML", r"dangerouslySetInnerHTML\s*:", "HIGH"),
            PatternSpec("XSS - eval()", r"(?<![\w.])eval\s*\(", "HIGH"),
            PatternSpec("XSS - Function()", r"new\s+Function\s*\(", "HIGH"),
            PatternSpec("XSS - srcdoc", r"\.srcdoc\s*=", "HIGH"),
            PatternSpec("XSS - jQuery .html()", r"\.\s*html\s*\(", "MEDIUM"),
            PatternSpec("Redirect - location assign", r"(?:window\.)?location(?:\.href)?\s*=", "MEDIUM"),
            PatternSpec("Redirect - location.replace", r"location\.replace\s*\(", "MEDIUM"),
            PatternSpec("Redirect - window.open", r"window\.open\s*\(", "MEDIUM"),
            PatternSpec("postMessage - listener", r"addEventListener\s*\(\s*['\"]message", "MEDIUM"),
            PatternSpec("postMessage - wildcard", r"postMessage\s*\([^)]*,\s*['\"]\*", "HIGH"),
            PatternSpec("Cookie - document.cookie write", r"document\.cookie\s*=", "MEDIUM"),
            PatternSpec("Cookie - SameSite None", r"samesite\s*:\s*['\"]?none", "MEDIUM"),
            PatternSpec("Debug - debugger", r"\bdebugger\b", "LOW"),
            PatternSpec("Debug - sourceMappingURL", r"//[#@]\s*sourceMappingURL", "INFO"),
            PatternSpec("Debug - security comment", r"(?:TODO|FIXME|HACK|XXX).{0,80}(?:security|auth|secret|vuln|xss|csrf|bypass)", "LOW"),
        ]

    def _build_secret_specs(self) -> List[SecretSpec]:
        return [
            SecretSpec("AWS Access Key", r"(AKIA[0-9A-Z]{16})", "HIGH"),
            SecretSpec("Google API Key", r"(AIza[0-9A-Za-z_-]{35})", "HIGH"),
            SecretSpec("Slack Token", r"(xox[baprs]-[0-9a-zA-Z-]{10,})", "HIGH"),
            SecretSpec("Slack Webhook", r"(https://hooks\.slack\.com/services/T\w+/B\w+/\w+)", "HIGH"),
            SecretSpec("GitHub Token", r"(gh[psu]_[A-Za-z0-9_]{20,})", "HIGH"),
            SecretSpec("JWT", r"(eyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,})", "MEDIUM"),
            SecretSpec("Stripe Key", r"(sk_live_[A-Za-z0-9]{16,}|pk_live_[A-Za-z0-9]{16,})", "HIGH"),
            SecretSpec("SendGrid Key", r"(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})", "HIGH"),
            SecretSpec("Private Key", r"(-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----)", "CRITICAL"),
            SecretSpec("DB URL", r"((?:mysql|postgres|mongodb|redis|amqp|mssql)://[^\s\"'`]+)", "HIGH"),
            SecretSpec("Generic API Key", r"(?:api[_-]?key|apikey|API_KEY)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]", "MEDIUM"),
            SecretSpec("Generic Secret", r"(?:secret|SECRET|client_secret)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]", "MEDIUM"),
        ]

