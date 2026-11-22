#!/usr/bin/env python3
"""
JS Bundle Analyzer v3.6 (base) — Recon / Bug Bounty Edition

Cambios clave sobre v3.3:
- Correlación source → sink por bloque lógico
- Auth mapper cruza storage + headers + endpoints
- Hotspots más tácticos
- Reporte de hipótesis accionables
- Mantiene confidence/vendor/chunks/sanitizer de v3.2

Uso:
    python3 js_analyzer_v4_7.py bundle.js --scope example.com --app-only --json
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
from typing import Dict, List, Tuple, Optional, Set

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
    def __init__(self, filepath: str, max_per: int = 5, scope: Optional[str] = None, app_only: bool = False):
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
        self._generate_validation_playbooks()
        self._build_action_clusters()
        self._analyze_data_flow()
        self._analyze_access_control()
        self._detect_hidden_debug()
        self._detect_source_maps()
        self._detect_error_patterns()
        self._extract_comments()
        self._analyze_file_uploads()
        self._analyze_redirect_params()
        self._extract_cors_hints()
        self._print_results()
        return self._build_report()

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

    def _banner(self) -> None:
        size_kb = self.path.stat().st_size / 1024
        print(c(CYAN + BOLD, f"\n{'=' * 78}"))
        print(c(CYAN + BOLD, f"  JS Bundle Analyzer v3.3 — {self.path.name} ({size_kb:.1f} KB)"))
        if self.scope:
            print(c(CYAN + BOLD, f"  Scope: {self.scope}"))
        if self.app_only:
            print(c(YELLOW + BOLD, f"  Mode: APP-ONLY (vendor-high findings filtered)"))
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
            SecretSpec("Generic API Key", r"(?:api[_-]?key|apikey|API_KEY)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]", "MEDIUM", flags=re.IGNORECASE),
            SecretSpec("Generic Secret", r"(?:secret|client_secret)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]", "MEDIUM", flags=re.IGNORECASE),
        ]

    def _scan_patterns(self) -> None:
        for spec in self._build_patterns():
            regex = re.compile(spec.regex, spec.flags)
            matches = list(regex.finditer(self.content))
            if not matches:
                continue
            total = len(matches)
            for m in matches[:self.max_per]:
                offset = m.start()
                vendor_confidence = self._vendor_confidence(offset)
                is_vendor = vendor_confidence in {"high", "medium"}
                func_ctx = self._get_func_context(offset)
                before, match_text, after = self._get_context(offset, m.end())
                chunk = self._chunk_at(offset)
                source_signals = self._detect_sources_nearby(offset)
                literal_assignment = self._is_literal_assignment(spec.name, offset)
                near_sanitizer = self._near_sanitizer(offset)
                scope_nearby = self._scope_nearby(offset)
                confidence, confidence_score = self._compute_confidence(spec.name, vendor_confidence, source_signals, literal_assignment, near_sanitizer, scope_nearby, offset)
                note_parts = []
                if func_ctx: note_parts.append(f"fn:{func_ctx}")
                if chunk: note_parts.append(f"chunk:{chunk.label or chunk.name}")
                if vendor_confidence != "none": note_parts.append(f"vendor:{vendor_confidence}")
                if source_signals: note_parts.append("sources:" + ",".join(source_signals))
                if near_sanitizer: note_parts.append("sanitizer:nearby")
                if literal_assignment: note_parts.append("assignment:literal")
                self._add_finding(Finding(
                    name=spec.name, severity=spec.severity, line=self._line_of(offset), offset=offset,
                    match=m.group(0)[:200], context_before=before, context_match=match_text, context_after=after,
                    total_hits_for_pattern=total, module=spec.module, note=" | ".join(note_parts + ([spec.note] if spec.note else [])),
                    is_vendor=is_vendor, vendor_confidence=vendor_confidence,
                    chunk_name=chunk.name if chunk else "", chunk_label=(chunk.label or chunk.name) if chunk else "",
                    function_context=func_ctx, confidence=confidence, confidence_score=confidence_score,
                    scope_nearby=scope_nearby, near_sanitizer=near_sanitizer,
                    source_signals=source_signals, literal_assignment=literal_assignment,
                ))

    def _extract_endpoints(self) -> None:
        skip_domains = {"w3.org", "schema.org", "mozilla.org", "reactjs.org", "formatjs.github.io", "momentjs.com", "github.com/js-cookie", "cdnjs.cloudflare.com", "fonts.googleapis.com", "fonts.gstatic.com", "unpkg.com"}
        for url in re.findall(r'https?://[^\s"\'`<>\]\[){};,]+', self.content):
            url = url.rstrip(".,;)")
            parsed = re.match(r'https?://([^/:]+)', url)
            if parsed and any(skip in parsed.group(1) for skip in skip_domains):
                continue
            self._add_endpoint(url, "hardcoded_url")
        for m in re.finditer(r'''["\'](/(?:api|graphql|rest|internal|admin|auth|oauth|login|logout|signup|register|callback|webhook|upload|download|import|export|search|user|users|account|profile|settings|config|status|health|metrics|manage|dashboard|staff|web_api|permissions|invites|sessions|notifications|projects|areas|verification)[a-zA-Z0-9/_\-.{}$:]* )["\']'''.replace(' ', ''), self.content, re.I):
            self._add_endpoint(m.group(1), "api_path")
        for m in re.finditer(r'(?:fetch|axios\.(?:get|post|put|patch|delete))\s*\(\s*["\']([^"\']+)["\']', self.content, re.I):
            self._add_endpoint(m.group(1), "fetch_call")
        for m in re.finditer(r'(?:fetch|axios)\s*\(\s*`([^`]+)`', self.content):
            self._add_endpoint(f"`{m.group(1)}`", "template_fetch")
        for m in re.finditer(r'(?:BASE_URL|baseURL|baseUrl|API_URL|apiUrl|API_BASE|apiBase|BACKEND_URL|endpoint)\s*[:=]\s*["\']([^"\']+)["\']', self.content):
            self._add_endpoint(m.group(1), "base_url")
        self.endpoints.sort(key=lambda x: (-x["score"], x["url"]))

    def _reconstruct_api_clients(self) -> None:
        clients = []
        api_calls = re.findall(r'(?:S0|apiClient|api|client)\s*\(\s*\{[^}]*path\s*:\s*["\']([^"\']+)["\'][^}]*action\s*:\s*["\']([^"\']+)["\']', self.content, re.I)
        if api_calls:
            by_method = defaultdict(list)
            for path, method in api_calls:
                by_method[method.upper()].append(path)
            clients.append({"type": "api_client_calls", "calls": {m: sorted(set(v)) for m, v in by_method.items()}})
        template_paths = re.findall(r'path\s*:\s*`(/[^`]+)`', self.content)
        if template_paths:
            clients.append({"type": "template_paths", "paths": sorted(set(template_paths))})
        axios_bases = re.findall(r'axios\.create\s*\(\s*\{[^}]*baseURL\s*:\s*["\']([^"\']+)["\']', self.content, re.I)
        if axios_bases:
            clients.append({"type": "axios_base_urls", "bases": sorted(set(axios_bases))})
        generic_api = sorted(set(re.findall(r'(?:S0|apiClient|fetchData|request|makeRequest)\s*\(\s*\{[^}]*path\s*:\s*["\']([^"\']+)["\']', self.content)))
        if generic_api:
            clients.append({"type": "generic_api_paths", "paths": generic_api})
        self.api_clients = clients

    def _extract_internal_infra(self) -> None:
        infra = {}
        private_ips = sorted(set(re.findall(r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})', self.content)))
        if private_ips: infra["private_ips"] = private_ips
        internal_hosts = sorted(set(re.findall(r'(?:https?://)?([a-zA-Z0-9_-]+\.(?:internal|local|intranet|corp|lan|dev|staging|test)\b[a-zA-Z0-9._-]*)', self.content, re.I)))
        if internal_hosts: infra["internal_hostnames"] = internal_hosts
        if self.scope:
            scope_hosts = sorted(set(re.findall(rf'([a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)*\.{re.escape(self.scope)})', self.content)))
            if scope_hosts: infra["scope_hostnames"] = scope_hosts
        emails = sorted(set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', self.content)))
        emails = [e for e in emails if not any(x in e.lower() for x in ['example.com', 'test.com', 'placeholder', 'email.com', 'domain.com'])]
        if emails: infra["emails"] = emails[:20]
        sentry_dsns = sorted(set(re.findall(r'(https?://[a-f0-9]+@[a-zA-Z0-9.-]+/\d+)', self.content)))
        if sentry_dsns: infra["sentry_dsns"] = sentry_dsns
        ai_keys = sorted(set(re.findall(r'(?:instrumentationKey|InstrumentationKey)\s*[:=]\s*["\']([a-f0-9-]{36})["\']', self.content)))
        if ai_keys: infra["app_insights_keys"] = ai_keys
        self.stats["internal_infra"] = infra

    def _extract_custom_headers(self) -> None:
        confirmed = set()
        suspicious = set()
        for block in re.finditer(r'headers\s*:\s*\{([^}]{0,800})\}', self.content, re.I | re.S):
            keys = re.findall(r'["\']([A-Za-z0-9-]{2,60})["\']\s*:', block.group(1))
            confirmed.update(k for k in keys if k.lower().startswith('x-') or k in {"Authorization", "X-Api-Key", "X-Auth-Token", "X-CSRF-Token"})
        confirmed.update(re.findall(r'(?:setRequestHeader|headers\.set)\s*\(\s*["\']([A-Za-z0-9-]{2,60})["\']', self.content, re.I))
        suspicious.update(re.findall(r'["\']([Xx]-[A-Za-z0-9-]{2,40})["\']', self.content))
        suspicious.update(h.strip("'\"") for h in re.findall(r'["\'](?:Authorization|Bearer|X-Api-Key|X-Auth-Token|X-CSRF-Token|X-Requested-With)["\']', self.content, re.I))
        noise = {"X-Requested-With", "X-Content-Type-Options", "X-Frame-Options", "X-XSS-Protection", "x-ms-request-id"}
        confirmed -= noise
        suspicious -= noise
        suspicious -= confirmed
        self.stats["custom_headers"] = {"confirmed": sorted(confirmed), "suspicious": sorted(suspicious)}

    def _extract_routes(self) -> None:
        routes = set()
        for p in [r'path\s*[:=]\s*["\']([^"\']+)["\']', r'routerLink\s*=\s*["\']([^"\']+)["\']', r'href\s*[:=]\s*["\'](/[^"\']+)["\']', r'(?:navigate|push|replace|go)\s*\(\s*["\']([^"\']+)["\']']:
            for route in re.findall(p, self.content):
                if route.startswith('/') and not route.startswith('//') and len(route) < 180 and not re.match(r'^/[a-f0-9]{20,}$', route):
                    routes.add(route)
        self.routes = sorted(routes)

    def _extract_params(self) -> None:
        params = set()
        params.update(re.findall(r'\.get\s*\(\s*["\']([a-zA-Z_][a-zA-Z0-9_-]{1,40})["\']\s*\)', self.content))
        params.update(re.findall(r'[?&]([a-zA-Z_][a-zA-Z0-9_-]{1,40})=', self.content))
        params.update(re.findall(r'(?:req|request)\.(?:query|params|body)\.([a-zA-Z_]\w+)', self.content))
        params.update(re.findall(r'\.append\s*\(\s*["\']([a-zA-Z_][a-zA-Z0-9_-]{1,40})["\']', self.content))
        noise = {"type", "value", "name", "id", "class", "style", "key", "ref", "src", "href", "alt", "title", "label", "index", "item", "children", "className", "onClick", "onChange", "onSubmit", "disabled", "placeholder", "method", "action", "target", "rel", "role", "for", "data", "content"}
        self.params = sorted(p for p in params if p not in noise and len(p) > 1)

    def _extract_storage_keys(self) -> None:
        keys = set()
        keys.update(re.findall(r'(?:localStorage|sessionStorage)\.(?:getItem|setItem|removeItem)\s*\(\s*["\']([^"\']+)["\']', self.content))
        keys.update(re.findall(r'(?:localStorage|sessionStorage)\[\s*["\']([^"\']+)["\']\s*\]', self.content))
        self.storage_keys = sorted(keys)

    def _extract_websockets(self) -> None:
        wss = set()
        wss.update(re.findall(r'wss?://[^\s"\'`<>\])}]+', self.content))
        wss.update(re.findall(r'new\s+WebSocket\s*\(\s*["\']([^"\']+)["\']', self.content))
        self.stats["websockets"] = sorted(wss)

    def _extract_graphql(self) -> None:
        ops = []
        for name in sorted(set(re.findall(r'\b(?:query|mutation|subscription)\s+(\w+)\s*(?:\([^)]*\))?\s*{', self.content))):
            ops.append({"type": "operation", "name": name})
        for ep in sorted(set(re.findall(r'["\']([^"\']*graphql[^"\']*)["\']', self.content, re.I))):
            ops.append({"type": "endpoint", "url": ep})
        if re.search(r'__schema|__type|IntrospectionQuery', self.content):
            ops.append({"type": "introspection", "note": "Introspection query found"})
        self.stats["graphql"] = ops

    def _extract_secrets(self) -> None:
        results = []
        for spec in self._build_secret_specs():
            regex = re.compile(spec.regex, spec.flags)
            for m in regex.finditer(self.content):
                value = m.group(1)
                if looks_like_placeholder(value):
                    continue
                if len(value) >= 20 and shannon_entropy(value) < 2.5 and spec.name not in {"JWT", "DB URL", "Private Key"}:
                    continue
                if self._is_vendor_context(m.start(), strict=False):
                    continue
                line_no = self._line_of(m.start())
                before, match_text, after = self._get_context(m.start(), m.end())
                preview = value[:100] + ("..." if len(value) > 100 else "")
                results.append({"type": spec.name, "severity": spec.severity, "line": line_no, "value_preview": preview, "entropy": round(shannon_entropy(value), 2)})
                self._add_finding(Finding(name=f"Secret - {spec.name}", severity=spec.severity, line=line_no, offset=m.start(), match=preview, context_before=before, context_match=match_text, context_after=after, total_hits_for_pattern=1, module="secrets", confidence="high", confidence_score=90))
        self.secrets = results

    def _decode_strings(self) -> None:
        decoded = []
        for candidate in re.findall(r'["\']([A-Za-z0-9+/=]{24,})["\']', self.content):
            if len(candidate) % 4 != 0:
                continue
            try:
                raw = base64.b64decode(candidate, validate=True)
                text = raw.decode("utf-8", errors="ignore")
                printable_ratio = sum(ch.isprintable() for ch in text) / max(1, len(text))
                if len(text) >= 6 and printable_ratio > 0.85 and shannon_entropy(text) < 4.5:
                    decoded.append({"encoding": "base64", "encoded_preview": candidate[:50], "decoded_preview": text[:140]})
            except Exception:
                pass
        self.stats["decoded_strings"] = decoded[:20]

    def _analyze_auth_flows(self) -> None:
        flows = []
        if re.search(r'(?:oauth|oidc|authorize|authorization_endpoint|token_endpoint|client_id|redirect_uri)', self.content, re.I):
            flows.append({"type": "OAuth/OIDC detected"})
        saml = set(re.findall(r'(SAMLRequest|SAMLResponse|RelayState|AssertionConsumerService)', self.content))
        if saml: flows.append({"type": "SAML", "signals": sorted(saml)})
        jwt_ops = []
        if re.search(r'jwt\.(?:verify|sign|decode)', self.content, re.I): jwt_ops.append("jwt library")
        if re.search(r'JSON\.parse\s*\(\s*atob', self.content): jwt_ops.append("manual atob decode")
        if jwt_ops: flows.append({"type": "JWT handling", "signals": jwt_ops})
        session_tokens = sorted(set(re.findall(r'(session[_-]?id|PHPSESSID|JSESSIONID|connect\.sid|csrf[_-]?token|xsrf[_-]?token|_csrf)', self.content, re.I)))
        if session_tokens: flows.append({"type": "Session/CSRF tokens", "signals": session_tokens})
        auth_urls = sorted(set(u for u in re.findall(r'["\']([^"\']*(?:login|logout|signin|signout|register|signup|auth|token|refresh|forgot|reset|confirm_code|request_code)[^"\']*)["\']', self.content, re.I) if '/' in u and len(u) < 120 and not any(x in u.lower() for x in ["node_modules", "github", "stackoverflow"])))
        if auth_urls: flows.append({"type": "Auth endpoints", "urls": auth_urls[:20]})
        self.stats["auth_flows"] = flows

    def _get_logical_block(self, offset: int, back_limit: int = 1200, forward_limit: int = 2400) -> str:
        start_search = max(0, offset - back_limit)
        end_search = min(len(self.content), offset + forward_limit)
        segment = self.content[start_search:end_search]
        rel = offset - start_search
        open_idx = segment.rfind("{", 0, rel + 1)
        if open_idx == -1:
            return segment[max(0, rel-250):min(len(segment), rel+450)]
        depth = 0
        close_idx = None
        for i in range(open_idx, len(segment)):
            ch = segment[i]
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    close_idx = i
                    break
        if close_idx is None:
            return segment[open_idx:min(len(segment), open_idx + 900)]
        return segment[open_idx:close_idx + 1]

    def _correlate_source_to_sink(self) -> None:
        correlations = []
        seen = set()
        source_patterns = {
            "query_or_hash": r"(?:searchParams|getParam|urlParam|URLSearchParams|location\.search|location\.hash|window\.location\.hash)",
            "postmessage": r"(?:event\.data|message\.data)",
            "storage": r"(?:localStorage|sessionStorage)\.(?:getItem|setItem)",
            "api_data": r"(?:response\.data|res\.data|await\s+[^;]+\.json\(|\.json\(\))",
        }
        sink_specs = [
            ("possible_open_redirect", r"(?:window\.)?location(?:\.href)?\s*=|location\.assign\(|location\.replace\(|window\.open\(", {"query_or_hash", "postmessage"}),
            ("possible_dom_xss", r"\.innerHTML\s*=|dangerouslySetInnerHTML\s*:|\.outerHTML\s*=|\.srcdoc\s*=|\.\s*html\s*\(", {"query_or_hash", "postmessage", "storage", "api_data"}),
            ("possible_postmessage_injection", r"(?<![\w.])eval\s*\(|\.innerHTML\s*=|(?:window\.)?location(?:\.href)?\s*=", {"postmessage"}),
            ("possible_client_side_ssrf", r'\bfetch\s*\(|axios\.(?:get|post|put|patch|delete)\s*\(|\.open\s*\(\s*["\'](?:GET|POST|PUT|DELETE|PATCH)["\']', {"query_or_hash"}),
        ]

        for sev_list in self.findings.values():
            for f in sev_list:
                if f.vendor_confidence == 'high':
                    continue
                block = self._get_logical_block(f.offset)
                present_sources = {name for name, pat in source_patterns.items() if re.search(pat, block, re.I)}
                if not present_sources:
                    continue
                for hyp, sink_pat, required_sources in sink_specs:
                    if not re.search(sink_pat, block, re.I):
                        continue
                    matched_sources = sorted(present_sources & required_sources)
                    if not matched_sources:
                        continue
                    key = (hyp, f.line, tuple(matched_sources), f.function_context)
                    if key in seen:
                        continue
                    seen.add(key)
                    conf = 'high' if (f.confidence_score >= 70 or len(matched_sources) > 1) else 'medium'
                    correlations.append({
                        'hypothesis': hyp,
                        'line': f.line,
                        'finding': f.name,
                        'function': f.function_context,
                        'chunk': f.chunk_label or f.chunk_name,
                        'sources': matched_sources,
                        'confidence': conf,
                        'score': min(100, f.confidence_score + (15 if conf == 'high' else 5)),
                    })

        self.stats['correlations'] = sorted(correlations, key=lambda x: (-x['score'], x['line']))[:25]

    def _source_category_for_expr(self, expr: str) -> Optional[str]:
        mapping = {
            "query_param": r"(?:searchParams|getParam|urlParam|URLSearchParams|location\.search|location\.hash|window\.location\.hash)",
            "postmessage": r"(?:event\.data|message\.data)",
            "storage": r"(?:localStorage|sessionStorage)\.(?:getItem|setItem)",
            "api_data": r"(?:response\.data|res\.data|await\s+[^;]+\.json\(|\.json\(\))",
        }
        for name, pat in mapping.items():
            if re.search(pat, expr, re.I):
                return name
        return None

    def _extract_taint_flows(self) -> None:
        flows = []
        seen = set()
        sink_specs = [
            ("dom_xss", r"(?:innerHTML|outerHTML|srcdoc)\s*=\s*(?P<expr>[^;\n]+)|insertAdjacentHTML\s*\([^,]+,\s*(?P<expr2>[^\)]+)\)|dangerouslySetInnerHTML\s*:\s*\{[^}]*__html\s*:\s*(?P<expr3>[^,}\n]+)", {"query_param", "postmessage", "storage", "api_data"}),
            ("open_redirect", r"(?:window\.)?location(?:\.href)?\s*=\s*(?P<expr>[^;\n]+)|location\.(?:assign|replace)\s*\((?P<expr2>[^\)]+)\)|window\.open\s*\((?P<expr3>[^,\)]+)", {"query_param", "postmessage"}),
            ("client_request_target", r"(?:fetch|axios\.(?:get|post|put|patch|delete))\s*\((?P<expr>[^,\)]+)", {"query_param", "storage", "postmessage"}),
        ]

        assign_re = re.compile(r'(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)')
        for m in assign_re.finditer(self.content):
            var_name = m.group(1)
            expr = m.group(2)
            source_cat = self._source_category_for_expr(expr)
            if not source_cat:
                continue
            offset = m.start()
            func_ctx = self._get_func_context(offset)
            chunk = self._chunk_at(offset)
            block = self._get_logical_block(offset, 1500, 3000)

            aliases = {var_name}
            for alias_m in assign_re.finditer(block):
                alias_name = alias_m.group(1)
                alias_expr = alias_m.group(2)
                if any(re.search(rf'\b{re.escape(existing)}\b', alias_expr) for existing in list(aliases)):
                    aliases.add(alias_name)

            for hyp, sink_pat, allowed_sources in sink_specs:
                if source_cat not in allowed_sources:
                    continue
                for sink_m in re.finditer(sink_pat, block, re.I):
                    sink_expr = sink_m.groupdict().get('expr') or sink_m.groupdict().get('expr2') or sink_m.groupdict().get('expr3') or ''
                    if not any(re.search(rf'\b{re.escape(alias)}\b', sink_expr) for alias in aliases):
                        continue
                    score = 72 + min(18, (len(aliases) - 1) * 5)
                    key = (hyp, func_ctx, var_name, sink_expr[:80])
                    if key in seen:
                        continue
                    seen.add(key)
                    flows.append({
                        "hypothesis": hyp,
                        "source_var": var_name,
                        "source_category": source_cat,
                        "aliases": sorted(aliases),
                        "line": self._line_of(offset),
                        "function": func_ctx,
                        "chunk": (chunk.label or chunk.name) if chunk else "",
                        "sink_expression": normalize_space(sink_expr)[:200],
                        "confidence": "high" if score >= 80 else "medium",
                        "score": min(95, score),
                    })

        flows = sorted(flows, key=lambda x: (-x['score'], x['line'], x['hypothesis']))[:25]
        self.stats['taint_flows'] = flows

    def _build_auth_map(self) -> None:
        tokenish_keys = [k for k in self.storage_keys if re.search(r'(token|jwt|auth|session|refresh|access)', k, re.I)]
        headers = self.stats.get('custom_headers', {})
        confirmed = headers.get('confirmed', []) if isinstance(headers, dict) else []
        suspicious = headers.get('suspicious', []) if isinstance(headers, dict) else []
        auth_endpoints = []
        for flow in self.stats.get('auth_flows', []):
            if flow.get('type') == 'Auth endpoints':
                auth_endpoints = flow.get('urls', [])
                break
        uses_bearer = bool(re.search(r'Authorization\s*[:=].{0,40}Bearer|Bearer\s+[A-Za-z]', self.content, re.I)) or 'Authorization' in confirmed or 'Authorization' in suspicious
        cookie_auth = bool(re.search(r'(document\.cookie|withCredentials|credentials\s*:\s*["\']include["\']|connect\.sid|PHPSESSID|JSESSIONID)', self.content, re.I))
        refresh_present = any(re.search(r'(refresh|token)', ep, re.I) for ep in auth_endpoints)
        auth_map = {
            'storage_keys_tokenish': tokenish_keys[:20],
            'confirmed_headers': confirmed[:20],
            'suspicious_headers': suspicious[:20],
            'auth_endpoints': auth_endpoints[:20],
            'transport': [],
        }
        if tokenish_keys and uses_bearer:
            auth_map['transport'].append('browser_storage -> Authorization/Bearer')
        if cookie_auth:
            auth_map['transport'].append('cookie/session-based auth signals')
        if refresh_present:
            auth_map['transport'].append('refresh-token-like flow present')
        if not auth_map['transport'] and auth_endpoints:
            auth_map['transport'].append('auth endpoints present, transport unclear')
        self.stats['auth_map'] = auth_map



    def _normalize_resource_base(self, endpoint: str) -> str:
        ep = (endpoint or '').strip()
        if not ep:
            return ''
        ep = re.sub(r'`', '', ep)
        ep = re.sub(r'\?.*$', '', ep)
        ep = re.sub(r'\$\{[^}]+\}', '{id}', ep)
        ep = re.sub(r'/\{[^/]+\}', '/{id}', ep)
        ep = re.sub(r'/(?:\d+|[0-9a-f]{8,}|[A-Za-z0-9_-]{12,})(?=$|/)', '/{id}', ep, flags=re.I)
        if re.match(r'^https?://', ep, re.I):
            m = re.match(r'^(https?://[^/]+)(/.*)?$', ep, re.I)
            origin = (m.group(1) if m else '').lower()
            path = (m.group(2) if m and m.group(2) else '/')
            if self.scope and self.scope.lower() not in origin:
                return ''
            ep = origin + re.sub(r'//+', '/', path)
        else:
            ep = re.sub(r'//+', '/', ep)
        return ep.rstrip('/') or ep

    def _is_internal_resource_candidate(self, endpoint: str, ep_type: str = '') -> bool:
        ep = (endpoint or '').strip().lower()
        t = (ep_type or '').lower()
        if not ep:
            return False
        if ep.startswith(('http://', 'https://')):
            return bool(self.scope and self.scope.lower() in ep)
        if not ep.startswith(('/', './', '../')):
            return False
        if t == 'hardcoded_url':
            return False
        if re.search(r'\.(?:pdf|csv|png|jpg|jpeg|svg|gif|woff2?|ttf|eot)(?:$|\?)', ep):
            return False
        if re.search(r'(?:github|g\.co|ietf|w3\.org|data\.gv\.at)', ep):
            return False
        return True

    def _entity_candidates_from_text(self, text: str) -> List[str]:
        vocab = [
            'user', 'benutzer', 'account', 'konto', 'profile', 'profil', 'member', 'mitglied', 'role', 'rolle', 'permission', 'berechtigung', 'admin', 'team', 'organisation', 'organization', 'tenant', 'workspace', 'arbeitsbereich',
            'project', 'projekt', 'proposal', 'vorschlag', 'vote', 'abstimmung', 'comment', 'kommentar', 'message', 'nachricht', 'chat', 'document', 'dokument', 'report', 'bericht', 'export', 'pdf', 'file', 'datei', 'media', 'content', 'inhalt',
            'application', 'antrag', 'submission', 'einreichung', 'order', 'bestellung', 'invoice', 'rechnung', 'payment', 'zahlung', 'billing', 'refund', 'erstattung', 'booking', 'buchung', 'notification', 'benachrichtigung', 'email', 'status'
        ] + self.profile_keywords
        found = []
        low = (text or '').lower()
        for word in vocab:
            if re.search(rf'(^|[^a-zäöüß]){re.escape(word.lower())}(?:[^a-zäöüß]|$)', low):
                found.append(word.lower())
        return sorted(set(found))[:14]

    def _build_resource_groups(self) -> None:
        groups = {}
        for ep in self.endpoints:
            url = ep.get('url', '')
            ep_type = ep.get('type', '')
            if not self._is_internal_resource_candidate(url, ep_type):
                continue
            base = self._normalize_resource_base(url)
            if not base or '/' not in base:
                continue
            grp = groups.setdefault(base, {
                'resource': base,
                'methods': set(),
                'sample_endpoints': set(),
                'entities': set(),
                'reads': 0,
                'writes': 0,
                'id_path_present': '{id}' in base,
                'method_sources': set(),
            })
            grp['sample_endpoints'].add(url)
            m = re.search(r'http_(get|post|put|patch|delete)_expr', ep_type, re.I)
            method = m.group(1).upper() if m else ('GET' if ep_type in {'fetch_call','template_fetch'} else '')
            if method:
                grp['methods'].add(method)
                grp['method_sources'].add(ep_type)
                if method == 'GET':
                    grp['reads'] += 1
                else:
                    grp['writes'] += 1
            grp['entities'].update(self._entity_candidates_from_text(url))
        out = []
        for _, grp in groups.items():
            if len(grp['methods']) < 2:
                continue
            if grp['writes'] == 0:
                continue
            score = 20 + len(grp['methods']) * 8 + (14 if grp['id_path_present'] else 0) + min(14, grp['writes'] * 4) + min(8, len(grp['entities']) * 2)
            if {'GET', 'POST'} <= grp['methods']:
                score += 6
            if grp['id_path_present'] and ({'PUT', 'DELETE'} & grp['methods']):
                score += 10
            out.append({
                'resource': grp['resource'],
                'methods': sorted(grp['methods']),
                'methods_on_id_path': sorted([m for m in grp['methods'] if grp['id_path_present'] and m in {'GET', 'PUT', 'PATCH', 'DELETE'}]),
                'id_path_present': grp['id_path_present'],
                'sample_endpoints': sorted(grp['sample_endpoints'])[:8],
                'entities': sorted(grp['entities'])[:8],
                'reads': grp['reads'],
                'writes': grp['writes'],
                'confidence': 'high' if score >= 74 else 'medium' if score >= 52 else 'low',
                'score': min(92, score),
                'hypotheses': ['resource_crud_surface', 'resource_authz_candidate'],
            })
        self.resource_groups = sorted(out, key=lambda x: (-x['score'], x['resource']))[:20]
        self.stats['resource_groups'] = self.resource_groups

    def _build_entities_map(self) -> None:
        entity_map = {}
        for rg in self.resource_groups:
            for ent in rg.get('entities', []):
                entry = entity_map.setdefault(ent, {'entity': ent, 'actions': set(), 'resources': set(), 'fields': set(), 'score': 18})
                entry['actions'].update(rg.get('methods', []))
                entry['resources'].add(rg.get('resource', ''))
                entry['score'] += len(rg.get('methods', [])) * 4
        for mut in self.critical_mutations:
            text = ' '.join([mut.get('endpoint',''), mut.get('function',''), ' '.join(mut.get('sensitive_fields', []))])
            ents = self._entity_candidates_from_text(text)
            for ent in ents:
                entry = entity_map.setdefault(ent, {'entity': ent, 'actions': set(), 'resources': set(), 'fields': set(), 'score': 18})
                entry['actions'].add(mut.get('method',''))
                entry['resources'].add(mut.get('endpoint',''))
                entry['fields'].update(mut.get('sensitive_fields', []))
                entry['score'] += 8
        out = []
        for ent, data in entity_map.items():
            out.append({
                'entity': ent,
                'actions': sorted(x for x in data['actions'] if x),
                'resources': sorted(x for x in data['resources'] if x)[:8],
                'fields': sorted(data['fields'])[:12],
                'confidence': 'high' if data['score'] >= 44 else 'medium',
                'score': min(100, data['score'])
            })
        self.entities_map = sorted(out, key=lambda x: (-x['score'], x['entity']))[:20]
        self.stats['entities_map'] = self.entities_map

    def _detect_authz_surfaces(self) -> None:
        out = []
        gate_patterns = {
            'role_check': r'isAdmin|hasRole|hasPermission|canEdit|canDelete|isOwner|isAuthenticated|isAuthorized|role|rolle|permission|berechtigung|admin|moderator|manager',
            'tenant_boundary': r'tenantId|workspaceId|organisationId|organizationId|teamId|mandantId|arbeitsbereichId',
            'ownership_boundary': r'ownerId|createdBy|created_by|memberId|userId|accountId|benutzerId|kontoId|eigentuemerId|eigentümerId',
        }
        for mut in self.critical_mutations:
            text = ' '.join([
                mut.get('endpoint', ''),
                mut.get('function', ''),
                ' '.join(mut.get('route_signals', [])),
                ' '.join(mut.get('sensitive_fields', [])),
                mut.get('body_preview', ''),
            ])
            direct_signals = [name for name, pat in gate_patterns.items() if re.search(pat, text, re.I)]
            signals = list(direct_signals)
            if mut.get('id_in_path') and direct_signals:
                signals.append('id_target_surface')
            auth_hint_count = len(mut.get('auth_signals', []))
            if not signals and auth_hint_count == 0:
                continue
            score = 36 + len(set(direct_signals)) * 10 + (8 if 'id_target_surface' in signals else 0) + (8 if mut.get('method') in {'PUT', 'PATCH', 'DELETE'} else 0) + min(8, auth_hint_count * 4)
            if len(set(direct_signals)) == 0 and auth_hint_count < 2:
                continue
            hypotheses = ['authz_surface_candidate']
            if 'ownership_boundary' in signals:
                hypotheses.append('ownership_boundary_candidate')
            if 'role_check' in signals:
                hypotheses.append('role_boundary_candidate')
            if 'tenant_boundary' in signals:
                hypotheses.append('tenant_boundary_candidate')
            out.append({
                'endpoint': mut.get('endpoint', ''),
                'method': mut.get('method', ''),
                'line': mut.get('line'),
                'signals': sorted(set(signals)),
                'hypotheses': hypotheses,
                'confidence': 'high' if score >= 74 else 'medium',
                'score': min(88, score),
            })
        self.authz_surfaces = sorted(out, key=lambda x: (-x['score'], str(x.get('endpoint', ''))))[:20]
        self.stats['authz_surfaces'] = self.authz_surfaces

    def _detect_workflow_surfaces(self) -> None:
        out = []
        workflow_terms = ['approve', 'reject', 'publish', 'archive', 'submit', 'verify', 'confirm', 'activate', 'deactivate', 'assign', 'invite', 'revoke', 'refund', 'cancel', 'genehmigen', 'ablehnen', 'veroeffentlichen', 'veröffentlichen', 'archivieren', 'einreichen', 'pruefen', 'prüfen', 'bestaetigen', 'bestätigen', 'aktivieren', 'deaktivieren', 'zuweisen', 'einladen', 'widerrufen', 'stornieren']
        for mut in self.critical_mutations:
            text = ' '.join([mut.get('endpoint',''), mut.get('function',''), ' '.join(mut.get('route_signals', [])), ' '.join(mut.get('sensitive_fields', []))])
            matched = sorted(set(t for t in workflow_terms if re.search(rf'(^|[^a-z]){re.escape(t)}(?:[^a-z]|$)', text, re.I)))
            status_like = any(re.search(r'status|state|publish|approve|verify|active|veroeffentlichen|veröffentlichen|genehmigen|aktiv', f, re.I) for f in mut.get('sensitive_fields', []))
            if not matched and not status_like:
                continue
            score = 48 + len(matched) * 8 + (10 if status_like else 0)
            hyps = ['workflow_transition_surface']
            if any(x in matched for x in ['approve', 'publish', 'verify']):
                hyps.append('approval_bypass_candidate')
            if any(x in matched for x in ['assign', 'invite', 'revoke']):
                hyps.append('role_assignment_surface')
            out.append({
                'endpoint': mut.get('endpoint',''),
                'method': mut.get('method',''),
                'line': mut.get('line'),
                'terms': matched,
                'status_like_fields': [f for f in mut.get('sensitive_fields', []) if re.search(r'status|state|publish|approve|verify|active', f, re.I)][:8],
                'hypotheses': hyps,
                'confidence': 'high' if score >= 74 else 'medium',
                'score': min(95, score),
            })
        self.workflow_surfaces = sorted(out, key=lambda x: (-x['score'], str(x.get('endpoint',''))))[:20]
        self.stats['workflow_surfaces'] = self.workflow_surfaces

    def _detect_write_effect_chains(self) -> None:
        out = []
        effect_terms = ['export', 'download', 'report', 'bericht', 'pdf', 'preview', 'vorschau', 'render', 'detail', 'details', 'notification', 'benachrichtigung', 'email', 'mail', 'public', 'oeffentlich', 'öffentlich', 'share', 'teilen']
        for mut in self.critical_mutations:
            if mut.get('method') not in {'POST', 'PUT', 'PATCH', 'DELETE'}:
                continue
            base = self._normalize_resource_base(mut.get('endpoint', '')).replace('/{id}', '')
            if not base:
                continue
            block = self._get_logical_block(self.line_offsets[max(0, (mut.get('line') or 1) - 1)], 1200, 2800).lower()
            endpoint_text = (mut.get('endpoint', '') + ' ' + mut.get('function', '') + ' ' + ' '.join(mut.get('route_signals', []))).lower()
            matched = []
            for term in effect_terms:
                direct_endpoint_link = term in endpoint_text
                nearby_block_link = bool(re.search(rf'(^|[^a-z]){re.escape(term)}(?:[^a-z]|$)', block, re.I))
                if direct_endpoint_link and nearby_block_link:
                    matched.append(term)
                elif direct_endpoint_link and term in {'export', 'download', 'report', 'pdf'}:
                    matched.append(term)
            matched = sorted(set(matched))
            if not matched:
                continue
            score = 42 + len(matched) * 8
            hyps = []
            if any(x in matched for x in ['export', 'download', 'report', 'pdf']):
                hyps.append('write_then_export_surface')
            if any(x in matched for x in ['preview', 'render', 'detail', 'public', 'share']):
                hyps.append('write_then_render_surface')
            if any(x in matched for x in ['notification', 'email']):
                hyps.append('write_then_notify_surface')
            out.append({
                'endpoint': mut.get('endpoint', ''),
                'method': mut.get('method', ''),
                'line': mut.get('line'),
                'effects': matched,
                'hypotheses': hyps,
                'confidence': 'high' if score >= 74 else 'medium',
                'score': min(82, score),
            })
        dedup = {}
        for item in out:
            key = (item.get('endpoint'), tuple(item.get('effects', [])))
            prev = dedup.get(key)
            if not prev or item.get('score', 0) > prev.get('score', 0):
                dedup[key] = item
        self.write_effect_chains = sorted(dedup.values(), key=lambda x: (-x['score'], str(x.get('endpoint', ''))))[:20]
        self.stats['write_effect_chains'] = self.write_effect_chains


    def _detect_document_export_flows(self) -> None:
        out = []
        seen = set()
        doc_terms = ['export', 'download', 'report', 'bericht', 'pdf', 'print', 'druck', 'invoice', 'rechnung', 'receipt', 'summary', 'preview', 'vorschau', 'document', 'dokument', 'template']
        file_fields_re = r'(file|datei|document|dokument|pdf|report|export|template|html|content|title|description|name|filename|path|url|link)'
        for mut in self.critical_mutations:
            endpoint_text = ' '.join([
                mut.get('endpoint', ''),
                mut.get('function', ''),
                ' '.join(mut.get('route_signals', [])),
                ' '.join(mut.get('sensitive_fields', [])),
                mut.get('body_preview', ''),
            ]).lower()
            matched_terms = sorted(set(t for t in doc_terms if t in endpoint_text))
            matched_fields = [f for f in mut.get('sensitive_fields', []) if re.search(file_fields_re, f, re.I)]
            if not matched_terms and not matched_fields:
                continue
            score = 52 + len(matched_terms) * 7 + min(16, len(matched_fields) * 4)
            if any(t in matched_terms for t in ['export', 'download', 'report', 'pdf']):
                score += 8
            hypotheses = ['document_or_export_surface']
            if any(t in matched_terms for t in ['template', 'preview', 'print', 'pdf']):
                hypotheses.append('trusted_output_tamper_candidate')
            if any(t in matched_terms for t in ['invoice', 'receipt', 'summary', 'report']):
                hypotheses.append('document_integrity_candidate')
            key = (mut.get('method'), mut.get('endpoint'))
            if key in seen:
                continue
            seen.add(key)
            out.append({
                'endpoint': mut.get('endpoint', ''),
                'method': mut.get('method', ''),
                'line': mut.get('line'),
                'terms': matched_terms[:10],
                'fields': matched_fields[:10],
                'hypotheses': hypotheses,
                'confidence': 'high' if score >= 76 else 'medium',
                'score': min(96, score),
            })
        self.document_export_flows = sorted(out, key=lambda x: (-x['score'], str(x.get('endpoint', ''))))[:20]
        self.stats['document_export_flows'] = self.document_export_flows

    def _detect_realtime_surfaces(self) -> None:
        out = []
        seen = set()
        ws_urls = self.stats.get('websockets', []) or []
        event_patterns = {
            'message_type': r"(?:type|event|event_type|action|command)[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_.:-]{3,80})[\"']",
            'session_param': r'(?:uid|uuid|userId|user_id|sessionId|session_id|conversationId|conversation_id|roomId|room_id|channel|token|auth|handover)'
        }
        for ws in ws_urls:
            base_score = 50
            signals = []
            if re.search(r'uid=|token=|session|conversation|room|channel', ws, re.I):
                base_score += 14
                signals.append('identifier_in_ws_url')
            if re.search(r'admin|handover|chat|notify|message|execution|agent', ws, re.I):
                base_score += 10
                signals.append('privileged_or_chat_channel')
            if self.scope and self.scope.lower() in ws.lower():
                base_score += 8
                signals.append('in_scope_ws')
            events = sorted(set(re.findall(event_patterns['message_type'], self.content)))[:12]
            has_session_terms = bool(re.search(event_patterns['session_param'], self.content, re.I))
            if has_session_terms:
                base_score += 8
                signals.append('session_binding_terms')
            hypotheses = ['realtime_surface']
            if 'identifier_in_ws_url' in signals:
                hypotheses.append('session_binding_candidate')
            if 'privileged_or_chat_channel' in signals:
                hypotheses.append('chat_or_handover_surface')
            key = ('ws', ws)
            if key in seen:
                continue
            seen.add(key)
            out.append({
                'protocol': 'websocket',
                'endpoint': ws,
                'line': None,
                'events': events,
                'signals': signals,
                'hypotheses': hypotheses,
                'confidence': 'high' if base_score >= 76 else 'medium',
                'score': min(95, base_score),
            })

        # postMessage / SSE / realtime event surface without explicit ws URL
        for m in re.finditer(r"addEventListener\s*\(\s*[\"']message[\"']|EventSource\s*\(|new\s+WebSocket\s*\(", self.content, re.I):
            offset = m.start()
            func_ctx = self._get_func_context(offset)
            block = self._get_logical_block(offset, 900, 2400)
            events = sorted(set(re.findall(event_patterns['message_type'], block)))[:10]
            signals = []
            if re.search(r'origin|source', block, re.I):
                signals.append('origin_logic_present')
            if re.search(event_patterns['session_param'], block, re.I):
                signals.append('session_binding_terms')
            if re.search(r'handover|chat|conversation|typing|agent|message|notify', block, re.I):
                signals.append('message_flow_terms')
            score = 42 + len(signals) * 8 + len(events) * 2
            hypotheses = ['realtime_event_surface']
            if 'session_binding_terms' in signals:
                hypotheses.append('identifier_bound_channel_candidate')
            if 'message_flow_terms' in signals:
                hypotheses.append('message_injection_or_leak_candidate')
            key = ('rt', func_ctx, m.group(0))
            if key in seen:
                continue
            seen.add(key)
            out.append({
                'protocol': 'event_surface',
                'endpoint': func_ctx or m.group(0),
                'line': self._line_of(offset),
                'events': events,
                'signals': signals,
                'hypotheses': hypotheses,
                'confidence': 'high' if score >= 74 else 'medium',
                'score': min(90, score),
            })
        self.realtime_surfaces = sorted(out, key=lambda x: (-x['score'], str(x.get('endpoint', ''))))[:20]
        self.stats['realtime_surfaces'] = self.realtime_surfaces

    def _detect_create_render_correlations(self) -> None:
        out = []
        seen = set()
        render_terms = ['render', 'preview', 'detail', 'details', 'viewer', 'display', 'show', 'public', 'share', 'feed', 'list', 'card', 'modal']
        for hint in self.stored_xss_hints:
            endpoint = hint.get('endpoint', '')
            base = self._normalize_resource_base(endpoint).replace('/{id}', '')
            html_fields = hint.get('html_like_fields', [])
            related_routes = [r for r in self.routes if base and any(seg and seg in r for seg in [base.split('/')[-1], *(html_fields[:2])])]
            matching_effects = [x for x in self.write_effect_chains if x.get('endpoint') == endpoint or (base and base in x.get('endpoint', ''))]
            render_matches = []
            for term in render_terms:
                if re.search(rf'(^|[^a-z]){re.escape(term)}(?:[^a-z]|$)', (endpoint + ' ' + hint.get('function', '') + ' ' + ' '.join(related_routes)).lower()):
                    render_matches.append(term)
            score = 56 + len(html_fields) * 4 + min(14, len(related_routes) * 3) + min(12, len(matching_effects) * 5) + len(render_matches) * 3
            hypotheses = ['create_render_chain']
            if matching_effects:
                hypotheses.append('write_then_render_surface')
            if related_routes:
                hypotheses.append('stored_content_route_match')
            key = (endpoint, tuple(html_fields[:4]))
            if key in seen:
                continue
            seen.add(key)
            out.append({
                'write_endpoint': endpoint,
                'method': hint.get('method', ''),
                'line': hint.get('line'),
                'fields': html_fields[:10],
                'related_routes': related_routes[:8],
                'render_terms': sorted(set(render_matches))[:8],
                'linked_effects': [x.get('effects', []) for x in matching_effects[:4]],
                'hypotheses': hypotheses,
                'confidence': 'high' if score >= 76 else 'medium',
                'score': min(96, score),
            })
        self.create_render_correlations = sorted(out, key=lambda x: (-x['score'], str(x.get('write_endpoint', ''))))[:20]
        self.stats['create_render_correlations'] = self.create_render_correlations

    def _playbook_template(self, category: str) -> Dict:
        templates = {
            "possible_open_redirect": {
                "goal": "Verificar si navegación controlada por el usuario permite redirigir fuera del dominio esperado",
                "payload_classes": ["absolute_url", "scheme_relative", "encoded_external_target", "parser_confusion_variants"],
                "manual_checks": [
                    "Confirmar si la validación ocurre antes o después de normalizar la URL",
                    "Revisar si comparan substring/dominios de forma débil en vez de usar hostname exacto",
                    "Probar si bloquean http(s) pero aceptan formas relativas o doble slash"
                ],
                "evidence_to_collect": [
                    "Valor original del parámetro controlado",
                    "Destino final luego del parseo y navegación",
                    "Cualquier lógica de allowlist o regex cercana",
                    "Si el redirect ocurre dentro de login/logout/callback"
                ],
                "impact_hypothesis": "Phishing desde dominio legítimo o alteración de flujos de autenticación"
            },
            "possible_dom_xss": {
                "goal": "Verificar si input controlable termina renderizado como HTML o ejecuta JS en el DOM",
                "payload_classes": ["html_injection", "attribute_injection", "event_handler_probe", "svg_or_srcdoc_probe"],
                "manual_checks": [
                    "Confirmar si la fuente viene de URL, postMessage, storage o respuesta de API",
                    "Verificar si hay sanitización efectiva o solo filtros parciales",
                    "Comparar renderizado real vs escape esperado"
                ],
                "evidence_to_collect": [
                    "Fuente exacta del input",
                    "Valor antes de llegar al sink HTML",
                    "Comportamiento del DOM resultante",
                    "Presencia o ausencia de sanitización cercana"
                ],
                "impact_hypothesis": "DOM XSS, UI redressing o inyección de contenido confiado"
            },
            "possible_postmessage_injection": {
                "goal": "Verificar si mensajes cross-origin pueden influir sinks sensibles sin validar origin/data",
                "payload_classes": ["cross_origin_message", "structured_object_message", "string_message", "redirect_or_html_message"],
                "manual_checks": [
                    "Revisar si existe chequeo explícito de origin/source",
                    "Confirmar qué campos de event.data son confiados",
                    "Ver si el mensaje llega a sinks como innerHTML, location o eval"
                ],
                "evidence_to_collect": [
                    "Origin enviado y origin aceptado",
                    "Payload entregado en event.data",
                    "Función receptora y sink alcanzado",
                    "Resultado visible en UI o navegación"
                ],
                "impact_hypothesis": "Cross-window injection, redirect o DOM compromise mediante mensajes no confiables"
            },
            "possible_client_side_ssrf": {
                "goal": "Verificar si el cliente arma destinos de request a partir de input controlable",
                "payload_classes": ["path_override", "absolute_url_override", "protocol_relative_target", "template_string_injection"],
                "manual_checks": [
                    "Determinar si fetch/axios permite sobreescribir host/path",
                    "Confirmar si la validación asume rutas relativas pero acepta URL completa",
                    "Revisar si se exponen requests internas, metadata o endpoints privilegiados"
                ],
                "evidence_to_collect": [
                    "Input controlado y URL final solicitada",
                    "Diferencias entre host esperado y host real",
                    "Headers/auth enviados en la request final",
                    "Respuesta observable o error diferencial"
                ],
                "impact_hypothesis": "Abuso de requests autenticadas del navegador o alcance a destinos no previstos"
            },
            "auth_token_exposure": {
                "goal": "Verificar si tokens o sesiones quedan expuestos en storage, headers o flujos recuperables",
                "payload_classes": ["storage_token_reuse", "bearer_replay", "session_cookie_vs_header_diff"],
                "manual_checks": [
                    "Confirmar si access/refresh tokens viven en localStorage/sessionStorage",
                    "Cruzar headers Authorization con endpoints sensibles detectados",
                    "Comparar comportamiento con cookie sola vs bearer solo"
                ],
                "evidence_to_collect": [
                    "Claves token-ish en storage",
                    "Headers de auth confirmados",
                    "Endpoints de login/refresh/logout",
                    "Diferencias de respuesta según transporte de auth"
                ],
                "impact_hypothesis": "Secuestro de sesión, reuse de tokens o auth inconsistente explotable"
            },
            "idor_or_authz_hint": {
                "goal": "Verificar si endpoints con IDs/objetos permiten acceso horizontal o vertical indebido",
                "payload_classes": ["id_swap", "numeric_increment", "uuid_swap", "method_variation"],
                "manual_checks": [
                    "Comparar mismo endpoint con usuario A vs usuario B",
                    "Probar cambios de ID en path/body/query",
                    "Observar diferencias sutiles en status, longitud o campos JSON"
                ],
                "evidence_to_collect": [
                    "Objeto propio vs objeto ajeno",
                    "Request original y request mutada",
                    "Status, tamaño y estructura JSON de ambas respuestas",
                    "Campos sensibles devueltos o acciones permitidas"
                ],
                "impact_hypothesis": "BOLA/IDOR o escalada de privilegios por autorización defectuosa"
            }
        }
        return templates.get(category, {})

    def _generate_validation_playbooks(self) -> None:
        playbooks = []
        seen = set()

        for item in self.stats.get("correlations", []):
            category = item.get("hypothesis")
            if category not in {
                "possible_open_redirect",
                "possible_dom_xss",
                "possible_postmessage_injection",
                "possible_client_side_ssrf",
            }:
                continue
            tpl = self._playbook_template(category)
            if not tpl:
                continue
            key = (category, item.get("line"), item.get("function"))
            if key in seen:
                continue
            seen.add(key)
            playbooks.append({
                "category": category,
                "line": item.get("line"),
                "confidence": item.get("confidence"),
                "score": item.get("score"),
                "source_signals": item.get("sources", []),
                "sink_finding": item.get("finding"),
                "function": item.get("function"),
                "chunk": item.get("chunk"),
                **tpl,
            })

        for item in self.stats.get("taint_flows", []):
            category_map = {
                "dom_xss": "possible_dom_xss",
                "open_redirect": "possible_open_redirect",
                "client_request_target": "possible_client_side_ssrf",
            }
            category = category_map.get(item.get("hypothesis"))
            if not category:
                continue
            tpl = self._playbook_template(category)
            key = (category, item.get("line"), item.get("function"), item.get("source_var"))
            if key in seen:
                continue
            seen.add(key)
            playbooks.append({
                "category": category,
                "line": item.get("line"),
                "confidence": item.get("confidence"),
                "score": item.get("score"),
                "source_signals": [item.get("source_category")],
                "sink_finding": item.get("sink_expression"),
                "function": item.get("function"),
                "chunk": item.get("chunk"),
                "taint_source_var": item.get("source_var"),
                "taint_aliases": item.get("aliases", []),
                **tpl,
            })

        auth_map = self.stats.get("auth_map", {})
        if auth_map.get("storage_keys_tokenish") or auth_map.get("transport"):
            category = "auth_token_exposure"
            tpl = self._playbook_template(category)
            playbooks.append({
                "category": category,
                "line": None,
                "confidence": "medium" if auth_map.get("transport") else "low",
                "score": 68 if auth_map.get("transport") else 52,
                "source_signals": auth_map.get("storage_keys_tokenish", []),
                "sink_finding": "auth_map",
                "function": "",
                "chunk": "",
                **tpl,
            })

        idor_candidates = [ep for ep in self.endpoints if re.search(r"/(?:users?|accounts?|projects?|documents?|orders?|exports?|admin|staff|teams?)/", ep.get("url", ""), re.I)]
        if idor_candidates:
            category = "idor_or_authz_hint"
            tpl = self._playbook_template(category)
            playbooks.append({
                "category": category,
                "line": None,
                "confidence": "medium",
                "score": min(85, 55 + len(idor_candidates) * 3),
                "source_signals": [ep["url"] for ep in idor_candidates[:5]],
                "sink_finding": "endpoint_profile",
                "function": "",
                "chunk": "",
                **tpl,
            })

        playbooks = sorted(playbooks, key=lambda x: (-(x.get("score") or 0), str(x.get("line") or "")))
        self.validation_playbooks = playbooks[:20]
        self.stats["validation_playbooks"] = self.validation_playbooks

    def _build_action_clusters(self) -> None:
        cluster_specs = [
            {
                "name": "Account / Auth",
                "keywords": [r"login", r"logout", r"signin", r"signout", r"register", r"signup", r"token", r"refresh", r"session", r"password", r"mfa", r"2fa", r"verify", r"confirm", r"oauth", r"saml", r"auth"],
                "endpoint": r"/(?:login|logout|signin|signout|register|signup|auth|oauth|token|refresh|forgot|reset|confirm|verify|session|mfa|2fa)\b",
                "finding": ["Redirect - location assign", "Redirect - location.replace", "Cookie - document.cookie write"],
                "playbook": ["possible_open_redirect", "auth_token_exposure"],
                "storage": r"(token|auth|session|refresh|csrf|xsrf)",
                "params": r"(next|return|redirect|callback|success|error|token|code|state)",
                "headers": r"(Authorization|X-Auth-Token|X-CSRF-Token)",
            },
            {
                "name": "Admin / User Management",
                "keywords": [r"admin", r"staff", r"manager", r"moderator", r"invite", r"role", r"permission", r"member", r"organization", r"team", r"user", r"account", r"delete", r"suspend"],
                "endpoint": r"/(?:admin|staff|users?|members?|roles?|permissions?|invites?|teams?|organizations?)\b",
                "finding": ["XSS - innerHTML", "Redirect - location assign"],
                "playbook": ["idor_or_authz_hint", "auth_token_exposure"],
                "params": r"(user|member|role|permission|invite|account|admin)",
                "headers": r"(Authorization|X-Auth-Token)",
            },
            {
                "name": "File Operations",
                "keywords": [r"upload", r"import", r"export", r"attach", r"file", r"csv", r"pdf", r"download", r"media", r"image"],
                "endpoint": r"/(?:upload|import|export|attach|download|files?|media)\b",
                "finding": ["XSS - innerHTML", "possible_client_side_ssrf"],
                "playbook": ["possible_client_side_ssrf"],
                "params": r"(file|filename|path|export|import|format)",
            },
            {
                "name": "Real-time / Messaging",
                "keywords": [r"websocket", r"socket", r"chat", r"message", r"handover", r"typing", r"conversation", r"notify", r"event"],
                "endpoint": r"(?:wss?://|/(?:ws|socket|chat|messages?|notifications?|handover))",
                "finding": ["postMessage - listener", "postMessage - wildcard", "possible_postmessage_injection"],
                "playbook": ["possible_postmessage_injection"],
                "params": r"(message|chat|uid|conversation|room|channel)",
            },
            {
                "name": "Search / Dynamic Queries",
                "keywords": [r"search", r"filter", r"query", r"sort", r"graphql", r"template", r"suggest", r"autocomplete", r"facet"],
                "endpoint": r"/(?:search|filter|query|graphql|suggest|autocomplete|facets?)\b",
                "finding": ["possible_client_side_ssrf", "possible_dom_xss"],
                "playbook": ["possible_client_side_ssrf", "possible_dom_xss"],
                "params": r"(q|query|search|filter|sort|order|template|index)",
            },
        ]

        all_findings = [f for sev in self.findings.values() for f in sev]
        endpoint_urls = [ep.get("url", "") for ep in self.endpoints]
        auth_map = self.stats.get("auth_map", {})
        playbooks = self.validation_playbooks or []
        taint_flows = self.stats.get("taint_flows", [])
        correlations = self.stats.get("correlations", [])
        methods = Counter(re.findall(r'\b(GET|POST|PUT|PATCH|DELETE)\b', self.content, re.I))

        clusters = []
        for spec in cluster_specs:
            matched_endpoints = [u for u in endpoint_urls if re.search(spec.get("endpoint", r"$^"), u, re.I)]
            matched_findings = [f for f in all_findings if f.name in spec.get("finding", []) or any(k.lower() in (f.name + " " + f.note).lower() for k in [spec["name"].split(" /")[0].lower()])]
            matched_playbooks = [p for p in playbooks if p.get("category") in spec.get("playbook", [])]
            matched_taints = [t for t in taint_flows if spec["name"].split(" /")[0].lower() in (t.get("sink_expression", "") + " " + t.get("function", "")).lower()]
            matched_correlations = [c for c in correlations if c.get("hypothesis") in spec.get("playbook", [])]

            keyword_hits = []
            for kw in spec.get("keywords", []):
                count = len(re.findall(kw, self.content, re.I))
                if count:
                    keyword_hits.append((kw, count))

            matched_params = [p for p in self.params if re.search(spec.get("params", r"$^"), p, re.I)]
            matched_storage = [k for k in self.storage_keys if re.search(spec.get("storage", r"$^"), k, re.I)] if spec.get("storage") else []
            header_pool = auth_map.get("confirmed_headers", []) + auth_map.get("suspicious_headers", []) + self.stats.get("custom_headers", {}).get("confirmed", [])
            matched_headers = [h for h in header_pool if re.search(spec.get("headers", r"$^"), h, re.I)] if spec.get("headers") else []

            if spec["name"] == "Real-time / Messaging" and self.stats.get("websockets"):
                matched_endpoints.extend(self.stats.get("websockets", []))
            if spec["name"] == "File Operations":
                for item in self.stats.get("file_uploads", []):
                    matched_endpoints.extend(item.get("urls", []))
            if spec["name"] == "Account / Auth":
                matched_endpoints.extend(auth_map.get("auth_endpoints", []))

            score = 0
            score += min(25, len(matched_endpoints) * 4)
            score += min(20, len(keyword_hits) * 3)
            score += min(18, len(matched_findings) * 5)
            score += min(18, len(matched_playbooks) * 6)
            score += min(12, len(matched_params) * 2)
            score += min(8, len(matched_storage) * 2)
            score += min(8, len(set(matched_headers)) * 3)
            score += min(10, len(matched_correlations) * 4 + len(matched_taints) * 5)
            if spec["name"] in {"Account / Auth", "Admin / User Management"} and any(m in methods for m in ["POST", "PUT", "PATCH", "DELETE"]):
                score += 6
            if spec["name"] == "Real-time / Messaging" and self.stats.get("websockets"):
                score += 8
            if spec["name"] == "Search / Dynamic Queries" and self.stats.get("graphql"):
                score += 6

            score = min(100, score)
            if score < 12:
                continue

            confidence = "high" if score >= 60 else "medium" if score >= 32 else "low"
            cluster = {
                "name": spec["name"],
                "score": score,
                "confidence": confidence,
                "endpoint_count": len(set(matched_endpoints)),
                "signal_counts": {
                    "keywords": sum(c for _, c in keyword_hits),
                    "findings": len(matched_findings),
                    "playbooks": len(matched_playbooks),
                    "params": len(matched_params),
                    "storage": len(matched_storage),
                    "headers": len(set(matched_headers)),
                    "correlations": len(matched_correlations),
                    "taint_flows": len(matched_taints),
                },
                "interesting_endpoints": sorted(set(matched_endpoints))[:12],
                "interesting_params": sorted(set(matched_params))[:12],
                "interesting_storage_keys": sorted(set(matched_storage))[:12],
                "interesting_headers": sorted(set(matched_headers))[:12],
                "finding_examples": sorted(set(f"{f.name}@L{f.line}" for f in matched_findings))[:10],
                "playbook_categories": sorted(set(p.get("category", "") for p in matched_playbooks))[:10],
                "taint_examples": sorted(set(f"{t.get('source_var')} -> {t.get('sink_expression')}" for t in matched_taints if t.get('source_var') and t.get('sink_expression')))[:8],
                "summary": self._cluster_summary(spec["name"], score, matched_endpoints, matched_findings, matched_playbooks, matched_params, matched_storage),
            }
            clusters.append(cluster)

        clusters = sorted(clusters, key=lambda x: (-x["score"], x["name"]))
        self.action_clusters = clusters[:8]
        self.stats["action_clusters"] = self.action_clusters

    def _cluster_summary(self, name: str, score: int, endpoints: List[str], findings: List[Finding], playbooks: List[Dict], params: List[str], storage_keys: List[str]) -> str:
        parts = []
        if endpoints:
            parts.append(f"{len(set(endpoints))} endpoints")
        if findings:
            parts.append(f"{len(findings)} findings")
        if playbooks:
            parts.append(f"{len(playbooks)} playbooks")
        if params:
            parts.append(f"params: {', '.join(sorted(set(params))[:4])}")
        if storage_keys:
            parts.append(f"storage: {', '.join(sorted(set(storage_keys))[:3])}")
        base = "; ".join(parts) if parts else "few weak signals"
        return f"{name} cluster [{score}] -> {base}"

    def _analyze_data_flow(self) -> None:
        sources = {"URL params": r"(?:location\.search|URLSearchParams|searchParams|window\.location\.hash)", "postMessage": r"addEventListener\s*\(\s*['\"]message", "document.referrer": r"document\.referrer", "document.cookie": r"document\.cookie", "localStorage": r"localStorage\.getItem", "File API": r"(?:FileReader|readAsDataURL|readAsText)", "Clipboard": r"(?:navigator\.clipboard|clipboardData)"}
        sinks = {"innerHTML": r"\.innerHTML\s*=", "eval": r"(?<![\w.])eval\s*\(", "document.write": r"document\.write", "location": r"(?:window\.)?location(?:\.href)?\s*=", "fetch": r"\bfetch\s*\(", "jQuery .html()": r"\.\s*html\s*\("}
        src_counts = [{"source": n, "count": len(re.findall(r, self.content, re.I))} for n, r in sources.items() if re.search(r, self.content, re.I)]
        sink_counts = [{"sink": n, "count": len(re.findall(r, self.content, re.I))} for n, r in sinks.items() if re.search(r, self.content, re.I)]
        self.stats["data_flow"] = {"sources": src_counts, "sinks": sink_counts}

    def _analyze_access_control(self) -> None:
        checks = []
        roles = sorted(set(re.findall(r'(isAdmin|is_admin|isEditor|isModerator|hasRole|hasPermission|canEdit|canDelete|isAuthenticated|isAuthorized|isSuperAdmin|super_admin)', self.content, re.I)))
        if roles: checks.append({"type": "Role/permission checks", "values": roles})
        perms = sorted(set(re.findall(r'(?:permission|scope|authority)\s*[:=]\s*["\']([^"\']+)["\']', self.content, re.I)))
        if perms: checks.append({"type": "Permission strings", "values": perms[:20]})
        self.stats["access_control"] = checks

    def _detect_hidden_debug(self) -> None:
        items = []
        if re.search(r'(?:debug[_-]?mode|devMode|isDebug|verbose)\s*[:=]\s*(?:true|1|["\']true["\'])', self.content, re.I):
            items.append({"type": "Debug mode flag"})
        hidden = sorted(set(re.findall(r'(?:searchParams|urlParams?|query)\.(?:get|has)\s*\(\s*["\'](debug|admin|test|dev|staging|preview|bypass|force|override|secret)["\']', self.content, re.I)))
        if hidden: items.append({"type": "Hidden URL params", "values": hidden})
        self.stats["hidden_debug"] = items

    def _detect_source_maps(self) -> None:
        self.stats["source_maps"] = re.findall(r'//[#@]\s*sourceMappingURL=(.+)', self.content)

    def _detect_error_patterns(self) -> None:
        issues = []
        if re.search(r'(?:stackTrace|Error\.captureStackTrace)', self.content): issues.append("Stack trace handling")
        self.stats["error_patterns"] = issues

    def _extract_comments(self) -> None:
        self.stats["comments"] = re.findall(r'//\s*((?:TODO|FIXME|HACK|XXX|BUG|SECURITY|UNSAFE|WORKAROUND)[^\n]{0,120})', self.content, re.I)[:15]

    def _analyze_file_uploads(self) -> None:
        upload = []
        urls = sorted(set(u for u in re.findall(r'["\']([^"\']*(?:upload|attach|import|file)[^"\']*)["\']', self.content, re.I) if '/' in u and len(u) < 140))
        if urls: upload.append({"type": "Upload endpoints", "urls": urls[:15]})
        accept = sorted(set(re.findall(r'\baccept\s*[:=]\s*["\']([^"\']+)["\']', self.content)))
        if accept: upload.append({"type": "File type validation (client-side)", "values": accept[:10]})
        self.stats["file_uploads"] = upload

    def _analyze_redirect_params(self) -> None:
        self.stats["redirect_params"] = sorted(set(re.findall(r'(returnto|redirect_uri|next|return_url|goto|continue|target|destination|callback_url|success_url|error_url)', self.content, re.I)))

    def _extract_cors_hints(self) -> None:
        cors = []
        origins = sorted(set(re.findall(r'(?:allowed?[_-]?origins?|cors[_-]?origins?|Access-Control-Allow-Origin)\s*[:=]\s*[\[{"\']([^"\'}\]]+)', self.content, re.I)))
        if origins: cors.append({"type": "Allowed origins", "values": origins[:15]})
        if re.search(r'(?:withCredentials|credentials)\s*[:=]\s*(?:true|["\'](?:include|true)["\'])', self.content, re.I):
            cors.append({"type": "Credentials: include/true"})
        self.stats["cors"] = cors

    def _top_hotspots(self) -> List[str]:
        hotspots = []
        corr = self.stats.get("correlations", [])
        for item in corr[:4]:
            hotspots.append(f"{item['hypothesis']} @L{item['line']} [{item['confidence']}/{item['score']}]")
        all_findings = [f for sev in self.findings.values() for f in sev]
        ranked_findings = sorted(all_findings, key=lambda f: (-f.confidence_score, SEVERITY_ORDER.get(f.severity, 99), f.line))
        for f in ranked_findings[:4]:
            hotspots.append(f"{f.name} @L{f.line} [{f.confidence}/{f.confidence_score}]")
        auth_map = self.stats.get('auth_map', {})
        for transport in auth_map.get('transport', [])[:2]:
            hotspots.append(f"auth-map {transport}")
        for cluster in self.stats.get("action_clusters", [])[:3]:
            hotspots.append(f"cluster {cluster['name']} [{cluster['confidence']}/{cluster['score']}]")
        for ep in self.endpoints[:3]:
            if ep["score"] >= 4:
                hotspots.append(f"endpoint {ep['url'][:80]} [score {ep['score']}]")
        deduped=[]
        seen=set()
        for h in hotspots:
            if h not in seen:
                seen.add(h)
                deduped.append(h)
        return deduped[:10]

    def _print_results(self) -> None:
        total = sum(len(v) for v in self.findings.values())
        counts = {sev: len(self.findings.get(sev, [])) for sev in SEVERITY_ORDER}
        vendor_count = sum(1 for sev_list in self.findings.values() for f in sev_list if f.vendor_confidence == "high")
        app_count = total - vendor_count

        hotspots = self._top_hotspots()
        if hotspots:
            print(c(BOLD, "\n🎯 HOTSPOTS"))
            print(c(BOLD, "─" * 60))
            for item in hotspots:
                print(f"  {c(MAGENTA, '•')} {item}")
            print()

        print(c(BOLD, f"📊 RESUMEN ({app_count} app/mixed, {vendor_count} vendor-high)"))
        print(c(BOLD, "─" * 60))
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if counts.get(sev):
                print(f"  {c(SEVERITY_COLOR[sev], sev)}: {counts[sev]}")
        print(f"  Total: {total}\n")

        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if not self.findings.get(severity):
                continue
            color = SEVERITY_COLOR[severity]
            print(c(color + BOLD, f"\n{'━' * 78}"))
            print(c(color + BOLD, f"  [{severity}]"))
            print(c(color + BOLD, f"{'━' * 78}"))
            grouped: Dict[str, List[Finding]] = defaultdict(list)
            for f in self.findings[severity]:
                grouped[f.name].append(f)
            for name, hits in sorted(grouped.items(), key=lambda kv: (-len(kv[1]), kv[0])):
                app_hits = [h for h in hits if h.vendor_confidence != "high"]
                ven_hits = [h for h in hits if h.vendor_confidence == "high"]
                vendor_tag = c(DIM, f" ({len(ven_hits)} vendor-high, {len(app_hits)} app/mixed)") if ven_hits else ""
                total_for = hits[0].total_hits_for_pattern
                print(f"\n{c(color + BOLD, f'▶ {name}')} {c(CYAN, f'({total_for} total)')}{vendor_tag}")
                for idx, h in enumerate(hits[:self.max_per], 1):
                    vendor_mark = c(DIM, f" [V:{h.vendor_confidence}]") if h.vendor_confidence != "none" else ""
                    conf_mark = c(YELLOW, f" conf={h.confidence}/{h.confidence_score}")
                    print(f"  {c(CYAN, f'#{idx} L:{h.line}')}{vendor_mark}{conf_mark}: ...{h.context_before} {c(RED + BOLD, h.context_match)} {h.context_after}...")
                    if h.note:
                        print(f"      {c(DIM, h.note)}")

        if self.endpoints:
            print(c(CYAN + BOLD, f"\n{'━' * 78}"))
            print(c(CYAN + BOLD, f"  🔗 ENDPOINTS ({len(self.endpoints)})"))
            print(c(CYAN + BOLD, f"{'━' * 78}"))
            for ep in self.endpoints[:50]:
                extras = []
                if ep["in_scope"]: extras.append(c(GREEN, "✓SCOPE"))
                if ep["score"] > 2: extras.append(c(MAGENTA, f"★{ep['score']}"))
                print(f"  {c(CYAN, ep['url'][:140])} {c(DIM, '[' + ep['type'] + ']')} {' '.join(extras)}")

        if self.api_clients:
            print(c(MAGENTA + BOLD, f"\n{'━' * 78}"))
            print(c(MAGENTA + BOLD, f"  🔧 API CLIENTS RECONSTRUCTED"))
            print(c(MAGENTA + BOLD, f"{'━' * 78}"))
            for client in self.api_clients:
                print(f"\n  {c(BOLD, client['type'])}:")
                if 'calls' in client:
                    for method, paths in client['calls'].items():
                        for p in paths[:20]:
                            print(f"    {c(YELLOW, method.ljust(7))} {c(CYAN, p)}")
                if 'paths' in client:
                    for p in client['paths'][:20]:
                        print(f"    {c(CYAN, p)}")
                if 'bases' in client:
                    for b in client['bases']:
                        print(f"    {c(CYAN, b)}")

        if self.routes:
            print(c(CYAN + BOLD, f"\n{'━' * 78}"))
            print(c(CYAN + BOLD, f"  🗺️ ROUTES ({len(self.routes)})"))
            print(c(CYAN + BOLD, f"{'━' * 78}"))
            for r in self.routes[:40]:
                print(f"  {c(CYAN, r)}")

        if self.params:
            print(c(CYAN + BOLD, f"\n{'━' * 78}"))
            print(c(CYAN + BOLD, f"  📝 PARAMS ({len(self.params)})"))
            print(c(CYAN + BOLD, f"{'━' * 78}"))
            for i in range(0, min(len(self.params), 60), 4):
                row = self.params[i:i+4]
                print("  " + "  ".join(c(CYAN, p.ljust(28)) for p in row))

        if self.stats.get("internal_infra"):
            print(c(RED + BOLD, f"\n{'━' * 78}"))
            print(c(RED + BOLD, f"  🏗️ INTERNAL INFRASTRUCTURE"))
            print(c(RED + BOLD, f"{'━' * 78}"))
            for key, values in self.stats["internal_infra"].items():
                print(f"\n  {c(BOLD, key)}:")
                for v in (values if isinstance(values, list) else [values])[:20]:
                    print(f"    {c(CYAN, v)}")

        if self.stats.get("custom_headers"):
            print(c(YELLOW + BOLD, f"\n{'━' * 78}"))
            print(c(YELLOW + BOLD, f"  📨 CUSTOM HTTP HEADERS"))
            print(c(YELLOW + BOLD, f"{'━' * 78}"))
            for h in self.stats["custom_headers"].get("confirmed", [])[:20]:
                print(f"  {c(GREEN, '[confirmed]')} {c(CYAN, h)}")
            for h in self.stats["custom_headers"].get("suspicious", [])[:20]:
                print(f"  {c(YELLOW, '[suspicious]')} {c(CYAN, h)}")

        if self.secrets:
            print(c(RED + BOLD, f"\n{'━' * 78}"))
            print(c(RED + BOLD, f"  🔐 SECRETS ({len(self.secrets)})"))
            print(c(RED + BOLD, f"{'━' * 78}"))
            for s in self.secrets[:20]:
                print(f"  {c(RED, s['type'])} L:{s['line']} entropy:{s['entropy']} → {c(YELLOW, s['value_preview'])}")

        if self.stats.get("auth_flows"):
            print(c(MAGENTA + BOLD, f"\n{'━' * 78}"))
            print(c(MAGENTA + BOLD, "  🔐 AUTH FLOWS"))
            print(c(MAGENTA + BOLD, f"{'━' * 78}"))
            for flow in self.stats["auth_flows"]:
                print(f"\n  {c(BOLD, flow['type'])}:")
                for k, v in flow.items():
                    if k == 'type':
                        continue
                    if isinstance(v, list):
                        for item in v[:15]:
                            print(f"    {c(CYAN, str(item))}")
                    else:
                        print(f"    {c(CYAN, str(v))}")

        if self.stats.get("taint_flows"):
            print(c(YELLOW + BOLD, f"\n{'━' * 78}"))
            print(c(YELLOW + BOLD, "  🧬 TAINT-LITE FLOWS"))
            print(c(YELLOW + BOLD, f"{'━' * 78}"))
            for item in self.stats["taint_flows"][:12]:
                print(f"  {c(MAGENTA, item['hypothesis'])} L:{item['line']} {c(YELLOW, '[' + item['confidence'] + '/' + str(item['score']) + ']')} var={item['source_var']} source={item['source_category']}")
                print(f"      {c(DIM, 'aliases:' + ','.join(item.get('aliases', [])) + ' -> sink:' + item.get('sink_expression', '')[:120])}")

        if self.stats.get("auth_map"):
            print(c(MAGENTA + BOLD, f"\n{'━' * 78}"))
            print(c(MAGENTA + BOLD, "  🧭 AUTH MAP"))
            print(c(MAGENTA + BOLD, f"{'━' * 78}"))
            auth_map = self.stats['auth_map']
            for k in ['storage_keys_tokenish', 'confirmed_headers', 'auth_endpoints', 'transport']:
                vals = auth_map.get(k, [])
                if vals:
                    print(f"\n  {c(BOLD, k)}:")
                    for item in vals[:15]:
                        print(f"    {c(CYAN, str(item))}")

        if self.stats.get("correlations"):
            print(c(YELLOW + BOLD, f"\n{'━' * 78}"))
            print(c(YELLOW + BOLD, "  🧪 CORRELATIONS / HYPOTHESES"))
            print(c(YELLOW + BOLD, f"{'━' * 78}"))
            for item in self.stats['correlations'][:12]:
                print(f"  {c(MAGENTA, item['hypothesis'])} L:{item['line']} {c(YELLOW, '[' + item['confidence'] + '/' + str(item['score']) + ']')} sources={','.join(item['sources'])}")
                if item.get('function'):
                    print(f"      {c(DIM, 'fn:' + item['function'])}")

        if self.stats.get("validation_playbooks"):
            print(c(CYAN + BOLD, f"\n{'━' * 78}"))
            print(c(CYAN + BOLD, "  📋 VALIDATION PLAYBOOKS"))
            print(c(CYAN + BOLD, f"{'━' * 78}"))
            for pb in self.stats["validation_playbooks"][:10]:
                headline = f"{pb['category']} [{pb.get('confidence','?')}/{pb.get('score','?')}]"
                if pb.get("line"):
                    headline += f" L:{pb['line']}"
                print(f"  {c(MAGENTA, headline)}")
                print(f"      {c(DIM, pb.get('goal',''))}")
                if pb.get("payload_classes"):
                    print(f"      {c(CYAN, 'payload_classes:')} {', '.join(pb['payload_classes'])}")
                if pb.get("manual_checks"):
                    print(f"      {c(CYAN, 'manual_checks:')} {' | '.join(pb['manual_checks'][:3])}")
                if pb.get("evidence_to_collect"):
                    print(f"      {c(CYAN, 'evidence:')} {' | '.join(pb['evidence_to_collect'][:3])}")

        if self.action_clusters:
            print(c(CYAN + BOLD, f"\n{'━' * 78}"))
            print(c(CYAN + BOLD, "  🧩 ACTION CLUSTERS"))
            print(c(CYAN + BOLD, f"{'━' * 78}"))
            for cluster in self.action_clusters[:8]:
                print(f"\n  {c(BOLD, cluster['name'])} {c(YELLOW, '[' + cluster['confidence'] + '/' + str(cluster['score']) + ']')}")
                print(f"    {c(DIM, cluster.get('summary', ''))}")
                if cluster.get('interesting_endpoints'):
                    for ep in cluster['interesting_endpoints'][:4]:
                        print(f"    endpoint: {c(CYAN, ep[:120])}")
                if cluster.get('finding_examples'):
                    print(f"    findings: {c(MAGENTA, ', '.join(cluster['finding_examples'][:4]))}")
                if cluster.get('playbook_categories'):
                    print(f"    playbooks: {c(GREEN, ', '.join(cluster['playbook_categories'][:4]))}")

        if self.stats.get("data_flow"):
            print(c(YELLOW + BOLD, f"\n{'━' * 78}"))
            print(c(YELLOW + BOLD, "  ⚡ DATA FLOW"))
            print(c(YELLOW + BOLD, f"{'━' * 78}"))
            for src in self.stats["data_flow"].get("sources", []):
                print(f"  {c(GREEN, '→')} {src['source']} ×{src['count']}")
            for sink in self.stats["data_flow"].get("sinks", []):
                print(f"  {c(RED, '←')} {sink['sink']} ×{sink['count']}")

        if self.storage_keys:
            print(c(CYAN + BOLD, f"\n{'━' * 78}"))
            print(c(CYAN + BOLD, f"  💾 STORAGE KEYS ({len(self.storage_keys)})"))
            print(c(CYAN + BOLD, f"{'━' * 78}"))
            for k in self.storage_keys[:25]:
                print(f"  {c(CYAN, k)}")

        if self.stats.get("websockets"):
            print(c(CYAN + BOLD, f"\n{'━' * 78}"))
            print(c(CYAN + BOLD, "  🔌 WEBSOCKETS"))
            print(c(CYAN + BOLD, f"{'━' * 78}"))
            for ws in self.stats["websockets"]:
                print(f"  {c(CYAN, ws)}")

        if self.stats.get("access_control"):
            print(c(MAGENTA + BOLD, f"\n{'━' * 78}"))
            print(c(MAGENTA + BOLD, "  🛡️ ACCESS CONTROL"))
            print(c(MAGENTA + BOLD, f"{'━' * 78}"))
            for ac in self.stats["access_control"]:
                print(f"\n  {c(BOLD, ac['type'])}:")
                for v in ac.get('values', []):
                    print(f"    {c(CYAN, v)}")

        if self.stats.get("hidden_debug"):
            print(c(RED + BOLD, f"\n{'━' * 78}"))
            print(c(RED + BOLD, "  🕵️ HIDDEN DEBUG"))
            print(c(RED + BOLD, f"{'━' * 78}"))
            for item in self.stats["hidden_debug"]:
                print(f"  {c(RED, json.dumps(item, ensure_ascii=False))}")

        if self.stats.get("source_maps"):
            print(c(RED + BOLD, f"\n  📦 SOURCE MAPS: {', '.join(self.stats['source_maps'])}"))
        if self.stats.get("redirect_params"):
            print(c(YELLOW, f"\n  ↩️ REDIRECT PARAMS: {', '.join(self.stats['redirect_params'])}"))
        if self.stats.get("comments"):
            print(c(YELLOW + BOLD, f"\n{'━' * 78}"))
            print(c(YELLOW + BOLD, "  💬 DEV COMMENTS"))
            print(c(YELLOW + BOLD, f"{'━' * 78}"))
            for cm in self.stats["comments"][:10]:
                print(f"  {c(YELLOW, cm[:120])}")

        print(c(BOLD, f"\n{'=' * 78}"))
        print(c(BOLD, "  DONE"))
        print(c(BOLD, f"{'=' * 78}\n"))

    def _build_report(self) -> Dict:
        return {
            "file": str(self.path),
            "size_kb": round(self.path.stat().st_size / 1024, 2),
            "sha256": hashlib.sha256(self.content.encode("utf-8", errors="ignore")).hexdigest(),
            "frameworks": self.frameworks,
            "chunks_detected": len(self.chunks),
            "hotspots": self._top_hotspots(),
            "summary": {sev: len(self.findings.get(sev, [])) for sev in SEVERITY_ORDER},
            "findings": {sev: [asdict(f) for f in self.findings.get(sev, [])] for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
            "endpoints": self.endpoints,
            "api_clients": self.api_clients,
            "routes": self.routes,
            "params": self.params,
            "storage_keys": self.storage_keys,
            "validation_playbooks": self.validation_playbooks,
            "action_clusters": self.action_clusters,
            "secrets": self.secrets,
            "stats": self.stats,
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="JS Bundle Analyzer v3.6 (base) — Recon / Bug Bounty", formatter_class=argparse.RawDescriptionHelpFormatter, epilog="""
Ejemplos:
  python3 js_analyzer_v4_7.py bundle.js --scope example.com --app-only
  python3 js_analyzer_v3_6.py chunk.js --json --no-color --max 10
    """)
    parser.add_argument("file", help="Archivo JS a analizar")
    parser.add_argument("--max", type=int, default=5, help="Max matches por patrón")
    parser.add_argument("--scope", type=str, default=None, help="Dominio en scope (ej: example.com)")
    parser.add_argument("--app-only", action="store_true", help="Filtrar findings de vendor-high code")
    parser.add_argument("--json", action="store_true", help="Guardar reporte JSON")
    parser.add_argument("--no-color", action="store_true", help="Sin colores")
    args = parser.parse_args()
    global NO_COLOR
    NO_COLOR = args.no_color
    analyzer = JSAnalyzer(args.file, max_per=args.max, scope=args.scope, app_only=args.app_only)
    report = analyzer.run()
    if args.json:
        out = Path(args.file).with_name(Path(args.file).stem + "_analysis_v3_6.json")
        with out.open("w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        print(c(GREEN, f"[+] JSON: {out}"))


class JSAnalyzerV4(JSAnalyzer):
    def __init__(self, filepath: str, max_per: int = 5, scope: Optional[str] = None, app_only: bool = False, profile: str = "generic"):
        super().__init__(filepath, max_per=max_per, scope=scope, app_only=app_only)
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

    def _get_profile_keywords(self, profile: str) -> List[str]:
        profiles = {
            "generic": ["admin", "user", "account", "profile", "settings", "role", "permission", "invite", "member", "project", "workspace", "upload", "download", "export", "report", "billing", "order", "price"],
            "saas": ["workspace", "member", "invite", "role", "permission", "billing", "subscription", "seat", "api", "token"],
            "ecommerce": ["cart", "checkout", "order", "invoice", "price", "discount", "coupon", "refund", "product", "shipment"],
            "cms": ["publish", "draft", "editor", "media", "asset", "content", "page", "article", "template", "preview"],
            "german": ["konto", "benutzer", "kontakt", "mitglied", "projekt", "export", "bericht", "dokument", "antrag", "service", "chat"],
        }
        return profiles.get((profile or "generic").lower(), profiles["generic"])

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
        self._generate_validation_playbooks()
        self._build_action_clusters()
        self._analyze_data_flow()
        self._analyze_access_control()
        self._detect_hidden_debug()
        self._detect_source_maps()
        self._detect_error_patterns()
        self._extract_comments()
        self._analyze_file_uploads()
        self._analyze_redirect_params()
        self._extract_cors_hints()
        self._print_results()
        return self._build_report()

    def _banner(self) -> None:
        size_kb = self.path.stat().st_size / 1024
        print(c(CYAN + BOLD, f"\n{'=' * 78}"))
        print(c(CYAN + BOLD, f"  JS Bundle Analyzer v4.5 — {self.path.name} ({size_kb:.1f} KB)"))
        if self.scope:
            print(c(CYAN + BOLD, f"  Scope: {self.scope}"))
        print(c(CYAN + BOLD, f"  Profile: {self.profile}"))
        if self.app_only:
            print(c(YELLOW + BOLD, "  Mode: APP-ONLY (vendor-high findings filtered)"))
        print(c(CYAN + BOLD, f"{'=' * 78}\n"))

    def _extract_http_call_candidates(self) -> List[Dict]:
        candidates: List[Dict] = []
        seen = set()
        regex = re.compile(r'(?:this\.http|http|axios)\.(get|post|put|patch|delete)\s*\(', re.I)
        for m in regex.finditer(self.content):
            method = m.group(1).upper()
            idx = m.end()
            depth = 1
            cur = idx
            while cur < len(self.content) and depth > 0:
                ch = self.content[cur]
                if ch == '(':
                    depth += 1
                elif ch == ')':
                    depth -= 1
                cur += 1
            inside = self.content[idx:cur - 1]
            if not inside:
                continue
            args, buf = [], []
            par = br = brace = 0
            in_str: Optional[str] = None
            esc = False
            for ch in inside:
                if in_str:
                    buf.append(ch)
                    if esc:
                        esc = False
                    elif ch == '\\':
                        esc = True
                    elif ch == in_str:
                        in_str = None
                    continue
                if ch in ('"', "'", '`'):
                    in_str = ch
                    buf.append(ch)
                    continue
                if ch == '(':
                    par += 1
                elif ch == ')':
                    par -= 1
                elif ch == '[':
                    br += 1
                elif ch == ']':
                    br -= 1
                elif ch == '{':
                    brace += 1
                elif ch == '}':
                    brace -= 1
                if ch == ',' and par == 0 and br == 0 and brace == 0:
                    args.append(''.join(buf).strip())
                    buf = []
                    continue
                buf.append(ch)
            if buf:
                args.append(''.join(buf).strip())
            if not args:
                continue
            url_expr = normalize_space(args[0])
            body_expr = normalize_space(args[1]) if len(args) > 1 else ''
            key = (method, url_expr[:180], body_expr[:120], m.start())
            if key in seen:
                continue
            seen.add(key)
            candidates.append({'method': method, 'url_expr': url_expr, 'body_expr': body_expr, 'start': m.start()})
        fetch_re = re.compile(r'fetch\s*\(\s*(?P<url>[^,\)]+)\s*(?:,\s*(?P<cfg>\{[\s\S]{0,1200}?\}))?\)', re.I)
        for m in fetch_re.finditer(self.content):
            url_expr = normalize_space(m.group('url') or '')
            cfg = m.group('cfg') or ''
            method_m = re.search(r'method\s*:\s*["\'](GET|POST|PUT|PATCH|DELETE)["\']', cfg, re.I)
            method = (method_m.group(1).upper() if method_m else 'GET')
            body_m = re.search(r'body\s*:\s*([^,}]+)', cfg, re.I)
            body_expr = normalize_space(body_m.group(1)) if body_m else ''
            key = (method, url_expr[:180], body_expr[:120], m.start())
            if key in seen:
                continue
            seen.add(key)
            candidates.append({'method': method, 'url_expr': url_expr, 'body_expr': body_expr, 'start': m.start()})
        return candidates

    def _reconstruct_endpoint_expr(self, expr: str) -> Optional[str]:
        expr = normalize_space(expr)
        if not expr:
            return None
        if len(expr) > 1000:
            expr = expr[:1000]
        if expr.startswith(('"', "'", '`')) and expr.endswith(('"', "'", '`')):
            candidate = expr.strip('"\'`')
            return candidate if '/' in candidate else None
        parts: List[str] = []
        if 'this.baseUrl' in expr or re.search(r'\bbaseUrl\b', expr):
            parts.append('./api')
        literals = re.findall(r'["\']([^"\']+)["\']', expr)
        for lit in literals:
            if '/' in lit or re.match(r'^[A-Za-z0-9_-]{3,}$', lit):
                parts.append(lit)
        joined = ''.join(parts)
        joined = re.sub(r'(?<!:)//+', '/', joined)
        if re.search(r'\.concat\([^)]*[A-Za-z_$][A-Za-z0-9_$]*\)', expr) or re.search(r'\$\{[^}]+\}', expr):
            if joined.endswith('/'):
                joined += '{id}'
            elif re.search(r'/[A-Za-z0-9_-]+$', joined):
                joined += '/{id}'
        return joined if joined and '/' in joined else None

    def _extract_endpoints(self) -> None:
        super()._extract_endpoints()
        for item in self._extract_http_call_candidates():
            rebuilt = self._reconstruct_endpoint_expr(item['url_expr'])
            if rebuilt:
                self._add_endpoint(rebuilt, f"http_{item['method'].lower()}_expr")
        self.endpoints.sort(key=lambda x: (-x['score'], x['url']))

    def _extract_objectish_fields(self, text: str) -> List[str]:
        found = set()
        patterns = [
            r'([A-Za-z_][A-Za-z0-9_]*)\s*:',
            r'this\.([A-Za-z_][A-Za-z0-9_]*)\s*=',
            r'([A-Za-z_][A-Za-z0-9_]*)\s*=\s*new\s+[A-Za-z_][A-Za-z0-9_]*',
            r'[,{]\s*([A-Za-z_][A-Za-z0-9_]*)\s*=',
            r"[,{]\s*[\"']([A-Za-z_][A-Za-z0-9_-]{1,60})[\"']\s*:",
            r"\.append\s*\(\s*[\"']([A-Za-z_][A-Za-z0-9_-]{1,60})[\"']",
            r"FormData\s*\([^\)]*\).*?\.append\s*\(\s*[\"']([A-Za-z_][A-Za-z0-9_-]{1,60})[\"']",
        ]
        noise = {'if', 'for', 'while', 'return', 'function', 'const', 'let', 'var', 'new', 'true', 'false', 'null', 'this', 'self', 'window'}
        for pat in patterns:
            for x in re.findall(pat, text, re.S):
                x = x.strip('-_')
                if x.lower() not in noise and len(x) > 1 and not re.fullmatch(r'[A-Z]{1,3}|[a-z]{1,2}\d*', x):
                    found.add(x)
        return sorted(found)

    def _detect_critical_mutations(self) -> None:
        mutations: List[Dict] = []
        seen = set()
        route_terms = [
            'create', 'update', 'delete', 'remove', 'save', 'publish', 'approve', 'archive', 'submit', 'verify', 'confirm',
            'erstellen', 'aktualisieren', 'loeschen', 'löschen', 'speichern', 'veroeffentlichen', 'veröffentlichen', 'genehmigen', 'einreichen', 'bestaetigen', 'bestätigen',
            'user', 'benutzer', 'admin', 'role', 'rolle', 'permission', 'berechtigung', 'invite', 'einladen', 'member', 'mitglied', 'account', 'konto', 'profile', 'profil',
            'settings', 'einstellungen', 'project', 'projekt', 'workspace', 'arbeitsbereich', 'billing', 'order', 'bestellung', 'product', 'produkt', 'price', 'preis', 'file', 'datei',
            'upload', 'download', 'export', 'report', 'bericht', 'pdf'
        ] + self.profile_keywords
        for item in self._extract_http_call_candidates():
            method = item['method']
            endpoint = self._reconstruct_endpoint_expr(item['url_expr']) or item['url_expr'][:240]
            block = self._get_logical_block(item['start'], 1600, 5200)
            func_ctx = self._get_func_context(item['start'])
            chunk = self._chunk_at(item['start'])
            body_fields = self._extract_objectish_fields((item['body_expr'][:2500] + '\n' + block[:2500]))
            sensitive_fields = [
                f for f in body_fields
                if re.search(r'(email|mail|telefon|phone|mobile|kontakt|contact|homepage|url|status|state|rolle|role|permission|berechtigung|user|userid|benutzer|owner|eigentuemer|eigentümer|assignee|account|konto|password|passwort|secret|token|key|schluessel|schlüssel|enabled|active|aktiv|admin|publish|veroeffentlichen|veröffentlichen|visibility|price|preis|amount|betrag|quota|limit|address|adresse|organisation|title|titel|name|content|inhalt|body|html|description|beschreibung)', f, re.I)
            ]
            route_signals = sorted(set(w for w in route_terms if re.search(w, endpoint + ' ' + func_ctx + ' ' + block[:900], re.I)))
            id_in_path = bool(re.search(r'\.concat\([^)]*[A-Za-z_$][A-Za-z0-9_$]*\)|\$\{[^}]+\}', item['url_expr'])) or ('{id}' in endpoint)
            object_like_body = bool(item['body_expr']) and (item['body_expr'].startswith('{') or len(body_fields) >= 4 or bool(re.search(r'new\s+[A-Za-z_$]', item['body_expr'])))
            auth_signals = []
            if re.search(r'Authorization|Bearer|X-Auth-Token|X-CSRF-Token|X-XSRF-TOKEN', block, re.I):
                auth_signals.append('explicit_auth_header')
            if re.search(r'withCredentials|credentials\s*:\s*["\']include["\']|document\.cookie|XSRF-TOKEN', block, re.I):
                auth_signals.append('cookie_or_xsrf_signal')
            score = 30
            score += {'POST': 8, 'PUT': 20, 'PATCH': 18, 'DELETE': 16}.get(method, 0)
            if endpoint.startswith(('./api', '/api')):
                score += 10
            if id_in_path:
                score += 18
            if object_like_body:
                score += 14
            score += min(21, len(sensitive_fields) * 3)
            score += min(12, len(route_signals) * 2)
            if any(x in route_signals for x in ['download', 'export', 'report', 'pdf']):
                score += 6
            if not auth_signals:
                score += 8
            if re.search(r'(update|delete|remove|save|publish|approve)', func_ctx or '', re.I):
                score += 6
            score = min(99, score)
            if score < 55:
                continue
            hypotheses = []
            if id_in_path:
                hypotheses.append('idor_possible')
            if object_like_body and len(body_fields) >= 6:
                hypotheses.append('mass_assignment_possible')
            if method in {'PUT', 'PATCH', 'DELETE'}:
                hypotheses.append('missing_authz_on_mutation')
            if any(x in route_signals for x in ['download', 'export', 'report', 'pdf']):
                hypotheses.append('business_flow_abuse_possible')
            key = (method, endpoint)
            if key in seen:
                continue
            seen.add(key)
            mutations.append({
                'method': method,
                'endpoint': endpoint,
                'line': self._line_of(item['start']),
                'function': func_ctx,
                'chunk': (chunk.label or chunk.name) if chunk else '',
                'confidence': 'high' if score >= 78 else 'medium',
                'score': score,
                'id_in_path': id_in_path,
                'object_like_body': object_like_body,
                'body_field_count': len(body_fields),
                'sensitive_fields': sensitive_fields[:20],
                'auth_signals': auth_signals,
                'route_signals': route_signals[:12],
                'hypotheses': hypotheses or ['business_critical_mutation'],
                'body_preview': item['body_expr'][:180],
            })
        self.critical_mutations = sorted(mutations, key=lambda x: (-x['score'], x['line']))[:25]
        self.stats['critical_mutations'] = self.critical_mutations

    def _detect_stored_xss_hints(self) -> None:
        hints: List[Dict] = []
        seen = set()
        html_fields = {'html', 'content', 'body', 'description', 'message', 'comment', 'title', 'name', 'text', 'summary', 'caption', 'note'}
        html_render_signals = bool(re.search(r'innerHTML\s*=|dangerouslySetInnerHTML|insertAdjacentHTML|srcdoc\s*=|\.html\s*\(', self.content, re.I))
        if not html_render_signals:
            self.stored_xss_hints = []
            self.stats['stored_xss_hints'] = []
            return
        for item in self._extract_http_call_candidates():
            method = item['method']
            if method not in {'POST', 'PUT', 'PATCH'}:
                continue
            endpoint = self._reconstruct_endpoint_expr(item['url_expr']) or item['url_expr'][:240]
            block = self._get_logical_block(item['start'], 1600, 4200)
            func_ctx = self._get_func_context(item['start'])
            chunk = self._chunk_at(item['start'])
            body_fields = self._extract_objectish_fields((item['body_expr'][:2200] + '\n' + block[:1800]))
            matched_fields = [f for f in body_fields if f.lower() in html_fields or re.search(r'(html|content|body|description|message|comment|title|name|text)', f, re.I)]
            if not matched_fields:
                continue
            score = 58 + min(20, len(matched_fields) * 4)
            if re.search(r'(render|preview|editor|viewer|detail|show|display)', endpoint + ' ' + func_ctx + ' ' + block[:500], re.I):
                score += 8
            key = (endpoint, tuple(matched_fields[:4]))
            if key in seen:
                continue
            seen.add(key)
            hints.append({
                'method': method,
                'endpoint': endpoint,
                'line': self._line_of(item['start']),
                'function': func_ctx,
                'chunk': (chunk.label or chunk.name) if chunk else '',
                'html_like_fields': matched_fields[:12],
                'confidence': 'high' if score >= 76 else 'medium',
                'score': min(95, score),
                'hypothesis': 'stored_xss_candidate',
                'body_preview': item['body_expr'][:180],
            })
        self.stored_xss_hints = sorted(hints, key=lambda x: (-x['score'], x['line']))[:20]
        self.stats['stored_xss_hints'] = self.stored_xss_hints


    def _normalize_resource_base(self, endpoint: str) -> str:
        ep = (endpoint or '').strip()
        if not ep:
            return ''
        ep = re.sub(r'`', '', ep)
        ep = re.sub(r'\?.*$', '', ep)
        ep = re.sub(r'\$\{[^}]+\}', '{id}', ep)
        ep = re.sub(r'/\{[^/]+\}', '/{id}', ep)
        ep = re.sub(r'/(?:\d+|[0-9a-f]{8,}|[A-Za-z0-9_-]{12,})(?=$|/)', '/{id}', ep, flags=re.I)
        if re.match(r'^https?://', ep, re.I):
            m = re.match(r'^(https?://[^/]+)(/.*)?$', ep, re.I)
            origin = (m.group(1) if m else '').lower()
            path = (m.group(2) if m and m.group(2) else '/')
            if self.scope and self.scope.lower() not in origin:
                return ''
            ep = origin + re.sub(r'//+', '/', path)
        else:
            ep = re.sub(r'//+', '/', ep)
        return ep.rstrip('/') or ep

    def _is_internal_resource_candidate(self, endpoint: str, ep_type: str = '') -> bool:
        ep = (endpoint or '').strip().lower()
        t = (ep_type or '').lower()
        if not ep:
            return False
        if ep.startswith(('http://', 'https://')):
            return bool(self.scope and self.scope.lower() in ep)
        if not ep.startswith(('/', './', '../')):
            return False
        if t == 'hardcoded_url':
            return False
        if re.search(r'\.(?:pdf|csv|png|jpg|jpeg|svg|gif|woff2?|ttf|eot)(?:$|\?)', ep):
            return False
        if re.search(r'(?:github|g\.co|ietf|w3\.org|data\.gv\.at)', ep):
            return False
        return True

    def _entity_candidates_from_text(self, text: str) -> List[str]:
        vocab = [
            'user', 'benutzer', 'account', 'konto', 'profile', 'profil', 'member', 'mitglied', 'role', 'rolle', 'permission', 'berechtigung', 'admin', 'team', 'organisation', 'organization', 'tenant', 'workspace', 'arbeitsbereich',
            'project', 'projekt', 'proposal', 'vorschlag', 'vote', 'abstimmung', 'comment', 'kommentar', 'message', 'nachricht', 'chat', 'document', 'dokument', 'report', 'bericht', 'export', 'pdf', 'file', 'datei', 'media', 'content', 'inhalt',
            'application', 'antrag', 'submission', 'einreichung', 'order', 'bestellung', 'invoice', 'rechnung', 'payment', 'zahlung', 'billing', 'refund', 'erstattung', 'booking', 'buchung', 'notification', 'benachrichtigung', 'email', 'status'
        ] + self.profile_keywords
        found = []
        low = (text or '').lower()
        for word in vocab:
            if re.search(rf'(^|[^a-zäöüß]){re.escape(word.lower())}(?:[^a-zäöüß]|$)', low):
                found.append(word.lower())
        return sorted(set(found))[:14]

    def _build_resource_groups(self) -> None:
        groups = {}
        for ep in self.endpoints:
            url = ep.get('url', '')
            ep_type = ep.get('type', '')
            if not self._is_internal_resource_candidate(url, ep_type):
                continue
            base = self._normalize_resource_base(url)
            if not base or '/' not in base:
                continue
            grp = groups.setdefault(base, {
                'resource': base,
                'methods': set(),
                'sample_endpoints': set(),
                'entities': set(),
                'reads': 0,
                'writes': 0,
                'id_path_present': '{id}' in base,
                'method_sources': set(),
            })
            grp['sample_endpoints'].add(url)
            m = re.search(r'http_(get|post|put|patch|delete)_expr', ep_type, re.I)
            method = m.group(1).upper() if m else ('GET' if ep_type in {'fetch_call','template_fetch'} else '')
            if method:
                grp['methods'].add(method)
                grp['method_sources'].add(ep_type)
                if method == 'GET':
                    grp['reads'] += 1
                else:
                    grp['writes'] += 1
            grp['entities'].update(self._entity_candidates_from_text(url))
        out = []
        for _, grp in groups.items():
            if len(grp['methods']) < 2:
                continue
            if grp['writes'] == 0:
                continue
            score = 20 + len(grp['methods']) * 8 + (14 if grp['id_path_present'] else 0) + min(14, grp['writes'] * 4) + min(8, len(grp['entities']) * 2)
            if {'GET', 'POST'} <= grp['methods']:
                score += 6
            if grp['id_path_present'] and ({'PUT', 'DELETE'} & grp['methods']):
                score += 10
            out.append({
                'resource': grp['resource'],
                'methods': sorted(grp['methods']),
                'methods_on_id_path': sorted([m for m in grp['methods'] if grp['id_path_present'] and m in {'GET', 'PUT', 'PATCH', 'DELETE'}]),
                'id_path_present': grp['id_path_present'],
                'sample_endpoints': sorted(grp['sample_endpoints'])[:8],
                'entities': sorted(grp['entities'])[:8],
                'reads': grp['reads'],
                'writes': grp['writes'],
                'confidence': 'high' if score >= 74 else 'medium' if score >= 52 else 'low',
                'score': min(92, score),
                'hypotheses': ['resource_crud_surface', 'resource_authz_candidate'],
            })
        self.resource_groups = sorted(out, key=lambda x: (-x['score'], x['resource']))[:20]
        self.stats['resource_groups'] = self.resource_groups

    def _build_entities_map(self) -> None:
        entity_map = {}
        for rg in self.resource_groups:
            for ent in rg.get('entities', []):
                entry = entity_map.setdefault(ent, {'entity': ent, 'actions': set(), 'resources': set(), 'fields': set(), 'score': 18})
                entry['actions'].update(rg.get('methods', []))
                entry['resources'].add(rg.get('resource', ''))
                entry['score'] += len(rg.get('methods', [])) * 4
        for mut in self.critical_mutations:
            text = ' '.join([mut.get('endpoint',''), mut.get('function',''), ' '.join(mut.get('sensitive_fields', []))])
            ents = self._entity_candidates_from_text(text)
            for ent in ents:
                entry = entity_map.setdefault(ent, {'entity': ent, 'actions': set(), 'resources': set(), 'fields': set(), 'score': 18})
                entry['actions'].add(mut.get('method',''))
                entry['resources'].add(mut.get('endpoint',''))
                entry['fields'].update(mut.get('sensitive_fields', []))
                entry['score'] += 8
        out = []
        for ent, data in entity_map.items():
            out.append({
                'entity': ent,
                'actions': sorted(x for x in data['actions'] if x),
                'resources': sorted(x for x in data['resources'] if x)[:8],
                'fields': sorted(data['fields'])[:12],
                'confidence': 'high' if data['score'] >= 44 else 'medium',
                'score': min(100, data['score'])
            })
        self.entities_map = sorted(out, key=lambda x: (-x['score'], x['entity']))[:20]
        self.stats['entities_map'] = self.entities_map

    def _detect_authz_surfaces(self) -> None:
        out = []
        gate_patterns = {
            'role_check': r'isAdmin|hasRole|hasPermission|canEdit|canDelete|isOwner|isAuthenticated|isAuthorized|role|rolle|permission|berechtigung|admin|moderator|manager',
            'tenant_boundary': r'tenantId|workspaceId|organisationId|organizationId|teamId|mandantId|arbeitsbereichId',
            'ownership_boundary': r'ownerId|createdBy|created_by|memberId|userId|accountId|benutzerId|kontoId|eigentuemerId|eigentümerId',
        }
        for mut in self.critical_mutations:
            text = ' '.join([
                mut.get('endpoint', ''),
                mut.get('function', ''),
                ' '.join(mut.get('route_signals', [])),
                ' '.join(mut.get('sensitive_fields', [])),
                mut.get('body_preview', ''),
            ])
            direct_signals = [name for name, pat in gate_patterns.items() if re.search(pat, text, re.I)]
            signals = list(direct_signals)
            if mut.get('id_in_path') and direct_signals:
                signals.append('id_target_surface')
            auth_hint_count = len(mut.get('auth_signals', []))
            if not signals and auth_hint_count == 0:
                continue
            score = 36 + len(set(direct_signals)) * 10 + (8 if 'id_target_surface' in signals else 0) + (8 if mut.get('method') in {'PUT', 'PATCH', 'DELETE'} else 0) + min(8, auth_hint_count * 4)
            if len(set(direct_signals)) == 0 and auth_hint_count < 2:
                continue
            hypotheses = ['authz_surface_candidate']
            if 'ownership_boundary' in signals:
                hypotheses.append('ownership_boundary_candidate')
            if 'role_check' in signals:
                hypotheses.append('role_boundary_candidate')
            if 'tenant_boundary' in signals:
                hypotheses.append('tenant_boundary_candidate')
            out.append({
                'endpoint': mut.get('endpoint', ''),
                'method': mut.get('method', ''),
                'line': mut.get('line'),
                'signals': sorted(set(signals)),
                'hypotheses': hypotheses,
                'confidence': 'high' if score >= 74 else 'medium',
                'score': min(88, score),
            })
        self.authz_surfaces = sorted(out, key=lambda x: (-x['score'], str(x.get('endpoint', ''))))[:20]
        self.stats['authz_surfaces'] = self.authz_surfaces

    def _detect_workflow_surfaces(self) -> None:
        out = []
        workflow_terms = ['approve', 'reject', 'publish', 'archive', 'submit', 'verify', 'confirm', 'activate', 'deactivate', 'assign', 'invite', 'revoke', 'refund', 'cancel', 'genehmigen', 'ablehnen', 'veroeffentlichen', 'veröffentlichen', 'archivieren', 'einreichen', 'pruefen', 'prüfen', 'bestaetigen', 'bestätigen', 'aktivieren', 'deaktivieren', 'zuweisen', 'einladen', 'widerrufen', 'stornieren']
        for mut in self.critical_mutations:
            text = ' '.join([mut.get('endpoint',''), mut.get('function',''), ' '.join(mut.get('route_signals', [])), ' '.join(mut.get('sensitive_fields', []))])
            matched = sorted(set(t for t in workflow_terms if re.search(rf'(^|[^a-z]){re.escape(t)}(?:[^a-z]|$)', text, re.I)))
            status_like = any(re.search(r'status|state|publish|approve|verify|active|veroeffentlichen|veröffentlichen|genehmigen|aktiv', f, re.I) for f in mut.get('sensitive_fields', []))
            if not matched and not status_like:
                continue
            score = 48 + len(matched) * 8 + (10 if status_like else 0)
            hyps = ['workflow_transition_surface']
            if any(x in matched for x in ['approve', 'publish', 'verify']):
                hyps.append('approval_bypass_candidate')
            if any(x in matched for x in ['assign', 'invite', 'revoke']):
                hyps.append('role_assignment_surface')
            out.append({
                'endpoint': mut.get('endpoint',''),
                'method': mut.get('method',''),
                'line': mut.get('line'),
                'terms': matched,
                'status_like_fields': [f for f in mut.get('sensitive_fields', []) if re.search(r'status|state|publish|approve|verify|active', f, re.I)][:8],
                'hypotheses': hyps,
                'confidence': 'high' if score >= 74 else 'medium',
                'score': min(95, score),
            })
        self.workflow_surfaces = sorted(out, key=lambda x: (-x['score'], str(x.get('endpoint',''))))[:20]
        self.stats['workflow_surfaces'] = self.workflow_surfaces

    def _detect_write_effect_chains(self) -> None:
        out = []
        effect_terms = ['export', 'download', 'report', 'bericht', 'pdf', 'preview', 'vorschau', 'render', 'detail', 'details', 'notification', 'benachrichtigung', 'email', 'mail', 'public', 'oeffentlich', 'öffentlich', 'share', 'teilen']
        for mut in self.critical_mutations:
            if mut.get('method') not in {'POST', 'PUT', 'PATCH', 'DELETE'}:
                continue
            base = self._normalize_resource_base(mut.get('endpoint', '')).replace('/{id}', '')
            if not base:
                continue
            block = self._get_logical_block(self.line_offsets[max(0, (mut.get('line') or 1) - 1)], 1200, 2800).lower()
            endpoint_text = (mut.get('endpoint', '') + ' ' + mut.get('function', '') + ' ' + ' '.join(mut.get('route_signals', []))).lower()
            matched = []
            for term in effect_terms:
                direct_endpoint_link = term in endpoint_text
                nearby_block_link = bool(re.search(rf'(^|[^a-z]){re.escape(term)}(?:[^a-z]|$)', block, re.I))
                if direct_endpoint_link and nearby_block_link:
                    matched.append(term)
                elif direct_endpoint_link and term in {'export', 'download', 'report', 'pdf'}:
                    matched.append(term)
            matched = sorted(set(matched))
            if not matched:
                continue
            score = 42 + len(matched) * 8
            hyps = []
            if any(x in matched for x in ['export', 'download', 'report', 'pdf']):
                hyps.append('write_then_export_surface')
            if any(x in matched for x in ['preview', 'render', 'detail', 'public', 'share']):
                hyps.append('write_then_render_surface')
            if any(x in matched for x in ['notification', 'email']):
                hyps.append('write_then_notify_surface')
            out.append({
                'endpoint': mut.get('endpoint', ''),
                'method': mut.get('method', ''),
                'line': mut.get('line'),
                'effects': matched,
                'hypotheses': hyps,
                'confidence': 'high' if score >= 74 else 'medium',
                'score': min(82, score),
            })
        dedup = {}
        for item in out:
            key = (item.get('endpoint'), tuple(item.get('effects', [])))
            prev = dedup.get(key)
            if not prev or item.get('score', 0) > prev.get('score', 0):
                dedup[key] = item
        self.write_effect_chains = sorted(dedup.values(), key=lambda x: (-x['score'], str(x.get('endpoint', ''))))[:20]
        self.stats['write_effect_chains'] = self.write_effect_chains

    def _playbook_template(self, category: str) -> Dict:
        if category == 'critical_mutation_endpoint':
            return {
                'goal': 'Verificar si una mutación sensible permite IDOR, mass assignment o abuso de flujo de negocio',
                'payload_classes': ['id_swap', 'body_overpost', 'role_or_status_flip', 'auth_transport_variation'],
                'manual_checks': [
                    'Cambiar IDs en path/body/query y comparar objeto propio vs ajeno',
                    'Agregar campos sensibles extra aunque la UI no los exponga',
                    'Comparar comportamiento con cookie sola, bearer solo y sin auth'
                ],
                'evidence_to_collect': ['Request original y mutada', 'Objeto antes y después', 'Campos sensibles aceptados', 'Respuesta y efecto persistente'],
                'impact_hypothesis': 'Broken authz, IDOR o abuso de flujo de negocio sobre mutaciones críticas'
            }
        if category == 'export_or_document_abuse':
            return {
                'goal': 'Verificar si una mutación sensible puede encadenarse con export/download/report para generar salidas confiables manipuladas',
                'payload_classes': ['pdf_field_injection', 'document_link_swap', 'report_content_tamper', 'export_after_update'],
                'manual_checks': [
                    'Cambiar campos visibles en exportes o documentos',
                    'Verificar si el sistema permite descargar PDF/CSV/reportes con el dato alterado',
                    'Observar si enlaces o metadata del documento reflejan el cambio'
                ],
                'evidence_to_collect': ['Objeto antes y después', 'Documento exportado o vista descargable', 'Campos o links alterados en la salida final'],
                'impact_hypothesis': 'Abuso de flujo de negocio mediante documentos/reportes confiables manipulados'
            }
        if category == 'stored_xss_hint':
            return {
                'goal': 'Verificar si contenido persistido luego es renderizado como HTML o markdown inseguro en otra vista',
                'payload_classes': ['basic_html_probe', 'attribute_probe', 'svg_probe', 'markdown_html_probe'],
                'manual_checks': [
                    'Persistir contenido en create/update y abrir vista detalle/listado/preview',
                    'Comparar si la UI escapa o interpreta HTML',
                    'Revisar si el render depende de otro rol o panel admin'
                ],
                'evidence_to_collect': ['Campo persistido y payload usado', 'Vista donde reaparece', 'Código o señal de sink HTML relacionado'],
                'impact_hypothesis': 'Stored XSS o HTML injection persistente'
            }
        if category == 'authz_surface_hint':
            return {
                'goal': 'Verificar si una acción sensible depende de checks de UI, ownership, rol o tenant insuficientes',
                'payload_classes': ['owner_swap', 'role_mismatch', 'tenant_swap', 'ui_gate_bypass'],
                'manual_checks': [
                    'Comparar acción con usuario propio vs ajeno',
                    'Probar cambios de ownerId/memberId/organisationId/tenantId',
                    'Ejecutar la request aunque la UI oculte el botón o flujo'
                ],
                'evidence_to_collect': ['Request original y mutada', 'Rol/tenant/owner de cada cuenta', 'Diferencias de status o efecto persistente'],
                'impact_hypothesis': 'Broken authorization por frontera de ownership, rol o tenant'
            }
        if category == 'workflow_transition_hint':
            return {
                'goal': 'Verificar si transiciones de estado o aprobación pueden ejecutarse fuera del flujo esperado',
                'payload_classes': ['status_flip', 'approve_without_role', 'publish_without_review', 'invite_assign_chain'],
                'manual_checks': [
                    'Enviar cambios de status/state/publish/approve directamente por API',
                    'Comparar respuesta con y sin privilegios esperados',
                    'Observar si la transición genera efectos secundarios visibles'
                ],
                'evidence_to_collect': ['Estado antes y después', 'Request original y mutada', 'Rol necesario según UI o negocio'],
                'impact_hypothesis': 'Abuso de workflow, aprobación o asignación de privilegios'
            }
        if category == 'write_effect_chain_hint':
            return {
                'goal': 'Verificar si una escritura sensible impacta exportes, vistas, PDFs o notificaciones confiables',
                'payload_classes': ['update_then_export', 'update_then_preview', 'update_then_notify'],
                'manual_checks': [
                    'Modificar campos visibles y descargar export/report/pdf',
                    'Abrir detalle/preview/vista pública luego del cambio',
                    'Observar emails o notificaciones disparadas por el write'
                ],
                'evidence_to_collect': ['Objeto antes y después', 'Salida exportada/renderizada', 'Efecto secundario observable'],
                'impact_hypothesis': 'Manipulación de salidas confiables o efectos secundarios de negocio'
            }
        return super()._playbook_template(category)

    def _generate_validation_playbooks(self) -> None:
        super()._generate_validation_playbooks()
        playbooks = list(getattr(self, 'validation_playbooks', []))
        seen = {(p.get('category'), p.get('line'), p.get('sink_finding')) for p in playbooks}
        for item in self.stats.get('critical_mutations', []):
            categories = ['critical_mutation_endpoint']
            if item.get('body_field_count', 0) >= 6 or item.get('sensitive_fields'):
                categories.append('idor_or_authz_hint')
            if any(x in item.get('route_signals', []) for x in ['download', 'export', 'report', 'pdf']):
                categories.append('export_or_document_abuse')
            for category in categories:
                tpl = self._playbook_template(category)
                key = (category, item.get('line'), f"{item.get('method')} {item.get('endpoint')}")
                if key in seen or not tpl:
                    continue
                seen.add(key)
                playbooks.append({
                    'category': category,
                    'line': item.get('line'),
                    'confidence': item.get('confidence'),
                    'score': item.get('score') if category == 'critical_mutation_endpoint' else min(95, (item.get('score') or 0) + 4),
                    'source_signals': item.get('hypotheses', []),
                    'sink_finding': f"{item.get('method')} {item.get('endpoint')}",
                    'function': item.get('function'),
                    'chunk': item.get('chunk'),
                    'mutation_fields': item.get('sensitive_fields', []),
                    **tpl,
                })
        for item in self.stats.get('stored_xss_hints', []):
            tpl = self._playbook_template('stored_xss_hint')
            key = ('stored_xss_hint', item.get('line'), item.get('endpoint'))
            if key in seen:
                continue
            seen.add(key)
            playbooks.append({
                'category': 'stored_xss_hint',
                'line': item.get('line'),
                'confidence': item.get('confidence'),
                'score': item.get('score'),
                'source_signals': item.get('html_like_fields', []),
                'sink_finding': f"{item.get('method')} {item.get('endpoint')}",
                'function': item.get('function'),
                'chunk': item.get('chunk'),
                **tpl,
            })
        for item in self.stats.get('authz_surfaces', []):
            tpl = self._playbook_template('authz_surface_hint')
            key = ('authz_surface_hint', item.get('line'), item.get('endpoint'))
            if key not in seen:
                seen.add(key)
                playbooks.append({
                    'category': 'authz_surface_hint',
                    'line': item.get('line'),
                    'confidence': item.get('confidence'),
                    'score': item.get('score'),
                    'source_signals': item.get('signals', []),
                    'sink_finding': f"{item.get('method')} {item.get('endpoint')}",
                    **tpl,
                })
        for item in self.stats.get('workflow_surfaces', []):
            tpl = self._playbook_template('workflow_transition_hint')
            key = ('workflow_transition_hint', item.get('line'), item.get('endpoint'))
            if key not in seen:
                seen.add(key)
                playbooks.append({
                    'category': 'workflow_transition_hint',
                    'line': item.get('line'),
                    'confidence': item.get('confidence'),
                    'score': item.get('score'),
                    'source_signals': item.get('terms', []) + item.get('status_like_fields', []),
                    'sink_finding': f"{item.get('method')} {item.get('endpoint')}",
                    **tpl,
                })
        for item in self.stats.get('write_effect_chains', []):
            tpl = self._playbook_template('write_effect_chain_hint')
            key = ('write_effect_chain_hint', item.get('line'), item.get('endpoint'))
            if key not in seen:
                seen.add(key)
                playbooks.append({
                    'category': 'write_effect_chain_hint',
                    'line': item.get('line'),
                    'confidence': item.get('confidence'),
                    'score': item.get('score'),
                    'source_signals': item.get('effects', []),
                    'sink_finding': f"{item.get('method')} {item.get('endpoint')}",
                    **tpl,
                })
        self.validation_playbooks = sorted(playbooks, key=lambda x: (-(x.get('score') or 0), str(x.get('line') or ''), x.get('category') or ''))[:30]
        self.stats['validation_playbooks'] = self.validation_playbooks

    def _build_action_clusters(self) -> None:
        super()._build_action_clusters()
        clusters = [c for c in self.action_clusters if c.get('name') not in {'Business Critical Mutations', 'Stored XSS Candidates'}]
        muts = self.stats.get('critical_mutations', [])
        if muts:
            score = min(100, 55 + len(muts) * 8 + sum(1 for m in muts if m.get('id_in_path')) * 4)
            clusters.append({
                'name': 'Business Critical Mutations',
                'score': score,
                'confidence': 'high' if score >= 70 else 'medium',
                'endpoint_count': len({m['endpoint'] for m in muts}),
                'signal_counts': {
                    'critical_mutations': len(muts),
                    'idor_like': sum(1 for m in muts if 'idor_possible' in m.get('hypotheses', [])),
                    'mass_assignment_like': sum(1 for m in muts if 'mass_assignment_possible' in m.get('hypotheses', [])),
                    'business_flow_abuse_like': sum(1 for m in muts if 'business_flow_abuse_possible' in m.get('hypotheses', [])),
                },
                'interesting_endpoints': sorted({m['endpoint'] for m in muts})[:12],
                'interesting_params': [],
                'interesting_storage_keys': [],
                'interesting_headers': sorted({sig for m in muts for sig in m.get('auth_signals', [])})[:12],
                'finding_examples': [],
                'playbook_categories': [p['category'] for p in self.validation_playbooks if p['category'] in {'critical_mutation_endpoint', 'idor_or_authz_hint', 'export_or_document_abuse'}][:10],
                'taint_examples': [],
                'summary': f"Business Critical Mutations cluster [{score}] -> {len(muts)} mutation endpoints; {sum(1 for m in muts if m.get('id_in_path'))} with ID-like path; {sum(1 for m in muts if m.get('sensitive_fields'))} with sensitive fields",
            })
        sx = self.stats.get('stored_xss_hints', [])
        if sx:
            score = min(95, 48 + len(sx) * 7)
            clusters.append({
                'name': 'Stored XSS Candidates',
                'score': score,
                'confidence': 'high' if score >= 72 else 'medium',
                'endpoint_count': len({m['endpoint'] for m in sx}),
                'signal_counts': {'stored_xss_hints': len(sx)},
                'interesting_endpoints': sorted({m['endpoint'] for m in sx})[:12],
                'interesting_params': [],
                'interesting_storage_keys': [],
                'interesting_headers': [],
                'finding_examples': [],
                'playbook_categories': ['stored_xss_hint'],
                'taint_examples': [],
                'summary': f"Stored XSS Candidates cluster [{score}] -> {len(sx)} write endpoints with html-like fields and render sinks nearby",
            })
        rg = self.stats.get('resource_groups', [])
        if rg:
            score = min(96, 44 + len(rg) * 6 + sum(1 for r in rg if r.get('id_path_present')) * 4)
            clusters.append({
                'name': 'Resource CRUD Surfaces',
                'score': score,
                'confidence': 'high' if score >= 72 else 'medium',
                'endpoint_count': len({x['resource'] for x in rg}),
                'signal_counts': {'resource_groups': len(rg)},
                'interesting_endpoints': [x['resource'] for x in rg[:12]],
                'interesting_params': [],
                'interesting_storage_keys': [],
                'interesting_headers': [],
                'finding_examples': [],
                'playbook_categories': ['critical_mutation_endpoint','authz_surface_hint'],
                'taint_examples': [],
                'summary': f"Resource CRUD Surfaces cluster [{score}] -> {len(rg)} grouped internal resources with read/write patterns",
            })
        az = self.stats.get('authz_surfaces', [])
        if az:
            score = min(98, 48 + len(az) * 7)
            clusters.append({
                'name': 'Authorization Boundaries',
                'score': score,
                'confidence': 'high' if score >= 72 else 'medium',
                'endpoint_count': len({x['endpoint'] for x in az}),
                'signal_counts': {'authz_surfaces': len(az)},
                'interesting_endpoints': sorted({x['endpoint'] for x in az})[:12],
                'interesting_params': [],
                'interesting_storage_keys': [],
                'interesting_headers': [],
                'finding_examples': [],
                'playbook_categories': ['authz_surface_hint'],
                'taint_examples': [],
                'summary': f"Authorization Boundaries cluster [{score}] -> {len(az)} mutation endpoints with concrete ownership/role/tenant signals",
            })
        wf = self.stats.get('workflow_surfaces', [])
        if wf:
            score = min(96, 46 + len(wf) * 7)
            clusters.append({
                'name': 'Workflow / Approval',
                'score': score,
                'confidence': 'high' if score >= 72 else 'medium',
                'endpoint_count': len({x['endpoint'] for x in wf}),
                'signal_counts': {'workflow_surfaces': len(wf)},
                'interesting_endpoints': sorted({x['endpoint'] for x in wf})[:12],
                'interesting_params': [],
                'interesting_storage_keys': [],
                'interesting_headers': [],
                'finding_examples': [],
                'playbook_categories': ['workflow_transition_hint'],
                'taint_examples': [],
                'summary': f"Workflow / Approval cluster [{score}] -> {len(wf)} endpoints with status, approval or publish signals",
            })
        we = self.stats.get('write_effect_chains', [])
        if we:
            score = min(94, 44 + len(we) * 7)
            clusters.append({
                'name': 'Write → Effect Chains',
                'score': score,
                'confidence': 'high' if score >= 72 else 'medium',
                'endpoint_count': len({x['endpoint'] for x in we}),
                'signal_counts': {'write_effect_chains': len(we)},
                'interesting_endpoints': sorted({x['endpoint'] for x in we})[:12],
                'interesting_params': [],
                'interesting_storage_keys': [],
                'interesting_headers': [],
                'finding_examples': [],
                'playbook_categories': ['write_effect_chain_hint'],
                'taint_examples': [],
                'summary': f"Write → Effect Chains cluster [{score}] -> {len(we)} write endpoints linked to exports, rendering or notifications",
            })
        de = self.stats.get('document_export_flows', [])
        if de:
            score = min(96, 48 + len(de) * 7)
            clusters.append({
                'name': 'Documents / Exports',
                'score': score,
                'confidence': 'high' if score >= 72 else 'medium',
                'endpoint_count': len({x['endpoint'] for x in de}),
                'signal_counts': {'document_export_flows': len(de)},
                'interesting_endpoints': sorted({x['endpoint'] for x in de})[:12],
                'interesting_params': [],
                'interesting_storage_keys': [],
                'interesting_headers': [],
                'finding_examples': [],
                'playbook_categories': ['document_export_flow_hint'],
                'taint_examples': [],
                'summary': f"Documents / Exports cluster [{score}] -> {len(de)} mutation flows linked to PDFs, reports or trusted output",
            })
        rt = self.stats.get('realtime_surfaces', [])
        if rt:
            score = min(96, 46 + len(rt) * 6)
            clusters.append({
                'name': 'Realtime / Channel Surfaces',
                'score': score,
                'confidence': 'high' if score >= 72 else 'medium',
                'endpoint_count': len({str(x['endpoint']) for x in rt}),
                'signal_counts': {'realtime_surfaces': len(rt)},
                'interesting_endpoints': sorted({str(x['endpoint']) for x in rt})[:12],
                'interesting_params': [],
                'interesting_storage_keys': [],
                'interesting_headers': [],
                'finding_examples': [],
                'playbook_categories': ['realtime_surface_hint'],
                'taint_examples': [],
                'summary': f"Realtime / Channel Surfaces cluster [{score}] -> {len(rt)} websocket/postMessage/event surfaces with binding hints",
            })
        cr = self.stats.get('create_render_correlations', [])
        if cr:
            score = min(98, 50 + len(cr) * 8)
            clusters.append({
                'name': 'Create → Render Chains',
                'score': score,
                'confidence': 'high' if score >= 72 else 'medium',
                'endpoint_count': len({x['write_endpoint'] for x in cr}),
                'signal_counts': {'create_render_correlations': len(cr)},
                'interesting_endpoints': sorted({x['write_endpoint'] for x in cr})[:12],
                'interesting_params': [],
                'interesting_storage_keys': [],
                'interesting_headers': [],
                'finding_examples': [],
                'playbook_categories': ['create_render_chain_hint', 'stored_xss_hint'],
                'taint_examples': [],
                'summary': f"Create → Render Chains cluster [{score}] -> {len(cr)} write endpoints tied to later render/detail/preview views",
            })
        self.action_clusters = sorted(clusters, key=lambda x: (-x['score'], x['name']))[:12]
        self.stats['action_clusters'] = self.action_clusters

    def _top_hotspots(self) -> List[str]:
        hotspots = super()._top_hotspots()
        for mut in self.stats.get('critical_mutations', [])[:4]:
            hotspots.insert(0, f"mutation {mut['method']} {mut['endpoint'][:70]} [{mut['confidence']}/{mut['score']}]")
        for sx in self.stats.get('stored_xss_hints', [])[:3]:
            hotspots.insert(0, f"stored-xss {sx['method']} {sx['endpoint'][:64]} [{sx['confidence']}/{sx['score']}]")
        for item in self.stats.get('authz_surfaces', [])[:3]:
            hotspots.insert(0, f"authz {item['method']} {item['endpoint'][:64]} [{item['confidence']}/{item['score']}]")
        for item in self.stats.get('workflow_surfaces', [])[:2]:
            hotspots.insert(0, f"workflow {item['method']} {item['endpoint'][:60]} [{item['confidence']}/{item['score']}]")
        for item in self.stats.get('write_effect_chains', [])[:2]:
            hotspots.insert(0, f"write-effect {item['method']} {item['endpoint'][:56]} [{item['confidence']}/{item['score']}]")
        for item in self.stats.get('document_export_flows', [])[:2]:
            hotspots.insert(0, f"doc-export {item['method']} {item['endpoint'][:58]} [{item['confidence']}/{item['score']}]")
        for item in self.stats.get('realtime_surfaces', [])[:2]:
            hotspots.insert(0, f"realtime {str(item['endpoint'])[:62]} [{item['confidence']}/{item['score']}]")
        for item in self.stats.get('create_render_correlations', [])[:2]:
            hotspots.insert(0, f"create-render {item['method']} {item['write_endpoint'][:54]} [{item['confidence']}/{item['score']}]")
        for item in self.stats.get('resource_groups', [])[:2]:
            hotspots.insert(0, f"resource {item['resource'][:62]} methods={','.join(item['methods'])} [{item['confidence']}/{item['score']}]")
        deduped = []
        seen = set()
        for h in hotspots:
            if h not in seen:
                seen.add(h)
                deduped.append(h)
        return deduped[:14]

    def _print_results(self) -> None:
        super()._print_results()
        if self.stats.get('stored_xss_hints'):
            print(c(RED + BOLD, f"\n{'━' * 78}"))
            print(c(RED + BOLD, "  🧨 STORED XSS HINTS"))
            print(c(RED + BOLD, f"{'━' * 78}"))
            for item in self.stats['stored_xss_hints'][:8]:
                print(f"  {c(RED, item['method'])} {c(CYAN, item['endpoint'][:110])} L:{item['line']} {c(YELLOW, '[' + item['confidence'] + '/' + str(item['score']) + ']')}")
                if item.get('html_like_fields'):
                    print(f"      {c(DIM, 'fields: ' + ', '.join(item['html_like_fields'][:8]))}")
        if self.stats.get('critical_mutations'):
            print(c(RED + BOLD, f"\n{'━' * 78}"))
            print(c(RED + BOLD, "  🚨 CRITICAL MUTATIONS (business logic)"))
            print(c(RED + BOLD, f"{'━' * 78}"))
            for item in self.stats['critical_mutations'][:8]:
                print(f"  {c(RED, item['method'])} {c(CYAN, item['endpoint'][:110])} L:{item['line']} {c(YELLOW, '[' + item['confidence'] + '/' + str(item['score']) + ']')}")
                if item.get('hypotheses'):
                    print(f"      {c(DIM, 'hypotheses: ' + ', '.join(item['hypotheses']))}")
                if item.get('sensitive_fields'):
                    print(f"      {c(DIM, 'fields: ' + ', '.join(item['sensitive_fields'][:8]))}")

    def _build_report(self) -> Dict:
        report = super()._build_report()
        report['profile'] = self.profile
        report['critical_mutations'] = self.critical_mutations
        report['stored_xss_hints'] = self.stored_xss_hints
        report['resource_groups'] = self.resource_groups
        report['entities_map'] = self.entities_map
        report['authz_surfaces'] = self.authz_surfaces
        report['workflow_surfaces'] = self.workflow_surfaces
        report['write_effect_chains'] = self.write_effect_chains
        report['document_export_flows'] = self.document_export_flows
        report['realtime_surfaces'] = self.realtime_surfaces
        report['create_render_correlations'] = self.create_render_correlations
        report['stats']['critical_mutations'] = self.critical_mutations
        report['stats']['stored_xss_hints'] = self.stored_xss_hints
        report['stats']['resource_groups'] = self.resource_groups
        report['stats']['entities_map'] = self.entities_map
        report['stats']['authz_surfaces'] = self.authz_surfaces
        report['stats']['workflow_surfaces'] = self.workflow_surfaces
        report['stats']['write_effect_chains'] = self.write_effect_chains
        report['stats']['document_export_flows'] = self.document_export_flows
        report['stats']['realtime_surfaces'] = self.realtime_surfaces
        report['stats']['create_render_correlations'] = self.create_render_correlations
        return report



class JSAnalyzerV46(JSAnalyzerV4):
    def __init__(self, filepath: str, max_per: int = 5, scope: Optional[str] = None, app_only: bool = False, profile: str = "generic", baseline_json: Optional[str] = None):
        super().__init__(filepath, max_per=max_per, scope=scope, app_only=app_only, profile=profile)
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

    def _banner(self) -> None:
        size_kb = self.path.stat().st_size / 1024
        print(c(CYAN + BOLD, f"\n{'=' * 78}"))
        print(c(CYAN + BOLD, f"  JS Bundle Analyzer v4.6 — {self.path.name} ({size_kb:.1f} KB)"))
        if self.scope:
            print(c(CYAN + BOLD, f"  Scope: {self.scope}"))
        print(c(CYAN + BOLD, f"  Profile: {self.profile}"))
        if self.app_only:
            print(c(YELLOW + BOLD, "  Mode: APP-ONLY (vendor-high findings filtered)"))
        if self.baseline_json:
            print(c(CYAN + BOLD, f"  Baseline: {self.baseline_json}"))
        print(c(CYAN + BOLD, f"{'=' * 78}\n"))

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
        self._generate_validation_playbooks()
        self._build_action_clusters()
        self._build_final_risk_ranking()
        self._build_manual_test_queue()
        self._build_entity_journeys()
        self._build_investigation_bundle()
        self._build_diff_report()
        self._analyze_data_flow()
        self._analyze_access_control()
        self._detect_hidden_debug()
        self._detect_source_maps()
        self._detect_error_patterns()
        self._extract_comments()
        self._analyze_file_uploads()
        self._analyze_redirect_params()
        self._extract_cors_hints()
        self._print_results()
        return self._build_report()

    def _reasons_from_item(self, item: Dict) -> List[str]:
        reasons = []
        if item.get("id_path_present") or item.get("id_in_path"):
            reasons.append("id-like target in path")
        if item.get("method") in {"PUT", "PATCH", "DELETE"}:
            reasons.append(f"{item.get('method')} mutation")
        if item.get("sensitive_fields"):
            reasons.append("sensitive fields present")
        if item.get("signals"):
            reasons.append("authz boundary signals")
        if item.get("terms"):
            reasons.append("workflow terms present")
        if item.get("effects"):
            reasons.append("write->effect correlation")
        if item.get("html_like_fields"):
            reasons.append("persisted html-like fields")
        if item.get("events"):
            reasons.append("realtime events detected")
        return reasons[:5]

    def _build_final_risk_ranking(self) -> None:
        ranking = []
        seen = set()

        def push(kind: str, endpoint: str, method: str, line: Optional[int], score: int, reasons: List[str], extra: Optional[Dict] = None):
            if not endpoint:
                return
            key = (kind, method, endpoint)
            if key in seen:
                return
            seen.add(key)
            final_score = max(0, min(100, score))
            if final_score >= 85:
                priority = "critical"
            elif final_score >= 70:
                priority = "high"
            elif final_score >= 52:
                priority = "medium"
            else:
                priority = "low"
            entry = {
                "kind": kind,
                "endpoint": endpoint,
                "method": method,
                "line": line,
                "final_risk_score": final_score,
                "final_priority": priority,
                "why_ranked": reasons[:8],
            }
            if extra:
                entry.update(extra)
            ranking.append(entry)

        resource_map = {}
        for rg in self.resource_groups:
            for sample in rg.get("sample_endpoints", []):
                resource_map[sample] = rg

        for item in self.critical_mutations:
            score = item.get("score", 0)
            reasons = self._reasons_from_item(item)
            if item.get("id_in_path"):
                score += 8
            if "mass_assignment_possible" in item.get("hypotheses", []):
                score += 7
            if "idor_possible" in item.get("hypotheses", []):
                score += 8
            if item.get("endpoint") in resource_map:
                score += 5
                reasons.append("resource CRUD surface")
            if any(x for x in self.authz_surfaces if x.get("endpoint") == item.get("endpoint")):
                score += 8
                reasons.append("authz surface overlap")
            if any(x for x in self.workflow_surfaces if x.get("endpoint") == item.get("endpoint")):
                score += 6
                reasons.append("workflow overlap")
            if any(x for x in self.document_export_flows if x.get("endpoint") == item.get("endpoint")):
                score += 7
                reasons.append("document/export overlap")
            push("critical_mutation", item.get("endpoint", ""), item.get("method", ""), item.get("line"), score, reasons, {
                "hypotheses": item.get("hypotheses", []),
                "sensitive_fields": item.get("sensitive_fields", [])[:10],
            })

        for item in self.authz_surfaces:
            score = item.get("score", 0) + 8
            reasons = self._reasons_from_item(item)
            if "ownership_boundary_candidate" in item.get("hypotheses", []):
                score += 8
            if "tenant_boundary_candidate" in item.get("hypotheses", []):
                score += 6
            if item.get("method") in {"PUT", "PATCH", "DELETE"}:
                score += 6
            push("authz_surface", item.get("endpoint", ""), item.get("method", ""), item.get("line"), score, reasons, {
                "signals": item.get("signals", []),
                "hypotheses": item.get("hypotheses", []),
            })

        for item in self.workflow_surfaces:
            score = item.get("score", 0) + 6
            reasons = self._reasons_from_item(item)
            if any(t in item.get("terms", []) for t in ["approve", "publish", "verify", "genehmigen", "veröffentlichen"]):
                score += 10
                reasons.append("approval/publish semantics")
            push("workflow_surface", item.get("endpoint", ""), item.get("method", ""), item.get("line"), score, reasons, {
                "terms": item.get("terms", []),
                "hypotheses": item.get("hypotheses", []),
            })

        for item in self.stored_xss_hints:
            score = item.get("score", 0) + 8
            reasons = self._reasons_from_item(item)
            linked = [x for x in self.create_render_correlations if x.get("write_endpoint") == item.get("endpoint")]
            if linked:
                score += 10
                reasons.append("create->render chain")
            push("stored_xss_hint", item.get("endpoint", ""), item.get("method", ""), item.get("line"), score, reasons, {
                "html_like_fields": item.get("html_like_fields", []),
            })

        for item in self.document_export_flows:
            score = item.get("score", 0) + 8
            reasons = self._reasons_from_item(item)
            if any(t in item.get("terms", []) for t in ["pdf", "report", "export", "invoice", "receipt"]):
                score += 8
                reasons.append("trusted output candidate")
            push("document_export_flow", item.get("endpoint", ""), item.get("method", ""), item.get("line"), score, reasons, {
                "terms": item.get("terms", []),
                "fields": item.get("fields", []),
            })

        for item in self.realtime_surfaces:
            score = item.get("score", 0) + 6
            reasons = self._reasons_from_item(item)
            if "identifier_in_ws_url" in item.get("signals", []):
                score += 10
                reasons.append("identifier in ws/url")
            if "session_binding_terms" in item.get("signals", []):
                score += 8
                reasons.append("session binding terms")
            push("realtime_surface", str(item.get("endpoint", "")), item.get("protocol", ""), item.get("line"), score, reasons, {
                "signals": item.get("signals", []),
                "events": item.get("events", []),
            })

        for item in self.create_render_correlations:
            score = item.get("score", 0) + 5
            reasons = ["create->render chain", "write endpoint tied to read/render route"]
            if item.get("related_routes"):
                reasons.append("related routes found")
            if item.get("fields"):
                reasons.append("content-bearing fields")
            push("create_render_correlation", item.get("write_endpoint", ""), item.get("method", ""), item.get("line"), score, reasons, {
                "fields": item.get("fields", []),
                "related_routes": item.get("related_routes", []),
            })

        ranking.sort(key=lambda x: (-x["final_risk_score"], x["endpoint"], x["kind"]))
        self.final_risk_ranking = ranking[:60]
        self.stats["final_risk_ranking"] = self.final_risk_ranking

    def _build_manual_test_queue(self) -> None:
        queue = {
            "idor": [],
            "workflow_bypass": [],
            "stored_xss": [],
            "document_export_abuse": [],
            "realtime_session_binding": [],
        }

        for item in self.final_risk_ranking:
            endpoint = item.get("endpoint", "")
            method = item.get("method", "")
            if item.get("kind") in {"critical_mutation", "authz_surface"}:
                queue["idor"].append({
                    "endpoint": endpoint,
                    "method": method,
                    "priority": item.get("final_priority"),
                    "why": item.get("why_ranked", [])[:4],
                    "test": "swap ids in path/body/query and compare own vs foreign object",
                    "look_for": "200/204 on foreign object, differential JSON, persisted changes",
                })
            if item.get("kind") == "workflow_surface":
                queue["workflow_bypass"].append({
                    "endpoint": endpoint,
                    "method": method,
                    "priority": item.get("final_priority"),
                    "why": item.get("why_ranked", [])[:4],
                    "test": "force status/approve/publish transitions directly via API",
                    "look_for": "state change without expected role or review flow",
                })
            if item.get("kind") in {"stored_xss_hint", "create_render_correlation"}:
                queue["stored_xss"].append({
                    "endpoint": endpoint,
                    "method": method,
                    "priority": item.get("final_priority"),
                    "why": item.get("why_ranked", [])[:4],
                    "test": "persist safe HTML probes and revisit detail/list/preview routes",
                    "look_for": "HTML interpretation, admin-only render, preview/detail reflection",
                })
            if item.get("kind") == "document_export_flow":
                queue["document_export_abuse"].append({
                    "endpoint": endpoint,
                    "method": method,
                    "priority": item.get("final_priority"),
                    "why": item.get("why_ranked", [])[:4],
                    "test": "modify visible/business fields and download pdf/report/export after write",
                    "look_for": "trusted document output reflecting tampered data",
                })
            if item.get("kind") == "realtime_surface":
                queue["realtime_session_binding"].append({
                    "endpoint": endpoint,
                    "method": method,
                    "priority": item.get("final_priority"),
                    "why": item.get("why_ranked", [])[:4],
                    "test": "change uid/conversation/channel identifiers and compare session isolation",
                    "look_for": "cross-session messages, hijack, join, replay or impersonation",
                })

        for key in list(queue.keys()):
            dedup = []
            seen = set()
            for item in queue[key]:
                sig = (item["endpoint"], item["method"])
                if sig in seen:
                    continue
                seen.add(sig)
                dedup.append(item)
            queue[key] = dedup[:12]

        self.manual_test_queue = queue
        self.stats["manual_test_queue"] = self.manual_test_queue

    def _infer_entity_from_endpoint(self, endpoint: str) -> str:
        path = endpoint.lower()
        path = re.sub(r'^https?://[^/]+', '', path)
        segments = [s for s in re.split(r'[/?&=._-]+', path) if s and s not in {"api", "v1", "v2", "v3", "admin", "internal", "public", "{id}"}]
        for seg in reversed(segments):
            if len(seg) > 2 and not seg.isdigit():
                return seg
        return "unknown"

    def _build_entity_journeys(self) -> None:
        journeys = {}
        def ensure(entity: str) -> Dict[str, Any]:
            return journeys.setdefault(entity, {
                "entity": entity,
                "create_endpoints": set(),
                "update_endpoints": set(),
                "read_routes": set(),
                "export_routes": set(),
                "realtime_channels": set(),
                "risk_signals": set(),
                "score": 20,
            })

        for item in self.critical_mutations:
            entity = self._infer_entity_from_endpoint(item.get("endpoint", ""))
            entry = ensure(entity)
            if item.get("method") == "POST":
                entry["create_endpoints"].add(item.get("endpoint", ""))
            else:
                entry["update_endpoints"].add(item.get("endpoint", ""))
            entry["risk_signals"].update(item.get("hypotheses", []))
            entry["score"] += 8

        for item in self.create_render_correlations:
            entity = self._infer_entity_from_endpoint(item.get("write_endpoint", ""))
            entry = ensure(entity)
            entry["read_routes"].update(item.get("related_routes", []))
            entry["risk_signals"].update(item.get("hypotheses", []))
            entry["score"] += 8

        for item in self.document_export_flows:
            entity = self._infer_entity_from_endpoint(item.get("endpoint", ""))
            entry = ensure(entity)
            entry["export_routes"].add(item.get("endpoint", ""))
            entry["risk_signals"].update(item.get("hypotheses", []))
            entry["score"] += 7

        for item in self.realtime_surfaces:
            entity = self._infer_entity_from_endpoint(str(item.get("endpoint", "")))
            entry = ensure(entity)
            entry["realtime_channels"].add(str(item.get("endpoint", "")))
            entry["risk_signals"].update(item.get("hypotheses", []))
            entry["score"] += 6

        out = []
        for entity, item in journeys.items():
            score = item["score"]
            risk = "high" if score >= 42 else "medium" if score >= 28 else "low"
            out.append({
                "entity": entity,
                "create_endpoints": sorted(x for x in item["create_endpoints"] if x)[:10],
                "update_endpoints": sorted(x for x in item["update_endpoints"] if x)[:10],
                "read_routes": sorted(x for x in item["read_routes"] if x)[:10],
                "export_routes": sorted(x for x in item["export_routes"] if x)[:10],
                "realtime_channels": sorted(x for x in item["realtime_channels"] if x)[:10],
                "risk_signals": sorted(x for x in item["risk_signals"] if x)[:12],
                "risk": risk,
                "score": min(100, score),
            })
        self.entity_journeys = sorted(out, key=lambda x: (-x["score"], x["entity"]))[:25]
        self.stats["entity_journeys"] = self.entity_journeys

    def _build_investigation_bundle(self) -> None:
        self.investigation_bundle = {
            "top_5_endpoints": self.final_risk_ranking[:5],
            "top_5_idor_candidates": self.manual_test_queue.get("idor", [])[:5],
            "top_5_workflow_bypass": self.manual_test_queue.get("workflow_bypass", [])[:5],
            "top_5_stored_xss": self.manual_test_queue.get("stored_xss", [])[:5],
            "top_5_export_abuse": self.manual_test_queue.get("document_export_abuse", [])[:5],
            "top_5_realtime_tests": self.manual_test_queue.get("realtime_session_binding", [])[:5],
        }
        self.stats["investigation_bundle"] = self.investigation_bundle

    def _load_baseline_report(self) -> Dict[str, Any]:
        if not self.baseline_json:
            return {}
        try:
            return json.loads(Path(self.baseline_json).read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _build_diff_report(self) -> None:
        baseline = self._load_baseline_report()
        if not baseline:
            self.diff_report = {}
            self.stats["diff_report"] = self.diff_report
            return

        def keyset(items, fields):
            out = set()
            for item in items or []:
                if isinstance(item, dict):
                    out.add(tuple(item.get(f, "") for f in fields))
            return out

        current_endpoints = {f"{x.get('type','')}::{x.get('url','')}" for x in self.endpoints}
        baseline_endpoints = {f"{x.get('type','')}::{x.get('url','')}" for x in baseline.get("endpoints", [])}
        current_muts = keyset(self.critical_mutations, ["method", "endpoint"])
        baseline_muts = keyset(baseline.get("critical_mutations", []), ["method", "endpoint"])
        current_authz = keyset(self.authz_surfaces, ["method", "endpoint"])
        baseline_authz = keyset(baseline.get("authz_surfaces", []), ["method", "endpoint"])
        current_workflow = keyset(self.workflow_surfaces, ["method", "endpoint"])
        baseline_workflow = keyset(baseline.get("workflow_surfaces", []), ["method", "endpoint"])

        self.diff_report = {
            "baseline_file": self.baseline_json,
            "new_endpoints": sorted(current_endpoints - baseline_endpoints)[:60],
            "new_mutations": [{"method": m, "endpoint": e} for m, e in sorted(current_muts - baseline_muts)[:30]],
            "new_authz_surfaces": [{"method": m, "endpoint": e} for m, e in sorted(current_authz - baseline_authz)[:30]],
            "new_workflow_surfaces": [{"method": m, "endpoint": e} for m, e in sorted(current_workflow - baseline_workflow)[:30]],
        }
        self.stats["diff_report"] = self.diff_report

    def _top_hotspots(self) -> List[str]:
        hotspots = super()._top_hotspots()
        for item in self.final_risk_ranking[:5]:
            hotspots.insert(0, f"final {item['kind']} {item['method']} {item['endpoint'][:54]} [{item['final_priority']}/{item['final_risk_score']}]")
        deduped = []
        seen = set()
        for h in hotspots:
            if h not in seen:
                seen.add(h)
                deduped.append(h)
        return deduped[:16]

    def _print_results(self) -> None:
        super()._print_results()
        if self.final_risk_ranking:
            print(c(RED + BOLD, f"\n{'━' * 78}"))
            print(c(RED + BOLD, "  🎯 FINAL RISK RANKING"))
            print(c(RED + BOLD, f"{'━' * 78}"))
            for item in self.final_risk_ranking[:10]:
                print(f"  {c(RED, item['final_priority'].upper())} {c(CYAN, item['method'])} {c(CYAN, item['endpoint'][:100])} {c(YELLOW, '[' + str(item['final_risk_score']) + ']')}")
                if item.get("why_ranked"):
                    print(f"      {c(DIM, 'why: ' + ' | '.join(item['why_ranked'][:4]))}")

        if self.manual_test_queue:
            print(c(CYAN + BOLD, f"\n{'━' * 78}"))
            print(c(CYAN + BOLD, "  🧪 MANUAL TEST QUEUE"))
            print(c(CYAN + BOLD, f"{'━' * 78}"))
            for bucket, items in self.manual_test_queue.items():
                if not items:
                    continue
                print(f"\n  {c(BOLD, bucket)}:")
                for item in items[:3]:
                    print(f"    {c(CYAN, item['method'])} {c(CYAN, item['endpoint'][:90])} {c(YELLOW, '[' + item['priority'] + ']')}")
                    print(f"      {c(DIM, item['test'])}")

        if self.entity_journeys:
            print(c(MAGENTA + BOLD, f"\n{'━' * 78}"))
            print(c(MAGENTA + BOLD, "  🧭 ENTITY JOURNEYS"))
            print(c(MAGENTA + BOLD, f"{'━' * 78}"))
            for item in self.entity_journeys[:8]:
                print(f"  {c(BOLD, item['entity'])} {c(YELLOW, '[' + item['risk'] + '/' + str(item['score']) + ']')}")
                if item.get("create_endpoints"):
                    print(f"      {c(DIM, 'create: ' + ', '.join(item['create_endpoints'][:2]))}")
                if item.get("update_endpoints"):
                    print(f"      {c(DIM, 'update: ' + ', '.join(item['update_endpoints'][:2]))}")
                if item.get("read_routes"):
                    print(f"      {c(DIM, 'read: ' + ', '.join(item['read_routes'][:2]))}")
                if item.get("export_routes"):
                    print(f"      {c(DIM, 'export: ' + ', '.join(item['export_routes'][:2]))}")

        if self.diff_report:
            print(c(YELLOW + BOLD, f"\n{'━' * 78}"))
            print(c(YELLOW + BOLD, "  🆚 DIFF REPORT"))
            print(c(YELLOW + BOLD, f"{'━' * 78}"))
            print(f"  baseline: {c(CYAN, str(self.diff_report.get('baseline_file', '')))}")
            print(f"  new_endpoints: {c(CYAN, str(len(self.diff_report.get('new_endpoints', []))))}")
            print(f"  new_mutations: {c(CYAN, str(len(self.diff_report.get('new_mutations', []))))}")
            print(f"  new_authz_surfaces: {c(CYAN, str(len(self.diff_report.get('new_authz_surfaces', []))))}")
            print(f"  new_workflow_surfaces: {c(CYAN, str(len(self.diff_report.get('new_workflow_surfaces', []))))}")

    def _build_report(self) -> Dict:
        report = super()._build_report()
        report["version"] = "4.6"
        report["final_risk_ranking"] = self.final_risk_ranking
        report["manual_test_queue"] = self.manual_test_queue
        report["entity_journeys"] = self.entity_journeys
        report["investigation_bundle"] = self.investigation_bundle
        report["diff_report"] = self.diff_report
        report["stats"]["final_risk_ranking"] = self.final_risk_ranking
        report["stats"]["manual_test_queue"] = self.manual_test_queue
        report["stats"]["entity_journeys"] = self.entity_journeys
        report["stats"]["investigation_bundle"] = self.investigation_bundle
        report["stats"]["diff_report"] = self.diff_report
        return report



class JSAnalyzerV47(JSAnalyzerV46):
    def __init__(self, filepath: str, max_per: int = 5, scope: Optional[str] = None, app_only: bool = False, profile: str = "generic", baseline_json: Optional[str] = None):
        super().__init__(filepath, max_per=max_per, scope=scope, app_only=app_only, profile=profile, baseline_json=baseline_json)
        self.prototype_pollution_hints: List[Dict] = []
        self.postmessage_analysis: List[Dict] = []
        self.file_media_surfaces: List[Dict] = []
        self.redirect_callback_abuse: List[Dict] = []
        self.attack_paths: List[Dict] = []

    def _banner(self) -> None:
        size_kb = self.path.stat().st_size / 1024
        print(c(CYAN + BOLD, f"\n{'=' * 78}"))
        print(c(CYAN + BOLD, f"  JS Bundle Analyzer v4.7 — {self.path.name} ({size_kb:.1f} KB)"))
        if self.scope:
            print(c(CYAN + BOLD, f"  Scope: {self.scope}"))
        print(c(CYAN + BOLD, f"  Profile: {self.profile}"))
        if self.app_only:
            print(c(YELLOW + BOLD, "  Mode: APP-ONLY (vendor-high findings filtered)"))
        if self.baseline_json:
            print(c(CYAN + BOLD, f"  Baseline: {self.baseline_json}"))
        print(c(CYAN + BOLD, f"{'=' * 78}\n"))

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
        self._generate_validation_playbooks()
        self._build_action_clusters()
        self._build_final_risk_ranking()
        self._boost_final_risk_ranking_v47()
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

    def _detect_prototype_pollution_hints(self) -> None:
        hints = []
        seen = set()
        merge_specs = [
            ("object_assign", r"Object\.assign\s*\("),
            ("lodash_merge", r"(?:_|lodash)\.merge\s*\("),
            ("lodash_defaultsdeep", r"(?:_|lodash)\.defaultsDeep\s*\("),
            ("jquery_extend", r"(?:jQuery|\$)\.extend\s*\("),
            ("generic_merge", r"\bmerge\s*\("),
            ("deep_set", r"\bset\s*\([^\n]{0,120}(?:__proto__|constructor|prototype)"),
        ]
        poison_terms = r"__proto__|constructor\.prototype|prototype\s*\]|prototype\s*:"
        source_terms = r"location\.search|URLSearchParams|qs\.parse|querystring|event\.data|JSON\.parse\(|response\.data|res\.data"
        for name, pat in merge_specs:
            for m in re.finditer(pat, self.content, re.I):
                if self._vendor_confidence(m.start()) == 'high':
                    continue
                block = self._get_logical_block(m.start(), 700, 2200)
                signals = [name]
                if re.search(poison_terms, block, re.I):
                    signals.append('prototype_key_terms')
                if re.search(source_terms, block, re.I):
                    signals.append('user_controlled_object_source')
                if re.search(r'deep|recursive|nested|clone', block, re.I):
                    signals.append('deep_merge_semantics')
                score = 48 + len(signals) * 9
                if 'prototype_key_terms' in signals:
                    score += 16
                if 'user_controlled_object_source' in signals:
                    score += 10
                key = (name, self._line_of(m.start()), self._get_func_context(m.start()))
                if key in seen:
                    continue
                seen.add(key)
                hints.append({
                    'kind': name,
                    'line': self._line_of(m.start()),
                    'function': self._get_func_context(m.start()),
                    'chunk': (self._chunk_at(m.start()).label or self._chunk_at(m.start()).name) if self._chunk_at(m.start()) else '',
                    'signals': signals,
                    'confidence': 'high' if score >= 78 else 'medium',
                    'score': min(96, score),
                    'hypotheses': ['prototype_pollution_candidate', 'unsafe_merge_candidate'],
                })
        self.prototype_pollution_hints = sorted(hints, key=lambda x: (-x['score'], x['line']))[:20]
        self.stats['prototype_pollution_hints'] = self.prototype_pollution_hints

    def _analyze_postmessage_deep(self) -> None:
        items = []
        seen = set()
        listener_re = re.compile(r"addEventListener\s*\(\s*['\"]message['\"]", re.I)
        sink_map = {
            'html_sink': r'innerHTML\s*=|outerHTML\s*=|insertAdjacentHTML\(|dangerouslySetInnerHTML|\.html\s*\(',
            'navigation_sink': r'location(?:\.href)?\s*=|location\.(?:assign|replace)\(|window\.open\(',
            'request_sink': r'fetch\s*\(|axios\.(?:get|post|put|patch|delete)\s*\(',
            'code_sink': r'(?<![\w.])eval\s*\(|new\s+Function\s*\('
        }
        for m in listener_re.finditer(self.content):
            if self._vendor_confidence(m.start()) == 'high':
                continue
            block = self._get_logical_block(m.start(), 900, 2800)
            signals = []
            if re.search(r'event\.origin|origin\s*===|origin\s*!==|allowedOrigins?|trustedOrigins?', block, re.I):
                signals.append('origin_check_present')
            else:
                signals.append('origin_check_missing')
            if re.search(r'event\.source|source\s*===|window\.parent|iframe', block, re.I):
                signals.append('source_logic_present')
            if re.search(r'event\.data|message\.data', block, re.I):
                signals.append('message_data_used')
            sink_hits = [name for name, pat in sink_map.items() if re.search(pat, block, re.I)]
            data_keys = sorted(set(re.findall(r'event\.data\.([A-Za-z_$][\w$]{1,60})', block)))[:12]
            score = 42 + len(signals) * 8 + len(sink_hits) * 10 + len(data_keys) * 2
            if 'origin_check_missing' in signals and sink_hits:
                score += 14
            key = (self._line_of(m.start()), tuple(sink_hits), tuple(data_keys[:4]))
            if key in seen:
                continue
            seen.add(key)
            items.append({
                'line': self._line_of(m.start()),
                'function': self._get_func_context(m.start()),
                'signals': signals,
                'sinks': sink_hits,
                'data_keys': data_keys,
                'confidence': 'high' if score >= 78 else 'medium',
                'score': min(96, score),
                'hypotheses': ['postmessage_injection_candidate'] + (['cross_origin_message_surface'] if 'origin_check_missing' in signals else []),
            })
        self.postmessage_analysis = sorted(items, key=lambda x: (-x['score'], x['line']))[:20]
        self.stats['postmessage_analysis'] = self.postmessage_analysis

    def _detect_file_media_surfaces(self) -> None:
        surfaces = []
        seen = set()
        patterns = [
            ('formdata_append', r'FormData\s*\(|\.append\s*\(\s*["\"][A-Za-z_][A-Za-z0-9_-]{1,60}["\"]'),
            ('file_input', r'type\s*=\s*["\"]file["\"]|accept\s*[:=]\s*["\"][^"\
]+["\"]'),
            ('file_reader', r'FileReader\s*\(|readAsDataURL\(|readAsText\('),
            ('preview_terms', r'preview|thumbnail|crop|editor|viewer|render|pdf|image|media|attachment|document'),
        ]
        block_re = re.compile(r'(?:FormData\s*\(|type\s*=\s*["\"]file["\"]|FileReader\s*\(|readAsDataURL\(|readAsText\()', re.I)
        for m in block_re.finditer(self.content):
            if self._vendor_confidence(m.start()) == 'high':
                continue
            block = self._get_logical_block(m.start(), 900, 2600)
            signals = [name for name, pat in patterns if re.search(pat, block, re.I)]
            fields = sorted(set(re.findall(r'\.append\s*\(\s*["\"]([A-Za-z_][A-Za-z0-9_-]{1,60})["\"]', block)))[:12]
            accepts = sorted(set(re.findall(r'accept\s*[:=]\s*["\"]([^"\n]+)["\"]', block)))[:8]
            validators = []
            if re.search(r'mime|content[-_ ]type|file\.type', block, re.I):
                validators.append('mime_check')
            if re.search(r'\.endsWith\(|extension|\.split\([^\n]{0,60}\.', block, re.I):
                validators.append('extension_check')
            if re.search(r'size|files\[0\]\.size|maxSize', block, re.I):
                validators.append('size_check')
            linked_exports = [x.get('endpoint') for x in self.document_export_flows if any(t in (x.get('endpoint','') + ' ' + ' '.join(x.get('terms', []))).lower() for t in ['pdf','document','file','media','preview'])][:5]
            score = 44 + len(signals) * 7 + len(fields) * 3 + len(validators) * 3
            if accepts and any(x for x in accepts if 'svg' in x.lower() or 'html' in x.lower() or 'pdf' in x.lower()):
                score += 10
            if linked_exports:
                score += 8
            key = (self._line_of(m.start()), tuple(fields[:4]), tuple(accepts[:2]))
            if key in seen:
                continue
            seen.add(key)
            surfaces.append({
                'line': self._line_of(m.start()),
                'function': self._get_func_context(m.start()),
                'signals': signals,
                'fields': fields,
                'accepts': accepts,
                'validators': validators,
                'linked_export_flows': linked_exports,
                'confidence': 'high' if score >= 76 else 'medium',
                'score': min(95, score),
                'hypotheses': ['file_media_surface', 'upload_preview_candidate'],
            })
        self.file_media_surfaces = sorted(surfaces, key=lambda x: (-x['score'], x['line']))[:20]
        self.stats['file_media_surfaces'] = self.file_media_surfaces

    def _detect_redirect_callback_abuse(self) -> None:
        items = []
        seen = set()
        redirectish = sorted(set(re.findall(r'(returnto|redirect_uri|next|return_url|goto|continue|target|destination|callback_url|success_url|error_url|relaystate|returnTo)', self.content, re.I)))
        auth_urls = []
        for flow in self.stats.get('auth_flows', []):
            if flow.get('type') == 'Auth endpoints':
                auth_urls.extend(flow.get('urls', []))
        endpoint_matches = [ep for ep in self.endpoints if re.search(r'login|logout|auth|oauth|callback|saml|signin|signout', ep.get('url',''), re.I)]
        for ep in endpoint_matches[:30]:
            url = ep.get('url', '')
            score = 36
            reasons = []
            if redirectish:
                score += min(18, len(redirectish) * 4)
                reasons.append('redirect parameters present')
            if re.search(r'callback|oauth|saml|signin|login|logout', url, re.I):
                score += 10
                reasons.append('auth or callback endpoint')
            if re.search(r'redirect|return|next|success|error|callback', self.content[max(0, self.content.find(url)-800):min(len(self.content), self.content.find(url)+1200)], re.I):
                score += 8
                reasons.append('redirect semantics nearby')
            key = (url, tuple(redirectish[:4]))
            if key in seen:
                continue
            seen.add(key)
            items.append({
                'endpoint': url,
                'method': '',
                'line': None,
                'params': redirectish[:12],
                'confidence': 'high' if score >= 72 else 'medium',
                'score': min(90, score),
                'hypotheses': ['redirect_callback_abuse_candidate'],
                'reasons': reasons,
            })
        self.redirect_callback_abuse = sorted(items, key=lambda x: (-x['score'], x['endpoint']))[:20]
        self.stats['redirect_callback_abuse'] = self.redirect_callback_abuse

    def _boost_final_risk_ranking_v47(self) -> None:
        boosts = {}
        authz_eps = {x.get('endpoint','') for x in self.authz_surfaces}
        workflow_eps = {x.get('endpoint','') for x in self.workflow_surfaces}
        doc_eps = {x.get('endpoint','') for x in self.document_export_flows}
        render_eps = {x.get('write_endpoint','') for x in self.create_render_correlations}
        realtime_eps = {str(x.get('endpoint','')) for x in self.realtime_surfaces}
        for item in self.final_risk_ranking:
            endpoint = item.get('endpoint', '')
            kind = item.get('kind')
            boost = 0
            why = list(item.get('why_ranked', []))
            if endpoint in authz_eps and endpoint in workflow_eps:
                boost += 9
                why.append('authz + workflow cross-signal')
            if endpoint in doc_eps and endpoint in render_eps:
                boost += 10
                why.append('render + export chain')
            if kind == 'critical_mutation' and endpoint in render_eps:
                boost += 7
                why.append('mutation + render chain')
            if kind == 'realtime_surface' and any(sig in item.get('signals', []) for sig in ['identifier_in_ws_url', 'session_binding_terms']):
                boost += 8
                why.append('realtime binding weakness')
            if kind == 'stored_xss_hint' and endpoint in doc_eps:
                boost += 7
                why.append('stored content reaches docs/exports')
            item['final_risk_score'] = min(100, item.get('final_risk_score', 0) + boost)
            if item['final_risk_score'] >= 85:
                item['final_priority'] = 'critical'
            elif item['final_risk_score'] >= 70:
                item['final_priority'] = 'high'
            elif item['final_risk_score'] >= 52:
                item['final_priority'] = 'medium'
            else:
                item['final_priority'] = 'low'
            item['why_ranked'] = why[:10]
        self.final_risk_ranking = sorted(self.final_risk_ranking, key=lambda x: (-x['final_risk_score'], x['endpoint'], x['kind']))[:70]
        self.stats['final_risk_ranking'] = self.final_risk_ranking

    def _build_manual_test_queue(self) -> None:
        super()._build_manual_test_queue()
        for item in self.redirect_callback_abuse[:8]:
            self.manual_test_queue['idor'].append({
                'endpoint': item.get('endpoint',''),
                'method': item.get('method','GET') or 'GET',
                'priority': item.get('confidence','medium'),
                'why': item.get('reasons', [])[:4],
                'test': 'tamper redirect/callback parameters with absolute, scheme-relative and encoded targets',
                'look_for': 'external redirect, callback confusion, auth flow redirection',
            })
        for item in self.prototype_pollution_hints[:8]:
            self.manual_test_queue['workflow_bypass'].append({
                'endpoint': item.get('function','prototype_merge_surface'),
                'method': 'merge',
                'priority': item.get('confidence','medium'),
                'why': item.get('signals', [])[:4],
                'test': 'probe __proto__, constructor.prototype and nested object keys through query/body/message objects',
                'look_for': 'unexpected flags, polluted defaults, auth or UI state changes',
            })
        for item in self.file_media_surfaces[:8]:
            self.manual_test_queue['document_export_abuse'].append({
                'endpoint': item.get('function','file_media_surface'),
                'method': 'upload',
                'priority': item.get('confidence','medium'),
                'why': item.get('signals', [])[:4],
                'test': 'upload svg/html/polyglot-like files and revisit preview/render/export paths',
                'look_for': 'stored rendering, pdf preview execution, file metadata trust',
            })
        for item in self.postmessage_analysis[:8]:
            self.manual_test_queue['realtime_session_binding'].append({
                'endpoint': item.get('function','postmessage_listener'),
                'method': 'postMessage',
                'priority': item.get('confidence','medium'),
                'why': item.get('signals', [])[:4] + item.get('sinks', [])[:2],
                'test': 'send crafted cross-origin messages with object and string payloads to the listener',
                'look_for': 'missing origin check, html/navigation/request sinks reached',
            })
        for k in list(self.manual_test_queue):
            dedup = []
            seen = set()
            for item in self.manual_test_queue[k]:
                key = (item.get('endpoint'), item.get('method'), item.get('test'))
                if key in seen:
                    continue
                seen.add(key)
                dedup.append(item)
            self.manual_test_queue[k] = dedup[:12]
        self.stats['manual_test_queue'] = self.manual_test_queue

    def _build_attack_paths(self) -> None:
        paths = []
        seen = set()
        for item in self.create_render_correlations[:12]:
            path = {
                'path': 'create -> render',
                'entity': (item.get('fields') or ['content'])[0],
                'risk': 'high' if item.get('score', 0) >= 78 else 'medium',
                'score': min(96, item.get('score', 0) + 6),
                'entrypoints': [item.get('write_endpoint','')],
                'followups': item.get('related_routes', [])[:6],
                'candidate_bugs': ['stored_xss', 'trusted_content_tamper'],
            }
            key = (path['path'], tuple(path['entrypoints']), tuple(path['followups']))
            if key not in seen:
                seen.add(key)
                paths.append(path)
        for item in self.document_export_flows[:10]:
            path = {
                'path': 'write -> export',
                'entity': (item.get('fields') or item.get('terms') or ['document'])[0],
                'risk': 'high' if item.get('score', 0) >= 76 else 'medium',
                'score': min(96, item.get('score', 0) + 5),
                'entrypoints': [item.get('endpoint','')],
                'followups': item.get('terms', [])[:6],
                'candidate_bugs': ['document_tampering', 'report_abuse'],
            }
            key = (path['path'], tuple(path['entrypoints']), tuple(path['followups']))
            if key not in seen:
                seen.add(key)
                paths.append(path)
        for item in self.workflow_surfaces[:10]:
            path = {
                'path': 'update -> workflow transition',
                'entity': (item.get('status_like_fields') or item.get('terms') or ['status'])[0],
                'risk': 'high' if item.get('score', 0) >= 76 else 'medium',
                'score': min(95, item.get('score', 0) + 4),
                'entrypoints': [item.get('endpoint','')],
                'followups': item.get('terms', [])[:6],
                'candidate_bugs': ['approval_bypass', 'workflow_abuse'],
            }
            key = (path['path'], tuple(path['entrypoints']), tuple(path['followups']))
            if key not in seen:
                seen.add(key)
                paths.append(path)
        for item in self.realtime_surfaces[:10]:
            path = {
                'path': 'bind -> channel -> inject',
                'entity': (item.get('events') or ['message'])[0],
                'risk': 'high' if item.get('score', 0) >= 78 else 'medium',
                'score': min(95, item.get('score', 0) + 5),
                'entrypoints': [str(item.get('endpoint',''))],
                'followups': item.get('signals', [])[:6],
                'candidate_bugs': ['session_binding_abuse', 'message_injection', 'chat_hijack'],
            }
            key = (path['path'], tuple(path['entrypoints']), tuple(path['followups']))
            if key not in seen:
                seen.add(key)
                paths.append(path)
        for item in self.prototype_pollution_hints[:10]:
            path = {
                'path': 'parse -> merge -> state change',
                'entity': (item.get('signals') or ['object'])[0],
                'risk': 'high' if item.get('score', 0) >= 80 else 'medium',
                'score': min(95, item.get('score', 0) + 4),
                'entrypoints': [item.get('function','unsafe_merge_surface')],
                'followups': item.get('signals', [])[:6],
                'candidate_bugs': ['prototype_pollution', 'unsafe_merge'],
            }
            key = (path['path'], tuple(path['entrypoints']), tuple(path['followups']))
            if key not in seen:
                seen.add(key)
                paths.append(path)
        self.attack_paths = sorted(paths, key=lambda x: (-x['score'], x['path']))[:24]
        self.stats['attack_paths'] = self.attack_paths

    def _build_investigation_bundle(self) -> None:
        super()._build_investigation_bundle()
        self.investigation_bundle['top_prototype_pollution'] = self.prototype_pollution_hints[:5]
        self.investigation_bundle['top_postmessage'] = self.postmessage_analysis[:5]
        self.investigation_bundle['top_file_media'] = self.file_media_surfaces[:5]
        self.investigation_bundle['top_redirect_callback'] = self.redirect_callback_abuse[:5]
        self.investigation_bundle['top_attack_paths'] = self.attack_paths[:8]
        self.stats['investigation_bundle'] = self.investigation_bundle

    def _build_diff_report(self) -> None:
        super()._build_diff_report()
        if not self.baseline_json or not Path(self.baseline_json).exists():
            return
        try:
            baseline = json.loads(Path(self.baseline_json).read_text(encoding='utf-8', errors='ignore'))
        except Exception:
            return
        def keyset(items: List[Dict], fields: List[str]):
            return {tuple(str(x.get(f, '')) for f in fields) for x in items if isinstance(x, dict)}
        current_pp = keyset(self.prototype_pollution_hints, ['kind', 'function'])
        baseline_pp = keyset(baseline.get('prototype_pollution_hints', []), ['kind', 'function'])
        current_pm = keyset(self.postmessage_analysis, ['function', 'line'])
        baseline_pm = keyset(baseline.get('postmessage_analysis', []), ['function', 'line'])
        current_fs = keyset(self.file_media_surfaces, ['function', 'line'])
        baseline_fs = keyset(baseline.get('file_media_surfaces', []), ['function', 'line'])
        current_ap = keyset(self.attack_paths, ['path', 'entity'])
        baseline_ap = keyset(baseline.get('attack_paths', []), ['path', 'entity'])
        self.diff_report['new_prototype_pollution_hints'] = [{'kind': a, 'function': b} for a, b in sorted(current_pp - baseline_pp)[:20]]
        self.diff_report['new_postmessage_surfaces'] = [{'function': a, 'line': b} for a, b in sorted(current_pm - baseline_pm)[:20]]
        self.diff_report['new_file_media_surfaces'] = [{'function': a, 'line': b} for a, b in sorted(current_fs - baseline_fs)[:20]]
        self.diff_report['new_attack_paths'] = [{'path': a, 'entity': b} for a, b in sorted(current_ap - baseline_ap)[:20]]
        self.stats['diff_report'] = self.diff_report

    def _top_hotspots(self) -> List[str]:
        hotspots = super()._top_hotspots()
        for item in self.attack_paths[:3]:
            hotspots.insert(0, f"path {item['path']} {item['entity']} [{item['risk']}/{item['score']}]")
        for item in self.prototype_pollution_hints[:2]:
            hotspots.insert(0, f"prototype {item['kind']} {item['function'] or 'anonymous'} [{item['confidence']}/{item['score']}]")
        for item in self.postmessage_analysis[:2]:
            hotspots.insert(0, f"postMessage {item['function'] or 'listener'} [{item['confidence']}/{item['score']}]")
        deduped = []
        seen = set()
        for h in hotspots:
            if h not in seen:
                seen.add(h)
                deduped.append(h)
        return deduped[:20]

    def _print_results(self) -> None:
        super()._print_results()
        if self.prototype_pollution_hints:
            print(c(RED + BOLD, f"\n{'━' * 78}"))
            print(c(RED + BOLD, "  🧪 PROTOTYPE / UNSAFE MERGE"))
            print(c(RED + BOLD, f"{'━' * 78}"))
            for item in self.prototype_pollution_hints[:8]:
                print(f"  {c(RED, item['kind'])} L:{item['line']} {c(YELLOW, '[' + item['confidence'] + '/' + str(item['score']) + ']')}")
                print(f"      {c(DIM, 'signals: ' + ', '.join(item['signals'][:4]))}")
        if self.postmessage_analysis:
            print(c(YELLOW + BOLD, f"\n{'━' * 78}"))
            print(c(YELLOW + BOLD, "  📨 POSTMESSAGE DEEP ANALYSIS"))
            print(c(YELLOW + BOLD, f"{'━' * 78}"))
            for item in self.postmessage_analysis[:8]:
                print(f"  L:{item['line']} {c(YELLOW, '[' + item['confidence'] + '/' + str(item['score']) + ']')} sinks={','.join(item['sinks'][:3]) or '-'}")
                print(f"      {c(DIM, 'signals: ' + ', '.join(item['signals'][:4]))}")
        if self.file_media_surfaces:
            print(c(CYAN + BOLD, f"\n{'━' * 78}"))
            print(c(CYAN + BOLD, "  📎 FILE / MEDIA SURFACES"))
            print(c(CYAN + BOLD, f"{'━' * 78}"))
            for item in self.file_media_surfaces[:8]:
                print(f"  L:{item['line']} {c(YELLOW, '[' + item['confidence'] + '/' + str(item['score']) + ']')} fields={','.join(item['fields'][:3]) or '-'}")
                if item.get('accepts'):
                    print(f"      {c(DIM, 'accepts: ' + ', '.join(item['accepts'][:2]))}")
        if self.redirect_callback_abuse:
            print(c(MAGENTA + BOLD, f"\n{'━' * 78}"))
            print(c(MAGENTA + BOLD, "  ↩️ REDIRECT / CALLBACK ABUSE"))
            print(c(MAGENTA + BOLD, f"{'━' * 78}"))
            for item in self.redirect_callback_abuse[:8]:
                print(f"  {c(CYAN, item['endpoint'][:100])} {c(YELLOW, '[' + item['confidence'] + '/' + str(item['score']) + ']')}")
                if item.get('params'):
                    print(f"      {c(DIM, 'params: ' + ', '.join(item['params'][:4]))}")
        if self.attack_paths:
            print(c(MAGENTA + BOLD, f"\n{'━' * 78}"))
            print(c(MAGENTA + BOLD, "  🛣️ ATTACK PATHS"))
            print(c(MAGENTA + BOLD, f"{'━' * 78}"))
            for item in self.attack_paths[:10]:
                print(f"  {c(BOLD, item['path'])} -> {c(CYAN, item['entity'])} {c(YELLOW, '[' + item['risk'] + '/' + str(item['score']) + ']')}")
                print(f"      {c(DIM, 'bugs: ' + ', '.join(item['candidate_bugs'][:3]))}")

    def _build_report(self) -> Dict:
        report = super()._build_report()
        report['version'] = '4.7'
        report['prototype_pollution_hints'] = self.prototype_pollution_hints
        report['postmessage_analysis'] = self.postmessage_analysis
        report['file_media_surfaces'] = self.file_media_surfaces
        report['redirect_callback_abuse'] = self.redirect_callback_abuse
        report['attack_paths'] = self.attack_paths
        report['stats']['prototype_pollution_hints'] = self.prototype_pollution_hints
        report['stats']['postmessage_analysis'] = self.postmessage_analysis
        report['stats']['file_media_surfaces'] = self.file_media_surfaces
        report['stats']['redirect_callback_abuse'] = self.redirect_callback_abuse
        report['stats']['attack_paths'] = self.attack_paths
        return report

def main() -> None:
    parser = argparse.ArgumentParser(description="JS Bundle Analyzer v4.7 — Recon / Bug Bounty", formatter_class=argparse.RawDescriptionHelpFormatter, epilog="""
Ejemplos:
  python3 js_analyzer_v4_7.py bundle.js --scope example.com --app-only --json --profile generic
  python3 js_analyzer_v4_7.py chunk.js --json --no-color --max 10 --profile saas --baseline-json prev.json
    """)
    parser.add_argument("file", help="Archivo JS a analizar")
    parser.add_argument("--max", type=int, default=5, help="Max matches por patrón")
    parser.add_argument("--scope", type=str, default=None, help="Dominio en scope (ej: example.com)")
    parser.add_argument("--profile", type=str, default="generic", help="Perfil opcional de keywords: generic, cms, saas, ecommerce, german")
    parser.add_argument("--baseline-json", type=str, default=None, help="Reporte JSON previo para diff incremental")
    parser.add_argument("--app-only", action="store_true", help="Filtrar findings de vendor-high code")
    parser.add_argument("--json", action="store_true", help="Guardar reporte JSON")
    parser.add_argument("--no-color", action="store_true", help="Sin colores")
    args = parser.parse_args()
    global NO_COLOR
    NO_COLOR = args.no_color
    analyzer = JSAnalyzerV47(args.file, max_per=args.max, scope=args.scope, app_only=args.app_only, profile=args.profile, baseline_json=args.baseline_json)
    report = analyzer.run()
    if args.json:
        out = Path(args.file).with_name(Path(args.file).stem + "_analysis_v4_7.json")
        with out.open("w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        print(c(GREEN, f"[+] JSON: {out}"))


if __name__ == "__main__":
    main()
