#!/usr/bin/env python3
from __future__ import annotations

import re
import json
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import js_analyzer_v4_7 as base


class JSAnalyzerV48(base.JSAnalyzerV47):
    def __init__(self, filepath: str, max_per: int = 5, scope: Optional[str] = None, app_only: bool = False, profile: str = "generic", baseline_json: Optional[str] = None):
        super().__init__(filepath, max_per=max_per, scope=scope, app_only=app_only, profile=profile, baseline_json=baseline_json)
        self.read_surfaces: List[Dict] = []
        self.mutation_read_links: List[Dict] = []
        self.prioritized_targets: List[Dict] = []

    def _banner(self) -> None:
        size_kb = self.path.stat().st_size / 1024
        print(base.c(base.CYAN + base.BOLD, f"\n{'=' * 78}"))
        print(base.c(base.CYAN + base.BOLD, f"  JS Bundle Analyzer v4.8 — {self.path.name} ({size_kb:.1f} KB)"))
        if self.scope:
            print(base.c(base.CYAN + base.BOLD, f"  Scope: {self.scope}"))
        print(base.c(base.CYAN + base.BOLD, f"  Profile: {self.profile}"))
        if self.app_only:
            print(base.c(base.YELLOW + base.BOLD, "  Mode: APP-ONLY (vendor-high findings filtered)"))
        if self.baseline_json:
            print(base.c(base.CYAN + base.BOLD, f"  Baseline: {self.baseline_json}"))
        print(base.c(base.CYAN + base.BOLD, f"{'=' * 78}\n"))

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

    def _canonical_base(self, value: str) -> str:
        if not value:
            return ""
        v = value.strip().strip('`')
        v = re.sub(r'https?://[^/]+', '', v, flags=re.I)
        v = re.sub(r'\?.*$', '', v)
        v = re.sub(r'\$\{[^}]+\}', '{id}', v)
        v = re.sub(r'/\{[^/]+\}', '/{id}', v)
        v = re.sub(r'/(?:\d+|[0-9a-f]{8,}|[A-Za-z0-9_-]{12,})(?=$|/)', '/{id}', v, flags=re.I)
        v = re.sub(r'//+', '/', v)
        return v.rstrip('/') or v

    def _entity_overlap(self, a: List[str], b: List[str]) -> List[str]:
        aset = {x.lower() for x in a if x}
        bset = {x.lower() for x in b if x}
        return sorted(aset & bset)

    def _detect_read_surfaces(self) -> None:
        surfaces: List[Dict] = []
        seen = set()
        read_terms = [
            'detail', 'details', 'view', 'preview', 'render', 'download', 'export', 'report', 'pdf', 'public', 'share', 'feed', 'list', 'search',
            'show', 'viewer', 'print', 'summary', 'status', 'history', 'result', 'results', 'dashboard', 'profile', 'document', 'comment'
        ] + self.profile_keywords

        endpoint_candidates = []
        for ep in self.endpoints:
            url = ep.get('url', '')
            ep_type = ep.get('type', '')
            method = 'GET' if ep_type in {'fetch_call', 'template_fetch', 'api_path', 'base_url'} or 'get' in ep_type.lower() else ''
            endpoint_candidates.append((url, method, ep_type))

        for route in self.routes:
            endpoint_candidates.append((route, 'GET', 'route'))

        for url, method, origin in endpoint_candidates:
            low = url.lower()
            if not url:
                continue
            if method != 'GET' and not re.search(r'\b(get|view|detail|preview|download|export|report|show|render|search|list)\b', origin + ' ' + low, re.I):
                continue
            entities = self._entity_candidates_from_text(url)
            terms = sorted({t for t in read_terms if t.lower() in low})[:12]
            score = 28
            if method == 'GET':
                score += 14
            if '{id}' in self._canonical_base(url) or re.search(r'/:[A-Za-z_]|/\$\{', url):
                score += 12
            score += min(18, len(terms) * 3)
            score += min(12, len(entities) * 2)
            if re.search(r'export|download|report|pdf|preview|render|public|share', low, re.I):
                score += 10
            if self.scope and self.scope.lower() in low:
                score += 4
            key = (self._canonical_base(url), method or 'READ')
            if key in seen:
                continue
            seen.add(key)
            surfaces.append({
                'endpoint': url,
                'method': method or 'READ',
                'origin': origin,
                'canonical_base': self._canonical_base(url),
                'terms': terms,
                'entities': entities[:10],
                'confidence': 'high' if score >= 70 else 'medium',
                'score': min(95, score),
                'hypotheses': ['read_surface'] + (['trusted_output_surface'] if any(t in terms for t in ['export', 'download', 'report', 'pdf', 'preview', 'render']) else []),
            })
        self.read_surfaces = sorted(surfaces, key=lambda x: (-x['score'], x['endpoint']))[:40]
        self.stats['read_surfaces'] = self.read_surfaces

    def _build_mutation_read_links(self) -> None:
        links: List[Dict] = []
        seen = set()
        for mut in self.critical_mutations:
            mut_base = self._canonical_base(mut.get('endpoint', ''))
            mut_entities = self._entity_candidates_from_text(' '.join([
                mut.get('endpoint', ''),
                mut.get('function', ''),
                ' '.join(mut.get('route_signals', [])),
                ' '.join(mut.get('sensitive_fields', [])),
            ]))
            for read in self.read_surfaces:
                read_base = read.get('canonical_base', '')
                overlap = self._entity_overlap(mut_entities, read.get('entities', []))
                same_base = bool(mut_base and read_base and (mut_base == read_base or mut_base.replace('/{id}', '') == read_base.replace('/{id}', '') or read_base.replace('/{id}', '') in mut_base.replace('/{id}', '') or mut_base.replace('/{id}', '') in read_base.replace('/{id}', '')))
                effect_overlap = []
                for t in mut.get('route_signals', []):
                    if t.lower() in ' '.join(read.get('terms', [])).lower():
                        effect_overlap.append(t)
                if not same_base and not overlap and not effect_overlap:
                    continue
                score = 42
                if same_base:
                    score += 20
                score += min(16, len(overlap) * 5)
                score += min(10, len(effect_overlap) * 4)
                if mut.get('method') in {'PUT', 'PATCH', 'DELETE'}:
                    score += 8
                if any(x in read.get('terms', []) for x in ['export', 'download', 'report', 'pdf', 'preview', 'render']):
                    score += 10
                if any(x in mut.get('hypotheses', []) for x in ['mass_assignment_possible', 'idor_possible']):
                    score += 8
                if any(x in read.get('hypotheses', []) for x in ['trusted_output_surface']):
                    score += 6
                key = (mut.get('method'), mut.get('endpoint'), read.get('endpoint'))
                if key in seen:
                    continue
                seen.add(key)
                candidate_bugs = []
                if 'mass_assignment_possible' in mut.get('hypotheses', []):
                    candidate_bugs.append('mass_assignment')
                if 'idor_possible' in mut.get('hypotheses', []):
                    candidate_bugs.append('idor_bola')
                if any(x in read.get('terms', []) for x in ['export', 'download', 'report', 'pdf']):
                    candidate_bugs.append('write_then_export')
                if any(x in read.get('terms', []) for x in ['preview', 'render', 'public', 'share']):
                    candidate_bugs.append('write_then_render')
                links.append({
                    'write_endpoint': mut.get('endpoint', ''),
                    'write_method': mut.get('method', ''),
                    'read_endpoint': read.get('endpoint', ''),
                    'read_method': read.get('method', ''),
                    'shared_entities': overlap,
                    'same_base': same_base,
                    'effect_overlap': sorted(set(effect_overlap)),
                    'candidate_bugs': sorted(set(candidate_bugs)) or ['business_logic_chain'],
                    'confidence': 'high' if score >= 76 else 'medium',
                    'score': min(98, score),
                })

        for sx in self.stored_xss_hints:
            sx_entities = self._entity_candidates_from_text(sx.get('endpoint', '') + ' ' + ' '.join(sx.get('html_like_fields', [])))
            for read in self.read_surfaces:
                overlap = self._entity_overlap(sx_entities, read.get('entities', []))
                same_base = self._canonical_base(sx.get('endpoint', '')).replace('/{id}', '') == read.get('canonical_base', '').replace('/{id}', '')
                if not same_base and not overlap:
                    continue
                if not any(x in read.get('terms', []) for x in ['detail', 'view', 'preview', 'render', 'public', 'share', 'document', 'comment', 'profile']):
                    continue
                score = 58 + (12 if same_base else 0) + min(12, len(overlap) * 4)
                links.append({
                    'write_endpoint': sx.get('endpoint', ''),
                    'write_method': sx.get('method', ''),
                    'read_endpoint': read.get('endpoint', ''),
                    'read_method': read.get('method', ''),
                    'shared_entities': overlap,
                    'same_base': same_base,
                    'effect_overlap': sx.get('html_like_fields', [])[:6],
                    'candidate_bugs': ['stored_xss_chain'],
                    'confidence': 'high' if score >= 76 else 'medium',
                    'score': min(98, score),
                })

        dedup = {}
        for item in links:
            key = (item['write_endpoint'], item['read_endpoint'], tuple(item['candidate_bugs']))
            prev = dedup.get(key)
            if not prev or item['score'] > prev['score']:
                dedup[key] = item
        self.mutation_read_links = sorted(dedup.values(), key=lambda x: (-x['score'], x['write_endpoint'], x['read_endpoint']))[:40]
        self.stats['mutation_read_links'] = self.mutation_read_links

    def _build_prioritized_targets_v48(self) -> None:
        ranked: List[Dict] = []
        seen = set()

        for item in self.mutation_read_links[:20]:
            score = item.get('score', 0)
            why = []
            if item.get('same_base'):
                why.append('same resource family')
            if item.get('shared_entities'):
                why.append('shared entities: ' + ', '.join(item['shared_entities'][:4]))
            if item.get('candidate_bugs'):
                why.append('candidate bugs: ' + ', '.join(item['candidate_bugs'][:3]))
            target = f"{item.get('write_method')} {item.get('write_endpoint')} -> {item.get('read_method')} {item.get('read_endpoint')}"
            key = ('chain', target)
            if key in seen:
                continue
            seen.add(key)
            ranked.append({
                'kind': 'write_read_chain',
                'target': target,
                'score': min(100, score + 6),
                'confidence': item.get('confidence', 'medium'),
                'why': why,
            })

        for item in getattr(self, 'final_risk_ranking', [])[:20]:
            endpoint = item.get('endpoint') or item.get('path') or item.get('target') or ''
            if not endpoint:
                continue
            target = f"{item.get('kind', 'surface')}: {endpoint}"
            key = ('risk', target)
            if key in seen:
                continue
            seen.add(key)
            ranked.append({
                'kind': item.get('kind', 'surface'),
                'target': target,
                'score': item.get('final_risk_score', item.get('score', 0)),
                'confidence': item.get('confidence', 'medium'),
                'why': item.get('why_ranked', [])[:4],
            })

        for item in self.read_surfaces[:15]:
            if item.get('score', 0) < 68:
                continue
            if not any(t in item.get('terms', []) for t in ['export', 'download', 'report', 'pdf', 'preview', 'render', 'public', 'share']):
                continue
            target = f"{item.get('method')} {item.get('endpoint')}"
            key = ('read', target)
            if key in seen:
                continue
            seen.add(key)
            ranked.append({
                'kind': 'trusted_output_surface',
                'target': target,
                'score': min(100, item.get('score', 0) + 4),
                'confidence': item.get('confidence', 'medium'),
                'why': ['read surface with trusted-output semantics'] + item.get('terms', [])[:3],
            })

        ranked.sort(key=lambda x: (-x['score'], x['target']))
        self.prioritized_targets = ranked[:25]
        self.stats['prioritized_targets'] = self.prioritized_targets

    def _top_hotspots(self) -> List[str]:
        hotspots = super()._top_hotspots()
        for item in self.prioritized_targets[:4]:
            hotspots.insert(0, f"target {item['kind']} [{item['confidence']}/{item['score']}] {item['target'][:90]}")
        deduped = []
        seen = set()
        for h in hotspots:
            if h not in seen:
                seen.add(h)
                deduped.append(h)
        return deduped[:20]

    def _print_results(self) -> None:
        super()._print_results()
        if self.read_surfaces:
            print(base.c(base.CYAN + base.BOLD, f"\n{'━' * 78}"))
            print(base.c(base.CYAN + base.BOLD, "  👁️ READ SURFACES"))
            print(base.c(base.CYAN + base.BOLD, f"{'━' * 78}"))
            for item in self.read_surfaces[:10]:
                print(f"  {base.c(base.CYAN, item['endpoint'][:100])} {base.c(base.YELLOW, '[' + item['confidence'] + '/' + str(item['score']) + ']')}")
                if item.get('terms'):
                    print(f"      {base.c(base.DIM, 'terms: ' + ', '.join(item['terms'][:5]))}")
        if self.mutation_read_links:
            print(base.c(base.MAGENTA + base.BOLD, f"\n{'━' * 78}"))
            print(base.c(base.MAGENTA + base.BOLD, "  🔗 WRITE → READ CHAINS"))
            print(base.c(base.MAGENTA + base.BOLD, f"{'━' * 78}"))
            for item in self.mutation_read_links[:10]:
                print(f"  {base.c(base.BOLD, item['write_method'] + ' ' + item['write_endpoint'][:70])}")
                print(f"      -> {base.c(base.CYAN, item['read_method'] + ' ' + item['read_endpoint'][:70])} {base.c(base.YELLOW, '[' + item['confidence'] + '/' + str(item['score']) + ']')}")
                print(f"      {base.c(base.DIM, 'bugs: ' + ', '.join(item['candidate_bugs'][:4]))}")
        if self.prioritized_targets:
            print(base.c(base.RED + base.BOLD, f"\n{'━' * 78}"))
            print(base.c(base.RED + base.BOLD, "  🎯 PRIORITIZED TARGETS V4.8"))
            print(base.c(base.RED + base.BOLD, f"{'━' * 78}"))
            for item in self.prioritized_targets[:12]:
                print(f"  {base.c(base.RED, item['kind'])} {base.c(base.YELLOW, '[' + item['confidence'] + '/' + str(item['score']) + ']')}")
                print(f"      {base.c(base.CYAN, item['target'][:120])}")
                if item.get('why'):
                    print(f"      {base.c(base.DIM, 'why: ' + ' | '.join(item['why'][:3]))}")

    def _build_report(self) -> Dict:
        report = super()._build_report()
        report['version'] = '4.8'
        report['read_surfaces'] = self.read_surfaces
        report['mutation_read_links'] = self.mutation_read_links
        report['prioritized_targets'] = self.prioritized_targets
        report['stats']['read_surfaces'] = self.read_surfaces
        report['stats']['mutation_read_links'] = self.mutation_read_links
        report['stats']['prioritized_targets'] = self.prioritized_targets
        return report


def main() -> None:
    parser = argparse.ArgumentParser(description="JS Bundle Analyzer v4.8 — Recon / Bug Bounty", formatter_class=argparse.RawDescriptionHelpFormatter, epilog="""
Ejemplos:
  python3 js_analyzer_v4_8.py bundle.js --scope example.com --app-only --json --profile generic
  python3 js_analyzer_v4_8.py chunk.js --json --no-color --max 10 --profile saas --baseline-json prev.json
    """)
    parser.add_argument("file", help="Archivo JS a analizar")
    parser.add_argument("--max", type=int, default=5, help="Max matches por patrón")
    parser.add_argument("--scope", type=str, default=None, help="Dominio en scope (ej: example.com)")
    parser.add_argument("--profile", type=str, default="generic", help="Perfil opcional de keywords: generic, cms, saas, ecommerce")
    parser.add_argument("--baseline-json", type=str, default=None, help="Reporte JSON previo para diff incremental")
    parser.add_argument("--app-only", action="store_true", help="Filtrar findings de vendor-high code")
    parser.add_argument("--json", action="store_true", help="Guardar reporte JSON")
    parser.add_argument("--no-color", action="store_true", help="Sin colores")
    args = parser.parse_args()

    base.NO_COLOR = args.no_color
    analyzer = JSAnalyzerV48(args.file, max_per=args.max, scope=args.scope, app_only=args.app_only, profile=args.profile, baseline_json=args.baseline_json)
    report = analyzer.run()
    if args.json:
        out = Path(args.file).with_name(Path(args.file).stem + "_analysis_v4_8.json")
        with out.open("w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        print(base.c(base.GREEN, f"[+] JSON: {out}"))


if __name__ == "__main__":
    main()
