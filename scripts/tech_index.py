#!/usr/bin/env python3
"""tech_index.py — índice invertido tecnología → hosts, cruzando TODOS los targets.

Lee cada targets/<t>/hosts.json (generado por el skill recon-map) y produce un
índice para responder al instante: "salió un CVE de <tecnología> — ¿en qué
hosts (y de qué target) la tengo?".

Uso:
  python3 scripts/tech_index.py                 # regenera targets/_fleet/tech_index.md
  python3 scripts/tech_index.py <query>         # busca una tech puntual (ej: "Next.js", "Fastly")

Salidas:
  targets/_fleet/tech_index.md   — tabla tech → count → hosts (por target)
  targets/_fleet/fleet.json      — dataset combinado (todos los hosts + campo target)
"""
import sys, json, os, glob
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGETS = os.path.join(ROOT, 'targets')
FLEET = os.path.join(TARGETS, '_fleet')

def load_all():
    combined = []
    for path in sorted(glob.glob(os.path.join(TARGETS, '*', 'hosts.json'))):
        target = os.path.basename(os.path.dirname(path))
        try:
            for d in json.load(open(path, encoding='utf-8')):
                d['target'] = target
                combined.append(d)
        except Exception as e:
            sys.stderr.write(f"skip {path}: {e}\n")
    return combined

def tech_set(d):
    """Todas las tecnologías detectables de un host (para el índice invertido).
    Incluye versiones (producto/x.y) para poder matchear un CVE por versión."""
    t = set(x for x in d.get('tags', []) if x)
    if d.get('framework'): t.add(d['framework'])
    if d.get('edge'): t.add(d['edge'])
    if d.get('infra'): t.add(d['infra'])
    if (d.get('server') or '').lower() == 'envoy': t.add('Envoy')
    for v in d.get('version', []): t.add(v)          # producto/version exacta
    if d.get('asn_org'): t.add('@'+d['asn_org'])      # hosting como dimensión (@ = infra)
    return t

def build_index(rows):
    idx = defaultdict(list)  # tech -> [(target, host, status)]
    for d in rows:
        for t in tech_set(d):
            idx[t].append((d['target'], d['host'], d['status']))
    return idx

def query(rows, q):
    idx = build_index(rows)
    ql = q.lower()
    hits = {t: v for t, v in idx.items() if ql in t.lower()}
    if not hits:
        print(f"sin hosts con tecnología ~ '{q}'"); return
    for t in sorted(hits, key=lambda x: -len(hits[x])):
        print(f"\n### {t}  ({len(hits[t])} hosts)")
        for tg, h, st in sorted(hits[t]):
            print(f"  [{tg}] {h}  ({st})")

def write_md(rows):
    os.makedirs(FLEET, exist_ok=True)
    idx = build_index(rows)
    ntargets = len(set(d['target'] for d in rows))
    lines = ["# Fleet — índice tecnología → hosts", "",
             f"Generado por `scripts/tech_index.py`. **{len(rows)} hosts** en **{ntargets} targets**.",
             "Cuando salga un CVE de una tecnología, buscarla acá para saber dónde aplicarlo.",
             "Regenerar tras cada `recon-map` de un target nuevo.", "",
             "| Tecnología | Hosts | Targets |", "|---|---:|---|"]
    for t in sorted(idx, key=lambda x: (-len(idx[x]), x.lower())):
        entries = idx[t]
        tgs = sorted(set(e[0] for e in entries))
        lines.append(f"| `{t}` | {len(entries)} | {', '.join(tgs)} |")
    lines += ["", "## Detalle por tecnología", ""]
    for t in sorted(idx, key=lambda x: (-len(idx[x]), x.lower())):
        lines.append(f"### {t}")
        for tg, h, st in sorted(idx[t]):
            lines.append(f"- `{h}` — {tg} ({st})")
        lines.append("")
    open(os.path.join(FLEET, 'tech_index.md'), 'w', encoding='utf-8').write('\n'.join(lines))
    with open(os.path.join(FLEET, 'fleet.json'), 'w', newline='', encoding='utf-8') as f:
        f.write(json.dumps(rows, ensure_ascii=False))
    print(f"tech_index.md + fleet.json -> {FLEET}  ({len(rows)} hosts, {len(idx)} techs, {ntargets} targets)")

if __name__ == '__main__':
    rows = load_all()
    if not rows:
        sys.stderr.write("no hay targets/*/hosts.json todavía — corré el skill recon-map primero.\n"); sys.exit(1)
    if len(sys.argv) > 1:
        query(rows, ' '.join(sys.argv[1:]))
    else:
        write_md(rows)
