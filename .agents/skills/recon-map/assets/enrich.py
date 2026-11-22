#!/usr/bin/env python3
"""enrich.py — convierte el PSV de fingerprint.sh en el hosts.json del explorer.
Agrega: resolución CNAME/A/IP (DoH), ASN + org (Team Cymru vía DoH), infra real,
versiones (de headers), tags de tecnología, bucket de estado, y (opcional) área.

Uso:
  python3 enrich.py <fp.psv> <hosts.json> [area_rules.tsv] [leads.tsv] [map_metadata.json]

Campos por host: host, area, code, server, edge, framework, infra, cname,
  ip, asn, asn_org, version (lista), status, loc, lead, tags.

Notas de calibración (bugs reales ya corregidos, no re-introducir):
  - Strip \\r de cada campo (Windows-python mete \\r\\n → clasificación rota).
  - json.dump en una sola línea (sin newlines) → no rompe el <script> del embed.
  - print()/stderr solo ASCII (consola cp1252 de Windows crashea con → · ).
"""
import sys, json, re, os, urllib.request, concurrent.futures

# ---------- reglas opcionales ----------
def load_rules(path):
    rules = []
    try:
        for ln in open(path, encoding='utf-8'):
            ln = ln.rstrip('\n').replace('\r', '')
            if not ln or ln.startswith('#') or '\t' not in ln: continue
            pat, lbl = ln.split('\t', 1)
            rules.append((re.compile(pat, re.I), lbl))
    except FileNotFoundError:
        pass
    return rules

def apex(h):
    p = h.split('.')
    return '.'.join(p[-2:]) if len(p) >= 2 else h

# ---------- DoH ----------
def doh(name, typ):
    try:
        return json.load(urllib.request.urlopen(
            f"https://dns.google/resolve?name={name}&type={typ}", timeout=6))
    except Exception:
        return {}

def resolve(h):
    c = doh(h, "CNAME"); a = doh(h, "A")
    cn = [x["data"].rstrip('.') for x in c.get("Answer", []) if x.get("type") == 5]
    ips = [x["data"] for x in a.get("Answer", []) if x.get("type") == 1]
    return h, (cn[0] if cn else ""), (ips[0] if ips else ""), a.get("Status")

# ---------- ASN vía Team Cymru (DoH TXT, sin token) ----------
_asn_org_cache = {}
def cymru_asn(ip):
    """ip -> (asn, org). Usa <rev>.origin.asn.cymru.com y ASxxx.asn.cymru.com."""
    try:
        rev = '.'.join(reversed(ip.split('.')))
        d = doh(f"{rev}.origin.asn.cymru.com", "TXT")
        txt = [x["data"].strip('"') for x in d.get("Answer", []) if x.get("type") == 16]
        if not txt: return ("", "")
        asn = txt[0].split('|')[0].strip().split()[0]
        if not asn.isdigit(): return ("", "")
        if asn in _asn_org_cache:
            return (f"AS{asn}", _asn_org_cache[asn])
        d2 = doh(f"AS{asn}.asn.cymru.com", "TXT")
        t2 = [x["data"].strip('"') for x in d2.get("Answer", []) if x.get("type") == 16]
        org = t2[0].split('|')[-1].strip() if t2 else ""
        org = re.sub(r',?\s*[A-Z]{2}$', '', org).strip()  # quitar ", US" final
        _asn_org_cache[asn] = org
        return (f"AS{asn}", org)
    except Exception:
        return ("", "")

# ---------- fingerprint mapping ----------
INFRA = [("fastly","Fastly"),("cloudfront","AWS CloudFront"),("elb.amazonaws","AWS ELB"),
    ("amazonaws","AWS"),("googlehosted","Google Sites"),("webflow","Webflow"),("netlify","Netlify"),
    ("vercel","Vercel"),("hubspot","HubSpot"),("bnc.lt","Branch.io"),("q4web","Q4"),
    ("atlassian","Atlassian"),("azure","Azure"),("jamf","Jamf"),("zendesk","Zendesk"),
    ("herokudns","Heroku"),("herokuapp","Heroku"),("myshopify","Shopify"),("readme.io","ReadMe")]
def infra_of(cn):
    cn = cn.lower()
    for k, v in INFRA:
        if k in cn: return v
    return ""

EDGE_MAP = {'akamaighost':'Akamai','amazons3':'AWS S3','uploadserver':'Google GCS',
    'google frontend':'Google GFE','awselb':'AWS ELB','openresty':'OpenResty','vercel':'Vercel','netlify':'Netlify'}
def edge_of(edge_raw, inf):
    e = (edge_raw or '').lower()
    for k, v in EDGE_MAP.items():
        if k in e: return v
    for k in ['fastly','varnish','cloudflare','akamai']:
        if k in e: return k.title()
    return inf

def framework_of(powered, server):
    p = (powered + ' ' + server).lower()
    if 'next' in p: return 'Next.js'
    if 'express' in p: return 'Express'
    if 'php' in p: return 'PHP'
    if 'aspnet' in p or 'asp.net' in p: return 'ASP.NET'
    if 'django' in p: return 'Django'
    if 'rails' in p or 'phusion' in p: return 'Rails'
    return ''

def versions_of(*strs):
    """Extrae 'producto/version' de headers (nginx/1.24.0, Apache/2.4.52, ...)."""
    out = []
    for s in strs:
        for m in re.finditer(r'([A-Za-z][A-Za-z0-9_+.-]*)/(\d+(?:\.\d+)+)', s or ''):
            v = f"{m.group(1)}/{m.group(2)}"
            if v not in out: out.append(v)
    return out

def status_bucket(code, cn, ip, ast):
    if code == '000' or (not ip and ast == 3):
        return 'dangling' if cn else 'dead/internal'
    if code.startswith('3'): return 'redirect'
    if code in ('401','403'): return 'gated'
    if code == '404': return 'live·404'
    if code.startswith('4'): return 'gated'
    if code.startswith('2'): return 'live'
    if code.startswith('5'): return 'error'
    return 'dead/internal'

def read_psv(fp):
    rows = []
    for line in open(fp, encoding='utf-8', errors='replace'):
        p = [x.strip() for x in line.rstrip('\n').replace('\r', '').split('|')]
        if len(p) < 6 or not p[0]: continue
        rows.append(dict(host=p[0], code=p[1], server=p[2], edge=p[3].lower(),
                         powered=p[4], loc=p[5], tech_ext=[], ip_ext=''))
    return rows

def read_httpx_jsonl(fp):
    """Consume el _alive.jsonl de httpx (reconv2.5.sh). Mucho más rico que el PSV:
    trae tech-detect (Wappalyzer), IP resuelta, webserver, status — sin re-probar."""
    rows = []
    for line in open(fp, encoding='utf-8', errors='replace'):
        line = line.strip()
        if not line or line[0] != '{': continue
        try: j = json.loads(line)
        except Exception: continue
        host = (j.get('input') or j.get('host') or '').strip()
        if not host: continue
        tech = j.get('tech') or []
        ip = j.get('host_ip') or (j.get('a') or [''])[0]
        # edge desde tech-detect (Wappalyzer nombra los CDN/WAF)
        edge_raw = ''
        for t in tech:
            tl = t.lower()
            for k in ['cloudflare','fastly','akamai','varnish','amazon s3','google frontend']:
                if k in tl: edge_raw = k
        rows.append(dict(host=host, code=str(j.get('status_code', '')),
                         server=j.get('webserver', ''), edge=edge_raw,
                         powered='', loc=(j.get('location') or ''),
                         tech_ext=tech, ip_ext=ip or ''))
    return rows

def read_host_metadata(path):
    """Load evidence-backed per-host labels omitted by a shallow fingerprint."""
    if not path:
        return {}
    with open(path, encoding='utf-8') as f:
        raw = json.load(f)
    if not isinstance(raw, dict):
        raise ValueError("map_metadata.json must be an object keyed by exact host")
    allowed = {'libraries', 'observations', 'observations_source'}
    result = {}
    for host, fields in raw.items():
        if not isinstance(host, str) or not isinstance(fields, dict):
            raise ValueError("each metadata entry must map a host string to an object")
        clean = {}
        for key in ('libraries', 'observations'):
            value = fields.get(key, [])
            if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
                raise ValueError(f"{host}.{key} must be an array of strings")
            clean[key] = list(dict.fromkeys(x.strip() for x in value if x.strip()))
        source = fields.get('observations_source', '')
        if not isinstance(source, str):
            raise ValueError(f"{host}.observations_source must be a string")
        clean['observations_source'] = source.strip()
        unknown = set(fields) - allowed
        if unknown:
            raise ValueError(f"unsupported metadata fields for {host}: {', '.join(sorted(unknown))}")
        result[host] = clean
    return result

def main():
    fp, out = sys.argv[1], sys.argv[2]
    area_rules = load_rules(sys.argv[3]) if len(sys.argv) > 3 else []
    lead_rules = []
    if len(sys.argv) > 4:
        try:
            for ln in open(sys.argv[4], encoding='utf-8', errors='replace'):
                ln = ln.rstrip('\n').replace('\r', '')
                if '\t' in ln: k, v = ln.split('\t', 1); lead_rules.append((k, v))
        except FileNotFoundError:
            pass
    metadata_path = sys.argv[5] if len(sys.argv) > 5 else os.path.join(os.path.dirname(out), 'map_metadata.json')
    if len(sys.argv) <= 5 and not os.path.isfile(metadata_path):
        metadata_path = None
    host_metadata = read_host_metadata(metadata_path)

    # detección de formato: .jsonl (httpx) o .psv (fingerprint.sh)
    head = open(fp, encoding='utf-8', errors='replace').read(1)
    rows = read_httpx_jsonl(fp) if (fp.endswith('.jsonl') or head == '{') else read_psv(fp)

    # DNS: CNAME + IP
    res = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=24) as ex:
        for h, cn, ip, ast in ex.map(resolve, [r['host'] for r in rows]):
            res[h] = (cn, ip, ast)
    # ASN: solo IPs únicas
    uips = sorted(set(v[1] for v in res.values() if v[1]))
    asnmap = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
        for ip, val in zip(uips, ex.map(cymru_asn, uips)):
            asnmap[ip] = val

    def area_of(h):
        for rx, lbl in area_rules:
            if rx.search(h): return lbl
        return apex(h)

    out_rows = []
    for r in rows:
        h = r['host']; cn, ip, ast = res.get(h, ("", "", None))
        if r.get('ip_ext'): ip = r['ip_ext']          # IP de httpx si vino del jsonl
        asn, org = asnmap.get(ip, ("", ""))
        inf = infra_of(cn); edge = edge_of(r['edge'], inf); fw = framework_of(r['powered'], r['server'])
        ver = versions_of(r['server'], r['powered'])
        # tech-detect de httpx (Wappalyzer) — si vino, es la mejor fuente
        tech_ext = r.get('tech_ext') or []
        if not fw:
            for t in tech_ext:
                if 'next.js' in t.lower(): fw = 'Next.js'; break
                if t.lower() in ('react',): fw = 'React'
                if 'express' in t.lower(): fw = 'Express'
        tags = []
        for t in [edge, (r['server'].split('/')[0] if r['server'] and r['server'].split('/')[0].lower() != edge.lower() else ''),
                  fw, (inf if inf and inf != edge else '')] + ver + tech_ext:
            if t and t not in tags: tags.append(t)
        metadata = host_metadata.get(h, {})
        libraries = metadata.get('libraries', [])
        for library in libraries:
            if library not in tags: tags.append(library)
        lead = next((v for k, v in lead_rules if k in h), '')
        out_rows.append(dict(host=h, area=area_of(h), code=r['code'], server=r['server'],
            edge=edge, framework=fw, infra=inf, cname=cn, ip=ip, asn=asn, asn_org=org,
            version=ver, status=status_bucket(r['code'], cn, ip, ast), loc=r['loc'],
            lead=lead, tags=tags, libraries=libraries,
            observations=metadata.get('observations', []),
            observations_source=metadata.get('observations_source', '')))

    out_rows.sort(key=lambda x: (x['area'], x['host']))
    with open(out, 'w', newline='', encoding='utf-8') as f:
        f.write(json.dumps(out_rows, ensure_ascii=False))

    from collections import Counter
    sys.stderr.write("hosts: %d\n" % len(out_rows))
    sys.stderr.write("with-ip: %d  with-asn: %d  with-version: %d\n" % (
        sum(1 for d in out_rows if d['ip']), sum(1 for d in out_rows if d['asn']),
        sum(1 for d in out_rows if d['version'])))
    sys.stderr.write("top ASN orgs: %s\n" % json.dumps(
        dict(Counter(d['asn_org'] for d in out_rows if d['asn_org']).most_common(8)), ensure_ascii=False))

if __name__ == '__main__':
    main()
