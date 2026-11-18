#!/usr/bin/env bash
# fingerprint.sh — probing HTTP dirigido (NO scanner) sobre una lista de hosts.
# Uso: bash fingerprint.sh <hosts.txt> <salida.psv>
# Salida PSV: host|code|server|edge|powered|location   (una línea por host)
#
# Reglas del repo: esto NO es un scanner ruidoso — es 1 GET por host con timeout
# corto. Respeta la prohibición de scans automáticos. Si un target prohíbe
# incluso esto (ej. assets.spotify.com), sacar ese host de la lista antes.
set -u
HOSTS="${1:?falta hosts.txt}"; OUT="${2:?falta salida.psv}"
UA="Mozilla/5.0 (Windows NT 10.0; Win64) Chrome/151"
# CRÍTICO: limpiar \r (Windows-python suele meter \r\n en la lista de hosts;
# un host con \r hace que curl resuelva "host\r" y lo marque muerto en falso).
tr -d '\r' < "$HOSTS" | sed '/^$/d' | sort -u > "$OUT.hosts.tmp"
: > "$OUT"

fp_one(){
  local h="$1" out code srv via powered loc
  out=$(curl -s -m 7 --compressed -A "$UA" -D - -o /dev/null "https://$h/" 2>/dev/null)
  if [ -z "$out" ]; then printf '%s|000|||||\n' "$h" >> "$OUT"; return; fi
  code=$(printf '%s' "$out"    | head -1 | grep -oE '[0-9]{3}' | head -1)
  srv=$(printf '%s' "$out"     | grep -iE '^server:' | head -1 | sed 's/[^:]*: //I' | tr -d '\r' | cut -c1-40)
  via=$(printf '%s' "$out"     | grep -iE '^(via|x-served-by):' | head -1 | grep -ioE 'varnish|fastly|cloudflare|akamai' | head -1)
  [ -z "$via" ] && via=$(printf '%s' "$out" | grep -iEo 'cloudflare|akamaighost|amazons3|uploadserver|google frontend|awselb|openresty|vercel|netlify' | head -1)
  powered=$(printf '%s' "$out" | grep -iE '^x-powered-by:' | head -1 | sed 's/[^:]*: //I' | tr -d '\r' | cut -c1-30)
  loc=$(printf '%s' "$out"     | grep -iE '^location:' | head -1 | sed 's/[^:]*: //I' | tr -d '\r' | cut -c1-46)
  printf '%s|%s|%s|%s|%s|%s\n' "$h" "$code" "$srv" "$via" "$powered" "$loc" >> "$OUT"
}
export -f fp_one; export OUT UA

# paralelo (30 workers). Bajar si el target es sensible al volumen.
cat "$OUT.hosts.tmp" | xargs -P 30 -I{} bash -c 'fp_one "$@"' _ {}
rm -f "$OUT.hosts.tmp"
echo "fingerprint → $OUT  ($(wc -l < "$OUT") hosts)"
awk -F'|' '{print $2}' "$OUT" | sort | uniq -c | sort -rn | sed 's/^/  /'
