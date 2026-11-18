#!/bin/bash
# ============================================================
# reconv2.5.sh — Daily subdomain discovery + DNS/HTTP enrichment + takeover checks + Telegram alerts
# Usage: ./reconv2.5.sh example.com [--yes] [-v]
# Cron:  0 8 * * * /path/to/reconv2.5.sh example.com --yes
# ============================================================

set -euo pipefail

# --- CONFIG via env vars (export or use .env) ---
# TELEGRAM_BOT_TOKEN=
# TELEGRAM_CHAT_ID=
# GITHUB_TOKEN=
# CHAOS_KEY=                      # optional, used by chaos client if configured
WORK_DIR="${SUBDOMAIN_MONITOR_DIR:-$HOME/.subdomain_monitor}"
CRTSH_TIMEOUT="${CRTSH_TIMEOUT:-45}"
DNS_THREADS="${DNS_THREADS:-20}"
HTTP_THREADS="${HTTP_THREADS:-25}"
TAKEOVER_ENABLED="${TAKEOVER_ENABLED:-true}"
VERBOSE=false
AUTHORIZED=false
DOMAIN=""
for arg in "$@"; do
    case "$arg" in
        -v|--verbose) VERBOSE=true ;;
        -y|--yes) AUTHORIZED=true ;;
        -h|--help)
            echo "Usage: $0 <domain> [--yes] [-v]" >&2
            exit 0
            ;;
        --*) echo "Error: Unknown option: $arg" >&2; exit 2 ;;
        *)
            if [[ -n "$DOMAIN" ]]; then
                echo "Error: Only one domain may be supplied." >&2
                exit 2
            fi
            DOMAIN="$arg"
            ;;
    esac
done
# -------------------------------------------------

# =====================
# INPUT VALIDATION
# =====================
if [[ -z "$DOMAIN" ]]; then
    echo "Usage: $0 <domain> [--yes] [-v]" >&2
    exit 1
fi

if ! [[ "$DOMAIN" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]; then
    echo "Error: Invalid domain format: $DOMAIN" >&2
    exit 1
fi

if [[ "$AUTHORIZED" != true ]]; then
    if [[ ! -t 0 ]]; then
        echo "Error: Active recon needs an interactive authorization confirmation or --yes." >&2
        exit 2
    fi
    read -r -p "¿Tienes autorización explícita para reconocimiento activo sobre $DOMAIN? (s/n): " answer
    if [[ "$answer" != "s" && "$answer" != "S" ]]; then
        echo "Recon cancelado por el operador." >&2
        exit 0
    fi
fi

# =====================
# SECRETS VALIDATION
# =====================
# Telegram es opcional: notifica si está configurado, pero el discovery
# (el trabajo real del script) no debe depender de esto. Antes esto era
# un exit 1 duro que impedía correr el script entero por falta de una
# feature de notificación — separado a propósito.
TELEGRAM_ENABLED=true
if [[ -z "${TELEGRAM_BOT_TOKEN:-}" || -z "${TELEGRAM_CHAT_ID:-}" ]]; then
    echo "Warning: TELEGRAM_BOT_TOKEN and/or TELEGRAM_CHAT_ID not set — Telegram notifications disabled, discovery runs normally." >&2
    TELEGRAM_ENABLED=false
fi

if [[ -z "${GITHUB_TOKEN:-}" ]]; then
    echo "Warning: GITHUB_TOKEN not set, github-subdomains will be skipped." >&2
fi

if [[ -z "${CHAOS_KEY:-}" ]]; then
    echo "Warning: CHAOS_KEY not set. chaos will still run if the local client has auth configured, otherwise it may fail." >&2
fi

# =====================
# TOOL AVAILABILITY CHECK
# =====================
AVAILABLE_TOOLS=()
MISSING_TOOLS=()

for tool in subfinder assetfinder findomain github-subdomains chaos curl; do
    if command -v "$tool" &>/dev/null; then
        AVAILABLE_TOOLS+=("$tool")
    else
        MISSING_TOOLS+=("$tool")
    fi
done

HAVE_DNSX=false
HAVE_HTTPX=false
HAVE_SUBZY=false
HAVE_JQ=false
command -v dnsx &>/dev/null && HAVE_DNSX=true
command -v httpx &>/dev/null && HAVE_HTTPX=true
command -v subzy &>/dev/null && HAVE_SUBZY=true
command -v jq &>/dev/null && HAVE_JQ=true

if [[ ${#AVAILABLE_TOOLS[@]} -lt 1 ]]; then
    echo "Error: Need at least 1 discovery tool. Found: ${AVAILABLE_TOOLS[*]:-none}" >&2
    echo "Missing: ${MISSING_TOOLS[*]}" >&2
    exit 1
fi
if [[ ${#AVAILABLE_TOOLS[@]} -lt 2 ]]; then
    echo "Warning: only 1 discovery tool available (${AVAILABLE_TOOLS[*]}) — coverage will be reduced (passive-only if that tool is curl/crt.sh)." >&2
fi

if [[ ${#MISSING_TOOLS[@]} -gt 0 ]]; then
    echo "Warning: Missing tools (will skip): ${MISSING_TOOLS[*]}" >&2
fi

# =====================
# DIRECTORY SETUP + LOCK
# =====================
DOMAIN_DIR="$WORK_DIR/$DOMAIN"
TODAY=$(date +%Y-%m-%d_%H%M)
RESULTS_DIR="$DOMAIN_DIR/scans"
MERGED="$RESULTS_DIR/${TODAY}_raw.txt"
RESOLVED="$RESULTS_DIR/${TODAY}_resolved.txt"
DNS_RECORDS="$RESULTS_DIR/${TODAY}_dns_records.txt"
CNAMES="$RESULTS_DIR/${TODAY}_cnames.txt"
ALIVE="$RESULTS_DIR/${TODAY}_alive.txt"
ALIVE_JSON="$RESULTS_DIR/${TODAY}_alive.jsonl"
TAKEOVER_SUBZY="$RESULTS_DIR/${TODAY}_takeover_subzy.txt"
TAKEOVER_FINDINGS="$RESULTS_DIR/${TODAY}_takeover_findings.txt"
SUMMARY_JSON="$RESULTS_DIR/${TODAY}_scan_summary.json"
KNOWN="$DOMAIN_DIR/known_subdomains.txt"
NEW_FILE="$DOMAIN_DIR/new_$TODAY.txt"
LOCK_FILE="$DOMAIN_DIR/.scan.lock"
LOG_FILE="$RESULTS_DIR/${TODAY}_scan.log"
SOURCE_DIR="$RESULTS_DIR/${TODAY}_sources"

mkdir -p "$RESULTS_DIR" "$SOURCE_DIR"
touch "$KNOWN"

if command -v flock &>/dev/null; then
    exec 9>"$LOCK_FILE"
    if ! flock -n 9; then
        echo "Another scan for $DOMAIN is already running. Lock: $LOCK_FILE" >&2
        exit 1
    fi
else
    # flock no disponible (ej. Git Bash/MSYS en Windows) — degradar a un
    # lock best-effort basado en mtime del archivo en vez de bloquear
    # todo el script. No perfecto ante carreras reales, pero evita el
    # falso positivo de "ya hay un scan corriendo" en cada invocación.
    if [[ -f "$LOCK_FILE" ]]; then
        LOCK_AGE=$(( $(date +%s) - $(date -r "$LOCK_FILE" +%s 2>/dev/null || echo 0) ))
        if [[ $LOCK_AGE -lt 1800 ]]; then
            echo "Another scan for $DOMAIN may be running (lock younger than 30min, no flock available to verify). Lock: $LOCK_FILE" >&2
            exit 1
        fi
        echo "Warning: stale lock (${LOCK_AGE}s old, no flock available) — ignoring and proceeding." >&2
    fi
    touch "$LOCK_FILE"
fi

TMP_DIR=$(mktemp -d)
cleanup() {
    rm -rf "$TMP_DIR"
    rm -f "$LOCK_FILE"
}
trap cleanup EXIT

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG_FILE"; }
vlog() { $VERBOSE && echo "[VERBOSE $(date +%H:%M:%S)] $*" | tee -a "$LOG_FILE" || true; }
count_lines() { [[ -s "$1" ]] && wc -l < "$1" || echo 0; }
json_escape() {
    if $HAVE_JQ; then
        jq -Rn --arg v "$1" '$v'
    else
        printf '"%s"' "${1//\"/\\\"}"
    fi
}

telegram_code_escape() {
    # Telegram Markdown code fences are fragile when output contains backticks.
    local value="${1:-}"
    value="${value//`/\\`}"
    printf '%s' "$value"
}

# =====================
# DISCOVERY TOOLS (each fault-tolerant)
# =====================
run_subfinder() {
    log "Running subfinder..."
    if subfinder -d "$DOMAIN" -all -recursive -t 10 -silent > "$TMP_DIR/subfinder.txt" 2>/dev/null; then
        log "  subfinder: $(count_lines "$TMP_DIR/subfinder.txt") results"
        vlog "  subfinder output: $(cat "$TMP_DIR/subfinder.txt")"
    else
        log "  subfinder: FAILED (skipping)"
        : > "$TMP_DIR/subfinder.txt"
    fi
}

run_assetfinder() {
    log "Running assetfinder..."
    if assetfinder --subs-only "$DOMAIN" > "$TMP_DIR/assetfinder.txt" 2>/dev/null; then
        log "  assetfinder: $(count_lines "$TMP_DIR/assetfinder.txt") results"
    else
        log "  assetfinder: FAILED (skipping)"
        : > "$TMP_DIR/assetfinder.txt"
    fi
}

run_findomain() {
    log "Running findomain..."
    if findomain -t "$DOMAIN" -q > "$TMP_DIR/findomain.txt" 2>/dev/null; then
        log "  findomain: $(count_lines "$TMP_DIR/findomain.txt") results"
    else
        log "  findomain: FAILED (skipping)"
        : > "$TMP_DIR/findomain.txt"
    fi
}

run_github_subdomains() {
    if [[ -z "${GITHUB_TOKEN:-}" ]]; then
        : > "$TMP_DIR/github_subs.txt"
        return
    fi
    log "Running github-subdomains..."
    if github-subdomains -d "$DOMAIN" -t "$GITHUB_TOKEN" -e -raw -o "$TMP_DIR/github_subs.txt" 2>/dev/null; then
        log "  github-subdomains: $(count_lines "$TMP_DIR/github_subs.txt") results"
    else
        log "  github-subdomains: FAILED (skipping)"
        : > "$TMP_DIR/github_subs.txt"
    fi
}

run_chaos() {
    log "Running ProjectDiscovery chaos..."
    # chaos CLI variants differ. This supports the common '-d domain -silent' behavior.
    if chaos -d "$DOMAIN" -silent > "$TMP_DIR/chaos.txt" 2>/dev/null; then
        log "  chaos: $(count_lines "$TMP_DIR/chaos.txt") results"
    else
        log "  chaos: FAILED or not authenticated (skipping)"
        : > "$TMP_DIR/chaos.txt"
    fi
}

run_crtsh() {
    log "Running crt.sh (timeout: ${CRTSH_TIMEOUT}s)..."
    CRTSH_RAW=$(curl -s --max-time "$CRTSH_TIMEOUT" "https://crt.sh/?q=%25.$DOMAIN&output=json" 2>/dev/null || echo "")

    if [[ -n "$CRTSH_RAW" && "$CRTSH_RAW" != "[]" ]]; then
        if $HAVE_JQ; then
            echo "$CRTSH_RAW" | jq -r '.[].name_value' 2>/dev/null | tr '\n' ',' | tr ',' '\n' | sed 's/\*\.//g' | sort -u > "$TMP_DIR/crtsh.txt"
        else
            echo "$CRTSH_RAW" | grep -o '"name_value":"[^"]*"' | cut -d':' -f2- | tr -d '"' | tr '\n' ',' | tr ',' '\n' | sed 's/\*\.//g' | sort -u > "$TMP_DIR/crtsh.txt"
        fi
        log "  crt.sh: $(count_lines "$TMP_DIR/crtsh.txt") results"
    else
        log "  crt.sh: FAILED or empty (skipping)"
        : > "$TMP_DIR/crtsh.txt"
    fi
}

# =====================
# RUN DISCOVERY (parallel, fault-tolerant)
# =====================
log "=== Subdomain scan for $DOMAIN ==="
log "Scan id: $TODAY"

PIDS=()

if [[ " ${AVAILABLE_TOOLS[*]} " =~ " subfinder " ]]; then
    run_subfinder & PIDS+=($!)
fi
if [[ " ${AVAILABLE_TOOLS[*]} " =~ " assetfinder " ]]; then
    run_assetfinder & PIDS+=($!)
fi
if [[ " ${AVAILABLE_TOOLS[*]} " =~ " findomain " ]]; then
    run_findomain & PIDS+=($!)
fi
if [[ " ${AVAILABLE_TOOLS[*]} " =~ " github-subdomains " ]]; then
    run_github_subdomains & PIDS+=($!)
fi
if [[ " ${AVAILABLE_TOOLS[*]} " =~ " chaos " ]]; then
    run_chaos & PIDS+=($!)
fi
if [[ " ${AVAILABLE_TOOLS[*]} " =~ " curl " ]]; then
    run_crtsh & PIDS+=($!)
fi

for pid in "${PIDS[@]}"; do
    wait "$pid" 2>/dev/null || true
done

log "All tools finished."

# Persist per-source raw outputs before TMP cleanup, useful for debugging cron runs.
# Using find avoids fragile empty-glob behavior under set -euo pipefail.
find "$TMP_DIR" -maxdepth 1 -type f -name '*.txt' -exec cp {} "$SOURCE_DIR"/ \; 2>/dev/null || true

# =====================
# MERGE & DEDUP
# =====================
DOMAIN_REGEX="(\.${DOMAIN//./\.}|^${DOMAIN//./\.})$"
cat "$TMP_DIR"/*.txt \
    | tr '[:upper:]' '[:lower:]' \
    | sed 's/^\.//g' \
    | sed 's/[[:space:]]//g' \
    | grep -E "$DOMAIN_REGEX" \
    | sort -u > "$MERGED"

TOTAL=$(count_lines "$MERGED")

log "Total unique subdomains: $TOTAL"

if [[ "$TOTAL" -eq 0 ]]; then
    log "No subdomains found. Check tools/network."
    exit 0
fi

# =====================
# DNS RESOLUTION + RECORD ENRICHMENT (dnsx)
# =====================
if $HAVE_DNSX; then
    log "Resolving DNS and collecting A/CNAME/response data with one dnsx run..."
    if dnsx -l "$MERGED" -silent -t "$DNS_THREADS" -a -cname -resp > "$DNS_RECORDS" 2>/dev/null; then
        log "  DNS records saved: $DNS_RECORDS"

        # Derive resolved hostnames from the enriched output instead of running dnsx twice.
        awk '{print $1}' "$DNS_RECORDS" | tr -d '[]' | sed 's/[[:space:]]//g' | grep -E "$DOMAIN_REGEX" | sort -u > "$RESOLVED" || : > "$RESOLVED"
        log "  Resolved: $(count_lines "$RESOLVED") / $TOTAL"
    else
        log "  dnsx enrichment failed, using raw list as fallback"
        : > "$DNS_RECORDS"
        cp "$MERGED" "$RESOLVED"
    fi

    # No dnsx JSONL is advertised here because generating it would require a second dnsx pass.

    # Extract likely CNAME rows from human dnsx output. Also keep full DNS_RECORDS for manual review.
    grep -i 'cname' "$DNS_RECORDS" > "$CNAMES" 2>/dev/null || : > "$CNAMES"
    log "  CNAME hints: $(count_lines "$CNAMES")"
else
    log "dnsx not installed, skipping DNS enrichment"
    cp "$MERGED" "$RESOLVED"
    : > "$DNS_RECORDS"
    : > "$CNAMES"
fi

# =====================
# TAKEOVER CHECKS (subzy)
# =====================
: > "$TAKEOVER_SUBZY"
: > "$TAKEOVER_FINDINGS"

if [[ "$TAKEOVER_ENABLED" == "true" ]]; then
    log "Running takeover checks..."

    if $HAVE_SUBZY; then
        # subzy usually accepts domains directly. Run on resolved list, because takeover needs live DNS delegation.
        if subzy run --targets "$RESOLVED" --hide_fails > "$TAKEOVER_SUBZY" 2>/dev/null; then
            log "  subzy output lines: $(count_lines "$TAKEOVER_SUBZY")"
        else
            log "  subzy takeover check failed or no findings"
            : > "$TAKEOVER_SUBZY"
        fi
    else
        log "  subzy not installed, skipping subzy"
    fi

    cat "$TAKEOVER_SUBZY" | sed '/^[[:space:]]*$/d' | sort -u > "$TAKEOVER_FINDINGS"
    log "  takeover findings merged: $(count_lines "$TAKEOVER_FINDINGS")"
else
    log "Takeover checks disabled via TAKEOVER_ENABLED=false"
fi

# =====================
# HTTP PROBING (httpx enriched)
# =====================
if $HAVE_HTTPX; then
    log "Probing HTTP with one httpx JSONL run..."
    if httpx -l "$RESOLVED" \
        -silent \
        -t "$HTTP_THREADS" \
        -status-code \
        -title \
        -tech-detect \
        -content-length \
        -follow-redirects \
        -json > "$ALIVE_JSON" 2>/dev/null; then
        log "  Alive JSONL saved: $ALIVE_JSON"

        # Derive the human-readable recon doc from JSONL instead of running httpx twice.
        if $HAVE_JQ; then
            jq -r '[
                (.url // .input // ""),
                ((.status_code // "") | tostring),
                (.title // ""),
                ((.content_length // .["content-length"] // "") | tostring),
                ((.tech // []) | if type == "array" then join(",") else tostring end)
            ] | @tsv' "$ALIVE_JSON" > "$ALIVE" 2>/dev/null || cp "$ALIVE_JSON" "$ALIVE"
        else
            cp "$ALIVE_JSON" "$ALIVE"
        fi
        log "  Alive hosts: $(count_lines "$ALIVE_JSON")"
    else
        log "  httpx failed (non-fatal)"
        : > "$ALIVE"
        : > "$ALIVE_JSON"
    fi
else
    log "httpx not installed, skipping HTTP probing"
    : > "$ALIVE"
    : > "$ALIVE_JSON"
fi

# =====================
# DIFF (defensive sort on both sides)
# =====================
sort -u "$KNOWN" -o "$KNOWN"
NEW_SUBS=$(comm -23 "$MERGED" "$KNOWN")
NEW_COUNT=$(echo "$NEW_SUBS" | grep -c '.' 2>/dev/null) || NEW_COUNT=0

if [[ "$NEW_COUNT" -gt 0 ]]; then
    echo "$NEW_SUBS" > "$NEW_FILE"
    log "NEW subdomains found: $NEW_COUNT"
    vlog "  New subs found:" && $VERBOSE && echo "$NEW_SUBS" | tee -a "$LOG_FILE"

    # Accumulate into known (merge, never replace)
    sort -u "$MERGED" "$KNOWN" -o "$KNOWN"
else
    log "No new subdomains."
    sort -u "$MERGED" "$KNOWN" -o "$KNOWN"
fi

# =====================
# POST-PROCESS: clean list + categorize
# =====================
CLEAN="$DOMAIN_DIR/clean_subdomains.txt"
INTERESTING="$DOMAIN_DIR/interesting.txt"
INTERESTING_LATEST="$DOMAIN_DIR/interesting_latest.txt"

# Strip www. duplicates
grep -v '^www\.' "$KNOWN" | sort -u > "$CLEAN"
log "Clean list (no www.): $(count_lines "$CLEAN")"

# Categorize interesting targets. These categories intentionally overlap: one host can appear in multiple risk buckets.
{
    echo "=== GENERATED: $(date) ==="
    echo "Domain: $DOMAIN"
    echo "Scan id: $TODAY"
    echo ""

    echo "--- DEV/TEST/QM/QS/STAGING (weak hardening candidates) ---"
    grep -iE '(^|[-.])(test|dev|devel|development|stage|staging|preprod|preview|qa|qm|qs|uat|demo|sandbox|sectest|int|integration)([-.]|$)' "$CLEAN" || echo "(none)"
    echo ""

    echo "--- AUTH/IDENTITY/LOGIN ---"
    grep -iE '(^|[-.])(auth|oauth|saml|sso|idp|identity|login|signin|account|accounts|user|users|iam|keycloak|cas|openid)([-.]|$)' "$CLEAN" || echo "(none)"
    echo ""

    echo "--- PORTALS/DASHBOARDS/PANELS ---"
    grep -iE '(^|[-.])(portal|dashboard|panel|console|admin|backend|backoffice|manage|manager|management|intern|internal|intranet)([-.]|$)' "$CLEAN" || echo "(none)"
    echo ""

    echo "--- MONITORING/OBSERVABILITY ---"
    grep -iE '(^|[-.])(monitor|monitoring|grafana|kibana|prometheus|alertmanager|graylog|splunk|logs|logging|logstash|sentry|status|uptime|health)([-.]|$)' "$CLEAN" || echo "(none)"
    echo ""

    echo "--- CI/CD / DEVOPS / CODE ---"
    grep -iE '(^|[-.])(jenkins|gitlab|github|bitbucket|gitea|sonar|sonarqube|nexus|artifactory|harbor|registry|docker|ci|cd|build|runner)([-.]|$)' "$CLEAN" || echo "(none)"
    echo ""

    echo "--- INFRA/VPN/REMOTE ACCESS ---"
    grep -iE '(^|[-.])(citrix|vpn|rdp|ssh|remote|gateway|gw|firewall|fw|waf|proxy|lb|loadbalancer|netscaler|forti|fortinet|paloalto|pulse|zscaler)([-.]|$)' "$CLEAN" || echo "(none)"
    echo ""

    echo "--- ENTERPRISE APPS (sap/jira/confluence/remedy/etc) ---"
    grep -iE '(^|[-.])(sap|jira|confluence|remedy|servicenow|service-now|sharepoint|crm|erp|idm|adfs|exchange|owa)([-.]|$)' "$CLEAN" || echo "(none)"
    echo ""

    echo "--- MAIL/COMMS (exchange/smtp/voip/uc/meet) ---"
    grep -iE '(^|[-.])(mail|mx[0-9]*|smtp|imap|pop|relay|collab|finesse|viedge|voicemail|sip|voip|meeting|meet|teams|webex|lync|skype)([-.]|$)' "$CLEAN" || echo "(none)"
    echo ""

    echo "--- API/DATA/GRAPHQL/FILES ---"
    grep -iE '(^|[-.])(api|apis|graphql|gql|data|open|gis|maps|map|stream|cloud|upload|uploads|files|file|download|media|assets|static|cdn|storage|blob|s3)([-.]|$)' "$CLEAN" || echo "(none)"
    echo ""

    echo "--- CMS/WIKI/EDITORIAL ---"
    grep -iE '(^|[-.])(cms|wordpress|wp|drupal|typo3|redaktion|editor|wiki|mediawiki|content)([-.]|$)' "$CLEAN" || echo "(none)"
    echo ""

    echo "--- PAYMENTS/ORDERS/BUSINESS LOGIC ---"
    grep -iE '(^|[-.])(pay|payment|checkout|billing|invoice|order|orders|shop|store|cart|booking|book|reservation|ticket|tickets)([-.]|$)' "$CLEAN" || echo "(none)"
    echo ""

    echo "--- CNAME HINTS FROM CURRENT SCAN ---"
    if [[ -s "$CNAMES" ]]; then
        cat "$CNAMES"
    else
        echo "(none)"
    fi
    echo ""

    echo "--- TAKEOVER FINDINGS FROM CURRENT SCAN ---"
    if [[ -s "$TAKEOVER_FINDINGS" ]]; then
        cat "$TAKEOVER_FINDINGS"
    else
        echo "(none)"
    fi

} > "$INTERESTING"
cp "$INTERESTING" "$INTERESTING_LATEST"
log "Interesting targets saved: $INTERESTING"

# =====================
# SUMMARY JSON
# =====================
RESOLVED_COUNT=$(count_lines "$RESOLVED")
ALIVE_COUNT=$(count_lines "$ALIVE")
KNOWN_COUNT=$(count_lines "$KNOWN")
CLEAN_COUNT=$(count_lines "$CLEAN")
CNAME_COUNT=$(count_lines "$CNAMES")
TAKEOVER_COUNT=$(count_lines "$TAKEOVER_FINDINGS")
SUBFINDER_COUNT=$(count_lines "$SOURCE_DIR/subfinder.txt")
ASSETFINDER_COUNT=$(count_lines "$SOURCE_DIR/assetfinder.txt")
FINDOMAIN_COUNT=$(count_lines "$SOURCE_DIR/findomain.txt")
GITHUB_COUNT=$(count_lines "$SOURCE_DIR/github_subs.txt")
CHAOS_COUNT=$(count_lines "$SOURCE_DIR/chaos.txt")
CRTSH_COUNT=$(count_lines "$SOURCE_DIR/crtsh.txt")

if $HAVE_JQ; then
    jq -n \
        --arg domain "$DOMAIN" \
        --arg scan_id "$TODAY" \
        --arg timestamp "$(date -Iseconds)" \
        --arg merged "$MERGED" \
        --arg resolved "$RESOLVED" \
        --arg dns_records "$DNS_RECORDS" \
        --arg cnames "$CNAMES" \
        --arg alive "$ALIVE" \
        --arg alive_json "$ALIVE_JSON" \
        --arg takeover_findings "$TAKEOVER_FINDINGS" \
        --arg interesting "$INTERESTING" \
        --arg known "$KNOWN" \
        --arg source_dir "$SOURCE_DIR" \
        --argjson total "$TOTAL" \
        --argjson new_count "$NEW_COUNT" \
        --argjson resolved_count "$RESOLVED_COUNT" \
        --argjson alive_count "$ALIVE_COUNT" \
        --argjson known_count "$KNOWN_COUNT" \
        --argjson clean_count "$CLEAN_COUNT" \
        --argjson cname_count "$CNAME_COUNT" \
        --argjson takeover_count "$TAKEOVER_COUNT" \
        --argjson subfinder_count "$SUBFINDER_COUNT" \
        --argjson assetfinder_count "$ASSETFINDER_COUNT" \
        --argjson findomain_count "$FINDOMAIN_COUNT" \
        --argjson github_count "$GITHUB_COUNT" \
        --argjson chaos_count "$CHAOS_COUNT" \
        --argjson crtsh_count "$CRTSH_COUNT" \
        '{
            domain: $domain,
            scan_id: $scan_id,
            timestamp: $timestamp,
            counts: {
                total_unique: $total,
                new: $new_count,
                resolved: $resolved_count,
                http_alive: $alive_count,
                known_total: $known_count,
                clean_total: $clean_count,
                cname_hints: $cname_count,
                takeover_findings: $takeover_count
            },
            source_counts: {
                subfinder: $subfinder_count,
                assetfinder: $assetfinder_count,
                findomain: $findomain_count,
                github_subdomains: $github_count,
                chaos: $chaos_count,
                crtsh: $crtsh_count
            },
            files: {
                raw: $merged,
                resolved: $resolved,
                dns_records: $dns_records,
                cnames: $cnames,
                http_alive: $alive,
                http_alive_json: $alive_json,
                takeover_findings: $takeover_findings,
                interesting: $interesting,
                known: $known,
                source_dir: $source_dir
            }
        }' > "$SUMMARY_JSON"
else
    cat > "$SUMMARY_JSON" <<JSON
{
  "domain": "${DOMAIN}",
  "scan_id": "${TODAY}",
  "timestamp": "$(date -Iseconds)",
  "counts": {
    "total_unique": ${TOTAL},
    "new": ${NEW_COUNT},
    "resolved": ${RESOLVED_COUNT},
    "http_alive": ${ALIVE_COUNT},
    "known_total": ${KNOWN_COUNT},
    "clean_total": ${CLEAN_COUNT},
    "cname_hints": ${CNAME_COUNT},
    "takeover_findings": ${TAKEOVER_COUNT}
  },
  "source_counts": {
    "subfinder": ${SUBFINDER_COUNT},
    "assetfinder": ${ASSETFINDER_COUNT},
    "findomain": ${FINDOMAIN_COUNT},
    "github_subdomains": ${GITHUB_COUNT},
    "chaos": ${CHAOS_COUNT},
    "crtsh": ${CRTSH_COUNT}
  },
  "files": {
    "raw": "${MERGED}",
    "resolved": "${RESOLVED}",
    "dns_records": "${DNS_RECORDS}",
    "cnames": "${CNAMES}",
    "http_alive": "${ALIVE}",
    "http_alive_json": "${ALIVE_JSON}",
    "takeover_findings": "${TAKEOVER_FINDINGS}",
    "interesting": "${INTERESTING}",
    "known": "${KNOWN}",
    "source_dir": "${SOURCE_DIR}"
  }
}
JSON
fi
log "Summary JSON saved: $SUMMARY_JSON"

# =====================
# TELEGRAM NOTIFICATION
# =====================
if ! $TELEGRAM_ENABLED; then
    log "Telegram notification skipped (not configured)."
    log "Done. Scan: $MERGED | Known: $(count_lines "$KNOWN") | Summary: $SUMMARY_JSON"
    exit 0
fi

HEADER="🔍 *Subdomain scan for* \`$DOMAIN\`
📅 $TODAY
📦 Unique this scan: *$TOTAL* | 🆕 New: *$NEW_COUNT* | 📋 Known: *$KNOWN_COUNT*
🌐 Resolved: $RESOLVED_COUNT | ✅ HTTP alive: $ALIVE_COUNT
🔗 CNAME hints: $CNAME_COUNT | ⚠️ Takeover findings: $TAKEOVER_COUNT"

NEW_SUBS_ESCAPED=""
TAKEOVER_SNIPPET_ESCAPED=""
if [[ "$NEW_COUNT" -gt 0 ]]; then
    NEW_SUBS_ESCAPED=$(telegram_code_escape "$NEW_SUBS")
fi
if [[ "$TAKEOVER_COUNT" -gt 0 ]]; then
    TAKEOVER_SNIPPET_ESCAPED=$(head -n 30 "$TAKEOVER_FINDINGS" | telegram_code_escape)
fi

if [[ "$NEW_COUNT" -gt 0 || "$TAKEOVER_COUNT" -gt 0 ]]; then
    TELEGRAM_BODY=""

    if [[ "$NEW_COUNT" -gt 0 ]]; then
        TELEGRAM_BODY+=$'\n\n*New subdomains:*\n```\n'
        TELEGRAM_BODY+="$NEW_SUBS_ESCAPED"
        TELEGRAM_BODY+=$'\n```'
    fi

    if [[ "$TAKEOVER_COUNT" -gt 0 ]]; then
        TELEGRAM_BODY+=$'\n\n*Potential takeover findings:*\n```\n'
        TELEGRAM_BODY+="$TAKEOVER_SNIPPET_ESCAPED"
        TELEGRAM_BODY+=$'\n```'
    fi

    FULL_MSG="$HEADER$TELEGRAM_BODY"

    if [[ ${#FULL_MSG} -le 4000 ]]; then
        TGRESULT=$(curl -s --max-time 10 -X POST \
            "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
            -d chat_id="$TELEGRAM_CHAT_ID" \
            -d parse_mode="Markdown" \
            -d text="$FULL_MSG" 2>&1)
        if echo "$TGRESULT" | grep -q '"ok":true'; then
            log "Telegram: sent as message"
        else
            log "Telegram: message failed, sending files as documents"
            curl -s --max-time 15 -X POST \
                "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendDocument" \
                -F chat_id="$TELEGRAM_CHAT_ID" \
                -F caption="Subdomain scan for $DOMAIN — $TODAY" \
                -F document=@"$SUMMARY_JSON" > /dev/null 2>&1
            [[ -s "$NEW_FILE" ]] && curl -s --max-time 15 -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendDocument" -F chat_id="$TELEGRAM_CHAT_ID" -F caption="New subdomains for $DOMAIN — $TODAY" -F document=@"$NEW_FILE" > /dev/null 2>&1
            [[ -s "$TAKEOVER_FINDINGS" ]] && curl -s --max-time 15 -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendDocument" -F chat_id="$TELEGRAM_CHAT_ID" -F caption="Takeover findings for $DOMAIN — $TODAY" -F document=@"$TAKEOVER_FINDINGS" > /dev/null 2>&1
        fi
    else
        curl -s --max-time 10 -X POST \
            "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
            -d chat_id="$TELEGRAM_CHAT_ID" \
            -d parse_mode="Markdown" \
            -d text="$HEADER

📎 Full output attached because the message is too long." > /dev/null 2>&1

        [[ -s "$NEW_FILE" ]] && curl -s --max-time 15 -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendDocument" -F chat_id="$TELEGRAM_CHAT_ID" -F caption="New subdomains for $DOMAIN — $TODAY" -F document=@"$NEW_FILE" > /dev/null 2>&1
        [[ -s "$TAKEOVER_FINDINGS" ]] && curl -s --max-time 15 -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendDocument" -F chat_id="$TELEGRAM_CHAT_ID" -F caption="Takeover findings for $DOMAIN — $TODAY" -F document=@"$TAKEOVER_FINDINGS" > /dev/null 2>&1
        curl -s --max-time 15 -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendDocument" -F chat_id="$TELEGRAM_CHAT_ID" -F caption="Scan summary for $DOMAIN — $TODAY" -F document=@"$SUMMARY_JSON" > /dev/null 2>&1
        log "Telegram: sent as documents (too long for message)"
    fi
else
    log "No new subdomains and no takeover findings. Sending compact summary only."
    curl -s --max-time 10 -X POST \
        "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        -d chat_id="$TELEGRAM_CHAT_ID" \
        -d parse_mode="Markdown" \
        -d text="$HEADER

No new subdomains. No takeover findings." > /dev/null 2>&1 || true
fi

log "Done. Scan: $MERGED | Known: $(count_lines "$KNOWN") | Summary: $SUMMARY_JSON"
