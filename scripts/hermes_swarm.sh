#!/usr/bin/env bash
# Dynamic Hermes pipeline wrapper for Mulderx.
#
# It creates only the stage that has actionable input:
#   start    -> Liquid + Solid, only when Triage has candidates
#   closeout -> coverage audit after hunters
#   posthunt-triage -> dedupe and handoff after closeout
#   judge    -> Ocelot, only when hunters left CONFIRMADO leads
#   reporter -> Scully, only when Ocelot approved findings
#
# Do not use `hermes kanban swarm`: Hermes v0.22.4 ignores the board workdir.

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd -- "$script_dir/.." && pwd)"
metrics_script="$repo/scripts/mulderx_metrics.py"
evidence_script="$repo/scripts/evidence_store.py"

usage() {
  cat >&2 <<'EOF'
Uso:
  hermes_swarm.sh <board> <workspace> <goal-file> <hunterA-profile> <hunterA-title> <hunterB-profile> <hunterB-title> [judge-profile] [reporter-profile]
  hermes_swarm.sh closeout <board> <workspace> <run-id> [closeout-profile]
  hermes_swarm.sh posthunt-triage <board> <workspace> <run-id> [triage-profile]
  hermes_swarm.sh judge <board> <workspace> <run-id> [judge-profile]
  hermes_swarm.sh reporter <board> <workspace> <run-id> [reporter-profile]

La primera forma inicia solo los hunters. Cuando ambos terminaron, Mulderx
llama `closeout`, luego `posthunt-triage` y finalmente `judge`; cuando Ocelot termina, llama `reporter`.
EOF
  exit 1
}

require_workspace_and_metrics() {
  if [ ! -d "$workspace" ]; then
    echo "workspace-path no existe: $workspace" >&2
    exit 1
  fi
  if [ ! -f "$metrics_script" ]; then
    echo "script de gating/métricas no existe: $metrics_script" >&2
    exit 1
  fi
  if [ ! -f "$evidence_script" ]; then
    echo "script de evidencia no existe: $evidence_script" >&2
    exit 1
  fi
  if [ ! -f "$workspace/findings.json" ]; then
    python3 "$evidence_script" init --workspace "$workspace" >/dev/null
  fi
}

gate_or_stop() {
  local stage="$1"
  local output status
  set +e
  output=$(python3 "$metrics_script" gate --workspace "$workspace" --stage "$stage")
  status=$?
  set -e
  if [ "$status" -eq 0 ]; then
    echo "Gating aprobado ($stage): $output"
    return 0
  fi
  if [ "$status" -eq 10 ]; then
    echo "Etapa '$stage' no creada: no hay input accionable. $output"
    return 10
  fi
  echo "Falló el gating de '$stage': $output" >&2
  return "$status"
}

dispatch_closeout() {
  local board="$1" workspace="$2" run_id="$3" closeout_profile="${4:-closeout}"
  require_workspace_and_metrics
  if gate_or_stop closeout; then
    :
  else
    status=$?
    [ "$status" -eq 10 ] && exit 0
    exit "$status"
  fi
  python3 "$metrics_script" snapshot --workspace "$workspace" --run-id "$run_id" --stage closeout >/dev/null
  hermes kanban --board "$board" create \
    "Closeout - auditar cobertura del sweep" \
    --body "Leer AGENT closeout y producir coverage.md. No ejecutar requests nuevos ni hacer hunting. Registrar metrics: python3 $metrics_script snapshot --workspace '$workspace' --run-id '$run_id' --stage closeout" \
    --assignee "$closeout_profile" --workspace "dir:$workspace" --priority 1 --json | jq -er '.id | select(type == "string" and length > 0)'
  hermes kanban --board "$board" dispatch
}

dispatch_posthunt_triage() {
  local board="$1" workspace="$2" run_id="$3" triage_profile="${4:-posthunt-triage}"
  require_workspace_and_metrics
  if gate_or_stop posthunt-triage; then
    :
  else
    status=$?
    [ "$status" -eq 10 ] && exit 0
    exit "$status"
  fi
  python3 "$metrics_script" snapshot --workspace "$workspace" --run-id "$run_id" --stage posthunt-triage >/dev/null
  hermes kanban --board "$board" create \
    "Post-hunt triage - dedupe y handoff" \
    --body "Leer coverage.md, leads.md y discarded.md; producir posthunt-triage.md. No ejecutar requests nuevos ni decidir severidad final. Registrar metrics: python3 $metrics_script snapshot --workspace '$workspace' --run-id '$run_id' --stage posthunt-triage" \
    --assignee "$triage_profile" --workspace "dir:$workspace" --priority 1 --json | jq -er '.id | select(type == "string" and length > 0)'
  hermes kanban --board "$board" dispatch
}

dispatch_judge() {
  local board="$1" workspace="$2" run_id="$3" judge_profile="${4:-ocelot}"
  require_workspace_and_metrics
  if gate_or_stop judge; then
    :
  else
    status=$?
    if [ "$status" -eq 10 ]; then
      python3 "$metrics_script" snapshot --workspace "$workspace" --run-id "$run_id" --stage hunters >/dev/null
      exit 0
    fi
    exit "$status"
  fi
  python3 "$metrics_script" snapshot --workspace "$workspace" --run-id "$run_id" --stage hunters >/dev/null
  hermes kanban --board "$board" create \
    "Judge — severity gate sobre hallazgos confirmados" \
    --body "Leer coverage.md, posthunt-triage.md si existen, leads.md y findings.json. Juzgar solo leads CONFIRMADO cuyo recibo estructurado y hashes sean válidos. Ocelot es read-only: no edites findings.json ni ejecutes requests. Criterio duro: sin PoC/config/pipeline/callback real -> Informational o P4 máximo. Chequear Q1/Q2/Q3, explicación benigna, evidence gate y contradicciones cruzadas. Al terminar, escribir judged.md y registrar métricas: python3 $metrics_script snapshot --workspace '$workspace' --run-id '$run_id' --stage judge" \
    --assignee "$judge_profile" --workspace "dir:$workspace" --priority 1 --json | jq -er '.id | select(type == "string" and length > 0)'
  hermes kanban --board "$board" dispatch
}

dispatch_reporter() {
  local board="$1" workspace="$2" run_id="$3" reporter_profile="${4:-scully}"
  require_workspace_and_metrics
  if gate_or_stop reporter; then
    :
  else
    status=$?
    if [ "$status" -eq 10 ]; then
      python3 "$metrics_script" snapshot --workspace "$workspace" --run-id "$run_id" --stage judge >/dev/null
      exit 0
    fi
    exit "$status"
  fi
  hermes kanban --board "$board" create \
    "Reporter — consolidar findings aprobados" \
    --body "Leer judged.md y findings.json; procesar únicamente leads con veredicto APPROVED y estado estructurado APPROVED con evidencia válida. Armar borradores en reports/ para revisión humana; no enviar. No inflar severidad ni inventar impacto. Al terminar, registrar métricas: python3 $metrics_script snapshot --workspace '$workspace' --run-id '$run_id' --stage reporter" \
    --assignee "$reporter_profile" --workspace "dir:$workspace" --priority 1 --json | jq -er '.id | select(type == "string" and length > 0)'
  hermes kanban --board "$board" dispatch
}

if [ "$#" -gt 0 ] && [ "$1" = "closeout" ]; then
  [ "$#" -ge 4 ] || usage
  board="$2"; workspace="$3"; run_id="$4"
  dispatch_closeout "$board" "$workspace" "$run_id" "${5:-closeout}"
  exit 0
fi

if [ "$#" -gt 0 ] && [ "$1" = "posthunt-triage" ]; then
  [ "$#" -ge 4 ] || usage
  board="$2"; workspace="$3"; run_id="$4"
  dispatch_posthunt_triage "$board" "$workspace" "$run_id" "${5:-posthunt-triage}"
  exit 0
fi

if [ "$#" -gt 0 ] && [ "$1" = "judge" ]; then
  [ "$#" -ge 4 ] || usage
  board="$2"; workspace="$3"; run_id="$4"
  dispatch_judge "$board" "$workspace" "$run_id" "${5:-ocelot}"
  exit 0
fi

if [ "$#" -gt 0 ] && [ "$1" = "reporter" ]; then
  [ "$#" -ge 4 ] || usage
  board="$2"; workspace="$3"; run_id="$4"
  dispatch_reporter "$board" "$workspace" "$run_id" "${5:-scully}"
  exit 0
fi

[ "$#" -ge 7 ] || usage
board="$1"; workspace="$2"; goal_file="$3"
hunterA_profile="$4"; hunterA_title="$5"
hunterB_profile="$6"; hunterB_title="$7"
judge_profile="${8:-ocelot}"
reporter_profile="${9:-scully}"

[ -f "$goal_file" ] || { echo "goal-body-file no existe: $goal_file" >&2; exit 1; }
require_workspace_and_metrics

if gate_or_stop hunters; then
  :
else
  status=$?
  [ "$status" -eq 10 ] && exit 0
  exit "$status"
fi

run_id="run-$(date -u +%Y%m%dT%H%M%SZ)-$$"
metrics_file=$(python3 "$metrics_script" start --workspace "$workspace" --run-id "$run_id" --board "$board")
hermes kanban boards create "$board" >/dev/null 2>&1 || true
hermes kanban boards set-default-workdir "$board" "$workspace"

hunterA_id=$(hermes kanban --board "$board" create "$hunterA_title" \
  --body-file "$goal_file" --assignee "$hunterA_profile" \
  --workspace "dir:$workspace" --priority 1 --json | jq -er '.id | select(type == "string" and length > 0)')
hunterB_id=$(hermes kanban --board "$board" create "$hunterB_title" \
  --body-file "$goal_file" --assignee "$hunterB_profile" \
  --workspace "dir:$workspace" --priority 1 --json | jq -er '.id | select(type == "string" and length > 0)')

echo "Hunters creados en board '$board':"
echo "  Hunter A ($hunterA_profile): $hunterA_id"
echo "  Hunter B ($hunterB_profile): $hunterB_id"
echo "  Métricas: $metrics_file"
echo "  Run ID: $run_id"
echo "Tras completar ambos hunters: $0 judge '$board' '$workspace' '$run_id' '$judge_profile'"
echo "Tras completar Ocelot: $0 reporter '$board' '$workspace' '$run_id' '$reporter_profile'"
hermes kanban --board "$board" dispatch
