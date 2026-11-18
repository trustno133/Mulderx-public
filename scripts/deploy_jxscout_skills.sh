#!/usr/bin/env bash
# Despliega la golden copy de las 5 skills de JXScout (jxscout-skills/ en este
# repo) a una o todas las instancias en C:\Users\Ecar\jxscout-pro\<instancia>\.
#
# Las skills por defecto que trae jxscout-pro-v2 quedan reemplazadas por estas
# versiones mejoradas (mismo contenido + Troubleshooting + Related skills).
# Correr de nuevo cada vez que se edite algo en jxscout-skills/, y para toda
# instancia nueva que cree jxscout-pro-v2.
#
# Uso:
#   scripts/deploy_jxscout_skills.sh --all
#   scripts/deploy_jxscout_skills.sh <nombre-instancia> [<nombre-instancia> ...]
# Configuración:
#   JXSCOUT_ROOT (default: $HOME/jxscout-pro) apunta al directorio de instancias.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_DIR="$REPO_ROOT/jxscout-skills"
JXSCOUT_ROOT="${JXSCOUT_ROOT:-$HOME/jxscout-pro}"

SKILLS=(jxscout-security-research jxscout-static-analysis jxscout-bookmarks jxscout-custom-analyzers jxscout-relationships)

if [[ $# -eq 0 ]]; then
  echo "Uso: $0 --all | <nombre-instancia> [<nombre-instancia> ...]" >&2
  exit 1
fi

if [[ ! -d "$SOURCE_DIR" ]]; then
  echo "[!] No existe la golden copy de skills: $SOURCE_DIR" >&2
  exit 1
fi
if [[ ! -d "$JXSCOUT_ROOT" ]]; then
  echo "[!] No existe JXSCOUT_ROOT=$JXSCOUT_ROOT; configurá la ruta local de instancias." >&2
  exit 1
fi

if [[ "$1" == "--all" ]]; then
  mapfile -t instances < <(find "$JXSCOUT_ROOT" -mindepth 1 -maxdepth 1 -type d -printf '%f\n')
else
  instances=("$@")
fi

for instance in "${instances[@]}"; do
  target_base="$JXSCOUT_ROOT/$instance/.claude/skills"
  if [[ ! -d "$JXSCOUT_ROOT/$instance" ]]; then
    echo "[!] Instancia '$instance' no existe en $JXSCOUT_ROOT -- salteando" >&2
    continue
  fi
  mkdir -p "$target_base"
  for skill in "${SKILLS[@]}"; do
    mkdir -p "$target_base/$skill"
    cp "$SOURCE_DIR/$skill/SKILL.md" "$target_base/$skill/SKILL.md"
  done
  echo "[+] $instance: 5 skills desplegadas"
done
