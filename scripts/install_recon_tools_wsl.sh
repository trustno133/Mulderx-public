#!/usr/bin/env bash
# Install Mulderx's Linux recon utilities into the current WSL user.
# Downloads tools, Python packages, templates, and small wordlists only;
# it does not send requests to any target.

set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
GOBIN="${GOBIN:-$HOME/go/bin}"
VENV="$HOME/.local/share/mulderx/venvs/mulderx"
SECLISTS_PATH="$HOME/.local/share/mulderx/SecLists"
BOOTSTRAP="$HOME/.cache/mulderx-bootstrap"

for tool in go curl python3 gzip gcc; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        printf 'Missing prerequisite in WSL: %s\n' "$tool" >&2
        exit 1
    fi
done

mkdir -p "$GOBIN" "$BOOTSTRAP" "$SECLISTS_PATH/Discovery/Web-Content"
export GOBIN
export PATH="$GOBIN:$PATH"

PROFILE="$HOME/.profile"
touch "$PROFILE"
if ! grep -Fq 'export PATH="$HOME/go/bin:$PATH"' "$PROFILE"; then
    printf '\n# Go tools used by Mulderx\nexport PATH="$HOME/go/bin:$PATH"\n' >> "$PROFILE"
fi
if ! grep -Fq 'export SECLISTS_PATH="$HOME/.local/share/mulderx/SecLists"' "$PROFILE"; then
    printf '\n# Wordlists used by Mulderx fuzzing skills\nexport SECLISTS_PATH="$HOME/.local/share/mulderx/SecLists"\n' >> "$PROFILE"
fi
if ! grep -Fq 'export MULDERX_PARAM_WORDLIST=' "$PROFILE"; then
    printf 'export MULDERX_PARAM_WORDLIST="$SECLISTS_PATH/Discovery/Web-Content/burp-parameter-names.txt"\n' >> "$PROFILE"
fi

printf 'Installing Go recon tools...\n'
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/PentestPad/subzy@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/gwen001/github-subdomains@latest
go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest

printf 'Installing Findomain Linux release...\n'
curl -fsSL https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip \
    -o "$BOOTSTRAP/findomain-linux.zip"
python3 - "$BOOTSTRAP/findomain-linux.zip" "$GOBIN/findomain" <<'PY'
import pathlib
import sys
import zipfile

source, target = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
with zipfile.ZipFile(source) as archive:
    candidates = [
        name for name in archive.namelist()
        if pathlib.PurePosixPath(name).name == "findomain"
        and ".." not in pathlib.PurePosixPath(name).parts
    ]
    if len(candidates) != 1:
        raise SystemExit(f"Expected one Findomain binary, found: {candidates}")
    target.write_bytes(archive.read(candidates[0]))
target.chmod(0o755)
PY

printf 'Installing x8 Linux release...\n'
curl -fsSL https://github.com/Sh1Yo/x8/releases/latest/download/x86_64-linux-x8.gz \
    -o "$BOOTSTRAP/x8.gz"
gzip -dc "$BOOTSTRAP/x8.gz" > "$GOBIN/x8"
chmod 755 "$GOBIN/x8"

printf 'Installing Mulderx Python dependencies and Arjun in a virtual environment...\n'
python3 -m venv "$VENV"
"$VENV/bin/python" -m pip install --upgrade pip
"$VENV/bin/python" -m pip install -r "$ROOT/requirements.txt" \
    networkx tree-sitter tree-sitter-javascript arjun
ln -sfn "$VENV/bin/arjun" "$GOBIN/arjun"

printf 'Downloading focused SecLists files...\n'
curl -fsSL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt \
    -o "$SECLISTS_PATH/Discovery/Web-Content/burp-parameter-names.txt"
curl -fsSL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt \
    -o "$SECLISTS_PATH/Discovery/Web-Content/common.txt"

printf 'Updating Nuclei templates...\n'
nuclei -update-templates

printf '\nInstalled commands are in %s\n' "$GOBIN"
printf 'SecLists path: %s\n' "$SECLISTS_PATH"
printf 'Optional provider API keys: GITHUB_TOKEN and CHAOS_KEY\n'
printf 'Reload WSL with: source ~/.profile\n'
