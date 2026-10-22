#!/usr/bin/env bash
# Builds a zip you can give to someone else (or copy to another computer).
#   bash package.sh            -> ~/ane_share.zip
# It INCLUDES the code, the trained models and the training data.
# It LEAVES OUT everything private or machine-specific: the venv, the login
# database, the encryption keys, the saved credentials, logs and reports.
set -euo pipefail
cd "$(dirname "$0")"
name="$(basename "$PWD")"
out="${1:-$HOME/ane_share.zip}"
rm -f "$out"
cd ..
zip -qr "$out" "$name" \
  -x "$name/venv/*" "$name/.venv/*" "*/__pycache__/*" "*.pyc" \
     "$name/data/secret.key" "$name/data/flask_secret" "$name/data/*.db" \
     "$name/data/status.json" "$name/data/metrics.jsonl" "$name/data/commands.jsonl" \
     "$name/data/control.json" "$name/data/approval*.json" "$name/data/settings.json" \
     "$name/data/audit.jsonl" "$name/data/reports/*" "$name/data/*.tmp" \
     "$name/data/test*.csv" "$name/instance/*"
echo "Created $out"
unzip -l "$out" | tail -1
echo "Check it contains no secrets (this should print nothing):"
unzip -l "$out" | grep -E "secret|flask_secret|\.db$|\.key$" || true
