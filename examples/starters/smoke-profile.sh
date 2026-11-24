#!/usr/bin/env bash
set -euo pipefail

profile="${1:?starter profile required}"
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
helm="$repo/bin/helm-ai-kernel"
if [[ ! -x "$helm" ]]; then
  printf 'Run make build to create %s.\n' "$helm" >&2
  exit 1
fi

scratch="$(mktemp -d)"
trap 'rm -rf -- "$scratch"' EXIT
project="$scratch/project"
"$helm" init "$profile" "$project"
for file in helm.yaml .env.helm.example; do
  if [[ ! -s "$project/$file" ]]; then
    printf 'Starter %s did not produce %s.\n' "$profile" "$file" >&2
    exit 1
  fi
done
printf 'PASS: starter %s initialized and generated helm.yaml and .env.helm.example.\n' "$profile"

printf '\nLocal environment diagnostics\n'
doctor_status=0
(cd "$project" && "$helm" doctor) || doctor_status=$?
printf 'Doctor exit status %s.\n' "$doctor_status"
