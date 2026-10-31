#!/usr/bin/env bash
# quantum_posture: build the classical-only receipt verifier; no trust is bundled.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output="${1:-${root}/bin/receipt-verifier-wasm}"
mkdir -p "${output}"
output="$(cd "${output}" && pwd)"
cd "${root}/core"
export GOWORK=off
version="$(go env GOVERSION)"
expected="go$(awk '$1 == "go" { print $2; exit }' go.mod)"
goroot="$(go env GOROOT)"
if [[ "${version}" != "${expected}" || "$(head -n 1 "${goroot}/VERSION")" != "${version}" ]]; then
  echo "the pinned ${expected} compiler and matching GOROOT are required" >&2
  exit 2
fi
GOOS=js GOARCH=wasm CGO_ENABLED=0 go build -mod=readonly -trimpath -ldflags='-s -w' \
  -o "${output}/receipt_verify.wasm" ./cmd/receipt_verify_wasm
cp "${goroot}/lib/wasm/wasm_exec.js" "${output}/wasm_exec.js"
cp "${goroot}/LICENSE" "${output}/GO-LICENSE"
cp cmd/receipt_verify_wasm/receipt-verifier.mjs "${output}/receipt-verifier.mjs"
python3 - "${root}" "${output}" "${version}" <<'PY'
import hashlib,json,subprocess,sys
from pathlib import Path
root,out=map(Path,sys.argv[1:3])
git=lambda *args:subprocess.check_output(['git','-C',str(root),*args],text=True).strip()
files=['receipt_verify.wasm','wasm_exec.js','receipt-verifier.mjs','GO-LICENSE']
manifest={'schema_version':'helm.receipt-verifier-wasm-build.v1',
          'source_revision':git('rev-parse','HEAD'),
          'source_dirty':bool(git('status','--porcelain','--untracked-files=normal')),
          'go_version':sys.argv[3],'target':'js/wasm',
          'verification_schema':'helm.receipt-verification.v1',
          'scope':'classical receipt-chain and EffectPermit verification; no EvidencePack/runtime acceptance',
          'sha256':{f:hashlib.sha256((out/f).read_bytes()).hexdigest() for f in files}}
(out/'build.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps({'bundle':str(out),'source_revision':manifest['source_revision'],
                  'source_dirty':manifest['source_dirty'],'target':manifest['target']}))
PY
