#!/usr/bin/env bash
# HELM-747: pin the lint findings protocols/proto/buf.yaml exempts.
#
# buf.yaml exempts the published v1 files from four naming rules. Its
# ignore_only entries are scoped to a file and a rule, so they would also let
# a new badly named RPC into one of those files. This check lints the module
# with no exemptions and requires the findings to be exactly the recorded
# legacy set below, counted per file and rule. A new finding fails. A fixed one
# fails too, so the list only shrinks in a reviewed change to this file and
# buf.yaml.
#
# Usage: check_proto_lint_exemptions.sh [module-dir]   (default: protocols/proto)
set -euo pipefail

module="${1:-protocols/proto}"

# <file> <rule> <count>, sorted. 23 findings.
expected='boundary/extauthz/v1/extauthz.proto PACKAGE_DIRECTORY_MATCH 1
boundary/extauthz/v1/extauthz.proto RPC_REQUEST_STANDARD_NAME 1
boundary/extauthz/v1/extauthz.proto RPC_RESPONSE_STANDARD_NAME 1
helm/authority/v1/authority.proto RPC_REQUEST_STANDARD_NAME 1
helm/authority/v1/authority.proto RPC_RESPONSE_STANDARD_NAME 1
helm/effects/v1/effects.proto RPC_REQUEST_STANDARD_NAME 1
helm/effects/v1/effects.proto RPC_RESPONSE_STANDARD_NAME 1
helm/kernel/v1/helm.proto RPC_REQUEST_STANDARD_NAME 3
helm/kernel/v1/helm.proto RPC_RESPONSE_STANDARD_NAME 3
helm/truth/v1/truth.proto RPC_REQUEST_RESPONSE_UNIQUE 4
helm/truth/v1/truth.proto RPC_REQUEST_STANDARD_NAME 3
helm/truth/v1/truth.proto RPC_RESPONSE_STANDARD_NAME 3'

command -v buf >/dev/null 2>&1 || {
  echo "::error::buf is required for the proto lint exemption check" >&2
  exit 2
}

# The same rule set as buf.yaml, without its ignore_only entries. --config
# resolves module paths against the working directory, hence the cd.
set +e
findings="$(cd "$module" && buf lint . --error-format=json \
  --config '{"version":"v2","lint":{"use":["STANDARD"]}}')"
status=$?
set -e
if [ "$status" -ne 0 ] && [ "$status" -ne 100 ]; then
  echo "::error::buf lint failed with exit ${status}; refusing to read a tool failure as a finding set" >&2
  exit 2
fi

actual="$(printf '%s\n' "$findings" | python3 -c '
import collections, json, sys
counts = collections.Counter()
for line in sys.stdin:
    if line.strip():
        finding = json.loads(line)
        counts[(finding["path"], finding["type"])] += 1
for (path, rule), n in sorted(counts.items()):
    print(path, rule, n)
')"

if [ "$actual" != "$expected" ]; then
  echo "::error::protocols/proto lint findings differ from the recorded exemptions (< recorded, > actual)" >&2
  diff <(printf '%s\n' "$expected") <(printf '%s\n' "$actual") >&2 || true
  echo "Fix the new finding. If a legacy finding was removed on purpose, update this list and protocols/proto/buf.yaml together." >&2
  exit 1
fi
echo "proto lint exemptions: the 23 recorded legacy findings, nothing else"
