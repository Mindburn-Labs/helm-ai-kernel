#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TRUTH="$ROOT/docs/specs/RELEASE_CHANNEL_TRUTH.md"
WORKFLOW="$ROOT/.github/workflows/release.yml"
ORCH_DOC="$ROOT/docs/INTEGRATIONS/ORCHESTRATORS.md"
INDEX_DOC="$ROOT/docs/index.md"
PUBLISHING_DOC="$ROOT/docs/PUBLISHING.md"

require_pattern() {
  local pattern="$1"
  local file="$2"
  if ! grep -qF "$pattern" "$file"; then
    echo "FAIL: expected pattern not found in $file"
    echo "  pattern: $pattern"
    exit 1
  fi
}

reject_pattern() {
  local pattern="$1"
  local file="$2"
  if grep -qF "$pattern" "$file"; then
    echo "FAIL: forbidden pattern found in $file"
    echo "  pattern: $pattern"
    exit 1
  fi
}

require_pattern '| PyPI | `helm` | `ACTIVE` | Yes |' "$TRUTH"
require_pattern '| crates.io | `helm` | `ACTIVE` | Yes |' "$TRUTH"
require_pattern '| Maven Central | `ai.mindburn.helm:helm` | `ACTIVE` | Yes |' "$TRUTH"
require_pattern '| npm | `@mindburn/helm-openai-agents` | `ACTIVE` | Yes |' "$TRUTH"
require_pattern '| npm | `@mindburn/helm-mastra` | `ACTIVE` | Yes |' "$TRUTH"
require_pattern '| npm | `@mindburn/helm-autogen` | `ACTIVE` | Yes |' "$TRUTH"
require_pattern '| npm | `@mindburn/helm-semantic-kernel` | `ACTIVE` | Yes |' "$TRUTH"
require_pattern '| NuGet | `.NET SDK package` | `BLOCKED` | No |' "$TRUTH"

require_pattern 'publish-pypi:' "$WORKFLOW"
require_pattern 'publish-crates:' "$WORKFLOW"
require_pattern 'publish-maven:' "$WORKFLOW"
require_pattern 'cd sdk/ts/openai-agents' "$WORKFLOW"
require_pattern 'cd sdk/ts/mastra' "$WORKFLOW"
require_pattern 'cd sdk/ts/autogen' "$WORKFLOW"
require_pattern 'cd sdk/ts/semantic-kernel' "$WORKFLOW"

require_pattern 'pip install helm' "$ORCH_DOC"
require_pattern 'npm install @mindburn/helm-openai-agents' "$ORCH_DOC"
reject_pattern 'currently ships from source' "$ORCH_DOC"

require_pattern 'pip install helm' "$INDEX_DOC"
require_pattern 'cargo add helm' "$INDEX_DOC"
require_pattern 'ai.mindburn.helm:helm' "$INDEX_DOC"

require_pattern 'RELEASE_CHANNEL_TRUTH.md' "$PUBLISHING_DOC"
require_pattern 'scripts/ci/release_truth_check.sh' "$PUBLISHING_DOC"

echo "release truth check: OK"
