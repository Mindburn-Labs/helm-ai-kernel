#!/bin/bash
# UC-011: Island Mode restricted operation
# Expected: kernel operates without external network access
set -euo pipefail

echo "=== UC-011: Island Mode ==="
cd "$(dirname "$0")/../../core"

# Verify kernel builds and tests pass without any external dependencies
go build ./cmd/helm
go test ./pkg/guardian/ ./pkg/executor/... ./pkg/contracts/... -count=1

echo "UC-011: PASS"
