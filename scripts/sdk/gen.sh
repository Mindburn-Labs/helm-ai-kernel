#!/usr/bin/env bash
# HELM SDK Type Generator
# Generates typed models from api/openapi/helm.openapi.yaml into each SDK.
# Uses openapi-generator-cli via Docker (pinned version).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SPEC="$PROJECT_ROOT/api/openapi/helm.openapi.yaml"
GENERATOR_IMAGE="openapitools/openapi-generator-cli:v7.4.0"

if [ ! -f "$SPEC" ]; then
    echo "❌ OpenAPI spec not found: $SPEC"
    exit 1
fi

echo "HELM SDK Generator"
echo "══════════════════"
echo "Spec: $SPEC"
echo "Generator: $GENERATOR_IMAGE"
echo ""

# ── TypeScript ────────────────────────────────────────
echo "  [ts] Generating types..."
TEMP_TS=$(mktemp -d)
docker run --rm -v "$PROJECT_ROOT:/work" -w /work "$GENERATOR_IMAGE" generate \
    -i /work/api/openapi/helm.openapi.yaml \
    -g typescript-fetch \
    -o /work/.gen_tmp/ts \
    --additional-properties=supportsES6=true,typescriptThreePlus=true,modelPropertyNaming=original \
    --global-property=models 2>/dev/null

# Extract only the model types
if [ -d "$PROJECT_ROOT/.gen_tmp/ts/models" ]; then
    cat > "$PROJECT_ROOT/sdk/ts/src/types.gen.ts" <<'HEADER'
// AUTO-GENERATED from api/openapi/helm.openapi.yaml — DO NOT EDIT
// Regenerate: bash scripts/sdk/gen.sh

HEADER
    for f in "$PROJECT_ROOT/.gen_tmp/ts/models/"*.ts; do
        [ -f "$f" ] && cat "$f" >> "$PROJECT_ROOT/sdk/ts/src/types.gen.ts"
    done
fi
echo "  [ts] ✅ sdk/ts/src/types.gen.ts"

# ── Python ────────────────────────────────────────────
echo "  [py] Generating types..."
docker run --rm -v "$PROJECT_ROOT:/work" -w /work "$GENERATOR_IMAGE" generate \
    -i /work/api/openapi/helm.openapi.yaml \
    -g python \
    -o /work/.gen_tmp/python \
    --additional-properties=packageName=helm_sdk,projectName=helm \
    --global-property=models 2>/dev/null

if [ -d "$PROJECT_ROOT/.gen_tmp/python/helm_sdk/models" ]; then
    cat > "$PROJECT_ROOT/sdk/python/helm_sdk/types_gen.py" <<'HEADER'
# AUTO-GENERATED from api/openapi/helm.openapi.yaml — DO NOT EDIT
# Regenerate: bash scripts/sdk/gen.sh

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Optional
HEADER
    for f in "$PROJECT_ROOT/.gen_tmp/python/helm_sdk/models/"*.py; do
        [ -f "$f" ] && grep -v "^from\|^import\|^#" "$f" >> "$PROJECT_ROOT/sdk/python/helm_sdk/types_gen.py" 2>/dev/null || true
    done
fi
echo "  [py] ✅ sdk/python/helm_sdk/types_gen.py"

# ── Go ────────────────────────────────────────────────
echo "  [go] Generating types..."
docker run --rm -v "$PROJECT_ROOT:/work" -w /work "$GENERATOR_IMAGE" generate \
    -i /work/api/openapi/helm.openapi.yaml \
    -g go \
    -o /work/.gen_tmp/go \
    --additional-properties=packageName=client \
    --global-property=models 2>/dev/null

if [ -d "$PROJECT_ROOT/.gen_tmp/go" ]; then
    cat > "$PROJECT_ROOT/sdk/go/client/types_gen.go" <<'HEADER'
// AUTO-GENERATED from api/openapi/helm.openapi.yaml — DO NOT EDIT
// Regenerate: bash scripts/sdk/gen.sh

package client
HEADER
    for f in "$PROJECT_ROOT/.gen_tmp/go/model_"*.go; do
        [ -f "$f" ] && sed '/^package /d;/^import/,/^)/d' "$f" >> "$PROJECT_ROOT/sdk/go/client/types_gen.go" 2>/dev/null || true
    done
fi
echo "  [go] ✅ sdk/go/client/types_gen.go"

# ── Rust ──────────────────────────────────────────────
echo "  [rs] Generating types..."
docker run --rm -v "$PROJECT_ROOT:/work" -w /work "$GENERATOR_IMAGE" generate \
    -i /work/api/openapi/helm.openapi.yaml \
    -g rust \
    -o /work/.gen_tmp/rust \
    --additional-properties=packageName=helm_sdk \
    --global-property=models 2>/dev/null

if [ -d "$PROJECT_ROOT/.gen_tmp/rust/src/models" ]; then
    cat > "$PROJECT_ROOT/sdk/rust/src/types_gen.rs" <<'HEADER'
// AUTO-GENERATED from api/openapi/helm.openapi.yaml — DO NOT EDIT
// Regenerate: bash scripts/sdk/gen.sh

use serde::{Deserialize, Serialize};
HEADER
    for f in "$PROJECT_ROOT/.gen_tmp/rust/src/models/"*.rs; do
        [ -f "$f" ] && grep -v "^use\|^pub mod\|^mod" "$f" >> "$PROJECT_ROOT/sdk/rust/src/types_gen.rs" 2>/dev/null || true
    done
fi
echo "  [rs] ✅ sdk/rust/src/types_gen.rs"

# ── Java ──────────────────────────────────────────────
echo "  [java] Generating types..."
docker run --rm -v "$PROJECT_ROOT:/work" -w /work "$GENERATOR_IMAGE" generate \
    -i /work/api/openapi/helm.openapi.yaml \
    -g java \
    -o /work/.gen_tmp/java \
    --additional-properties=artifactId=helm,groupId=ai.mindburn.helm,invokerPackage=labs.mindburn.helm,modelPackage=labs.mindburn.helm.models,library=native \
    --global-property=models 2>/dev/null

JAVA_OUT="$PROJECT_ROOT/sdk/java/src/main/java/labs/mindburn/helm"
if [ -d "$PROJECT_ROOT/.gen_tmp/java/src/main/java" ]; then
    shopt -s nullglob
    mkdir -p "$JAVA_OUT"
    cat > "$JAVA_OUT/TypesGen.java" <<'HEADER'
// AUTO-GENERATED from api/openapi/helm.openapi.yaml — DO NOT EDIT
// Regenerate: bash scripts/sdk/gen.sh

package labs.mindburn.helm;

import java.util.List;
import java.util.Map;
HEADER
    # Extract class bodies from generated models
    for f in "$PROJECT_ROOT/.gen_tmp/java/src/main/java/labs/mindburn/helm/models/"*.java; do
        [ -f "$f" ] && sed '/^package /d;/^import/d' "$f" >> "$JAVA_OUT/TypesGen.java" 2>/dev/null || true
    done
    shopt -u nullglob
fi
echo "  [java] ✅ sdk/java/src/.../TypesGen.java"

# ── Cleanup ───────────────────────────────────────────
rm -rf "$PROJECT_ROOT/.gen_tmp"

echo ""
echo "══════════════════"
echo "✅ All SDK types generated from OpenAPI spec"
