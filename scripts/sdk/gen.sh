#!/usr/bin/env bash
# HELM SDK Type Generator
# Generates typed models from api/openapi/helm.openapi.yaml into each SDK.
# Uses openapi-generator-cli via Docker, pinned by digest for deterministic
# output. Post-generation patches are patch-as-assertion: every patch that is
# expected to apply hard-fails when its anchor is missing, so generator or
# spec drift breaks the build loudly instead of corrupting SDKs silently.
set -euo pipefail

# Concatenated SDK model files must not inherit a developer's locale-specific
# glob order; the C locale is bytewise and available on every supported runner.
export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SPEC="$PROJECT_ROOT/api/openapi/helm.openapi.yaml"
# Digest-pinned generator. Override only for controlled upgrades:
#   HELM_OPENAPI_GENERATOR_IMAGE=<image> bash scripts/sdk/gen.sh
GENERATOR_IMAGE="${HELM_OPENAPI_GENERATOR_IMAGE:-openapitools/openapi-generator-cli:v7.4.0@sha256:579832bed49ea6c275ce2fb5f2d515f5b03d2b6243f3c80fa8430e4f5a770e9a}"

fail() {
    echo "❌ $*" >&2
    exit 1
}

if [ ! -f "$SPEC" ]; then
    fail "OpenAPI spec not found: $SPEC"
fi
command -v docker >/dev/null 2>&1 || fail "docker is required to run the pinned generator"
command -v python3 >/dev/null 2>&1 || fail "python3 is required for post-generation patches"
command -v gofmt >/dev/null 2>&1 || fail "gofmt is required for the Go SDK output"
if [ -n "${HELM_OPENAPI_GENERATOR_IMAGE:-}" ]; then
    echo "⚠️  generator image overridden via HELM_OPENAPI_GENERATOR_IMAGE: $GENERATOR_IMAGE"
fi

echo "HELM SDK Generator"
echo "══════════════════"
echo "Spec: $SPEC"
echo "Generator: $GENERATOR_IMAGE"
echo ""

# ── TypeScript ────────────────────────────────────────
echo "  [ts] Generating types..."
TEMP_TS=$(mktemp -d)
docker run --rm --user "$(id -u):$(id -g)" -v "$PROJECT_ROOT:/work" -w /work "$GENERATOR_IMAGE" generate \
    -i /work/api/openapi/helm.openapi.yaml \
    -g typescript-fetch \
    -o /work/.gen_tmp/ts \
    --additional-properties=supportsES6=true,typescriptThreePlus=true,modelPropertyNaming=original \
    --global-property=models 2>/dev/null

# Extract only the model types
[ -d "$PROJECT_ROOT/.gen_tmp/ts/models" ] || fail "[ts] generator produced no models directory — refusing to keep stale output"
cat > "$PROJECT_ROOT/sdk/ts/src/types.gen.ts" <<'HEADER'
// AUTO-GENERATED from api/openapi/helm.openapi.yaml — DO NOT EDIT
// Regenerate: bash scripts/sdk/gen.sh

HEADER
TS_MODEL_COUNT=0
for f in "$PROJECT_ROOT/.gen_tmp/ts/models/"*.ts; do
    if [ -f "$f" ]; then
        cat "$f" >> "$PROJECT_ROOT/sdk/ts/src/types.gen.ts"
        TS_MODEL_COUNT=$((TS_MODEL_COUNT + 1))
    fi
done
[ "$TS_MODEL_COUNT" -gt 0 ] || fail "[ts] generator produced zero model files"
python3 - "$PROJECT_ROOT/sdk/ts/src/types.gen.ts" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
lines = path.read_text().splitlines()
out = []
skip_import = False
for line in lines:
    stripped = line.strip()
    if skip_import:
        if stripped.endswith(";"):
            skip_import = False
        continue
    if stripped.startswith("import "):
        if not stripped.endswith(";"):
            skip_import = True
        continue
    out.append(line)

s = "\n".join(out) + "\n"
helpers = """const mapValues = <T, R>(data: { [key: string]: T }, fn: (item: T) => R): { [key: string]: R } =>
    Object.keys(data).reduce((acc, key) => ({ ...acc, [key]: fn(data[key]) }), {} as { [key: string]: R });

const stringFromJSONTyped = (json: any, _ignoreDiscriminator: boolean): string => json;
const stringToJSON = (value: string): any => value;
const instanceOfstring = (value: any): value is string => typeof value === 'string';
const numberFromJSONTyped = (json: any, _ignoreDiscriminator: boolean): number => json;
const numberToJSON = (value: number): any => value;
const instanceOfnumber = (value: any): value is number => typeof value === 'number';

"""
marker = "// Regenerate: bash scripts/sdk/gen.sh\n\n"
if marker not in s:
    raise SystemExit("ts patch failed: header marker missing; generated header changed unexpectedly")
s = s.replace(marker, marker + helpers, 1)

def replace_one(s: str, signature: str, body: str) -> str:
    # Patch-as-assertion: a missing anchor means the generator output changed
    # underneath us; fail loudly instead of shipping an unpatched SDK.
    start = s.find(signature)
    if start == -1:
        raise SystemExit(f"ts patch did not apply: signature not found: {signature[:90]}")
    brace = s.find("{", start)
    depth = 0
    end = brace
    while end < len(s):
        ch = s[end]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end += 1
                break
        end += 1
    return s[:start] + body + s[end:]

for name in ("MCPJSONRPCRequestId", "MCPJSONRPCResponseId", "MCPToolCallResponseResult"):
    s = replace_one(
        s,
        f"export function {name}FromJSONTyped(json: any, ignoreDiscriminator: boolean): {name}",
        f"export function {name}FromJSONTyped(json: any, ignoreDiscriminator: boolean): {name} {{\n"
        "    if (json == null) {\n"
        "        return json;\n"
        "    }\n"
        "    return json;\n"
        "}",
    )
    s = replace_one(
        s,
        f"export function {name}ToJSON(value?: {name} | null): any",
        f"export function {name}ToJSON(value?: {name} | null): any {{\n"
        "    if (value == null) {\n"
        "        return value;\n"
        "    }\n\n"
        "    return value;\n"
        "}",
    )

s = replace_one(
    s,
    "export function SandboxGrantInspectionFromJSONTyped(json: any, ignoreDiscriminator: boolean): SandboxGrantInspection",
    "export function SandboxGrantInspectionFromJSONTyped(json: any, ignoreDiscriminator: boolean): SandboxGrantInspection {\n"
    "    if (json == null) {\n"
    "        return json;\n"
    "    }\n"
    "    if (Array.isArray(json)) {\n"
    "        return json.map((item) => SandboxBackendProfileFromJSONTyped(item, true));\n"
    "    }\n"
    "    return SandboxGrantFromJSONTyped(json, true);\n"
    "}",
)
s = replace_one(
    s,
    "export function SandboxGrantInspectionToJSON(value?: SandboxGrantInspection | null): any",
    "export function SandboxGrantInspectionToJSON(value?: SandboxGrantInspection | null): any {\n"
    "    if (value == null) {\n"
    "        return value;\n"
    "    }\n"
    "    if (Array.isArray(value)) {\n"
    "        return value.map((item) => SandboxBackendProfileToJSON(item));\n"
    "    }\n"
    "    return SandboxGrantToJSON(value as SandboxGrant);\n"
    "}",
)

if "export type ReasonCode = HelmErrorErrorReasonCodeEnum;" not in s:
    if "HelmErrorErrorReasonCodeEnum" not in s:
        raise SystemExit("ts patch failed: HelmErrorErrorReasonCodeEnum missing; cannot add ReasonCode alias")
    s += "\nexport type ReasonCode = HelmErrorErrorReasonCodeEnum;\n"

path.write_text("\n".join(line.rstrip() for line in s.splitlines()).rstrip() + "\n")
PY
echo "  [ts] ✅ sdk/ts/src/types.gen.ts"
python3 "$SCRIPT_DIR/manifest.py" write "$PROJECT_ROOT/sdk/ts" "$GENERATOR_IMAGE" "$SPEC" "src/types.gen.ts"

# ── Python ────────────────────────────────────────────
echo "  [py] Generating types..."
docker run --rm --user "$(id -u):$(id -g)" -v "$PROJECT_ROOT:/work" -w /work "$GENERATOR_IMAGE" generate \
    -i /work/api/openapi/helm.openapi.yaml \
    -g python \
    -o /work/.gen_tmp/python \
    --additional-properties=packageName=helm_sdk,projectName=helm \
    --global-property=models 2>/dev/null

[ -d "$PROJECT_ROOT/.gen_tmp/python/helm_sdk/models" ] || fail "[py] generator produced no models directory — refusing to keep stale output"
cat > "$PROJECT_ROOT/sdk/python/helm_sdk/types_gen.py" <<'HEADER'
# AUTO-GENERATED from api/openapi/helm.openapi.yaml — DO NOT EDIT
# Regenerate: bash scripts/sdk/gen.sh

from __future__ import annotations
import json
import pprint
import re
from datetime import datetime
from typing import Annotated, Any, ClassVar, Dict, List, Literal, Optional, Set, Union

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictFloat, StrictInt, StrictStr, ValidationError, field_validator
HEADER
PY_MODEL_COUNT=0
for f in "$PROJECT_ROOT/.gen_tmp/python/helm_sdk/models/"*.py; do
    if [ -f "$f" ]; then
        grep -v "^from\|^import\|^#" "$f" >> "$PROJECT_ROOT/sdk/python/helm_sdk/types_gen.py" 2>/dev/null || true
        PY_MODEL_COUNT=$((PY_MODEL_COUNT + 1))
    fi
done
[ "$PY_MODEL_COUNT" -gt 0 ] || fail "[py] generator produced zero model files"
python3 - "$PROJECT_ROOT/sdk/python/helm_sdk/types_gen.py" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
s = path.read_text()

# Patch-as-assertion: Pydantic v2 field validators whose generated signature
# receives cls must be explicit classmethods. Keep this structural rather than
# model-specific so a newly generated validator cannot silently miss the fix.
lines = s.splitlines()

def validator_definition_index(lines, decorator_index):
    indent = len(lines[decorator_index]) - len(lines[decorator_index].lstrip())
    for index in range(decorator_index + 1, len(lines)):
        stripped = lines[index].lstrip()
        if re.match(r"^def\s+", stripped):
            return index
        if stripped.startswith("@") or stripped.startswith("#") or not stripped:
            continue
        line_indent = len(lines[index]) - len(stripped)
        if line_indent <= indent:
            return None
    return None

def classmethod_present(lines, decorator_index, definition_index):
    return any(line.lstrip() == "@classmethod" for line in lines[decorator_index + 1:definition_index])

out = []
for i, line in enumerate(lines):
    out.append(line)
    if line.lstrip().startswith("@field_validator("):
        definition_index = validator_definition_index(lines, i)
        if definition_index is not None and re.match(r"^\s*def\s+\w+\(cls(?:,|\))", lines[definition_index]) and not classmethod_present(lines, i, definition_index):
            out.append(f"{line[:len(line) - len(line.lstrip())]}@classmethod")
s = "\n".join(out)

generated_lines = s.splitlines()
missing_classmethods = []
for i, line in enumerate(generated_lines):
    if not line.lstrip().startswith("@field_validator("):
        continue
    definition_index = validator_definition_index(generated_lines, i)
    if definition_index is not None and re.match(r"^\s*def\s+\w+\(cls(?:,|\))", generated_lines[definition_index]) and not classmethod_present(generated_lines, i, definition_index):
        missing_classmethods.append(generated_lines[definition_index].strip().split("(", 1)[0])
if missing_classmethods:
    raise SystemExit(f"py patch did not apply: missing @classmethod for {missing_classmethods}")

receipt_public_key_set = (
    '            "signature_algorithm": obj.get("signature_algorithm"),\n'
    '            "key_id": obj.get("key_id"),\n'
    '            "timestamp": obj.get("timestamp"),'
)
if '"public_key_set": obj.get("public_key_set")' not in s:
    if s.count(receipt_public_key_set) != 1:
        raise SystemExit("py patch did not apply: expected exactly one Receipt from_dict anchor for public_key_set")
    s = s.replace(
        receipt_public_key_set,
        '            "signature_algorithm": obj.get("signature_algorithm"),\n'
        '            "key_id": obj.get("key_id"),\n'
        '            "public_key_set": obj.get("public_key_set"),\n'
        '            "timestamp": obj.get("timestamp"),'
    )

boundary_status_components = (
    '            "quarantined_mcp_count": obj.get("quarantined_mcp_count"),\n'
    '            "updated_at": obj.get("updated_at"),'
)
if s.count(boundary_status_components) != 1:
    raise SystemExit("expected exactly one BoundaryStatus from_dict tail")
s = s.replace(
    boundary_status_components,
    '            "quarantined_mcp_count": obj.get("quarantined_mcp_count"),\n'
    '            "updated_at": obj.get("updated_at"),\n'
    '            "components": obj.get("components"),',
    1,
)

path.write_text("\n".join(line.rstrip() for line in s.splitlines()).rstrip() + "\n")
PY
echo "  [py] ✅ sdk/python/helm_sdk/types_gen.py"
python3 "$SCRIPT_DIR/manifest.py" write "$PROJECT_ROOT/sdk/python" "$GENERATOR_IMAGE" "$SPEC" "helm_sdk/types_gen.py"

# ── Go ────────────────────────────────────────────────
echo "  [go] Generating types..."
docker run --rm --user "$(id -u):$(id -g)" -v "$PROJECT_ROOT:/work" -w /work "$GENERATOR_IMAGE" generate \
    -i /work/api/openapi/helm.openapi.yaml \
    -g go \
    -o /work/.gen_tmp/go \
    --additional-properties=packageName=client \
    --global-property=models 2>/dev/null

[ -d "$PROJECT_ROOT/.gen_tmp/go" ] || fail "[go] generator produced no output directory — refusing to keep stale output"
cat > "$PROJECT_ROOT/sdk/go/client/types_gen.go" <<'HEADER'
// AUTO-GENERATED from api/openapi/helm.openapi.yaml — DO NOT EDIT
// Regenerate: bash scripts/sdk/gen.sh

package client

import (
    "bytes"
    "encoding/json"
    "fmt"
    "time"
)
HEADER
GO_SKIP_MODELS=(
    model_agent_identity_profile.go
    model_approval_ceremony.go
    model_approval_web_authn_assertion.go
    model_approval_web_authn_challenge.go
    model_authz_health.go
    model_authz_snapshot.go
    model_boundary_capability_summary.go
    model_boundary_checkpoint.go
    model_boundary_record_verification.go
    model_boundary_status.go
    model_budget_ceiling.go
    model_coexistence_capability_manifest.go
    model_evidence_envelope_export_request.go
    model_evidence_envelope_manifest.go
    model_evidence_envelope_payload.go
    model_evidence_envelope_verification.go
    model_execution_boundary_record.go
    model_mcp_authorization_profile.go
    model_mcp_authorize_call_request.go
    model_mcp_quarantine_record.go
    model_mcp_registry_approval_request.go
    model_mcp_registry_discover_request.go
    model_mcp_scan_request.go
    model_mcp_scan_result.go
    model_negative_boundary_vector.go
    model_sandbox_backend_profile.go
    model_sandbox_grant.go
    model_sandbox_preflight_request.go
    model_sandbox_preflight_result.go
    model_telemetry_export_request.go
    model_telemetry_export_result.go
    model_telemetry_o_tel_config.go
)
should_skip_go_model() {
    local base="$1"
    for skip in "${GO_SKIP_MODELS[@]}"; do
        if [ "$base" = "$skip" ]; then
            return 0
        fi
    done
    return 1
}
GO_MODEL_COUNT=0
for f in "$PROJECT_ROOT/.gen_tmp/go/model_"*.go; do
    if [ -f "$f" ] && ! should_skip_go_model "$(basename "$f")"; then
        sed '/^package /d;/^import/,/^)/d' "$f" >> "$PROJECT_ROOT/sdk/go/client/types_gen.go" 2>/dev/null || true
        GO_MODEL_COUNT=$((GO_MODEL_COUNT + 1))
    fi
done
[ "$GO_MODEL_COUNT" -gt 0 ] || fail "[go] generator produced zero model files"
python3 - "$PROJECT_ROOT/sdk/go/client/types_gen.go" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
s = path.read_text()
path.write_text("\n".join(line.rstrip() for line in s.splitlines()).rstrip() + "\n")
PY
gofmt -w "$PROJECT_ROOT/sdk/go/client/types_gen.go"
echo "  [go] ✅ sdk/go/client/types_gen.go ($GO_MODEL_COUNT models)"
python3 "$SCRIPT_DIR/manifest.py" write "$PROJECT_ROOT/sdk/go" "$GENERATOR_IMAGE" "$SPEC" "client/types_gen.go"

# ── Rust ──────────────────────────────────────────────
echo "  [rs] Generating types..."
docker run --rm --user "$(id -u):$(id -g)" -v "$PROJECT_ROOT:/work" -w /work "$GENERATOR_IMAGE" generate \
    -i /work/api/openapi/helm.openapi.yaml \
    -g rust \
    -o /work/.gen_tmp/rust \
    --additional-properties=packageName=helm_sdk \
    --global-property=models 2>/dev/null

[ -d "$PROJECT_ROOT/.gen_tmp/rust/src/models" ] || fail "[rs] generator produced no models directory — refusing to keep stale output"
cat > "$PROJECT_ROOT/sdk/rust/src/types_gen.rs" <<'HEADER'
// AUTO-GENERATED from api/openapi/helm.openapi.yaml — DO NOT EDIT
// Regenerate: bash scripts/sdk/gen.sh

use serde::{Deserialize, Serialize};
HEADER
python3 - "$PROJECT_ROOT/sdk/rust/src/types_gen.rs" "$PROJECT_ROOT/.gen_tmp/rust/src/models" <<'PY'
from pathlib import Path
import re
import sys

out_path = Path(sys.argv[1])
models_dir = Path(sys.argv[2])

def render(path: Path) -> tuple[str, str]:
    s = "\n".join(
        line
        for line in path.read_text().splitlines()
        if not (line.startswith("use ") or line.startswith("pub mod") or line.startswith("mod "))
    )
    struct_match = re.search(r"\bpub struct ([A-Za-z0-9_]+)\b", s)
    if struct_match:
        struct_name = struct_match.group(1)
        enum_names = list(dict.fromkeys(re.findall(r"\bpub enum ([A-Za-z0-9_]+)\b", s)))
        for enum_name in enum_names:
            renamed = f"{struct_name}{enum_name}"
            s = re.sub(rf"\b{re.escape(enum_name)}\b", renamed, s)
        return struct_name, s
    symbol_match = re.search(r"\bpub enum ([A-Za-z0-9_]+)\b", s)
    return (symbol_match.group(1) if symbol_match else path.stem), s

snippets = [render(path) for path in models_dir.glob("*.rs")]
if not snippets:
    raise SystemExit("rs generation failed: generator produced zero model files")
with out_path.open("a", encoding="utf-8") as out:
    for _, s in sorted(snippets, key=lambda item: item[0]):
        out.write(s)
        out.write("\n")
PY
python3 - "$PROJECT_ROOT/sdk/rust/src/types_gen.rs" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
s = path.read_text()

# Cosmetic normalizations (safe no-ops when the generator changes shape).
s = s.replace("/// \n", "///\n")
s = s.replace("models::", "")
s = s.replace(', with = "::serde_with::rust::double_option"', "")

# Patch-as-assertion postconditions: the per-struct enum rename in render()
# must leave no bare colliding enum names behind. If a future spec or
# generator version reintroduces `Type` / `Verdict` / `Jsonrpc` collisions,
# fail here instead of emitting uncompilable Rust.
for collision in ("pub enum Type {", "pub enum Verdict {", "pub enum Jsonrpc {"):
    if collision in s:
        raise SystemExit(f"rs postcondition failed: bare {collision!r} survived rendering")

if "pub type ReasonCode = HelmErrorErrorReasonCode;" not in s:
    if "pub enum HelmErrorErrorReasonCode" not in s:
        raise SystemExit("rs patch failed: HelmErrorErrorReasonCode missing; cannot add ReasonCode alias")
    s += "\npub type ReasonCode = HelmErrorErrorReasonCode;\n"

path.write_text("\n".join(line.rstrip() for line in s.splitlines()).rstrip() + "\n")
PY
echo "  [rs] ✅ sdk/rust/src/types_gen.rs"
python3 "$SCRIPT_DIR/manifest.py" write "$PROJECT_ROOT/sdk/rust" "$GENERATOR_IMAGE" "$SPEC" "src/types_gen.rs"

# ── Java ──────────────────────────────────────────────
echo "  [java] Generating types..."
docker run --rm --user "$(id -u):$(id -g)" -v "$PROJECT_ROOT:/work" -w /work "$GENERATOR_IMAGE" generate \
    -i /work/api/openapi/helm.openapi.yaml \
    -g java \
    -o /work/.gen_tmp/java \
    --additional-properties=artifactId=helm,groupId=io.github.mindburnlabs,invokerPackage=labs.mindburn.helm,modelPackage=labs.mindburn.helm.models,library=native \
    --global-property=models 2>/dev/null

JAVA_OUT="$PROJECT_ROOT/sdk/java/src/main/java/labs/mindburn/helm"
[ -d "$PROJECT_ROOT/.gen_tmp/java/src/main/java" ] || fail "[java] generator produced no output directory — refusing to keep stale output"
shopt -s nullglob
mkdir -p "$JAVA_OUT"
JAVA_MODELS=("$PROJECT_ROOT/.gen_tmp/java/src/main/java/labs/mindburn/helm/models/"*.java)
[ "${#JAVA_MODELS[@]}" -gt 0 ] || fail "[java] generator produced zero model files"
cat > "$JAVA_OUT/TypesGen.java" <<'HEADER'
// AUTO-GENERATED from api/openapi/helm.openapi.yaml — DO NOT EDIT
// Regenerate: bash scripts/sdk/gen.sh

package labs.mindburn.helm;

import java.io.IOException;
import java.util.*;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.util.logging.Level;
import java.util.logging.Logger;
import com.fasterxml.jackson.annotation.*;
import com.fasterxml.jackson.core.*;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.annotation.*;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import org.openapitools.jackson.nullable.JsonNullable;

/**
 * Combined HELM SDK Models.
 * Silenced for internal warnings as this is generated code.
 */
@SuppressWarnings("all")
public interface TypesGen {

// Minimal AbstractOpenApiSchema base class for oneOf/anyOf union types.
// Normally provided by the OpenAPI Generator runtime library.
abstract class AbstractOpenApiSchema {
    private Object instance;
    private String schemaType;
    private Boolean nullable;
    public AbstractOpenApiSchema() {}
    public AbstractOpenApiSchema(String schemaType, Boolean nullable) {
        this.schemaType = schemaType;
        this.nullable = nullable;
    }
    public Object getActualInstance() { return instance; }
    public void setActualInstance(Object instance) { this.instance = instance; }
    public String getSchemaType() { return schemaType; }
    public void setSchemaType(String schemaType) { this.schemaType = schemaType; }
    public Boolean isNullable() { return nullable != null ? nullable : false; }
    public Map<String, Class<?>> getSchemas() { return Collections.emptyMap(); }
}

// Minimal JSON utility for OpenAPI Generator runtime.
static class JSON {
    private static final Map<Class<?>, Map<String, Class<?>>> descendants = new HashMap<>();
    public static void registerDescendants(Class<?> parent, Map<String, Class<?>> map) {
        descendants.put(parent, map);
    }
    public static boolean isInstanceOf(Class<?> clazz, Object instance, Set<Class<?>> visited) {
        return clazz.isInstance(instance);
    }
    public static ObjectMapper getDefault() { return new ObjectMapper(); }
}

HEADER
# Extract class bodies from generated models
for f in "${JAVA_MODELS[@]}"; do
    sed '/^package /d;/^import/d' "$f" >> "$JAVA_OUT/TypesGen.java" 2>/dev/null || true
done
python3 - "$JAVA_OUT/TypesGen.java" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
s = path.read_text()

def must_replace(text: str, old: str, new: str, label: str, min_count: int = 1) -> str:
    # Patch-as-assertion: every rewrite below is required for TypesGen.java to
    # compile as a single combined interface. A missing anchor means the
    # generator output changed; fail loudly instead of shipping a broken SDK.
    count = text.count(old)
    if count < min_count:
        raise SystemExit(
            f"java patch did not apply ({label}): expected at least {min_count} occurrence(s), found {count}"
        )
    return text.replace(old, new)

s, generated_count = re.subn(
    r'@javax\.annotation\.Generated\(value = "org\.openapitools\.codegen\.languages\.JavaClientCodegen", date = "[^"]+", comments = "Generator version: ([^"]+)"\)',
    r'@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen", comments = "Generator version: \1")',
    s,
)
if generated_count == 0:
    raise SystemExit("java patch did not apply (strip @Generated date): no annotations matched")
s = must_replace(s, "public class ", "public static class ", "nest model classes")
s = must_replace(s, "Map<String, Object>.class", "Map.class", "erase Map class literal")
s = must_replace(s, "List<SandboxBackendProfile>.class", "List.class", "erase List class literal")
s = must_replace(s, "getActualInstance() instanceof List<SandboxBackendProfile>", "getActualInstance() instanceof List", "erase instanceof check")
s = must_replace(s, "((SandboxBackendProfile)getActualInstance()).get(i)", "((List<SandboxBackendProfile>)getActualInstance()).get(i)", "cast list element access")
s = must_replace(s, "getMap<String, Object>()", "getMap()", "rename map accessor call site")
s = must_replace(s, "getList<SandboxBackendProfile>()", "getSandboxBackendProfiles()", "rename list accessor call site")
s = must_replace(s, "public List<SandboxBackendProfile> getSandboxBackendProfiles() throws ClassCastException", "@SuppressWarnings(\"unchecked\")\n    public List<SandboxBackendProfile> getSandboxBackendProfiles() throws ClassCastException", "suppress unchecked list accessor")
s = must_replace(s, "public Map<String, Object> getMap() throws ClassCastException", "public Map<String, Object> getMapStringObject() throws ClassCastException", "rename map accessor declaration")
s = must_replace(
    s,
    "if (getActualInstance() instanceof Map<String, Object>) {\n        if (getActualInstance() != null) {",
    "@SuppressWarnings(\"unchecked\")\n    Map<String, Object> _mapInstance = (getActualInstance() instanceof Map) ? (Map<String, Object>) getActualInstance() : null;\n    if (_mapInstance != null) {\n        if (getActualInstance() != null) {",
    "erase union map branch",
)
s = must_replace(s, "getActualInstance().get(_key),", "((Map<String, Object>)getActualInstance()).get(_key),", "cast map key access")
s = must_replace(
    s,
    "// TODO: there is no validation against JSON schema constraints",
    "// Union matching here does not enforce full JSON schema constraints.",
    "rewrite union validation note",
)

# openapi-generator emits map query values twice: a raw value that has no
# matching format placeholder, followed by the URL-encoded value that should
# fill the final placeholder. Remove the raw argument for every generated map
# field so the query string is encoded and String.format receives four values
# for four placeholders. Map keys are strings, so their deepObject placeholder
# must also be %s rather than the list-index %d form.
lines = s.splitlines()
patched_lines = []
map_value_patches = 0
for line in lines:
    raw_prefix, separator, encoded = line.partition(", URLEncoder.encode(String.valueOf(")
    candidate = raw_prefix.strip()
    if (
        separator
        and candidate.endswith(".get(_key)")
        and encoded.startswith(candidate + "), StandardCharsets.UTF_8)")
    ):
        indent = raw_prefix[: len(raw_prefix) - len(candidate)]
        line = indent + "URLEncoder.encode(String.valueOf(" + encoded
        map_value_patches += 1
    patched_lines.append(line)
s = "\n".join(patched_lines)
if map_value_patches == 0:
    raise SystemExit("java patch did not apply (encode map query values): no raw map values matched")
if any(".get(_key), URLEncoder.encode(String.valueOf(" in line for line in patched_lines):
    raise SystemExit("java postcondition failed: raw map query value survived encoding patch")

map_key_format = 'String.format("%s%d%s", containerPrefix, _key, containerSuffix)'
map_key_format_count = s.count(map_key_format)
if map_key_format_count == 0:
    raise SystemExit("java patch did not apply (string map deepObject key): no map key placeholders matched")
s = s.replace(
    map_key_format,
    'String.format("%s%s%s", containerPrefix, _key, containerSuffix)',
)

# Scalar-only query serializers inherit list/map container locals from the
# generator. Remove them only when they are demonstrably unused in that method;
# collection serializers retain the declarations and assignments they need.
method_marker = "  public String toUrlQueryString(String prefix) {"
cursor = 0
chunks = []
unused_container_methods = 0
while True:
    start = s.find(method_marker, cursor)
    if start == -1:
        chunks.append(s[cursor:])
        break
    chunks.append(s[cursor:start])
    opening_brace = s.find("{", start)
    depth = 0
    end = opening_brace
    while end < len(s):
        if s[end] == "{":
            depth += 1
        elif s[end] == "}":
            depth -= 1
            if depth == 0:
                end += 1
                break
        end += 1
    if depth != 0:
        raise SystemExit("java patch failed (find query serializer boundary): unmatched braces")
    method = s[start:end]
    if method.count("containerSuffix") == 2 and method.count("containerPrefix") == 2:
        for declaration in (
            '    String containerSuffix = "";\n',
            '    String containerPrefix = "";\n',
            '      containerSuffix = "]";\n',
            '      containerPrefix = "[";\n',
        ):
            method = method.replace(declaration, "")
        unused_container_methods += 1
    chunks.append(method)
    cursor = end
s = "".join(chunks)
if unused_container_methods == 0:
    raise SystemExit("java patch did not apply (remove unused query container locals): no scalar serializers matched")
s = s + "\n}\n"
path.write_text("\n".join(line.rstrip() for line in s.splitlines()).rstrip() + "\n")
PY
shopt -u nullglob
echo "  [java] ✅ sdk/java/src/.../TypesGen.java (${#JAVA_MODELS[@]} models)"
python3 "$SCRIPT_DIR/manifest.py" write "$PROJECT_ROOT/sdk/java" "$GENERATOR_IMAGE" "$SPEC" "src/main/java/labs/mindburn/helm/TypesGen.java"

# ── Cleanup ───────────────────────────────────────────
rm -rf "$PROJECT_ROOT/.gen_tmp"

echo ""
echo "══════════════════"
echo "✅ All SDK types generated from OpenAPI spec"
