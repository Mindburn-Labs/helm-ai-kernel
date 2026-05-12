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
    python3 - "$PROJECT_ROOT/sdk/ts/src/types.gen.ts" <<'PY'
from pathlib import Path
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
s = s.replace(marker, marker + helpers, 1)

def replace_one(s: str, signature: str, body: str) -> str:
    start = s.find(signature)
    if start == -1:
        return s
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
    s += "\nexport type ReasonCode = HelmErrorErrorReasonCodeEnum;\n"

path.write_text("\n".join(line.rstrip() for line in s.splitlines()).rstrip() + "\n")
PY
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
import json
import pprint
from datetime import datetime
from typing import Any, ClassVar, Dict, List, Literal, Optional, Set, Union

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictFloat, StrictInt, StrictStr, ValidationError, field_validator
HEADER
    for f in "$PROJECT_ROOT/.gen_tmp/python/helm_sdk/models/"*.py; do
        [ -f "$f" ] && grep -v "^from\|^import\|^#" "$f" >> "$PROJECT_ROOT/sdk/python/helm_sdk/types_gen.py" 2>/dev/null || true
    done
    python3 - "$PROJECT_ROOT/sdk/python/helm_sdk/types_gen.py" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
s = path.read_text()
path.write_text("\n".join(line.rstrip() for line in s.splitlines()).rstrip() + "\n")
PY
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
    for f in "$PROJECT_ROOT/.gen_tmp/go/model_"*.go; do
        if [ -f "$f" ] && ! should_skip_go_model "$(basename "$f")"; then
            sed '/^package /d;/^import/,/^)/d' "$f" >> "$PROJECT_ROOT/sdk/go/client/types_gen.go" 2>/dev/null || true
        fi
    done
    python3 - "$PROJECT_ROOT/sdk/go/client/types_gen.go" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
s = path.read_text()
path.write_text("\n".join(line.rstrip() for line in s.splitlines()).rstrip() + "\n")
PY
    gofmt -w "$PROJECT_ROOT/sdk/go/client/types_gen.go"
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
        [ -f "$f" ] && python3 - "$f" >> "$PROJECT_ROOT/sdk/rust/src/types_gen.rs" <<'PY' || true
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
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
print(s)
PY
    done
    python3 - "$PROJECT_ROOT/sdk/rust/src/types_gen.rs" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
s = path.read_text()
s = s.replace("/// \n", "///\n")
s = s.replace("models::", "")
s = s.replace(', with = "::serde_with::rust::double_option"', "")

s = s.replace("pub r#type: Type,", "pub r#type: ErrorType,")
s = s.replace(
    "pub fn new(message: String, r#type: Type, code: String, reason_code: ReasonCode) -> HelmErrorError",
    "pub fn new(message: String, r#type: ErrorType, code: String, reason_code: ReasonCode) -> HelmErrorError",
)
s = re.sub(
    r'pub enum Type \{\n    #\[serde\(rename = "invalid_request"\)\]\n    InvalidRequest,\n    #\[serde\(rename = "authentication_error"\)\]\n    AuthenticationError,\n    #\[serde\(rename = "permission_denied"\)\]\n    PermissionDenied,\n    #\[serde\(rename = "not_found"\)\]\n    NotFound,\n    #\[serde\(rename = "internal_error"\)\]\n    InternalError,\n\}\n\nimpl Default for Type \{\n    fn default\(\) -> Type \{\n        Self::InvalidRequest\n    \}\n\}',
    'pub enum ErrorType {\n    #[serde(rename = "invalid_request")]\n    InvalidRequest,\n    #[serde(rename = "authentication_error")]\n    AuthenticationError,\n    #[serde(rename = "permission_denied")]\n    PermissionDenied,\n    #[serde(rename = "not_found")]\n    NotFound,\n    #[serde(rename = "internal_error")]\n    InternalError,\n}\n\nimpl Default for ErrorType {\n    fn default() -> ErrorType {\n        Self::InvalidRequest\n    }\n}',
    s,
    count=1,
)

s = s.replace("pub verdict: Verdict,\n    /// Null for ALLOW.", "pub verdict: GovernanceVerdict,\n    /// Null for ALLOW.")
s = s.replace(
    "pub fn new(decision_id: String, effect_id: String, verdict: Verdict) -> GovernanceDecision",
    "pub fn new(decision_id: String, effect_id: String, verdict: GovernanceVerdict) -> GovernanceDecision",
)
s = re.sub(
    r'pub enum Verdict \{\n    #\[serde\(rename = "ALLOW"\)\]\n    Allow,\n    #\[serde\(rename = "DENY"\)\]\n    Deny,\n    #\[serde\(rename = "ESCALATE"\)\]\n    Escalate,\n\}\n\nimpl Default for Verdict \{\n    fn default\(\) -> Verdict \{\n        Self::Allow\n    \}\n\}',
    'pub enum GovernanceVerdict {\n    #[serde(rename = "ALLOW")]\n    Allow,\n    #[serde(rename = "DENY")]\n    Deny,\n    #[serde(rename = "ESCALATE")]\n    Escalate,\n}\n\nimpl Default for GovernanceVerdict {\n    fn default() -> GovernanceVerdict {\n        Self::Allow\n    }\n}',
    s,
    count=1,
)

jsonrpc_block = '''///
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub enum Jsonrpc {
    #[serde(rename = "2.0")]
    Variant2Period0,
}

impl Default for Jsonrpc {
    fn default() -> Jsonrpc {
        Self::Variant2Period0
    }
}
'''
pos = s.find("pub struct McpjsonrpcResponse")
if pos != -1:
    dup = s.find(jsonrpc_block, pos)
    if dup != -1:
        s = s[:dup] + "// Duplicate Jsonrpc enum removed (canonical def above)\n" + s[dup + len(jsonrpc_block):]

verdict_block = '''///
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub enum Verdict {
    #[serde(rename = "PASS")]
    Pass,
    #[serde(rename = "FAIL")]
    Fail,
}

impl Default for Verdict {
    fn default() -> Verdict {
        Self::Pass
    }
}
'''
pos = s.find("pub struct VerificationResult")
if pos != -1:
    dup = s.find(verdict_block, pos)
    if dup != -1:
        s = s[:dup] + "// Duplicate Verdict enum removed (canonical def above)\n" + s[dup + len(verdict_block):]

if "pub type ReasonCode = HelmErrorErrorReasonCode;" not in s and "pub enum HelmErrorErrorReasonCode" in s:
    s += "\npub type ReasonCode = HelmErrorErrorReasonCode;\n"

path.write_text("\n".join(line.rstrip() for line in s.splitlines()).rstrip() + "\n")
PY
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

import java.io.IOException;
import java.util.*;
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
    for f in "$PROJECT_ROOT/.gen_tmp/java/src/main/java/labs/mindburn/helm/models/"*.java; do
        [ -f "$f" ] && sed '/^package /d;/^import/d' "$f" >> "$JAVA_OUT/TypesGen.java" 2>/dev/null || true
    done
python3 - "$JAVA_OUT/TypesGen.java" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
s = path.read_text()
s = re.sub(
    r'@javax\.annotation\.Generated\(value = "org\.openapitools\.codegen\.languages\.JavaClientCodegen", date = "[^"]+", comments = "Generator version: ([^"]+)"\)',
    r'@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen", comments = "Generator version: \1")',
    s,
)
s = s.replace("public class ", "public static class ")
s = s.replace("Map<String, Object>.class", "Map.class")
s = s.replace("List<SandboxBackendProfile>.class", "List.class")
s = s.replace("getActualInstance() instanceof List<SandboxBackendProfile>", "getActualInstance() instanceof List")
s = s.replace("((SandboxBackendProfile)getActualInstance()).get(i)", "((List<SandboxBackendProfile>)getActualInstance()).get(i)")
s = s.replace("getMap<String, Object>()", "getMap()")
s = s.replace("getList<SandboxBackendProfile>()", "getSandboxBackendProfiles()")
s = s.replace("public List<SandboxBackendProfile> getSandboxBackendProfiles() throws ClassCastException", "@SuppressWarnings(\"unchecked\")\n    public List<SandboxBackendProfile> getSandboxBackendProfiles() throws ClassCastException")
s = s.replace("public Map<String, Object> getMap() throws ClassCastException", "public Map<String, Object> getMapStringObject() throws ClassCastException")
s = s.replace(
    "if (getActualInstance() instanceof Map<String, Object>) {\n        if (getActualInstance() != null) {",
    "@SuppressWarnings(\"unchecked\")\n    Map<String, Object> _mapInstance = (getActualInstance() instanceof Map) ? (Map<String, Object>) getActualInstance() : null;\n    if (_mapInstance != null) {\n        if (getActualInstance() != null) {",
)
s = s.replace("getActualInstance().get(_key),", "((Map<String, Object>)getActualInstance()).get(_key),")
s = s.replace(
    "// TODO: there is no validation against JSON schema constraints",
    "// Union matching here does not enforce full JSON schema constraints.",
)
s = s + "\n}\n"
path.write_text("\n".join(line.rstrip() for line in s.splitlines()).rstrip() + "\n")
PY
    shopt -u nullglob
fi
echo "  [java] ✅ sdk/java/src/.../TypesGen.java"

# ── Cleanup ───────────────────────────────────────────
rm -rf "$PROJECT_ROOT/.gen_tmp"

echo ""
echo "══════════════════"
echo "✅ All SDK types generated from OpenAPI spec"
