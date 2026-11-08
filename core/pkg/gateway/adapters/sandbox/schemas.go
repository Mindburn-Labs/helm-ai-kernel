package sandbox

// The argument and result schemas of the three sandbox effects. They are closed
// (additionalProperties false) JSON Schema documents, draft 2020-12; the
// gateway compiles them once (adapters.CompileArgumentSchema and
// CompileResultSchema) and checks every proposal and every observation
// against them. The Go parsers in args.go repeat the bounds, so a drift
// between the two is a test failure (TestArgumentParsersAgreeWithTheSchemas).

const (
	createSchemaID    = "helm.sandbox.create.v1"
	execSchemaID      = "helm.sandbox.exec.v1"
	terminateSchemaID = "helm.sandbox.terminate.v1"

	createResultID    = "helm.sandbox.create.result.v1"
	execResultID      = "helm.sandbox.exec.result.v1"
	terminateResultID = "helm.sandbox.terminate.result.v1"
)

const providerEnum = `["claude-managed-agents","daytona","docker","e2b","opensandbox"]`

const createArgumentSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "helm.sandbox.create.v1",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema", "runtime", "cpu_millis", "memory_mb", "disk_mb", "timeout_seconds", "max_processes", "egress_disabled"],
  "properties": {
    "schema": {"const": "helm.sandbox.create.v1"},
    "runtime": {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$"},
    "cpu_millis": {"type": "integer", "minimum": 100, "maximum": 16000},
    "memory_mb": {"type": "integer", "minimum": 64, "maximum": 65536},
    "disk_mb": {"type": "integer", "minimum": 0, "maximum": 204800},
    "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 86400},
    "max_processes": {"type": "integer", "minimum": 0, "maximum": 32768},
    "egress_disabled": {"type": "boolean"}
  }
}`

const execArgumentSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "helm.sandbox.exec.v1",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema", "command", "workdir", "timeout_seconds"],
  "properties": {
    "schema": {"const": "helm.sandbox.exec.v1"},
    "command": {"type": "array", "minItems": 1, "maxItems": 64, "items": {"type": "string", "minLength": 1, "maxLength": 4096}},
    "workdir": {"type": "string", "maxLength": 512, "pattern": "^(/[A-Za-z0-9._/@+=,: -]*)?$", "not": {"pattern": "[.][.]"}},
    "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 3600}
  }
}`

const terminateArgumentSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "helm.sandbox.terminate.v1",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema"],
  "properties": {
    "schema": {"const": "helm.sandbox.terminate.v1"}
  }
}`

const createResultSchema = `{
  "$id": "helm.sandbox.create.result.v1",
  "type": "object",
  "additionalProperties": false,
  "required": ["provider", "sandbox_id", "state", "runtime"],
  "properties": {
    "provider": {"enum": ` + providerEnum + `},
    "sandbox_id": {"type": "string", "pattern": "^([A-Za-z0-9][A-Za-z0-9._-]{0,127})?$"},
    "state": {"enum": ["running", "creating", "paused", "terminated", "error", "absent", "ambiguous"]},
    "runtime": {"type": "string", "maxLength": 256}
  }
}`

const execResultSchema = `{
  "$id": "helm.sandbox.exec.result.v1",
  "type": "object",
  "additionalProperties": false,
  "required": ["provider", "sandbox_id", "state", "exit_code", "stdout_bytes", "stderr_bytes",
    "stdout_excerpt", "stderr_excerpt", "stdout_truncated", "stderr_truncated"],
  "properties": {
    "provider": {"enum": ` + providerEnum + `},
    "sandbox_id": {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"},
    "state": {"enum": ["not_started", "completed", "timed_out"]},
    "exit_code": {"type": "integer", "minimum": -1, "maximum": 255},
    "stdout_bytes": {"type": "integer", "minimum": 0},
    "stderr_bytes": {"type": "integer", "minimum": 0},
    "stdout_excerpt": {"type": "string", "maxLength": 8192},
    "stderr_excerpt": {"type": "string", "maxLength": 8192},
    "stdout_truncated": {"type": "boolean"},
    "stderr_truncated": {"type": "boolean"}
  }
}`

const terminateResultSchema = `{
  "$id": "helm.sandbox.terminate.result.v1",
  "type": "object",
  "additionalProperties": false,
  "required": ["provider", "sandbox_id", "state"],
  "properties": {
    "provider": {"enum": ` + providerEnum + `},
    "sandbox_id": {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"},
    "state": {"enum": ["terminated", "running", "paused", "creating", "error"]}
  }
}`
