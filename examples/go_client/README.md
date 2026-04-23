# Go Client Example

Shows HELM integration with the Go SDK.

## Prerequisites

- HELM running at `http://localhost:8080` (`docker compose up -d`)
- Go 1.25+

## Run

```bash
go run main.go
```

## Expected Output

```
=== Chat Completions ===
Denied: DENY_TOOL_NOT_FOUND — Tool not found

=== Evidence ===
Exported: 1234 bytes

=== Conformance ===
Verdict: PASS Gates: 12 Failed: 0

=== Health ===
Status: map[status:ok version:0.1.0]
```
