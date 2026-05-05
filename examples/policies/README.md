# Policy Examples

This directory contains the retained CEL, Rego, and Cedar example policy files
used by the public compatibility docs.

## Files

| Path | Purpose |
| --- | --- |
| `cel/example.cel` | CEL allow/deny example. |
| `rego/example.rego` | Rego allow/deny example. |
| `cedar/example.cedar` | Cedar allow/deny example. |
| `cedar/entities.json` | Cedar entity context for the example policy. |

## Build Examples

```bash
make build
./bin/helm bundle build --language cel examples/policies/cel/example.cel
./bin/helm bundle build --language rego examples/policies/rego/example.rego
./bin/helm bundle build --language cedar --entities examples/policies/cedar/entities.json examples/policies/cedar/example.cedar
```

`helm bundle build` accepts the policy source as the positional argument.
`--policy` belongs to `helm serve` and is intentionally not accepted by this
subcommand.

Policy-language behavior is documented in
`docs/architecture/policy-languages.md`.
