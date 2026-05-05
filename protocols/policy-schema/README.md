# Policy Schema Source Owner

## Audience

Use this file when changing policy schema generation, Buf configuration, or policy-language compatibility claims.

## Responsibility

`protocols/policy-schema` owns schema generation inputs for policy contracts. Public docs may explain CEL, Rego, and Cedar support only when backed by this directory, the policy bundle code, or examples under `examples/policies`.

## Validation

Run:

```bash
make test
make docs-truth
```

Any public policy-language claim must name the code or example that proves it.
