# Protocol Specs Source Owner

## Audience

Use this file when changing normative protocol specs, version markers, or reference behavior that public docs expose as stable.

## Responsibility

`protocols/specs` owns spec text and version state. Public docs should link here for normative protocol behavior instead of copying internal drafts into multiple public pages.

## Validation

Run:

```bash
make docs-coverage
make docs-truth
```

Keep public reference pages aligned with spec version changes.
