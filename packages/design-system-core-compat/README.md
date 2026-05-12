# @helm/design-system-core

Deprecated compatibility wrapper for `@mindburn/ui-core`.

This package exists for one migration window so older HELM consumers can resolve the former package name while active code moves to the parent-company foundation package.

New code must import from:

```ts
import { Button } from "@mindburn/ui-core";
import "@mindburn/ui-core/styles.css";
import { tokens } from "@mindburn/ui-core/tokens";
```

This wrapper does not own tokens, CSS, components, docs, or governance. Its public entrypoints re-export `@mindburn/ui-core`.
