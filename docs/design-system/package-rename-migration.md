# Mindburn UI Core Package Rename

`@mindburn/ui-core` is the canonical parent-company UI foundation package.

The former `@helm/design-system-core` name is retained only as a compatibility wrapper for one migration window. It re-exports `@mindburn/ui-core`, imports `@mindburn/ui-core/styles.css`, and exposes the same token JSON contract for old consumers.

## Import Migration

Use:

```ts
import { Button } from "@mindburn/ui-core";
import "@mindburn/ui-core/styles.css";
import { tokens } from "@mindburn/ui-core/tokens";
```

Do not add new imports from:

```ts
import { Button } from "@helm/design-system-core";
import "@helm/design-tokens/styles.css";
```

`@helm/design-system-helm` remains the HELM product-pattern package. It depends on `@mindburn/ui-core` but does not re-export it.
