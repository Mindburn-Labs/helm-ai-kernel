import { Fragment, useMemo, type ReactNode } from 'react';
import { getSlotContributions } from './registry';
import type { ExtensionSlotId } from './types';

interface ExtensionSlotProps {
  /** Which slot this is. */
  id: ExtensionSlotId;
  /** Optional props forwarded to every contributed widget. */
  context?: Record<string, unknown>;
  /** Rendered when no module contributes to this slot. */
  fallback?: ReactNode;
}

/**
 * Mount point for module-contributed widgets.
 *
 * The shell places `<ExtensionSlot id="..." />` at every extension point.
 * Private modules (loaded only in `STUDIO_PROFILE=commercial` builds) contribute
 * widgets via their manifest; in an OSS build the slot renders `fallback` or nothing.
 *
 * Slot contributions are resolved once per mount (at render time). Modules are
 * expected to register at boot, before any slot renders, so further updates
 * are not observed — if you need reactive contributions, that is a shell
 * concern and should be added here deliberately.
 */
export function ExtensionSlot({ id, context, fallback = null }: ExtensionSlotProps): ReactNode {
  const contributions = useMemo(() => getSlotContributions(id), [id]);

  if (contributions.length === 0) {
    return <>{fallback}</>;
  }

  return (
    <>
      {contributions.map((widget) => {
        const Component = widget.component;
        return (
          <Fragment key={`${widget.moduleId}:${widget.id}`}>
            <Component {...(context ?? {})} />
          </Fragment>
        );
      })}
    </>
  );
}
