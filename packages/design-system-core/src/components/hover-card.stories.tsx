import type { Story, StoryDefault } from "@ladle/react";
import { Badge, HoverCard, Panel } from "@helm/design-system-core";

export default {
  title: "Primitives / HoverCard",
} satisfies StoryDefault;

export const AvatarPeek: Story = () => (
  <Panel title="HoverCard" kicker="Hover the @handle to peek at the profile.">
    <p style={{ lineHeight: 1.6 }}>
      Approval was filed by{" "}
      <HoverCard trigger={<a href="#ada">@ada</a>} side="bottom" align="start">
        <strong>Ada Lovelace</strong>
        <span style={{ color: "var(--helm-text-muted)" }}>
          Compliance lead · last seen 2h ago
        </span>
        <span>3 active policies, 12 reviews this quarter.</span>
      </HoverCard>{" "}
      on behalf of the policy review group.
    </p>
  </Panel>
);

export const Citation: Story = () => (
  <Panel title="Citation footnote" kicker="HoverCard for inline citations.">
    <p style={{ lineHeight: 1.6 }}>
      Per the latest review,{" "}
      <HoverCard
        trigger={<sup>[1]</sup>}
        side="top"
        align="center"
        openDelay={150}
      >
        <strong>Decision DR-2026-04-01</strong>
        <span>Approved 2026-04-12 by the safety council.</span>
      </HoverCard>{" "}
      every action above $50k requires dual approval.
    </p>
  </Panel>
);

export const DocPreview: Story = () => (
  <Panel title="Document preview" kicker="HoverCard with rich content.">
    <ul>
      <li>
        <HoverCard
          trigger={<a href="#policy">policy.json</a>}
          side="end"
          align="start"
        >
          <strong>policy.json</strong>
          <span style={{ color: "var(--helm-text-muted)" }}>
            v3.2 · 24 KB · last edited 4 days ago
          </span>
          <Badge state="allow" />
        </HoverCard>
      </li>
    </ul>
  </Panel>
);

export const Controlled: Story = () => (
  <Panel title="Always-open (controlled)" kicker="open=true, no debounce.">
    <HoverCard open trigger={<a href="#x">@always</a>} side="bottom">
      <p>This card is forced open via the controlled `open` prop.</p>
    </HoverCard>
  </Panel>
);
