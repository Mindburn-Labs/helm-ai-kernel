import type { Story, StoryDefault } from "@ladle/react";
import { useState } from "react";
import {
  I18nProvider,
  Panel,
  SelectField,
  useFormatDate,
  useFormatNumber,
  useFormatRelativeTime,
  useI18n,
} from "@mindburn/ui-core";

export default {
  title: "Providers / I18nProvider",
} satisfies StoryDefault;

const LOCALES = ["en-US", "de-DE", "ja-JP", "ar-SA", "he-IL"] as const;

const MESSAGES = {
  greeting: "Hello, {name}! You have {count} alerts.",
  policy: "Policy {id} approved by {owner}.",
} as const;

function I18nDemo() {
  const ctx = useI18n();
  const fmtN = useFormatNumber();
  const fmtD = useFormatDate();
  const fmtR = useFormatRelativeTime();
  const [stableNow] = useState(() => Date.now());
  if (!ctx) return <p>No I18nProvider in scope.</p>;

  return (
    <Panel
      title={`Locale: ${ctx.locale} (dir=${ctx.direction})`}
      kicker="Locale picker rewires Intl formatters and toggles document dir."
    >
      <div style={{ display: "grid", gap: 12 }}>
        <div style={{ maxInlineSize: 240 }}>
          <SelectField
            value={ctx.locale}
            options={LOCALES}
            onChange={(event) => ctx.setLocale(event.currentTarget.value)}
            aria-label="Locale"
          />
        </div>
        <dl style={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: "4px 12px" }}>
          <dt>t(greeting, name=Ada, count=3)</dt>
          <dd>{ctx.t("greeting", { name: "Ada", count: 3 })}</dd>
          <dt>fmtN(1234567.89)</dt>
          <dd>{fmtN(1234567.89)}</dd>
          <dt>fmtD(now)</dt>
          <dd>{fmtD(stableNow)}</dd>
          <dt>fmtR(-1, day)</dt>
          <dd>{fmtR(-1, "day")}</dd>
          <dt>fmtR(2, hour)</dt>
          <dd>{fmtR(2, "hour")}</dd>
        </dl>
      </div>
    </Panel>
  );
}

export const Default: Story = () => (
  <I18nProvider defaultLocale="en-US" messages={MESSAGES}>
    <I18nDemo />
  </I18nProvider>
);

export const German: Story = () => (
  <I18nProvider defaultLocale="de-DE" messages={MESSAGES}>
    <I18nDemo />
  </I18nProvider>
);

export const Japanese: Story = () => (
  <I18nProvider defaultLocale="ja-JP" messages={MESSAGES}>
    <I18nDemo />
  </I18nProvider>
);

export const ArabicRTL: Story = () => (
  <I18nProvider defaultLocale="ar-SA" messages={MESSAGES}>
    <I18nDemo />
  </I18nProvider>
);
