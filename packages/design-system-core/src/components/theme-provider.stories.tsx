import type { Story, StoryDefault } from "@ladle/react";
import { Button, Panel, ThemeProvider, useTheme } from "@mindburn/ui-core";

export default {
  title: "Providers / ThemeProvider",
} satisfies StoryDefault;

function PreferencePanel() {
  const theme = useTheme();
  if (!theme) return <p>No ThemeProvider in scope.</p>;
  return (
    <Panel title="Theme" kicker="Read + write preference, density, and resolved mode.">
      <div style={{ display: "grid", gap: 12 }}>
        <dl style={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: "4px 12px" }}>
          <dt>preference</dt>
          <dd>{theme.preference}</dd>
          <dt>resolvedMode</dt>
          <dd>{theme.resolvedMode}</dd>
          <dt>density</dt>
          <dd>{theme.density}</dd>
        </dl>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <Button variant="secondary" size="sm" onClick={() => theme.setPreference("light")}>
            Force light
          </Button>
          <Button variant="secondary" size="sm" onClick={() => theme.setPreference("dark")}>
            Force dark
          </Button>
          <Button variant="secondary" size="sm" onClick={() => theme.setPreference("auto")}>
            Auto
          </Button>
          <Button variant="ghost" size="sm" onClick={theme.toggleMode}>
            Toggle
          </Button>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <Button variant="ghost" size="sm" onClick={() => theme.setDensity("compact")}>
            Compact
          </Button>
          <Button variant="ghost" size="sm" onClick={() => theme.setDensity("comfortable")}>
            Comfortable
          </Button>
        </div>
      </div>
    </Panel>
  );
}

export const Default: Story = () => (
  <ThemeProvider defaultPreference="auto">
    <PreferencePanel />
  </ThemeProvider>
);

export const ForcedLight: Story = () => (
  <ThemeProvider defaultPreference="light" defaultDensity="comfortable" persist={false}>
    <PreferencePanel />
  </ThemeProvider>
);

export const ForcedDark: Story = () => (
  <ThemeProvider defaultPreference="dark" defaultDensity="compact" persist={false}>
    <PreferencePanel />
  </ThemeProvider>
);

export const NotWrapped: Story = () => <PreferencePanel />;
