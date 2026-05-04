import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { approvedDynamicInlineStyles } from "./tokens";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function read(relativePath: string): string {
  return readFileSync(path.join(repoRoot, relativePath), "utf8");
}

function componentExports(source: string): string[] {
  const matches = source.matchAll(/export \* from "\.\/components\/([^"]+)";/g);
  return [...matches].map((match) => match[1]).sort();
}

describe("package integration contract", () => {
  it("./components barrel stays aligned with root component exports", () => {
    const rootComponents = componentExports(read("src/index.ts"));
    const componentsBarrel = read("src/components/index.ts");

    for (const component of rootComponents) {
      expect(componentsBarrel).toContain(`export * from "./${component}";`);
    }
  });

  it("package.json exposes every public component subpath", () => {
    const rootComponents = componentExports(read("src/index.ts"));
    const pkg = JSON.parse(read("package.json")) as { exports: Record<string, unknown> };

    for (const component of rootComponents) {
      expect(pkg.exports).toHaveProperty(`./components/${component}`);
    }
  });

  it("new component class names have shipped CSS selectors", () => {
    const css = [
      read("src/styles/primitives.css"),
      read("src/styles/forms.css"),
    ].join("\n");

    for (const selector of [
      ".context-menu-region",
      ".context-menu-popup",
      ".context-menu-item",
      ".file-field",
      ".file-field-dropzone",
      ".file-field-input",
      ".file-field-list-item",
    ]) {
      expect(css).toContain(selector);
    }
  });

  it("context menu uses approved dynamic CSS variables instead of hard-coded z-index", () => {
    const source = read("src/components/context-menu.tsx");
    const css = read("src/styles/primitives.css");

    expect(source).not.toContain("zIndex: 1000");
    expect(source).toContain("--helm-context-menu-x");
    expect(source).toContain("--helm-context-menu-y");
    expect(css).toContain("z-index: var(--helm-z-context-menu)");
    expect(approvedDynamicInlineStyles).toContain("context menu viewport coordinates");
  });
});
