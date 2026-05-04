import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const root = path.resolve(new URL("..", import.meta.url).pathname);
const pkg = JSON.parse(await readFile(path.join(root, "package.json"), "utf8"));

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd ?? root,
    encoding: "utf8",
    stdio: options.capture ? "pipe" : "inherit",
    env: { ...process.env, npm_config_audit: "false", npm_config_fund: "false" },
  });
  if (result.status !== 0) {
    const detail = options.capture ? `\n${result.stdout}\n${result.stderr}` : "";
    throw new Error(`${command} ${args.join(" ")} failed${detail}`);
  }
  return result.stdout;
}

function packageExportTargets(exportsMap) {
  const targets = [];
  for (const value of Object.values(exportsMap)) {
    if (typeof value === "string") {
      targets.push(value);
    } else {
      for (const target of Object.values(value)) targets.push(target);
    }
  }
  return [...new Set(targets.filter((target) => target.startsWith("./dist/")))];
}

const packOutput = run("npm", ["pack", "--json"], { capture: true });
const [pack] = JSON.parse(packOutput);
if (!pack?.filename || !Array.isArray(pack.files)) throw new Error("npm pack did not return file metadata.");

const packedFiles = new Set(pack.files.map((file) => file.path));
for (const target of packageExportTargets(pkg.exports)) {
  const packedPath = target.replace(/^\.\//, "");
  if (!packedFiles.has(packedPath)) {
    throw new Error(`Packed tarball is missing exported target ${packedPath}.`);
  }
}

const temp = await mkdtemp(path.join(tmpdir(), "helm-design-system-smoke-"));

try {
  await writeFile(
    path.join(temp, "package.json"),
    JSON.stringify({ type: "module", private: true }, null, 2),
  );

  run(
    "npm",
    [
      "install",
      "--silent",
      "--ignore-scripts",
      path.join(root, pack.filename),
      "react@19.2.1",
      "react-dom@19.2.1",
      "typescript@6.0.3",
      "@types/react@19.2.7",
      "@types/react-dom@19.2.3",
    ],
    { cwd: temp },
  );

  await writeFile(
    path.join(temp, "tsconfig.json"),
    JSON.stringify(
      {
        compilerOptions: {
          target: "ES2022",
          module: "ES2022",
          moduleResolution: "bundler",
          jsx: "react-jsx",
          strict: true,
          resolveJsonModule: true,
          skipLibCheck: true,
          noEmit: true,
        },
        include: ["index.tsx", "global.d.ts"],
      },
      null,
      2,
    ),
  );

  await writeFile(
    path.join(temp, "global.d.ts"),
    'declare module "*.css";\n',
  );

  await writeFile(
    path.join(temp, "index.tsx"),
    `import "@helm/design-system-core/styles.css";
import tokens from "@helm/design-system-core/tokens.json";
import {
  Button,
  DatePicker,
  DataTable,
  ThemeProvider,
  primitiveCoverage,
} from "@helm/design-system-core";
import { Calendar } from "@helm/design-system-core/components/datepicker";
import { DataTable as SubpathDataTable } from "@helm/design-system-core/components/data-table";
import { ContextMenu } from "@helm/design-system-core/components/context-menu";
import { FieldArray, FileField } from "@helm/design-system-core/components/form-extensions";
import { HoverCard } from "@helm/design-system-core/components/hover-card";
import { I18nProvider } from "@helm/design-system-core/components/i18n";
import { MenuBar } from "@helm/design-system-core/components/menubar";
import { AnnounceProvider } from "@helm/design-system-core/components/announce";
import { TelemetryProvider } from "@helm/design-system-core/components/telemetry";
import { Slot } from "@helm/design-system-core/components/slot";
import * as components from "@helm/design-system-core/components";
import * as core from "@helm/design-system-core/components/core";
import * as data from "@helm/design-system-core/components/data";
import * as feedback from "@helm/design-system-core/components/feedback";
import * as forms from "@helm/design-system-core/components/forms";
import * as inspect from "@helm/design-system-core/components/inspect";
import * as layout from "@helm/design-system-core/components/layout";
import * as primitives from "@helm/design-system-core/components/primitives";
import * as status from "@helm/design-system-core/components/status";
import * as state from "@helm/design-system-core/state";
import * as tokenApi from "@helm/design-system-core/tokens";
import { primitiveCoverageSummary } from "@helm/design-system-core/primitives/catalog";

const refs = [
  Button,
  DatePicker,
  DataTable,
  ThemeProvider,
  Calendar,
  SubpathDataTable,
  ContextMenu,
  FieldArray,
  FileField,
  HoverCard,
  I18nProvider,
  MenuBar,
  AnnounceProvider,
  TelemetryProvider,
  Slot,
  components,
  core,
  data,
  feedback,
  forms,
  inspect,
  layout,
  primitives,
  status,
  state,
  tokenApi,
  tokens,
  primitiveCoverage,
  primitiveCoverageSummary,
];

void refs;
`,
  );

  run("npx", ["tsc", "--noEmit"], { cwd: temp });

  await writeFile(
    path.join(temp, "runtime.mjs"),
    `const paths = [
  "@helm/design-system-core",
  "@helm/design-system-core/components",
  "@helm/design-system-core/components/core",
  "@helm/design-system-core/components/data",
  "@helm/design-system-core/components/data-table",
  "@helm/design-system-core/components/datepicker",
  "@helm/design-system-core/components/feedback",
  "@helm/design-system-core/components/form-extensions",
  "@helm/design-system-core/components/forms",
  "@helm/design-system-core/components/context-menu",
  "@helm/design-system-core/components/hover-card",
  "@helm/design-system-core/components/i18n",
  "@helm/design-system-core/components/inspect",
  "@helm/design-system-core/components/layout",
  "@helm/design-system-core/components/menubar",
  "@helm/design-system-core/components/primitives",
  "@helm/design-system-core/components/slot",
  "@helm/design-system-core/components/status",
  "@helm/design-system-core/components/theme-provider",
  "@helm/design-system-core/components/announce",
  "@helm/design-system-core/components/telemetry",
  "@helm/design-system-core/primitives/catalog",
  "@helm/design-system-core/state",
  "@helm/design-system-core/tokens",
];

for (const specifier of paths) {
  await import(specifier);
}

await import("@helm/design-system-core/tokens.json", { with: { type: "json" } });
`,
  );

  run("node", ["runtime.mjs"], { cwd: temp });
} finally {
  await rm(temp, { recursive: true, force: true });
  await rm(path.join(root, pack.filename), { force: true });
}
