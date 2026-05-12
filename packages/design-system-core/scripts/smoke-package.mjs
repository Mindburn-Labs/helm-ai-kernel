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

const temp = await mkdtemp(path.join(tmpdir(), "mindburn-ui-core-smoke-"));

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
    `import "@mindburn/ui-core/styles.css";
import tokens from "@mindburn/ui-core/tokens.json";
import {
  Button,
  DatePicker,
  DataTable,
  ThemeProvider,
  primitiveCoverage,
} from "@mindburn/ui-core";
import { Calendar } from "@mindburn/ui-core/components/datepicker";
import { DataTable as SubpathDataTable } from "@mindburn/ui-core/components/data-table";
import { ContextMenu } from "@mindburn/ui-core/components/context-menu";
import { FieldArray, FileField } from "@mindburn/ui-core/components/form-extensions";
import { HoverCard } from "@mindburn/ui-core/components/hover-card";
import { I18nProvider } from "@mindburn/ui-core/components/i18n";
import { MenuBar } from "@mindburn/ui-core/components/menubar";
import { AnnounceProvider } from "@mindburn/ui-core/components/announce";
import { TelemetryProvider } from "@mindburn/ui-core/components/telemetry";
import { Slot } from "@mindburn/ui-core/components/slot";
import * as components from "@mindburn/ui-core/components";
import * as core from "@mindburn/ui-core/components/core";
import * as data from "@mindburn/ui-core/components/data";
import * as feedback from "@mindburn/ui-core/components/feedback";
import * as forms from "@mindburn/ui-core/components/forms";
import * as inspect from "@mindburn/ui-core/components/inspect";
import * as layout from "@mindburn/ui-core/components/layout";
import * as primitives from "@mindburn/ui-core/components/primitives";
import * as status from "@mindburn/ui-core/components/status";
import * as state from "@mindburn/ui-core/state";
import * as tokenApi from "@mindburn/ui-core/tokens";
import { primitiveCoverageSummary } from "@mindburn/ui-core/primitives/catalog";

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
  "@mindburn/ui-core",
  "@mindburn/ui-core/components",
  "@mindburn/ui-core/components/core",
  "@mindburn/ui-core/components/data",
  "@mindburn/ui-core/components/data-table",
  "@mindburn/ui-core/components/datepicker",
  "@mindburn/ui-core/components/feedback",
  "@mindburn/ui-core/components/form-extensions",
  "@mindburn/ui-core/components/forms",
  "@mindburn/ui-core/components/context-menu",
  "@mindburn/ui-core/components/hover-card",
  "@mindburn/ui-core/components/i18n",
  "@mindburn/ui-core/components/inspect",
  "@mindburn/ui-core/components/layout",
  "@mindburn/ui-core/components/menubar",
  "@mindburn/ui-core/components/primitives",
  "@mindburn/ui-core/components/slot",
  "@mindburn/ui-core/components/status",
  "@mindburn/ui-core/components/theme-provider",
  "@mindburn/ui-core/components/announce",
  "@mindburn/ui-core/components/telemetry",
  "@mindburn/ui-core/primitives/catalog",
  "@mindburn/ui-core/state",
  "@mindburn/ui-core/tokens",
];

for (const specifier of paths) {
  await import(specifier);
}

await import("@mindburn/ui-core/tokens.json", { with: { type: "json" } });
`,
  );

  run("node", ["runtime.mjs"], { cwd: temp });
} finally {
  await rm(temp, { recursive: true, force: true });
  await rm(path.join(root, pack.filename), { force: true });
}
