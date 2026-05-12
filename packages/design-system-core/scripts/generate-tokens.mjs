import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import ts from "typescript";

const root = path.resolve(new URL("..", import.meta.url).pathname);
const sourcePath = path.join(root, "src", "tokens", "source.ts");
const targetPath = path.join(root, "src", "tokens", "tokens.json");
const check = process.argv.includes("--check");

const source = await readFile(sourcePath, "utf8");
const transpiled = ts.transpileModule(source, {
  compilerOptions: {
    module: ts.ModuleKind.CommonJS,
    target: ts.ScriptTarget.ES2022,
  },
}).outputText;

const module = { exports: {} };
Function("exports", "module", transpiled)(module.exports, module);

const { designTokenSource } = module.exports;
if (!designTokenSource) {
  throw new Error(`Could not load designTokenSource from ${sourcePath}`);
}

const nextJson = `${JSON.stringify(designTokenSource, null, 2)}\n`;

if (check) {
  const currentJson = await readFile(targetPath, "utf8");
  if (currentJson !== nextJson) {
    throw new Error("Generated token JSON is stale. Run npm run tokens:generate in @mindburn/ui-core.");
  }
} else {
  await writeFile(targetPath, nextJson);
}
