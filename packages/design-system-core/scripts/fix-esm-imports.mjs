import { existsSync } from "node:fs";
import { readdir, readFile, stat, writeFile } from "node:fs/promises";
import path from "node:path";

const root = path.resolve(process.argv[2] ?? "dist");

async function* jsFiles(dir) {
  for (const entry of await readdir(dir)) {
    const full = path.join(dir, entry);
    const info = await stat(full);
    if (info.isDirectory()) {
      yield* jsFiles(full);
    } else if (entry.endsWith(".js")) {
      yield full;
    }
  }
}

function withJsExtension(file, specifier) {
  if (!specifier.startsWith(".")) return specifier;
  if (path.extname(specifier)) return specifier;
  const resolved = path.resolve(path.dirname(file), specifier);
  if (existsSync(`${resolved}.js`)) return `${specifier}.js`;
  if (existsSync(path.join(resolved, "index.js"))) return `${specifier}/index.js`;
  return `${specifier}.js`;
}

function rewriteRelativeSpecifiers(file, source) {
  let next = source.replace(
    /(\b(?:import|export)\s+(?:[^'"]*?\s+from\s+)?["'])(\.[^'"]+)(["'])/g,
    (_match, prefix, specifier, suffix) => `${prefix}${withJsExtension(file, specifier)}${suffix}`,
  );

  next = next.replace(
    /(\bimport\s*\(\s*["'])(\.[^'"]+)(["']\s*\))/g,
    (_match, prefix, specifier, suffix) => `${prefix}${withJsExtension(file, specifier)}${suffix}`,
  );

  return next;
}

for await (const file of jsFiles(root)) {
  const source = await readFile(file, "utf8");
  const next = rewriteRelativeSpecifiers(file, source);
  if (next !== source) await writeFile(file, next);
}
