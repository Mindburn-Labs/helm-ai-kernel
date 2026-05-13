import { access, readFile } from "node:fs/promises";
import { join } from "node:path";

const root = new URL("..", import.meta.url);
const dist = new URL("dist/", root);

await access(new URL("index.html", dist));
await access(new URL(".vite/manifest.json", dist));

const manifest = JSON.parse(await readFile(new URL(".vite/manifest.json", dist), "utf8"));
const entries = Object.values(manifest);
if (!entries.some((entry) => entry.isEntry && String(entry.file).endsWith(".js"))) {
  throw new Error("Console dist manifest does not contain a JavaScript entry.");
}

const index = await readFile(join(dist.pathname, "index.html"), "utf8");
if (!index.includes("HELM AI Kernel Console")) {
  throw new Error("Console index.html is missing the app title.");
}

console.log("console dist smoke passed");
